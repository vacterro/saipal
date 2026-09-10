"""Source enrollment and health surfaces (T-85 extension of sources.py).

`enroll_source` is a DELIBERATE configuration write: a discovered candidate
gains authority only through it, never because a folder name looks familiar.
Structure verification runs before the write; enrollment is atomic; an
already-enrolled path under a different spelling is refused (identity is the
canonicalized path, deduped before ids are minted).

Health truth is observational: READY/EMPTY/UNAVAILABLE/MISCONFIGURED/DISABLED/
UNSUPPORTED derived from observed facts, with failure memory
(`last_error`, `consecutive_failures`) persisted beside the registry. A
source outage is never semantic evidence.
"""

from __future__ import annotations

import time
from pathlib import Path

from .adapters import ADAPTER_REGISTRY
from .capability import require_action
from .errors import PalError
from .paths import home_paths, read_json
from .sources import load_sources, save_sources

HEALTH_SCHEMA_VERSION = 2
HEALTH_NAME = "source_health.json"

HEALTH_FIELDS = ("schema_version", "updated_at", "sources")
SOURCE_HEALTH_FIELDS = (
    "source_id",
    "last_discovery_ok",
    "last_import_ok",
    "sessions_seen",
    "sessions_imported",
    "bundles_dispatched",
    "sessions_unchanged",
    "sessions_rejected",
    "sessions_conflict",
    "pending",
    "last_discovery_at",
    "last_import_at",
    "last_success_at",
    "watermark",
    "last_error",
    "consecutive_failures",
)

HEALTH_STATES = (
    "READY",
    "EMPTY",
    "UNAVAILABLE",
    "MISCONFIGURED",
    "DISABLED",
    "UNSUPPORTED",
)


def health_path(home: Path | str) -> Path:
    return home_paths(home).root / HEALTH_NAME


def fresh_health() -> dict:
    return {"schema_version": HEALTH_SCHEMA_VERSION, "updated_at": "", "sources": {}}


def _fresh_source_record(source_id: str) -> dict:
    return {
        "source_id": source_id,
        "last_discovery_ok": False,
        "last_import_ok": False,
        "sessions_seen": 0,
        "sessions_imported": 0,
        "bundles_dispatched": 0,
        "sessions_unchanged": 0,
        "sessions_rejected": 0,
        "sessions_conflict": 0,
        "pending": 0,
        "last_discovery_at": None,
        "last_import_at": None,
        "last_success_at": None,
        "watermark": None,
        "last_error": None,
        "consecutive_failures": 0,
    }


def load_health(home: Path | str) -> dict:
    """Load source health, explicitly migrating v1 records in memory (T-97).

    A v1 file is readable and valid; it is upgraded to the v2 field set when
    next SAVED. Read-only surfaces never write, so they never migrate on
    disk -- they simply observe defaults for fields a v1 record lacks.
    """
    path = health_path(home)
    if not path.exists():
        return fresh_health()
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise PalError(
            "INVALID_SOURCE_REGISTRY",
            f"source health record is unreadable: {exc}",
            next_action="repair or remove .saipal/source_health.json by hand",
        ) from None
    problems = health_problems(payload)
    if problems and payload.get("schema_version") == 1:
        # Explicit v1 -> v2 migration: same shape, added counters default to
        # 0 and timestamps to null. Apply deterministically, re-validate.
        migrated = _migrate_v1(payload)
        problems = health_problems(migrated)
        if not problems:
            return migrated
    if problems:
        raise PalError(
            "INVALID_SOURCE_REGISTRY",
            "source health record is invalid: " + "; ".join(problems[:5]),
        )
    return payload


def _migrate_v1(payload: dict) -> dict:
    sources = payload.get("sources") or {}
    migrated_sources: dict[str, dict] = {}
    for source_id, record in sources.items():
        if not isinstance(record, dict):
            migrated_sources[source_id] = record
            continue
        migrated = dict(record)
        for field, default in (
            ("bundles_dispatched", 0),
            ("sessions_unchanged", 0),
            ("sessions_rejected", 0),
            ("sessions_conflict", 0),
            ("pending", 0),
            ("last_discovery_at", None),
            ("last_import_at", None),
            ("last_success_at", None),
            ("watermark", None),
        ):
            migrated.setdefault(field, default)
        migrated_sources[source_id] = migrated
    return {**payload, "schema_version": HEALTH_SCHEMA_VERSION, "sources": migrated_sources}


def save_health(home: Path | str, payload: dict) -> Path:
    problems = health_problems(payload)
    if problems:
        raise PalError(
            "INVALID_SOURCE_REGISTRY",
            "refusing invalid source health record: " + "; ".join(problems[:5]),
        )
    from .paths import atomic_write_json

    payload["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return atomic_write_json(health_path(home), payload, root=home_paths(home).root)


def health_problems(payload: object) -> list[str]:
    if not isinstance(payload, dict):
        return ["source health root is not an object"]
    if payload.get("schema_version") != HEALTH_SCHEMA_VERSION:
        return [f"schema_version must be {HEALTH_SCHEMA_VERSION}"]
    for key in sorted(set(payload) - set(HEALTH_FIELDS)):
        return [f"unknown source health field {key!r}"]
    sources = payload.get("sources")
    if not isinstance(sources, dict):
        return ["sources must be an object"]
    for source_id, record in sources.items():
        if not isinstance(record, dict):
            return [f"source health {source_id!r} is not an object"]
        for field in sorted(set(record) - set(SOURCE_HEALTH_FIELDS)):
            return [f"source health {source_id!r} has unknown field {field!r}"]
    return []


def _canonical(path: Path) -> str:
    """Case/slash-normalized identity on Windows, no symlink resolution.

    Resolving symlinks/junctions could break root-confinement reasoning, so
    enrollment dedupes on the expanduser+resolve(False)+casefold string.
    """
    expanded = Path(str(path)).expanduser()
    try:
        resolved = expanded.resolve()
    except OSError:
        resolved = expanded
    return str(resolved).casefold()


def structure_verified(kind: str, path: Path) -> tuple[bool, str]:
    """Does the adapter recognize this path's expected structure?"""
    if kind not in ADAPTER_REGISTRY:
        return False, f"adapter {kind!r} is not registered"
    if not path.exists():
        return False, f"{path} does not exist"
    try:
        sessions = ADAPTER_REGISTRY[kind].discover(str(path))
    except Exception as exc:  # noqa: BLE001
        return False, f"adapter could not read the store: {exc}"
    return True, f"recognized ({len(sessions)} sessions)"


def enroll_source(
    home: Path | str,
    *,
    kind: str,
    path: Path | str,
    source_id: str | None = None,
    enabled: bool = True,
) -> dict:
    """The ONE canonical source write gate. Verified, atomic, idempotent (T-112).

    CORE-001 ROLE 20260910 §4: mutation takes the common writer fence HERE
    (reentrant), so a direct library call cannot bypass the boundary. The
    structure verification (provider I/O) runs OUTSIDE the fence (ROLE H:
    no provider latency while held); the read-modify-write of sources.json
    is fenced.
    """
    # Provider I/O outside the fence (ROLE H)
    verified, reason = structure_verified(kind, Path(path).expanduser())
    if not verified:
        raise PalError(
            "INVALID_SOURCE_REGISTRY",
            f"enrollment refused: {reason}",
            next_action="enrollment is deliberate; a candidate is not authority",
        )

    # Durable transaction inside the fence (reentrant)
    from saipal_engine.paths import writer_fence

    with writer_fence(home):
        require_action("write_own_index")
        status, payload, _detail = load_sources(home)
        sources = list((payload or {}).get("sources") or [])
        canonical = _canonical(Path(path))

        for existing in sources:
            if _canonical(Path(str(existing.get("path") or ""))) != canonical:
                continue
            existing_kind = str(existing.get("kind") or "")
            if existing_kind == kind:
                return {
                    "source_enroll": True,
                    "ok": True,
                    "id": str(existing.get("id") or ""),
                    "kind": existing_kind,
                    "path": str(existing.get("path") or ""),
                    "verified": "already enrolled (idempotent no-op)",
                    "unchanged": True,
                }
            raise PalError(
                "INVALID_SOURCE_REGISTRY",
                (
                    f"source {existing.get('id')!r} is already enrolled at this path "
                    f"with kind {existing_kind!r}; enrolling {kind!r} would conflict. "
                    "Enable/disable or re-configure the existing source deliberately."
                ),
                next_action="sources enable/disable change state; enrollment never "
                            "rewrites an existing source's identity",
            )
        if source_id and any(str(existing.get("id") or "") == source_id for existing in sources):
            raise PalError("INVALID_SOURCE_REGISTRY", f"source id {source_id!r} already exists")

        minted = source_id or f"{kind}-{len(sources) + 1:02d}"
        sources.append(
            {
                "id": minted,
                "kind": kind,
                "path": str(Path(path).expanduser()),
                "enabled": bool(enabled),
            }
        )
        save_sources(home, {"schema_version": 1, "sources": sources})
        return {
            "source_enroll": True,
            "ok": True,
            "id": minted,
            "kind": kind,
            "path": str(Path(path).expanduser()),
            "verified": reason,
        }


def set_source_state(home: Path | str, source_id: str, enabled: bool) -> dict:
    """Canonical enabled/disabled flip: self-fenced, zero writes if unchanged."""
    from saipal_engine.paths import writer_fence

    with writer_fence(home):
        require_action("write_own_index")
        status, payload, _detail = load_sources(home)
        sources = list((payload or {}).get("sources") or [])
        for source in sources:
            if str(source.get("id") or "") == source_id:
                if source.get("enabled") == enabled:
                    return {
                        "sources_state": "enable" if enabled else "disable",
                        "ok": True,
                        "id": source_id,
                        "unchanged": True,
                    }
                source["enabled"] = enabled
                save_sources(home, {"schema_version": 1, "sources": sources})
                return {
                    "sources_state": "enable" if enabled else "disable",
                    "ok": True,
                    "id": source_id,
                    "enabled": enabled,
                }
        raise PalError(
            "INVALID_SOURCE_REGISTRY",
            f"no configured source {source_id!r}; discovery never auto-enrolls",
        )


def remove_source(home: Path | str, source_id: str) -> dict:
    """Canonical removal: self-fenced. Provider evidence on disk is NEVER deleted."""
    from saipal_engine.paths import writer_fence

    with writer_fence(home):
        require_action("write_own_index")
        status, payload, _detail = load_sources(home)
        sources = list((payload or {}).get("sources") or [])
        remaining = [s for s in sources if str(s.get("id") or "") != source_id]
        if len(remaining) == len(sources):
            raise PalError("INVALID_SOURCE_REGISTRY", f"no configured source {source_id!r}")
        save_sources(home, {"schema_version": 1, "sources": remaining})
        return {
            "sources_remove": True,
            "ok": True,
            "id": source_id,
            "note": "configuration removed; provider evidence on disk is untouched",
        }


def record_source_import(
    home: Path | str,
    *,
    source_id: str,
    sessions_seen: int = 0,
    sessions_imported: int = 0,
    sessions_unchanged: int = 0,
    sessions_rejected: int = 0,
    sessions_conflict: int = 0,
    bundles_dispatched: int = 0,
    pending: int = 0,
    watermark: int | None = None,
    error: str | None = None,
) -> dict:
    """Observational health memory for one source. Never semantic evidence.

    T-97: every counter is EXPLICIT provenance -- the caller attributes
    outcomes to a source_id carried through dispatch -> inbox -> import;
    health never divides global totals or guesses from filenames. Timestamps
    are real timestamps or null (never zero), and a watermark is recorded
    only when the caller vouches it is trustworthy.
    """
    health = load_health(home)
    records = health.setdefault("sources", {})
    record = records.setdefault(source_id, _fresh_source_record(source_id))
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if error:
        record["last_import_ok"] = False
        record["last_error"] = str(error)[:200]
        record["consecutive_failures"] = int(record.get("consecutive_failures") or 0) + 1
        record["last_import_at"] = now
        record["sessions_rejected"] = (
            int(record.get("sessions_rejected") or 0) + int(sessions_rejected or 1)
        )
    else:
        record["last_import_ok"] = True
        record["last_discovery_ok"] = True
        record["last_error"] = None
        record["consecutive_failures"] = 0
        record["sessions_seen"] = int(record.get("sessions_seen") or 0) + int(sessions_seen)
        record["sessions_imported"] = (
            int(record.get("sessions_imported") or 0) + int(sessions_imported)
        )
        record["sessions_unchanged"] = (
            int(record.get("sessions_unchanged") or 0) + int(sessions_unchanged)
        )
        record["sessions_conflict"] = (
            int(record.get("sessions_conflict") or 0) + int(sessions_conflict)
        )
        record["bundles_dispatched"] = (
            int(record.get("bundles_dispatched") or 0) + int(bundles_dispatched)
        )
        record["pending"] = int(pending)
        record["last_import_at"] = now
        if sessions_imported > 0:
            record["last_success_at"] = now
        if watermark is not None:
            record["watermark"] = int(watermark)
    if record.get("last_discovery_at") is None:
        record["last_discovery_at"] = now
    save_health(home, health)
    return record


def health_report(home: Path | str) -> dict:
    """Per-source health: observed facts only, outages are not evidence."""
    from .sources import discover

    rows = discover(home)
    health = load_health(home)
    records = health.get("sources") or {}
    out = []
    for row in rows:
        record = records.get(str(row.get("id"))) or {}
        out.append(
            {
                "id": row.get("id"),
                "kind": row.get("kind"),
                "path": row.get("path"),
                "status": row.get("status"),
                "sessions": row.get("sessions"),
                "last_import_ok": record.get("last_import_ok"),
                "last_error": record.get("last_error"),
                "consecutive_failures": record.get("consecutive_failures", 0),
                "sessions_imported": record.get("sessions_imported", 0),
                "sessions_seen": record.get("sessions_seen", 0),
                "sessions_unchanged": record.get("sessions_unchanged", 0),
                "sessions_rejected": record.get("sessions_rejected", 0),
                "sessions_conflict": record.get("sessions_conflict", 0),
                "bundles_dispatched": record.get("bundles_dispatched", 0),
                "pending": record.get("pending", 0),
                "last_discovery_at": record.get("last_discovery_at"),
                "last_import_at": record.get("last_import_at"),
                "last_success_at": record.get("last_success_at"),
                "watermark": record.get("watermark"),
            }
        )
    return {
        "source_health": True,
        "ok": True,
        "sources": out,
        "note": "source outage is never semantic evidence",
    }
