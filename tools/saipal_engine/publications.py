"""Pending external publication: local staging is not delivery (audit CORE-007).

`PUBLISH_ENABLED` means a configured maintainer sink receives the numbered audit.
When that sink is unavailable the audit still stages locally -- correct, a finding
is never lost to an outage -- but the finding used to advance to `EMITTED`
regardless, so the outage permanently lost delivery: nothing recorded that the
sink had never seen it, and no later cycle tried again.

This ledger is that record. It holds the audit number and body digest of every
staged audit a sink has not confirmed, so the next cycle republishes exactly that
audit rather than allocating a new one.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .capability import require_action
from .paths import atomic_write_json, home_paths, read_json, utc_now_iso

SCHEMA_VERSION = 1

STATUS_ABSENT = "absent"
STATUS_OK = "ok"
STATUS_UNRECOVERABLE = "unrecoverable"

#: A staged audit no sink has confirmed.
PENDING = "PENDING"
#: A sink write that was verified at the target.
PUBLISHED = "PUBLISHED"


def empty_ledger() -> dict:
    return {"schema_version": SCHEMA_VERSION, "publications": []}


def load_publications(home: Path | str) -> tuple[str, dict | None, str]:
    """`(status, ledger, detail)`.

    Corruption is NOT absence. An unreadable ledger refuses mutation and keeps its
    bytes: overwriting it would silently drop the record of every undelivered
    audit, which is the same class of failure this module exists to prevent.
    """
    path = home_paths(home).publications
    if not path.exists():
        return STATUS_ABSENT, None, ""
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return STATUS_UNRECOVERABLE, None, f"publication ledger is unreadable: {exc}"
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != SCHEMA_VERSION
        or not isinstance(payload.get("publications"), list)
    ):
        return STATUS_UNRECOVERABLE, None, "publication ledger is malformed"
    return STATUS_OK, payload, ""


def save_publications(home: Path | str, ledger: dict, *, registry: dict | None = None) -> dict:
    require_action("write_own_index", registry=registry)
    paths = home_paths(home)
    atomic_write_json(paths.publications, ledger, root=paths.root)
    return ledger


def _key(entry: dict) -> tuple[int, str]:
    return (int(entry.get("audit_number") or 0), str(entry.get("audit_sha256") or ""))


def record_pending(
    home: Path | str,
    *,
    finding_id: str,
    audit_number: int,
    audit_path: str,
    audit_sha256: str,
    reason: str,
    registry: dict | None = None,
) -> dict:
    """Note that this exact audit is staged but undelivered. Idempotent."""
    status, ledger, detail = load_publications(home)
    if status == STATUS_UNRECOVERABLE:
        from .errors import PalError

        raise PalError("VALIDATION_FAILED", detail)
    if ledger is None:
        ledger = empty_ledger()

    entry = {
        "finding_id": str(finding_id),
        "audit_number": int(audit_number),
        "audit_path": str(audit_path),
        "audit_sha256": str(audit_sha256),
        "status": PENDING,
        "reason": str(reason),
        "attempts": 1,
        "first_failed_at": utc_now_iso(),
        "last_attempt_at": utc_now_iso(),
    }
    for existing in ledger["publications"]:
        if _key(existing) == _key(entry):
            existing["status"] = PENDING
            existing["reason"] = entry["reason"]
            existing["attempts"] = int(existing.get("attempts") or 0) + 1
            existing["last_attempt_at"] = entry["last_attempt_at"]
            save_publications(home, ledger, registry=registry)
            return existing
    ledger["publications"].append(entry)
    save_publications(home, ledger, registry=registry)
    return entry


def mark_published(
    home: Path | str,
    *,
    audit_number: int,
    audit_sha256: str,
    registry: dict | None = None,
) -> dict | None:
    """Record that the sink confirmed this audit. Returns the entry, or None."""
    status, ledger, detail = load_publications(home)
    if status != STATUS_OK or ledger is None:
        return None
    for entry in ledger["publications"]:
        if _key(entry) == (int(audit_number), str(audit_sha256)):
            entry["status"] = PUBLISHED
            entry["published_at"] = utc_now_iso()
            entry.pop("reason", None)
            save_publications(home, ledger, registry=registry)
            return entry
    return None


def pending(home: Path | str) -> list[dict]:
    """Every staged audit still awaiting delivery, oldest first."""
    status, ledger, _detail = load_publications(home)
    if status != STATUS_OK or ledger is None:
        return []
    return [
        entry
        for entry in ledger["publications"]
        if isinstance(entry, dict) and entry.get("status") == PENDING
    ]


def retry_pending(home: Path | str, *, registry: dict | None = None) -> dict[str, Any]:
    """Republish every pending audit through the configured sink.

    Runs before ordinary cycle work, so a restored sink receives the backlog
    before anything new is produced. Reuses the staged body and its audit number:
    a retry that allocated a fresh number would publish the same finding twice.
    """
    from . import audits as audits_mod  # noqa: F401  (kept for parity/imports)
    from .errors import PalError
    from .sink import configured_sink

    outstanding = pending(home)
    result = {"attempted": len(outstanding), "published": 0, "still_pending": 0, "failures": []}
    if not outstanding:
        return result

    sink_status, sink, sink_detail = configured_sink(home)
    if sink_status != "ok" or sink is None:
        result["still_pending"] = len(outstanding)
        result["failures"].append({"reason": sink_detail or "no sink configured"})
        return result

    root = Path(home)
    for entry in outstanding:
        staged = root / str(entry.get("audit_path") or "")
        try:
            body = staged.read_text(encoding="utf-8")
        except OSError as exc:
            result["still_pending"] += 1
            result["failures"].append(
                {"audit_number": entry.get("audit_number"), "reason": f"staged audit unreadable: {exc}"}
            )
            continue
        finding = {"finding_id": entry.get("finding_id")}
        try:
            # Reuse the number the audit was staged as: a fresh one would deliver
            # the same finding to the maintainer under a second identity.
            published = sink.publish(
                finding, body, reserve_number=int(entry.get("audit_number") or 0)
            )
            if not sink.verify(published):
                raise PalError("SINK_UNAVAILABLE", "sink write did not verify")
        except (OSError, PalError) as exc:
            result["still_pending"] += 1
            result["failures"].append(
                {"audit_number": entry.get("audit_number"), "reason": str(exc)}
            )
            continue
        mark_published(
            home,
            audit_number=int(entry.get("audit_number") or 0),
            audit_sha256=str(entry.get("audit_sha256") or ""),
            registry=registry,
        )
        result["published"] += 1
    return result
