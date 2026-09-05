"""Generic session intake (PAL-SESSION-04).

Deterministic, provider-neutral, and forgiving of a bad export: a broken bundle
is reported and skipped, never partially ingested and never repaired. Nothing is
ever deleted from the inbox -- SAIPAL observes, it does not clean up after the
operator.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from . import bundle as bundle_mod
from . import episodes as episodes_mod
from .errors import PalError
from .paths import home_paths, sha256_file, utc_now_iso
from .registry import load_registry
from .sessions import (
    STATUS_ABSENT,
    STATUS_UNRECOVERABLE,
    already_imported,
    latest_generation,
    load_index,
    new_record,
    records_for_session,
    save_index,
    validate_index,
)

BUNDLE_SUFFIX = ".json"

#: Remembers which inbox file, at which size and mtime, produced which session
#: and digest. The inbox is a durable forensic archive, not a queue: without this
#: every cycle re-read, re-validated and re-hashed all 99 retained artifacts to
#: discover that 95 of them were duplicates it had already skipped -- cost
#: proportional to all history rather than to new evidence (PERF-002).
INBOX_CACHE_NAME = "inbox_cache.json"
INBOX_CACHE_VERSION = 1


def _cache_path(root: Path) -> Path:
    return home_paths(root).root / INBOX_CACHE_NAME


def _load_cache(root: Path) -> dict:
    from .paths import read_json

    path = _cache_path(root)
    if not path.exists():
        return {"schema_version": INBOX_CACHE_VERSION, "files": {}}
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError):
        return {"schema_version": INBOX_CACHE_VERSION, "files": {}}
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != INBOX_CACHE_VERSION
        or not isinstance(payload.get("files"), dict)
    ):
        return {"schema_version": INBOX_CACHE_VERSION, "files": {}}
    return payload


def _save_cache(root: Path, cache: dict, *, registry: dict | None) -> None:
    from .capability import require_action
    from .paths import atomic_write_json

    require_action("write_own_cache", registry=registry)
    atomic_write_json(_cache_path(root), cache, root=home_paths(root).root)


def _stat_key(path: Path) -> dict | None:
    """Size and mtime: cheap, and enough to notice a rewritten artifact.

    Not a substitute for the digest -- the digest is what identity rests on. This
    only decides whether re-reading the file can be skipped, and any mismatch
    falls through to a full read.
    """
    try:
        info = path.stat()
    except OSError:
        return None
    return {"size": int(info.st_size), "mtime_ns": int(info.st_mtime_ns)}


def _trustworthy(remembered: object, stat: dict) -> bool:
    """May this cache entry stand in for reading the file?

    Size and mtime alone are not enough. A file rewritten to the SAME size within
    the same filesystem mtime tick as the moment the entry was recorded looks
    identical to the unchanged file, and trusting that would suppress changed
    evidence -- the exact failure mode CORE-002 and W2-003 were about, reintroduced
    by a cache. So an entry is only trusted when the file's mtime is strictly
    older than the observation: anything racy re-reads.
    """
    if not isinstance(remembered, dict):
        return False
    if remembered.get("size") != stat["size"]:
        return False
    if remembered.get("mtime_ns") != stat["mtime_ns"]:
        return False
    if not isinstance(remembered.get("session_id"), str):
        return False
    if not isinstance(remembered.get("bundle_sha256"), str):
        return False
    try:
        observed_at = int(remembered.get("observed_at") or 0)
    except (TypeError, ValueError):
        return False
    return observed_at > int(stat["mtime_ns"])


def inbox_files(home: Path | str) -> list[Path]:
    """Inbox files in name order, so the result never depends on the filesystem."""
    directory = home_paths(home).session_inbox
    if not directory.is_dir():
        return []
    return sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and path.suffix == BUNDLE_SUFFIX and not path.name.startswith(".")
    )


def import_inbox(
    home: Path | str, *, registry: dict | None = None, now: str | None = None,
    authority: dict | None = None,
) -> dict[str, Any]:
    """Ingest every canonical bundle in the inbox. Returns a full report."""
    data = registry if registry is not None else load_registry()
    paths = home_paths(home)
    timestamp = now or utc_now_iso()

    status, index, detail = load_index(paths.root, registry=data)
    if status == STATUS_UNRECOVERABLE:
        raise PalError(
            "VALIDATION_FAILED",
            f"session index is unusable: {detail}",
            next_action="repair or remove .saipal/sessions/index.json by hand",
        )
    if status == STATUS_ABSENT or index is None:
        index = {"schema_version": 1, "sessions": []}

    imported: list[dict] = []
    skipped: list[dict] = []
    rejected: list[dict] = []
    conflicts: list[dict] = []
    cache = _load_cache(paths.root)
    cache_files = cache["files"]
    cache_dirty = False
    index_dirty = False

    for path in inbox_files(paths.root):
        source_ref = f"session_inbox/{path.name}"
        stat = _stat_key(path)
        remembered = cache_files.get(path.name)
        if (
            stat is not None
            and _trustworthy(remembered, stat)
            and already_imported(
                records_for_session(index, remembered["session_id"]),
                remembered["bundle_sha256"],
            )
        ):
            # Same bytes as last time, and that content is already indexed. There
            # is nothing this file can contribute, so it is not read at all.
            skipped.append({"source_ref": source_ref, "reason": "duplicate digest"})
            continue

        try:
            bundle, bundle_sha256 = bundle_mod.load_bundle_with_digest(
                path, registry=data
            )
        except PalError as exc:
            rejected.append(
                {"source_ref": source_ref, "code": exc.code, "reason": exc.message}
            )
            continue

        session_id = bundle["session_id"]
        if stat is not None:
            cache_files[path.name] = {
                **stat,
                "session_id": session_id,
                "bundle_sha256": bundle_sha256,
                "observed_at": time.time_ns(),
            }
            cache_dirty = True
        generations = records_for_session(index, session_id)
        existing = generations[-1] if generations else None

        if existing is None:
            record = _create(index, bundle, source_ref, path, bundle_sha256, timestamp, data, authority=authority)
            index["sessions"].append(record)
            imported.append(_report(record, "new-session"))
            index_dirty = True
            continue

        # Dedupe BEFORE any generation decision, and across every generation:
        # a digest that already produced generation 2 must not produce a third.
        if already_imported(generations, bundle_sha256):
            skipped.append({"source_ref": source_ref, "reason": "duplicate digest"})
            continue

        if bundle["temperature"] == "COLD":
            record = _create(index, bundle, source_ref, path, bundle_sha256, timestamp, data, authority=authority)
            index["sessions"].append(record)
            imported.append(_report(record, "new-generation"))
            index_dirty = True
            continue

        outcome = _extend_hot(existing, bundle, source_ref, path, bundle_sha256, timestamp, data)
        index_dirty = True
        if outcome["conflict"]:
            conflicts.append(outcome["entry"])
        else:
            imported.append(outcome["entry"])

    # An unchanged inbox is a no-op: rewriting the session index after a pass that
    # decided nothing was the same amplification (PERF-002/PERF-004).
    if index_dirty:
        save_index(paths.root, index, registry=data)
    if cache_dirty:
        _save_cache(paths.root, cache, registry=data)

    return {
        "imported": imported,
        "skipped": skipped,
        "rejected": rejected,
        "conflicts": conflicts,
        "sessions_total": len(index["sessions"]),
        "new_sessions": len(imported),
        "hot": sum(1 for r in index["sessions"] if r["temperature"] == "HOT"),
        "cold": sum(1 for r in index["sessions"] if r["temperature"] == "COLD"),
        "conflicted": sum(1 for r in index["sessions"] if r["status"] == "CONFLICT"),
    }


def _create(
    index: dict,
    bundle: dict,
    source_ref: str,
    path: Path,
    bundle_sha256: str,
    timestamp: str,
    registry: dict,
    *,
    authority=None,
) -> dict:
    generation = latest_generation(index, bundle["session_id"]) + 1
    return new_record(
        bundle,
        source_ref=source_ref,
        source_sha256=sha256_file(path),
        bundle_sha256=bundle_sha256,
        generation=generation,
        imported_at=timestamp,
        episodes=episodes_mod.extract_episodes(
            bundle_mod.events_of(bundle), registry=registry
        ),
        authority=authority,
        registry=registry,
    )


def _extend_hot(
    record: dict,
    bundle: dict,
    source_ref: str,
    path: Path,
    bundle_sha256: str,
    timestamp: str,
    registry: dict,
) -> dict:
    """Grow a hot session, or freeze it in CONFLICT -- never continue silently."""
    events = bundle_mod.events_of(bundle)
    watermark = int(record["last_analyzed_seq"])
    observed_prefix = bundle_mod.prefix_digest(bundle, watermark)
    expected_prefix = record.get("prefix_sha256")

    if watermark > 0 and expected_prefix and observed_prefix != expected_prefix:
        record["status"] = "CONFLICT"
        record["conflict"] = {
            "detected_at": timestamp,
            "reason": "the already-analyzed prefix changed under a stable watermark",
            "last_analyzed_seq": watermark,
            "expected_prefix_sha256": expected_prefix,
            "observed_prefix_sha256": observed_prefix,
            "source_ref": source_ref,
        }
        return {
            "conflict": True,
            "entry": {
                "session_id": record["session_id"],
                "generation": record["generation"],
                "source_ref": source_ref,
                "status": "CONFLICT",
                "reason": record["conflict"]["reason"],
            },
        }

    record["source_ref"] = source_ref
    record["provider_source_ref"] = bundle.get("raw_source_ref")
    record["source_sha256"] = sha256_file(path)
    record["bundle_sha256"] = bundle_sha256
    record["event_count"] = len(events)
    record["prefix_sha256"] = observed_prefix
    record["updated_at"] = timestamp
    record["episodes"] = episodes_mod.extract_episodes(events, registry=registry)
    record.pop("mechanical_spans", None)
    record["evidence_refs"] = [
        {"seq": event["seq"], "evidence_ref": event["evidence_ref"]}
        for event in events
        if event.get("evidence_ref") is not None
    ]
    record["imports"].append(
        {
            "source_ref": source_ref,
            "sha256": bundle_sha256,
            "generation": record["generation"],
            "imported_at": timestamp,
        }
    )
    if len(events) > watermark:
        # the analyzed tail grew; clear the exhausted flag so the pipeline
        # re-analyzes the new events (the prefix stays frozen by watermark).
        record["analysis"] = {
            "episodes_exhausted": False,
            "last_analyzed_at": None,
            "analyzed_up_to_seq": watermark,
            "next_episode_index": 0,
        }
        semantic = record.get("semantic")
        semantic = dict(semantic) if isinstance(semantic, dict) else {}
        # New episodes arrived, so semantic exhaustion is no longer true. The
        # semantic position itself is preserved: the analyst already covered
        # those episodes and must not be asked to re-reason over them.
        semantic["exhausted"] = False
        record["semantic"] = semantic
    problems = validate_index(
        {"schema_version": 1, "sessions": [record]}, registry=registry
    )
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "refusing to record an invalid session: " + "; ".join(problems),
            next_action="the existing index was left untouched",
        )
    return {
        "conflict": False,
        "entry": {
            "session_id": record["session_id"],
            "generation": record["generation"],
            "source_ref": source_ref,
            "status": record["status"],
            "events": len(events),
        },
    }


def _report(record: dict, outcome: str) -> dict:
    return {
        "session_id": record["session_id"],
        "generation": record["generation"],
        "source_ref": record["source_ref"],
        "status": record["status"],
        "outcome": outcome,
        "events": record["event_count"],
    }
