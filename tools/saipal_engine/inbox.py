"""Generic session intake (PAL-SESSION-04).

Deterministic, provider-neutral, and forgiving of a bad export: a broken bundle
is reported and skipped, never partially ingested and never repaired. Nothing is
ever deleted from the inbox -- SAIPAL observes, it does not clean up after the
operator.
"""

from __future__ import annotations

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
    find_session,
    latest_generation,
    load_index,
    new_record,
    save_index,
    validate_index,
)

BUNDLE_SUFFIX = ".json"


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

    for path in inbox_files(paths.root):
        source_ref = f"session_inbox/{path.name}"
        try:
            bundle = bundle_mod.load_bundle_file(path, registry=data)
        except PalError as exc:
            rejected.append(
                {"source_ref": source_ref, "code": exc.code, "reason": exc.message}
            )
            continue

        bundle_sha256 = bundle_mod.bundle_digest(bundle)
        session_id = bundle["session_id"]
        existing = find_session(index, session_id)

        if existing is None:
            record = _create(index, bundle, source_ref, path, bundle_sha256, timestamp, data, authority=authority)
            index["sessions"].append(record)
            imported.append(_report(record, "new-session"))
            continue

        if already_imported(existing, bundle_sha256):
            skipped.append({"source_ref": source_ref, "reason": "duplicate digest"})
            continue

        if bundle["temperature"] == "COLD":
            record = _create(index, bundle, source_ref, path, bundle_sha256, timestamp, data, authority=authority)
            index["sessions"].append(record)
            imported.append(_report(record, "new-generation"))
            continue

        outcome = _extend_hot(existing, bundle, source_ref, path, bundle_sha256, timestamp, data)
        if outcome["conflict"]:
            conflicts.append(outcome["entry"])
        else:
            imported.append(outcome["entry"])

    save_index(paths.root, index, registry=data)

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
    record["mechanical_spans"] = episodes_mod.mechanical_spans(events)
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
