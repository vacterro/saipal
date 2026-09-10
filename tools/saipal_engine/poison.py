"""T-106 operational poison-artifact quarantine (ROLE 28).

A source artifact whose bytes are rejected again and again is an operational
hazard, not semantic evidence: every cycle pays a full normalize+validate for
a verdict already known. The quarantine records the identity of the poison
(source_id, session_id, raw-source digest, rejection class) and lets the
dispatcher skip the reparse while the artifact stays byte-identical. A
material source change (new bytes) makes it eligible again immediately.

The quarantine NEVER deletes, mutates or reclassifies a source; it never
touches semantic verdicts; it is durable operational bookkeeping keyed by the
same identity the dispatcher already stages.
"""

from __future__ import annotations

import time
from pathlib import Path

from .capability import require_action
from .errors import PalError
from .paths import atomic_write_json, home_paths, read_json

POISON_NAME = "poison_quarantine.json"
SCHEMA_VERSION = 1

#: How many consecutive identical rejections before the artifact stops being
#: reparsed. One rejection is observed, not quarantined: a single malformed
#: write must not suppress a fix that lands one cycle later.
QUARANTINE_THRESHOLD = 2


def poison_path(home: Path | str) -> Path:
    return home_paths(home).root / POISON_NAME


def fresh_poison() -> dict:
    return {"schema_version": SCHEMA_VERSION, "artifacts": {}}


def _valid(payload) -> bool:
    return (
        isinstance(payload, dict)
        and payload.get("schema_version") == SCHEMA_VERSION
        and isinstance(payload.get("artifacts"), dict)
    )


def load_poison(home: Path | str) -> dict:
    path = poison_path(home)
    if not path.exists():
        return fresh_poison()
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError):
        # A corrupt quarantine must never hide evidence: fail open to
        # reparsing everything.
        return fresh_poison()
    if not _valid(payload):
        return fresh_poison()
    return payload


def _save_poison(home: Path | str, payload: dict, *, registry=None) -> None:
    require_action("write_own_index", registry=registry)
    atomic_write_json(poison_path(home), payload, root=home_paths(home).root)


def _identity(source_id: str, session_id: str, raw_source_sha256: str) -> str:
    return f"{source_id}::{session_id}::{raw_source_sha256}"


def record_rejected_artifact(
    home: Path | str,
    *,
    source_id: str,
    session_id: str,
    raw_source_sha256: str,
    rejection_class: str,
    reason: str,
    registry=None,
) -> dict:
    """One consecutive identical rejection of one artifact identity."""
    payload = load_poison(home)
    key = _identity(str(source_id or ""), str(session_id or ""), str(raw_source_sha256 or ""))
    entry = payload["artifacts"].setdefault(key, {
        "source_id": str(source_id or ""),
        "session_id": str(session_id or ""),
        "raw_source_sha256": str(raw_source_sha256 or ""),
        "rejection_class": str(rejection_class or "REJECTED"),
        "reason": str(reason or "")[:200],
        "count": 0,
        "first_seen": "",
        "last_seen": "",
    })
    entry["count"] = int(entry["count"] or 0) + 1
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    entry["last_seen"] = now
    if not entry["first_seen"]:
        entry["first_seen"] = now
    entry["quarantined"] = int(entry["count"] or 0) >= QUARANTINE_THRESHOLD
    _save_poison(home, payload, registry=registry)
    return entry


def quarantine_state(
    home: Path | str,
    *,
    source_id: str,
    session_id: str,
    raw_source_sha256: str,
) -> dict:
    """Is this exact artifact identity quarantined, released, or unknown?

    A material source change (new bytes) releases the quarantine: the artifact
    is eligible for intake again, and the old verdict no longer describes it.
    """
    payload = load_poison(home)
    key = _identity(str(source_id or ""), str(session_id or ""), str(raw_source_sha256 or ""))
    entry = payload["artifacts"].get(key)
    if not isinstance(entry, dict):
        return {"quarantined": False, "reason": "no recorded rejection"}
    if entry.get("quarantined"):
        return {
            "quarantined": True,
            "count": int(entry.get("count") or 0),
            "rejection_class": entry.get("rejection_class"),
            "reason": entry.get("reason"),
        }
    return {"quarantined": False, "count": int(entry.get("count") or 0)}


def release_changed_artifact(
    home: Path | str,
    *,
    source_id: str,
    session_id: str,
    raw_source_sha256: str,
    registry=None,
) -> bool:
    """Drop the quarantine entry when the artifact's bytes changed (ROLE 28).

    A material source change makes the artifact eligible again. Returns True
    when an entry was released.
    """
    payload = load_poison(home)
    key = _identity(str(source_id or ""), str(session_id or ""), str(raw_source_sha256 or ""))
    entry = payload["artifacts"].get(key)
    if not isinstance(entry, dict):
        return False
    payload["artifacts"].pop(key)
    _save_poison(home, payload, registry=registry)
    return True