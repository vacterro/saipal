"""Binding coverage diagnostics (T-102): WHY the corpus is not fully BOUND.

A read-only planner. It never rebinds, never writes, never probes authority
roots with side effects: it classifies the CURRENT binding state of every
indexed session into the reason that blocks it from being BOUND and groups
the blockers with counts and representative session ids. The operator should
learn in one screen whether enrollment/rebind can actually unlock work.

Reason classes (closed set):
- TRUSTED_AUTHORITY_ABSENT: no authority root is declared at all
- LEGACY_UNPINNED: a root is declared but carries no pinning record (T-100)
- IDENTITY_ABSENT: the protocol block carries no historical identity claim
- MALFORMED_CLAIM: an identity claim is present but not defensible (bad hex,
  missing version)
- AUTHORITY_UNREADABLE: a claim exists and an authority root is configured,
  but the authority could not verify it (missing release material, unreadable
  snapshot tree)
- COMMIT_UNVERIFIED: a full commit id is claimed but no authority could
  resolve the object
- CONFLICT_SESSION: the session is in a CONFLICT state (binding work must not
  churn it)
- OTHER: unknown-shape fallback so a new reason never hides inside a big
  unnamed bucket

Every session blocked from BOUND with a recoverable reason is reported with
its recoverability class, so the operator knows whether enrollment + rebind
can actually fix it.
"""

from __future__ import annotations

from pathlib import Path

from . import carrier as carrier_mod
from . import sessions as sessions_mod
from .config import load_config, protocol_authority
from .errors import PalError
from .registry import load_registry
from .sessions import load_index

BLOCKER_REASONS = (
    "TRUSTED_AUTHORITY_ABSENT",
    "LEGACY_UNPINNED",
    "IDENTITY_ABSENT",
    "MALFORMED_CLAIM",
    "AUTHORITY_UNREADABLE",
    "COMMIT_UNVERIFIED",
    "CONFLICT_SESSION",
    "OTHER",
)

RECOVERABLE = frozenset(
    {
        "TRUSTED_AUTHORITY_ABSENT",
        "LEGACY_UNPINNED",
        "AUTHORITY_UNREADABLE",
        "COMMIT_UNVERIFIED",
    }
)

#: Representative session ids per reason shown by default (never hundreds).
SAMPLE_LIMIT = 5


def _authority_shape(home: Path) -> tuple[dict, list[str]]:
    """(declared roots, kinds configured but not backed by a pin)."""
    _status, config, _detail = load_config(home)
    declared = protocol_authority(home, config if isinstance(config, dict) else None) or {}
    configured = [
        kind
        for kind, value in declared.items()
        if value
    ]
    # T-100 will gate on pinning; until it lands, treat any declared root as
    # present and let LEGACY_UNPINNED classify homes whose pinning record is
    # missing entirely.
    return declared, configured


def _per_kind_trust(home: Path) -> dict[str, str]:
    """TRUSTED / LEGACY_UNPINNED / ABSENT per authority kind (T-114).

    One pinned kind must never make another configured-but-unpinned root
    appear trusted, and LEGACY_UNPINNED is derived PER KIND from that kind's
    own pinning record -- never from "at least one pin exists somewhere".
    """
    _status, config, _detail = load_config(home)
    declared = protocol_authority(home, config if isinstance(config, dict) else None) or {}
    try:
        from .authority import load_pinning

        roots = (load_pinning(home).get("roots") or {})
    except PalError:
        roots = {}
    trust: dict[str, str] = {}
    for kind in ("git_repository", "release_root", "snapshot_root"):
        if not declared.get(kind):
            trust[kind] = "ABSENT"
        elif kind in roots and str(roots[kind].get("canonical_path") or "") == str(declared.get(kind)):
            trust[kind] = "TRUSTED"
        else:
            trust[kind] = "LEGACY_UNPINNED"
    return trust


def _classify(record: dict, *, authority_declared: bool, trust: dict[str, str]) -> str:
    protocol = record.get("protocol")
    if record.get("status") == "CONFLICT":
        return "CONFLICT_SESSION"
    if not isinstance(protocol, dict):
        return "IDENTITY_ABSENT"
    has_commit = bool(str(protocol.get("git_head") or "").strip())
    has_version = bool(str(protocol.get("version") or "").strip())
    has_registry = bool(str(protocol.get("registry_sha256") or "").strip())
    has_tree = bool(str(protocol.get("tree_fingerprint") or "").strip())
    if not (has_commit or has_version or has_registry or has_tree):
        return "IDENTITY_ABSENT"
    from .sessions import _FULL_GIT_OBJECT_ID, _SHA256

    if has_commit and not _FULL_GIT_OBJECT_ID.fullmatch(str(protocol.get("git_head"))):
        return "MALFORMED_CLAIM"
    if has_registry and not _SHA256.fullmatch(str(protocol.get("registry_sha256"))):
        return "MALFORMED_CLAIM"
    if has_tree and not _SHA256.fullmatch(str(protocol.get("tree_fingerprint"))):
        return "MALFORMED_CLAIM"
    # Per-KIND trust (T-114): a git-commit claim needs a TRUSTED git root; a
    # release/snapshot claim needs that kind trusted. One pinned kind never
    # covers another configured-but-unpinned root.
    if has_commit:
        if trust.get("git_repository") == "TRUSTED":
            return "COMMIT_UNVERIFIED"
        if trust.get("git_repository") == "LEGACY_UNPINNED":
            return "LEGACY_UNPINNED"
        return "TRUSTED_AUTHORITY_ABSENT"
    if trust.get("release_root") == "TRUSTED" or trust.get("snapshot_root") == "TRUSTED":
        return "AUTHORITY_UNREADABLE"
    if "LEGACY_UNPINNED" in trust.values():
        return "LEGACY_UNPINNED"
    _ = authority_declared
    return "TRUSTED_AUTHORITY_ABSENT"


def binding_blockers(
    home: Path | str,
    *,
    registry: dict | None = None,
    index: dict | None = None,
) -> dict:
    """Read-only aggregation: which reasons keep sessions from being BOUND."""
    root = Path(home)
    registry = registry if registry is not None else load_registry()
    if index is None:
        index_status, index, index_detail = load_index(root, registry=registry)
        if index_status == sessions_mod.STATUS_UNRECOVERABLE:
            raise PalError(
                "VALIDATION_FAILED", f"session index is unusable: {index_detail}"
            )
    groups: dict[str, list[str]] = {reason: [] for reason in BLOCKER_REASONS}
    counts = {
        "current_sessions_total": 0,
        "bound": 0,
        "partial": 0,
        "unknown": 0,
    }
    _declared, configured = _authority_shape(root)
    trust = _per_kind_trust(root)
    authority_declared = bool(configured)

    for record in carrier_mod.freshest_records(index or {}):
        counts["current_sessions_total"] += 1
        protocol = record.get("protocol") or {}
        status = str(protocol.get("binding_status") or "UNKNOWN")
        if status == "BOUND":
            counts["bound"] += 1
            continue
        counts["partial" if status == "PARTIAL" else "unknown"] += 1
        reason = _classify(record, authority_declared=authority_declared, trust=trust)
        groups[reason].append(str(record.get("session_id") or ""))

    blockers = []
    for reason in BLOCKER_REASONS:
        ids = groups[reason]
        if not ids:
            continue
        blockers.append(
            {
                "reason": reason,
                "count": len(ids),
                "representative_sessions": sorted(ids)[:SAMPLE_LIMIT],
                "recoverable": reason in RECOVERABLE,
            }
        )
    blockers.sort(key=lambda row: (-row["count"], row["reason"]))
    return {
        "binding_blockers": True,
        "ok": True,
        "read_only": True,
        "counts": counts,
        "blockers": blockers,
        "recoverable_blocked": sum(
            row["count"] for row in blockers if row["recoverable"]
        ),
        "authority_trust_by_kind": trust,
        "note": (
            "counts describe the CURRENT (freshest generation per session) "
            "population, not all indexed records/generations; recoverable "
            "blockers are unlockable by enrolling/pinning the per-kind "
            "authority and rebinding; IDENTITY_ABSENT/MALFORMED sessions "
            "cannot be fixed by rebind alone"
        ),
    }
