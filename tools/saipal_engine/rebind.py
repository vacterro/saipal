"""Deterministic historical rebinding of indexed sessions (T-87).

Sessions imported while an authority root was null carry PARTIAL/UNKNOWN
bindings that later enrollment can strengthen. `rebind` recomputes ONLY the
historical binding proof from the existing protocol identity claims plus the
now-enrolled authority: evidence identity, provider digests, episodes,
receipts and cursors are preserved verbatim. Only a STRENGTHENING transition
writes (UNKNOWN->PARTIAL, UNKNOWN->BOUND, PARTIAL->BOUND); a BOUND record
becoming weaker is a serious authority event -- recorded, never applied.

Rebinding a session to BOUND makes its BLOCKED_BINDING analyst jobs eligible
automatically: the worker allocator inspects CURRENT binding at scan time, so
no journal surgery and no re-import is required.
"""

from __future__ import annotations

import time
from pathlib import Path

from saipal_engine import sessions as sessions_mod
from saipal_engine.config import load_config, protocol_authority
from saipal_engine.errors import PalError
from saipal_engine.registry import load_registry
from saipal_engine.sessions import load_index, save_index

STRENGTHENING = {
    ("UNKNOWN", "PARTIAL"),
    ("UNKNOWN", "BOUND"),
    ("PARTIAL", "BOUND"),
}

BINDING_ORDER = {"UNKNOWN": 0, "PARTIAL": 1, "BOUND": 2}

CHECKPOINT_SCHEMA_VERSION = 2
CHECKPOINT_NAME = "rebind_checkpoint.json"

#: The closed checkpoint schema (T-101 r27/r29). Unknown fields are invalid,
#: never silently ignored; a corrupt or future checkpoint is a LOUD state
#: condition, not "never reconciled".
CHECKPOINT_FIELDS = (
    "schema_version",
    "authority_fingerprint",
    "index_generation_digest",
    "reconciled_at",
)

_HEX16 = None


def _checkpoint_problems(payload: object) -> list[str]:
    import re

    global _HEX16
    if _HEX16 is None:
        _HEX16 = re.compile(r"^[0-9a-f]{16}$")
    if not isinstance(payload, dict):
        return ["checkpoint root is not an object"]
    if payload.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
        return [
            f"schema_version must be {CHECKPOINT_SCHEMA_VERSION} "
            f"(got {payload.get('schema_version')!r}); MIGRATION_REQUIRED"
        ]
    for key in sorted(set(payload) - set(CHECKPOINT_FIELDS)):
        return [f"unknown checkpoint field {key!r}"]
    fingerprint = payload.get("authority_fingerprint")
    if fingerprint is not None and not (
        isinstance(fingerprint, str) and _HEX16.fullmatch(fingerprint)
    ):
        return ["authority_fingerprint must be a 16-hex digest or null"]
    digest = payload.get("index_generation_digest")
    if digest is not None and not (
        isinstance(digest, str) and _HEX16.fullmatch(digest)
    ):
        return ["index_generation_digest must be a 16-hex digest or null"]
    reconciled = payload.get("reconciled_at")
    if reconciled is not None and not isinstance(reconciled, str):
        return ["reconciled_at must be a timestamp string or null"]
    return []


def checkpoint_path(home: Path | str) -> Path:
    """Operational checkpoint OUTSIDE supervisor state (T-101 rule 27).

    The 'bindings were reconciled against fingerprint X' fact must survive
    supervisor-state loss: it lives beside the indexed forensic state, not in
    the supervisor's own runtime checkpoint.
    """
    return _home_root(home) / CHECKPOINT_NAME


def _home_root(home: Path | str) -> Path:
    from saipal_engine.paths import home_paths

    return home_paths(home).root


def load_checkpoint(home: Path | str) -> dict:
    """Load the reconciliation checkpoint; corrupt state is a LOUD refusal.

    T-101 r28/r29: unreadable JSON or an invalid shape used to silently
    return a fresh checkpoint, reinterpreting corruption as "never
    reconciled" -- evidence of prior reconciliation destroyed by the very
    reader meant to trust it. Now the payload is validated as a CLOSED
    schema and a corrupt checkpoint raises; callers that must stay read-only
    use `checkpoint_status` instead.
    """
    from saipal_engine.errors import PalError
    from saipal_engine.paths import read_json

    path = _home_root(home) / CHECKPOINT_NAME
    if not path.exists():
        return fresh_checkpoint()
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise PalError(
            "VALIDATION_FAILED",
            f"rebind checkpoint is unreadable: {exc}",
            next_action="repair or remove .saipal/rebind_checkpoint.json by hand; "
                        "it is evidence of prior reconciliation and is never "
                        "silently reset",
        ) from None
    problems = _checkpoint_problems(payload)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "rebind checkpoint is invalid: " + "; ".join(problems),
            next_action="repair or migrate .saipal/rebind_checkpoint.json by hand",
        )
    return payload


def checkpoint_status(home: Path | str) -> dict:
    """READ-ONLY checkpoint health for status surfaces (r29).

    Reports OK/INVALID/MIGRATION_REQUIRED without writing anything; mutating
    startup paths must refuse via `load_checkpoint` instead.
    """
    from saipal_engine.paths import read_json

    path = _home_root(home) / CHECKPOINT_NAME
    if not path.exists():
        return {"state": "ABSENT"}
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return {"state": "INVALID", "detail": f"unreadable: {exc}", "wrote": False}
    problems = _checkpoint_problems(payload)
    if problems:
        if any("MIGRATION_REQUIRED" in p for p in problems):
            return {"state": "MIGRATION_REQUIRED", "detail": "; ".join(problems), "wrote": False}
        return {"state": "INVALID", "detail": "; ".join(problems), "wrote": False}
    return {"state": "OK", "checkpoint": payload, "wrote": False}


def fresh_checkpoint() -> dict:
    return {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "authority_fingerprint": None,
        "index_generation_digest": None,
        "reconciled_at": None,
    }


def save_checkpoint(home: Path | str, checkpoint: dict) -> Path:
    from saipal_engine.errors import PalError
    from saipal_engine.paths import atomic_write_json

    checkpoint = dict(checkpoint)
    checkpoint["schema_version"] = CHECKPOINT_SCHEMA_VERSION
    checkpoint.setdefault("index_generation_digest", None)
    checkpoint["reconciled_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    problems = _checkpoint_problems(checkpoint)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "refusing invalid rebind checkpoint: " + "; ".join(problems),
        )
    return atomic_write_json(
        _home_root(home) / CHECKPOINT_NAME, checkpoint, root=_home_root(home)
    )


def index_generation_digest(home: Path | str, *, index: dict | None = None) -> str:
    """The identity of the RELEVANT binding inputs in the session index (r27).

    Hashes only the fields the NEXT reconciliation consumes as INPUT -- the
    session ids and their historical identity CLAIMS (not the derived
    binding_status, which rebind itself writes) -- over the FRESHEST
    generation per session. Ordinary semantic receipts change no binding
    input and never churn the checkpoint; new sessions and changed claims
    do.
    """
    import hashlib

    from . import carrier as carrier_mod

    if index is None:
        index_status, index, _detail = __import__(
            "saipal_engine.sessions", fromlist=["load_index"]
        ).load_index(home)
        if index is None:
            index = {}
    rows: list[str] = []
    for record in carrier_mod.freshest_records(index or {}):
        session_id = str(record.get("session_id") or "")
        protocol = record.get("protocol") or {}
        claim = "|".join(
            str(protocol.get(key) or "")
            for key in (
                "git_head", "version", "registry_sha256", "tree_fingerprint",
            )
        )
        rows.append(f"{session_id}::{claim}")
    rows.sort()
    material = "\n".join(rows).encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:16]


def _aggregate_release_identity(base: Path) -> str:
    """The COMPLETE release index identity (T-101 r23).

    Every existing release contributes its name AND its registry digest, so
    mutating a NON-max release's registry under the same directory name
    changes the aggregate. The old `digests[-1]`-only scheme missed exactly
    that (verified collision: A mutates below B's high hash, fingerprint
    unchanged, authority materially changed and invisible).
    """
    import hashlib

    rows: list[str] = []
    try:
        children = sorted(child for child in base.iterdir() if child.is_dir())
    except OSError:
        children = []
    for child in children:
        registry = child / "saipal" / "REGISTRY.json"
        if not registry.is_file():
            continue
        try:
            digest = hashlib.sha256(registry.read_bytes()).hexdigest()
        except OSError:
            digest = "unreadable"
        rows.append(f"{child.name}={digest}")
    return ",".join(rows) if rows else "none"


def _aggregate_snapshot_identity(base: Path) -> str:
    """Per-snapshot CONTENT identity, deterministically aggregated (r24).

    A snapshot changing under the same name must be visible. If a snapshot
    already carries a cheap tree fingerprint (a registry digest beside its
    protocol tree), use it; otherwise hash the snapshot's protocol surface
    files (bounded: names + digests of files under saipal/), never arbitrary
    huge trees.
    """
    import hashlib

    rows: list[str] = []
    try:
        children = sorted(child for child in base.iterdir() if child.is_dir())
    except OSError:
        children = []
    for child in children:
        registry = child / "saipal" / "REGISTRY.json"
        if registry.is_file():
            try:
                digest = hashlib.sha256(registry.read_bytes()).hexdigest()
            except OSError:
                digest = "unreadable"
            rows.append(f"{child.name}={digest}")
            continue
        # No registry: digest the snapshot's protocol surface file identities
        # (names + content digests), deterministically sorted.
        pieces: list[str] = []
        surface = child / "saipal"
        try:
            for path in sorted(p for p in surface.rglob("*") if p.is_file()):
                try:
                    piece = f"{path.relative_to(child).as_posix()}:{hashlib.sha256(path.read_bytes()).hexdigest()}"
                except OSError:
                    piece = f"{path.relative_to(child).as_posix()}:unreadable"
                pieces.append(piece)
        except OSError:
            pieces = []
        rows.append(f"{child.name}={'|'.join(pieces) if pieces else 'empty'}")
    return ";".join(rows) if rows else "none"


def material_fingerprint(home: Path | str, *, registry: dict | None = None) -> str:
    """Cheap deterministic fingerprint of the authority MATERIAL (T-101 r24).

    The old supervisor digest hashed only the configured path STRINGS, so a
    repository advancing under the same path (new HEAD, new release, new
    snapshot) was invisible and rebind never ran. This fingerprint captures
    the state of the material inside the TRUSTED roots (T-100):

    - git_repository: the COMMITTED HEAD identity (cheap `git rev-parse`);
      uncommitted worktree churn never rebinds (r25);
    - release_root: the COMPLETE release index -- every release's name and
      registry digest, sorted (r23) -- never one max digest;
    - snapshot_root: per-snapshot content identity, aggregated (r24).

    It never hashes a whole repository. Trust-root identity (the configured
    path) is reported SEPARATELY from the material state inside it.
    """
    import hashlib

    from saipal_engine.authority import (
        _git_head,
        _registry_fingerprint,
        trusted_protocol_authority,
    )

    root = Path(home)
    trust = trusted_protocol_authority(root)
    parts: list[str] = []
    for kind in ("git_repository", "release_root", "snapshot_root"):
        record = trust.get(kind) or {}
        state = str(record.get("state") or "ABSENT")
        configured = record.get("configured_root")
        if state == "ABSENT" or not configured:
            parts.append(f"{kind}=absent:{state}")
            continue
        # The trust identity: state + canonical root. A configured root that
        # is not TRUSTED still fingerprints its OBSERVED state (so an enroll
        # that changes state is visible), but only TRUSTED material is hashed.
        if state != "TRUSTED":
            parts.append(f"{kind}={state}")
            continue
        base = Path(str(configured))
        registry_sha, _present = _registry_fingerprint(base, kind)
        if kind == "git_repository":
            # Committed HEAD only: an unrelated uncommitted file must not
            # churn the fingerprint every cycle (r25).
            head = _git_head(base)
            parts.append(f"{kind}=head:{head or 'none'}")
        elif kind == "release_root":
            parts.append(f"{kind}=releases:{_aggregate_release_identity(base)}")
        else:  # snapshot_root
            parts.append(f"{kind}=snapshots:{_aggregate_snapshot_identity(base)}")
        parts.append(f"{kind}=registry:{registry_sha or 'none'}")
    material = "\n".join(parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def rebind(
    home: Path | str,
    *,
    registry: dict | None = None,
    authority: dict | None = None,
    dry_run: bool = False,
) -> dict:
    """One deterministic pass over every indexed session record.

    T-100: historical strengthening uses only TRUSTED authority roots. A
    configured root without a matching pin is LEGACY_UNPINNED -- visible in
    the report and fail-closed: it can never strengthen UNKNOWN/PARTIAL to
    BOUND. Existing BOUND evidence is preserved (a BOUND record is never
    re-derived from a weaker present authority; it is skipped as unchanged).

    CORE-001 (SRC-004 ROLE 15-17): rebind is a session-index mutation, so the
    CANONICAL boundary takes the common writer fence here, reentrantly. The
    supervisor's intake section and the CLI share one invariant automatically;
    a direct library caller cannot bypass the fence by skipping the CLI. The
    dry-run pass is read-only and stays unfenced.
    """
    root = Path(home)
    if dry_run:
        return _rebind_locked(
            root, registry=registry, authority=authority, dry_run=True
        )
    from saipal_engine.paths import writer_fence

    with writer_fence(root):
        return _rebind_locked(
            root, registry=registry, authority=authority, dry_run=False
        )


def _rebind_locked(
    root: Path,
    *,
    registry: dict | None,
    authority: dict | None,
    dry_run: bool,
) -> dict:
    registry = registry if registry is not None else load_registry()
    _status, config, detail = load_config(root)
    if not isinstance(config, dict):
        raise PalError("VALIDATION_FAILED", f"config.json is unusable: {detail}")

    index_status, index, index_detail = load_index(root, registry=registry)
    if index_status == sessions_mod.STATUS_UNRECOVERABLE:
        raise PalError("VALIDATION_FAILED", f"session index is unusable: {index_detail}")
    if index is None:
        # Nothing imported yet: no record can rebind.
        return {
            "rebind": True,
            "ok": True,
            "scanned": 0,
            "unchanged": 0,
            "unknown_to_partial": 0,
            "unknown_to_bound": 0,
            "partial_to_bound": 0,
            "suspicious_downgrades": [],
            "errors": [],
            "newly_eligible_units": 0,
            "upgraded_sessions": 0,
            "dry_run": bool(dry_run),
        }

    report = {
        "rebind": True,
        "ok": True,
        "scanned": 0,
        "unchanged": 0,
        "unknown_to_partial": 0,
        "unknown_to_bound": 0,
        "partial_to_bound": 0,
        "suspicious_downgrades": [],
        "errors": [],
        "newly_eligible_units": 0,
        "dry_run": bool(dry_run),
    }
    upgraded_sessions = 0
    legacy_unpinned_kinds: list[str] = []
    trusted_roots: dict[str, str] = {}

    # T-100: only TRUSTED roots may drive strengthening. The raw configured
    # authority stays observable; the trusted accessor decides what binds.
    if authority is None:
        try:
            from .authority import TRUST_LEGACY_UNPINNED, trusted_protocol_authority

            trust = trusted_protocol_authority(root)
            trusted_roots = {
                kind: str(record["configured_root"])
                for kind, record in trust.items()
                if record["state"] == "TRUSTED"
            }
            legacy_unpinned_kinds = [
                kind
                for kind, record in trust.items()
                if record["state"] == TRUST_LEGACY_UNPINNED
            ]
            authority = trust_to_authority(trusted_roots)
        except PalError:
            raise
    else:
        # An explicitly injected authority (tests) is used as-is: the caller
        # owns that decision, exactly as before T-100.
        pass

    for record in index.get("sessions") or []:
        report["scanned"] += 1
        session_id = str(record.get("session_id") or "")
        protocol = record.get("protocol")
        if not isinstance(protocol, dict):
            report["errors"].append({"session_id": session_id, "detail": "record has no protocol block"})
            continue
        try:
            proof = sessions_mod.binding_proof_of(
                protocol, authority=authority, registry=registry
            )
        except PalError as exc:
            report["errors"].append({"session_id": session_id, "detail": str(exc.message or exc)})
            continue

        old_status = str(protocol.get("binding_status") or "UNKNOWN")
        new_status = str(proof["binding_status"])
        if old_status == "BOUND" and new_status != "BOUND":
            # T-100 rule 20: existing BOUND evidence from previously accepted
            # proof is PRESERVED -- a missing/offline/legacy-unpinned current
            # authority never silently downgrades accepted forensic proof.
            report["unchanged"] += 1
            continue
        if old_status == new_status:
            report["unchanged"] += 1
            continue
        transition = (old_status, new_status)
        if transition not in STRENGTHENING:
            report["suspicious_downgrades"].append(
                {
                    "session_id": session_id,
                    "from": old_status,
                    "to": new_status,
                    "detail": proof["reason"],
                }
            )
            continue
        if dry_run:
            report["unchanged"] += 0  # counted as a prospective upgrade below
        else:
            protocol["binding_status"] = proof["binding_status"]
            protocol["proof_level"] = proof["proof_level"]
            record["updated_at"] = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
            )
            record["rebind"] = {
                "from": old_status,
                "to": new_status,
                "reason": proof["reason"],
            }
        if transition == ("UNKNOWN", "PARTIAL"):
            report["unknown_to_partial"] += 1
        elif transition == ("UNKNOWN", "BOUND"):
            report["unknown_to_bound"] += 1
            upgraded_sessions += 1
        else:
            report["partial_to_bound"] += 1
            upgraded_sessions += 1

    if report["suspicious_downgrades"] and not dry_run:
        # Downgrades were recorded, never applied; save still proceeds for the
        # strengthening records.
        pass
    if not dry_run:
        save_index(root, index, registry=registry)

    # Backlog impact: units the operator gains when binding improved to BOUND.
    report["newly_eligible_units"] = _newly_eligible(root, index, registry=registry)
    report["upgraded_sessions"] = upgraded_sessions
    report["trusted_authority_kinds"] = sorted(trusted_roots)
    report["legacy_unpinned_kinds"] = sorted(legacy_unpinned_kinds)
    return report


def trust_to_authority(trusted_roots: dict[str, str]) -> dict[str, str]:
    """`{kind: root}` trusted map -> the authority dict readers consume."""
    return {kind: root for kind, root in trusted_roots.items()}


def _newly_eligible(root: Path, index: dict, *, registry: dict) -> int:
    """Pending FINAL+BOUND units after the pass (the operational number)."""
    from saipal_engine import carrier as carrier_mod

    event_limit = int(carrier_mod._limits(registry)["max_events"])
    eligible = 0
    for record in carrier_mod.freshest_records(index):
        if record.get("status") != "IMPORTED":
            continue
        state = carrier_mod.semantic_state(record)
        if state["exhausted"]:
            continue
        episodes = record.get("episodes") or []
        if state["next_episode_index"] >= len(episodes):
            continue
        episode = episodes[state["next_episode_index"]]
        protocol = record.get("protocol") or {}
        if protocol.get("binding_status") != "BOUND":
            continue
        if (
            carrier_mod.episode_finality(record, episode) == "PROVISIONAL"
            and state["tail_reviewed_digest"]
            and state["tail_reviewed_digest"]
            == carrier_mod.tail_digest(record, episode, state["next_slice_index"])
        ):
            continue
        eligible += max(1, len(episodes) - state["next_episode_index"])
    return eligible
