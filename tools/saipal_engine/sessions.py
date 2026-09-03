"""The session index: identity, generations, watermark and binding.

Identity is source identity plus digest, never a filename. A duplicate digest
is not a new session; a changed digest is a new generation of the same one.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

from . import bundle as bundle_mod
from . import episodes as episodes_mod
from .capability import require_action
from .errors import PalError
from .paths import atomic_write_json, home_paths, read_json
from .registry import load_registry, require_string_list

STATUS_OK = "ok"
STATUS_ABSENT = "absent"
STATUS_UNRECOVERABLE = "unrecoverable"

RECORD_REQUIRED = (
    "session_id",
    "generation",
    "source_ref",
    "source_sha256",
    "bundle_sha256",
    "adapter",
    "temperature",
    "project",
    "runtime",
    "protocol",
    "last_analyzed_seq",
    "prefix_sha256",
    "status",
    "event_count",
    "imported_at",
    "updated_at",
    "imports",
    "episodes",
)

_VERSION_PART = re.compile(r"\d+")
_FULL_GIT_OBJECT_ID = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")

PROOF_EXACT_COMMIT = "EXACT_COMMIT"
PROOF_RELEASE_REGISTRY = "RELEASE_REGISTRY"
PROOF_CAPTURED_FINGERPRINT = "CAPTURED_FINGERPRINT"
PROOF_INSTALLED_RELEASE = "INSTALLED_RELEASE"
PROOF_UNKNOWN = "UNKNOWN"

CommitResolver = Callable[[str], bool]


def empty_index() -> dict:
    return {"schema_version": 1, "sessions": []}


def validate_index(payload: object, *, registry: dict | None = None) -> list[str]:
    data = registry if registry is not None else load_registry()
    statuses = set(require_string_list(data, "session_status"))
    temperatures = set(require_string_list(data, "temperature_enum"))
    binding_statuses = set(require_string_list(data, "binding_status"))
    proof_levels = set(require_string_list(data, "binding_proof_levels"))

    if not isinstance(payload, dict):
        return ["session index root is not an object"]
    problems: list[str] = []
    if payload.get("schema_version") != 1:
        problems.append(f"schema_version {payload.get('schema_version')!r} != 1")
    if not isinstance(payload.get("sessions"), list):
        return problems + ["sessions must be an array"]

    seen: set[tuple[str, int]] = set()
    for position, record in enumerate(payload["sessions"]):
        where = f"sessions[{position}]"
        if not isinstance(record, dict):
            problems.append(f"{where} is not an object")
            continue
        for field in RECORD_REQUIRED:
            if field not in record:
                problems.append(f"{where} missing {field!r}")

        key = (str(record.get("session_id")), record.get("generation"))
        if key in seen:
            problems.append(f"{where} duplicates session_id/generation {key}")
        seen.add(key)

        if record.get("status") not in statuses:
            problems.append(f"{where}.status {record.get('status')!r} outside {sorted(statuses)}")
        if record.get("temperature") not in temperatures:
            problems.append(
                f"{where}.temperature {record.get('temperature')!r} outside {sorted(temperatures)}"
            )
        if not isinstance(record.get("last_analyzed_seq"), int) or isinstance(
            record.get("last_analyzed_seq"), bool
        ):
            problems.append(f"{where}.last_analyzed_seq must be an integer")
        elif record["last_analyzed_seq"] < 0:
            problems.append(f"{where}.last_analyzed_seq must not be negative")
        if not isinstance(record.get("imports"), list):
            problems.append(f"{where}.imports must be an array")
        if not isinstance(record.get("episodes"), list):
            problems.append(f"{where}.episodes must be an array")
        if "evidence_refs" in record and not isinstance(record.get("evidence_refs"), list):
            problems.append(f"{where}.evidence_refs must be an array")
        if "semantic" in record and not isinstance(record.get("semantic"), dict):
            problems.append(f"{where}.semantic must be an object")

        protocol = record.get("protocol")
        if not isinstance(protocol, dict):
            problems.append(f"{where}.protocol must be an object")
        elif protocol.get("binding_status") not in binding_statuses:
            problems.append(f"{where} binding_status outside {sorted(binding_statuses)}")
        elif protocol.get("proof_level") is not None and protocol.get("proof_level") not in proof_levels:
            problems.append(f"{where} proof_level outside {sorted(proof_levels)}")

    return problems


def load_index(
    home: Path | str, *, registry: dict | None = None
) -> tuple[str, dict | None, str]:
    """`(status, index, detail)` where status is ok / absent / unrecoverable."""
    paths = home_paths(home)
    if not paths.sessions_index.exists():
        return STATUS_ABSENT, None, ""
    try:
        payload = read_json(paths.sessions_index)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return STATUS_UNRECOVERABLE, None, f"session index is unreadable: {exc}"
    problems = validate_index(payload, registry=registry)
    if problems:
        return STATUS_UNRECOVERABLE, None, "; ".join(problems)
    return STATUS_OK, payload, ""


def save_index(home: Path | str, index: dict, *, registry: dict | None = None) -> dict:
    require_action("write_own_index", registry=registry)
    problems = validate_index(index, registry=registry)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "refusing to write an invalid session index: " + "; ".join(problems),
            next_action="the existing index was left untouched",
        )
    paths = home_paths(home)
    atomic_write_json(paths.sessions_index, index, root=paths.root)
    return index


def find_session(index: dict, session_id: str) -> dict | None:
    for record in index.get("sessions", []):
        if record.get("session_id") == session_id:
            return record
    return None


def latest_generation(index: dict, session_id: str) -> int:
    return max(
        (
            int(record.get("generation", 0))
            for record in index.get("sessions", [])
            if record.get("session_id") == session_id
        ),
        default=0,
    )


def already_imported(record: dict, bundle_sha256: str) -> bool:
    """True when this exact content was ingested before, under any filename."""
    return any(
        entry.get("sha256") == bundle_sha256 for entry in record.get("imports", [])
    )


def new_record(
    bundle: dict,
    *,
    source_ref: str,
    source_sha256: str,
    bundle_sha256: str,
    generation: int,
    imported_at: str,
    episodes: list[dict],
    authority: dict | None = None,
    registry: dict | None = None,
) -> dict:
    protocol = bundle.get("protocol") or {}
    # A bundle's own `binding_status`/`proof_level` are DECLARATIONS, never
    # persisted truth: a canonical bundle dropped straight into the inbox would
    # otherwise self-promote to BOUND and every downstream claim would rest on a
    # binding Layer A never established (PAL-BINDING-01, PAL-SESSION-03). The
    # persisted proof is always re-derived here against the operator-configured
    # authority; the declaration is kept only as a non-authoritative field.
    proof = binding_proof_of(protocol, authority=authority, registry=registry)
    return {
        "session_id": bundle["session_id"],
        "generation": generation,
        "source_ref": source_ref,
        "source_sha256": source_sha256,
        "provider_source_ref": bundle.get("raw_source_ref"),
        "bundle_sha256": bundle_sha256,
        "adapter": bundle["adapter"],
        "temperature": bundle["temperature"],
        "project": bundle.get("project") or {},
        "runtime": bundle.get("runtime") or {},
        "protocol": {
            "git_head": protocol.get("git_head"),
            "version": protocol.get("version"),
            "registry_sha256": protocol.get("registry_sha256"),
            "tree_fingerprint": protocol.get("tree_fingerprint"),
            "binding_status": proof["binding_status"],
            "proof_level": proof["proof_level"],
            "confidence": protocol.get("confidence"),
            "source": protocol.get("source"),
        },
        "last_analyzed_seq": 0,
        "prefix_sha256": None,
        "status": "IMPORTED",
        "semantic": {
            "next_episode_index": 0,
            "exhausted": False,
            "submitted": 0,
            "no_drift": 0,
        },
        "event_count": len(bundle_mod.events_of(bundle)),
        "started_at": bundle.get("started_at"),
        "ended_at": bundle.get("ended_at"),
        "imported_at": imported_at,
        "updated_at": imported_at,
        "episodes": episodes,
        "mechanical_spans": episodes_mod.mechanical_spans(bundle_mod.events_of(bundle)),
        "evidence_refs": [
            {"seq": event["seq"], "evidence_ref": event["evidence_ref"]}
            for event in bundle_mod.events_of(bundle)
            if event.get("evidence_ref") is not None
        ],
        "imports": [
            {
                "source_ref": source_ref,
                "sha256": bundle_sha256,
                "generation": generation,
                "imported_at": imported_at,
            }
        ],
        "conflict": None,
    }


# --------------------------------------------------------------------------- #
# protocol binding (PAL-SESSION-03)
# --------------------------------------------------------------------------- #


def _version_tuple(version: object) -> tuple:
    text = str(version or "")
    if not text:
        return ()
    return tuple(int(part) for part in _VERSION_PART.findall(text))


def _verify_release_registry(
    version: str,
    registry_digest: str,
    release_root,
) -> dict[str, str] | None:
    """Verify RELEASE_REGISTRY binding against the operator's release authority.

    Returns a proof dict on success or None when verification is not possible.
    """
    from .paths import sha256_bytes

    if release_root is None:
        return None
    try:
        from pathlib import Path as _Path
        from .historical import _directory_reader, _registry_from_bytes

        root = _Path(release_root) / version
        reader = _directory_reader(root)
        registry_raw = reader("saipal/REGISTRY.json")
        _registry_from_bytes(registry_raw)
        actual_digest = sha256_bytes(registry_raw)
        if actual_digest == registry_digest.lower():
            return {
                "proof_level": PROOF_RELEASE_REGISTRY,
                "binding_status": "BOUND",
                "reason": "release registry digest verified by authority",
            }
        return {
            "proof_level": PROOF_RELEASE_REGISTRY,
            "binding_status": "PARTIAL",
            "reason": "release registry digest mismatch with authority",
        }
    except (OSError, ValueError):
        return None


def _verify_captured_fingerprint(
    tree_fingerprint: str,
    snapshot_root,
    registry: dict | None = None,
) -> dict[str, str] | None:
    """Verify CAPTURED_FINGERPRINT against the operator's snapshot authority.

    Returns a proof dict on success or None when verification is not possible.
    """
    if snapshot_root is None:
        return None
    try:
        from pathlib import Path as _Path
        from .historical import protocol_tree_fingerprint as _ptf

        root = _Path(snapshot_root) / tree_fingerprint
        recomputed = _ptf(root, registry=registry)
        if recomputed == tree_fingerprint.lower():
            return {
                "proof_level": PROOF_CAPTURED_FINGERPRINT,
                "binding_status": "BOUND",
                "reason": "captured fingerprint verified by authority",
            }
        return {
            "proof_level": PROOF_CAPTURED_FINGERPRINT,
            "binding_status": "PARTIAL",
            "reason": "captured fingerprint mismatch with authority",
        }
    except (OSError, ValueError):
        return None


def binding_proof_of(
    protocol: dict | None,
    *,
    commit_exists: CommitResolver | None = None,
    authority: dict | None = None,
    registry: dict | None = None,
) -> dict[str, str]:
    """Return the strongest independently defensible historical binding proof.

    A transcript or bundle may *claim* ``BOUND`` but cannot grant itself that
    status.  Every proof level requires independently verifiable evidence:

    * ``EXACT_COMMIT`` requires a ``commit_exists`` resolver that confirms the
      object exists in an authority-owned repository.
    * ``RELEASE_REGISTRY`` requires the operator-configured ``release_root``;
      the on-disk registry bytes must match the claimed SHA-256 digest.
    * ``CAPTURED_FINGERPRINT`` requires the operator-configured
      ``snapshot_root``; the recomputed protocol tree fingerprint must match
      the claimed one.

    When an authority is absent or verification fails, the binding is
    downgraded to ``PARTIAL``/``UNKNOWN`` -- never promoted to ``BOUND`` on
    syntactic shape alone.
    """
    evidence = protocol if isinstance(protocol, dict) else {}
    git_head = str(evidence.get("git_head") or "").strip()
    version = str(evidence.get("version") or "").strip()
    registry_digest = str(evidence.get("registry_sha256") or "").strip()
    tree_fingerprint = str(evidence.get("tree_fingerprint") or "").strip()

    auth = authority or {}
    release_root = auth.get("release_root")
    snapshot_root = auth.get("snapshot_root")

    commit_problem = ""
    if git_head:
        if not _FULL_GIT_OBJECT_ID.fullmatch(git_head):
            commit_problem = "git object id is not a full 40- or 64-hex identity"
        elif commit_exists is None:
            commit_problem = "git commit is syntactically valid but unverified"
        else:
            try:
                verified = bool(commit_exists(git_head.lower()))
            except (OSError, ValueError):
                verified = False
            if verified:
                return {
                    "proof_level": PROOF_EXACT_COMMIT,
                    "binding_status": "BOUND",
                    "reason": "exact commit resolved by protocol authority",
                }
            commit_problem = "git commit was not found by protocol authority"

    # RELEASE_REGISTRY: the claimed version+digest must be verified against the
    # operator-configured release authority.  A merely well-shaped pair is
    # PARTIAL, never BOUND -- the transcript cannot self-certify.
    if version and _SHA256.fullmatch(registry_digest):
        verified = _verify_release_registry(version, registry_digest, release_root)
        if verified is not None:
            return verified
        return {
            "proof_level": PROOF_RELEASE_REGISTRY,
            "binding_status": "PARTIAL",
            "reason": "release identity present but historical authority not configured or unreadable",
        }
    # CAPTURED_FINGERPRINT: the claimed tree fingerprint must be recomputed
    # from the snapshot authority root.  A well-shaped hex digest is not enough.
    if _SHA256.fullmatch(tree_fingerprint):
        verified = _verify_captured_fingerprint(tree_fingerprint, snapshot_root, registry=registry)
        if verified is not None:
            return verified
        return {
            "proof_level": PROOF_CAPTURED_FINGERPRINT,
            "binding_status": "PARTIAL",
            "reason": "captured fingerprint present but historical authority not configured or unreadable",
        }
    if version:
        return {
            "proof_level": PROOF_INSTALLED_RELEASE,
            "binding_status": "PARTIAL",
            "reason": commit_problem or "version metadata has no verified rule-surface digest",
        }
    return {
        "proof_level": PROOF_UNKNOWN,
        "binding_status": "UNKNOWN",
        "reason": commit_problem or "no defensible historical binding evidence",
    }


def binding_status_of(
    protocol: dict | None,
    *,
    commit_exists: CommitResolver | None = None,
    authority: dict | None = None,
    registry: dict | None = None,
) -> str:
    """`BOUND`, `PARTIAL` or `UNKNOWN`, derived from proof rather than prose.

    A `binding_status` already present in the mapping is a claim, not an answer:
    trusting it let a bundle grant itself `BOUND`. Callers holding an
    already-verified *session record* read `record["protocol"]["binding_status"]`
    directly -- that value was derived here, against the authority, at intake.
    """
    return binding_proof_of(
        protocol, commit_exists=commit_exists, authority=authority, registry=registry
    )["binding_status"]


def historical_applicability(
    protocol: dict | None,
    *,
    rule_introduced_in: str | None = None,
    fix_version: str | None = None,
    current_version: str | None = None,
    commit_exists: CommitResolver | None = None,
    binding_status: str | None = None,
) -> dict[str, Any]:
    """Can a finding claim a protocol violation against this session?

    The no-hindsight rule made mechanical: a rule that did not exist in the
    governing version cannot be violated by a session that ran under it. The
    retrospective `current_protocol_protection` field is separate and is
    `UNKNOWN` unless a fix version and a current version are both supplied --
    SAIPAL does not invent that data.
    """
    proof = binding_proof_of(protocol, commit_exists=commit_exists)
    # Use the session record's pre-verified binding_status when available,
    # rather than recomputing from raw protocol fields (which lacks the
    # authority-backed verification done during intake).
    status = binding_status if binding_status else proof["binding_status"]
    version = (protocol or {}).get("version")

    claimable = True
    reason = ""
    if status == "UNKNOWN" or not version:
        claimable = False
        reason = (
            "protocol binding unknown; no historical violation may be claimed"
            if status == "UNKNOWN"
            else "governing version unavailable; no historical violation may be claimed"
        )
    elif rule_introduced_in and _version_tuple(version) < _version_tuple(rule_introduced_in):
        claimable = False
        reason = (
            f"rule appeared in {rule_introduced_in}, after the governing version {version}"
        )

    protection = "UNKNOWN"
    if fix_version and current_version:
        protection = (
            "PROTECTED"
            if _version_tuple(current_version) >= _version_tuple(fix_version)
            else "STILL_VULNERABLE"
        )

    return {
        "session_protocol_status": status,
        "binding_proof_level": proof["proof_level"],
        "governing_version": version,
        "violation_claimable": claimable,
        "reason": reason,
        "current_protocol_protection": protection,
    }
