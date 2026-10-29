"""Protocol authority bootstrap and trust pinning (T-86).

Trust is enrolled ONCE by the operator and never inferred: discovery may name
candidate roots, but nothing trusts a path because its folder looks familiar.
`authority-enroll` writes the operator's choice into `config.json`
(protocol_authority) plus a pinning record (`.saipal/authority_pinning.json`)
that remembers WHICH repository was enrolled, that it carries the protocol
registry surface, and what was first observed there -- so an accidental
substitution is detectable while HEAD is free to advance.

Session transcripts never choose authority roots: enrollment is a CLI write,
not an evidence-derived decision.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from saipal_engine.config import load_config, protocol_authority, save_config
from saipal_engine.errors import PalError
from saipal_engine.paths import atomic_write_json, home_paths, read_json

PINNING_SCHEMA_VERSION = 1
PINNING_NAME = "authority_pinning.json"

#: T-113: the durable enrollment transaction journal. `authority.enroll`
#: writes config and pinning as TWO files; a crash between them used to leave
#: `configured but unpinned` half state that nothing could name. The journal
#: records the enrollment's phase so any half state is visibly
#: PREPARED/INCOMPLETE (never trusted) and a retry converges idempotently.
ENROLLMENT_JOURNAL_NAME = "authority_enrollment.json"
ENROLLMENT_PHASES = ("PREPARED", "COMMITTED")

PINNING_FIELDS = (
    "schema_version",
    "updated_at",
    "roots",
)
ROOT_PIN_FIELDS = (
    "kind",
    "canonical_path",
    "head_at_enroll",
    "registry_sha256",
    "registry_present",
)

CANDIDATE_LABELS = ("git_repository", "release_root", "snapshot_root")


def pinning_path(home: Path | str) -> Path:
    return home_paths(home).root / PINNING_NAME


def fresh_pinning() -> dict:
    return {"schema_version": PINNING_SCHEMA_VERSION, "updated_at": "", "roots": {}}


def load_pinning(home: Path | str) -> dict:
    path = pinning_path(home)
    if not path.exists():
        return fresh_pinning()
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise PalError(
            "VALIDATION_FAILED",
            f"authority pinning record is unreadable: {exc}",
            next_action="repair or remove .saipal/authority_pinning.json by hand",
        ) from None
    problems = pinning_problems(payload)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "authority pinning record is invalid: " + "; ".join(problems[:5]),
        )
    return payload


def save_pinning(home: Path | str, payload: dict) -> Path:
    problems = pinning_problems(payload)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "refusing invalid authority pinning record: " + "; ".join(problems[:5]),
        )
    from time import gmtime, strftime

    payload["updated_at"] = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
    return atomic_write_json(pinning_path(home), payload, root=home_paths(home).root)


def pinning_problems(payload: object) -> list[str]:
    if not isinstance(payload, dict):
        return ["authority pinning root is not an object"]
    if payload.get("schema_version") != PINNING_SCHEMA_VERSION:
        return [f"schema_version must be {PINNING_SCHEMA_VERSION}"]
    for key in sorted(set(payload) - set(PINNING_FIELDS)):
        return [f"unknown pinning field {key!r}"]
    roots = payload.get("roots")
    if not isinstance(roots, dict):
        return ["roots must be an object"]
    for key, record in roots.items():
        if key not in CANDIDATE_LABELS:
            return [f"pinning root key {key!r} is not an authority kind"]
        if not isinstance(record, dict):
            return [f"pinning root {key} is not an object"]
        for field in sorted(set(record) - set(ROOT_PIN_FIELDS)):
            return [f"pinning root {key} has unknown field {field!r}"]
    return []


def discover(home: Path | str) -> dict:
    """Read-only candidates. Discovery NEVER trusts; it only reports.

    A candidate is a defensible local location observed on this machine:
    the checkout this tool runs from for `git_repository`, an existing
    `releases`-shaped sibling for `release_root`. Both need explicit
    enrollment before any authority reader consumes them.
    """
    home = Path(home)
    candidates: list[dict] = []
    checkout = Path(__file__).resolve().parents[1]
    candidates.append(
        {
            "kind": "git_repository",
            "path": str(checkout),
            "exists": checkout.is_dir(),
            "is_git_repo": (checkout / ".git").exists(),
            "registry_present": (checkout / "saipal" / "REGISTRY.json").is_file(),
            "confidence": "high" if (checkout / "saipal" / "REGISTRY.json").is_file() else "low",
            "reason": "the checkout this tool runs from",
        }
    )
    releases = home.parent / "protocol_authority" / "releases"
    candidates.append(
        {
            "kind": "release_root",
            "path": str(releases),
            "exists": releases.is_dir(),
            "is_git_repo": False,
            "registry_present": any(
                (child / "saipal" / "REGISTRY.json").is_file()
                for child in (releases.iterdir() if releases.is_dir() else [])
            ),
            "confidence": "medium" if releases.is_dir() else "low",
            "reason": "a conventional release root beside this home",
        }
    )
    declared = protocol_authority(home)
    enrolled = {key: str(path) if path else None for key, path in declared.items()}
    pinning = load_pinning(home)
    return {
        "authority_discover": True,
        "ok": True,
        "candidates": candidates,
        "currently_enrolled": enrolled,
        "pinned": sorted((pinning.get("roots") or {}).keys()),
        "trusted": False,
        "note": "discovery never trusts; enrollment is the only trust action",
    }


def _canonical_identity(path: Path) -> str:
    """Deliberate canonical trust identity (T-100 rule 38, Windows-aware).

    Drive-letter case, `.` segments, duplicate separators and case-only
    aliases must compare as ONE root, while an actual different directory
    must stay detectable as substitution. `Path.resolve()` on an EXISTING
    path normalizes all of these without following the final symlink on
    strict=False (Python resolves what exists; the final component's own
    symlink is not followed on all platforms, so substitution by swapping a
    directory for a symlink stays visible to the registry-fingerprint pin).
    """
    try:
        return str(Path(path).expanduser().resolve()).casefold()
    except OSError:
        return str(Path(path).expanduser()).casefold()


#: Per-kind trust state for the trusted-authority accessor (T-100 rule 19).
TRUST_ABSENT = "ABSENT"
TRUST_LEGACY_UNPINNED = "LEGACY_UNPINNED"
TRUST_TRUSTED = "TRUSTED"
TRUST_SUBSTITUTED = "SUBSTITUTED"


def trusted_protocol_authority(
    home: Path | str,
    *,
    config: dict | None = None,
    pinning: dict | None = None,
) -> dict[str, dict]:
    """The canonical trusted-authority accessor (T-100).

    Configured raw roots remain OBSERVABLE but are not automatically
    authority. For each authority kind the state is exactly one of:

    - ABSENT: nothing configured;
    - TRUSTED: a valid pin names the same canonical root;
    - LEGACY_UNPINNED: a root is configured but carries no matching pin;
    - SUBSTITUTED: the config root differs from the pinned root.

    Historical strengthening may use only TRUSTED roots. A LEGACY_UNPINNED
    root is reported (fail-closed, visible) and provides the
    `authority enroll` adoption path; it is never silently used.
    """
    root = Path(home)
    if config is None:
        _status, config, _detail = load_config(root)
        if not isinstance(config, dict):
            config = {}
    declared = (config or {}).get("protocol_authority") or {}
    if pinning is None:
        pinning = load_pinning(root)
    roots = pinning.get("roots") or {}

    out: dict[str, dict] = {}
    for kind in CANDIDATE_LABELS:
        raw = declared.get(kind)
        raw_str = str(raw) if isinstance(raw, str) and raw.strip() else None
        pin = roots.get(kind) if isinstance(roots, dict) else None
        record: dict = {
            "state": TRUST_ABSENT,
            "configured_root": raw_str,
            "pinned_root": None,
        }
        if raw_str is None:
            out[kind] = record
            continue
        canonical = _canonical_identity(Path(raw_str))
        record["canonical_root"] = canonical
        if not isinstance(pin, dict) or not pin.get("canonical_path"):
            record["state"] = TRUST_LEGACY_UNPINNED
            out[kind] = record
            continue
        pinned_canonical = _canonical_identity(Path(str(pin.get("canonical_path"))))
        record["pinned_root"] = pin.get("canonical_path")
        if pinned_canonical != canonical:
            record["state"] = TRUST_SUBSTITUTED
        else:
            record["state"] = TRUST_TRUSTED
        out[kind] = record
    return out


def trusted_roots(home: Path | str) -> dict[str, str]:
    """`{kind: root}` for kinds whose authority state is exactly TRUSTED."""
    state = trusted_protocol_authority(home)
    return {
        kind: str(record["configured_root"])
        for kind, record in state.items()
        if record["state"] == TRUST_TRUSTED
    }


def enroll(home: Path | str, kind: str, path: Path | str) -> dict:
    """The ONE explicit trust action. Refuses obvious substitution loudly.

    T-113: enrollment is a durable TWO-PHASE transaction. Config and pinning
    are two files, so "write both" is not atomic; instead the sequence is:

        validate root + derive pin
        -> persist PREPARED journal (kind, root, pin)   [phase 1]
        -> save_pinning (pin durable)
        -> save_config   (config durable)
        -> mark COMMITTED (journal update)             [phase 2]

    A crash at any boundary leaves a PREPARED record: `trusted_state` (and
    any reader) can see the enrollment is INCOMPLETE, and the next `enroll`
    call for the SAME root converges idempotently -- a different root is
    refused until the operator resolves the interrupted one deliberately.
    No successful return until config+pin agree.
    """
    if kind not in CANDIDATE_LABELS:
        raise PalError(
            "USAGE", f"unknown authority kind {kind!r}; expected one of {list(CANDIDATE_LABELS)}"
        )
    # CORE-001 (ROLE 20260910 §4): enrollment is the canonical MUTATION --
    # it takes the common writer fence HERE, reentrantly, so a direct library
    # call cannot race a concurrent supervisor rebind/intake. The fence is
    # per-transaction, not per byte: save_pinning/save_config stay raw.
    from saipal_engine.paths import writer_fence

    with writer_fence(home):
        return _enroll_fenced(home, kind, path)


def _enroll_fenced(home: Path | str, kind: str, path: Path | str) -> dict:
    resolved = Path(path).expanduser()
    if not resolved.exists():
        raise PalError(
            "VALIDATION_FAILED", f"authority root {resolved} does not exist; nothing enrolled"
        )
    head_at_enroll = _git_head(resolved) if kind == "git_repository" else None
    if kind == "git_repository" and not (resolved / ".git").exists():
        raise PalError(
            "VALIDATION_FAILED",
            f"{resolved} is not a git repository; a git_repository authority must be one",
        )
    registry_sha, registry_present = _registry_fingerprint(resolved, kind)

    _status, config, detail = load_config(home)
    if not isinstance(config, dict):
        raise PalError("VALIDATION_FAILED", f"config.json is unusable: {detail}")

    # An interrupted prior enrollment for the SAME kind: converge idempotently
    # when it names this same root, refuse loudly when it names another -- a
    # half-written transaction must never be silently replaced.
    journal = _load_enrollment_journal(home)
    pending = journal.get("pending") or {}
    if pending and pending.get("kind") == kind:
        if pending.get("root") != str(resolved):
            raise PalError(
                "AUTHORITY_ENROLLMENT_INCOMPLETE",
                (
                    f"a previous {kind} enrollment for {pending.get('root')!r} is "
                    f"PREPARED but not committed; resolve it (re-run it to completion "
                    f"or clear the journal deliberately) before enrolling elsewhere"
                ),
                next_action="re-run the interrupted enrollment for the same root, "
                            "or remove .saipal/authority_enrollment.json by hand",
            )

    previous = (config.get("protocol_authority") or {}).get(kind)
    pinning = load_pinning(home)
    roots = pinning.setdefault("roots", {})
    if previous and kind in roots:
        previous_pin = roots[kind]
        if previous_pin.get("canonical_path") not in (None, str(resolved)):
            raise PalError(
                "AUTHORITY_SUBSTITUTION",
                (
                    f"{kind} was pinned to {previous_pin.get('canonical_path')!r}; "
                    f"re-enrolling {str(resolved)!r} would substitute the pinned "
                    "authority. Clear the pin deliberately before enrolling elsewhere."
                ),
            )

    # Already fully enrolled at this exact root: idempotent success, no writes.
    existing_pin = roots.get(kind)
    if (
        previous == str(resolved)
        and existing_pin is not None
        and existing_pin.get("canonical_path") == str(resolved)
    ):
        return {
            "authority_enroll": True,
            "ok": True,
            "kind": kind,
            "path": str(resolved),
            "head_at_enroll": existing_pin.get("head_at_enroll"),
            "registry_sha256": existing_pin.get("registry_sha256"),
            "registry_present": existing_pin.get("registry_present"),
            "unchanged": True,
        }

    # Phase 1: the enrollment intention is durable BEFORE either data file.
    _save_enrollment_journal(
        home,
        {
            "kind": kind,
            "root": str(resolved),
            "pin": {
                "kind": kind,
                "canonical_path": str(resolved),
                "head_at_enroll": head_at_enroll,
                "registry_sha256": registry_sha,
                "registry_present": registry_present,
            },
        },
    )

    # Phase 2: pin first, then config, then commit the journal.
    roots[kind] = {
        "kind": kind,
        "canonical_path": str(resolved),
        "head_at_enroll": head_at_enroll,
        "registry_sha256": registry_sha,
        "registry_present": registry_present,
    }
    save_pinning(home, pinning)
    config.setdefault("protocol_authority", {})[kind] = str(resolved)
    save_config(home, config)
    _clear_enrollment_journal(home)
    return {
        "authority_enroll": True,
        "ok": True,
        "kind": kind,
        "path": str(resolved),
        "head_at_enroll": head_at_enroll,
        "registry_sha256": registry_sha,
        "registry_present": registry_present,
    }


def enrollment_journal_path(home: Path | str) -> Path:
    return home_paths(home).root / ENROLLMENT_JOURNAL_NAME


def _load_enrollment_journal(home: Path | str) -> dict:
    path = enrollment_journal_path(home)
    if not path.exists():
        return {}
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _save_enrollment_journal(home: Path | str, pending: dict) -> None:
    payload = {"phase": "PREPARED", "pending": pending}
    atomic_write_json(enrollment_journal_path(home), payload, root=home_paths(home).root)


def _clear_enrollment_journal(home: Path | str) -> None:
    path = enrollment_journal_path(home)
    # T-125 Defect D: the one raw unlink() in the engine. A parent
    # indirection (home replaced by a symlink after validation) could carry
    # the deletion outside the home. confined_unlink binds the deletion to
    # the verified physical home parent on POSIX and reparse-verifies it on
    # Windows; a missing journal stays a no-op.
    try:
        from saipal_engine.paths import confined_unlink

        confined_unlink(home_paths(home).root, ENROLLMENT_JOURNAL_NAME)
    except OSError:
        pass


def enrollment_incomplete(home: Path | str) -> dict:
    """The visible PREPARED/COMMITTED truth of the enrollment transaction.

    Read-only: reports any half-enrolled authority so doctor/status can show
    INCOMPLETE instead of trusting configured-but-unpinned state.
    """
    journal = _load_enrollment_journal(home)
    if not journal:
        return {"incomplete": False, "pending": None}
    return {
        "incomplete": True,
        "pending": journal.get("pending") or None,
    }


def doctor(home: Path | str) -> dict:
    """Read-only trust health of the enrolled authority."""
    declared = protocol_authority(home)
    pinning = load_pinning(home)
    transaction = enrollment_incomplete(home)
    roots_out: dict[str, dict] = {}
    for kind in CANDIDATE_LABELS:
        path = declared.get(kind)
        record: dict = {"enrolled": bool(path), "path": str(path) if path else None}
        if transaction["incomplete"] and (transaction["pending"] or {}).get("kind") == kind:
            record["enrollment_incomplete"] = True
        if path:
            pin = (pinning.get("roots") or {}).get(kind)
            if pin and pin.get("canonical_path") not in (None, str(path)):
                record["substitution_detected"] = True
                record["pinned_path"] = pin.get("canonical_path")
            else:
                record["substitution_detected"] = False
            registry_sha, registry_present = _registry_fingerprint(Path(path), kind)
            record["registry_present"] = registry_present
            record["registry_sha256"] = registry_sha
            if pin and registry_sha and pin.get("registry_sha256"):
                record["registry_advanced_since_enroll"] = (
                    pin["registry_sha256"] != registry_sha
                )
        roots_out[kind] = record
    return {
        "authority_doctor": True,
        "ok": True,
        "roots": roots_out,
        "pinned": sorted((pinning.get("roots") or {}).keys()),
        "enrollment_transaction": transaction,
    }


def _git_head(root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    head = completed.stdout.strip()
    return head or None


def _registry_fingerprint(root: Path, kind: str) -> tuple[str | None, bool]:
    """The registry digest under this root, per kind layout. Never trusted.

    A release_root carries `<release>/saipal/REGISTRY.json`; a snapshot_root
    carries `saipal/REGISTRY.json`; a git_repository carries the checkout's
    own `saipal/REGISTRY.json` at HEAD (worktree state).
    """
    direct = root / "saipal" / "REGISTRY.json"
    if direct.is_file():
        return hashlib.sha256(direct.read_bytes()).hexdigest(), True
    releases = root if kind == "release_root" else None
    if releases is not None and releases.is_dir():
        digests = sorted(
            hashlib.sha256(child.read_bytes()).hexdigest()
            for child in releases.glob("*/saipal/REGISTRY.json")
            if child.is_file()
        )
        if digests:
            return digests[-1], True
    return None, False
