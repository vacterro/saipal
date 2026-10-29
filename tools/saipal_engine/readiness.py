"""Publication-gate readiness attestation (T-109).

Durable proof that a bounded STAGE_ONLY convergence review has been completed
and that the reviewed source + reviewed sink identities were valid at review
time. Revalidated at every external-effect boundary.

Non-negotiable constraints:
- not a free-form config flag;
- not mintable by editing config or by --shadow-reviewed alone;
- bound to reviewed software identity + reviewed sink identity + sink manifest;
- revalidated on every publish path, including the pending-publication retry.
"""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

from . import authority as _authority_mod
from .config import configured_sink_root, load_config as _load_config
from .errors import PalError
from .paths import (
    atomic_write_json,
    home_paths,
    read_json,
    resolve_tool_root,
    sha256_file,
    utc_now_iso,
)
from .sink import AuditSink

_SCHEMA_VERSION = 1
_MANIFEST_KIND = "saipen-audit-inbox"
_MANIFEST_SUPPORTED_SCHEMA = 1
_ARTIFACT_NAME = "readiness.json"

#: The reviewed software identity is an EXPLICIT ALLOWLIST of authored runtime
#: and protocol-contract surfaces, never a whole-repository walk. Everything
#: not named here is mutable operational or VCS state by construction, so the
#: fingerprint cannot drift when readiness.json is written, config/state/log/
#: inbox/telemetry change, SAIPEN lifecycle files change, git metadata changes,
#: or caches/test fixtures are rebuilt. T-109: a fingerprint that includes its
#: own artifact invalidates itself the moment it is persisted.
_FINGERPRINT_FIXED_FILES = (
    "tools/saipal.py",
    "saipal/REGISTRY.json",
)
_FINGERPRINT_RECURSIVE_PACKAGES = (
    "tools/saipal_engine",
    "tools/saipal_analyst",
)


def software_fingerprint(base: Path | str | None = None) -> str:
    """Deterministic digest of the authored publication/runtime surface.

    Scoped to an explicit allowlist: the CLI entry point, the deterministic
    engine package, the analyst/supervisor package, and the machine protocol
    registry. Test files, fixtures, caches and every operational/VCS state
    directory are outside the allowlist by construction, so the identity is
    an identity: it changes only when authored publication/runtime code or
    the protocol contract changes.
    """
    root = Path(base).resolve() if base is not None else resolve_tool_root()
    relatives: set[str] = {rel for rel in _FINGERPRINT_FIXED_FILES if (root / rel).is_file()}
    for prefix in _FINGERPRINT_RECURSIVE_PACKAGES:
        directory = root / prefix
        if not directory.is_dir():
            continue
        for path in directory.rglob("*.py"):
            parts = path.relative_to(root).parts
            if "tests" in parts or path.name.startswith("test_"):
                continue
            relatives.add("/".join(parts))
    digest = hashlib.sha256()
    for rel in sorted(relatives):
        try:
            data = (root / rel).read_bytes()
        except OSError:
            continue
        digest.update(rel.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(data)
        digest.update(b"\x00")
    return digest.hexdigest()[:32]


def _artifact_path(home: Path | str) -> Path:
    return home_paths(home).root / _ARTIFACT_NAME


def _validation_problems(attest: object) -> list[str]:
    if not isinstance(attest, dict):
        return ["readiness root is not an object"]
    if attest.get("schema_version") != _SCHEMA_VERSION:
        return [f"readiness schema_version must be {_SCHEMA_VERSION}"]
    if attest.get("state") != "READY":
        return ["readiness state is not READY"]
    for key in (
        "review_id",
        "checkpoint_id",
        "software_fingerprint",
        "sink_canonical",
        "sink_manifest_sha256",
        "manifest_kind",
        "created_at",
    ):
        if not isinstance(attest.get(key), str) or not attest.get(key):
            return [f"readiness is missing {key}"]
    if attest.get("manifest_kind") != _MANIFEST_KIND:
        return [f"readiness manifest_kind is not {_MANIFEST_KIND!r}"]
    try:
        sv = int(attest.get("manifest_schema_version") or 0)
    except (TypeError, ValueError):
        return ["readiness manifest_schema_version is not an integer"]
    if sv != _MANIFEST_SUPPORTED_SCHEMA:
        return ["readiness manifest_schema_version is unsupported"]
    return []


def load(home: Path | str) -> tuple[str, dict | None, str]:
    path = _artifact_path(home)
    if not path.is_file():
        return "absent", None, "publication readiness proof is missing"
    try:
        attest = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return "unrecoverable", None, f"readiness proof is unreadable: {exc}"
    problems = _validation_problems(attest)
    if problems:
        return "unrecoverable", None, "; ".join(problems[:5])
    return "ok", attest, ""


def sink_identity(sink: AuditSink) -> dict:
    """Canonical sink identity that no user-provided path string can forge."""
    manifest = sink.audit_dir / "MANIFEST.json"
    manifest_sha = sha256_file(manifest) if manifest.is_file() else ""
    return {
        "canonical_root": _authority_mod._canonical_identity(sink.root),
        "manifest_sha256": manifest_sha,
        "manifest_kind": _MANIFEST_KIND,
        "manifest_schema_version": _MANIFEST_SUPPORTED_SCHEMA,
    }


def _write(home: Path | str, attest: dict) -> Path:
    path = _artifact_path(home)
    return atomic_write_json(path, attest, root=home_paths(home).root)


def _review_problems(report: object) -> list[str]:
    """Every reason this report is not a SUCCESSFUL bounded convergence review.

    A canary-shaped dictionary is not a review. Minting requires the report to
    prove, from its own derived fields, that a real bounded STAGE_ONLY run
    completed: ok, the healthy bounded stop reason, completed cycles, valid
    positive bounds, attempt accounting inside the hard bound, zero failures,
    and a derived publication-safety table that says external delivery was
    impossible for the whole review. Python returning is never the proof.
    """
    if not isinstance(report, dict):
        return ["review report is not an object"]
    problems: list[str] = []
    if not report.get("canary"):
        problems.append("review report is not a canary convergence review")
    if report.get("ok") is not True:
        problems.append("review did not complete successfully (ok is not true)")
    if report.get("stop_reason") != "MAX_CYCLES":
        problems.append(
            "review did not end on the healthy bounded stop "
            f"(stop_reason is {report.get('stop_reason')!r})"
        )
    cycles = report.get("cycles_completed")
    if not isinstance(cycles, int) or isinstance(cycles, bool) or cycles <= 0:
        problems.append("review completed zero cycles")
    limits = report.get("limits") if isinstance(report.get("limits"), dict) else {}
    for key in ("cycles_requested", "max_units_per_cycle", "max_model_attempts"):
        value = limits.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            problems.append(f"review limit {key} is missing or invalid")
    attempts = report.get("attempts") if isinstance(report.get("attempts"), dict) else {}
    model_calls = attempts.get("model_calls")
    budget = limits.get("max_model_attempts")
    if isinstance(model_calls, int) and isinstance(budget, int) and model_calls > budget:
        problems.append("review model attempt accounting exceeded its hard bound")
    if report.get("failures") != 0:
        problems.append("review reported failures")
    if report.get("blocked") != 0:
        problems.append("review reported blocked or retry-waiting work")
    safety = report.get("publication_safety") if isinstance(report.get("publication_safety"), dict) else {}
    if safety.get("configured_publication_mode") != "STAGE_ONLY":
        problems.append(
            "review publication mode was not STAGE_ONLY "
            f"(configured {safety.get('configured_publication_mode')!r})"
        )
    if safety.get("runtime_publication_ceiling") != "STAGE_ONLY":
        problems.append(
            "review runtime publication ceiling was not STAGE_ONLY "
            f"(ceiling {safety.get('runtime_publication_ceiling')!r})"
        )
    if safety.get("effective_external_publication") is not False:
        problems.append("review reported effective external publication as possible")
    if report.get("stop_reason") in (
        "PUBLICATION_MODE_BLOCKED", "CONFIGURATION_BLOCKED", "OWNERSHIP_LOST",
        "FATAL_CYCLE_ERROR", "MODEL_ATTEMPT_BUDGET_EXCEEDED",
    ):
        problems.append(f"refusing to certify a {report.get('stop_reason')} result")
    return problems


def _build_attestation(*, report: dict, reviewed: dict) -> dict:
    return {
        "schema_version": _SCHEMA_VERSION,
        "state": "READY",
        "review_id": str(report.get("review_id") or utc_now_iso()),
        "checkpoint_id": "T-109-" + uuid.uuid4().hex[:12] + "-" + utc_now_iso(),
        "software_fingerprint": software_fingerprint(),
        "sink_canonical": reviewed["canonical_root"],
        "sink_manifest_sha256": reviewed["manifest_sha256"],
        "manifest_kind": reviewed["manifest_kind"],
        "manifest_schema_version": int(reviewed["manifest_schema_version"]),
        "created_at": utc_now_iso(),
    }


def mint(home: Path | str, *, report: dict, sink: AuditSink, replace: bool = False) -> dict:
    """Mint a new readiness attestation after a successful convergence review.

    The caller owns the proof surfaces; this function binds them. A non-canary
    or failed/incomplete report is rejected so no malformed artifact lands on
    disk. The current config must be STAGE_ONLY so a manually tampered config
    cannot mint a readiness proof that validates against itself.

    Renewal is explicit and atomic: every proof surface is validated before a
    single write. A failed replacement leaves the prior artifact byte-identical.
    Corrupt durable state is repaired only through an explicit replacement.
    """
    problems = _review_problems(report)
    if problems:
        raise ValueError(
            "cannot mint readiness from an inadequate review: " + "; ".join(problems)
        )
    if not sink.preflight()["ok"]:
        raise ValueError("refusing to mint readiness against an invalid sink")
    status, config, detail = _load_config(home)
    if status != "ok" or not isinstance(config, dict):
        raise ValueError(f"config is unusable: {detail}")
    if config.get("publication_mode") != "STAGE_ONLY":
        raise ValueError(
            "readiness may only be minted on a STAGE_ONLY home; "
            f"current mode is {config.get('publication_mode')!r}"
        )
    reviewed = sink_identity(sink)
    prior_status, _, detail = load(home)
    if prior_status == "ok" and not replace:
        raise ValueError(
            "a readiness proof already exists; "
            "replace it explicitly before minting a new one"
        )
    if prior_status == "unrecoverable" and not replace:
        raise ValueError(
            f"readiness proof is unrecoverable at {_artifact_path(home)}: {detail}; "
            "repair it explicitly with mint --replace after a successful review"
        )
    attest = _build_attestation(report=report, reviewed=reviewed)
    _write(home, attest)
    return attest


def require_for_config(home: Path | str, config: dict) -> dict:
    """Return the attestation or fail closed when a config requests PUBLISH_ENABLED.

    This is the config-time gate: it does not write anything. Zero-write refusal.
    """
    status, attest, detail = load(home)
    if status != "ok" or attest is None:
        raise PalError(
            "PUBLICATION_GATE_CLOSED",
            detail or "publication readiness proof is missing",
            next_action="complete a STAGE_ONLY convergence review before enabling publication",
        )
    mode = config.get("publication_mode")
    if mode != "PUBLISH_ENABLED":
        raise PalError(
            "PUBLICATION_GATE_CLOSED",
            f"publication_mode is {mode!r}; PUBLISH_ENABLED requires a readiness proof",
        )
    if not config.get("shadow_reviewed"):
        raise PalError(
            "PUBLICATION_GATE_CLOSED",
            "shadow_reviewed is not set; PUBLISH_ENABLED requires an explicit reviewed flag",
        )
    root = configured_sink_root(home, config)
    if root is None:
        raise PalError(
            "PUBLICATION_GATE_CLOSED",
            "PUBLISH_ENABLED requires a configured sink.root",
        )
    sink = AuditSink(home, root=root)
    if not sink.preflight()["ok"]:
        raise PalError(
            "PUBLICATION_GATE_CLOSED",
            "the configured sink is not a valid saipen-audit-inbox",
            next_action="repair the sink and retry setup",
        )
    current = sink_identity(sink)
    problems: list[str] = []
    if str(current.get("canonical_root") or "") != str(attest.get("sink_canonical") or ""):
        problems.append("sink canonical root does not match the reviewed sink")
    if str(current.get("manifest_sha256") or "") != str(attest.get("sink_manifest_sha256") or ""):
        problems.append("sink manifest bytes do not match the reviewed sink")
    if str(current.get("manifest_kind") or "") != str(attest.get("manifest_kind") or ""):
        problems.append("sink manifest kind does not match the reviewed sink")
    if int(current.get("manifest_schema_version") or 0) != int(attest.get("manifest_schema_version") or 0):
        problems.append("sink manifest schema_version does not match the reviewed sink")
    if str(attest.get("software_fingerprint") or "") != software_fingerprint():
        problems.append("reviewed software fingerprint does not match the current checkout")
    if problems:
        raise PalError(
            "PUBLICATION_GATE_CLOSED",
            "; ".join(problems),
            next_action="rerun the convergence review against the current sink and checkout",
        )
    return attest


def require(home: Path | str) -> dict:
    """Convenience wrapper that reads the current config first."""
    status, config, detail = _load_config(home)
    if status != "ok" or config is None:
        raise PalError(
            "PUBLICATION_GATE_CLOSED",
            f"config is unusable: {detail}",
        )
    return require_for_config(home, config)


def check_publish_gate(home: Path | str, sink: AuditSink) -> dict:
    """Revalidate at the external-effect boundary.

    Returns a dict with `ok` plus gate state. Raises when the gate is closed so
    the caller can stage locally without ever writing externally.
    """
    status, config, detail = _load_config(home)
    if status != "ok" or config is None:
        raise PalError("PUBLICATION_GATE_CLOSED", f"config is unusable: {detail}")
    mode = config.get("publication_mode")
    if mode != "PUBLISH_ENABLED":
        raise PalError("PUBLICATION_GATE_CLOSED", f"publication_mode is {mode!r}")
    if not config.get("shadow_reviewed"):
        raise PalError("PUBLICATION_GATE_CLOSED", "shadow_reviewed is not set")
    if not sink.preflight()["ok"]:
        raise PalError("PUBLICATION_GATE_CLOSED", "sink preflight failed")
    return {"ok": True, "attestation": require(home)}


def mint_readiness_for_tests(home: Path | str, sink: AuditSink) -> dict:
    """Test-only: mint a readiness attestation from a synthetic SUCCESSFUL
    convergence review, so isolated test homes reach PUBLISH_ENABLED through the
    real (hardened) proof boundary instead of bypassing it.

    This builds a report that satisfies the same `_review_problems` contract the
    production `readiness.mint` enforces. It is NOT a substitute for the
    production review path in end-to-end acceptance: only a real bounded
    canary/convergence run through `readiness.mint` (the CLI `review` surface)
    produces an admissible production proof.
    """
    report = {
        "canary": True,
        "ok": True,
        "review_id": "TEST-" + utc_now_iso(),
        "stop_reason": "MAX_CYCLES",
        "cycles_completed": 1,
        "limits": {
            "cycles_requested": 1,
            "max_units_per_cycle": 1,
            "max_model_attempts": 1,
        },
        "attempts": {"model_calls": 1},
        "failures": 0,
        "blocked": 0,
        "publication_safety": {
            "configured_publication_mode": "STAGE_ONLY",
            "runtime_publication_ceiling": "STAGE_ONLY",
            "effective_external_publication": False,
        },
    }
    return mint(home, report=report, sink=sink)
