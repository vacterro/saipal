"""The constrained submission boundary: Layer B's only way in (PAL-ANALYSIS-05).

An analyst hands the kernel one structured candidate. The kernel re-derives the
unit from its own index, validates shape, claim discipline and scope, then either
merges a finding through the existing lifecycle or records a no-drift receipt.
Either way the semantic watermark advances exactly once per unit.

The analyst never chooses a path, a filename, an audit number or a lifecycle
state. It submits reasoning; Layer A decides what that reasoning is worth.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import bundle as bundle_mod
from . import candidates as cand_mod
from . import carrier as carrier_mod
from . import findings as findings_mod
from . import log as log_mod
from . import pipeline as pipeline_mod
from . import recurrence as recurrence_mod
from . import sessions as sessions_mod
from .capability import require_action, require_analyst_action
from .errors import PalError
from .paths import home_paths, sha256_text
from .registry import load_registry

RECEIPTS_NAME = "semantic_receipts.json"
RECEIPT_SCHEMA_VERSION = 1


def receipt_id(candidate: dict) -> str:
    """Idempotency key: this verdict, on this unit, from this reasoning.

    The unit alone is not enough (a HOT tail legitimately produces a second
    verdict for a later episode), and reasoning alone is not enough (identical
    prose about two units is two submissions).
    """
    parts = (
        str(candidate.get("unit_digest") or ""),
        str(candidate.get("verdict") or ""),
        sha256_text(str(candidate.get("reasoning") or "")),
    )
    return "rcp-" + sha256_text("\x00".join(parts))[:32]


def _receipts_path(home: Path) -> Path:
    return home_paths(home).root / RECEIPTS_NAME


def load_receipts(home: Path | str) -> tuple[str, dict | None, str]:
    from .paths import read_json

    path = _receipts_path(Path(home))
    if not path.exists():
        return "absent", None, ""
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return "unrecoverable", None, f"semantic receipts are unreadable: {exc}"
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != RECEIPT_SCHEMA_VERSION
        or not isinstance(payload.get("receipts"), list)
    ):
        return "unrecoverable", None, "semantic receipts root is malformed"
    return "ok", payload, ""


def _save_receipts(home: Path, payload: dict, *, registry: dict | None) -> dict:
    from .paths import atomic_write_json

    require_action("write_own_index", registry=registry)
    paths = home_paths(home)
    atomic_write_json(_receipts_path(paths.root), payload, root=paths.root)
    return payload


def _existing_receipt(payload: dict | None, key: str) -> dict | None:
    for entry in (payload or {}).get("receipts") or []:
        if entry.get("receipt_id") == key:
            return entry
    return None


def _advance_semantic(record: dict, episode: dict, verdict: str, *, finality: str) -> dict:
    """Move the semantic watermark past this episode, exactly once.

    A PROVISIONAL episode is the growing tail of a HOT session: the verdict is
    recorded, but the watermark does not pass it, because the next cycle will
    hand the analyst a longer version of the same episode. Advancing here would
    quietly declare a sentence finished mid-word.
    """
    state = carrier_mod.semantic_state(record)
    index = int(episode.get("index", 0))
    if finality == "PROVISIONAL":
        if verdict == cand_mod.VERDICT_DRIFT:
            state["submitted"] += 1
        else:
            state["no_drift"] += 1
        state["provisional"] = int(state.get("provisional") or 0) + 1
        record["semantic"] = state
        return state
    if index >= state["next_episode_index"]:
        state["next_episode_index"] = index + 1
    total = len(record.get("episodes") or [])
    state["exhausted"] = state["next_episode_index"] >= total
    if verdict == cand_mod.VERDICT_DRIFT:
        state["submitted"] += 1
    else:
        state["no_drift"] += 1
    record["semantic"] = state
    return state


def _shape_finding(
    candidate: dict,
    record: dict,
    historical: dict | None,
    spread: dict | None = None,
) -> dict:
    """The analyst's candidate in the finding shape Layer A already knows.

    Confidence is the analyst's proposal, but the no-hindsight gate still owns
    the ceiling: an unbound session cannot yield a claimable violation whatever
    the model asserts.
    """
    protocol = record.get("protocol") if isinstance(record.get("protocol"), dict) else {}
    claimable = sessions_mod.historical_applicability(
        protocol, binding_status=protocol.get("binding_status"),
    )["violation_claimable"]
    confidence = candidate.get("confidence") or "LOW"
    if not claimable:
        confidence = "LOW"
    challenge = candidate.get("challenge") or {}
    return {
        "detector": "analyst",
        "session_id": record.get("session_id", ""),
        "episode_id": candidate.get("episode_index", -1),
        "episode_index": candidate.get("episode_index", -1),
        "rule_ids": list(candidate.get("rule_ids") or []),
        "drift_class": candidate.get("drift_class", "UNKNOWN"),
        "severity": candidate.get("severity", "P3"),
        "confidence": confidence,
        "change_target": candidate.get("change_target", "UNKNOWN"),
        "root_cause": candidate.get("root_cause", ""),
        "alternatives": list(candidate.get("alternatives") or []),
        "missing_evidence": list(candidate.get("missing_evidence") or []),
        "protocol_bindings": [protocol],
        "protected_invariants": list(candidate.get("protected_invariants") or []),
        "event_refs": list(candidate.get("event_refs") or []),
        "mechanical_confidence": "LOW",
        "contrary_evidence_found": bool(candidate.get("contrary_evidence")),
        "contrary_evidence": list(candidate.get("contrary_evidence") or []),
        "root_cause_hypothesis": candidate.get("root_cause", ""),
        "historical_rule_surface": historical,
        "recurrence_spread": spread,
        "challenge": {
            "pass_a": challenge.get("prosecutor", ""),
            "pass_b": challenge.get("defender", ""),
            "decided": challenge.get("winner", ""),
            "loser_rejection": challenge.get("loser_rejection", ""),
            "session_id": record.get("session_id"),
            "addressed_defences": list(candidate.get("addressed_defences") or []),
        },
        "disposition_class": candidate.get("disposition_class", "INSUFFICIENT_EVIDENCE"),
        "analyst_reasoning": candidate.get("reasoning", ""),
    }


def submit_candidate(
    home: Path | str,
    candidate: object,
    *,
    registry: dict | None = None,
) -> dict[str, Any]:
    """Validate and absorb one analyst candidate. Returns the submission receipt.

    Refuses -- with zero writes -- when the candidate is malformed, out of scope,
    or answers a unit whose evidence has since changed. A refusal is a result.
    """
    data = registry if registry is not None else load_registry()
    require_analyst_action("submit_candidate", registry=data)
    root = Path(home)

    if not isinstance(candidate, dict):
        raise PalError(
            "VALIDATION_FAILED",
            "candidate root is not an object",
            next_action="submit a structured candidate (PAL-ANALYSIS-04)",
        )

    problems = cand_mod.candidate_problems(candidate, registry=data)
    if problems:
        raise PalError(
            "CANDIDATE_INADMISSIBLE",
            "candidate is inadmissible: " + "; ".join(problems),
            next_action="fix the candidate; nothing was written",
        )

    status, index, detail = sessions_mod.load_index(root, registry=data)
    if status == sessions_mod.STATUS_UNRECOVERABLE:
        raise PalError("VALIDATION_FAILED", f"session index is unusable: {detail}")
    if status == sessions_mod.STATUS_ABSENT or index is None:
        raise PalError(
            "EVIDENCE_NOT_FOUND",
            "no sessions are indexed in this home",
            next_action="saipal continue",
        )

    session_id = str(candidate.get("session_id"))
    episode_index = int(candidate.get("episode_index"))
    record, episode = carrier_mod.find_unit(index, session_id, episode_index)
    if record is None:
        raise PalError(
            "EVIDENCE_NOT_FOUND",
            f"session {session_id!r} is not indexed",
            next_action="saipal --json next",
        )
    if episode is None:
        raise PalError(
            "EVIDENCE_NOT_FOUND",
            f"session {session_id!r} has no episode {episode_index}",
            next_action="saipal --json next",
        )
    if record.get("status") != "IMPORTED":
        raise PalError(
            "SESSION_CONFLICT",
            f"session {session_id!r} is {record.get('status')}; its evidence is frozen",
            next_action="resolve the conflict before submitting reasoning about it",
        )

    unit = carrier_mod.build_carrier(
        root,
        registry=data,
        index=index,
        session_id=session_id,
        episode_index=episode_index,
    )
    scope = cand_mod.episode_scope_problems(candidate, unit, registry=data)
    if scope:
        raise PalError(
            "CANDIDATE_OUT_OF_SCOPE",
            "candidate does not answer the unit it names: " + "; ".join(scope),
            next_action="re-read the carrier with `saipal --json next`; nothing was written",
        )

    key = receipt_id(candidate)
    receipts_status, receipts, receipts_detail = load_receipts(root)
    if receipts_status == "unrecoverable":
        raise PalError(
            "VALIDATION_FAILED",
            receipts_detail,
            next_action=f"repair or remove .saipal/{RECEIPTS_NAME} by hand",
        )
    if receipts is None:
        receipts = {"schema_version": RECEIPT_SCHEMA_VERSION, "receipts": []}
    duplicate = _existing_receipt(receipts, key)
    if duplicate is not None:
        return {
            "receipt_id": key,
            "verdict": duplicate.get("verdict"),
            "session_id": session_id,
            "episode_index": episode_index,
            "finality": duplicate.get("finality", "FINAL"),
            "finding_id": duplicate.get("finding_id"),
            "audit": duplicate.get("audit"),
            "semantic": carrier_mod.semantic_state(record),
            "duplicate": True,
        }

    normalized = cand_mod.normalize_candidate(candidate, registry=data)
    verdict = str(normalized["verdict"])
    finality = carrier_mod.episode_finality(record, episode)
    finding_id = None
    audit = None

    if verdict == cand_mod.VERDICT_DRIFT:
        finding_id, audit = _absorb_drift(
            root, normalized, record, unit, data, finality=finality
        )
    else:
        recurrence_mod.record_negative(root, record, registry=data)

    semantic = _advance_semantic(record, episode, verdict, finality=finality)
    sessions_mod.save_index(root, index, registry=data)

    entry = {
        "receipt_id": key,
        "verdict": verdict,
        "session_id": session_id,
        "episode_index": episode_index,
        "unit_digest": normalized["unit_digest"],
        "disposition_class": normalized["disposition_class"],
        "finality": finality,
        "finding_id": finding_id,
        "audit": audit,
        "recorded_at": _now(),
    }
    receipts["receipts"].append(entry)
    _save_receipts(root, receipts, registry=data)

    log_mod.append_event(
        root,
        "candidate_submitted",
        data={
            "receipt_id": key,
            "verdict": verdict,
            "session_id": session_id,
            "episode_index": episode_index,
            "finality": finality,
            "finding_id": finding_id,
            "audit_number": (audit or {}).get("audit_number"),
        },
        registry=data,
    )

    return {
        "receipt_id": key,
        "verdict": verdict,
        "session_id": session_id,
        "episode_index": episode_index,
        "finality": finality,
        "finding_id": finding_id,
        "audit": audit,
        "semantic": semantic,
        "duplicate": False,
    }


def _absorb_drift(
    home: Path,
    candidate: dict,
    record: dict,
    unit: dict,
    registry: dict,
    *,
    finality: str = "FINAL",
) -> tuple[str | None, dict | None]:
    """Merge a DRIFT candidate through the existing finding lifecycle.

    The analyst's verdict is an input to that lifecycle, never a bypass of it:
    the do-no-harm gate, the qualification threshold and the audit quality gate
    all still decide whether anything leaves the home. A PROVISIONAL episode
    produces a finding but never an audit -- the evidence can still change.
    """
    findings_status, findings_idx, detail = findings_mod.load_index(home, registry=registry)
    if findings_status == "unrecoverable":
        raise PalError(
            "VALIDATION_FAILED",
            f"findings index is unusable: {detail}",
            next_action="repair or remove .saipal/findings/index.json by hand",
        )
    if findings_status == "absent" or findings_idx is None:
        findings_idx = findings_mod.empty_index()

    shaped = _shape_finding(
        candidate,
        record,
        unit.get("historical_rule_surface"),
        (unit.get("recurrence") or {}).get("spread"),
    )
    shaped["episode_finality"] = finality
    advanced = findings_mod.merge_candidates(findings_idx, [shaped], record)
    if not advanced:
        findings_mod.save_index(home, findings_idx, registry=registry)
        return None, None

    finding = advanced[0]
    pipeline_mod.advance_to_qualified(findings_idx, finding)
    audit = None
    emit_allowed = finality == "FINAL"
    if not emit_allowed:
        finding["provisional_hold"] = (
            "the episode is the growing tail of a HOT session; the finding is held "
            "until the evidence is final (PAL-SESSION-06)"
        )
    if emit_allowed and findings_mod.qualification_threshold(finding, registry=registry):
        source_ref = str(record.get("source_ref") or "")
        bundle_path = home_paths(home).session_inbox / Path(source_ref).name
        try:
            bundle = bundle_mod.load_bundle_file(bundle_path, registry=registry)
        except (OSError, PalError):
            bundle = {"adapter": record.get("adapter"), "project": record.get("project") or {}}
        emitted: list[dict] = []
        pipeline_mod.emit_audit(
            home, finding, record, bundle, home_paths(home), registry, emitted
        )
        if emitted:
            audit = finding.get("audit")

    findings_mod.save_index(home, findings_idx, registry=registry)
    recurrence_mod.record_occurrence(home, finding, record, registry=registry)
    return finding.get("finding_id"), audit


def _now() -> str:
    from .paths import utc_now_iso

    return utc_now_iso()
