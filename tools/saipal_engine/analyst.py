"""Deterministic signal generator for SAIPAL Wave C.

This module is NOT a semantic analyst. It is the deterministic **signal
generator** layer (Layer A per ARCHITECTURE.md): it takes mechanical detector
facts and produces structured hypothesis templates. It answers "where should I
look?", never "what is the final truth?".

The real semantic analyst (Layer B — the replaceable AI agent) receives these
signals as one input among many, alongside evidence windows, historical rules
and prior recurrence. An LLM analyst can be injected later behind the same
return shape.
"""

from __future__ import annotations

from typing import Any

from .detectors import detect_for_episode
from .registry import load_registry


_CHANGE_TARGET_BY_DRIFT: dict[str, str] = {
    "COMMAND_ROUTE_DRIFT": "ENGINE",
    "PHASE_ILLEGALITY": "PHASE_CONTRACT",
    "ACTIVE_WORK_PREEMPTION": "CORE_PROTOCOL",
    "CONTINUE_IDLE_FALSE_POSITIVE": "ENGINE",
    "SOURCE_CLOSURE_FALSE_GREEN": "SOURCE_CONTRACT",
    "BOARD_PRIORITY_DRIFT": "CORE_PROTOCOL",
    "PHASE_SKIP": "PHASE_CONTRACT",
    "SOURCE_AUTHORITY_DRIFT": "SOURCE_CONTRACT",
    "EVIDENCE_FABRICATION": "CORE_PROTOCOL",
    "RECOVERY_ORDER_DRIFT": "CORE_PROTOCOL",
    "DESTRUCTIVE_GATE_DRIFT": "EXECUTION_POLICY",
    "IMPROVE_PRECEDENCE_DRIFT": "CORE_PROTOCOL",
    "AUDIT_INBOX_DRIFT": "ENGINE",
    "HUSH_NARRATION_DRIFT": "ENGINE",
    "HUSH_SAFETY_SUPPRESSION": "CORE_PROTOCOL",
    "PROTOCOL_ENGINE_SPLIT": "CORE_PROTOCOL",
    "ADAPTER_COMMAND_SPLIT": "ADAPTER",
    "COLD_RESUME_FAILURE": "ENGINE",
    "CHAT_MEMORY_AUTHORITY": "EXECUTION_POLICY",
    "FALSE_DONE": "CORE_PROTOCOL",
    "ACCIDENTAL_SUCCESS": "CORE_PROTOCOL",
    "RULE_LOAD_FAILURE": "ENGINE",
    "CONTEXT_OVERLOAD": "ENGINE",
}


_DETECTOR_HYPOTHESES: dict[str, str] = {
    "detect_command_route": (
        "command {canonical!r} routed outside the closed command surface; "
        "the carrier did not recognize it as a declared saipal subcommand"
    ),
    "detect_phase_illegality": (
        "phase transition {from_phase!r} -> {to_phase!r} is not in the declared "
        "carrier phase graph"
    ),
    "detect_active_work_preemption": (
        "active work changed from {prev!r} to {new!r} at seq {switch_seq} without "
        "a terminal boundary closing the prior identity"
    ),
    "detect_false_continue_idle": (
        "continue was emitted while active work {active_work!r} was still open; "
        "continue implies idle, not in-flight work"
    ),
    "detect_source_closure_false_green": (
        "source event {source_kind!r} was received at seq {source_seq} with no "
        "subsequent SESSION_BOUNDARY or PHASE_CHANGE to close the intake"
    ),
}


_DETECTOR_ALTERNATIVES: dict[str, tuple[str, ...]] = {
    "detect_command_route": (
        "user explicitly invoked a non-saipal command that was forwarded by the shell",
        "adapter normalized the command to a canonical form the registry does not list",
    ),
    "detect_phase_illegality": (
        "an emergency recovery path short-circuited the normal phase graph",
        "registry drift: the phase contract was edited mid-session",
    ),
    "detect_active_work_preemption": (
        "the user explicitly switched work and the operator logged the new identity",
        "environment or tool failure caused a stale snapshot to overwrite active work",
    ),
    "detect_false_continue_idle": (
        "the user issued a non-resume continue that was mis-classified as resume",
        "active work field is stale; the prior task already closed",
    ),
    "detect_source_closure_false_green": (
        "the source-of-truth document for this drift is missing from the home",
        "environment or harness failure aborted the closure event",
    ),
}


_DETECTOR_MISSING: dict[str, tuple[str, ...]] = {
    "detect_command_route": (
        "registry snapshot at the time of the command",
        "shell history showing the literal command typed by the user",
    ),
    "detect_phase_illegality": (
        "the active carrier-phase spec the session was running against",
        "operator note explaining the unexpected transition",
    ),
    "detect_active_work_preemption": (
        "an explicit terminal event between the two work identities",
        "BOARD snapshot proving the prior work was actually closed",
    ),
    "detect_false_continue_idle": (
        "the most recent SESSION_BOUNDARY or terminal marker",
        "operator confirmation that no active work was open at continue time",
    ),
    "detect_source_closure_false_green": (
        "the missing SESSION_BOUNDARY or PHASE_CHANGE event that should follow",
        "owner document confirming the source's closure contract",
    ),
}


def _binding_status(episode: dict, session_record: dict, bundle: dict) -> str:
    proto = session_record.get("protocol") if isinstance(session_record, dict) else None
    if isinstance(proto, dict):
        status = proto.get("binding_status")
        if status in ("BOUND", "PARTIAL", "UNKNOWN"):
            return status
    bundle_proto = bundle.get("protocol") if isinstance(bundle, dict) else None
    if isinstance(bundle_proto, dict):
        status = bundle_proto.get("binding_status")
        if status in ("BOUND", "PARTIAL", "UNKNOWN"):
            return status
    return "UNKNOWN"


def _observed(candidate: dict) -> dict:
    observed = candidate.get("observed")
    return observed if isinstance(observed, dict) else {}


def _change_target(drift_class: str) -> str:
    return _CHANGE_TARGET_BY_DRIFT.get(str(drift_class), "UNKNOWN")


def _root_cause(candidate: dict) -> str:
    detector = str(candidate.get("detector") or "")
    template = _DETECTOR_HYPOTHESES.get(detector)
    observed = _observed(candidate)
    if template is None:
        return (
            f"drift class {candidate.get('drift_class')!r} raised by {detector!r} "
            "with no analyst template; mechanical confidence stands on its own"
        )
    try:
        return template.format(**observed)
    except (KeyError, IndexError):
        return (
            f"{detector} fired with observed keys {sorted(observed)}; "
            "hypothesis template could not bind all fields"
        )


def _alternatives(candidate: dict) -> list[str]:
    detector = str(candidate.get("detector") or "")
    return list(_DETECTOR_ALTERNATIVES.get(detector, ()))


def _missing_evidence(candidate: dict) -> list[str]:
    detector = str(candidate.get("detector") or "")
    return list(_DETECTOR_MISSING.get(detector, ()))


def _confidence(
    mechanical: str, binding: str
) -> str:
    if mechanical == "HIGH" and binding == "BOUND":
        return "HIGH"
    if mechanical == "HIGH":
        return "MEDIUM"
    if mechanical == "MEDIUM":
        return "MEDIUM"
    return "LOW"


def classify_candidate(
    candidate: dict,
    episode: dict,
    bundle: dict,
    session_record: dict,
    *,
    registry: dict | None = None,
) -> dict:
    drift_class = str(candidate.get("drift_class", ""))
    mechanical = str(candidate.get("mechanical_confidence", "LOW"))
    binding = _binding_status(episode, session_record, bundle)
    return {
        "drift_class": drift_class,
        "root_cause_hypothesis": _root_cause(candidate),
        "alternative_explanations": _alternatives(candidate),
        "likely_change_target": _change_target(drift_class),
        "missing_evidence": _missing_evidence(candidate),
        "confidence_proposal": _confidence(mechanical, binding),
        "session_id": candidate.get("session_id", ""),
        "episode_id": candidate.get("episode_id", -1),
    }


def contrary_evidence_pass(
    candidate: dict, bundle: dict, episode: dict
) -> dict:
    refs = [int(seq) for seq in (candidate.get("event_refs") or [])]
    lower = max(refs) if refs else -1
    end_seq = int(episode.get("end_seq", -1)) if isinstance(episode, dict) else -1
    findings: list[str] = []
    events = list(bundle.get("events") or []) if isinstance(bundle, dict) else []

    for event in events:
        seq = int(event.get("seq", -1))
        etype = event.get("type")
        facts = event.get("facts") or {}
        if end_seq >= 0 and seq > end_seq:
            continue
        # An explicit user override is a legal mitigation wherever it sits in
        # the episode: the user may have authorized the behavior in advance.
        if etype == "USER_MESSAGE" and isinstance(facts.get("override"), bool) and facts["override"]:
            findings.append("user explicitly overrode the route for this action")
            continue
        if lower >= 0 and seq <= lower:
            continue
        if etype == "STATE_SNAPSHOT" and facts.get("kind") == "adapter_normalization":
            findings.append("adapter normalization event recorded after the candidate")
        if etype == "ERROR" and (facts.get("recovery") or facts.get("kind") == "recovery"):
            findings.append("recovery event follows the candidate event")
        if etype == "SESSION_BOUNDARY" and facts.get("kind") == "owner_doc":
            findings.append("later session boundary carried a source owner document")
        if etype in ("TOOL_RESULT", "TOOL_CALL") and facts.get("env_failure"):
            findings.append("environment or tool failure reported in a later tool event")

    out = dict(candidate)
    out["contrary_evidence_found"] = bool(findings)
    out["contrary_evidence"] = findings
    return out


def analyze_episode(
    episode: dict,
    bundle: dict,
    session_record: dict,
    detector_candidates: list[dict] | None = None,
    *,
    registry: dict | None = None,
) -> list[dict]:
    data = registry if registry is not None else load_registry()
    raw = (
        list(detector_candidates)
        if detector_candidates is not None
        else detect_for_episode(episode, bundle, session_record, registry=data)
    )
    refined: list[dict] = []
    for candidate in raw:
        if not isinstance(candidate, dict):
            continue
        classified = classify_candidate(
            candidate, episode, bundle, session_record, registry=data
        )
        merged = dict(candidate)
        merged.update(classified)
        merged = contrary_evidence_pass(merged, bundle, episode)
        refined.append(merged)
    return refined
