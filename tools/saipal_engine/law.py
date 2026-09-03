"""Applicable law resolver for SAIPAL Wave C."""

from __future__ import annotations

import re
from typing import Any

from .errors import PalError
from .registry import RegistryError, load_registry
from .sessions import historical_applicability

LAW_SURFACE: dict[str, dict[str, Any]] = {
    "COMMAND_ROUTE_DRIFT": {
        "rule_ids": ["PAL-CMD-01", "PAL-CMD-02", "PAL-CMD-03"],
        "owner": "saipal/COMMANDS.md",
        "expected": "commands route through declared phase contract",
    },
    "ACTIVE_WORK_PREEMPTION": {
        "rule_ids": ["PAL-SESSION-01", "PAL-SESSION-02"],
        "owner": "saipal/SESSIONS.md",
        "expected": "session work identity is stable across episode",
    },
    "BOARD_PRIORITY_DRIFT": {
        "rule_ids": ["PAL-ROLE-01", "PAL-OWNERSHIP-01"],
        "owner": "saipal/CORE.md",
        "expected": "board priority reflects work queue order",
    },
    "PHASE_ILLEGALITY": {
        "rule_ids": ["PAL-CMD-02", "PAL-CMD-03"],
        "owner": "saipal/COMMANDS.md",
        "expected": "phase transition respects declared carrier-phase contract",
    },
    "PHASE_SKIP": {
        "rule_ids": ["PAL-CMD-02", "PAL-CMD-03"],
        "owner": "saipal/COMMANDS.md",
        "expected": "no phase may be skipped in carrier sequence",
    },
    "SOURCE_CLOSURE_FALSE_GREEN": {
        "rule_ids": ["PAL-EVIDENCE-01", "PAL-FINDING-01"],
        "owner": "saipal/FINDINGS.md",
        "expected": "source closure requires verified evidence, not assertion",
    },
    "RECOVERY_ORDER_DRIFT": {
        "rule_ids": ["PAL-BOOT-01", "PAL-BOOT-02", "PAL-CMD-02"],
        "owner": "saipal/BOOT.md",
        "expected": "recovery follows declared ordering contract",
    },
    "DESTRUCTIVE_GATE_DRIFT": {
        "rule_ids": ["PAL-DONOHARM-01", "PAL-NOEDIT-01", "PAL-WRITE-01"],
        "owner": "saipal/CORE.md",
        "expected": "destructive actions pass pre-execution gate",
    },
    "CONTINUE_IDLE_FALSE_POSITIVE": {
        "rule_ids": ["PAL-SESSION-01", "PAL-SESSION-04"],
        "owner": "saipal/SESSIONS.md",
        "expected": "continue from idle requires active session evidence",
    },
    "IMPROVE_PRECEDENCE_DRIFT": {
        "rule_ids": ["PAL-ROLE-01", "PAL-OWNERSHIP-01"],
        "owner": "saipal/CORE.md",
        "expected": "improve respects role and ownership boundaries",
    },
    "AUDIT_INBOX_DRIFT": {
        "rule_ids": ["PAL-AUDIT-01", "PAL-AUDIT-02", "PAL-AUDIT-03"],
        "owner": "saipal/AUDITS.md",
        "expected": "audit publication follows inbox lifecycle",
    },
    "COLD_RESUME_FAILURE": {
        "rule_ids": ["PAL-BOOT-01", "PAL-BOOT-02", "PAL-SESSION-05"],
        "owner": "saipal/BOOT.md",
        "expected": "cold resume recovers state from last checkpoint",
    },
    "FALSE_DONE": {
        "rule_ids": ["PAL-ROOTCAUSE-01", "PAL-EVIDENCE-01", "PAL-FINDING-02"],
        "owner": "saipal/CORE.md",
        "expected": "done requires verified root cause, not absence of error",
    },
    "ACCIDENTAL_SUCCESS": {
        "rule_ids": ["PAL-ROOTCAUSE-01", "PAL-FINDING-02"],
        "owner": "saipal/CORE.md",
        "expected": "success must be traced to deliberate action, not coincidence",
    },
    "PROTOCOL_ENGINE_SPLIT": {
        "rule_ids": ["PAL-ROLE-01", "PAL-BINDING-01", "PAL-SESSION-03"],
        "owner": "saipal/CORE.md",
        "expected": "protocol and engine version binding is consistent",
    },
    "SOURCE_AUTHORITY_DRIFT": {
        "rule_ids": ["PAL-EVIDENCE-01", "PAL-SESSION-01", "PAL-SESSION-03"],
        "owner": "saipal/SESSIONS.md",
        "expected": "source authority and historical binding are explicit",
    },
    "EVIDENCE_FABRICATION": {
        "rule_ids": ["PAL-EVIDENCE-01", "PAL-FINDING-02"],
        "owner": "saipal/CORE.md",
        "expected": "claims use observable evidence only",
    },
    "HUSH_NARRATION_DRIFT": {
        "rule_ids": ["PAL-FINDING-01", "PAL-FINDING-02"],
        "owner": "saipal/FINDINGS.md",
        "expected": "required operational trace is not suppressed",
    },
    "HUSH_SAFETY_SUPPRESSION": {
        "rule_ids": ["PAL-DONOHARM-01", "PAL-EVIDENCE-01"],
        "owner": "saipal/CORE.md",
        "expected": "safety and evidence warnings remain visible",
    },
    "ADAPTER_COMMAND_SPLIT": {
        "rule_ids": ["PAL-SESSION-01", "PAL-SESSION-04"],
        "owner": "saipal/SESSIONS.md",
        "expected": "adapters preserve command semantics during normalization",
    },
    "CHAT_MEMORY_AUTHORITY": {
        "rule_ids": ["PAL-EVIDENCE-01", "PAL-ROOTCAUSE-01"],
        "owner": "saipal/CORE.md",
        "expected": "chat memory does not outrank durable project evidence",
    },
    "RULE_LOAD_FAILURE": {
        "rule_ids": ["PAL-BOOT-01", "PAL-ROLE-01"],
        "owner": "saipal/BOOT.md",
        "expected": "the applicable owner document is loaded before enforcement",
    },
    "CONTEXT_OVERLOAD": {
        "rule_ids": ["PAL-EVIDENCE-01", "PAL-SESSION-04"],
        "owner": "saipal/SESSIONS.md",
        "expected": "evidence remains bounded and auditable",
    },
}

#: Alias — same bounded surface, prefer this name for law-resolution context.
RESOLVED_LAW = LAW_SURFACE


def _owner_documents(rule_ids: list[str], *, registry: dict[str, Any]) -> list[str]:
    owners = registry.get("rule_owners", {})
    seen: list[str] = []
    for rid in rule_ids:
        doc = owners.get(rid)
        if doc and doc not in seen:
            seen.append(doc)
    return seen


def load_law_surface(*, registry: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    try:
        data = registry if registry is not None else load_registry(required=False)
    except RegistryError:
        return dict(LAW_SURFACE)

    if not data:
        return dict(LAW_SURFACE)

    surface = data.get("law_surface")
    if isinstance(surface, dict) and surface:
        return surface
    return dict(LAW_SURFACE)


def resolve_law(
    drift_class: str,
    *,
    registry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    surface = load_law_surface(registry=registry)
    entry = surface.get(drift_class)
    if entry is None:
        raise PalError(
            "UNKNOWN_DRIFT_CLASS",
            f"drift class {drift_class!r} is not in the law surface",
            next_action="check REGISTRY.json drift_taxonomy for valid classes",
        )

    data = registry if registry is not None else load_registry(required=False)
    docs = _owner_documents(entry["rule_ids"], registry=data) if data else []

    return {
        "rule_ids": list(entry["rule_ids"]),
        "owner_documents": docs,
        "drift_class": drift_class,
        "expected_behavior": entry["expected"],
    }


def resolve_for_episode(
    episode: dict,
    session_protocol: dict | None,
    *,
    registry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    drift_class = _drift_class_for_kind(episode.get("kind", "unknown"))
    law = resolve_law(drift_class, registry=registry)

    data = registry if registry is not None else load_registry(required=False)
    deferred = data.get("deferred_semantics", {}) if data else {}
    rule_introduced = _earliest_version(law["rule_ids"], deferred)

    applicability = historical_applicability(
        session_protocol,
        rule_introduced_in=rule_introduced,
        current_version=session_protocol.get("version") if session_protocol else None,
        fix_version=None,
        binding_status=(session_protocol or {}).get("binding_status"),
    )

    return {
        "applicable_law": law,
        "violation_claimable": applicability["violation_claimable"],
        "reason": applicability["reason"],
        "current_protocol_protection": applicability["current_protocol_protection"],
    }


_KIND_TO_DRIFT: dict[str, str] = {
    "command": "COMMAND_ROUTE_DRIFT",
    "work_switch": "ACTIVE_WORK_PREEMPTION",
    "phase_change": "PHASE_ILLEGALITY",
    "source_intake": "SOURCE_CLOSURE_FALSE_GREEN",
    "recovery": "RECOVERY_ORDER_DRIFT",
    "terminal_task": "FALSE_DONE",
}


def _drift_class_for_kind(episode_kind: str) -> str:
    return _KIND_TO_DRIFT.get(episode_kind, "PROTOCOL_ENGINE_SPLIT")


def _earliest_version(
    rule_ids: list[str],
    deferred: dict[str, Any],
) -> str | None:
    """The version in which the earliest matching deferred rule appeared.

    `deferred_semantics` maps a contract name to `{introduced_in, rules}`. The
    returned value MUST be a comparable version string: it feeds
    `historical_applicability(rule_introduced_in=...)`, whose comparison is a
    numeric tuple. Returning the contract NAME made that comparison a no-op --
    `_version_tuple("WAVE_H_HUSH")` is `()`, which is never greater than a real
    version, so the no-hindsight gate silently passed everything (T-027). The
    legacy list shape is still read so an old registry does not become corrupt;
    it simply carries no version and defers nothing.
    """
    versions: list[str] = []
    for _name, entry in sorted(deferred.items()):
        if isinstance(entry, dict):
            rules = entry.get("rules") or []
            introduced = entry.get("introduced_in")
        else:
            rules = entry or []
            introduced = None
        if not any(rid in rules for rid in rule_ids):
            continue
        if isinstance(introduced, str) and introduced.strip():
            versions.append(introduced.strip())
    if not versions:
        return None
    return min(versions, key=_version_key)


def _version_key(version: str) -> tuple:
    return tuple(int(part) for part in re.findall(r"\d+", version))