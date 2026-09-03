"""Audit markdown builder and quality gate (PAL-AUDIT-03).

Builds an immutable audit body from a qualified finding and its session evidence,
then checks it against the 12-question PAL-AUDIT-03 quality gate before enqueue.
"""

from __future__ import annotations

from .redact import redact_audit_body

TEMPLATE_SECTIONS = (
    "Identity",
    "Observed scope",
    "Applicable protocol",
    "Observed behavior",
    "Evidence",
    "Contradiction",
    "Root-cause assessment",
    "Recurrence",
    "Impact",
    "Recommended maintainer direction",
    "Verification to add",
    "DO NOT WEAKEN",
    "Non-goals",
    "Historical applicability",
    "Acceptance",
)

QUALITY_QUESTIONS = (
    "What happened?",
    "Where?",
    "Which model/project/adapter?",
    "Which protocol version?",
    "Which rule applied?",
    "What was observed?",
    "Why is it a contradiction?",
    "Why is it not a simpler explanation?",
    "Where is the likely fix surface?",
    "What must not be weakened?",
    "How to reproduce?",
    "How to prove closure?",
)

_QUESTION_TO_SECTION = {
    "What happened?": "Contradiction",
    "Where?": "Observed scope",
    "Which model/project/adapter?": "Observed scope",
    "Which protocol version?": "Applicable protocol",
    "Which rule applied?": "Applicable protocol",
    "What was observed?": "Observed behavior",
    "Why is it a contradiction?": "Contradiction",
    "Why is it not a simpler explanation?": "Root-cause assessment",
    "Where is the likely fix surface?": "Recommended maintainer direction",
    "What must not be weakened?": "DO NOT WEAKEN",
    "How to reproduce?": "Verification to add",
    "How to prove closure?": "Acceptance",
}

#: The exact fields each question needs answered. Section-level checking was not
#: enough: two questions can share a section, so a blank `models` field passed on
#: the strength of a populated `projects` field next to it. Every question now
#: names the fields that actually answer it, and ALL of them must carry content.
_QUESTION_TO_FIELDS: dict[str, tuple[str, ...]] = {
    "What happened?": ("actual", "why_they_conflict"),
    "Where?": ("sessions", "projects"),
    "Which model/project/adapter?": ("models", "adapters"),
    "Which protocol version?": ("historical_protocol_binding",),
    "Which rule applied?": ("rule_ids", "owner_documents"),
    "What was observed?": ("actual_behavior",),
    "Why is it a contradiction?": ("expected", "actual"),
    "Why is it not a simpler explanation?": (
        "primary_hypothesis",
        "why_alternatives_were_rejected",
    ),
    "Where is the likely fix surface?": ("preferred_fix_surface",),
    "What must not be weakened?": ("protected_invariants",),
    "How to reproduce?": ("reproduction",),
    "How to prove closure?": ("1.",),
}

def _fmt(val: object) -> str:
    if val is None:
        return ""
    if isinstance(val, list):
        return ", ".join(str(v) for v in val)
    if isinstance(val, dict):
        import json

        return json.dumps(val, indent=2, default=str)
    return str(val)


def _section(title: str, *fields: tuple[str, object]) -> str:
    lines = [f"## {title}", ""]
    for label, value in fields:
        rendered = _fmt(value)
        if rendered:
            lines.append(f"- {label}: {rendered}")
        else:
            lines.append(f"- {label}:")
    lines.append("")
    return "\n".join(lines)


def _protocol_binding(finding: dict, bundle: dict) -> str:
    bindings = finding.get("protocol_bindings") or []
    if bindings:
        return _fmt(bindings[0])
    proto = bundle.get("protocol") or {}
    return _fmt(proto.get("binding_status", "UNKNOWN"))


def _historical_rule_surface(finding: dict) -> str:
    """The retrieved historical rule identity, as digests the maintainer can re-fetch.

    Never the rule text: an audit quotes the protocol by identity, so it cannot
    drift out of step with the authority it came from.
    """
    surface = finding.get("historical_rule_surface")
    if not isinstance(surface, dict):
        return ""
    status = str(surface.get("status") or "UNAVAILABLE")
    if status != "RESOLVED":
        reasons = "; ".join(
            f"{attempt.get('source', 'UNKNOWN')}: {attempt.get('reason', '')}"
            for attempt in (surface.get("attempts") or [])
            if isinstance(attempt, dict)
        )
        return f"{status} ({reasons})" if reasons else status
    rules = ", ".join(
        f"{rule.get('rule_id')}@{rule.get('owner')} doc={str(rule.get('document_sha256') or '')[:12]}"
        for rule in (surface.get("rules") or [])
        if isinstance(rule, dict)
    )
    return (
        f"{status} via {surface.get('source')} identity={surface.get('identity')} "
        f"registry={str(surface.get('registry_sha256') or '')[:12]}"
        + (f" rules=[{rules}]" if rules else "")
    )


def _verdict(finding: dict) -> str:
    audit = finding.get("audit") or {}
    return str(audit.get("maintainer_verdict", "PENDING"))


def _runtime_identity(session_record: dict, bundle: dict) -> str:
    """provider/model/agent, from the index record or the bundle.

    A maintainer's first question about drift is *which model did this*, and the
    second is *under which provider and agent*. Leaving it blank made every audit
    unattributable, which is most of why they were hard to act on.
    """
    runtime = session_record.get("runtime")
    if not isinstance(runtime, dict) or not runtime:
        runtime = bundle.get("runtime") if isinstance(bundle.get("runtime"), dict) else {}
    parts = [
        str(runtime.get(key) or "")
        for key in ("provider", "model", "agent", "reasoning_mode")
    ]
    labels = ("provider", "model", "agent", "reasoning")
    rendered = [
        f"{label}={value}" for label, value in zip(labels, parts) if value
    ]
    return ", ".join(rendered)


def _project_identity(session_record: dict, bundle: dict) -> str:
    project = session_record.get("project")
    if not isinstance(project, dict) or not project:
        project = bundle.get("project") if isinstance(bundle.get("project"), dict) else {}
    name = project.get("name") or project.get("project") or ""
    fingerprint = str(project.get("root_fingerprint") or "")
    head = str(project.get("git_head") or "")
    parts = [str(name)] if name else []
    if fingerprint:
        parts.append(f"root={fingerprint}")
    if head:
        parts.append(f"git_head={head}")
    return ", ".join(parts)


def _owner_documents(finding: dict, registry: dict | None) -> str:
    """The documents that own the cited rules, resolved from the registry.

    The registry is loaded when the caller did not thread one through: an audit
    that omits its owner documents because of a plumbing detail is exactly the
    unroutable audit this metadata exists to prevent.
    """
    data = registry
    if not isinstance(data, dict) or "rule_owners" not in data:
        from .registry import load_registry, RegistryError

        try:
            data = load_registry()
        except RegistryError:
            return ""
    owners = data.get("rule_owners")
    if not isinstance(owners, dict):
        return ""
    seen: list[str] = []
    for rule in finding.get("rule_ids") or []:
        document = owners.get(str(rule))
        if document and document not in seen:
            seen.append(str(document))
    return ", ".join(seen)


def _session_identity(session_record: dict) -> str:
    parts = [str(session_record.get("session_id") or "")]
    generation = session_record.get("generation")
    if generation is not None:
        parts.append(f"gen={generation}")
    temperature = session_record.get("temperature")
    if temperature:
        parts.append(str(temperature))
    finality = session_record.get("episode_finality") or ""
    if finality:
        parts.append(str(finality))
    return ", ".join(part for part in parts if part)


def _occurrence_dimension(
    occurrences: list, session_record: dict, bundle: dict, dimension: str
) -> str:
    """What this finding spans along one dimension, from its own occurrences.

    Only the observing session's identity is known here, so a single-session
    finding reports one value rather than an empty field. The recurrence ledger
    owns the cross-session picture; this is the audit's honest local view.
    """
    runtime = session_record.get("runtime")
    if not isinstance(runtime, dict) or not runtime:
        runtime = bundle.get("runtime") if isinstance(bundle.get("runtime"), dict) else {}
    project = session_record.get("project")
    if not isinstance(project, dict) or not project:
        project = bundle.get("project") if isinstance(bundle.get("project"), dict) else {}
    value = (
        str(runtime.get("model") or "")
        if dimension == "model"
        else str(project.get("name") or "")
    )
    sessions = len({entry.get("session_id") for entry in occurrences or []})
    if not value:
        return ""
    return f"{value} ({sessions} session(s) observed)"


def _spread(finding: dict) -> str:
    """The recurrence spread verdict the analyst reasoned against, if any.

    It travels on the finding rather than being recomputed here: the audit must
    record what was known when the judgement was made, not what the ledger says
    later.
    """
    spread = finding.get("recurrence_spread")
    if not isinstance(spread, dict):
        return ""
    models = ", ".join(spread.get("drifting_models") or []) or "none recorded"
    clean = ", ".join(spread.get("clean_models") or [])
    parts = [f"{spread.get('classification', 'UNKNOWN')} (drifting: {models}"]
    if clean:
        parts.append(f"compliant: {clean}")
    rendered = "; ".join(parts) + ")"
    guidance = str(spread.get("guidance") or "")
    return f"{rendered} — {guidance}" if guidance else rendered


def build_audit_body(
    finding: dict,
    session_record: dict,
    bundle: dict,
    *,
    registry: dict | None = None,
) -> str:
    parts: list[str] = []

    root_cause = (finding.get("root_cause") or "").strip()
    short = (root_cause[:60] + "...") if len(root_cause) > 60 else root_cause or "UNKNOWN"
    parts.append(f"# SAIPAL AUDIT — {short}")
    parts.append("")

    parts.append(
        _section(
            "Identity",
            ("finding_id", finding.get("finding_id")),
            ("producer", "SAIPAL"),
            ("created_at", session_record.get("imported_at")),
            ("severity", finding.get("severity")),
            ("confidence", finding.get("confidence")),
            ("drift_class", finding.get("drift_class")),
            ("change_target", finding.get("change_target")),
            ("maintainer_verdict", _verdict(finding)),
            ("related_audit", ""),
            ("amends_audit", ""),
        )
    )

    scope = bundle.get("project") or {}
    sessions_fmt = _session_identity(session_record) or _fmt(
        session_record.get("session_id")
    )
    parts.append(
        _section(
            "Observed scope",
            ("projects", _project_identity(session_record, bundle) or scope.get("name") or ""),
            ("models", _runtime_identity(session_record, bundle)),
            ("adapters", session_record.get("adapter") or bundle.get("adapter")),
            ("sessions", sessions_fmt),
            ("protocol_versions", _protocol_binding(finding, bundle)),
        )
    )

    proto = bundle.get("protocol") or {}
    parts.append(
        _section(
            "Applicable protocol",
            ("rule_ids", finding.get("rule_ids")),
            ("owner_documents", _owner_documents(finding, registry)),
            ("historical_protocol_binding", _protocol_binding(finding, bundle)),
            ("historical_rule_surface", _historical_rule_surface(finding)),
            ("expected_behavior", proto.get("binding_status", "UNKNOWN")),
        )
    )

    parts.append(
        _section(
            "Observed behavior",
            ("actual_behavior", root_cause),
            ("analyst_reasoning", finding.get("analyst_reasoning", "")),
            ("disposition_class", finding.get("disposition_class", "")),
        )
    )

    bundle_sha = bundle.get("bundle_sha256") or bundle.get("session_sha256") or ""
    occurrences = finding.get("occurrences") or []
    first_occ = occurrences[0] if occurrences else {}
    parts.append(
        _section(
            "Evidence",
            ("session", first_occ.get("session_id")),
            ("episode", first_occ.get("episode_id")),
            ("event_refs", first_occ.get("event_refs")),
            ("source_digest", bundle_sha),
            ("minimal_excerpt", root_cause[:200]),
            ("state/tool/log evidence", ""),
        )
    )

    parts.append(
        _section(
            "Contradiction",
            ("expected", "protocol rule"),
            ("actual", root_cause),
            ("why_they_conflict", root_cause),
        )
    )

    alts = finding.get("alternatives") or []
    challenge = finding.get("challenge") or {}
    loser_rejection = challenge.get("loser_rejection") or ""
    if not loser_rejection and alts:
        loser_rejection = (
            "alternatives lack executable evidence that neutralizes the primary"
        )
    elif not loser_rejection:
        loser_rejection = "no alternative explanation survived challenge"
    parts.append(
        _section(
            "Root-cause assessment",
            ("primary_hypothesis", root_cause),
            ("alternative_explanations", alts),
            ("why_alternatives_were_rejected", loser_rejection),
        )
    )

    parts.append(
        _section(
            "Recurrence",
            ("occurrences", len(occurrences)),
            ("causal_key", finding.get("causal_key", "")),
            ("cross_model", _occurrence_dimension(occurrences, session_record, bundle, "model")),
            ("cross_project", _occurrence_dimension(occurrences, session_record, bundle, "project")),
            ("spread", _spread(finding)),
            ("negative_evidence", ""),
        )
    )

    parts.append(_section("Impact", ("what_can_go_wrong", root_cause)))

    parts.append(
        _section(
            "Recommended maintainer direction",
            ("preferred_fix_surface", finding.get("change_target")),
            ("ordered_steps", ""),
        )
    )

    parts.append(
        _section(
            "Verification to add",
            ("reproduction", root_cause),
            ("tests", _fmt(finding.get("missing_evidence"))),
            ("red_controls", _fmt(finding.get("event_refs"))),
        )
    )

    invariants = _fmt(finding.get("protected_invariants"))
    harm = finding.get("harm_warnings") or []
    parts.append(
        _section(
            "DO NOT WEAKEN",
            ("protected_invariants", invariants),
            ("harm_warnings", harm),
        )
    )

    parts.append(_section("Non-goals", ("this audit does not claim", "")))

    parts.append(
        _section(
            "Historical applicability",
            ("session_protocol_status", _protocol_binding(finding, bundle)),
            ("historical_rule_surface", _historical_rule_surface(finding)),
            ("current_protocol_protection", "UNKNOWN"),
        )
    )

    parts.append(
        _section(
            "Acceptance",
            ("1.", "maintainer reproduces the finding from session and event refs"),
            ("2.", "maintainer confirms or rejects the root cause"),
            ("3.", "closure recorded via disposition import"),
        )
    )

    body = "\n".join(parts)
    return redact_audit_body(body)


def _section_block(body: str, section: str) -> str | None:
    """The text of one section, or None when the section is absent."""
    header = f"## {section}"
    if header not in body:
        return None
    idx = body.index(header)
    block = body[idx + len(header) :]
    return block[: _next_section(block)]


def _field_values(block: str) -> dict[str, str]:
    """`{field: value}` for the `- field: value` lines of one section.

    A multi-line value (a JSON blob, an indented continuation) is folded into the
    field it belongs to, so a rendered binding object still counts as an answer.
    """
    values: dict[str, str] = {}
    current: str | None = None
    for raw in block.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("<!--"):
            continue
        if stripped.startswith("- ") and ":" in stripped:
            name, _, value = stripped[2:].partition(":")
            current = name.strip()
            values[current] = value.strip()
            continue
        if current is not None:
            values[current] = (values[current] + " " + stripped).strip()
    return values


def audit_quality_gate(body: str, finding: dict) -> list[str]:
    """The 12 questions PAL-AUDIT-03 requires, checked field by field.

    A question is answered only when every field that carries it has substantive
    content. Section-level checking let a blank field pass on a populated
    neighbour, which is how an unattributable audit reached a maintainer looking
    like work.
    """
    missing: list[str] = []
    for question in QUALITY_QUESTIONS:
        section = _QUESTION_TO_SECTION.get(question)
        if section is None:
            missing.append(question)
            continue
        block = _section_block(body, section)
        if block is None:
            missing.append(question)
            continue
        fields = _QUESTION_TO_FIELDS.get(question)
        values = _field_values(block)
        if fields:
            answered = all(
                name in values
                and values[name]
                and not _placeholder_line(f"{name}: {values[name]}")
                for name in fields
            )
            if not answered:
                missing.append(question)
            continue
        # No field mapping declared: fall back to "the section says something".
        substantive = [
            value for value in values.values()
            if value and not _placeholder_line(value)
        ]
        if not substantive:
            missing.append(question)
    return missing


# Generic filler phrases that look like answers but carry no information.
# The audit gate must reject these so a placeholder audit cannot sneak past
# (T-029: "evidence supports the primary hypothesis" is not an answer).
_FILLER_PHRASES = frozenset({
    "",
    "UNKNOWN",
    "N/A",
    "NONE",
    "NULL",
    "TBD",
    "EVIDENCE SUPPORTS THE PRIMARY HYPOTHESIS",
    "EVIDENCE SUPPORTS THE PRIMARY",
    "SEE ABOVE",
    "AS NOTED ABOVE",
})


def _placeholder_line(line: str) -> bool:
    value = line.split(":", 1)[1].strip() if ":" in line else line.strip()
    return value.upper() in _FILLER_PHRASES


def _next_section(text: str) -> int:
    for sep in ("\n## ", "\n# "):
        idx = text.find(sep)
        if idx != -1:
            return idx
    return len(text)


def passes_quality_gate(body: str, finding: dict) -> bool:
    return len(audit_quality_gate(body, finding)) == 0