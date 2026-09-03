"""Recurrence / regression intelligence (Wave H)."""

from __future__ import annotations

import copy
import re
from pathlib import Path

from .capability import require_action
from .errors import PalError
from .paths import atomic_write_json, home_paths, read_json

SCHEMA_VERSION = 1

TELEMETRY_KEYS = (
    "sessions_analyzed", "events_analyzed", "bytes_loaded",
    "rule_bytes_loaded", "findings_created", "findings_rejected",
    "audits_emitted", "avg_context_per_episode",
)

_VERSION = re.compile(r"\d+")


def _vt(value) -> tuple:
    return tuple(int(part) for part in _VERSION.findall(str(value or "")))


def _project(session: dict) -> str:
    project = session.get("project")
    if isinstance(project, dict):
        for key in ("id", "name", "slug", "repo"):
            value = project.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return "unknown"


def _provider(session: dict) -> str:
    runtime = session.get("runtime")
    if isinstance(runtime, dict):
        value = runtime.get("provider")
        if isinstance(value, str) and value.strip():
            return value.strip()
    parts = str(session.get("adapter") or "").split(":")
    if len(parts) > 1 and parts[1].strip():
        return parts[1].strip()
    head = parts[0].strip().lower() if parts else ""
    return head or "unknown"


def _occurrence(session: dict, finding: dict, *, conformant: bool) -> dict:
    adapter = str(session.get("adapter") or "")
    model = adapter.split(":", 1)[0].strip().lower() or "unknown"
    return {
        "session_id": session.get("session_id"),
        "adapter": adapter,
        "provider": _provider(session),
        "model_family": model,
        "project": _project(session),
        "protocol_version": ((session.get("protocol") or {}).get("version") or "").strip(),
        "drift_class": str(finding.get("drift_class") or "UNKNOWN"),
        "confidence": finding.get("confidence") or "LOW",
        "severity": finding.get("severity") or "P3",
        "conformant": conformant,
        "imported_at": session.get("imported_at") or "",
    }


def empty_recurrence() -> dict:
    return {"schema_version": SCHEMA_VERSION, "by_finding": {}, "by_rule": {}}


def _valid(data) -> bool:
    return (
        isinstance(data, dict)
        and data.get("schema_version") == SCHEMA_VERSION
        and isinstance(data.get("by_finding"), dict)
        and isinstance(data.get("by_rule"), dict)
    )


def load_recurrence(home: Path | str) -> dict:
    paths = home_paths(home)
    if not paths.recurrence.exists():
        return empty_recurrence()
    try:
        payload = read_json(paths.recurrence)
    except (OSError, ValueError, UnicodeDecodeError):
        return empty_recurrence()
    if not _valid(payload):
        return empty_recurrence()
    return payload


def save_recurrence(home: Path | str, data: dict, *, registry=None) -> dict:
    require_action("write_own_index", registry=registry)
    if not _valid(data):
        raise PalError(
            "VALIDATION_FAILED", "refusing to write an invalid recurrence",
            next_action="the existing recurrence was left untouched",
        )
    paths = home_paths(home)
    atomic_write_json(paths.recurrence, data, root=paths.root)
    return data


def _bump_occurrence(data: dict, finding: dict, session: dict, *, conformant: bool) -> None:
    fingerprint = str(finding.get("fingerprint") or finding.get("finding_id")
                      or finding.get("drift_class") or "UNKNOWN")
    entry = data["by_finding"].setdefault(fingerprint, {
        "finding_id": finding.get("finding_id") or "",
        "fingerprint": fingerprint,
        "causal_key": finding.get("causal_key") or "",
        "drift_class": str(finding.get("drift_class") or "UNKNOWN"),
        "severity": finding.get("severity") or "P3",
        "confidence": finding.get("confidence") or "LOW",
        "last_fix_version": finding.get("last_fix_version") or "",
        "occurrences": [],
    })
    # An entry created before causal keys existed, or by the negative-evidence
    # path, gains its key the first time a real finding supplies one.
    if not entry.get("causal_key") and finding.get("causal_key"):
        entry["causal_key"] = finding["causal_key"]
    entry["occurrences"].append(_occurrence(session, finding, conformant=conformant))
    for rule in finding.get("rule_ids") or []:
        bucket = data["by_rule"].setdefault(str(rule), {"total": 0, "drift": 0})
        bucket["total"] += 1
        if not conformant:
            bucket["drift"] += 1


def record_occurrence(home, finding, session, *, registry=None) -> dict:
    if not isinstance(finding, dict) or not isinstance(session, dict):
        raise PalError("VALIDATION_FAILED", "finding and session must be objects")
    data = load_recurrence(home)
    _bump_occurrence(data, finding, session, conformant=bool(session.get("conformant", True)))
    return save_recurrence(home, data, registry=registry)


def record_negative(home, session, *, registry=None) -> dict:
    if not isinstance(session, dict):
        raise PalError("VALIDATION_FAILED", "session must be an object")
    data = load_recurrence(home)
    _bump_occurrence(
        data, {"drift_class": "CONFORMANT", "severity": "P3", "confidence": "HIGH"},
        session, conformant=True,
    )
    return save_recurrence(home, data, registry=registry)


def _breakdown(data: dict, drift_class: str, dimension: str, label: str) -> list[dict]:
    counts: dict[str, dict] = {}
    for finding in data.get("by_finding", {}).values():
        if finding.get("drift_class") != drift_class:
            continue
        for occurrence in finding.get("occurrences", []):
            key = str(occurrence.get(dimension) or "unknown")
            slot = counts.setdefault(key, {"drift": 0, "total": 0})
            slot["total"] += 1
            if not occurrence.get("conformant", True):
                slot["drift"] += 1
    rows = [
        {label: k, "drift": v["drift"], "total": v["total"],
         "rate": v["drift"] / v["total"] if v["total"] else 0.0}
        for k, v in counts.items()
    ]
    return sorted(rows, key=lambda r: (-r["drift"], -r["total"], r[label]))


def cross_model_recurrence(data: dict, drift_class: str) -> list[dict]:
    return _breakdown(data, drift_class, "model_family", "model")


def cross_project_recurrence(data: dict, drift_class: str) -> list[dict]:
    return _breakdown(data, drift_class, "project", "project")


def _summary(occurrences: list[dict]) -> dict:
    sessions = {o.get("session_id") for o in occurrences}
    drift_sessions = {o.get("session_id") for o in occurrences
                      if not o.get("conformant", True)}
    return {
        "occurrences": len(occurrences),
        "sessions": len(sessions),
        "rate": len(drift_sessions) / len(sessions) if sessions else 0.0,
    }


def before_after_analysis(data: dict, drift_class: str, fix_version: str) -> dict:
    fix = _vt(fix_version)
    before, after = [], []
    for finding in data.get("by_finding", {}).values():
        if finding.get("drift_class") != drift_class:
            continue
        for occurrence in finding.get("occurrences", []):
            version = _vt(occurrence.get("protocol_version"))
            target = before if version and fix and version < fix else after
            target.append(occurrence)
    return {"before": _summary(before), "after": _summary(after)}


def detect_regression(data, fingerprint, new_session, *, registry=None) -> dict | None:
    finding = data.get("by_finding", {}).get(fingerprint) if isinstance(data, dict) else None
    if not isinstance(finding, dict):
        return None
    last_fix = finding.get("last_fix_version")
    version = ((new_session.get("protocol") or {}).get("version") or "").strip()
    if not last_fix or not version or _vt(version) < _vt(last_fix):
        return None
    return {
        "regression": True,
        "original_finding_id": finding.get("finding_id") or "",
        "last_fix_version": last_fix,
        "occurrence": _occurrence(new_session, finding, conformant=False),
    }


#: What a spread means for the fix surface. One model drifting where others
#: comply is evidence about that model; the same drift across models under one
#: protocol version is evidence about the protocol or its enforcement.
SPREAD_SINGLE = "SINGLE_MODEL"
SPREAD_CROSS_MODEL = "CROSS_MODEL"
SPREAD_CROSS_PROJECT = "CROSS_PROJECT"
SPREAD_CROSS_BOTH = "CROSS_MODEL_AND_PROJECT"
SPREAD_UNKNOWN = "UNKNOWN"


def spread(data: dict, drift_class: str) -> dict:
    """How widely one drift class has actually been observed.

    The judgement this supports is PAL-FINDING-02's: an isolated model failure
    normally points at enforcement, guidance or a conformance test, NOT at
    rewriting the protocol. Reporting the spread lets the analyst make that call
    from evidence instead of from the single session in front of it.
    """
    models = {row["model"]: row for row in cross_model_recurrence(data, drift_class)}
    projects = {row["project"]: row for row in cross_project_recurrence(data, drift_class)}
    drifting_models = sorted(name for name, row in models.items() if row["drift"] > 0)
    clean_models = sorted(name for name, row in models.items() if row["drift"] == 0)
    drifting_projects = sorted(name for name, row in projects.items() if row["drift"] > 0)

    if not drifting_models and not drifting_projects:
        classification = SPREAD_UNKNOWN
    elif len(drifting_models) > 1 and len(drifting_projects) > 1:
        classification = SPREAD_CROSS_BOTH
    elif len(drifting_models) > 1:
        classification = SPREAD_CROSS_MODEL
    elif len(drifting_projects) > 1:
        classification = SPREAD_CROSS_PROJECT
    else:
        classification = SPREAD_SINGLE

    return {
        "drift_class": drift_class,
        "classification": classification,
        "drifting_models": drifting_models,
        "clean_models": clean_models,
        "drifting_projects": drifting_projects,
        "occurrences": sum(row["drift"] for row in models.values()),
        "isolated_to_one_model": classification == SPREAD_SINGLE and len(drifting_models) == 1,
        "contradicted_by_a_clean_model": bool(
            classification == SPREAD_SINGLE and clean_models
        ),
        "guidance": _spread_guidance(classification, clean_models),
    }


def _spread_guidance(classification: str, clean_models: list) -> str:
    if classification in (SPREAD_CROSS_MODEL, SPREAD_CROSS_BOTH):
        return (
            "the same drift appears under more than one model, so the protocol or its "
            "executable enforcement is the likelier surface than any single model"
        )
    if classification == SPREAD_CROSS_PROJECT:
        return (
            "one model drifts across several projects, so the surface is that model's "
            "guidance or the engine's enforcement rather than one project's setup"
        )
    if classification == SPREAD_SINGLE and clean_models:
        return (
            "another model complied under the same rule, so this is model "
            "noncompliance: prefer enforcement, guidance or a conformance test over "
            "changing the protocol"
        )
    if classification == SPREAD_SINGLE:
        return (
            "observed under one model only, with no comparison available; treat "
            "protocol change as unproven"
        )
    return "no drift occurrences recorded for this class"


def update_telemetry(home, telemetry, *, registry=None) -> dict:
    if not isinstance(telemetry, dict):
        raise PalError("VALIDATION_FAILED", "telemetry must be an object")
    require_action("write_own_index", registry=registry)
    paths = home_paths(home)
    current: dict = {}
    if paths.telemetry.exists():
        try:
            loaded = read_json(paths.telemetry)
            if isinstance(loaded, dict):
                current = loaded
        except (OSError, ValueError, UnicodeDecodeError):
            current = {}
    merged = copy.deepcopy(current)
    merged.setdefault("schema_version", SCHEMA_VERSION)
    for key in TELEMETRY_KEYS:
        if key in telemetry:
            merged[key] = telemetry[key]
    atomic_write_json(paths.telemetry, merged, root=paths.root)
    return merged
