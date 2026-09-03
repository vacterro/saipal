"""Mechanical drift detectors (Wave C).

Each detector takes `(episode, bundle, session_record, *, registry=None)` and
returns a candidate dict or `None`. Detectors emit only on mechanical evidence
that survives the no-hindsight rule: they compare observed facts against the
closed registry, never against prose.
"""

from __future__ import annotations

from typing import Any

from .episodes import ACTIVE_WORK_KEYS, TERMINAL_KIND
from .errors import PalError
from .registry import load_registry

DETECTOR_REGISTRY: list[str] = [
    "detect_command_route",
    "detect_phase_illegality",
    "detect_active_work_preemption",
    "detect_false_continue_idle",
    "detect_source_closure_false_green",
]

# Carrier phase machine -- mirrors SAIPEN CORE.md §1.6's canonical transition
# table. From-any-phase entry (CLEAN/TRANSLATE/PREPARE/VALIDATE/MARKHUNT/PLAN/
# HUNT) is expressed as a full FROM row so the detector stays mechanical.
_LEGAL_PHASE_EDGES: frozenset[tuple[str, str]] = frozenset(
    {
        ("INIT", "PLAN"),
        ("INIT", "BLOCKED"),
        ("PLAN", "SCOUT"),
        ("PLAN", "BUILD"),
        ("PLAN", "DONE"),
        ("PLAN", "BLOCKED"),
        ("SCOUT", "BUILD"),
        ("SCOUT", "BLOCKED"),
        ("BUILD", "VERIFY"),
        ("BUILD", "BLOCKED"),
        ("VERIFY", "REVIEW"),
        ("VERIFY", "SCOUT"),
        ("VERIFY", "BUILD"),
        ("VERIFY", "BLOCKED"),
        ("REVIEW", "SHIP"),
        ("REVIEW", "BUILD"),
        ("REVIEW", "SCOUT"),
        ("REVIEW", "BLOCKED"),
        ("SHIP", "DONE"),
        ("SHIP", "BUILD"),
        ("SHIP", "BLOCKED"),
        ("DONE", "SCOUT"),
        ("DONE", "PLAN"),
        ("DONE", "HUNT"),
        ("DONE", "BLOCKED"),
        ("VALIDATE", "SCOUT"),
        ("VALIDATE", "PLAN"),
        ("VALIDATE", "DONE"),
        ("VALIDATE", "BLOCKED"),
        ("HUNT", "ADD"),
        ("HUNT", "PLAN"),
        ("HUNT", "SCOUT"),
        ("HUNT", "BLOCKED"),
        ("MARKHUNT", "DONE"),
        ("MARKHUNT", "BLOCKED"),
        ("ADD", "BUILD"),
        ("ADD", "PLAN"),
        ("ADD", "SCOUT"),
        ("ADD", "DONE"),
        ("ADD", "BLOCKED"),
        ("CLEAN", "DONE"),
        ("CLEAN", "BLOCKED"),
        ("TRANSLATE", "DONE"),
        ("TRANSLATE", "BLOCKED"),
        ("PREPARE", "DONE"),
        ("PREPARE", "BLOCKED"),
        ("BLOCKED", "PLAN"),
        ("BLOCKED", "SCOUT"),
        ("BLOCKED", "DONE"),
        # from-any-phase entry by explicit command (§1.6):
        ("*", "CLEAN"),
        ("*", "TRANSLATE"),
        ("*", "PREPARE"),
        ("*", "VALIDATE"),
        ("*", "MARKHUNT"),
        ("*", "PLAN"),
        ("*", "HUNT"),
    }
)

_TERMINAL_KINDS = frozenset({TERMINAL_KIND, "terminal_task", "session_end"})


def _events(bundle: dict) -> list[dict]:
    return list(bundle.get("events") or [])


def _span(bundle: dict, episode: dict) -> list[dict]:
    start = int(episode["start_seq"])
    end = int(episode["end_seq"])
    return [
        event
        for event in _events(bundle)
        if start <= int(event["seq"]) <= end
    ]


def _active_work(event: dict) -> Any:
    facts = event.get("facts") or {}
    for key in ACTIVE_WORK_KEYS:
        if key in facts:
            return facts[key]
    return None


def _known_commands(registry: dict | None) -> set[str]:
    data = registry if registry is not None else load_registry()
    surface = data.get("observed_command_tokens")
    if isinstance(surface, list):
        return {str(t) for t in surface if isinstance(t, str) and t.strip()}
    commands = data.get("commands")
    if not isinstance(commands, dict):
        return set()
    known: set[str] = set()
    for tool, subs in commands.items():
        if not isinstance(tool, str):
            continue
        if isinstance(subs, list) and subs:
            known.update(f"{tool} {sub}" for sub in subs if isinstance(sub, str))
        else:
            known.add(tool)
    return known


def _drift_classes(registry: dict | None) -> set[str]:
    data = registry if registry is not None else load_registry()
    raw = data.get("drift_taxonomy")
    if not isinstance(raw, list):
        return set()
    return {str(item) for item in raw if isinstance(item, str)}


def _rule_ids(drift_class: str, registry: dict | None) -> list[str]:
    """The real PAL rule ids behind a drift class.

    A detector knows the symptom, not the law. Putting the drift class into
    `rule_ids` made every downstream consumer that resolves rule -> owner
    document come up empty, so the law surface is asked instead. If the class has
    no law entry the list is empty rather than a fabricated id; the law-coverage
    validator check is what keeps that from happening quietly.
    """
    from . import law as law_mod

    try:
        return list(law_mod.resolve_law(drift_class, registry=registry)["rule_ids"])
    except PalError:
        return []


def _candidate(
    *,
    detector: str,
    episode: dict,
    session_record: dict,
    rule_id: str,
    drift_class: str,
    expected: dict,
    observed: dict,
    event_refs: list[int],
    confidence: str,
    registry: dict | None,
) -> dict | None:
    classes = _drift_classes(registry)
    if classes and drift_class not in classes:
        return None
    return {
        "detector": detector,
        "session_id": session_record.get("session_id", ""),
        "episode_id": int(episode.get("index", -1)),
        "episode_index": int(episode.get("index", -1)),
        "rule_ids": _rule_ids(drift_class, registry),
        "expected": expected,
        "observed": observed,
        "event_refs": [int(seq) for seq in event_refs],
        "mechanical_confidence": confidence,
        "drift_class": drift_class,
    }


def detect_command_route(
    episode: dict,
    bundle: dict,
    session_record: dict,
    *,
    registry: dict | None = None,
) -> dict | None:
    known = _known_commands(registry)
    if not known:
        return None
    for event in _span(bundle, episode):
        if event.get("type") != "COMMAND":
            continue
        facts = event.get("facts") or {}
        canonical = facts.get("canonical")
        if not isinstance(canonical, str) or not canonical.strip():
            continue
        head = canonical.split()[0]
        two = canonical.split()
        two_token = " ".join(two[:2]) if len(two) >= 2 else head
        if two_token in known or head in known:
            continue
        return _candidate(
            detector="detect_command_route",
            episode=episode,
            session_record=session_record,
            rule_id="COMMAND_ROUTE_DRIFT",
            drift_class="COMMAND_ROUTE_DRIFT",
            expected={"known_commands": sorted(known)},
            observed={"canonical": canonical, "head": head, "two_token": two_token},
            event_refs=[int(event["seq"])],
            confidence="HIGH",
            registry=registry,
        )
    return None


def detect_phase_illegality(
    episode: dict,
    bundle: dict,
    session_record: dict,
    *,
    registry: dict | None = None,
) -> dict | None:
    for event in _span(bundle, episode):
        if event.get("type") != "PHASE_CHANGE":
            continue
        facts = event.get("facts") or {}
        from_phase = facts.get("from_phase")
        to_phase = facts.get("to_phase")
        if not (isinstance(from_phase, str) and isinstance(to_phase, str)):
            continue
        if (from_phase, to_phase) in _LEGAL_PHASE_EDGES or ("*", to_phase) in _LEGAL_PHASE_EDGES:
            continue
        return _candidate(
            detector="detect_phase_illegality",
            episode=episode,
            session_record=session_record,
            rule_id="PHASE_ILLEGALITY",
            drift_class="PHASE_ILLEGALITY",
            expected={"legal_transition": sorted(_LEGAL_PHASE_EDGES)},
            observed={"from_phase": from_phase, "to_phase": to_phase},
            event_refs=[int(event["seq"])],
            confidence="HIGH",
            registry=registry,
        )
    return None


def detect_active_work_preemption(
    episode: dict,
    bundle: dict,
    session_record: dict,
    *,
    registry: dict | None = None,
) -> dict | None:
    spans = _span(bundle, episode)
    if not spans:
        return None

    seen_work: Any = None
    work_seen = False
    work_switches: list[tuple[int, Any, Any]] = []

    for event in spans:
        if event.get("type") != "STATE_SNAPSHOT":
            continue
        work = _active_work(event)
        if work is None:
            continue
        if work_seen and work != seen_work:
            work_switches.append((int(event["seq"]), seen_work, work))
        seen_work = work
        work_seen = True

    if not work_switches:
        return None

    seq_set = {int(event["seq"]) for event in spans}
    for switch_seq, prev, new in work_switches:
        terminal_follows = any(
            int(event["seq"]) > switch_seq
            and (
                event.get("type") == "SESSION_BOUNDARY"
                or (event.get("type") == "PHASE_CHANGE" and (event.get("facts") or {}).get("to_phase") == "IDLE")
            )
            for event in _events(bundle)
        )
        if terminal_follows:
            continue
        if switch_seq + 1 in seq_set or any(
            int(event["seq"]) > switch_seq for event in spans
        ):
            return _candidate(
                detector="detect_active_work_preemption",
                episode=episode,
                session_record=session_record,
                rule_id="ACTIVE_WORK_PREEMPTION",
                drift_class="ACTIVE_WORK_PREEMPTION",
                expected={"work_change_requires_terminal": True},
                observed={"from": prev, "to": new, "switch_seq": switch_seq},
                event_refs=[switch_seq],
                confidence="MEDIUM",
                registry=registry,
            )
    return None


def detect_false_continue_idle(
    episode: dict,
    bundle: dict,
    session_record: dict,
    *,
    registry: dict | None = None,
) -> dict | None:
    spans = _span(bundle, episode)
    if not spans:
        return None

    active_state: Any = None
    for event in spans:
        if event.get("type") == "STATE_SNAPSHOT":
            work = _active_work(event)
            if work is not None:
                active_state = work

    if not active_state:
        return None

    for event in spans:
        if event.get("type") != "COMMAND":
            continue
        facts = event.get("facts") or {}
        canonical = facts.get("canonical")
        if not isinstance(canonical, str):
            continue
        if not canonical.split():
            continue
        tokens = [t.lower() for t in canonical.split()]
        if "continue" not in tokens:
            continue
        return _candidate(
            detector="detect_false_continue_idle",
            episode=episode,
            session_record=session_record,
            rule_id="CONTINUE_IDLE_FALSE_POSITIVE",
            drift_class="CONTINUE_IDLE_FALSE_POSITIVE",
            expected={"active_work_at_continue": None, "command": "continue implies idle"},
            observed={"command": canonical, "active_work": active_state},
            event_refs=[int(event["seq"])],
            confidence="HIGH",
            registry=registry,
        )
    return None


def detect_source_closure_false_green(
    episode: dict,
    bundle: dict,
    session_record: dict,
    *,
    registry: dict | None = None,
) -> dict | None:
    spans = _span(bundle, episode)
    if not spans:
        return None

    kinds = {episode.get("kind")}
    if kinds & _TERMINAL_KINDS:
        return None

    last_source: dict | None = None
    for event in spans:
        if event.get("type") == "SOURCE_EVENT":
            last_source = event

    if last_source is None:
        return None

    last_source_seq = int(last_source["seq"])
    has_closure = any(
        int(event["seq"]) > last_source_seq
        and event.get("type") in {"SESSION_BOUNDARY", "PHASE_CHANGE"}
        for event in _events(bundle)
    )
    if has_closure:
        return None

    facts = last_source.get("facts") or {}
    return _candidate(
        detector="detect_source_closure_false_green",
        episode=episode,
        session_record=session_record,
        rule_id="SOURCE_CLOSURE_FALSE_GREEN",
        drift_class="SOURCE_CLOSURE_FALSE_GREEN",
        expected={"source_receipt_requires_boundary": True},
        observed={"source_kind": facts.get("kind"), "source_seq": last_source_seq},
        event_refs=[last_source_seq],
        confidence="LOW",
        registry=registry,
    )


def detect_all(
    episode: dict,
    bundle: dict,
    session_record: dict,
    *,
    registry: dict | None = None,
) -> list[dict]:
    candidates: list[dict] = []
    for name in DETECTOR_REGISTRY:
        detector = globals().get(name)
        if detector is None:
            continue
        result = detector(episode, bundle, session_record, registry=registry)
        if result is not None:
            candidates.append(result)
    return candidates


def detect_for_episode(
    episode: dict,
    bundle: dict,
    session_record: dict,
    *,
    registry: dict | None = None,
) -> list[dict]:
    return detect_all(episode, bundle, session_record, registry=registry)
