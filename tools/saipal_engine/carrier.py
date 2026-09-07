"""The analysis carrier: what Layer B receives (PAL-ANALYSIS-01).

Layer A hands the analyst one unit of work. The carrier is a bounded, read-only
projection: session identity, the target semantic episode, that episode's
normalized events, evidence locators it may reopen, the historical protocol
binding and rule surface, the mechanical signals, prior recurrence and prior
maintainer calibration.

It is not the transcript, and it is never analysis output. Building a carrier
performs zero writes -- the whole point is that `next` can be called freely.
"""

from __future__ import annotations

from pathlib import Path

from . import bundle as bundle_mod
from . import closedloop as closedloop_mod
from . import config as config_mod
from . import defence as defence_mod
from . import detectors as detectors_mod
from . import findings as findings_mod
from . import law as law_mod
from . import recurrence as recurrence_mod
from . import sessions as sessions_mod
from .errors import PalError
from .paths import home_paths, sha256_text
from .registry import load_registry, require_mapping, require_string_list

CARRIER_SCHEMA_KEY = "carrier_schema_version"


def unit_digest(record: dict, episode: dict, slice_index: int = 0) -> str:
    """A digest of the evidence identity this unit of work stands on.

    Deliberately NOT a digest of the whole carrier: recurrence, calibration and
    open candidates move as unrelated work proceeds, and a digest that changed
    with them would reject every honest submission. What must not change under
    the analyst is the evidence: this session generation, this bundle content,
    this episode span, and which slice of that span was handed over.
    """
    parts = (
        str(record.get("session_id") or ""),
        str(record.get("generation") or ""),
        str(record.get("bundle_sha256") or ""),
        str(episode.get("index") if episode is not None else ""),
        str(episode.get("start_seq") if episode is not None else ""),
        str(episode.get("end_seq") if episode is not None else ""),
        str(int(slice_index)),
    )
    return sha256_text("\x00".join(parts))


def _limits(registry: dict) -> dict[str, int]:
    return {key: int(value) for key, value in require_mapping(registry, "carrier_limits").items()}


def _kinds(registry: dict) -> dict[str, str]:
    """Carrier kinds by role, so no call site spells a carrier value itself."""
    (
        idle,
        resume_session,
        advance_candidate,
        resolve_conflict,
        analyze_episodes,
        discover_sources,
    ) = require_string_list(registry, "next_carriers")
    return {
        "idle": idle,
        "resume_session": resume_session,
        "advance_candidate": advance_candidate,
        "resolve_conflict": resolve_conflict,
        "analyze_episodes": analyze_episodes,
        "discover_sources": discover_sources,
    }


def episode_finality(record: dict, episode: dict) -> str:
    """`FINAL` or `PROVISIONAL` for one episode (PAL-SESSION-06).

    A COLD session is complete, so every episode is final. In a HOT session the
    trailing episode has no closing boundary yet: it can still grow, and new
    episodes can appear after it. Reasoning about it is legitimate — it is often
    the most interesting part of a live session — but it is reasoning about a
    sentence that is not finished, so it may never become an external audit.
    """
    if str(record.get("temperature") or "") != "HOT":
        return "FINAL"
    episodes = record.get("episodes") or []
    if not episodes:
        return "FINAL"
    last_index = max(int(item.get("index", 0)) for item in episodes)
    return "PROVISIONAL" if int(episode.get("index", -1)) >= last_index else "FINAL"


def tail_digest(record: dict, episode: dict, slice_index: int) -> str:
    """The identity of a provisional-tail review position (PAL-SESSION-06).

    The digest covers exactly the facts that make a re-review pointless: which
    session generation, which episode, which slice of it, which span. When any
    of them changes -- the episode grows, a new slice becomes pending, the
    session re-imports as a new generation -- the digest changes and the unit
    is offered again. A re-offer without a change would ask the analyst to
    re-read an unfinished sentence it already read to the end.
    """
    return unit_digest(record, episode, int(slice_index))


def semantic_state(record: dict) -> dict:
    """The session's SEMANTIC analysis position, distinct from the mechanical one.

    The deterministic pass consumes episodes to produce signals and records that
    in `analysis`. Semantic analysis is Layer B's, runs at its own pace, and has
    its own watermark: a mechanically exhausted session can still owe every one
    of its episodes to the analyst. Conflating the two made `next` idle the
    moment `continue` finished, which is why nothing was ever handed over.

    The position is an episode AND a slice inside it: a long episode is handed
    over in bounded windows, so the cursor has to name which window comes next.
    `tail_reviewed_digest` is the material-change watermark: when set, the
    growing HOT tail has been judged provisionally in its entirety at that
    position, and the carrier must not re-offer it without a delta.
    """
    raw = record.get("semantic")
    state = raw if isinstance(raw, dict) else {}
    try:
        index = int(state.get("next_episode_index") or 0)
    except (TypeError, ValueError):
        index = 0
    try:
        slice_index = int(state.get("next_slice_index") or 0)
    except (TypeError, ValueError):
        slice_index = 0
    tail = state.get("tail_reviewed_digest")
    return {
        "next_episode_index": max(0, index),
        "next_slice_index": max(0, slice_index),
        "exhausted": bool(state.get("exhausted")),
        "submitted": int(state.get("submitted") or 0),
        "no_drift": int(state.get("no_drift") or 0),
        "provisional": int(state.get("provisional") or 0),
        "tail_reviewed_digest": tail if isinstance(tail, str) and tail else None,
    }


def slice_count(events: object, limit: int) -> int:
    """How many bounded windows an episode of `events` events needs (min 1).

    `events` is the span size: the real one when a bundle is loaded, otherwise
    the `event_count` an episode recorded at intake. A record written before
    episodes carried that count reports one slice -- the pre-paging behaviour,
    which a re-import corrects.
    """
    try:
        total = int(events or 0)
    except (TypeError, ValueError):
        total = 0
    if total <= 0 or limit <= 0:
        return 1
    return (total + limit - 1) // limit


def _generation(record: dict) -> int:
    """A record's generation as an int, tolerating a legacy or absent value."""
    try:
        return int(record.get("generation") or 0)
    except (TypeError, ValueError):
        return 0


def freshest_records(index: dict | None) -> list[dict]:
    """One record per session id: the newest generation of each session.

    A changed COLD artifact is a new generation of the same session, so the index
    legitimately holds several records per id. Everything that measures
    *outstanding work* must look at the freshest one only: counting superseded
    generations made `pending` unreachable and counted a single receipt once per
    generation. Superseded records keep their own receipts as history.
    """
    best: dict[str, dict] = {}
    for record in (index or {}).get("sessions") or []:
        session_id = str(record.get("session_id") or "")
        current = best.get(session_id)
        if current is None or _generation(record) > _generation(current):
            best[session_id] = record
    return list(best.values())


def episode_slice_count(record: dict, episode: dict, limit: int) -> int:
    """How many bounded slices this episode is handed over in."""
    if episode is None:
        return 1
    recorded = episode.get("event_count")
    if recorded is None:
        # A record written before episodes carried their span size. Fall back to
        # the span width, which over-counts skipped sequence numbers but never
        # hides events behind a slice that is never offered.
        try:
            recorded = int(episode.get("end_seq", 0)) - int(episode.get("start_seq", 0)) + 1
        except (TypeError, ValueError):
            recorded = 0
    return slice_count(recorded, limit)


def next_unit(
    index: dict | None, registry: dict
) -> tuple[dict | None, dict | None, int]:
    """`(session_record, episode, slice_index)` for the next SEMANTIC unit.

    `(None, None, 0)` when nothing is pending. Freshest-first, matching the
    intake order, so a carrier follows the same priority the pipeline would. A
    session in CONFLICT is never handed over: its evidence mutated under an
    analyzed prefix and the operator owns that.

    Only the freshest generation of a session is offered. A candidate names a
    session plus an episode index, so offering a superseded generation would hand
    out a unit the submission boundary cannot address -- a loop that refuses every
    reply as stale.
    """
    limit = _limits(registry)["max_events"]
    ordered = sorted(
        freshest_records(index),
        key=lambda record: (
            record.get("updated_at") or record.get("imported_at") or "",
            _generation(record),
        ),
        reverse=True,
    )
    for record in ordered:
        if record.get("status") != "IMPORTED":
            continue
        episodes = list(record.get("episodes") or [])
        if not episodes:
            continue
        state = semantic_state(record)
        if state["exhausted"]:
            continue
        start = state["next_episode_index"]
        if start >= len(episodes):
            continue
        episode = episodes[start]
        # The cursor's slice is clamped, never trusted: a re-imported session can
        # legitimately have fewer slices than the position recorded against its
        # predecessor, and an unreachable slice would idle the analyst forever.
        slices = episode_slice_count(record, episode, limit)
        slice_at = min(state["next_slice_index"], slices - 1)
        # Material-change rule (PAL-SESSION-06): a HOT tail that was judged
        # provisionally in its entirety at exactly this position is not handed
        # out again. The verdict is already recorded; the evidence has not
        # moved; re-offering the same unfinished sentence is not work. When the
        # episode grows, a new slice becomes pending, or the session re-imports
        # as a new generation, the digest changes and the unit returns.
        if (
            episode_finality(record, episode) == "PROVISIONAL"
            and state["tail_reviewed_digest"]
            and state["tail_reviewed_digest"] == tail_digest(record, episode, slice_at)
        ):
            continue
        return record, episode, slice_at
    return None, None, 0


def _in_window(entry: dict, episode: dict, window: dict) -> bool:
    """Is this indexed locator inside the slice the analyst was handed?

    Locators for events it cannot see are not evidence it may reopen: they would
    invite a citation of something outside its own window.
    """
    try:
        seq = int(entry.get("seq", -1))
    except (TypeError, ValueError):
        return False
    start = window.get("start_seq")
    end = window.get("end_seq")
    if start is None or end is None:
        start = int(episode.get("start_seq", 0))
        end = int(episode.get("end_seq", 0))
    return int(start) <= seq <= int(end)


def _project(record: dict) -> dict:
    project = record.get("project")
    return dict(project) if isinstance(project, dict) else {}


def _runtime(record: dict) -> dict:
    runtime = record.get("runtime")
    return dict(runtime) if isinstance(runtime, dict) else {}


def _episode_events(
    bundle: dict, episode: dict, limit: int, slice_index: int = 0
) -> tuple[list[dict], bool, dict]:
    """One bounded slice of an episode's events, plus that slice's identity.

    A real episode can be hundreds of events long, so a single truncated window
    made an honest analyst answer INSUFFICIENT_EVIDENCE about almost every live
    unit: it could see the first `limit` events and nothing else, forever. The
    span is therefore handed over in consecutive windows, and the slice says
    which one this is and whether more remain.
    """
    start = int(episode.get("start_seq", 0))
    end = int(episode.get("end_seq", 0))
    span = [
        event
        for event in bundle_mod.events_of(bundle)
        if start <= int(event.get("seq", -1)) <= end
    ]
    total = slice_count(len(span), limit)
    index = max(0, min(int(slice_index), total - 1))
    offset = index * limit if limit > 0 else 0
    window = span[offset : offset + limit] if limit > 0 else list(span)
    return (
        window,
        offset + len(window) < len(span),
        {
            "index": index,
            "count": total,
            "offset": offset,
            "span_event_count": len(span),
            "start_seq": int(window[0]["seq"]) if window else None,
            "end_seq": int(window[-1]["seq"]) if window else None,
            "final_slice": index >= total - 1,
        },
    )


def _signals(episode: dict, bundle: dict, record: dict, registry: dict, limit: int) -> list[dict]:
    raw = detectors_mod.detect_for_episode(episode, bundle, record, registry=registry)
    return raw[:limit]


def _applicable_law(episode: dict, record: dict, registry: dict, limit: int) -> dict:
    protocol = record.get("protocol") if isinstance(record.get("protocol"), dict) else {}
    try:
        resolved = law_mod.resolve_for_episode(episode, protocol, registry=registry)
    except PalError as exc:
        return {
            "status": "UNRESOLVED",
            "reason": exc.message,
            "rule_ids": [],
            "owner_documents": [],
        }
    law = resolved.get("applicable_law") or {}
    return {
        "status": "RESOLVED",
        "drift_class": law.get("drift_class"),
        "rule_ids": list(law.get("rule_ids") or [])[:limit],
        "owner_documents": list(law.get("owner_documents") or [])[:limit],
        "expected_behavior": law.get("expected_behavior", ""),
        "violation_claimable": bool(resolved.get("violation_claimable")),
        "reason": resolved.get("reason", ""),
        "current_protocol_protection": resolved.get("current_protocol_protection", "UNKNOWN"),
    }


def _historical(home: Path, record: dict, rule_ids: list[str], registry: dict) -> dict | None:
    """The compact historical rule surface, when an authority is configured."""
    from .pipeline import HistoricalRuleReader

    status, config, detail = config_mod.load_config(home)
    if status == "unrecoverable":
        return {"status": "UNAVAILABLE", "attempts": [{"source": "UNKNOWN", "reason": detail}]}
    reader = HistoricalRuleReader(
        config_mod.protocol_authority(home, config), registry=registry
    )
    if not reader.configured:
        return None
    return reader.read(record.get("protocol"), rule_ids)


def _recurrence(home: Path, drift_class: str | None, limit: int) -> dict:
    data = recurrence_mod.load_recurrence(home)
    if not drift_class:
        return {"by_model": [], "by_project": [], "known_findings": 0, "spread": None}
    return {
        "by_model": recurrence_mod.cross_model_recurrence(data, drift_class)[:limit],
        "by_project": recurrence_mod.cross_project_recurrence(data, drift_class)[:limit],
        "known_findings": sum(
            1
            for entry in (data.get("by_finding") or {}).values()
            if entry.get("drift_class") == drift_class
        ),
        # The spread is the part the analyst must actually reason with: one model
        # drifting where another complied is not evidence about the protocol.
        "spread": recurrence_mod.spread(data, drift_class),
    }


def _calibration(home: Path, limit: int) -> list[dict]:
    """Prior maintainer verdicts: what this analyst's predecessors got wrong."""
    status, links, _detail = closedloop_mod.load_links(home)
    if status != "ok" or links is None:
        return []
    decided = [
        {
            "audit_number": entry.get("audit_number"),
            "finding_id": entry.get("finding_id"),
            "disposition": entry.get("disposition"),
            "fix_version": entry.get("fix_version"),
            "receipt_id": entry.get("receipt_id"),
            "closed_at": entry.get("closed_at"),
        }
        for entry in links.get("links") or []
        if entry.get("disposition")
    ]
    return decided[-limit:]


def _open_candidates(home: Path, registry: dict, limit: int) -> list[dict]:
    status, index, _detail = findings_mod.load_index(home, registry=registry)
    if status != "ok" or index is None:
        return []
    open_states = ("OBSERVED", "BOUND", "CHALLENGED", "QUALIFIED")
    rows = [
        {
            "finding_id": record.get("finding_id"),
            "state": record.get("state"),
            "drift_class": record.get("drift_class"),
            "severity": record.get("severity"),
            "confidence": record.get("confidence"),
            "occurrences": len(record.get("occurrences") or []),
        }
        for record in index.get("findings") or []
        if record.get("state") in open_states and record.get("audit") is None
    ]
    return rows[:limit]


def find_unit(
    index: dict | None, session_id: str, episode_index: int
) -> tuple[dict | None, dict | None]:
    """`(session_record, episode)` for one named unit, or `(None, None)`.

    Used when a submission names the unit it answers: the analyst is not asked to
    trust that `next` still points at the same place by the time it replies.

    One session id can hold several generations (a COLD artifact that changed is a
    new generation of the same session), so the record is selected the same way
    `next_unit` would select it -- freshest generation first. Taking the first
    index match instead made every submission against a re-imported session fail
    as stale: `next` offered generation N and this rebuilt generation 1, so the
    unit digests could never agree.
    """
    candidates = [
        record
        for record in (index or {}).get("sessions") or []
        if record.get("session_id") == session_id
    ]
    if not candidates:
        return None, None
    record = max(
        candidates,
        key=lambda item: (
            _generation(item),
            str(item.get("updated_at") or item.get("imported_at") or ""),
        ),
    )
    for episode in record.get("episodes") or []:
        if int(episode.get("index", -1)) == int(episode_index):
            return record, episode
    return record, None


def build_carrier(
    home: Path | str,
    *,
    registry: dict | None = None,
    index: dict | None = None,
    session_id: str | None = None,
    episode_index: int | None = None,
    slice_index: int | None = None,
) -> dict:
    """One bounded analysis carrier, or the idle carrier. Performs zero writes.

    With no target, the next pending semantic unit is chosen. With an explicit
    `session_id` + `episode_index` (and optionally `slice_index`), that exact unit
    is rebuilt -- which is how a submission is checked against the evidence it
    claims to have reasoned over.
    """
    data = registry if registry is not None else load_registry()
    limits = _limits(data)
    kinds = _kinds(data)
    root = Path(home)

    if index is None:
        status, index, detail = sessions_mod.load_index(root, registry=data)
        if status == sessions_mod.STATUS_UNRECOVERABLE:
            raise PalError(
                "VALIDATION_FAILED",
                f"session index is unusable: {detail}",
                next_action="repair .saipal/sessions/index.json by hand",
            )

    if session_id is not None and episode_index is not None:
        record, episode = find_unit(index, session_id, int(episode_index))
        target_slice = int(slice_index or 0)
    else:
        record, episode, target_slice = next_unit(index, data)
    if record is None or episode is None:
        return {
            "schema_version": int(data.get(CARRIER_SCHEMA_KEY, 1)),
            "carrier": kinds["idle"],
            "session": None,
            "episode": None,
            "next_action": "saipal continue",
            "note": "no analyzable episode is pending",
        }

    source_ref = str(record.get("source_ref") or "")
    bundle_path = home_paths(root).session_inbox / Path(source_ref).name
    try:
        bundle = bundle_mod.load_bundle_file(bundle_path, registry=data)
    except (OSError, PalError):
        # The index knows the session but its canonical bundle is not readable
        # here. That is a real operator condition, not an exception path: the
        # carrier reports the pointer and lets `continue` reconcile it.
        return {
            "schema_version": int(data.get(CARRIER_SCHEMA_KEY, 1)),
            "carrier": kinds["analyze_episodes"],
            "unit_digest": unit_digest(record, episode, target_slice),
            "session": {"session_id": record.get("session_id"), "source_ref": source_ref},
            "episode": {"index": episode.get("index")},
            "next_action": "saipal continue",
            "note": "the indexed session bundle is absent or unreadable in this home",
        }

    events, truncated, window = _episode_events(
        bundle, episode, limits["max_events"], target_slice
    )
    signals = _signals(episode, bundle, record, data, limits["max_signals"])
    law = _applicable_law(episode, record, data, limits["max_rules"])
    rule_ids = list(law.get("rule_ids") or [])
    for signal in signals:
        for rule in signal.get("rule_ids") or []:
            if rule not in rule_ids:
                rule_ids.append(str(rule))
    protocol = record.get("protocol") if isinstance(record.get("protocol"), dict) else {}
    applicability = sessions_mod.historical_applicability(
        protocol, binding_status=protocol.get("binding_status"),
    )

    evidence_refs = [
        entry
        for entry in (record.get("evidence_refs") or [])
        if _in_window(entry, episode, window)
    ][: limits["max_evidence_refs"]]

    return {
        "schema_version": int(data.get(CARRIER_SCHEMA_KEY, 1)),
        "carrier": kinds["analyze_episodes"],
        "unit_digest": unit_digest(record, episode, window["index"]),
        "session": {
            "session_id": record.get("session_id"),
            "generation": record.get("generation"),
            "adapter": record.get("adapter"),
            "temperature": record.get("temperature"),
            "status": record.get("status"),
            "event_count": record.get("event_count"),
            "last_analyzed_seq": record.get("last_analyzed_seq"),
            "source_ref": source_ref,
            "project": _project(record),
            "runtime": _runtime(record),
        },
        "episode": {
            "index": episode.get("index"),
            "kind": episode.get("kind"),
            "start_seq": episode.get("start_seq"),
            "end_seq": episode.get("end_seq"),
            "trigger_seq": episode.get("trigger_seq"),
            "event_count": len(events),
            "events_truncated": truncated,
            "finality": episode_finality(record, episode),
        },
        "slice": window,
        "events": events,
        "evidence_refs": evidence_refs,
        "evidence_command": (
            f"saipal --json evidence {record.get('session_id')} <event_seq>"
        ),
        "protocol": {
            "binding_status": protocol.get("binding_status", "UNKNOWN"),
            "proof_level": protocol.get("proof_level", "UNKNOWN"),
            "version": protocol.get("version"),
            "git_head": protocol.get("git_head"),
            "registry_sha256": protocol.get("registry_sha256"),
            "tree_fingerprint": protocol.get("tree_fingerprint"),
            "violation_claimable": bool(applicability["violation_claimable"]),
            "reason": applicability["reason"],
        },
        "applicable_law": law,
        "historical_rule_surface": _historical(root, record, rule_ids, data),
        "signals": signals,
        "defence_surface": defence_mod.defence_surface(
            bundle, episode, record, registry=data
        ),
        "recurrence": _recurrence(root, law.get("drift_class"), limits["max_recurrence_rows"]),
        "calibration": _calibration(root, limits["max_calibration_rows"]),
        "open_candidates": _open_candidates(root, data, limits["max_open_candidates"]),
        "next_action": "saipal continue",
    }


def carrier_problems(carrier: object, *, registry: dict | None = None) -> list[str]:
    """Every reason a carrier is not the declared shape, or an empty list."""
    data = registry if registry is not None else load_registry()
    fields = set(require_string_list(data, "carrier_fields"))
    kinds = set(require_string_list(data, "next_carriers"))
    expected_schema = int(data.get(CARRIER_SCHEMA_KEY, 1))

    if not isinstance(carrier, dict):
        return ["carrier root is not an object"]
    problems: list[str] = []
    if carrier.get("schema_version") != expected_schema:
        problems.append(
            f"schema_version {carrier.get('schema_version')!r} != {expected_schema}"
        )
    if carrier.get("carrier") not in kinds:
        problems.append(f"carrier {carrier.get('carrier')!r} outside {sorted(kinds)}")
    for name in sorted(set(carrier) - fields):
        problems.append(f"unknown carrier field {name!r}")
    if carrier.get("carrier") != _kinds(data)["idle"] and "session" not in carrier:
        problems.append("a non-idle carrier must name a session")
    forbidden = set(require_string_list(data, "forbidden_event_keys"))
    for position, event in enumerate(carrier.get("events") or []):
        if not isinstance(event, dict):
            problems.append(f"events[{position}] is not an object")
            continue
        for key in sorted(forbidden & set(event)):
            problems.append(f"events[{position}] carries forbidden raw key {key!r}")
    return problems
