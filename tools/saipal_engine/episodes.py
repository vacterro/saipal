"""Episode boundary hooks (PAL-SESSION-05).

Segmentation is preparation only. This module marks where an episode starts; it
does not look inside one, compare it to anything, or emit anything about it.
The mapping from event type to boundary kind is mechanical and declared here,
never guessed per session.
"""

from __future__ import annotations

from typing import Any

from .registry import load_registry, require_string_list

#: Event types that always open a new episode.
TYPE_TO_KIND = {
    "USER_MESSAGE": "user_task",
    "COMMAND": "command",
    "PHASE_CHANGE": "phase_change",
    "SOURCE_EVENT": "source_intake",
}

#: `STATE_SNAPSHOT` fields that carry the active Work identity.
ACTIVE_WORK_KEYS = ("active_work", "active_ticket", "work")

TERMINAL_KIND = "terminal_task"


def _active_work(event: dict) -> Any:
    facts = event.get("facts") or {}
    for key in ACTIVE_WORK_KEYS:
        if key in facts:
            return facts[key]
    return None


def boundary_marks(events: list[dict], *, registry: dict | None = None) -> list[dict]:
    """Where episodes begin: `(seq, kind)` for each boundary event."""
    data = registry if registry is not None else load_registry()
    kinds = set(require_string_list(data, "episode_boundary_kinds"))

    marks: list[dict] = []
    previous_work: Any = None
    work_seen = False

    for event in events:
        kind = TYPE_TO_KIND.get(event.get("type"))

        if event.get("type") == "STATE_SNAPSHOT":
            work = _active_work(event)
            if work is not None and work_seen and work != previous_work:
                kind = "work_switch"
            if work is not None:
                previous_work = work
                work_seen = True

        if event.get("type") == "ERROR":
            facts = event.get("facts") or {}
            if facts.get("recovery") or facts.get("kind") == "recovery":
                kind = "recovery"

        if kind and kind in kinds:
            marks.append({"seq": int(event["seq"]), "kind": kind})

    return marks


def mechanical_spans(events: list[dict]) -> list[dict]:
    """Preserve provider step bookkeeping without treating it as meaning."""
    if not events:
        return []
    spans: list[dict] = []
    start = int(events[0]["seq"])
    for event in events:
        if event.get("type") != "SESSION_BOUNDARY":
            continue
        end = int(event["seq"])
        spans.append(
            {
                "index": len(spans),
                "start_seq": start,
                "end_seq": end,
                "marker": dict(event.get("facts") or {}),
            }
        )
        start = end + 1
    last = int(events[-1]["seq"])
    if start <= last:
        spans.append(
            {"index": len(spans), "start_seq": start, "end_seq": last, "marker": None}
        )
    return spans


def extract_episodes(events: list[dict], *, registry: dict | None = None) -> list[dict]:
    """Split a normalized event stream into episode spans.

    An episode covers `[start_seq, end_seq]` and is named by the boundary that
    opened it. The trailing span is `terminal_task`, because the end of the
    evidence is itself a boundary.
    """
    if not events:
        return []

    sequences = [int(event["seq"]) for event in events]
    first, last = sequences[0], sequences[-1]

    episodes: list[dict] = []
    by_seq = {int(event["seq"]): event for event in events}

    def locator_at(seq: int) -> dict | None:
        ref = by_seq.get(seq, {}).get("evidence_ref")
        return dict(ref) if isinstance(ref, dict) else None

    def episode(start_seq: int, end_seq: int, kind: str, trigger_seq: int | None) -> dict:
        return {
            "index": len(episodes),
            "start_seq": start_seq,
            "end_seq": end_seq,
            "kind": kind,
            "trigger_seq": trigger_seq,
            "start_evidence_ref": locator_at(start_seq),
            "end_evidence_ref": locator_at(end_seq),
        }
    start = first
    for mark in boundary_marks(events, registry=registry):
        if mark["seq"] <= start:
            continue
        episodes.append(episode(start, mark["seq"] - 1, mark["kind"], mark["seq"]))
        start = mark["seq"]

    if start < last:
        episodes.append(episode(start, last, TERMINAL_KIND, None))
    elif not episodes:
        episodes.append(episode(first, last, TERMINAL_KIND, None))

    return episodes
