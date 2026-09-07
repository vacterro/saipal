"""Semantic coverage: exhaustion you can check, not exhaustion you assert.

`semantic.exhausted` is a cursor claim. It is written by the code that advances
the watermark, so it can only ever say "the cursor ran off the end" -- which is
also what a bug that skipped ten episodes would say.

Coverage answers the real question by counting receipts: which episodes of this
session actually have a recorded verdict, which are still held provisional, and
which have nothing at all. That is auditable evidence of work, and it is what
`status` reports instead of a flag.

An episode longer than one carrier window is judged in slices, so the unit of
accounting is the slice: an episode counts as judged only when EVERY one of its
slices has a final verdict. Counting an episode judged on its first slice is how
a paged episode would silently report a prefix as the whole thing.
"""

from __future__ import annotations

from pathlib import Path

from . import carrier as carrier_mod
from . import submit as submit_mod
from .registry import load_registry, require_mapping


def _slice_limit(registry: dict | None) -> int:
    data = registry if registry is not None else load_registry()
    return int(require_mapping(data, "carrier_limits")["max_events"])


def _receipts_by_session(home: Path) -> dict[str, dict[int, list[dict]]]:
    status, payload, _detail = submit_mod.load_receipts(home)
    out: dict[str, dict[int, list[dict]]] = {}
    if status != "ok" or payload is None:
        return out
    for entry in payload.get("receipts") or []:
        if not isinstance(entry, dict):
            continue
        session = str(entry.get("session_id") or "")
        try:
            index = int(entry.get("episode_index"))
        except (TypeError, ValueError):
            continue
        out.setdefault(session, {}).setdefault(index, []).append(entry)
    return out


def _slice_of(entry: dict) -> int:
    """Which slice a receipt answered. A receipt written before paging is slice 0."""
    try:
        return max(0, int(entry.get("slice_index") or 0))
    except (TypeError, ValueError):
        return 0


def session_coverage(
    record: dict,
    receipts: dict[int, list[dict]] | None,
    *,
    registry: dict | None = None,
) -> dict:
    """Per-episode semantic coverage for one session, derived from receipts.

    `final` counts episodes whose every slice carries a verdict recorded against
    final evidence. `provisional` counts episodes with some work recorded but no
    conclusion -- a HOT tail, or an episode judged only up to slice N of M.
    `pending` is the honest remainder.
    """
    limit = _slice_limit(registry)
    episodes = record.get("episodes") or []
    total = len(episodes)
    by_index = receipts or {}
    final = 0
    provisional = 0
    slices_total = 0
    slices_final = 0
    slices_provisional = 0
    for episode in episodes:
        entries = by_index.get(int(episode.get("index", -1))) or []
        expected = carrier_mod.episode_slice_count(record, episode, limit)
        slices_total += expected
        judged = {
            _slice_of(entry)
            for entry in entries
            if str(entry.get("finality", "FINAL")) == "FINAL"
        }
        started = {_slice_of(entry) for entry in entries} - judged
        covered = {index for index in judged if index < expected}
        slices_final += len(covered)
        slices_provisional += len({index for index in started if index < expected})
        if expected and len(covered) == expected:
            final += 1
        elif entries:
            provisional += 1
    state = carrier_mod.semantic_state(record)
    return {
        "session_id": record.get("session_id"),
        "temperature": record.get("temperature"),
        "status": record.get("status"),
        "episodes": total,
        "final": final,
        "provisional": provisional,
        "pending": max(0, total - final - provisional),
        # Episodes that do not yet carry a FINAL verdict for every slice. On a
        # HOT session the tail is expected here; on a COLD session this is the
        # final-review backlog: a provisional receipt is work, never a
        # conclusion, so finalization turns it into owed review (PAL-SESSION-06).
        "needs_final_review": max(0, total - final),
        "slices": slices_total,
        "slices_final": slices_final,
        "slices_provisional": slices_provisional,
        "slices_pending": max(0, slices_total - slices_final - slices_provisional),
        "cursor": state["next_episode_index"],
        "cursor_slice": state["next_slice_index"],
        "claimed_exhausted": state["exhausted"],
        "truly_exhausted": total > 0 and final == total,
        "receipts": sum(len(entries) for entries in by_index.values()),
    }


def coverage(home: Path | str, index: dict | None, *, registry: dict | None = None) -> dict:
    """Semantic coverage across every indexed session.

    Counted over the freshest generation of each session, because that is the only
    generation analysis is offered for: including superseded ones made `pending`
    unreachable and counted one receipt once per generation.

    `cursor_claims_more_than_receipts` is the discrepancy worth surfacing: the
    watermark says a session is finished while the receipts say episodes were
    never judged. That is a bug signature, not a normal state, so it is named
    rather than averaged away.
    """
    root = Path(home)
    receipts = _receipts_by_session(root)
    sessions = [
        session_coverage(
            record,
            receipts.get(str(record.get("session_id") or "")),
            registry=registry,
        )
        for record in carrier_mod.freshest_records(index)
    ]
    discrepancies = [
        row["session_id"]
        for row in sessions
        if row["claimed_exhausted"] and not row["truly_exhausted"]
    ]
    return {
        "sessions": sessions,
        "episodes_total": sum(row["episodes"] for row in sessions),
        "episodes_final": sum(row["final"] for row in sessions),
        "episodes_provisional": sum(row["provisional"] for row in sessions),
        "episodes_pending": sum(row["pending"] for row in sessions),
        "slices_total": sum(row["slices"] for row in sessions),
        "slices_final": sum(row["slices_final"] for row in sessions),
        "slices_provisional": sum(row["slices_provisional"] for row in sessions),
        "slices_pending": sum(row["slices_pending"] for row in sessions),
        "receipts_total": sum(row["receipts"] for row in sessions),
        "sessions_truly_exhausted": sum(1 for row in sessions if row["truly_exhausted"]),
        "cursor_claims_more_than_receipts": discrepancies,
    }
