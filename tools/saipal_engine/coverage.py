"""Semantic coverage: exhaustion you can check, not exhaustion you assert.

`semantic.exhausted` is a cursor claim. It is written by the code that advances
the watermark, so it can only ever say "the cursor ran off the end" -- which is
also what a bug that skipped ten episodes would say.

Coverage answers the real question by counting receipts: which episodes of this
session actually have a recorded verdict, which are still held provisional, and
which have nothing at all. That is auditable evidence of work, and it is what
`status` reports instead of a flag.
"""

from __future__ import annotations

from pathlib import Path

from . import carrier as carrier_mod
from . import submit as submit_mod


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


def session_coverage(record: dict, receipts: dict[int, list[dict]] | None) -> dict:
    """Per-episode semantic coverage for one session, derived from receipts.

    `final` counts episodes with a verdict recorded against final evidence.
    `provisional` counts episodes whose only verdicts were recorded while the
    evidence could still grow -- work done, but nothing concluded. `pending` is
    the honest remainder.
    """
    episodes = record.get("episodes") or []
    total = len(episodes)
    by_index = receipts or {}
    final = 0
    provisional = 0
    for episode in episodes:
        entries = by_index.get(int(episode.get("index", -1))) or []
        if any(str(e.get("finality", "FINAL")) == "FINAL" for e in entries):
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
        "cursor": state["next_episode_index"],
        "claimed_exhausted": state["exhausted"],
        "truly_exhausted": total > 0 and final == total,
        "receipts": sum(len(entries) for entries in by_index.values()),
    }


def coverage(home: Path | str, index: dict | None) -> dict:
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
        session_coverage(record, receipts.get(str(record.get("session_id") or "")))
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
        "receipts_total": sum(row["receipts"] for row in sessions),
        "sessions_truly_exhausted": sum(1 for row in sessions if row["truly_exhausted"]),
        "cursor_claims_more_than_receipts": discrepancies,
    }
