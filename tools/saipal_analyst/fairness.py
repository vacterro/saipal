"""Durable fair-share scheduling state v2: `.saipal/analyst/fairness.json`.

T-107: v1 ranked work by LIFETIME served count, so a veteran session (served
100) starved forever behind an endless stream of zero-served newcomers, and a
re-entering veteran inherited a 100-turn debt from last month's work. Fairness
debt is CURRENT-WORK age, not lifetime history (ROLE 16/19): every currently
eligible session holds one queue ticket minted monotonically when it became
eligible; the OLDEST waiting ticket is served first; after one unit is served
the claim is retired and the session's next pending unit receives a fresh TAIL
ticket. The lifetime `served` count survives as telemetry only and never
participates in ranking.

Consequences, by construction: endless newcomers cannot starve a waiting
veteran (each arrival mints a ticket BEHIND the veteran's); a giant session
cannot monopolize (each service re-queues its next unit at the tail); a
re-entering veteran gets a fresh position (exhaustion retired its claim);
restart preserves ticket order and the counter (ROLE 26). Mechanical hint
severity never enters this module: ordering is signal-neutral by design
(ROLE 15/25), and signals can never decide a semantic verdict.
"""

from __future__ import annotations

from pathlib import Path

from saipal_engine.errors import PalError
from saipal_engine.paths import atomic_write_json, home_paths, read_json

FAIRNESS_SCHEMA_VERSION = 2
FAIRNESS_NAME = "fairness.json"

FAIRNESS_FIELDS = (
    "schema_version",
    "updated_at",
    "sessions",
    "service_sequence",
    "next_ticket",
)
SESSION_FIELDS = ("session_id", "served", "ticket", "current_unit_digest")

MAX_SERVICE_SEQUENCE = 64


def fairness_path(home: Path | str) -> Path:
    from . import jobs as jobs_mod

    return jobs_mod.journal_dir(home) / FAIRNESS_NAME


def fresh_state() -> dict:
    return {
        "schema_version": FAIRNESS_SCHEMA_VERSION,
        "updated_at": "",
        "sessions": {},
        "service_sequence": [],
        "next_ticket": 1,
    }


def _migrate_v1(payload: dict) -> dict:
    """v1 -> v2 (ROLE 17): preserve served as telemetry, drop it as debt.

    Explicit, deterministic, idempotent: v1 `served` counts keep their value
    but no session carries a v2 queue ticket until it is next seen eligible,
    so nobody inherits a historical debt for CURRENT work.
    """
    migrated = fresh_state()
    migrated["service_sequence"] = [
        item for item in (payload.get("service_sequence") or [])
    ][-MAX_SERVICE_SEQUENCE:]
    for session_id, record in (payload.get("sessions") or {}).items():
        if not isinstance(record, dict):
            continue
        migrated["sessions"][session_id] = {
            "session_id": session_id,
            "served": int(record.get("served") or 0),
            "ticket": 0,
            "current_unit_digest": "",
        }
    return migrated


def load_state(home: Path | str) -> dict:
    path = fairness_path(home)
    if not path.exists():
        return fresh_state()
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise PalError(
            "VALIDATION_FAILED",
            f"fairness state is unreadable: {exc}",
            next_action="repair or remove .saipal/analyst/fairness.json by hand",
        ) from None
    if payload.get("schema_version") == 1:
        payload = _migrate_v1(payload)
    problems = state_problems(payload)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "fairness state is invalid: " + "; ".join(problems[:5]),
        )
    return payload


def save_state(home: Path | str, state: dict) -> Path:
    problems = state_problems(state)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "refusing invalid fairness state: " + "; ".join(problems[:5]),
        )
    from time import gmtime, strftime

    state["updated_at"] = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
    # TARGET B2 (T-125): the analyst workspace directory is materialized
    # explicitly by its owning writer (see jobs.ensure_journal_dir).
    from . import jobs as _jobs

    _jobs.ensure_journal_dir(home)
    return atomic_write_json(fairness_path(home), state, root=home_paths(home).root)


def state_problems(payload: object) -> list[str]:
    if not isinstance(payload, dict):
        return ["fairness state root is not an object"]
    if payload.get("schema_version") != FAIRNESS_SCHEMA_VERSION:
        return [f"schema_version must be {FAIRNESS_SCHEMA_VERSION}"]
    for key in sorted(set(payload) - set(FAIRNESS_FIELDS)):
        return [f"unknown fairness field {key!r}"]
    sessions = payload.get("sessions")
    if not isinstance(sessions, dict):
        return ["sessions must be an object"]
    next_ticket = payload.get("next_ticket")
    if not isinstance(next_ticket, int) or isinstance(next_ticket, bool):
        return ["next_ticket must be an integer"]
    for session_id, record in sessions.items():
        if not isinstance(record, dict):
            return [f"fairness session {session_id!r} is not an object"]
        for key in sorted(set(record) - set(SESSION_FIELDS)):
            return [f"fairness session {session_id!r} has unknown field {key!r}"]
        for field in ("served", "ticket"):
            if not isinstance(record.get(field), int) or isinstance(
                record.get(field), bool
            ):
                return [f"fairness session {session_id!r} {field} must be an integer"]
    sequence = payload.get("service_sequence")
    if not isinstance(sequence, list):
        return ["service_sequence must be a list"]
    return []


def served_counts(home: Path | str) -> dict[str, int]:
    """Lifetime telemetry only (ROLE 24): never a ranking input."""
    state = load_state(home)
    return {
        session_id: int(record.get("served") or 0)
        for session_id, record in (state.get("sessions") or {}).items()
    }


def fairness_rank(session_id: str, served: dict[str, int]) -> tuple:
    """v1-compat rank, kept only for import/test compatibility.

    Lifetime served as the first key is exactly the T-107 starvation defect;
    the allocator orders by `queue_rank`. This shim is never handed to the
    allocator.
    """
    return (served.get(session_id, 0), session_id)


def queue_rank(session_id: str, state: dict) -> tuple:
    """The v2 ordering key: (queue ticket, session_id).

    Missing/zero ticket means "not synced" and sorts LAST, never as oldest
    (ROLE fix: missing ticket must not mean priority zero). Runnable work must
    own a real positive ticket before ranking; the large sentinel is a safety
    net if synchronization was missed.
    """
    record = (state.get("sessions") or {}).get(session_id) or {}
    ticket = int(record.get("ticket") or 0)
    if ticket <= 0:
        return (10**12, session_id)
    return (ticket, session_id)


def sync_eligibility(
    home: Path | str, eligible: dict[str, str]
) -> tuple[dict, bool]:
    """Reconcile queue claims against the CURRENTLY eligible set (ROLE 18).

    `eligible` maps session_id -> current unit digest for every session the
    worker's scan proved eligible right now. For each eligible session a claim
    is ensured: a session with NO active claim (new arrival, post-service
    next unit, post-exhaustion re-entry) mints a fresh TAIL ticket --
    monotonically increasing, so arrival order is preserved and newcomers
    queue behind older waiting work. A session already holding a claim for
    the SAME digest keeps its ticket: it is already waiting at its position
    and must not lose it across repeated identical scans. Sessions no longer
    eligible (exhausted, blocked) keep their lifetime served count but lose
    the claim (ROLE 18/24): the claim stops participating, and re-entry gets
    a fresh position.

    Persisted ONLY on material change; an unchanged eligible set performs
    zero writes.
    """
    state = load_state(home)
    sessions = state.setdefault("sessions", {})
    next_ticket = int(state.get("next_ticket") or 1)
    changed = False
    for session_id, digest in eligible.items():
        record = sessions.get(session_id)
        if record is None:
            sessions[session_id] = {
                "session_id": session_id,
                "served": 0,
                "ticket": next_ticket,
                "current_unit_digest": digest,
            }
            next_ticket += 1
            changed = True
            continue
        if str(record.get("current_unit_digest") or "") != digest:
            # The previous claim was consumed (service) or the session is
            # re-entering with new evidence: a fresh TAIL ticket, never the
            # front, and never an inherited historical position.
            record["ticket"] = next_ticket
            record["current_unit_digest"] = digest
            next_ticket += 1
            changed = True
    for session_id in list(sessions):
        if session_id not in eligible:
            record = sessions[session_id]
            if record.get("ticket") or record.get("current_unit_digest"):
                record["ticket"] = 0
                record["current_unit_digest"] = ""
                changed = True
    state["next_ticket"] = next_ticket
    if changed:
        save_state(home, state)
    return state, changed


def record_service(home: Path | str, session_id: str) -> dict:
    """One unit served: lifetime telemetry +1, claim retired.

    The session's NEXT pending unit (a new digest) is re-ticketed at the TAIL
    by the next `sync_eligibility`, so a multi-episode giant re-queues behind
    every other waiting session instead of monopolizing the run (ROLE 22).
    """
    state = load_state(home)
    sessions = state.setdefault("sessions", {})
    record = sessions.setdefault(
        session_id,
        {"session_id": session_id, "served": 0, "ticket": 0, "current_unit_digest": ""},
    )
    record["served"] = int(record["served"]) + 1
    record["ticket"] = 0
    record["current_unit_digest"] = ""
    sequence = state.setdefault("service_sequence", [])
    sequence.append(session_id)
    del sequence[:-MAX_SERVICE_SEQUENCE]
    save_state(home, state)
    return state
