"""Autonomous detective loop: allocate, deliberate, submit, repeat within budget.

The durable job journal is the loop's spine, not an accessory: before every
model call the job records exactly which role is about to be called, after
every successful paid response the raw artifact is persisted BEFORE parsing
or the next expensive step, and the submit boundary is written down before it
is crossed. A crash at any write leaves a state whose single deterministic
next action resumes the exact deliberation stage normal execution would have
entered -- recovery never weakens the critic/finalizer gates and never
repeats paid semantic work.

Model-call accounting has ONE authoritative boundary: exactly one transport
attempt is exactly one model call, counted inside `_guarded_call` whether the
attempt succeeds or fails. Provider failure is a structured BackendFailure (a
worker-visible transport outcome), never a malformed-output failure, and the
worker -- not the transport -- owns the bounded deterministic retry policy.
Repair attempts are tracked per role in durable counters that survive
restart, so a crash can never grant a fresh repair budget.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from saipal_engine import carrier as carrier_mod
from saipal_engine import submit as submit_mod
from saipal_engine.errors import PalError
from saipal_engine.registry import load_registry
from saipal_engine.sessions import STATUS_UNRECOVERABLE, load_index

from . import backend as backend_mod
from . import jobs as jobs_mod
from . import openai_compatible as transport_mod
from . import output as output_mod
from . import packet as packet_mod
from . import prompts as prompts_mod
from .backend import BackendFailure
from .config import egress_verdict, load_analyst_config

ANALYST_RUNTIME_VERSION = 1
ANALYST_DIRNAME = "analyst"

ANALYST_PROVENANCE_PREFIX = "analyst_inv_"

#: Bounded deterministic transport backoff, owned by the worker:
#: attempt 1 -> 1s, attempt 2 -> 2s, attempt 3 -> 4s ... capped.
BACKOFF_BASE_SECONDS = 1.0
BACKOFF_FACTOR = 2.0
BACKOFF_CAP_SECONDS = 30.0

#: A new remote call may start only when at least this much wall budget
#: remains; the effective per-call timeout is bounded by the same remainder.
MIN_CALL_WINDOW_SECONDS = 5.0

#: The one bounded validation-repair attempt per role (deliberation contract).
#: The allowance is durable per job: a restart cannot grant another one.
DEFAULT_MAX_REPAIRS = 1

_TERMINAL = jobs_mod.TERMINAL_STAGES


class WorkerClock:
    """The worker's single time authority: monotonic, wall, sleep.

    Production wires the real clocks. Tests inject all three so retry
    determinism never depends on real multi-second sleeps or wall-clock
    races. Core retry decisions never call time.time() directly.
    """

    __slots__ = ("_monotonic", "_wall", "_sleep")

    def __init__(
        self,
        *,
        monotonic: Callable[[], float] | None = None,
        wall: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._monotonic = monotonic if monotonic is not None else time.monotonic
        self._wall = wall if wall is not None else time.time
        self._sleep = sleep if sleep is not None else time.sleep

    def monotonic_now(self) -> float:
        return self._monotonic()

    def wall_now(self) -> float:
        return self._wall()

    def sleep(self, seconds: float) -> None:
        self._sleep(seconds)


def _run_id() -> str:
    return hashlib.sha256(os.urandom(16)).hexdigest()[:24]


class _BudgetStop(Exception):
    """Raised before a disallowed call; the job stage is already durable."""

    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True)
class _Validation:
    """Closed outcome of parsing/validating one role's raw response.

    Exactly one of: a validated value, a structured backend failure, or an
    output-invalid detail. A transport outcome is never smuggled through a
    string and never becomes an output contract failure.
    """

    value: object = None
    failure: BackendFailure | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.value is not None and self.failure is None and not self.detail

    @property
    def backend_failed(self) -> bool:
        return self.failure is not None


def investigate(  # noqa: C901
    home: Path | str,
    *,
    max_units: int | None = None,
    drain: bool = False,
    provisional: bool = False,
    time_source: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
    clock: WorkerClock | None = None,
    restrict_job_ids: set[str] | None = None,
    publication_ceiling: str | None = None,
    max_model_calls_override: int | None = None,
) -> dict:
    """Run the autonomous semantic loop, bounded. Returns a summary receipt.

    T-111: `publication_ceiling` is orchestration authority from the CALLER
    (a shadow supervisor passes "STAGE_ONLY"); it is threaded to the audit
    external-effect boundary and can never be set or weakened by analyst or
    transcript content.
    """
    summary: dict = {
        "analyst_investigate": True,
        "analyst_version": ANALYST_RUNTIME_VERSION,
        "ok": True,
        "stop_reason": "IDLE",
        "runs_started": 1,
        "runs_completed": 0,
        "run_duration_seconds": 0.0,
        "units": 0,
        "jobs_completed": 0,
        "jobs_blocked": 0,
        "jobs_blocked_binding": 0,
        "jobs_stale": 0,
        "receipts": [],
        "errors": [],
        "model_calls": 0,
        "investigator_calls": 0,
        "critic_calls": 0,
        "finalizer_calls": 0,
        "repair_calls": 0,
        "rate_limited": 0,
        "timeouts": 0,
        "backend_successes": 0,
        "backend_retryable_failures": 0,
        "backend_auth_failures": 0,
        "backend_permanent_failures": 0,
        "backend_limits": 0,
        "submit_attempts": 0,
        "submit_successes": 0,
        "stale_refusals": 0,
        "kernel_refusals": 0,
        "usage_available": False,
    }
    worker_clock = clock if clock is not None else WorkerClock(
        monotonic=time_source, sleep=sleep
    )
    started = worker_clock.monotonic_now()
    root = Path(home)

    status, analyst_config, detail = load_analyst_config(root)
    if status == "absent":
        return _stop(summary, "CONFIG_DISABLED", "analyst is not configured; `saipal analyst-setup` first")
    if status == "unrecoverable":
        return _stop(summary, "ERROR", detail)
    if not analyst_config.get("enabled"):
        return _stop(summary, "CONFIG_DISABLED", "analyst is off; `saipal analyst-setup --enable` to permit it")
    if not (analyst_config.get("backend") or {}).get("model"):
        return _stop(summary, "CONFIG_DISABLED", "backend.model is not configured")

    budgets_cfg = analyst_config.get("budgets") or {}
    budget_units = int(max_units if max_units is not None else budgets_cfg.get("max_units_per_run") or 25)
    configured_max_calls = int(budgets_cfg.get("max_model_calls_per_run") or 50)
    max_calls = min(configured_max_calls, int(max_model_calls_override)) if max_model_calls_override is not None else configured_max_calls
    max_wall = float(budgets_cfg.get("max_wall_seconds") or 1800)
    max_retries = int(budgets_cfg.get("max_retries_per_unit") or 2)
    max_response_bytes = int(
        (analyst_config.get("backend") or {}).get("max_response_bytes") or 131072
    )

    drain_limit = int(budgets_cfg.get("max_units_per_run") or 25) * 4
    limit = drain_limit if drain else budget_units

    worker = jobs_mod.AnalystWorkerLock(root)
    if not worker.acquire():
        return _stop(summary, "BUSY", worker.detail)

    ledger = backend_mod.UsageLedger()
    try:
        # Recover any provenance link whose write crashed after the kernel
        # committed: journal facts rebuild it, no model call, no duplicate
        # receipt. A receipt without its link is a loud telemetry discrepancy.
        try:
            from . import provenance as provenance_mod

            reconciliation = provenance_mod.reconcile_provenance(root)
            if reconciliation.get("reconciled"):
                summary["provenance_reconciled"] = reconciliation["reconciled"]
        except PalError as exc:
            summary["errors"].append(
                {"code": "PROVENANCE_RECONCILE_FAILED", "detail": str(exc.message or exc)}
            )
        result = _loop(
            summary,
            root,
            analyst_config,
            ledger,
            worker_clock,
            started,
            limit=limit,
            max_calls=max_calls,
            max_wall=max_wall,
            max_retries=max_retries,
            max_response_bytes=max_response_bytes,
            provisional=provisional,
            restrict_job_ids=restrict_job_ids,
            publication_ceiling=publication_ceiling,
        )
        result["runs_completed"] = 1
        result["run_duration_seconds"] = round(worker_clock.monotonic_now() - started, 3)
        usage = {
            "input_tokens": ledger.input_tokens,
            "output_tokens": ledger.output_tokens,
            "total_tokens": ledger.total_tokens,
            "usage_available": ledger.reported > 0,
        }
        result.update(usage)
        try:
            journal_at_stop = jobs_mod.load_journal(root)
            by_stage: dict[str, int] = {}
            for job in (journal_at_stop.get("jobs") or {}).values():
                by_stage[str(job.get("stage"))] = (
                    by_stage.get(str(job.get("stage")), 0) + 1
                )
            result["jobs"] = by_stage
        except PalError as exc:
            result["jobs"] = {"error": exc.code}
        return result
    finally:
        worker.release()


def _stop(summary: dict, reason: str, note: str = "") -> dict:
    summary["stop_reason"] = reason
    if note:
        summary["detail"] = note
    return summary


def _bindable(record_or_carrier: dict) -> tuple[bool, str]:
    binding = (record_or_carrier.get("protocol") or {}).get("binding_status")
    if binding in (None, "UNKNOWN", "PARTIAL"):
        return False, f"binding status is {binding or 'UNKNOWN'}: no historical protocol authority to compare against"
    return True, ""


def _backoff_delay(transport_attempts: int) -> float:
    delay = BACKOFF_BASE_SECONDS * (BACKOFF_FACTOR ** max(0, int(transport_attempts) - 1))
    return min(delay, BACKOFF_CAP_SECONDS)


def _classify_unit(
    record: dict,
    event_limit: int,
    journal: dict,
    provisional: bool,
    wall_now: float,
) -> str:
    """One deterministic, model-free eligibility classification (ROLE 6)."""
    if record.get("status") != "IMPORTED":
        return "STALE"
    state = carrier_mod.semantic_state(record)
    if state["exhausted"]:
        return "DONE"
    episodes = list(record.get("episodes") or [])
    if not episodes:
        return "DONE"
    start = state["next_episode_index"]
    if start >= len(episodes):
        return "DONE"
    episode = episodes[start]
    slices = carrier_mod.episode_slice_count(record, episode, event_limit)
    slice_at = min(state["next_slice_index"], slices - 1)
    if (
        carrier_mod.episode_finality(record, episode) == "PROVISIONAL"
        and state["tail_reviewed_digest"]
        and state["tail_reviewed_digest"] == carrier_mod.tail_digest(record, episode, slice_at)
    ):
        return "DONE"
    finality = carrier_mod.episode_finality(record, episode)
    if finality == "PROVISIONAL" and not provisional:
        return "PROVISIONAL_DISABLED"
    session_id = str(record.get("session_id") or "")
    digest = carrier_mod.unit_digest(record, episode, slice_at)
    job_id = jobs_mod.unit_job_id(session_id, int(episode["index"]), slice_at, digest)
    job = jobs_mod.find_job(journal, job_id)
    bindable, _ = _bindable(record)
    if (
        job is not None
        and job.get("stage") == jobs_mod.BLOCKED_BINDING
        and bindable
    ):
        # Conditional block whose condition resolved: re-eligible now, at a
        # NORMAL current-work queue position (ROLE 7).
        return "RUNNABLE_FINAL" if finality == "FINAL" else "RUNNABLE_PROVISIONAL"
    if job is not None and job.get("stage") in _TERMINAL:
        return "TERMINAL"
    if job is not None and job.get("stage") == jobs_mod.RETRY_WAIT:
        if not jobs_mod._retry_due(job, now=wall_now):
            return "WAITING_RETRY"
    if not bindable:
        return "BLOCKED_BINDING"
    if finality == "FINAL":
        return "RUNNABLE_FINAL"
    if finality == "PROVISIONAL" and provisional:
        return "RUNNABLE_PROVISIONAL"
    return "BLOCKED"


def _allocate(  # noqa: C901
    root: Path,
    index: dict,
    journal: dict,
    *,
    provisional: bool,
    event_limit: int,
    summary: dict,
    backend_type: str,
    model: str,
    wall_now: float,
    restrict_job_ids: set[str] | None = None,
) -> tuple[dict | None, str]:
    """Pick the next eligible semantic unit under the worker's own policy.

    Deterministic, model-free. Single eligibility classification drives BOTH
    fairness sync and ranking: only RUNNABLE_FINAL/PROVISIONAL get queue claims.
    Fresh and recovery FINAL share one fairness population ordered by queue ticket
    (ROLE 2/3). Bands: 1 FINAL runnable, 2 PROVISIONAL runnable when permitted.
    Blocked/retry/provisional-disabled/terminal never get active claims.

    T-107 second-pass bridge: the RUNNABLE set is built COMPLETELY -- current
    cursor units AND durable second-pass recoverable jobs that can run now --
    BEFORE fairness is synchronized, so every legitimate runnable candidate
    holds a real positive ticket when it is ranked. The 10**12 sentinel stays
    an invariant-defense fallback only; normal operation must never rely on it
    (relying on it starved recoverable work behind endless newcomers).

    Fairness claim identity is the SESSION (one active claim per session).
    Invariant: at most one runnable semantic job per session can exist at a
    time -- the allocator derives fresh units from each session's FRESHEST
    record cursor, and a second-pass recovery job from the same session only
    enters when its unit is NOT the cursor unit (`job_id in cursor_job_ids`
    check), so the two populations are disjoint per session. A session with a
    recovery entry therefore has no concurrent fresh entry, and one claim
    cannot overwrite another.
    """
    ranked: list[tuple[tuple, dict]] = []
    blocked_fresh = 0
    only_future_retry = False
    only_provisional = True
    records_by_session = {
        str(record.get("session_id") or ""): record
        for record in carrier_mod.freshest_records(index)
    }
    from . import fairness as fairness_mod

    classifications: dict[str, str] = {}
    for sid, rec in records_by_session.items():
        classifications[sid] = _classify_unit(rec, event_limit, journal, provisional, wall_now)

    eligible_digests: dict[str, str] = {}
    for session_id, record in records_by_session.items():
        cls = classifications.get(session_id, "")
        if cls not in ("RUNNABLE_FINAL", "RUNNABLE_PROVISIONAL"):
            continue
        state_ = carrier_mod.semantic_state(record)
        episodes = list(record.get("episodes") or [])
        if not episodes:
            continue
        start = state_["next_episode_index"]
        if start >= len(episodes):
            continue
        episode = episodes[start]
        slices = carrier_mod.episode_slice_count(record, episode, event_limit)
        slice_at = min(state_["next_slice_index"], slices - 1)
        eligible_digests[session_id] = carrier_mod.unit_digest(record, episode, slice_at)

    runnable_entries: list[tuple[dict, int, tuple]] = []
    fresh_cursor_job_ids: set[str] = set()
    for record in carrier_mod.freshest_records(index):
        if record.get("status") != "IMPORTED":
            continue
        episodes = list(record.get("episodes") or [])
        if not episodes:
            continue
        state = carrier_mod.semantic_state(record)
        if state["exhausted"]:
            continue
        start = state["next_episode_index"]
        if start >= len(episodes):
            continue
        episode = episodes[start]
        slices = carrier_mod.episode_slice_count(record, episode, event_limit)
        slice_at = min(state["next_slice_index"], slices - 1)
        if (
            carrier_mod.episode_finality(record, episode) == "PROVISIONAL"
            and state["tail_reviewed_digest"]
            and state["tail_reviewed_digest"] == carrier_mod.tail_digest(record, episode, slice_at)
        ):
            continue
        session_id = str(record.get("session_id") or "")
        finality = carrier_mod.episode_finality(record, episode)
        digest = carrier_mod.unit_digest(record, episode, slice_at)
        job_id = jobs_mod.unit_job_id(session_id, int(episode["index"]), slice_at, digest)
        fresh_cursor_job_ids.add(job_id)
        job = jobs_mod.find_job(journal, job_id)
        bindable, reason = _bindable(record)

        entry = {
            "session_id": session_id,
            "episode_index": int(episode["index"]),
            "slice_index": slice_at,
            "unit_digest": digest,
            "finality": finality,
            "bindable": bindable,
            "job_id": job_id,
            "reason": reason,
        }
        order_key_tail = (
            str(record.get("updated_at") or record.get("imported_at") or ""),
            session_id,
            int(episode["index"]),
            slice_at,
        )

        cls = classifications.get(session_id, "")
        if cls not in ("RUNNABLE_FINAL", "RUNNABLE_PROVISIONAL"):
            if cls == "BLOCKED_BINDING":
                if _record_binding_block(root, journal, entry, backend_type, model):
                    blocked_fresh += 1
            elif cls == "WAITING_RETRY":
                only_future_retry = True
                only_provisional = False
            elif cls in ("TERMINAL", "DONE", "STALE"):
                only_provisional = False
            elif cls == "PROVISIONAL_DISABLED":
                pass
            continue
        if job is not None and job.get("stage") == jobs_mod.BLOCKED_BINDING and not bindable:
            continue
        if (
            job is not None
            and job.get("stage") in _TERMINAL
            and job.get("stage") != jobs_mod.BLOCKED_BINDING
        ):
            only_provisional = False
            continue
        if job is not None and job.get("stage") == jobs_mod.RETRY_WAIT:
            if not jobs_mod._retry_due(job, now=wall_now):
                only_future_retry = True
                only_provisional = False
                continue
        only_provisional = False
        band = 1 if finality == "FINAL" else 2
        runnable_entries.append((entry, band, order_key_tail))

    # Second pass: durable jobs whose unit the cursor has already moved past
    # (the receipt advanced coverage mid-flight, or the job was interrupted at
    # a stage that survives a cursor move). They are recoverable work the
    # journal proves: a SUBMITTING job resubmits and converges idempotently.
    recovery_bands: list[tuple[dict, int, tuple]] = []
    recovery_digests: dict[str, str] = {}
    for job in (journal.get("jobs") or {}).values():
        stage = job.get("stage")
        if stage in _TERMINAL or stage == jobs_mod.BLOCKED_BINDING:
            continue
        job_id = str(job.get("job_id") or "")
        if job_id in fresh_cursor_job_ids:
            continue
        record = records_by_session.get(str(job.get("session_id") or ""))
        if record is None:
            # The session is no longer indexed: nothing can drive this job.
            continue
        finality = str(job.get("finality") or "FINAL")
        bindable, reason = _bindable(record)
        if stage == jobs_mod.RETRY_WAIT and not jobs_mod._retry_due(job, now=wall_now):
            only_future_retry = True
            only_provisional = False
            continue
        if not bindable:
            continue
        entry = {
            "session_id": str(job.get("session_id") or ""),
            "episode_index": int(job.get("episode_index") or 0),
            "slice_index": int(job.get("slice_index") or 0),
            "unit_digest": str(job.get("unit_digest") or ""),
            "finality": finality,
            "bindable": True,
            "job_id": job_id,
            "reason": reason,
        }
        order_key_tail = (
            str(record.get("updated_at") or record.get("imported_at") or ""),
            str(job.get("session_id") or ""),
            int(job.get("episode_index") or 0),
            int(job.get("slice_index") or 0),
        )
        band = 1 if finality == "FINAL" else 2
        recovery_bands.append((entry, band, order_key_tail))
        # T-107 bridge: a recoverable job's session joins the eligible set with
        # ITS OWN unit digest (never the cursor's), so its ticket names the
        # work that will actually be ranked and served.
        recovery_digests.setdefault(entry["session_id"], entry["unit_digest"])

    # BOTH runnable populations are known: NOW synchronize fairness and rank.
    # The combined eligible set is the union; per session at most one claim can
    # exist (fresh cursor and recovery entry are disjoint per session), so one
    # claim per session cannot overwrite another.
    combined_eligible = dict(recovery_digests)
    for sid, digest in eligible_digests.items():
        combined_eligible.setdefault(sid, digest)
    fairness_state, _changed = fairness_mod.sync_eligibility(root, combined_eligible)
    fairness_state = _reconcile_done_receipt_claims(root, fairness_state, records_by_session)

    for entry, band, order_key_tail in runnable_entries:
        order_key = (fairness_mod.queue_rank(entry["session_id"], fairness_state),) + order_key_tail
        ranked.append(((band, order_key), entry))
    for entry, band, order_key_tail in recovery_bands:
        order_key = (fairness_mod.queue_rank(entry["session_id"], fairness_state),) + order_key_tail
        ranked.append(((band, order_key), entry))

    summary["jobs_blocked_binding"] += blocked_fresh
    ranked.sort(key=lambda item: item[0])
    for _key, entry in ranked:
        if restrict_job_ids is not None and entry["job_id"] not in restrict_job_ids:
            continue
        return entry, ""
    if only_future_retry:
        return None, "RETRY_WAIT"
    if only_provisional:
        return None, "only HOT provisional work remains; enable provisional investigation explicitly"
    return None, "IDLE"


def _reconcile_done_receipt_claims(
    root: Path,
    fairness_state: dict,
    records_by_session: dict[str, dict],
) -> dict:
    """Reconcile stale claims where a receipt committed but fairness did not.

    Expected conditions (silently handled, nothing hidden):
    - receipts ledger absent (`absent`) or empty;
    - no stale claim for a session (nothing to reconcile);
    - the claim names a unit the session still owes (already correct).
    DANGEROUS conditions are integrity failures and must be loud, never
    `except Exception: pass` (the corrupt-fairness-fails-loudly contract):
    - an UNRECOVERABLE receipts ledger (torn bytes): refusing is the only safe
      answer, because "no receipt" cannot be distinguished from "unreadable";
    - a fairness save failure (disk/permission/atomicity): allocation stops so
      no new model call is paid against an untracked claim.
    """
    from saipal_engine.submit import load_receipts as _load_receipts

    status, _payload, _detail = _load_receipts(root)
    if status == "unrecoverable":
        raise PalError(
            "VALIDATION_FAILED",
            "semantic receipts ledger is unreadable while reconciling fairness "
            "claims; refusing to allocate work against unknown completion state",
            next_action="repair or remove .saipal/semantic_receipts.json by hand",
        )
    if status != "ok":
        return fairness_state
    _st, payload, _d = _load_receipts(root)
    done_sessions = {
        str(r.get("session_id")) for r in ((payload or {}).get("receipts") or [])
    }
    changed = False
    for sid in list((fairness_state.get("sessions") or {})):
        if sid not in done_sessions or not fairness_state["sessions"][sid].get("ticket"):
            continue
        rec = records_by_session.get(sid)
        if rec is None or carrier_mod.semantic_state(rec).get("exhausted"):
            fairness_state["sessions"][sid]["ticket"] = 0
            fairness_state["sessions"][sid]["current_unit_digest"] = ""
            changed = True    if changed:
        from .fairness import save_state as _save_fairness

        _save_fairness(root, fairness_state)
    return fairness_state


def _record_binding_block(
    root: Path, journal: dict, entry: dict, backend_type: str, model: str
) -> bool:
    """Upsert the BLOCKED_BINDING job for a non-bindable unit. Never selects it.

    Returns True when the record was fresh (first block), False on re-confirm.
    """
    job = jobs_mod.find_job(journal, entry["job_id"])
    fresh = job is None
    if fresh:
        job = jobs_mod.new_job(
            session_id=entry["session_id"],
            episode_index=entry["episode_index"],
            slice_index=entry["slice_index"],
            unit_digest=entry["unit_digest"],
            finality=entry["finality"],
            backend_type=backend_type,
            model=model,
            run_id="",
        )
    job["stage"] = jobs_mod.BLOCKED_BINDING
    job["error_class"] = "BLOCKED_BINDING"
    job["error_detail"] = entry["reason"]
    jobs_mod.upsert(journal, job)
    jobs_mod.save_journal(root, journal)
    return fresh


def _loop(  # noqa: C901
    summary, root, config, ledger, clock: WorkerClock, started, *,
    limit, max_calls, max_wall, max_retries, max_response_bytes,
    provisional, restrict_job_ids=None, publication_ceiling=None,
) -> dict:
    """Inner loop. `summary` is live; returns it on every stop condition."""
    policy = config.get("deliberation") or {}
    run_id = _run_id()
    timeout_cfg = float((config.get("backend") or {}).get("timeout_seconds") or 120.0)

    allowed, detail = egress_verdict(config)
    if not allowed:
        return _stop(summary, "ERROR", detail)

    # ROLE 9 (T-119): a corrupt recurrence ledger refuses BEFORE the first
    # unit allocation, so paid model work never discovers the damage late.
    from saipal_engine.recurrence import recurrence_status

    if recurrence_status(root) == "INVALID":
        return _stop(
            summary,
            "ERROR",
            ".saipal/recurrence.json is corrupt; refusing to run semantic work "
            "that would need the recurrence ledger",
        )


    event_limit = int(carrier_mod._limits(load_registry())["max_events"])

    while summary["units"] < limit:
        index_status, index, index_detail = load_index(root)
        if index_status == STATUS_UNRECOVERABLE:
            return _stop(summary, "ERROR", index_detail)

        journal = jobs_mod.load_journal(root)
        unit, note = _allocate(
            root, index, journal,
            provisional=provisional, event_limit=event_limit, summary=summary,
            backend_type=str(config["backend"].get("type") or ""),
            model=str(config["backend"].get("model") or ""),
            wall_now=clock.wall_now(),
            restrict_job_ids=restrict_job_ids,
        )
        if unit is None:
            if note == "RETRY_WAIT":
                due = _earliest_retry(journal)
                remaining = max_wall - (clock.monotonic_now() - started)
                if due is not None and 0 < due - clock.wall_now() <= remaining:
                    # Nothing else is eligible: waiting for the bounded retry
                    # is the only progress available. Never a busy loop: the
                    # sleep reaches exactly the due time, within the wall budget.
                    clock.sleep(due - clock.wall_now())
                    continue
                return _stop(summary, "RETRY_WAIT", "eligible work exists only as a future retry; stopping until its time is due")
            blocked_recorded = summary["jobs_blocked_binding"] + summary["jobs_blocked"] > 0
            if blocked_recorded:
                return _stop(summary, "BLOCKED", "no eligible unit remains; blocked units are recorded in the journal")
            return _stop(summary, "IDLE", note or "no analyzable episode is pending")

        carrier = carrier_mod.build_carrier(
            root,
            index=index,
            registry=None,
            session_id=unit["session_id"],
            episode_index=unit["episode_index"],
            slice_index=unit["slice_index"],
        )
        if not carrier.get("session") or not carrier.get("unit_digest"):
            return _stop(summary, "ERROR", "allocator selected a unit the carrier cannot rebuild")

        try:
            unit_started = clock.monotonic_now()
            outcome = _drive_unit(
                carrier, journal, root, summary, ledger, config, policy, run_id,
                clock, started, max_calls, max_wall, max_retries, max_response_bytes,
                timeout_cfg, publication_ceiling=publication_ceiling,
            )
            summary.setdefault("unit_latencies", []).append(
                round(clock.monotonic_now() - unit_started, 3)
            )
            if outcome == "DONE":
                try:
                    from . import fairness as fairness_mod

                    fairness_mod.record_service(root, str(unit["session_id"]))
                except PalError as exc:
                    summary["ok"] = False
                    summary["errors"].append(
                        {"code": "FAIRNESS_PERSISTENCE_FAILED", "detail": str(exc.message or exc)}
                    )
                    return _stop(
                        summary,
                        "ERROR",
                        f"fairness persistence failed after receipt commit: {exc.message or exc}",
                    )
        except _BudgetStop as stop:
            return _stop(summary, "BUDGET_EXHAUSTED", stop.detail)

        if outcome == "RETRY_WAIT":
            continue
        summary["units"] += 1
        try:
            from . import budgets as budgets_mod

            budgets_mod.record_consumption(root, units=1)
        except PalError:
            pass
        if outcome in ("BLOCKED", "BLOCKED_BINDING"):
            reason = "BLOCKED" if outcome == "BLOCKED" else "BLOCKED_BINDING"
            note = (
                "backend or output failure blocked the unit; the journal records it"
                if outcome == "BLOCKED"
                else "historical binding is insufficient; the unit is recorded and revisited when authority improves"
            )
            return _stop(summary, reason, note)
        if outcome == "STALE":
            continue

    return _stop(summary, "BUDGET_EXHAUSTED", f"unit budget {limit} reached")


def _earliest_retry(journal: dict) -> float | None:
    times: list[float] = []
    for job in (journal.get("jobs") or {}).values():
        if job.get("stage") != jobs_mod.RETRY_WAIT:
            continue
        raw = job.get("next_retry_at")
        try:
            times.append(float(raw))
        except (TypeError, ValueError):
            continue
    return min(times) if times else None


def _persist(root: Path, journal: dict, job: dict) -> None:
    jobs_mod.upsert(journal, job)
    jobs_mod.save_journal(root, journal)


def _drive_unit(  # noqa: C901
    carrier, journal, root, summary, ledger, config, policy, run_id,
    clock: WorkerClock, started, max_calls, max_wall, max_retries, max_response_bytes,
    timeout_cfg, publication_ceiling=None,
):
    """Take one unit through the durable stage machine to a settled outcome.

    Returns DONE / BLOCKED / BLOCKED_BINDING / STALE / RETRY_WAIT, or raises
    _BudgetStop with the job stage already durable for the exact resume point.
    """
    session_id = carrier["session"]["session_id"]
    episode_index = carrier["episode"]["index"]
    slice_index = (carrier.get("slice") or {}).get("index", 0)
    unit_digest = carrier["unit_digest"]
    finality = str((carrier.get("episode") or {}).get("finality") or "")
    job_id = jobs_mod.unit_job_id(session_id, episode_index, slice_index, unit_digest)
    job = jobs_mod.find_job(journal, job_id)

    if job is None:
        job = jobs_mod.new_job(
            session_id=session_id,
            episode_index=episode_index,
            slice_index=slice_index,
            unit_digest=unit_digest,
            finality=finality,
            backend_type=config["backend"]["type"],
            model=config["backend"]["model"],
            run_id=run_id,
        )
        _persist(root, journal, job)

    if job.get("stage") == jobs_mod.BLOCKED_BINDING:
        # Automatic reactivation: the unit identity is evidence-based, so
        # protocol authority becoming BOUND does not change the job id. The
        # worker resumes at the stage the persisted artifacts prove.
        bindable, _reason = _bindable(carrier)
        if not bindable:
            job["error_detail"] = _reason
            _persist(root, journal, job)
            summary["jobs_blocked_binding"] += 1
            return "BLOCKED_BINDING"
        job["error_class"] = None
        job["error_detail"] = None
        jobs_mod.advance(journal, job, jobs_mod.resume_stage(job))
        _persist(root, journal, job)

    try:
        packet = packet_mod.build_packet(carrier, analyst=config["backend"])
    except PalError as exc:
        job["stage"] = jobs_mod.BLOCKED
        job["error_class"] = exc.code
        job["error_detail"] = str(exc.message or exc)
        _persist(root, journal, job)
        summary["jobs_blocked"] += 1
        return "BLOCKED"

    def call_role(role: str, user: str) -> object:
        return _guarded_call(
            root, job, summary, ledger, config, role, user,
            clock, started, max_calls, max_wall, timeout_cfg,
        )

    def persist_raw(role: str, text: str) -> None:
        """Durable BEFORE parse: the paid response must never be re-billed."""
        if role == "investigator":
            _stage(
                root, journal, job, jobs_mod.INVESTIGATOR_RESPONSE,
                response_text=text, response_digest=_digest(text),
            )
        elif role == "critic":
            job["critic_response_text"] = text
            _persist(root, journal, job)
        else:
            job["finalizer_response_text"] = text
            _persist(root, journal, job)

    def validate_with_repair(role: str, parse, reject_note: str) -> _Validation:
        """Parse the role's persisted raw text with the one durable repair.

        A persisted repair response is re-parsed on restart without a new
        model call; the per-role repair allowance is a durable counter, so a
        crash cannot reset it and a failed repair can never loop.
        """
        counter = f"{role}_repairs"
        repair_field = f"{role}_repair_text"
        if role == "investigator":
            raw = str(job.get("response_text") or "")
        elif role == "critic":
            raw = str(job.get("critic_response_text") or "")
        else:
            raw = str(job.get("finalizer_response_text") or "")
        try:
            return _Validation(value=parse(raw))
        except output_mod.OutputRejected as first:
            persisted_repair = job.get(repair_field)
            if persisted_repair:
                try:
                    return _Validation(value=parse(str(persisted_repair)))
                except output_mod.OutputRejected as second:
                    return _Validation(detail=f"{reject_note}: still invalid after repair: {second}")
            if int(job.get(counter) or 0) >= DEFAULT_MAX_REPAIRS:
                return _Validation(
                    detail=f"{reject_note}: invalid after durable repair budget: {first}"
                )
            summary["repair_calls"] += 1
            outcome = call_role(
                role, prompts_mod.repair_user_message(packet, raw, [str(first)])
            )
            if isinstance(outcome, BackendFailure):
                # A transport failure is a transport retry, never a consumed
                # semantic repair: the budget is only spent by a DURABLE
                # repair response, persisted together with its counter.
                return _Validation(failure=outcome)
            repair_text = str(outcome)
            job[counter] = int(job.get(counter) or 0) + 1
            job[repair_field] = repair_text
            _persist(root, journal, job)
            try:
                return _Validation(value=parse(repair_text))
            except output_mod.OutputRejected as second:
                return _Validation(detail=f"{reject_note}: still invalid after repair: {second}")

    while True:
        action = jobs_mod.next_action(job)
        if action == "skip":
            return "BLOCKED"

        if action == "ambiguous":
            # W2-005 default policy: no automatic paid replay when a CALLING
            # record has an attempt identity but no persisted response. Keep
            # the durable evidence visible and stop this unit.
            job["stage"] = jobs_mod.REMOTE_OUTCOME_UNKNOWN
            job["error_class"] = "REMOTE_OUTCOME_UNKNOWN"
            job["error_detail"] = (
                "paid remote attempt has unknown outcome; operator review or "
                "an explicitly idempotent retry policy is required"
            )
            _persist(root, journal, job)
            summary["jobs_blocked"] += 1
            return "BLOCKED"

        if action == "call":
            _stage(root, journal, job, jobs_mod.INVESTIGATOR_CALLING)
            outcome = call_role("investigator", prompts_mod.packet_user_message(packet))
            if isinstance(outcome, BackendFailure):
                return _transport_failure(
                    root, journal, job, summary, outcome, max_retries, clock
                )
            persist_raw("investigator", str(outcome))
            # The response is durable: the ambiguous attempt is resolved.
            job["ambiguous_attempt_ids"] = []
            action = "validate"

        if action == "validate":
            result = validate_with_repair(
                "investigator",
                lambda text: output_mod.validate_candidate(
                    output_mod.parse_json_object(text), packet
                ),
                "investigator output",
            )
            if result.backend_failed:
                return _transport_failure(
                    root, journal, job, summary, result.failure, max_retries, clock
                )
            if not result.ok:
                job["stage"] = jobs_mod.BLOCKED
                job["error_class"] = "BLOCKED_OUTPUT"
                job["error_detail"] = result.detail
                _persist(root, journal, job)
                summary["jobs_blocked"] += 1
                return "BLOCKED"
            candidate = result.value
            job["candidate"] = candidate
            job["candidate_digest"] = _digest(json.dumps(candidate, sort_keys=True))
            job["verdict"] = candidate.get("verdict")
            if job.get("investigator_repair_text"):
                # The repaired response is the effective reasoning source.
                job["response_digest"] = _digest(str(job["investigator_repair_text"]))
            jobs_mod.advance(journal, job, jobs_mod.CANDIDATE_READY)
            _persist(root, journal, job)
            action = "critic"

        if action == "critic":
            need, _reason = output_mod.needs_critic(
                job["candidate"], packet, policy=policy,
                unit_digest=str(packet.get("unit_digest")),
            )
            if not need:
                jobs_mod.advance(journal, job, jobs_mod.FINAL_READY)
                _persist(root, journal, job)
                action = "submit"
            else:
                if job["stage"] == jobs_mod.CANDIDATE_READY:
                    _stage(root, journal, job, jobs_mod.CRITIC_CALLING)
                if not job.get("critic_response_text"):
                    outcome = call_role(
                        "critic",
                        prompts_mod.critic_user_message(packet, job["candidate"]),
                    )
                    if isinstance(outcome, BackendFailure):
                        return _transport_failure(
                            root, journal, job, summary, outcome, max_retries, clock
                        )
                    persist_raw("critic", str(outcome))
                    job["ambiguous_attempt_ids"] = []
                result = validate_with_repair(
                    "critic",
                    lambda text: output_mod.parse_critic(text, packet),
                    "critic output",
                )
                if result.backend_failed:
                    return _transport_failure(
                        root, journal, job, summary, result.failure, max_retries, clock
                    )
                if not result.ok:
                    job["stage"] = jobs_mod.BLOCKED
                    job["error_class"] = "BLOCKED_OUTPUT"
                    job["error_detail"] = result.detail
                    _persist(root, journal, job)
                    summary["jobs_blocked"] += 1
                    return "BLOCKED"
                _stage(
                    root, journal, job, jobs_mod.CRITIC_READY,
                    critic_payload=result.value,
                    critic_digest=_digest(
                        str(job.get("critic_repair_text") or job.get("critic_response_text") or "")
                    ),
                )
                action = "finalize"

        if action == "finalize":
            critic = job.get("critic_payload")
            if not isinstance(critic, dict):
                job["stage"] = jobs_mod.BLOCKED
                job["error_class"] = "VALIDATION_FAILED"
                job["error_detail"] = "finalize without a persisted critic payload"
                _persist(root, journal, job)
                summary["jobs_blocked"] += 1
                return "BLOCKED"
            verdict = (job.get("candidate") or {}).get("verdict")
            decision = critic.get("decision")
            if decision == "DISAGREE" or (verdict == "DRIFT" and decision != "AGREE"):
                if not policy.get("finalizer_on_disagreement", True):
                    job["stage"] = jobs_mod.BLOCKED
                    job["error_class"] = "BLOCKED_OUTPUT"
                    job["error_detail"] = "critic disagreement with finalizer disabled"
                    _persist(root, journal, job)
                    summary["jobs_blocked"] += 1
                    return "BLOCKED"
                if job["stage"] == jobs_mod.CRITIC_READY:
                    _stage(root, journal, job, jobs_mod.FINALIZER_CALLING)
                if not job.get("finalizer_response_text"):
                    outcome = call_role(
                        "finalizer",
                        prompts_mod.finalizer_user_message(packet, job["candidate"], critic),
                    )
                    if isinstance(outcome, BackendFailure):
                        return _transport_failure(
                            root, journal, job, summary, outcome, max_retries, clock
                        )
                    persist_raw("finalizer", str(outcome))
                    job["ambiguous_attempt_ids"] = []
                result = validate_with_repair(
                    "finalizer",
                    lambda text: output_mod.validate_candidate(
                        output_mod.parse_json_object(text), packet
                    ),
                    "finalizer output",
                )
                if result.backend_failed:
                    return _transport_failure(
                        root, journal, job, summary, result.failure, max_retries, clock
                    )
                if not result.ok:
                    job["stage"] = jobs_mod.BLOCKED
                    job["error_class"] = "BLOCKED_OUTPUT"
                    job["error_detail"] = result.detail
                    _persist(root, journal, job)
                    summary["jobs_blocked"] += 1
                    return "BLOCKED"
                candidate = result.value
                job["candidate"] = candidate
                job["candidate_digest"] = _digest(json.dumps(candidate, sort_keys=True))
                job["verdict"] = candidate.get("verdict")
                _stage(
                    root, journal, job, jobs_mod.FINAL_READY,
                    finalizer_digest=_digest(
                        str(job.get("finalizer_repair_text") or job.get("finalizer_response_text") or "")
                    ),
                )
            else:
                # AGREE (incl. DRIFT+AGREE) or the kept NO_DRIFT/INSUFFICIENT
                # path: the critic has spoken and the candidate stands as is.
                _stage(root, journal, job, jobs_mod.FINAL_READY)
            action = "submit"

        if action == "submit":
            job["candidate_digest"] = _digest(json.dumps(job["candidate"], sort_keys=True))
            _stage(root, journal, job, jobs_mod.SUBMITTING, candidate_digest=job["candidate_digest"])
            candidate = job["candidate"]
            submission_candidate = {
                key: value
                for key, value in candidate.items()
                if key != "analyst_provenance"
            }
            summary["submit_attempts"] += 1
            try:
                receipt = submit_mod.submit_candidate(
                    root, submission_candidate,
                    publication_ceiling=publication_ceiling,
                )
            except PalError as exc:
                if exc.code in ("CANDIDATE_OUT_OF_SCOPE", "EVIDENCE_NOT_FOUND") or "stale" in str(
                    exc.message or ""
                ).lower():
                    summary["stale_refusals"] += 1
                    job["stage"] = jobs_mod.STALE
                    job["error_class"] = "STALE"
                    job["error_detail"] = str(exc.message or exc)
                    _persist(root, journal, job)
                    summary["jobs_stale"] += 1
                    return "STALE"
                summary["kernel_refusals"] += 1
                job["submit_attempts"] = int(job.get("submit_attempts") or 0) + 1
                if job["submit_attempts"] > max_retries:
                    job["stage"] = jobs_mod.BLOCKED
                    job["error_class"] = exc.code
                    job["error_detail"] = str(exc.message or exc)
                    _persist(root, journal, job)
                    summary["jobs_blocked"] += 1
                    return "BLOCKED"
                job["next_retry_at"] = _retry_at(
                    clock.wall_now(), _backoff_delay(job["submit_attempts"])
                )
                jobs_mod.advance(journal, job, jobs_mod.RETRY_WAIT)
                _persist(root, journal, job)
                return "RETRY_WAIT"

            receipt_id = receipt.get("receipt_id")
            job["receipt_id"] = receipt_id
            summary["submit_successes"] += 1
            # Receipt-linked provenance: observational truth, written after
            # the kernel committed. A provenance failure never invalidates
            # the receipt -- it surfaces as a discrepancy and the journal
            # still proves the link for `reconcile_provenance`.
            try:
                from . import provenance as provenance_mod

                provenance_mod.record_provenance(
                    root, provenance_mod.provenance_from_job(job)
                )
            except PalError as exc:
                summary["errors"].append(
                    {"code": "PROVENANCE_WRITE_FAILED", "detail": str(exc.message or exc)}
                )
            job["stage"] = jobs_mod.DONE
            _persist(root, journal, job)
            summary["jobs_completed"] += 1
            summary["receipts"].append(
                {
                    "receipt_id": receipt_id,
                    "verdict": candidate.get("verdict"),
                    "session_id": str(job.get("session_id") or ""),
                }
            )
            return "DONE"

        if action == "retry":
            # A due RETRY_WAIT: resume at the stage the artifacts prove.
            target = jobs_mod.resume_stage(job)
            if target != job.get("stage"):
                jobs_mod.advance(journal, job, target)
                _persist(root, journal, job)
            continue

        job["stage"] = jobs_mod.BLOCKED
        job["error_class"] = "VALIDATION_FAILED"
        job["error_detail"] = f"no drivable action for stage {job.get('stage')!r}"
        _persist(root, journal, job)
        summary["jobs_blocked"] += 1
        return "BLOCKED"


def _stage(root: Path, journal: dict, job: dict, to_state: str, **fields: object) -> None:
    for key, value in fields.items():
        job[key] = value
    jobs_mod.advance(journal, job, to_state)
    _persist(root, journal, job)


def _guarded_call(  # noqa: C901
    home, job, summary, ledger, config, role, user,
    clock: WorkerClock, started, max_calls, max_wall, timeout_cfg,
) -> object:
    """One budget-guarded transport attempt. Returns text or BackendFailure.

    Budgets apply BEFORE every model call, not per unit: a critic or
    finalizer request that would violate the hard run budget is never
    started. The effective timeout is bounded by the remaining wall budget
    (never a 120s backend timeout when only seconds remain). The job stage
    was made durable before this call, so a budget stop resumes at the exact
    deliberation stage instead of repeating paid work.
    """
    if summary["model_calls"] >= max_calls:
        raise _BudgetStop(f"model call budget {max_calls} reached")
    remaining = max_wall - (clock.monotonic_now() - started)
    if remaining <= MIN_CALL_WINDOW_SECONDS:
        raise _BudgetStop(f"wall budget {max_wall}s has no room for another call")
    effective_timeout = min(timeout_cfg, remaining)

    # Durable cross-run gates: the hourly ledger and the backend circuit are
    # checked BEFORE every transport attempt, and a failed attempt is still
    # charged -- an unattended loop can never reset its own budget.
    from . import budgets as budgets_mod

    global_limits = {
        "max_model_attempts_per_hour": (config.get("budgets") or {}).get(
            "max_model_attempts_per_hour"
        ),
        "max_semantic_units_per_hour": (config.get("budgets") or {}).get(
            "max_semantic_units_per_hour"
        ),
    }
    allowed, reason = budgets_mod.budget_allows(home, limits=global_limits)
    if not allowed:
        raise _BudgetStop(f"global hourly budget: {reason}")
    budgets_mod.circuit_probe_allowed(home)
    allowed, reason = budgets_mod.circuit_allows(home)
    if not allowed:
        raise _BudgetStop(reason)

    from saipal_analyst.prompts import (
        CRITIC_SYSTEM,
        FINALIZER_SYSTEM,
        INVESTIGATOR_SYSTEM,
    )

    role_system = {
        "investigator": INVESTIGATOR_SYSTEM,
        "critic": CRITIC_SYSTEM,
        "finalizer": FINALIZER_SYSTEM,
    }.get(role, INVESTIGATOR_SYSTEM)

    # ONE authoritative accounting boundary: one transport attempt is exactly
    # one model call, counted here whether it succeeds or fails.
    summary["model_calls"] += 1
    summary[f"{role}_calls"] = summary.get(f"{role}_calls", 0) + 1
    # W2-005: persist the paid-attempt identity BEFORE transport. If the
    # process dies after the provider accepted the request but before the raw
    # response reaches the journal, the restart finds the attempt_id,
    # classifies the outcome REMOTE_OUTCOME_UNKNOWN, and never silently
    # re-issues the same paid work under a fresh identity.
    try:
        from saipal_analyst import jobs as jobs_mod

        attempt_id = jobs_mod.next_attempt_id(job, role, _digest(user))
        jobs_mod.mark_ambiguous_attempt(job, role, attempt_id)
        fresh = jobs_mod.load_journal(home)
        stored = jobs_mod.find_job(fresh, job["job_id"]) or job
        stored.update(job)
        jobs_mod.upsert(fresh, stored)
        jobs_mod.save_journal(home, fresh)
        job.pop("error_class", None)
        job.pop("error_detail", None)
    except PalError:
        pass  # the transport call itself may still fail; accounting is best-effort here
    try:
        reply = transport_mod.call(config, system=role_system, user=user, timeout=effective_timeout)
    finally:
        pass
    if not reply.ok:
        try:
            budgets_mod.record_backend_failure(
                home,
                failure_class=reply.failure_class,
                retryable=reply.failure_class == backend_mod.RETRYABLE,
            )
        except PalError:
            pass
        # A failed attempt is still an attempt: charged to the durable window.
        try:
            budgets_mod.record_consumption(home, model_attempts=1)
        except PalError:
            pass
        if reply.failure_class == backend_mod.RETRYABLE:
            summary["backend_retryable_failures"] += 1
            if reply.http_status == 429:
                summary["rate_limited"] += 1
            if reply.timed_out:
                summary["timeouts"] += 1
        elif reply.failure_class == backend_mod.AUTH:
            summary["backend_auth_failures"] += 1
        elif reply.failure_class == backend_mod.PERMANENT:
            summary["backend_permanent_failures"] += 1
        elif reply.failure_class == backend_mod.LIMIT:
            summary["backend_limits"] += 1
        return BackendFailure(reply)

    try:
        budgets_mod.record_backend_success(home)
    except PalError:
        pass
    summary["backend_successes"] += 1
    ledger.calls += 1
    usage_dict = reply.usage if isinstance(reply.usage, dict) else None
    # W2-002: the run ledger stays cumulative, but the DURABLE window is
    # charged with THIS reply's usage delta only. Passing the cumulative
    # totals here triangularly overcounted every run (100+100 became 300).
    delta_in, delta_out = backend_mod.UsageLedger.usage_delta(usage_dict)
    ledger.absorb(usage_dict)
    summary.update(ledger.snapshot())
    try:
        budgets_mod.record_consumption(
            home,
            model_attempts=1,
            input_tokens=delta_in,
            output_tokens=delta_out,
        )
    except PalError:
        pass
    return reply.text


def _transport_failure(  # noqa: C901
    root, journal, job, summary, failure: BackendFailure, max_retries, clock: WorkerClock
):
    """Provider failure is not output failure: RETRY_WAIT under a bounded,
    deterministic backoff, or a loud BLOCKED for AUTH/PERMANENT/LIMIT."""
    if not failure.retryable:
        job["stage"] = jobs_mod.BLOCKED
        job["error_class"] = f"BACKEND_{failure.failure_class}"
        job["error_detail"] = str(failure)
        _persist(root, journal, job)
        summary["jobs_blocked"] += 1
        return "BLOCKED"

    job["transport_attempts"] = int(job.get("transport_attempts") or 0) + 1
    if job["transport_attempts"] > max_retries:
        job["stage"] = jobs_mod.BLOCKED
        job["error_class"] = "BACKEND_RETRYABLE_EXHAUSTED"
        job["error_detail"] = str(failure)
        _persist(root, journal, job)
        summary["jobs_blocked"] += 1
        return "BLOCKED"
    job["next_retry_at"] = _retry_at(
        clock.wall_now(), _backoff_delay(job["transport_attempts"])
    )
    job["error_class"] = "BACKEND_RETRYABLE"
    job["error_detail"] = str(failure)
    jobs_mod.advance(journal, job, jobs_mod.RETRY_WAIT)
    _persist(root, journal, job)
    return "RETRY_WAIT"


def _retry_at(now_wall: float, delay: float) -> float:
    return float(now_wall) + float(delay)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
