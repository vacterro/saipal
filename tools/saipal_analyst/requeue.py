"""Canonical reactivation of semantically refused analyst units (T-136).

A unit the analyst examined and the candidate contract REFUSED lands in the
journal as `BLOCKED` -- for a model whose JSON did not parse, for a payload
the schema does not own, for a packet that could not be built. That refusal is
durable and the allocator treats `BLOCKED` as terminal, so without a canonical
way back the unit is lost for good: it is not pending (it has a job), it is not
analysable (it has no job that can be selected), and nothing in the protocol
ever names it again. This module closes that gap.

It is the journal-side twin of `saipal_engine.rebind`: rebind wakes a unit
whose *authority* became sufficient, requeue wakes a unit whose *answer* was
refused, and neither performs journal surgery by hand.

What a requeue is NOT -- and the guard that makes that true:

- It is not a replay. The failed attempt's raw response, repair text,
  candidate, critic payload and paid-attempt identity are CLEARED, because
  re-parsing a response already known to be inadmissible would spend zero
  calls and refuse the unit again -- a spin disguised as progress. A requeue
  buys exactly one FRESH attempt: a new model call, with its own repair
  allowance.
- It is not a fix for the model. A requeue is admitted only when the material
  conditions that produced the refusal CHANGED (the analyst config digest --
  the same identity the AUTH latch is pinned to -- so a different model, a
  different endpoint, a different budget). Requeuing under an identical
  material is refused with `NO_MATERIAL_CHANGE` and names the honest choices:
  change the model or the evidence, or pass `--force` to spend the attempt
  knowingly.
- It is not unbounded. `budgets.max_requeues_per_unit` (default 1) is a
  durable counter carried in the job, so a crash cannot reset it and pressing
  requeue in a loop cannot bill forever. `--force` is the single, recorded
  escape hatch; it is an operator decision, never a policy.
- It is not the right answer everywhere. `BLOCKED_BINDING` is woken by
  `authority enroll` + `rebind`, `REMOTE_OUTCOME_UNKNOWN` by the paid-attempt
  policy (W2-005), `STALE` by nothing. Those are refused BY NAME with the
  canonical action attached, never silently reactivated.

Every requeue stays auditable afterwards: the refused output is preserved by
digest inside the job's `requeues` history, so what was refused, why, under
which material, and with whose authority is readable without replaying it.
"""

from __future__ import annotations

import time
from pathlib import Path

from saipal_engine.errors import PalError
from saipal_engine.registry import load_registry

from . import jobs as jobs_mod

#: Fresh attempts per unit when the config names no budget. One: enough to
#: distinguish "the refusal was a fluke" from "the model cannot answer this".
DEFAULT_MAX_REQUEUES = 1

#: Bounded history: the journal is a hot file, and only the last few refusals
#: matter for deciding whether another attempt is justified.
MAX_HISTORY = 8

#: The failed attempt's payload, cleared so the next run makes a NEW call.
#: Digests of the cleared artifacts are kept in the history entry -- only what
#: would make the next pass re-judge the SAME bytes is dropped.
CLEARED_FIELDS = (
    "response_text",
    "response_digest",
    "investigator_repair_text",
    "critic_response_text",
    "critic_repair_text",
    "critic_payload",
    "critic_digest",
    "finalizer_response_text",
    "finalizer_repair_text",
    "finalizer_digest",
    "candidate",
    "candidate_digest",
    "verdict",
)

#: ... and the two CONTAINERS, which are emptied rather than nulled. A paid-attempt
#: identity belongs to the attempt that was cleared: keeping it would let a crash
#: detector report an ambiguity for a request that will never be re-issued, and a
#: NULL container is not a legal journal value for them.
RESET_FIELDS: dict[str, object] = {
    "attempt_ids": {},
    "ambiguous_attempt_ids": [],
}

#: Durable repair allowances belong to the response they repaired; a fresh
#: response gets its own. Everything else (`attempts`, `transport_attempts`,
#: `submit_attempts`) is cumulative and stays.
CLEARED_COUNTERS = (
    "repairs",
    "investigator_repairs",
    "critic_repairs",
    "finalizer_repairs",
)

#: The stage that is the SUBJECT of a requeue ...
REQUEUE_STAGE = jobs_mod.BLOCKED

#: ... and the stages that look adjacent but have their own canonical path.
#: Named with the exact next command, never silently skipped.
OTHER_STAGES: dict[str, dict] = {
    "BLOCKED_BINDING": {
        "reason": "the unit is blocked on protocol binding authority, not on the model's answer",
        "next_action": (
            "python -B tools/saipal.py authority enroll --release-root PATH, "
            "then rebind --dry-run: a rebind to BOUND re-eligibilizes the job "
            "automatically"
        ),
    },
    "REMOTE_OUTCOME_UNKNOWN": {
        "reason": (
            "a paid remote attempt has an unknown outcome; the default policy "
            "(W2-005) never replays it automatically"
        ),
        "next_action": "resolve the paid attempt explicitly before any retry",
    },
    "STALE": {
        "reason": "the session is no longer importable, so no attempt can be driven",
        "next_action": "re-import the session; a requeue would be a no-op",
    },
}

#: The refusal classes the journal is known to write for a `BLOCKED` unit: the
#: candidate contract refusing output, the finalizer finding no critic payload,
#: a transport retry budget that ran out, and the backend's own error codes
#: (AUTH, configuration). The requeue is the canonical answer for all of them,
#: so this tuple documents the vocabulary -- it is NOT an allow-list. A class
#: the protocol has not seen yet is requeued like the rest: silently excluding
#: it is the failure mode this module exists to remove, and the material guard
#: plus the durable allowance already bound what can be spent.
BLOCKED_CLASSES = (
    "BLOCKED_OUTPUT",
    "VALIDATION_FAILED",
    "BACKEND_AUTH",
    "BACKEND_RETRYABLE_EXHAUSTED",
)


def max_requeues_per_unit(config: dict | None, *, default: int = DEFAULT_MAX_REQUEUES) -> int:
    """The durable allowance, from the analyst budgets block. Fail-closed."""
    budgets = (config or {}).get("budgets") or {}
    value = budgets.get("max_requeues_per_unit")
    if value is None:
        return int(default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise PalError(
            "VALIDATION_FAILED",
            f"budgets.max_requeues_per_unit must be a non-negative integer, got {value!r}",
        )
    return int(value)


def material_identity(home: Path | str, *, config: dict | None = None) -> dict:
    """What has to CHANGE for another attempt to be worth paying for.

    The config digest is the *same* identity the AUTH latch is pinned to, so
    "the material changed" means one thing in this protocol: the analyst
    configuration (endpoint, model, key, budgets) or the credential verdict
    moved. Requeuing under an unchanged digest is refused -- that is not a
    retry policy, it is a spin.
    """
    from . import budgets as budgets_mod

    backend = (config or {}).get("backend") or {}
    return {
        "config_digest": budgets_mod._config_digest(home),
        "backend_type": str(backend.get("type") or ""),
        "model": str(backend.get("model") or ""),
    }


def _excerpt(value: object, limit: int = 240) -> str | None:
    if value in (None, ""):
        return None
    text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def _jobs(journal: dict) -> list[dict]:
    return [
        job
        for _job_id, job in sorted((journal.get("jobs") or {}).items())
        if isinstance(job, dict)
    ]


def _indexed_sessions(home: Path | str, registry: dict) -> set[str] | None:
    """The sessions a requeued job could still be served from. None if unknown."""
    from saipal_engine import carrier as carrier_mod
    from saipal_engine import sessions as sessions_mod

    status, index, _detail = sessions_mod.load_index(home, registry=registry)
    if status == sessions_mod.STATUS_UNRECOVERABLE or index is None:
        return None
    return {
        str(record.get("session_id") or "")
        for record in carrier_mod.freshest_records(index)
    }


def _decide(
    job: dict,
    material: dict,
    max_requeues: int,
    force: bool,
) -> tuple[str, str]:
    """`(verdict, detail)` for one job: requeued | refused | not_applicable."""
    stage = str(job.get("stage") or "")
    if stage != REQUEUE_STAGE:
        other = OTHER_STAGES.get(stage)
        if other is not None:
            return "refused", other["reason"]
        return "not_applicable", f"stage {stage or 'unknown'} is not a semantic refusal"
    history = job.get("requeues") or []
    if len(history) >= max_requeues and not force:
        return "refused", (
            f"the requeue budget ({max_requeues}) for this unit is spent; "
            "another attempt needs --force"
        )
    if history and not force and (history[-1].get("material") or {}) == material:
        return "refused", (
            "no material change since the last requeue: the same analyst "
            "config already produced this refusal, so the same call would be "
            "paid for again"
        )
    return "requeued", "semantic refusal requeued for one fresh attempt"


def _apply(
    journal: dict,
    job: dict,
    *,
    material: dict,
    reason: str | None,
    detail: str,
    forced: bool,
    at: str,
) -> dict:
    """Clear the refused attempt and re-open the unit. In memory; caller saves."""
    history = list(job.get("requeues") or [])
    entry = {
        "at": at,
        "from_stage": str(job.get("stage")),
        "error_class": job.get("error_class"),
        "error_detail": _excerpt(job.get("error_detail")),
        # `--reason` is the operator's own note and is optional; the history
        # entry is never reasonless, so an unannotated requeue records the
        # canonical decision that admitted it (jobs._requeue_problems).
        "reason": str(reason).strip() if reason and reason.strip() else detail,
        "forced": bool(forced),
        "material": dict(material),
        "attempts": int(job.get("attempts") or 0),
        "transport_attempts": int(job.get("transport_attempts") or 0),
        "cleared_digests": {
            field: job.get(field)
            for field in (
                "response_digest",
                "candidate_digest",
                "critic_digest",
                "finalizer_digest",
            )
        },
    }
    history.append(entry)
    job["requeues"] = history[-MAX_HISTORY:]
    for field in CLEARED_FIELDS:
        job[field] = None
    for field, empty in RESET_FIELDS.items():
        job[field] = dict(empty) if isinstance(empty, dict) else list(empty)
    for counter in CLEARED_COUNTERS:
        job[counter] = 0
    job["error_class"] = None
    job["error_detail"] = None
    job["next_retry_at"] = None
    # The journal names who is expected to answer the fresh attempt.
    job["backend_type"] = str(material.get("backend_type") or job.get("backend_type") or "")
    job["model"] = str(material.get("model") or job.get("model") or "")
    jobs_mod.advance(journal, job, jobs_mod.READY)
    job["updated_at"] = at
    return entry


def _load_config(root: Path) -> tuple[str, dict | None]:
    from .config import load_analyst_config

    status, config, _detail = load_analyst_config(root)
    return status, config if isinstance(config, dict) else None


def _plan(
    journal: dict,
    *,
    indexed: set[str] | None,
    material: dict,
    max_requeues: int,
    wanted: tuple[str, ...] | None,
    limit: int | None,
    reason: str | None,
    force: bool,
    at: str,
    apply: bool,
) -> dict:
    """One deterministic pass over the journal. Mutates only when `apply`."""
    report: dict = {
        "scanned": 0,
        "eligible": 0,
        "requeued": [],
        "refused": [],
        "not_applicable": {},
        "by_class": {},
        "remaining": 0,
        "history": [],
    }
    for job in _jobs(journal):
        report["scanned"] += 1
        stage = str(job.get("stage") or "")
        if stage != REQUEUE_STAGE:
            verdict, detail = _decide(job, material, max_requeues, force)
            if verdict == "refused":
                report["refused"].append(_refusal(job, detail, stage))
            else:
                key = stage or "unknown"
                report["not_applicable"][key] = report["not_applicable"].get(key, 0) + 1
            continue
        error_class = str(job.get("error_class") or "UNCLASSIFIED")
        if wanted is not None and error_class not in wanted:
            key = f"class:{error_class}"
            report["not_applicable"][key] = report["not_applicable"].get(key, 0) + 1
            continue
        report["eligible"] += 1
        report["by_class"][error_class] = report["by_class"].get(error_class, 0) + 1
        if indexed is not None and str(job.get("session_id") or "") not in indexed:
            report["refused"].append(
                _refusal(
                    job,
                    "the session is not in the current index, so a requeued job "
                    "could never be served",
                    stage,
                )
            )
            continue
        verdict, detail = _decide(job, material, max_requeues, force)
        if verdict == "refused":
            report["refused"].append(_refusal(job, detail, stage))
            continue
        if limit is not None and len(report["requeued"]) >= int(limit):
            report["remaining"] += 1
            continue
        if not apply:
            report["requeued"].append(
                {
                    "job_id": str(job.get("job_id")),
                    "session_id": str(job.get("session_id")),
                    "error_class": error_class,
                    "requeues_spent": len(job.get("requeues") or []),
                    "reason": detail,
                }
            )
            continue
        entry = _apply(
            journal, job, material=material, reason=reason, detail=detail, forced=force, at=at
        )
        report["requeued"].append(
            {
                "job_id": str(job.get("job_id")),
                "session_id": str(job.get("session_id")),
                "error_class": error_class,
                "requeues_spent": len(job.get("requeues") or []),
                "reason": detail,
            }
        )
        report["history"].append(entry)
    return report


def requeue(
    home: Path | str,
    *,
    registry: dict | None = None,
    config: dict | None = None,
    job_classes: tuple[str, ...] | list[str] | None = None,
    limit: int | None = None,
    reason: str | None = None,
    force: bool = False,
    dry_run: bool = False,
) -> dict:
    """One recorded pass over the analyst journal. Bounded, serialized, honest.

    Serialized by the SAME `AnalystWorkerLock` the worker takes, so a requeue
    can never race a live run: the journal is read AND written under the lock.
    A live worker is a refusal (`WRITER_BUSY`), never a queue. The dry run
    takes no lock and writes nothing -- a diagnostic that materializes a lock
    node is not a diagnostic.
    """
    data = registry if registry is not None else load_registry()
    root = Path(home)
    if config is None:
        status, loaded = _load_config(root)
        if status != "ok" or loaded is None:
            raise PalError(
                "VALIDATION_FAILED",
                f"analyst config is unusable ({status})",
                next_action="python -B tools/saipal.py analyst-setup",
            )
        config = loaded

    # No filter means EVERY refused unit: the default must not be an allow-list
    # that silently drops a class the protocol has not met before.
    wanted = tuple(job_classes) if job_classes else None
    max_requeues = max_requeues_per_unit(config)
    material = material_identity(root, config=config)
    indexed = _indexed_sessions(root, data)
    at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    base: dict = {
        "requeue": True,
        "dry_run": bool(dry_run),
        "wrote": False,
        "material": dict(material),
        "max_requeues_per_unit": max_requeues,
        "classes": list(wanted) if wanted is not None else ["*"],
        "index_available": indexed is not None,
    }

    if dry_run:
        journal = jobs_mod.load_journal(root)
        # A dry run must not materialize the worker lock (a diagnostic that
        # creates a node is not a diagnostic); it also cannot race, because it
        # writes nothing.
        plan = _plan(
            journal,
            indexed=indexed,
            material=material,
            max_requeues=max_requeues,
            wanted=wanted,
            limit=limit,
            reason=reason,
            force=force,
            at=at,
            apply=False,
        )
        return _finish(base, plan)

    lock = jobs_mod.AnalystWorkerLock(root)
    if not lock.acquire():
        raise PalError("WRITER_BUSY", lock.detail)
    try:
        journal = jobs_mod.load_journal(root)
        plan = _plan(
            journal,
            indexed=indexed,
            material=material,
            max_requeues=max_requeues,
            wanted=wanted,
            limit=limit,
            reason=reason,
            force=force,
            at=at,
            apply=True,
        )
        if plan["requeued"]:
            jobs_mod.save_journal(root, journal)
            base["wrote"] = True
    finally:
        lock.release()
    return _finish(base, plan)


def _finish(base: dict, plan: dict) -> dict:
    report = dict(base)
    report.update(plan)
    report["ok"] = not plan["refused"]
    report["counts"] = {
        "requeued": len(plan["requeued"]),
        "refused": len(plan["refused"]),
        "not_applicable": sum(plan["not_applicable"].values()),
        "remaining": plan["remaining"],
    }
    return report


def _refusal(job: dict, detail: str, stage: str) -> dict:
    row = {
        "job_id": str(job.get("job_id")),
        "session_id": str(job.get("session_id")),
        "stage": stage,
        "error_class": job.get("error_class"),
        "reason": detail,
        "requeues_spent": len(job.get("requeues") or []),
    }
    other = OTHER_STAGES.get(stage)
    if other is not None:
        row["next_action"] = other["next_action"]
    return row


def requeue_status(
    home: Path | str,
    *,
    registry: dict | None = None,
    journal: dict | None = None,
) -> dict:
    """READ-ONLY view of what a requeue would do. Writes nothing, no network.

    `analyst-doctor` reads this so the operator is told the cheapest canonical
    step per refused unit instead of a bare count. An invalid budget is a LOUD
    refusal, never a silently substituted default.
    """
    root = Path(home)
    data = registry if registry is not None else load_registry()
    if journal is None:
        journal = jobs_mod.load_journal(root)
    status, config = _load_config(root)
    config_ok = status == "ok" and config is not None
    max_requeues = max_requeues_per_unit(config)
    material = material_identity(root, config=config) if config_ok else {}
    ready = 0
    refused = 0
    by_class: dict[str, int] = {}
    for job in _jobs(journal):
        if str(job.get("stage") or "") != REQUEUE_STAGE:
            continue
        # Every refused class is eligible by default: the count the triage
        # publishes must be the whole refused population, by class.
        error_class = str(job.get("error_class") or "UNCLASSIFIED")
        by_class[error_class] = by_class.get(error_class, 0) + 1
        verdict, _detail = _decide(job, material, max_requeues, False)
        if verdict == "requeued":
            ready += 1
        else:
            refused += 1
    return {
        "command": "analyst-requeue",
        "read_only": True,
        "material": material,
        "max_requeues_per_unit": max_requeues,
        "blocked_by_class": dict(sorted(by_class.items(), key=lambda item: (-item[1], item[0]))),
        "requeue_ready": ready,
        "requeue_refused": refused,
        "command_line": "python -B tools/saipal.py analyst-requeue --dry-run",
    }


__all__ = [
    "BLOCKED_CLASSES",
    "CLEARED_COUNTERS",
    "CLEARED_FIELDS",
    "DEFAULT_MAX_REQUEUES",
    "OTHER_STAGES",
    "RESET_FIELDS",
    "material_identity",
    "max_requeues_per_unit",
    "requeue",
    "requeue_status",
]
