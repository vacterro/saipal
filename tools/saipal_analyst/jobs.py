"""Durable analyst job journal: `.saipal/analyst/jobs.json`.

One job per semantic unit. The journal is the worker's crash memory: a job
records where it died, what was already persisted (a raw model response, a
validated candidate), how many attempts are spent, and which receipt (if any)
closed it. It never duplicates session evidence -- the transcript lives in the
canonical home; the journal only carries digests plus the small model outputs
needed to avoid paying for the same reasoning twice.

Every write is atomic and root-confined. A journal that fails validation is a
refusal, never a silent reset.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from saipal_engine.errors import PalError
from saipal_engine.paths import FencedLockFile, atomic_write_json, home_paths, read_json

JOURNAL_SCHEMA_VERSION = 2
JOURNAL_NAME = "jobs.json"
ANALYST_DIRNAME = "analyst"

READY = "READY"
INVESTIGATOR_CALLING = "INVESTIGATOR_CALLING"
INVESTIGATOR_RESPONSE = "INVESTIGATOR_RESPONSE"
CANDIDATE_READY = "CANDIDATE_READY"
CRITIC_CALLING = "CRITIC_CALLING"
CRITIC_READY = "CRITIC_READY"
FINALIZER_CALLING = "FINALIZER_CALLING"
FINAL_READY = "FINAL_READY"
SUBMITTING = "SUBMITTING"
DONE = "DONE"
RETRY_WAIT = "RETRY_WAIT"
BLOCKED = "BLOCKED"
BLOCKED_BINDING = "BLOCKED_BINDING"
STALE = "STALE"
#: W2-005: a CALLING stage that may or may not have already billed a paid
#: remote call. The transport request left the process but no response was
#: persisted, so a restart cannot know whether the provider received billed
#: work. The job sits here instead of silently re-issuing the same paid call.
REMOTE_OUTCOME_UNKNOWN = "REMOTE_OUTCOME_UNKNOWN"

STATES = (
    READY,
    INVESTIGATOR_CALLING,
    INVESTIGATOR_RESPONSE,
    CANDIDATE_READY,
    CRITIC_CALLING,
    CRITIC_READY,
    FINALIZER_CALLING,
    FINAL_READY,
    SUBMITTING,
    DONE,
    RETRY_WAIT,
    BLOCKED,
    BLOCKED_BINDING,
    STALE,
    REMOTE_OUTCOME_UNKNOWN,
)

#: Where each state may go. An illegal transition is a programming error and is
#: refused instead of written -- a journal that lies about how it got somewhere
#: is worse than no journal.
TRANSITIONS: dict[str, tuple[str, ...]] = {
    READY: (INVESTIGATOR_CALLING, BLOCKED_BINDING, BLOCKED, STALE),
    INVESTIGATOR_CALLING: (INVESTIGATOR_RESPONSE, RETRY_WAIT, BLOCKED, STALE),
    INVESTIGATOR_RESPONSE: (CANDIDATE_READY, RETRY_WAIT, BLOCKED, STALE),
    CANDIDATE_READY: (CRITIC_CALLING, FINAL_READY, STALE),
    CRITIC_CALLING: (CRITIC_READY, RETRY_WAIT, BLOCKED, STALE),
    CRITIC_READY: (FINALIZER_CALLING, FINAL_READY, RETRY_WAIT, BLOCKED, STALE),
    FINALIZER_CALLING: (FINAL_READY, RETRY_WAIT, BLOCKED, STALE),
    FINAL_READY: (SUBMITTING, RETRY_WAIT, BLOCKED, STALE),
    SUBMITTING: (DONE, BLOCKED, STALE),
    RETRY_WAIT: (READY, INVESTIGATOR_RESPONSE, CANDIDATE_READY, CRITIC_READY, FINAL_READY, STALE),
    BLOCKED: (READY, STALE),
    BLOCKED_BINDING: (READY, INVESTIGATOR_RESPONSE, CANDIDATE_READY, CRITIC_READY, FINAL_READY, STALE),
    STALE: (),
    DONE: (),
    # W2-005: the ambiguous paid-call state is resolvable only by an explicit
    # operator/configured retry policy (one counted re-attempt) or terminal
    # refusal -- never by pretending the prior attempt did not happen.
    REMOTE_OUTCOME_UNKNOWN: (INVESTIGATOR_CALLING, CRITIC_CALLING, FINALIZER_CALLING, BLOCKED, STALE),
}

JOB_FIELDS = (
    "job_id",
    "session_id",
    "episode_index",
    "slice_index",
    "unit_digest",
    "finality",
    "stage",
    "attempts",
    "transport_attempts",
    "submit_attempts",
    "repairs",
    "investigator_repairs",
    "critic_repairs",
    "finalizer_repairs",
    "backend_type",
    "model",
    "created_at",
    "updated_at",
    "run_id",
    # W2-005: durable paid-attempt identity, persisted BEFORE transport so a
    # crash can never lose which attempt is ambiguous. Role-scoped: the
    # investigator, critic, finalizer (and repair) attempts each carry their
    # own deterministic id and are counted separately below.
    "attempt_ids",
    "ambiguous_attempt_ids",
    "response_digest",
    "response_text",
    "investigator_repair_text",
    "critic_digest",
    "critic_payload",
    "critic_response_text",
    "critic_repair_text",
    "finalizer_digest",
    "finalizer_response_text",
    "finalizer_repair_text",
    "candidate_digest",
    "candidate",
    "receipt_id",
    "error_class",
    "error_detail",
    "next_retry_at",
    "verdict",
)

TERMINAL_STAGES = (DONE, BLOCKED, BLOCKED_BINDING, STALE)

#: Back-compat aliases — old journal/tests use CALLING; new name is investigator-side.
CALLING = INVESTIGATOR_CALLING


def journal_dir(home: Path | str) -> Path:
    return home_paths(home).root / ANALYST_DIRNAME


def journal_path(home: Path | str) -> Path:
    return journal_dir(home) / JOURNAL_NAME


def worker_lock_path(home: Path | str) -> Path:
    return home_paths(home).locks / "analyst-worker.lock"


def unit_job_id(
    session_id: str, episode_index: int, slice_index: int, unit_digest: str
) -> str:
    """Deterministic job identity: the same unit is always the same job."""
    identity = f"{session_id}|{int(episode_index)}|{int(slice_index)}|{unit_digest}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]


def fresh_journal() -> dict:
    return {
        "schema_version": JOURNAL_SCHEMA_VERSION,
        "updated_at": _now(),
        "jobs": {},
    }


def load_journal(home: Path | str) -> dict:
    """Read the journal, validating shape. Absent means empty, never guessed."""
    path = journal_path(home)
    if not path.exists():
        return fresh_journal()
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise PalError(
            "VALIDATION_FAILED",
            f"analyst journal is unreadable: {exc}",
            next_action="repair or remove .saipal/analyst/jobs.json by hand",
        ) from None
    if payload.get("schema_version") == 1:
        # Legacy journals upgrade in memory; the next canonical save persists v2.
        payload = migrate_journal(payload)
    problems = journal_problems(payload)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "analyst journal is invalid: " + "; ".join(problems[:5]),
            next_action="repair or remove .saipal/analyst/jobs.json by hand",
        )
    return payload


def migrate_journal(payload: dict) -> dict:
    """v1 -> v2, deterministic and idempotent. Refuses to guess.

    v1 worker only ever wrote READY/CANDIDATE_READY/SUBMITTING/DONE/RETRY_WAIT/
    BLOCKED/BLOCKED_BINDING/STALE plus CALLING-without-response; the mapping
    uses the persisted artifacts, so a v1 CALLING job resumes exactly where the
    recorded evidence ends. `attempts` in v1 counted submit failures only, so
    it migrates to `submit_attempts`; transport attempts restart at zero.
    """
    if not isinstance(payload, dict):
        raise PalError("VALIDATION_FAILED", "analyst journal is not an object")
    version = payload.get("schema_version")
    if version == JOURNAL_SCHEMA_VERSION:
        return payload
    if version != 1:
        raise PalError(
            "VALIDATION_FAILED",
            f"analyst journal schema_version {version!r} has no migration path",
        )
    jobs = payload.get("jobs")
    if not isinstance(jobs, dict):
        raise PalError("VALIDATION_FAILED", "analyst journal jobs must be an object")
    migrated: dict[str, dict] = {}
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            raise PalError(
                "VALIDATION_FAILED", f"analyst job {job_id} is not an object"
            )
        stage = job.get("stage")
        mapped = dict(job)
        if stage == CALLING:
            mapped["stage"] = (
                INVESTIGATOR_RESPONSE if job.get("response_text") else INVESTIGATOR_CALLING
            )
        elif stage not in STATES:
            raise PalError(
                "VALIDATION_FAILED",
                f"analyst job {job_id} stage {stage!r} has no migration path",
            )
        mapped["transport_attempts"] = 0
        mapped["submit_attempts"] = int(job.get("attempts") or 0)
        migrated[job_id] = mapped
    return {
        "schema_version": JOURNAL_SCHEMA_VERSION,
        "updated_at": payload.get("updated_at") or _now(),
        "jobs": migrated,
    }


def save_journal(home: Path | str, journal: dict) -> Path:
    problems = journal_problems(journal)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "refusing to save invalid analyst journal: " + "; ".join(problems[:5]),
        )
    journal["updated_at"] = _now()
    return atomic_write_json(
        journal_path(home), journal, root=home_paths(home).root
    )


def journal_problems(payload: object) -> list[str]:
    if not isinstance(payload, dict):
        return ["journal root is not an object"]
    if payload.get("schema_version") != JOURNAL_SCHEMA_VERSION:
        return [f"schema_version must be {JOURNAL_SCHEMA_VERSION}"]
    for key in sorted(set(payload) - {"schema_version", "updated_at", "jobs"}):
        return [f"unknown journal field {key!r}"]
    jobs = payload.get("jobs")
    if not isinstance(jobs, dict):
        return ["jobs must be an object"]
    problems: list[str] = []
    for job_id, job in sorted(jobs.items()):
        if not isinstance(job, dict):
            problems.append(f"job {job_id} is not an object")
            continue
        if job.get("job_id") != job_id:
            problems.append(f"job {job_id} disagrees with its own id")
            continue
        problems.extend(_job_problems(job))
    return problems


def _job_problems(job: dict) -> list[str]:
    problems: list[str] = []
    for key in sorted(set(job) - set(JOB_FIELDS)):
        problems.append(f"job {job.get('job_id')!r} has unknown field {key!r}")
    stage = job.get("stage")
    if stage not in STATES:
        problems.append(f"job {job.get('job_id')!r} stage {stage!r} outside the state set")
    for key in ("session_id", "unit_digest"):
        if not isinstance(job.get(key), str) or not job.get(key):
            problems.append(f"job {job.get('job_id')!r} missing {key}")
    for key in ("episode_index", "slice_index"):
        value = job.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            problems.append(f"job {job.get('job_id')!r} {key} must be a non-negative integer")
    for key in ("attempts", "repairs", "transport_attempts", "submit_attempts",
                "investigator_repairs", "critic_repairs", "finalizer_repairs"):
        value = job.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            problems.append(f"job {job.get('job_id')!r} {key} must be a non-negative integer")
    return problems


def new_job(
    *,
    session_id: str,
    episode_index: int,
    slice_index: int,
    unit_digest: str,
    finality: str,
    backend_type: str,
    model: str,
    run_id: str,
) -> dict:
    now = _now()
    return {
        "job_id": unit_job_id(session_id, episode_index, slice_index, unit_digest),
        "session_id": session_id,
        "episode_index": int(episode_index),
        "slice_index": int(slice_index),
        "unit_digest": unit_digest,
        "finality": finality,
        "stage": READY,
        "attempts": 0,
        "transport_attempts": 0,
        "submit_attempts": 0,
        "repairs": 0,
        "investigator_repairs": 0,
        "critic_repairs": 0,
        "finalizer_repairs": 0,
        "backend_type": backend_type,
        "model": model,
        "created_at": now,
        "updated_at": now,
        "run_id": run_id,
        "attempt_ids": {},
        "ambiguous_attempt_ids": [],
        "response_digest": None,
        "response_text": None,
        "investigator_repair_text": None,
        "critic_digest": None,
        "critic_payload": None,
        "critic_response_text": None,
        "critic_repair_text": None,
        "finalizer_digest": None,
        "finalizer_response_text": None,
        "finalizer_repair_text": None,
        "candidate_digest": None,
        "candidate": None,
        "receipt_id": None,
        "error_class": None,
        "error_detail": None,
        "next_retry_at": None,
        "verdict": None,
    }


def advance(journal: dict, job: dict, to_state: str) -> None:
    """Move one job to a legal next state, in memory. Persist is the caller's.

    A same-state re-entry is a no-op (a restart re-derives `call` for a job
    already INVESTIGATOR_CALLING); it updates nothing but is not illegal.
    """
    if job.get("stage") == to_state:
        return
    if to_state not in TRANSITIONS.get(job.get("stage"), ()):
        raise PalError(
            "VALIDATION_FAILED",
            (
                f"illegal job transition {job.get('stage')!r} -> {to_state!r} "
                f"for {job.get('job_id')}"
            ),
        )
    job["stage"] = to_state
    job["updated_at"] = _now()


def upsert(journal: dict, job: dict) -> None:
    journal.setdefault("jobs", {})[job["job_id"]] = job


def find_job(journal: dict, job_id: str) -> dict | None:
    return (journal.get("jobs") or {}).get(job_id)


def next_attempt_id(job: dict, role: str, payload_digest: str) -> str:
    """W2-005: the deterministic paid-attempt identity for one role call.

    Derived from the job id, the role, the request payload digest and the
    attempt ordinal, so a restart that re-derives the same call computes the
    same id. Backends with a caller-supplied idempotency contract reuse this
    value after a crash; ambiguity accounting (below) records it durably
    BEFORE transport leaves the process.
    """
    ids = job.setdefault("attempt_ids", {})
    ordinal = int(job.get("transport_attempts") or 0) + 1
    identity = f"{job.get('job_id')}|{role}|{ordinal}|{payload_digest}"
    attempt_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
    ids[role] = attempt_id
    return attempt_id


def mark_ambiguous_attempt(job: dict, role: str, attempt_id: str) -> None:
    """Record that this paid attempt left the process with no known outcome.

    Called BEFORE transport; if the process dies before persist_raw writes
    the response, the journal already names the possibly-billed attempt and
    the restart path reports ambiguity instead of silently re-paying.
    """
    job.setdefault("ambiguous_attempt_ids", [])
    pair = {"role": role, "attempt_id": attempt_id}
    if pair not in job["ambiguous_attempt_ids"]:
        job["ambiguous_attempt_ids"].append(pair)
    job["error_class"] = "REMOTE_OUTCOME_POSSIBLE"
    job["error_detail"] = (
        f"a paid {role} attempt may have reached the provider before the "
        "process died; outcome unknown"
    )


def resume_stage(job: dict) -> str:
    """The exact deliberation stage persisted artifacts prove, no guessing.

    The durable finalizer artifact outranks the critic payload, which outranks
    the validated candidate, which outranks the raw investigator response. A
    RETRY_WAIT (or a reactivated BLOCKED_BINDING job) resumes at the stage its
    evidence ends at: paid semantic work is never repeated. A stage with only
    a candidate re-enters at CANDIDATE_READY so the critic policy is evaluated
    by the same code fresh execution uses.
    """
    if job.get("candidate"):
        if job.get("finalizer_digest"):
            return FINAL_READY
        if job.get("critic_payload"):
            return CRITIC_READY
        return CANDIDATE_READY
    if job.get("response_text"):
        return INVESTIGATOR_RESPONSE
    if job.get("stage") == REMOTE_OUTCOME_UNKNOWN:
        return REMOTE_OUTCOME_UNKNOWN
    return READY


def next_action(job: dict) -> str:
    """What a restarted worker must do with this job. No guessing.

    INVESTIGATOR_CALLING with a persisted response means the crash happened
    between the response write and validation: the response is reused, the
    model is not called again. CANDIDATE_READY means a validated investigator
    candidate awaits the critic decision. CRITIC_READY means the critic has
    spoken and the disagreement (if any) must be resolved without re-paying
    the critic. FINAL_READY/SUBMITTING mean a final candidate is waiting for
    submit; SUBMITTING resubmits the exact same candidate and the kernel's
    receipt idempotency converges.
    """
    stage = job.get("stage")
    if stage in TERMINAL_STAGES:
        return "skip"
    if stage == REMOTE_OUTCOME_UNKNOWN:
        return "ambiguous"
    if stage == READY:
        return "call"
    if stage == INVESTIGATOR_CALLING:
        if not job.get("response_text"):
            return "ambiguous" if job.get("attempt_ids", {}).get("investigator") else "call"
        return "validate"
    if stage == INVESTIGATOR_RESPONSE:
        return "validate"
    if stage == CANDIDATE_READY:
        return "critic"
    if stage == CRITIC_CALLING:
        # Always re-enter the critic handler: it skips the transport call when
        # the raw response is already persisted and parses it from the journal.
        return "ambiguous" if not job.get("critic_response_text") and job.get("attempt_ids", {}).get("critic") else "critic"
    if stage in (CRITIC_READY, FINALIZER_CALLING):
        if stage == FINALIZER_CALLING and not job.get("finalizer_response_text") and job.get("attempt_ids", {}).get("finalizer"):
            return "ambiguous"
        return "finalize"
    if stage in (FINAL_READY, SUBMITTING):
        return "submit"
    if stage == RETRY_WAIT:
        return "retry" if _retry_due(job) else "wait"
    return "skip"


def _retry_due(job: dict, *, now: float | None = None) -> bool:
    raw = job.get("next_retry_at")
    if raw is None:
        return True
    try:
        due = float(raw)
    except (TypeError, ValueError):
        return True
    return due <= (time.time() if now is None else now)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class AnalystWorkerLock:
    """One analyst worker per home, with kernel-grade fencing.

    Reuses `FencedLockFile` (W2-001): owner token, PID-alive stale recovery,
    rename-fenced takeover, ownership-fenced release. A second worker refuses
    with WRITER_BUSY instead of racing the first.
    """

    BUSY = "another analyst worker holds this home"

    def __init__(self, home: Path | str, *, ttl: float = 900.0):
        self._lock = FencedLockFile(
            worker_lock_path(home), ttl=ttl, busy_detail=self.BUSY
        )

    @property
    def held(self) -> bool:
        return self._lock.held

    @property
    def detail(self) -> str:
        return self._lock.detail

    @property
    def stale_taken_over(self) -> bool:
        return self._lock.stale_taken_over

    def acquire(self) -> bool:
        return self._lock.acquire()

    def release(self) -> None:
        self._lock.release()

    def __enter__(self) -> "AnalystWorkerLock":
        if not self.acquire():
            raise PalError("WRITER_BUSY", self.detail)
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.release()
        return False
