"""CPALL -- the durable autonomous convergence objective.

`/goal cpall` is not a longer `continue`. It is a *persistent objective* that
chains bounded, individually safe slices until SAIPAL reaches a truthful
terminal state. The distinction is load-bearing:

- the process is disposable, the objective is durable;
- a budget is a checkpoint boundary, never a goal terminator;
- a `CONFLICT` isolates one work item, it does not stop the universe;
- a restart, a context exhaustion, a crash or a backend outage becomes a
  durable recovery state, never a silent "done".

The supervisor here owns orchestration only. It decides *when* the next
bounded slice runs, what the durable state is, and whether the objective may
end. Mechanical and semantic work stay owned by their existing boundaries --
`continue`'s cycle and the analyst `investigate` loop -- and are injected as
`mechanical_slice` / `semantic_slice` callables, so this module can never grow
a second intake pipeline or a second semantic engine.

Durability model
----------------

One objective, at ``.saipal/cpall.json``, is the only source of truth. Chat
history, model context and the life of any process are irrelevant to it: a
fresh process reconstructs everything by loading the objective, the session
index and the receipts.

Execution semantics are at-least-once at the slice boundary and effectively
exactly-once at the accepted-result boundary: a crash between a slice's
accepted submission and its checkpoint re-runs the slice from the last durable
cursor, and the underlying submission/receipt identity makes the replay
idempotent. The cursor is therefore advanced *after* the slice reports, and the
objective is persisted before the next slice starts.

States
------

``ACTIVE``           work remains and progress is being made;
``WAITING``          useful work remains behind a future recoverable condition
                     (backend down, rate limit, retry delay, foreign lock);
``OPERATOR_BLOCKED`` only a human decision can unblock the remaining work;
``COMPLETED``        nothing eligible, ownable or scheduled remains;
``SAFETY_STOP``      a real invariant was violated; recovery path persisted;
``CANCELLED``        the operator explicitly stopped the objective.

Only ``COMPLETED``, ``SAFETY_STOP`` and ``CANCELLED`` are terminal. Everything
else is resumable, and ``WAITING`` in particular must never degrade into
"done" -- it is a promise to try again.
"""

from __future__ import annotations

import calendar
import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from . import carrier as carrier_mod
from . import coverage as coverage_mod
from . import publications as pub_mod
from . import sessions as sessions_mod
from .capability import require_action
from .errors import PalError
from .paths import (
    atomic_write_json,
    confined_append_line,
    home_paths,
    read_json,
    sha256_text,
    utc_now_iso,
)
from .registry import load_registry, require_mapping

CPALL_SCHEMA_VERSION = 1
CPALL_NAME = "cpall.json"
CPALL_REPORTS_NAME = "cpall_reports.jsonl"

STATE_ACTIVE = "ACTIVE"
STATE_WAITING = "WAITING"
STATE_OPERATOR_BLOCKED = "OPERATOR_BLOCKED"
STATE_COMPLETED = "COMPLETED"
STATE_SAFETY_STOP = "SAFETY_STOP"
STATE_CANCELLED = "CANCELLED"

CPALL_STATES: tuple[str, ...] = (
    STATE_ACTIVE,
    STATE_WAITING,
    STATE_OPERATOR_BLOCKED,
    STATE_COMPLETED,
    STATE_SAFETY_STOP,
    STATE_CANCELLED,
)
RESUMABLE_STATES: tuple[str, ...] = (STATE_ACTIVE, STATE_WAITING)
TERMINAL_STATES: tuple[str, ...] = (STATE_COMPLETED, STATE_SAFETY_STOP, STATE_CANCELLED)

#: Report kinds. `REPORT_START` and `REPORT_FINAL` bracket an objective's life;
#: everything else may repeat.
REPORT_START = "START"
REPORT_PROGRESS = "PROGRESS"
REPORT_STATE_CHANGE = "STATE_CHANGE"
REPORT_BLOCKED = "BLOCKED"
REPORT_RECOVERY = "RECOVERY"
REPORT_FINAL = "FINAL"

#: Work families. Independent families are what keep one blocked item from
#: freezing everything: a family is only "blocked" for itself.
FAMILY_MECHANICAL = "mechanical"
FAMILY_SEMANTIC = "semantic"
FAMILIES: tuple[str, ...] = (FAMILY_MECHANICAL, FAMILY_SEMANTIC)

#: Per-family dispositions inside the objective (not the top-level state).
FAMILY_ACTIVE = "ACTIVE"
FAMILY_DONE = "DONE"
FAMILY_WAITING = "WAITING"
FAMILY_BLOCKED = "BLOCKED"

#: The only slice stop reasons that mean an operator has to touch the ANALYST
#: RUNTIME, each mapped to the route that actually clears it. The blocked
#: reasons are deliberately absent: a binding or output wall is fixed by
#: authority or by re-running a unit, and naming the runtime there repeats an
#: advice the operator already acted on.
_RUNTIME_OFF_ROUTES = {
    "CONFIG_DISABLED": "enable the analyst runtime",
    "CONFIGURATION_BLOCKED": "fix the analyst configuration",
}

#: Failure classes the retry scheduler reasons about.
FAILURE_NONE = "NONE"
FAILURE_TRANSIENT = "TRANSIENT"
FAILURE_RATE_LIMIT = "RATE_LIMIT"
FAILURE_CONFIGURATION = "CONFIGURATION"
FAILURE_PERMANENT = "PERMANENT"
FAILURE_UNSAFE = "UNSAFE"

TRANSIENT_CLASSES = (FAILURE_TRANSIENT, FAILURE_RATE_LIMIT)

DEFAULT_SETTINGS: dict[str, Any] = {
    "report_cadence_seconds": 1800.0,
    "min_report_interval_seconds": 5.0,
    "max_slices_per_process": 0,
    "max_units_per_slice": 25,
    "owner_ttl_seconds": 3600.0,
    "stale_owner_grace_seconds": 60.0,
    "retry_base_seconds": 30.0,
    "retry_max_seconds": 1800.0,
    "retry_probe_after_seconds": 900.0,
    "report_history_limit": 24,
    "sleep_chunk_seconds": 15.0,
    "rescan_every_slices": 10,
}


# --------------------------------------------------------------------------- #
# clock
# --------------------------------------------------------------------------- #


class Clock:
    """Wall clock plus sleep, injectable so tests never wait real hours.

    Every timing decision in this module goes through `now()` and `sleep()`,
    which is what makes "7 simulated days", "backend down for three simulated
    hours" and "report cadence survives a restart" testable deterministically.
    """

    def __init__(
        self, *, now: Callable[[], float] | None = None, sleep: Callable[[float], None] | None = None
    ) -> None:
        self.now_fn = now if now is not None else time.time
        self.sleep_fn = sleep if sleep is not None else time.sleep
        self.slept = 0.0

    def now(self) -> float:
        return float(self.now_fn())

    def sleep(self, seconds: float) -> None:
        seconds = max(0.0, float(seconds))
        self.slept += seconds
        self.sleep_fn(seconds)


def _as_clock(clock: object, sleep_fn: Callable[[float], None] | None) -> Clock:
    """Accept a Clock, a `now()`-bearing object, or nothing.

    An injected clock's OWN `sleep` is honoured. Substituting `time.sleep` for a
    virtual clock that has one turns every simulated wait into a real one, which
    is how a test of "the backend was down for three hours" becomes a three-hour
    test -- or, in production, how a caller-supplied clock silently stops being
    the schedule.
    """
    if isinstance(clock, Clock):
        return Clock(
            now=clock.now_fn,
            sleep=sleep_fn if sleep_fn is not None else clock.sleep_fn,
        )
    if clock is not None and hasattr(clock, "now"):
        inner = clock
        own_sleep = getattr(inner, "sleep", None)
        chosen = sleep_fn if sleep_fn is not None else own_sleep
        if not callable(chosen):
            chosen = None

        def _now() -> float:
            return float(inner.now())  # type: ignore[attr-defined]

        return Clock(now=_now, sleep=chosen)
    if callable(clock):
        return Clock(now=clock, sleep=sleep_fn)
    return Clock(sleep=sleep_fn)


def _iso(seconds: float | None) -> str | None:
    if seconds is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(seconds)))


def _epoch(value: object) -> float | None:
    """Parse a persisted UTC timestamp back to an epoch second.

    `calendar.timegm`, never `time.mktime`: `_iso` writes UTC, and `mktime`
    interprets its struct as LOCAL time, so the round trip silently lost the
    local UTC offset. In DST that error reaches an hour, and an hour-long
    negative delay turned every retry gate into an instantaneous probe -- a hot
    spin that never let the clock advance and never let the backend recover.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        return float(calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")))
    except (ValueError, OverflowError):
        return None


# --------------------------------------------------------------------------- #
# settings
# --------------------------------------------------------------------------- #


def settings_from_registry(registry: dict | None = None) -> dict[str, Any]:
    """CPALL budgets, read from the machine registry, never from prose."""
    data = registry if registry is not None else load_registry()
    declared = data.get("cpall") or {}
    if not isinstance(declared, dict):
        declared = {}
    settings = dict(DEFAULT_SETTINGS)
    for key, default in DEFAULT_SETTINGS.items():
        value = declared.get(key, default)
        if isinstance(default, float):
            try:
                settings[key] = float(value)
            except (TypeError, ValueError):
                settings[key] = default
        else:
            try:
                settings[key] = int(value)
            except (TypeError, ValueError):
                settings[key] = default
    return settings


# --------------------------------------------------------------------------- #
# persistence
# --------------------------------------------------------------------------- #


def objective_path(home: Path | str) -> Path:
    return Path(home) / CPALL_NAME


def reports_path(home: Path | str) -> Path:
    return Path(home) / CPALL_REPORTS_NAME


def owner_lock_path(home: Path | str) -> Path:
    return home_paths(home).locks / "cpall-owner.lock"


def fresh_objective(
    *,
    started_at: float,
    objective_id: str | None = None,
    settings: dict | None = None,
    previous_objective_id: str | None = None,
) -> dict:
    merged = dict(DEFAULT_SETTINGS)
    merged.update(settings or {})
    return {
        "schema_version": CPALL_SCHEMA_VERSION,
        "objective_id": objective_id or f"cpall-{uuid.uuid4().hex[:16]}",
        "previous_objective_id": previous_objective_id,
        "state": STATE_ACTIVE,
        "state_reason": "objective accepted",
        "state_reason_class": FAILURE_NONE,
        "started_at": _iso(started_at),
        "started_epoch": float(started_at),
        "last_progress_at": _iso(started_at),
        "last_progress_epoch": float(started_at),
        "last_checkpoint_at": None,
        "last_report_at": None,
        "last_report_epoch": None,
        "slices": 0,
        "runs_completed": 0,
        "runtime_seconds": 0.0,
        "mechanical_units_completed": 0,
        "semantic_units_completed": 0,
        "units_discovered": 0,
        "units_completed": 0,
        "units_remaining": 0,
        "units_eligible_remaining": 0,
        "units_blocked": 0,
        "units_conflict": 0,
        "units_failed_retry": 0,
        "sessions_total": 0,
        "sessions_completed": 0,
        "sessions_touched": 0,
        "phase": "RECOVER",
        "cursor": {
            "mechanical_cycle": 0,
            "semantic_units": 0,
            "last_carrier_digest": None,
            "last_slice_at": None,
        },
        "families": {
            FAMILY_MECHANICAL: {
                "state": FAMILY_ACTIVE,
                "reason": "not started",
                "attempts": 0,
                "next_attempt_at": None,
                "last_error_class": FAILURE_NONE,
                "last_error": None,
                "consecutive_failures": 0,
                "zero_progress_slices": 0,
                "intake_idle": False,
                "slices_since_run": 0,
            },
            FAMILY_SEMANTIC: {
                "state": FAMILY_ACTIVE,
                "reason": "not started",
                "attempts": 0,
                "next_attempt_at": None,
                "last_error_class": FAILURE_NONE,
                "last_error": None,
                "consecutive_failures": 0,
                "zero_progress_slices": 0,
                "slices_since_run": 0,
            },
        },
        "retry": {
            "attempts": 0,
            "consecutive_failures": 0,
            "next_attempt_at": None,
            "last_error_class": FAILURE_NONE,
            "last_error": None,
            "probes": 0,
        },
        "conflicts": {
            "current": 0,
            "indexed_total": 0,
            "superseded_total": 0,
            "isolated": [],
            "last_scan_at": None,
            "operator_review_required": 0,
        },
        "failures": {
            "transient": 0,
            "rate_limit": 0,
            "permanent": 0,
            "malformed_model_response": 0,
            "rejected_candidates": 0,
            "validation_failures": 0,
            "stale_owner_recoveries": 0,
            "checkpoint_recoveries": 0,
            "safety_stops": 0,
        },
        "owner": None,
        "source_fingerprint": None,
        "backend": {},
        "mechanical_pending": 0,
        "last_discrepancy_at": None,
        "reports": {
            "cadence_seconds": float(merged["report_cadence_seconds"]),
            "delivered": 0,
            "missed": 0,
            "delivery_failures": 0,
            "history": [],
        },
        "settings": merged,
        "next_action": "run the next bounded slice",
        "unresolved": [],
        "protocol_version": CPALL_SCHEMA_VERSION,
        "updated": None,
    }


#: Typed shape of the persisted objective. Every field must appear here, so an
#: unreadable or hand-edited state is reported rather than half-adopted.
_STRING_FIELDS = ("objective_id", "previous_objective_id", "started_at", "last_progress_at",
                  "last_checkpoint_at", "last_report_at", "phase", "next_action", "updated",
                  "source_fingerprint")
_INT_FIELDS = ("slices", "runs_completed", "mechanical_units_completed",
               "semantic_units_completed", "units_discovered", "units_completed",
               "units_remaining", "units_eligible_remaining", "units_blocked",
               "units_conflict", "units_failed_retry", "sessions_total",
               "sessions_completed", "sessions_touched", "schema_version")
_KNOWN_FIELDS = (
    "schema_version", "objective_id", "previous_objective_id", "state", "state_reason",
    "state_reason_class", "started_at", "started_epoch", "last_progress_at",
    "last_progress_epoch", "last_checkpoint_at", "last_report_at", "last_report_epoch",
    "slices", "runs_completed", "runtime_seconds", "mechanical_units_completed",
    "semantic_units_completed", "units_discovered", "units_completed", "units_remaining",
    "units_eligible_remaining", "units_blocked", "units_conflict", "units_failed_retry",
    "sessions_total", "sessions_completed", "sessions_touched", "phase", "cursor",
    "families", "retry", "conflicts", "failures", "owner", "source_fingerprint", "reports",
    "settings", "next_action", "unresolved", "protocol_version", "updated",
    "cancelled_at", "cancelled_reason", "cancelled_by", "backend", "mechanical_pending",
    "last_discrepancy_at",
)


def objective_problems(payload: object) -> list[str]:
    """Every reason `payload` is not a usable objective, or an empty list."""
    if not isinstance(payload, dict):
        return ["cpall objective root is not an object"]
    problems: list[str] = []
    if payload.get("schema_version") != CPALL_SCHEMA_VERSION:
        problems.append(
            f"schema_version {payload.get('schema_version')!r} != {CPALL_SCHEMA_VERSION}"
        )
    for key in sorted(set(payload) - set(_KNOWN_FIELDS)):
        problems.append(f"unknown field {key!r}")
    for key in _STRING_FIELDS:
        if key not in payload:
            problems.append(f"missing field {key!r}")
        elif payload[key] is not None and not isinstance(payload[key], str):
            problems.append(f"{key} must be a string or null")
    for key in _INT_FIELDS:
        if key not in payload:
            problems.append(f"missing field {key!r}")
        elif not isinstance(payload[key], int) or isinstance(payload[key], bool):
            problems.append(f"{key} must be an integer")
        elif payload[key] < 0:
            problems.append(f"{key} must not be negative")
    if payload.get("state") not in CPALL_STATES:
        problems.append(f"state {payload.get('state')!r} outside {list(CPALL_STATES)}")
    if not isinstance(payload.get("objective_id"), str) or not str(payload.get("objective_id")).strip():
        problems.append("objective_id must be a non-empty string")
    for key in ("families", "retry", "conflicts", "failures", "reports", "cursor", "settings"):
        if not isinstance(payload.get(key), dict):
            problems.append(f"{key} must be an object")
    families = payload.get("families")
    if isinstance(families, dict):
        for name in FAMILIES:
            entry = families.get(name)
            if not isinstance(entry, dict):
                problems.append(f"families.{name} must be an object")
            elif entry.get("state") not in (
                FAMILY_ACTIVE, FAMILY_DONE, FAMILY_WAITING, FAMILY_BLOCKED
            ):
                problems.append(f"families.{name}.state is not a known disposition")
    if not isinstance(payload.get("unresolved"), list):
        problems.append("unresolved must be an array")
    return problems


def load_objective(home: Path | str) -> tuple[str, dict[str, Any] | None, str]:
    """`(status, objective, detail)` with status ok / absent / unrecoverable.

    Recovery is refusal, not repair: an objective SAIPAL cannot understand is
    left exactly as it was found, because silently rewriting it would destroy
    the evidence of what the autonomous run had actually done.
    """
    path = objective_path(home)
    if not path.exists():
        return "absent", None, ""
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return "unrecoverable", None, f"cpall objective is unreadable: {exc}"
    problems = objective_problems(payload)
    if problems:
        return "unrecoverable", None, "; ".join(problems[:6])
    return "ok", payload, ""


def save_objective(home: Path | str, objective: dict, *, registry: dict | None = None) -> dict:
    """Validate then atomically replace the objective."""
    require_action("write_own_state", registry=registry)
    problems = objective_problems(objective)
    if problems:
        raise PalError(
            "STATE_UNRECOVERABLE",
            "refusing to write an invalid cpall objective: " + "; ".join(problems[:4]),
            next_action="the previous objective was left untouched",
        )
    payload = dict(objective)
    payload["last_checkpoint_at"] = utc_now_iso()
    payload["updated"] = utc_now_iso()
    atomic_write_json(objective_path(home), payload, root=home_paths(home).root)
    return payload


def append_report(home: Path | str, record: dict) -> bool:
    """Append one durable report line. Never raises into the run loop.

    Delivery of an operator-facing report is cosmetic; losing it must not
    corrupt or terminate the objective. The caller records the failure on the
    objective and keeps working.
    """
    try:
        line = (json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
        confined_append_line(home_paths(home).root, Path(CPALL_REPORTS_NAME), line)
        return True
    except (OSError, PalError, ValueError, TypeError):
        return False


def load_reports(home: Path | str, limit: int = 200) -> list[dict]:
    path = reports_path(home)
    if not path.is_file():
        return []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    rows: list[dict] = []
    for line in raw[-max(1, int(limit)):]:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


# --------------------------------------------------------------------------- #
# backlog truth
# --------------------------------------------------------------------------- #


def source_fingerprint(home: Path | str) -> str:
    """A cheap identity over the durable inputs the objective converges on.

    Not a content hash of the corpus (that would cost a full re-read every
    slice): the session index size plus the newest indexed update, so a
    fingerprint change means the work graph really moved.
    """
    index_path = home_paths(home).sessions_index
    try:
        stat = index_path.stat()
    except OSError:
        return "absent"
    return sha256_text(f"{stat.st_size}:{int(stat.st_mtime)}")[:16]


def backlog(home: Path | str, index: dict | None = None, *, registry: dict | None = None) -> dict:
    """The canonical eligible-work view CPALL converges on.

    Reads durable state only. `units` are semantic episodes (the unit the
    receipts are keyed by); `slices` are their bounded windows, reported beside
    them because a paged episode can be half-judged. Mechanical work -- staged
    audits a sink has not confirmed plus unread inbox bundles -- is counted
    separately, because it is a different family with its own owner.
    """
    root = Path(home)
    if index is None:
        status, index, _detail = sessions_mod.load_index(root, registry=registry)
        if status == sessions_mod.STATUS_UNRECOVERABLE:
            raise PalError(
                "VALIDATION_FAILED",
                "session index is unusable; cpall refuses to converge on a corpus it "
                "cannot read",
            )
        if index is None:
            index = {"schema_version": 1, "sessions": []}

    population = carrier_mod.conflict_population(index)
    conflicts = population["current"]
    conflict_ids = {str(row.get("session_id") or "") for row in conflicts}

    cover = coverage_mod.coverage(root, index, registry=registry)
    # A conflicted session is not eligible: its watermark is frozen until an
    # operator resolves the changed prefix. Counting its episodes as
    # "remaining eligible" would be a lie the objective then reasons on.
    conflict_episodes = 0
    eligible_episodes = 0
    eligible_slices = 0
    sessions_completed = 0
    for row in cover["sessions"]:
        session_id = str(row.get("session_id") or "")
        if row.get("truly_exhausted"):
            sessions_completed += 1
        owed = int(row.get("episodes") or 0) - int(row.get("final") or 0)
        if session_id in conflict_ids:
            conflict_episodes += max(0, owed)
            continue
        eligible_episodes += max(0, owed)
        eligible_slices += int(row.get("slices_pending") or 0) + int(
            row.get("slices_provisional") or 0
        )

    staged_audits = len(pub_mod.pending(root))
    # The inbox is an INPUT directory whose processed bundles are deliberately
    # retained (import is idempotent by digest, never destructive), so the count
    # of files in it is NOT a backlog: 601 settled bundles would otherwise keep
    # the mechanical family alive forever. Only UNDELIVERED mechanical output
    # is durable debt; whether new input remains is what the next `continue`
    # cycle's own `idle` answer reports, and that is what the objective records.
    inbox = home_paths(root).session_inbox
    inbox_files = 0
    if inbox.is_dir():
        inbox_files = sum(1 for path in inbox.iterdir() if path.is_file())
    mechanical_pending = staged_audits

    return {
        "ok": True,
        "sessions_total": len(cover["sessions"]),
        "sessions_completed": sessions_completed,
        "units_discovered": int(cover["episodes_total"]),
        "units_completed": int(cover["episodes_final"]),
        "units_provisional": int(cover["episodes_provisional"]),
        "units_remaining": max(0, int(cover["episodes_total"]) - int(cover["episodes_final"])),
        "units_eligible_remaining": max(0, eligible_episodes),
        "units_conflict": conflict_episodes,
        "slices_discovered": int(cover["slices_total"]),
        "slices_final": int(cover["slices_final"]),
        "slices_eligible_remaining": max(0, eligible_slices),
        "receipts_total": int(cover["receipts_total"]),
        "cursor_discrepancies": list(cover["cursor_claims_more_than_receipts"]),
        "conflicts_current": population["current_total"],
        "conflicts_indexed": population["indexed_total"],
        "conflicts_superseded": population["superseded_total"],
        "conflict_rows": conflicts,
        "staged_audits": staged_audits,
        "inbox_files": inbox_files,
        "mechanical_pending": mechanical_pending,
        "source_fingerprint": source_fingerprint(root),
    }


# --------------------------------------------------------------------------- #
# conflict isolation
# --------------------------------------------------------------------------- #


def isolate_conflicts(objective: dict, rows: list[dict], *, now: float) -> dict:
    """Reconcile the durable conflict set against the live one.

    Every current `CONFLICT` is one operator-blocked work item with its exact
    material evidence persisted, so the operator gets a stable identity rather
    than a count that drifts. Resolved conflicts drop out; a conflict whose
    material evidence changed is a *new* item (new digest), not a stale
    disposition silently reused.
    """
    previous = {
        str(row.get("conflict_material_sha256") or ""): row
        for row in (objective.get("conflicts") or {}).get("isolated") or []
    }
    isolated: list[dict] = []
    resolved: list[str] = []
    for row in rows:
        digest = str(row.get("conflict_material_sha256") or "")
        prior = previous.get(digest)
        isolated.append(
            {
                "session_id": row.get("session_id"),
                "generation": row.get("generation"),
                "conflict_material_sha256": digest,
                "material_digest_version": row.get("material_digest_version"),
                "detected_at": row.get("detected_at"),
                "source_ref": row.get("source_ref"),
                "last_analyzed_seq": row.get("last_analyzed_seq"),
                "expected_prefix_sha256": row.get("expected_prefix_sha256"),
                "observed_prefix_sha256": row.get("observed_prefix_sha256"),
                "first_seen_at": (prior or {}).get("first_seen_at") or _iso(now),
                "state": "OPERATOR_BLOCKED",
                "resolvable_by": "operator",
            }
        )
    live = {str(row.get("conflict_material_sha256") or "") for row in rows}
    for digest, prior in previous.items():
        if digest not in live:
            resolved.append(str(prior.get("session_id") or digest))
    return {"isolated": isolated, "resolved": resolved}


def conflict_evidence(home: Path | str, session_id: str, *, registry: dict | None = None) -> dict:
    """The exact persisted evidence behind one isolated conflict."""
    status, index, _detail = sessions_mod.load_index(Path(home), registry=registry)
    if status != sessions_mod.STATUS_OK or index is None:
        return {"ok": False, "reason": "session index unreadable"}
    for record in carrier_mod.freshest_records(index):
        if str(record.get("session_id") or "") == str(session_id):
            return {
                "ok": True,
                "session_id": session_id,
                "generation": record.get("generation"),
                "status": record.get("status"),
                "conflict": record.get("conflict"),
                "conflict_material_sha256": carrier_mod.conflict_material_digest(record),
            }
    return {"ok": False, "reason": "session is not in the freshest index population"}


# --------------------------------------------------------------------------- #
# failure classification
# --------------------------------------------------------------------------- #


#: Error codes / stop reasons that are a *future recoverable condition*. They
#: put a family into WAITING with a durable retry, never into a terminal state.
_TRANSIENT_CODES = (
    "SINK_UNAVAILABLE",
    "WRITER_BUSY",
    "HOME_UNRESOLVED",
    "INBOX_UNREADABLE",
    "EVIDENCE_UNSUPPORTED",
)
_RATE_LIMIT_CODES = ("RATE_LIMITED", "RATE_LIMIT")
_CONFIGURATION_CODES = ("CONFIGURATION_BLOCKED", "PUBLICATION_MODE_BLOCKED", "CONFIG_DISABLED")
_SAFETY_CODES = ("PATH_ESCAPE", "AUTHORITY_SUBSTITUTION", "STATE_UNRECOVERABLE")


def classify_failure(*, code: str | None = None, reason: str | None = None,
                     stop_reason: str | None = None) -> str:
    """One closed classification for anything a slice can report.

    Classification decides the difference between "try again in a minute" and
    "a human must decide", which is exactly the difference between WAITING and
    OPERATOR_BLOCKED. Getting it wrong in the optimistic direction spins for
    days; getting it wrong in the pessimistic direction abandons work.
    """
    token = str(code or stop_reason or "").upper()
    text = str(reason or "").lower()
    if token in _SAFETY_CODES:
        return FAILURE_UNSAFE
    if token in _RATE_LIMIT_CODES or "rate limit" in text or "rate_limit" in text:
        return FAILURE_RATE_LIMIT
    if token in _TRANSIENT_CODES:
        return FAILURE_TRANSIENT
    if token in _CONFIGURATION_CODES:
        return FAILURE_CONFIGURATION
    for marker in (
        "connection refused",
        "connection reset",
        "connection error",
        "timed out",
        "timeout",
        "temporarily unavailable",
        "temporarily loading",
        "service unavailable",
        "model loading",
        "unreachable",
        "eof occurred",
        "worker restart",
        "deadlock",
        "sharing violation",
    ):
        if marker in text:
            return FAILURE_TRANSIENT
    for marker in ("429", "too many requests", "quota"):
        if marker in text:
            return FAILURE_RATE_LIMIT
    if token in ("INTERRUPTED",):
        return FAILURE_TRANSIENT
    return FAILURE_PERMANENT


#: A slice that completed nothing and says WHY in these terms is describing a
#: configuration an operator has to clear, not a condition a retry can outlast:
#: the analyst's backend circuit opens on an `AUTH` failure and then "stays until
#: the config materially changes". Matched on the refusal's own words so the
#: classification cannot drift from the sentence it classifies -- and on
#: BEHAVIOURAL words only: the kernel stays free of provider vocabulary, so the
#: marker set may not name a credential surface (T-109 / KernelStaysModelFree).
_CONFIG_WALL_MARKERS = (
    "fix the configuration",
    "no request was sent",
)


def names_unusable_configuration(detail: str) -> bool:
    """Does this slice detail describe a configuration only an operator can fix?"""
    text = str(detail or "").lower()
    return any(marker in text for marker in _CONFIG_WALL_MARKERS)


def _slice_detail(result: dict) -> str:
    """The slice's own explanation, however the worker happened to phrase it."""
    return " ".join(
        str(part)
        for part in (result.get("detail"), result.get("next_action"))
        if part
    ).strip()


def retry_delay(attempts: int, settings: dict) -> float:
    """Bounded exponential backoff with a hard cap."""
    base = float(settings.get("retry_base_seconds", DEFAULT_SETTINGS["retry_base_seconds"]))
    cap = float(settings.get("retry_max_seconds", DEFAULT_SETTINGS["retry_max_seconds"]))
    exponent = max(0, min(int(attempts), 20))
    return float(min(cap, base * (2 ** exponent)))


# --------------------------------------------------------------------------- #
# objective lifecycle
# --------------------------------------------------------------------------- #


def _family(objective: dict, name: str) -> dict:
    return objective["families"][name]


def _set_family(objective: dict, name: str, *, state: str, reason: str,
                failure_class: str = FAILURE_NONE, now: float,
                attempts: int | None = None, backoff: float = 0.0) -> None:
    family = _family(objective, name)
    family["state"] = state
    family["reason"] = reason
    family["last_error_class"] = failure_class
    family["last_error"] = reason if failure_class != FAILURE_NONE else None
    if attempts is not None:
        family["attempts"] = int(attempts)
    if backoff > 0:
        family["next_attempt_at"] = _iso(now + backoff)
    else:
        family["next_attempt_at"] = None


def derive_state(objective: dict) -> tuple[str, str, str]:
    """Top-level state from the per-family dispositions.

    This is the only place the top-level state is decided, so `status`, the
    run loop and the reports can never disagree about what the objective is
    doing.
    """
    dispositions = [objective["families"][name]["state"] for name in FAMILIES]
    if all(disposition == FAMILY_DONE for disposition in dispositions):
        if int(objective.get("units_conflict") or 0) or int(
            (objective.get("conflicts") or {}).get("current") or 0
        ):
            return (
                STATE_OPERATOR_BLOCKED,
                "independent work is exhausted; only operator-resolved conflicts remain",
                "CONFLICT",
            )
        return STATE_COMPLETED, "no eligible work remains in any family", FAILURE_NONE
    if any(disposition == FAMILY_ACTIVE for disposition in dispositions):
        # A blocked or waiting family does NOT freeze a family that can still
        # work: independent work continues first, and the wall is NAMED in the
        # reason instead of being allowed to stop the universe. This is
        # PAL-CPALL-03's rule for conflicts, applied to every kind of wall -- the
        # objective answers OPERATOR_BLOCKED only when the last independent
        # workstream is DONE, so a configuration problem in one family cannot
        # halt another family's convergence.
        blocked = [
            name for name in FAMILIES if objective["families"][name]["state"] == FAMILY_BLOCKED
        ]
        waiting = [
            name for name in FAMILIES if objective["families"][name]["state"] == FAMILY_WAITING
        ]
        reason = "eligible work remains"
        klass = FAILURE_NONE
        if blocked:
            reason += "; blocked: " + ", ".join(blocked)
            klass = FAILURE_CONFIGURATION
        elif waiting:
            reason += "; waiting on: " + ", ".join(waiting)
            klass = FAILURE_TRANSIENT
        return STATE_ACTIVE, reason, klass
    if any(disposition == FAMILY_WAITING for disposition in dispositions):
        waiting = [
            name for name in FAMILIES if objective["families"][name]["state"] == FAMILY_WAITING
        ]
        return (
            STATE_WAITING,
            "waiting on a recoverable condition in: " + ", ".join(waiting),
            FAILURE_TRANSIENT,
        )
    if any(disposition == FAMILY_BLOCKED for disposition in dispositions):
        blocked = [
            name for name in FAMILIES if objective["families"][name]["state"] == FAMILY_BLOCKED
        ]
        reason = "operator authority required for: " + ", ".join(blocked)
        # The SESSION count is what an operator resolves (`current`), not the
        # number of episodes those sessions carry -- 275 conflict UNITS next to an
        # 11-session conflict set is exactly the kind of ambiguous number this
        # wave removed from every other surface.
        conflicts = int((objective.get("conflicts") or {}).get("current") or 0) or int(
            objective.get("units_conflict") or 0
        )
        if conflicts:
            reason += f"; {conflicts} isolated conflict(s) stay operator-resolved"
        return STATE_OPERATOR_BLOCKED, reason, FAILURE_CONFIGURATION
    return STATE_ACTIVE, "eligible work remains", FAILURE_NONE


def _owner_is_live(objective: dict, *, now: float, settings: dict) -> bool:
    owner = objective.get("owner")
    if not isinstance(owner, dict) or not owner.get("owner_id"):
        return False
    heartbeat = _epoch(owner.get("heartbeat_at")) or 0.0
    ttl = float(owner.get("ttl_seconds") or settings.get("owner_ttl_seconds") or 0.0)
    if str(owner.get("host") or "") != _hostname():
        # A lease taken on another host cannot be probed locally: a foreign PID
        # answering here would be about an unrelated process. The TTL is the only
        # evidence this host has.
        return now - heartbeat <= ttl
    if not _pid_alive(owner.get("pid")):
        # Same host, and the process that took the lease is GONE. That is machine
        # evidence, so the lease is recoverable NOW rather than when the TTL
        # happens to lapse: a bounded worker that already exited must not hold its
        # own objective hostage -- a dead PID answering "still alive" for the rest
        # of an hour is how "durable objective" becomes "one run per TTL".
        return False
    # The PID answers: assume the owner is live even past its TTL. Killing a
    # healthy worker to take its home is worse than waiting for its heartbeat.
    return True


def _hostname() -> str:
    try:
        import socket

        return socket.gethostname()
    except OSError:  # pragma: no cover - hostname is always available in practice
        return ""


def _pid_alive(pid: object) -> bool:
    try:
        value = int(pid)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    if value <= 0:
        return False
    if os.name == "nt":  # pragma: no cover - exercised on Windows runs
        from .paths import _pid_alive as probe

        return bool(probe(value))
    try:
        os.kill(value, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def claim_ownership(objective: dict, *, now: float, settings: dict,
                    recovered: bool = False) -> dict:
    """Mint a fresh owner lease. The previous owner is gone by construction."""
    token = f"cpall-{uuid.uuid4().hex[:12]}"
    settings = settings or {}
    objective["owner"] = {
        "owner_id": token,
        "pid": os.getpid(),
        "host": _hostname(),
        "acquired_at": _iso(now),
        "heartbeat_at": _iso(now),
        "ttl_seconds": float(settings.get("owner_ttl_seconds") or
                            DEFAULT_SETTINGS["owner_ttl_seconds"]),
        "recovered_from": (objective.get("owner") or {}).get("owner_id") if recovered else None,
    }
    if recovered:
        failures = objective.setdefault("failures", {})
        failures["stale_owner_recoveries"] = int(failures.get("stale_owner_recoveries") or 0) + 1
    return objective


def heartbeat(objective: dict, *, now: float) -> None:
    owner = objective.get("owner")
    if isinstance(owner, dict):
        owner["heartbeat_at"] = _iso(now)


def owns(objective: dict, owner_id: str | None) -> bool:
    return isinstance(objective.get("owner"), dict) and objective["owner"].get(
        "owner_id"
    ) == owner_id


def attach_or_start(home: Path | str, *, registry: dict | None = None, now: float | None = None,
                    settings: dict | None = None) -> dict:
    """Idempotent `/goal cpall`.

    One live objective is never duplicated. A second invocation attaches to the
    objective that exists instead of minting a second worker for the same home,
    and a resumed objective keeps its identity, counters, cursor and reports.
    """
    settings = settings_from_registry(registry) if settings is None else settings
    clock_now = float(now if now is not None else time.time())
    status, objective, detail = load_objective(home)
    if status == "unrecoverable":
        raise PalError(
            "STATE_UNRECOVERABLE",
            f"{CPALL_NAME} is unusable: {detail}",
            next_action=(
                f"repair or remove .saipal/{CPALL_NAME} by hand; SAIPAL will not "
                "overwrite an objective it cannot understand"
            ),
        )

    if status == "ok" and objective is not None and objective["state"] in RESUMABLE_STATES:
        live = _owner_is_live(objective, now=clock_now, settings=settings)
        return {
            "ok": True,
            "attached": True,
            "resumed": live,
            "recovered_stale_owner": not live,
            "objective": objective,
            "objective_id": objective["objective_id"],
            "state": objective["state"],
            "detail": (
                f"cpall already active; attached to existing objective "
                f"{objective['objective_id']}"
            ),
        }

    previous = objective["objective_id"] if objective is not None else None
    fresh = fresh_objective(
        started_at=clock_now, settings=settings, previous_objective_id=previous
    )
    claim_ownership(fresh, now=clock_now, settings=settings, recovered=False)
    saved = save_objective(home, fresh, registry=registry)
    report = progress_report(saved, kind=REPORT_START, now=clock_now)
    if not append_report(home, report):
        saved["reports"]["delivery_failures"] = int(
            saved["reports"].get("delivery_failures") or 0
        ) + 1
    saved["reports"]["delivered"] = int(saved["reports"].get("delivered") or 0) + 1
    saved["last_report_at"] = _iso(clock_now)
    saved["last_report_epoch"] = clock_now
    saved = save_objective(home, saved, registry=registry)
    return {
        "ok": True,
        "attached": False,
        "resumed": False,
        "recovered_stale_owner": False,
        "previous_objective_id": previous,
        "objective": saved,
        "objective_id": saved["objective_id"],
        "state": saved["state"],
        "detail": f"cpall objective {saved['objective_id']} accepted",
    }


def cancel(home: Path | str, *, reason: str, registry: dict | None = None,
           now: float | None = None, by: str = "operator") -> dict:
    """Intentionally stop the objective. Evidence and completed work survive."""
    clock_now = float(now if now is not None else time.time())
    status, objective, detail = load_objective(home)
    if status == "absent":
        raise PalError("VALIDATION_FAILED", "there is no cpall objective to cancel")
    if status == "unrecoverable":
        raise PalError("STATE_UNRECOVERABLE", f"{CPALL_NAME} is unusable: {detail}")
    assert objective is not None
    if objective["state"] == STATE_CANCELLED:
        return {"ok": True, "already_cancelled": True, "objective": objective,
                "objective_id": objective["objective_id"], "state": STATE_CANCELLED}
    if objective["state"] in TERMINAL_STATES:
        return {"ok": True, "already_terminal": True, "objective": objective,
                "objective_id": objective["objective_id"], "state": objective["state"]}
    objective["state"] = STATE_CANCELLED
    objective["state_reason"] = reason
    objective["cancelled_at"] = _iso(clock_now)
    objective["cancelled_reason"] = reason
    objective["cancelled_by"] = by
    objective["owner"] = None
    objective["retry"]["next_attempt_at"] = None
    objective["next_action"] = "explicit new `/goal cpall` to start a fresh objective"
    saved = save_objective(home, objective, registry=registry)
    report = progress_report(saved, kind=REPORT_FINAL, now=clock_now)
    append_report(home, report)
    return {"ok": True, "cancelled": True, "objective": saved,
            "objective_id": saved["objective_id"], "state": STATE_CANCELLED}


def recover(home: Path | str, *, registry: dict | None = None, now: float | None = None,
            settings: dict | None = None) -> dict:
    """What a brand-new process needs to continue the same objective.

    Deliberately reads only durable state: the next worker is expected to have
    zero knowledge of the chat that started the run.
    """
    settings = settings_from_registry(registry) if settings is None else settings
    clock_now = float(now if now is not None else time.time())
    status, objective, detail = load_objective(home)
    if status == "absent":
        return {"ok": True, "present": False, "resumable": False,
                "objective": None, "detail": "no cpall objective exists"}
    if status == "unrecoverable":
        return {"ok": False, "present": True, "resumable": False, "objective": None,
                "detail": detail, "state": "UNRECOVERABLE"}
    assert objective is not None
    live = _owner_is_live(objective, now=clock_now, settings=settings)
    resumable = objective["state"] in RESUMABLE_STATES
    return {
        "ok": True,
        "present": True,
        "resumable": resumable,
        "state": objective["state"],
        "objective_id": objective["objective_id"],
        "objective": objective,
        "owner_live": live,
        "stale_owner": bool(resumable and not live and objective.get("owner")),
        "next_action": objective.get("next_action"),
        "cursor": objective.get("cursor"),
        "unresolved": objective.get("unresolved") or [],
        "detail": (
            f"objective {objective['objective_id']} is {objective['state']}"
            + ("" if live else "; its owner lease is recoverable")
        ),
    }


def status(home: Path | str, *, registry: dict | None = None, index: dict | None = None,
           now: float | None = None) -> dict:
    """Read-only CPALL truth. Never reports IDLE while an objective lives."""
    settings = settings_from_registry(registry)
    clock_now = float(now if now is not None else time.time())
    state_status, objective, detail = load_objective(home)
    if state_status == "absent":
        return {
            "exists": False,
            "state": None,
            "objective_id": None,
            "detail": "no cpall objective exists",
            "next_action": "`/goal cpall` starts a durable convergence objective",
        }
    if state_status == "unrecoverable":
        return {
            "exists": True,
            "state": "UNRECOVERABLE",
            "objective_id": None,
            "detail": detail,
            "next_action": f"repair or remove .saipal/{CPALL_NAME} by hand",
        }
    assert objective is not None
    owner = objective.get("owner") or {}
    retry = objective.get("retry") or {}
    next_attempt = retry.get("next_attempt_at")
    next_attempt_epoch = _epoch(next_attempt)
    return {
        "exists": True,
        "state": objective["state"],
        "objective_id": objective["objective_id"],
        "state_reason": objective.get("state_reason"),
        "started_at": objective.get("started_at"),
        "last_progress_at": objective.get("last_progress_at"),
        "last_checkpoint_at": objective.get("last_checkpoint_at"),
        "last_report_at": objective.get("last_report_at"),
        "runtime_seconds": round(float(objective.get("runtime_seconds") or 0.0), 1),
        "elapsed_seconds": round(
            max(0.0, clock_now - float(objective.get("started_epoch") or clock_now)), 1
        ),
        "slices": objective.get("slices"),
        "coverage": {
            "units_discovered": objective.get("units_discovered"),
            "units_completed": objective.get("units_completed"),
            "units_remaining": objective.get("units_remaining"),
            "units_eligible_remaining": objective.get("units_eligible_remaining"),
            "units_blocked": objective.get("units_blocked"),
            "units_conflict": objective.get("units_conflict"),
            "percent": (
                round(
                    100.0 * float(objective.get("units_completed") or 0)
                    / float(objective.get("units_discovered") or 0),
                    1,
                )
                if int(objective.get("units_discovered") or 0)
                else None
            ),
            "sessions_total": objective.get("sessions_total"),
            "sessions_completed": objective.get("sessions_completed"),
        },
        "conflicts": {
            "current": int((objective.get("conflicts") or {}).get("current") or 0),
            "indexed": int((objective.get("conflicts") or {}).get("indexed_total") or 0),
            "superseded": int((objective.get("conflicts") or {}).get("superseded_total") or 0),
            "isolated": len((objective.get("conflicts") or {}).get("isolated") or []),
        },
        "families": objective.get("families"),
        "retry": {
            "attempts": retry.get("attempts"),
            "consecutive_failures": retry.get("consecutive_failures"),
            "next_attempt_at": next_attempt,
            "seconds_until_retry": (
                round(max(0.0, next_attempt_epoch - clock_now), 1)
                if next_attempt_epoch is not None
                else None
            ),
            "last_error_class": retry.get("last_error_class"),
        },
        "owner": {
            "owner_id": owner.get("owner_id"),
            "pid": owner.get("pid"),
            "host": owner.get("host"),
            "heartbeat_at": owner.get("heartbeat_at"),
            "live": _owner_is_live(objective, now=clock_now, settings=settings),
        },
        "backend": objective.get("backend") or {},
        "failures": objective.get("failures"),
        "reports": {
            "cadence_seconds": (objective.get("reports") or {}).get("cadence_seconds"),
            "delivered": (objective.get("reports") or {}).get("delivered"),
            "missed": (objective.get("reports") or {}).get("missed"),
            "delivery_failures": (objective.get("reports") or {}).get("delivery_failures"),
        },
        "next_action": objective.get("next_action"),
        "unresolved": objective.get("unresolved") or [],
    }


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #


def progress_report(objective: dict, *, kind: str, now: float,
                    extras: dict | None = None) -> dict:
    """One durable, machine-truth progress record.

    Counts come from the objective, which is itself derived from durable state;
    nothing here is estimated to look better than the run actually is.
    """
    coverage = {
        "units_completed": int(objective.get("units_completed") or 0),
        "units_discovered": int(objective.get("units_discovered") or 0),
        "sessions_completed": int(objective.get("sessions_completed") or 0),
        "sessions_total": int(objective.get("sessions_total") or 0),
        "units_eligible_remaining": int(objective.get("units_eligible_remaining") or 0),
        "units_conflict": int(objective.get("units_conflict") or 0),
    }
    percent = (
        round(
            100.0 * coverage["units_completed"] / coverage["units_discovered"],
            1,
        )
        if coverage["units_discovered"]
        else None
    )
    record = {
        "schema_version": CPALL_SCHEMA_VERSION,
        "kind": kind,
        "objective_id": objective.get("objective_id"),
        "state": objective.get("state"),
        "state_reason": objective.get("state_reason"),
        "at": _iso(now),
        "runtime_seconds": round(float(objective.get("runtime_seconds") or 0.0), 1),
        "elapsed_seconds": round(
            max(0.0, now - float(objective.get("started_epoch") or now)), 1
        ),
        "slices": int(objective.get("slices") or 0),
        "coverage": dict(coverage, percent=percent),
        "conflicts": {
            "current": int((objective.get("conflicts") or {}).get("current") or 0),
            "indexed": int((objective.get("conflicts") or {}).get("indexed_total") or 0),
            "superseded": int((objective.get("conflicts") or {}).get("superseded_total") or 0),
            "operator_review_required": int(
                (objective.get("conflicts") or {}).get("operator_review_required") or 0
            ),
        },
        "families": objective.get("families"),
        "retry": objective.get("retry"),
        "backend": objective.get("backend") or {},
        "phase": objective.get("phase"),
        "failures": objective.get("failures"),
        "last_checkpoint_at": objective.get("last_checkpoint_at"),
        "next_action": objective.get("next_action"),
        "unresolved": objective.get("unresolved") or [],
    }
    if extras:
        record.update(extras)
    return record


def render_report_text(record: dict) -> str:
    """The operator-facing periodic report block."""
    coverage = record.get("coverage") or {}
    lines = [
        f"CPALL {record.get('state')} [{record.get('kind')}]",
        f"Objective: {record.get('objective_id')}",
        f"Runtime: {_human_duration(record.get('elapsed_seconds') or 0)}",
        f"Semantic: {coverage.get('units_completed', 0):,} / "
        f"{coverage.get('units_discovered', 0):,}",
        f"Sessions complete: {coverage.get('sessions_completed', 0):,} / "
        f"{coverage.get('sessions_total', 0):,}",
        f"Blocked conflicts: {((record.get('conflicts') or {}).get('current') or 0)}",
        f"Retry queue: {((record.get('retry') or {}).get('consecutive_failures') or 0)}",
    ]
    if record.get("new_units_since_last_report") is not None:
        lines.append(f"Last interval: +{record['new_units_since_last_report']} units")
    if coverage.get("percent") is not None:
        lines.append(f"Coverage: {coverage['percent']}%")
    lines.append(f"Checkpoint: {record.get('last_checkpoint_at') or '-'}")
    backend = record.get("backend") or {}
    if backend.get("model"):
        lines.append(f"Backend: {backend.get('route', 'unknown')}/{backend.get('model')}")
    lines.append(f"Next: {record.get('next_action') or '-'}")
    if record.get("state_reason"):
        lines.append(f"Reason: {record['state_reason']}")
    return "\n".join(lines)


def _human_duration(seconds: float) -> str:
    total = int(max(0.0, float(seconds)))
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


# --------------------------------------------------------------------------- #
# the supervisor
# --------------------------------------------------------------------------- #


class CpallRun:
    """One process's tenure as owner of the durable objective.

    The instance is disposable: everything it learns is persisted on the
    objective before the next slice starts, so killing this object at any point
    loses at most one uncommitted slice.
    """

    def __init__(
        self,
        home: Path | str,
        *,
        mechanical_slice: Callable[[Path], dict],
        semantic_slice: Callable[[Path], dict],
        registry: dict | None = None,
        settings: dict | None = None,
        clock: object = None,
        sleep_fn: Callable[[float], None] | None = None,
        probe_fn: Callable[[Path], dict] | None = None,
        conflict_rows: Callable[[Path], list[dict]] | None = None,
        backlog_fn: Callable[[Path], dict] | None = None,
        operator_queue: Any = None,
    ) -> None:
        self.home = Path(home)
        self.mechanical_slice = mechanical_slice
        self.semantic_slice = semantic_slice
        self.registry = registry
        self.settings = settings_from_registry(registry) if settings is None else settings
        self.clock = _as_clock(clock, sleep_fn)
        self.probe_fn = probe_fn
        self.conflict_rows = conflict_rows
        #: PAL-CPALL-05's packet, INJECTED like every other slice dependency.
        #: The queue needs the analyst allocator's classifier to know what is
        #: runnable, and `saipal_engine` may never import `saipal_analyst` --
        #: that invariant is what keeps the kernel model-free. So the caller
        #: supplies the module and the kernel only ever calls it.
        self.operator_queue = operator_queue
        #: A completion claim is verified once against a fresh intake pass.
        self.completion_rescanned = False
        #: The durable work view. Injected for the long-duration simulations, so
        #: "seven days and thousands of slices" is deterministic and cheap while
        #: still exercising the real supervisor, state machine and reporting.
        self.backlog_fn = backlog_fn
        self.summary: dict[str, Any] = {
            "ok": True,
            "command": "cpall",
            "slices": 0,
            "slice_results": [],
            "stop_reason": None,
            "state": None,
        }

    # -- helpers ---------------------------------------------------------- #

    def _now(self) -> float:
        return self.clock.now()

    def _save(self, objective: dict) -> dict:
        objective["runtime_seconds"] = round(
            max(0.0, self._now() - float(objective.get("started_epoch") or self._now())), 3
        )
        saved = save_objective(self.home, objective, registry=self.registry)
        objective.clear()
        objective.update(saved)
        return saved

    def _emit(self, objective: dict, *, kind: str, extras: dict | None = None,
              force: bool = False) -> bool:
        """Durable internal report. Never raises into the run loop."""
        now = self._now()
        cadence = float((objective.get("reports") or {}).get("cadence_seconds") or 0.0)
        last = float(objective.get("last_report_epoch") or 0.0)
        minimum = float(self.settings.get("min_report_interval_seconds") or 0.0)
        if not force and cadence and (now - last) < max(minimum, cadence):
            return False
        record = progress_report(objective, kind=kind, now=now, extras=extras)
        record["delivery"] = "durable"
        delivered = append_report(self.home, record)
        reports = objective.setdefault("reports", {})
        if delivered:
            reports["delivered"] = int(reports.get("delivered") or 0) + 1
            objective["last_report_at"] = _iso(now)
            objective["last_report_epoch"] = now
            history = list(reports.get("history") or [])
            history.append(record)
            limit = int(self.settings.get("report_history_limit") or 0)
            reports["history"] = history[-limit:] if limit > 0 else history
        else:
            # A missed cosmetic report is recorded, never fatal: the objective
            # keeps converging and the delivery debt stays visible.
            reports["missed"] = int(reports.get("missed") or 0) + 1
            reports["delivery_failures"] = int(reports.get("delivery_failures") or 0) + 1
        return delivered

    def _sleep_with_heartbeat(self, objective: dict, seconds: float) -> bool:
        """Sleep in heartbeat chunks so a long WAITING stretch keeps the lease.

        Returns False when this process is no longer the owner.
        """
        chunk = max(1.0, float(self.settings.get("sleep_chunk_seconds") or 15.0))
        remaining = max(0.0, float(seconds))
        while remaining > 0:
            step = min(remaining, chunk)
            self.clock.sleep(step)
            remaining -= step
            heartbeat(objective, now=self._now())
            self._save(objective)
            if not owns(objective, self.summary.get("owner_id")):
                return False
        return True

    def _backlog(self) -> dict:
        if self.backlog_fn is not None:
            return self.backlog_fn(self.home)
        return backlog(self.home, registry=self.registry)

    # -- the loop --------------------------------------------------------- #

    def run(
        self,
        *,
        objective: dict,
        owner_id: str,
        max_slices: int = 0,
        stop_requested: Callable[[], bool] | None = None,
    ) -> dict:
        self.summary["owner_id"] = owner_id
        self.summary["objective_id"] = objective["objective_id"]
        started = self._now()
        previous_report_units = int(objective.get("units_completed") or 0)

        objective["phase"] = "CONVERGE"
        self._save(objective)

        while True:
            if stop_requested is not None and stop_requested():
                self.summary["stop_reason"] = "STOP_REQUESTED"
                objective["next_action"] = "explicit `/goal cpall` resumes the objective"
                self._save(objective)
                break
            if not owns(objective, owner_id):
                self.summary["ok"] = False
                self.summary["stop_reason"] = "OWNERSHIP_LOST"
                self.summary["detail"] = (
                    "another cpall owner took this objective; this process stopped "
                    "instead of writing into a stolen home"
                )
                break
            if max_slices and int(self.summary["slices"]) >= int(max_slices):
                # A process lifetime is a checkpoint boundary, never a goal
                # boundary: the objective stays exactly as resumable as it was.
                self.summary["stop_reason"] = "SLICE_BUDGET"
                objective["next_action"] = (
                    "resume the objective: the slice budget was reached with work "
                    "still eligible"
                )
                self._save(objective)
                break

            self._claim_source_fingerprint(objective)

            # -- retry gate ---------------------------------------------- #
            attempt_at = _epoch((objective.get("retry") or {}).get("next_attempt_at"))
            if objective["state"] == STATE_WAITING and attempt_at is not None:
                delay = attempt_at - self._now()
                if delay > 0:
                    if not self._sleep_with_heartbeat(objective, min(delay, 300.0)):
                        self.summary["stop_reason"] = "OWNERSHIP_LOST"
                        self.summary["ok"] = False
                        break
                    self._recompute(objective, save=False)
                    objective["state"], reason, klass = derive_state(objective)
                    objective["state_reason"] = reason
                    objective["state_reason_class"] = klass
                    self._emit(objective, kind=REPORT_PROGRESS,
                               extras={"note": "waiting out a retry delay"})
                    self._save(objective)
                    continue
                # Delay elapsed: probe readiness once rather than guessing.
                ready, probe_detail, probe_outcome = self._probe(objective)
                if probe_outcome is not None:
                    self._apply_outcome(objective, FAMILY_SEMANTIC, probe_outcome,
                                        self._now())
                if not ready:
                    objective["retry"]["probes"] = int(objective["retry"].get("probes") or 0) + 1
                    objective["retry"]["attempts"] = int(objective["retry"].get("attempts") or 0) + 1
                    backoff = retry_delay(objective["retry"]["attempts"], self.settings)
                    objective["retry"]["next_attempt_at"] = _iso(self._now() + backoff)
                    objective["retry"]["last_error"] = probe_detail
                    objective["next_action"] = (
                        f"retry readiness probe in {int(backoff)}s"
                    )
                    self._save(objective)
                    continue

            # -- one bounded slice --------------------------------------- #
            state_before = objective["state"]
            self._slice(objective)
            self.summary["slices"] += 1
            objective["slices"] = int(objective.get("slices") or 0) + 1
            objective["cursor"]["last_slice_at"] = utc_now_iso()

            self._recompute(objective)

            new_state, reason, klass = derive_state(objective)
            objective["state"] = new_state
            objective["state_reason"] = reason
            objective["state_reason_class"] = klass
            objective["next_action"] = self._next_action(objective)

            # -- report --------------------------------------------------- #
            current_units = int(objective.get("units_completed") or 0)
            delta = max(0, current_units - previous_report_units)
            forced = new_state != state_before
            if new_state in (STATE_COMPLETED, STATE_SAFETY_STOP, STATE_CANCELLED):
                self._emit(objective, kind=REPORT_FINAL, force=True,
                           extras={"new_units_since_last_report": delta})
            elif new_state == STATE_OPERATOR_BLOCKED and forced:
                self._emit(objective, kind=REPORT_BLOCKED, force=True,
                           extras={"new_units_since_last_report": delta})
            elif forced:
                self._emit(objective, kind=REPORT_STATE_CHANGE, force=True,
                           extras={"new_units_since_last_report": delta})
            elif self._emit(objective, kind=REPORT_PROGRESS,
                            extras={"new_units_since_last_report": delta}):
                previous_report_units = current_units

            self._save(objective)

            if objective["state"] == STATE_COMPLETED and not self.completion_rescanned:
                # Truthful completion needs an intake answer taken AT the moment
                # of completion. The last ordinary mechanical pass may predate
                # evidence that has since landed on disk, and a `CONFLICT`-free
                # idle answer from before it is not authority to claim done.
                self.completion_rescanned = True
                forced = self._run_family(
                    FAMILY_MECHANICAL, self.mechanical_slice, objective
                )
                forced["state"] = forced.get("state") or FAMILY_ACTIVE
                objective["families"][FAMILY_MECHANICAL]["slices_since_run"] = 0
                self._apply_outcome(objective, FAMILY_MECHANICAL, forced, self._now())
                self._recompute(objective)
                objective["state"], reason, klass = derive_state(objective)
                objective["state_reason"] = reason
                objective["state_reason_class"] = klass
                objective["next_action"] = self._next_action(objective)
                self.summary["completion_rescan"] = {
                    "state": objective["state"],
                    "reason": reason,
                }
                self._save(objective)
                if objective["state"] != STATE_COMPLETED:
                    continue

            if objective["state"] == STATE_SAFETY_STOP:
                self.summary["ok"] = False
                self.summary["stop_reason"] = "SAFETY_STOP"
                break
            if objective["state"] in TERMINAL_STATES:
                self.summary["stop_reason"] = objective["state"]
                break
            if objective["state"] == STATE_OPERATOR_BLOCKED:
                # Blocked means every independent workstream is exhausted; there
                # is nothing left to chain, so stop the process (the objective
                # stays OPERATOR_BLOCKED and resumable through the canonical
                # path if new evidence or an operator decision changes it).
                #
                # PAL-CPALL-05: a blocked state is a CLAIM that everything the
                # agent may lawfully do is done. Stopping with only the state
                # name leaves that claim unaudited, so the boundary is rendered
                # here: every session partitioned into exactly one decision, the
                # exact identities attached, and the packet persisted next to
                # the objective. Rebuilding it is deterministic, so after one
                # operator decision it reclassifies only the affected sessions.
                self.summary["operator_queue"] = self._emit_operator_queue()
                self.summary["stop_reason"] = STATE_OPERATOR_BLOCKED
                break

        # The process is disposable; the objective is durable. A bounded run that
        # stops with work still eligible RELEASES its lease on the way out, so the
        # next invocation resumes instead of attaching to a process that no longer
        # exists and waiting out the TTL -- "durable objective" must not become
        # "one run per owner TTL". A process that died without reaching here
        # releases nothing, which is exactly what the TTL and the same-host PID
        # probe are for.
        if objective.get("owner") and owns(objective, owner_id):
            objective["owner"] = None
            self._save(objective)

        self.summary["state"] = objective["state"]
        self.summary["objective"] = objective
        self.summary["runtime_seconds"] = round(self._now() - started, 3)
        self.summary["coverage"] = {
            "units_discovered": objective.get("units_discovered"),
            "units_completed": objective.get("units_completed"),
            "units_eligible_remaining": objective.get("units_eligible_remaining"),
            "sessions_total": objective.get("sessions_total"),
            "sessions_completed": objective.get("sessions_completed"),
        }
        self.summary["conflicts"] = {
            "current": (objective.get("conflicts") or {}).get("current"),
            "indexed": (objective.get("conflicts") or {}).get("indexed_total"),
            "superseded": (objective.get("conflicts") or {}).get("superseded_total"),
        }
        return self.summary

    # -- slice internals --------------------------------------------------- #

    def _claim_source_fingerprint(self, objective: dict) -> None:
        current = source_fingerprint(self.home)
        if objective.get("source_fingerprint") != current:
            objective["source_fingerprint"] = current

    def _probe(self, objective: dict) -> tuple[bool, str, dict | None]:
        """One readiness probe after a retry delay elapses.

        The probe is the work itself, not a guess about it: a synthetic readiness
        endpoint would be a second source of truth for whether the backend
        answers, and could disagree with the transport that has to work anyway.
        A probe that reports a transient failure re-arms the retry and is counted
        in the failure ledger; anything else means the family may run again. A
        successful probe's work is
        FOLDED BACK into the objective rather than discarded, so probing cannot
        cost a unit.
        """
        try:
            if self.probe_fn is not None:
                result = self.probe_fn(self.home)
            else:
                result = self.semantic_slice(self.home)
        except PalError as exc:
            detail = str(exc.message or exc)
            self._count_probe_failure(
                objective, classify_failure(code=str(exc.code), reason=detail)
            )
            return False, detail, None
        except Exception as exc:  # noqa: BLE001
            detail = f"{type(exc).__name__}: {exc}"
            self._count_probe_failure(objective, classify_failure(reason=detail))
            return False, detail, None
        outcome = self._classify_slice(FAMILY_SEMANTIC, result if isinstance(result, dict) else {})
        if outcome["state"] == FAMILY_WAITING:
            self._count_probe_failure(
                objective, outcome.get("failure_class") or FAILURE_NONE
            )
            return False, str(outcome.get("reason") or "still unavailable"), None
        objective.setdefault("retry", {})["next_attempt_at"] = None
        return True, "ready", outcome

    def _count_probe_failure(self, objective: dict, klass: str) -> None:
        """An unready probe is an OBSERVED failure, not a guess about one.

        A backend that refuses connections or rate-limits for hours would
        otherwise leave `failures` at zero while the retry queue grew, and the
        periodic report would understate exactly the condition the operator
        needs to see.
        """
        if klass and klass != FAILURE_NONE:
            self._bump_failure(objective, klass)
            objective.setdefault("retry", {})["last_error_class"] = klass

    def _slice(self, objective: dict) -> None:
        """One bounded mechanical pass plus one bounded semantic pass."""
        now = self._now()
        family_outcomes: dict[str, dict] = {}

        # A settled family is not re-run on every slice: the mechanical pass is a
        # full intake + analysis cycle, and paying it once per semantic carrier
        # would make control-plane bookkeeping dominate model analysis. A
        # settled family is still re-examined at every safe RESCAN boundary, so
        # new evidence discovered mid-objective is imported (PAL-CPALL-01).
        rescan_every = max(1, int(self.settings.get("rescan_every_slices") or 10))
        for name, runner in (
            (FAMILY_MECHANICAL, self.mechanical_slice),
            (FAMILY_SEMANTIC, self.semantic_slice),
        ):
            family = _family(objective, name)
            if family["state"] == FAMILY_DONE:
                if name != FAMILY_MECHANICAL:
                    continue
                since = int(family.get("slices_since_run") or 0) + 1
                family["slices_since_run"] = since
                if since < rescan_every:
                    continue
            family["slices_since_run"] = 0
            family_outcomes[name] = self._run_family(name, runner, objective)

        for name, outcome in family_outcomes.items():
            self._apply_outcome(objective, name, outcome, now)

        self.summary["slice_results"].append(
            {
                "slice": self.summary["slices"] + 1,
                "families": {
                    name: {
                        "state": outcome["state"],
                        "failure_class": outcome["failure_class"],
                        "reason": outcome.get("reason"),
                        "units": outcome.get("units", 0),
                    }
                    for name, outcome in family_outcomes.items()
                },
            }
        )

    def _apply_outcome(self, objective: dict, name: str, outcome: dict, now: float) -> None:
        """One family's slice result, folded into the durable objective.

        The single place where a family's disposition, counters, cursor,
        logging and retry schedule move, so a slice, a folded readiness probe
        and a recovered run can never account for the same work differently.
        """
        family = _family(objective, name)
        family["attempts"] = int(family.get("attempts") or 0) + 1
        klass = outcome["failure_class"]
        if outcome["state"] == FAMILY_ACTIVE:
            # `unresolved` means CURRENTLY unresolved. A family that just ran is
            # not blocked any more, so the wall it reported earlier stops being
            # listed -- otherwise a reader sees "FAMILY_BLOCKED:semantic" next to
            # a family that is working, and stops trusting the section.
            self._clear_unresolved(objective, f"FAMILY_BLOCKED:{name}")
            # Failure count resets on PROGRESS, never on a slice that merely
            # returned. A worker that keeps answering without advancing is not
            # a success, and the backoff has to be able to grow because of it.
            if int(outcome.get("units") or 0):
                family["consecutive_failures"] = 0
                self._clear_unresolved(objective, "SEMANTIC_NO_PROGRESS")
            elif klass != FAILURE_NONE:
                # A slice that advanced nothing but NAMED a wall is counted even
                # though the family stays runnable. Only a classifier that
                # returned a real class reaches this branch (`_classify_slice`
                # declares FAILURE_NONE for an idle or merely budget-bounded
                # slice), so this cannot turn "nothing to do" into a failure --
                # while a run blocked on protocol authority can no longer report
                # zero failures.
                self._bump_failure(objective, klass)
            _set_family(objective, name, state=FAMILY_ACTIVE,
                        reason=outcome.get("reason") or "progress", now=now,
                        failure_class=klass)
        elif outcome["state"] == FAMILY_DONE:
            family["consecutive_failures"] = 0
            self._clear_unresolved(objective, f"FAMILY_BLOCKED:{name}")
            _set_family(objective, name, state=FAMILY_DONE,
                        reason=outcome.get("reason") or "no eligible work", now=now)
        elif outcome["state"] == FAMILY_BLOCKED:
            blocked_reason = outcome.get("reason") or "operator decision required"
            _set_family(objective, name, state=FAMILY_BLOCKED,
                        reason=blocked_reason,
                        failure_class=klass, now=now)
            errors = objective.setdefault("failures", {})
            if klass == FAILURE_CONFIGURATION:
                errors["validation_failures"] = int(
                    errors.get("validation_failures") or 0
                ) + 1
            # A blocked family that keeps another family working is exactly the
            # case an operator has to SEE: it is named on the durable objective,
            # not only in the log of the slice that discovered it.
            self._record_unresolved(objective, kind=f"FAMILY_BLOCKED:{name}", payload={
                "family": name,
                "failure_class": klass,
                "reason": blocked_reason,
                "recovery": (
                    "fix the named condition, then resume: the family is re-examined "
                    "at every slice and at every rescan boundary"
                ),
            })
        elif outcome["state"] == FAMILY_WAITING:
            family["consecutive_failures"] = int(family.get("consecutive_failures") or 0) + 1
            backoff = retry_delay(family["consecutive_failures"], self.settings)
            _set_family(objective, name, state=FAMILY_WAITING,
                        reason=outcome.get("reason") or "temporarily unavailable",
                        failure_class=klass, now=now, backoff=backoff)
            self._bump_failure(objective, klass)
            self._arm_retry(objective, now=now, backoff=backoff,
                            reason=outcome.get("reason") or "temporarily unavailable",
                            klass=klass)
        produced = int(outcome.get("units") or 0)
        if produced:
            family["zero_progress_slices"] = 0
            # Work appeared, so any earlier completion verification is void.
            self.completion_rescanned = False
            if name == FAMILY_SEMANTIC:
                objective["semantic_units_completed"] = int(
                    objective.get("semantic_units_completed") or 0
                ) + produced
            else:
                objective["mechanical_units_completed"] = int(
                    objective.get("mechanical_units_completed") or 0
                ) + produced
        elif outcome["state"] == FAMILY_ACTIVE:
            family["zero_progress_slices"] = int(
                family.get("zero_progress_slices") or 0
            ) + 1
        if "intake_idle" in outcome:
            family["intake_idle"] = bool(outcome["intake_idle"])
        for key in ("settled",):
            if key in outcome:
                family[key] = bool(outcome[key])
        if "conflicts_now" in outcome:
            family["conflicts_now"] = int(outcome["conflicts_now"])
        if "stop_reason" in outcome:
            family["last_stop_reason"] = str(outcome["stop_reason"])
        if isinstance(outcome.get("backend"), dict) and outcome["backend"]:
            objective["backend"] = outcome["backend"]
        objective["cursor"]["mechanical_cycle"] = int(
            objective.get("cursor", {}).get("mechanical_cycle") or 0
        ) + (1 if name == FAMILY_MECHANICAL else 0)
        objective["cursor"]["semantic_units"] = int(objective["semantic_units_completed"])

    def _run_family(self, name: str, runner: Callable[[Path], dict], objective: dict) -> dict:
        try:
            result = runner(self.home)
        except PalError as exc:
            klass = classify_failure(code=str(exc.code), reason=str(exc.message or exc))
            if klass == FAILURE_UNSAFE:
                self._safety_stop(objective, invariant=str(exc.code), detail=str(exc.message or exc))
                return {"state": FAMILY_BLOCKED, "failure_class": klass,
                        "reason": str(exc.message or exc), "units": 0}
            return self._family_outcome_from_failure(klass, str(exc.message or exc))
        except Exception as exc:  # noqa: BLE001 - a durable objective never dies of a slice bug
            klass = classify_failure(reason=f"{type(exc).__name__}: {exc}")
            errors = objective.setdefault("failures", {})
            if klass == FAILURE_PERMANENT:
                errors["permanent"] = int(errors.get("permanent") or 0) + 1
            return self._family_outcome_from_failure(klass, f"{type(exc).__name__}: {exc}")

        if not isinstance(result, dict):
            return {"state": FAMILY_ACTIVE, "failure_class": FAILURE_NONE,
                    "reason": "slice returned no receipt", "units": 0}

        outcome = self._classify_slice(name, result)
        # The slice's OWN stop_reason is the only evidence of which wall stopped
        # it. FAILURE_CONFIGURATION covers at least three of them (runtime off,
        # config incomplete, authority unbound), so the next action cannot read
        # the failure class and name a route -- it would repeat the same advice
        # on an objective whose runtime is already live.
        outcome["stop_reason"] = str(result.get("stop_reason") or "")
        return outcome

    def _classify_slice(self, name: str, result: dict) -> dict:
        errors = result.get("errors")
        code = result.get("error_code") or result.get("code")
        stop_reason = result.get("stop_reason")
        klass = classify_failure(code=code, reason=_first_error_text(errors),
                                 stop_reason=stop_reason)
        units = int(result.get("units") or 0)
        backend = result.get("backend") if isinstance(result.get("backend"), dict) else {}

        if name == FAMILY_MECHANICAL:
            reported = int(result.get("events_analyzed") or 0)
            if result.get("ok") is False and klass in TRANSIENT_CLASSES:
                return self._family_outcome_from_failure(
                    klass, _first_error_text(errors) or "mechanical slice failed"
                )
            # A cycle reports TWO different facts and cpall needs both.
            # `intake_idle` is "no new evidence arrived and no session is in
            # CONFLICT"; `work_remaining` is "some indexed record still owes
            # locally processable episodes". A conflict is NOT mechanical work:
            # it is an isolated operator item, and `derive_state` already turns
            # "every family settled with conflicts left" into OPERATOR_BLOCKED.
            # Folding conflicts into this family's settle condition made the
            # family UNSETTLEABLE on any home that has a conflict at all
            # (measured: zero analysis debt, 11 CONFLICT sessions, `idle: False`
            # forever -- so the objective could never reach a terminal state).
            # `budget_hit` is a checkpoint boundary: it settles nothing.
            intake = result.get("intake")
            intake = intake if isinstance(intake, dict) else {}
            conflicts_now = int(
                intake.get("conflicted") or len(intake.get("conflicts") or [])
            )
            exported = int(result.get("sessions_indexed") or 0)
            if "work_remaining" in result or "intake_idle" in result:
                settled = (
                    not bool(result.get("work_remaining"))
                    and exported == 0
                    # `intake_idle: False` means "something arrived OR a conflict
                    # exists". Only a CONFLICT is forgiven here, because a
                    # conflict is an isolated operator item that `derive_state`
                    # answers for; an arrival is real work for the next cycle.
                    and (bool(result.get("intake_idle")) or conflicts_now > 0)
                )
            else:
                # A caller that answers only the terminal boolean.
                settled = bool(result.get("idle"))
            return {
                "state": FAMILY_DONE if settled else FAMILY_ACTIVE,
                "failure_class": FAILURE_NONE,
                "reason": (
                    "intake and mechanical analysis are idle"
                    if settled
                    else str(result.get("next_action") or "cycle advanced")
                ),
                "units": reported,
                "result": result,
                "intake_idle": bool(result.get("intake_idle", settled)),
                "settled": settled,
                "conflicts_now": conflicts_now,
            }

        # semantic family
        if stop_reason == "CONFIG_DISABLED":
            return self._family_outcome_from_failure(
                FAILURE_CONFIGURATION,
                "the analyst runtime is disabled; an operator must enable it",
            )
        if stop_reason == "CONFIGURATION_BLOCKED":
            return self._family_outcome_from_failure(
                FAILURE_CONFIGURATION,
                _first_error_text(errors) or "analyst configuration is incomplete",
            )
        detail = _slice_detail(result)
        if units <= 0 and names_unusable_configuration(detail):
            # An OPEN AUTH circuit and an unset key environment variable are the
            # same fact: the analyst cannot call its backend until an operator
            # changes the configuration. Reporting that as "the slice ran" and
            # retrying it forever would hide the one thing the operator has to
            # act on -- so the family BLOCKS (OPERATOR_BLOCKED once independent
            # work is exhausted) and the refusal itself becomes the reason. It is
            # checked BEFORE `ok is False`, because a refused transport reports
            # its own failure class and that class is not this wall.
            return self._family_outcome_from_failure(
                FAILURE_CONFIGURATION,
                detail or f"analyst configuration is unusable ({stop_reason})",
            )
        if result.get("ok") is False:
            return self._family_outcome_from_failure(
                klass, _first_error_text(errors) or f"semantic slice stopped: {stop_reason}"
            )
        if int(result.get("rate_limited") or 0):
            return self._family_outcome_from_failure(FAILURE_RATE_LIMIT, "rate limited")
        if units <= 0 and stop_reason == "RETRY_WAIT":
            return self._family_outcome_from_failure(FAILURE_TRANSIENT, "worker asked to retry")
        if units <= 0 and stop_reason in ("BLOCKED", "BLOCKED_BINDING"):
            # The analyst reached a wall for a unit and STOPPED with nothing
            # completed. The family stays runnable -- authority can improve, and
            # the worker journals the unit for revisiting -- but the wall is
            # named in the reason and counted in the ledger. Silently reporting
            # "the slice ran" with zero failures is how a run blocked on
            # protocol authority looks like a healthy one.
            note = detail
            wall = (
                "the analyst blocked the unit: historical binding is insufficient "
                "to compare against"
                if stop_reason == "BLOCKED_BINDING"
                else "the analyst blocked the unit on a backend or output failure"
            )
            if result.get("no_eligible_unit"):
                # The WORKER's authoritative answer, not a kernel estimate: the
                # eligible set is EMPTY and only blocked units remain. The kernel
                # still counts those episodes as outstanding, so a family that
                # stayed runnable here would report a backlog that can never
                # converge -- the objective would slice forever and never reach a
                # truthful terminal state. Authority and model capability are
                # operator decisions (PAL-CPALL-02), so the family BLOCKS; the
                # objective still answers OPERATOR_BLOCKED only once every other
                # family is DONE, and independent work continues first.
                output_blocks = int(result.get("jobs_blocked") or 0)
                binding_blocks = int(result.get("jobs_blocked_binding") or 0)
                # PAL-CPALL-04: a wall keeps its own owner, and the family reason
                # NAMES it. "an operator decision ... makes them eligible again"
                # is not actionable from the read the objective publishes -- the
                # operator still has to know that unbound authority is cured by
                # enrolling and rebinding rather than by re-running. The kernel
                # stays free of provider vocabulary, so the way back is named as
                # the kernel's own two verbs.
                recovery = (
                    " -- `authority enroll` + `rebind` makes them eligible again"
                    if stop_reason == "BLOCKED_BINDING"
                    else " -- an operator decision (authority, a different model, "
                    "or accepting the wall) makes them eligible again"
                )
                return {
                    "state": FAMILY_BLOCKED,
                    "failure_class": FAILURE_CONFIGURATION,
                    "reason": (
                        f"{wall}; the worker reports no eligible unit remains "
                        f"({output_blocks} backend/output blocked, {binding_blocks} "
                        "binding blocked)"
                        + recovery
                        + (f" ({note})" if note else "")
                    ),
                    "units": units,
                    "result": result,
                    "backend": backend,
                }
            return {
                "state": FAMILY_ACTIVE,
                "failure_class": FAILURE_PERMANENT,
                "reason": f"{wall} ({note})" if note else wall,
                "units": units,
                "result": result,
                "backend": backend,
            }
        # The worker examined its whole population and found nothing to do --
        # while the kernel still counts units without a verdict. Those units are
        # not absent, they are blocked: unbound authority, provisional work the
        # operator has not enabled, or model output the backend cannot judge.
        # Reporting that as "the slice ran" kept the family ACTIVE over a backlog
        # that could never converge, which is exactly the silent spin
        # PAL-CPALL-02 forbids. The classes are named so the reason is actionable.
        if units <= 0 and result.get("no_analyzable_unit"):
            outstanding = int(self._backlog().get("units_eligible_remaining") or 0)
            if outstanding > 0:
                classes = result.get("population_classes") or {}
                blocked_classes = ", ".join(
                    f"{count} {name.lower().replace('_', ' ')}"
                    for name, count in sorted(
                        classes.items(), key=lambda item: (-item[1], item[0])
                    )
                    if name not in ("RUNNABLE_FINAL", "RUNNABLE_PROVISIONAL")
                )
                # PAL-CPALL-04: a refused unit (the candidate contract said no)
                # is not lost -- it has a canonical, bounded way back. Naming the
                # command here means the wall is actionable from the same read
                # the objective publishes, instead of an operator grep.
                refused_units = int(classes.get("BLOCKED") or 0)
                unknown_remote = int(classes.get("REMOTE_OUTCOME_UNKNOWN") or 0)
                recover = (
                    f"; {refused_units} refused unit(s) have a canonical way "
                    "back: python -B tools/saipal.py analyst-requeue"
                    if refused_units
                    else ""
                )
                unknown_action = (
                    f"; {unknown_remote} REMOTE_OUTCOME_UNKNOWN attempt(s) "
                    "require explicit resolution under W2-005 and must not be "
                    "replayed automatically"
                    if unknown_remote
                    else ""
                )
                return {
                    "state": FAMILY_BLOCKED,
                    "failure_class": FAILURE_CONFIGURATION,
                    "reason": (
                        f"the worker reports no analyzable unit remains, yet "
                        f"{outstanding} unit(s) still lack a verdict"
                        + (f" ({blocked_classes})" if blocked_classes else "")
                        + "; an operator decision (authority, provisional "
                        "investigation, or a different model) makes them "
                        "analyzable again"
                        + recover
                        + unknown_action
                    ),
                    "units": units,
                    "result": result,
                    "backend": backend,
                }
        # A zero-unit slice is never allowed to declare the family DONE on its
        # own: completion is decided from durable coverage in
        # `_reconcile_families`, so "the worker had nothing to do" cannot pass
        # for "the backlog is empty" (the failure mode `--drain` had).
        # The worker's own sentence rides along: a family disposition that says
        # only "the slice ran" cannot answer "why did it skip a unit?", which is
        # the question a long autonomous run is judged on.
        reason = f"semantic slice ran ({stop_reason or 'OK'})"
        blocked_units = int(result.get("jobs_blocked") or 0) + int(
            result.get("jobs_blocked_binding") or 0
        )
        if blocked_units:
            # A slice can judge units AND block units. The block is a property of
            # those units, never of the family, so it is NAMED here instead of
            # backing the family off work that is still converging -- and a run
            # that blocked a unit can no longer read as an ordinary budget stop.
            reason = f"{reason}: {units} judged, {blocked_units} unit(s) blocked"
        if detail:
            reason = f"{reason}: {detail}"
        return {"state": FAMILY_ACTIVE, "failure_class": FAILURE_NONE,
                "reason": reason,
                "units": units, "result": result, "backend": backend}

    def _family_outcome_from_failure(self, klass: str, reason: str) -> dict:
        if klass == FAILURE_UNSAFE:
            return {"state": FAMILY_BLOCKED, "failure_class": klass, "reason": reason, "units": 0}
        if klass == FAILURE_CONFIGURATION:
            return {"state": FAMILY_BLOCKED, "failure_class": klass, "reason": reason, "units": 0}
        if klass == FAILURE_PERMANENT:
            # A permanent failure is still not a goal terminator while another
            # family can make progress, but the family itself goes WAITING with
            # backoff rather than re-running instantly forever.
            return {"state": FAMILY_WAITING, "failure_class": klass, "reason": reason, "units": 0}
        return {"state": FAMILY_WAITING, "failure_class": klass, "reason": reason, "units": 0}

    def _bump_failure(self, objective: dict, klass: str) -> None:
        errors = objective.setdefault("failures", {})
        key = {
            FAILURE_RATE_LIMIT: "rate_limit",
            FAILURE_TRANSIENT: "transient",
            FAILURE_PERMANENT: "permanent",
        }.get(klass)
        if key:
            errors[key] = int(errors.get(key) or 0) + 1

    def _arm_retry(self, objective: dict, *, now: float, backoff: float, reason: str,
                   klass: str) -> None:
        retry = objective.setdefault("retry", {})
        retry["attempts"] = int(retry.get("attempts") or 0) + 1
        retry["consecutive_failures"] = int(retry.get("consecutive_failures") or 0) + 1
        retry["next_attempt_at"] = _iso(now + max(0.0, backoff))
        retry["last_error_class"] = klass
        retry["last_error"] = reason
        objective["units_failed_retry"] = int(objective.get("units_failed_retry") or 0) + 1

    def _safety_stop(self, objective: dict, *, invariant: str, detail: str) -> None:
        objective["state"] = STATE_SAFETY_STOP
        objective["state_reason"] = f"invariant {invariant} violated: {detail}"
        objective["state_reason_class"] = FAILURE_UNSAFE
        objective["unresolved"] = list(objective.get("unresolved") or []) + [
            {"kind": "SAFETY_STOP", "invariant": invariant, "detail": detail,
             "recovery": (
                 "inspect the persisted objective and the named invariant; the run "
                 "resumes only through an explicit new `/goal cpall`"
             )},
        ]
        objective["next_action"] = f"resolve invariant {invariant} by hand"
        errors = objective.setdefault("failures", {})
        errors["safety_stops"] = int(errors.get("safety_stops") or 0) + 1
        self.summary["ok"] = False
        self.summary["safety_stop"] = {"invariant": invariant, "detail": detail}

    def _recompute(self, objective: dict, *, save: bool = True) -> dict:
        """Re-derive every count from durable state, then reconcile families."""
        previous_completed = int(objective.get("units_completed") or 0)
        previous_sessions = int(objective.get("sessions_completed") or 0)
        try:
            view = self._backlog()
            if (
                int(view["units_completed"]) > previous_completed
                or int(view["sessions_completed"]) > previous_sessions
            ):
                objective["last_progress_at"] = _iso(self._now())
                objective["last_progress_epoch"] = self._now()
        except PalError as exc:
            # A corpus we cannot read is a transient condition for the loop: the
            # objective keeps its last known truth and waits.
            self._bump_failure(objective, FAILURE_TRANSIENT)
            self._arm_retry(objective, now=self._now(),
                            backoff=retry_delay(int(objective.get("slices") or 1), self.settings),
                            reason=str(exc.message or exc), klass=FAILURE_TRANSIENT)
            objective["state"] = STATE_WAITING
            objective["state_reason"] = f"corpus unreadable: {exc.message or exc}"
            objective["state_reason_class"] = FAILURE_TRANSIENT
            objective["next_action"] = "retry once the session index is readable again"
            if save:
                self._save(objective)
            return {}

        rows = view["conflict_rows"]
        if self.conflict_rows is not None:
            try:
                rows = self.conflict_rows(self.home)
            except Exception:  # noqa: BLE001
                rows = view["conflict_rows"]
        reconciliation = isolate_conflicts(objective, rows, now=self._now())
        objective["conflicts"].update(
            {
                "current": int(view["conflicts_current"]),
                "indexed_total": int(view["conflicts_indexed"]),
                "superseded_total": int(view["conflicts_superseded"]),
                "isolated": reconciliation["isolated"],
                "last_scan_at": utc_now_iso(),
            }
        )
        if reconciliation["resolved"]:
            objective["conflicts"]["last_resolved"] = reconciliation["resolved"]

        objective["units_discovered"] = int(view["units_discovered"])
        objective["units_completed"] = int(view["units_completed"])
        objective["units_remaining"] = int(view["units_remaining"])
        objective["units_eligible_remaining"] = int(view["units_eligible_remaining"])
        objective["units_conflict"] = int(view["units_conflict"])
        objective["units_blocked"] = int(
            view["units_conflict"] + int(view["mechanical_pending"])
        )
        objective["sessions_total"] = int(view["sessions_total"])
        objective["sessions_completed"] = int(view["sessions_completed"])
        objective["mechanical_pending"] = int(view["mechanical_pending"])
        objective["source_fingerprint"] = view["source_fingerprint"]

        self._reconcile_families(objective, view)
        if save:
            self._save(objective)
        return view

    def _reconcile_families(self, objective: dict, view: dict) -> None:
        """Work-family exhaustion decided from durable counts, not from the loop.

        Durable coverage is authoritative in BOTH directions. A family cannot
        declare itself done by reporting "nothing to do" (that is how a bounded
        run reports a false idle), and a family that went DONE can be reopened
        by new evidence -- which is what makes `/goal cpall` converge over the
        live work graph rather than the snapshot taken at command time.
        """
        now = self._now()
        mechanical = _family(objective, FAMILY_MECHANICAL)
        semantic = _family(objective, FAMILY_SEMANTIC)
        pending = int(view["mechanical_pending"])
        eligible = int(view["units_eligible_remaining"])

        # Mechanical exhaustion needs THREE facts, each about a DIFFERENT debt:
        # no local analysis debt (`debt_free`), no evidence imported by the last
        # pass (`new_evidence`), and no delivered-audit debt (`pending`). Any one
        # alone would be a false done. Conflicts are deliberately NOT part of this
        # test -- an isolated conflict is an operator item that `derive_state`
        # answers for, and letting it unsettle the mechanical family made the
        # objective unable to reach a terminal state at all.
        if mechanical["state"] in (FAMILY_ACTIVE, FAMILY_DONE):
            # The cycle's own "settled" verdict carries the analysis reasoning
            # (no local debt, nothing imported, and any non-idle intake answer
            # explained by isolated conflicts); this adds the audit debt, which
            # the cycle cannot see.
            settled = bool(mechanical.get("settled", mechanical.get("intake_idle")))
            if settled and pending <= 0:
                mechanical["state"] = FAMILY_DONE
                mechanical["reason"] = (
                    "intake and mechanical analysis are idle and no audit is undelivered"
                )
                mechanical["next_attempt_at"] = None
            else:
                mechanical["state"] = FAMILY_ACTIVE
                if pending > 0:
                    mechanical["reason"] = f"{pending} undelivered audit(s)"
                else:
                    mechanical["reason"] = "intake or analysis work observed"
                mechanical["next_attempt_at"] = None

        if eligible <= 0 and semantic["state"] == FAMILY_ACTIVE:
            semantic["state"] = FAMILY_DONE
            semantic["reason"] = "no eligible semantic unit remains"
            semantic["next_attempt_at"] = None
            semantic["zero_progress_slices"] = 0
        elif eligible > 0 and semantic["state"] == FAMILY_DONE:
            semantic["state"] = FAMILY_ACTIVE
            semantic["reason"] = f"{eligible} eligible semantic unit(s) discovered"
            semantic["next_attempt_at"] = None

        # A semantic family that keeps returning without producing anything
        # while durable coverage still says work is owed is a discrepancy, not
        # progress. Back off and name it instead of hot-spinning for days.
        budget = max(1, int(self.settings.get("max_units_per_slice") or 1))
        streak_limit = max(3, budget)
        if (
            semantic["state"] == FAMILY_ACTIVE
            and eligible > 0
            and int(semantic.get("zero_progress_slices") or 0) >= streak_limit
        ):
            # A worker that keeps returning nothing while durable coverage still
            # owes work is a DISCREPANCY, not progress and not a backend outage.
            # Back off (so it can never hot-spin for days), name it, and keep
            # the objective alive rather than declaring a false idle.
            semantic["consecutive_failures"] = int(
                semantic.get("consecutive_failures") or 0
            ) + 1
            backoff = retry_delay(int(semantic["consecutive_failures"]), self.settings)
            semantic["state"] = FAMILY_WAITING
            semantic["reason"] = (
                f"{int(semantic.get('zero_progress_slices') or 0)} consecutive semantic "
                f"slices produced nothing while {eligible} eligible unit(s) remain"
            )
            semantic["next_attempt_at"] = _iso(now + backoff)
            objective["last_discrepancy_at"] = utc_now_iso()
            self._record_unresolved(
                objective,
                kind="SEMANTIC_NO_PROGRESS",
                payload={"eligible_remaining": eligible, "detail": semantic["reason"]},
            )

        # A family whose retry delay elapsed becomes executable again.
        for name in FAMILIES:
            entry = _family(objective, name)
            if entry["state"] == FAMILY_WAITING:
                due = _epoch(entry.get("next_attempt_at"))
                if due is None or due <= now:
                    entry["state"] = FAMILY_ACTIVE
                    entry["reason"] = "retry delay elapsed"
                    entry["next_attempt_at"] = None

        self._sync_retry_clock(objective, now=now)

    def _sync_retry_clock(self, objective: dict, *, now: float) -> None:
        """One retry clock for the process, derived from the waiting families.

        The run loop reads `retry.next_attempt_at`; the families own their own
        schedules. Without this derivation a family could be WAITING while the
        objective's clock said "nothing scheduled", and the loop -- seeing no
        delay to wait out -- would run the next slice immediately, forever. That
        is a hot spin that never lets the clock move, so the condition it waits
        for can never become true.
        """
        waits = [
            (_epoch(_family(objective, name).get("next_attempt_at")), name)
            for name in FAMILIES
            if _family(objective, name)["state"] == FAMILY_WAITING
        ]
        retry = objective.setdefault("retry", {})
        if not waits:
            retry["next_attempt_at"] = None
            return
        due = min(entry[0] if entry[0] is not None else now for entry in waits)
        retry["next_attempt_at"] = _iso(due)
        retry["last_error_class"] = str(
            _family(objective, waits[0][1]).get("last_error_class") or FAILURE_TRANSIENT
        )
        retry["last_error"] = _family(objective, waits[0][1]).get("last_error")

    def _clear_unresolved(self, objective: dict, kind: str) -> None:
        """Drop a named problem that no longer describes the durable state."""
        rows = [
            row
            for row in (objective.get("unresolved") or [])
            if not (isinstance(row, dict) and row.get("kind") == kind)
        ]
        objective["unresolved"] = rows

    def _record_unresolved(self, objective: dict, *, kind: str, payload: dict) -> None:
        """One entry per named problem, updated in place rather than appended."""
        rows = [row for row in (objective.get("unresolved") or [])
                if isinstance(row, dict) and row.get("kind") != kind]
        rows.append(dict(payload, kind=kind, detected_at=utc_now_iso()))
        objective["unresolved"] = rows[-10:]

    def _emit_operator_queue(self) -> dict:
        """Render and persist the operator queue for a blocked boundary.

        Best effort by construction: a rendering failure must never turn a
        truthful `OPERATOR_BLOCKED` into a crash or a `SAFETY_STOP`, because
        the state itself is still correct without the packet. When it fails the
        summary says so in words rather than omitting the key, so "no packet"
        is never mistaken for "nothing to report".
        """
        queue_mod = self.operator_queue
        if queue_mod is None:
            return {
                "ok": False,
                "code": "NOT_WIRED",
                "note": (
                    "this run was constructed without the operator-queue module, so the "
                    "boundary packet was not produced; run `saipal operator-queue` for it"
                ),
            }

        try:
            packet = queue_mod.build(self.home)
            boundary = dict(packet.get("boundary") or {})
            unassigned = int(boundary.get("unassigned_sessions") or 0)
            if not packet.get("ok") or unassigned:
                # A partition that does not re-sum to the population is not a
                # queue -- it is a partial view with an authoritative-sounding
                # count on it. Refuse to persist that rather than leave an
                # artifact whose numbers look total.
                return {
                    "ok": False,
                    "code": "VALIDATION_FAILED",
                    "unassigned_sessions": unassigned,
                    "population_sessions": boundary.get("population_sessions"),
                    "note": (
                        "the partition is incomplete, so no packet was written; "
                        "run `saipal operator-queue` for the detail"
                    ),
                }
            path = queue_mod.write_packet(self.home, packet)
        except Exception as exc:  # noqa: BLE001 -- a packet is not a state change
            return {
                "ok": False,
                "code": type(exc).__name__,
                "message": str(exc),
                "note": "the objective state stands; only the packet failed",
            }
        return {
            "ok": True,
            "packet": str(path),
            "digest": packet.get("corpus_digest"),
            "state": boundary.get("state"),
            "auto_drain_complete": boundary.get("auto_drain_complete"),
            "corpus_fully_resolved": boundary.get("corpus_fully_resolved"),
            "operator_work_remaining_sessions": boundary.get("operator_work_remaining_sessions"),
            "permanently_unverifiable_sessions": boundary.get(
                "permanently_unverifiable_sessions"
            ),
            "unsafe_to_replay_sessions": boundary.get("unsafe_to_replay_sessions"),
            "decisions": {
                str(d.get("decision")): d.get("sessions")
                for d in packet.get("decisions") or []
            },
        }

    def _next_action(self, objective: dict) -> str:
        state = objective["state"]
        if state == STATE_COMPLETED:
            return "objective complete; evidence is durable in the report log"
        if state == STATE_OPERATOR_BLOCKED:
            # PAL-CPALL-05: the queue is the whole boundary, so it is named. The
            # conflict route stays because a conflict is still a real, separate
            # wall -- the queue says which sessions, this says that a frozen
            # generation waits on a human either way.
            routes = ["resolve the isolated conflicts"]
            seen = [
                _RUNTIME_OFF_ROUTES[_family(objective, name)["last_stop_reason"]]
                for name in FAMILIES
                if _family(objective, name).get("last_stop_reason") in _RUNTIME_OFF_ROUTES
            ]
            routes.extend(dict.fromkeys(seen))
            routes.append(
                "work the operator queue in .saipal/operator_queue.json (every blocked "
                "session, one decision each; `saipal operator-queue` rebuilds it)"
            )
            return ", then ".join(routes) + ", then resume"
        if state == STATE_WAITING:
            return (
                "automatic retry at "
                f"{(objective.get('retry') or {}).get('next_attempt_at') or 'next probe'}"
            )
        if state == STATE_SAFETY_STOP:
            return "resolve the named invariant by hand"
        eligible = int(objective.get("units_eligible_remaining") or 0)
        pending = int(objective.get("mechanical_pending") or 0)
        if pending:
            return f"mechanical backlog: {pending} item(s) (staged audits / inbox bundles)"
        if eligible:
            return f"semantic carrier drain: {eligible} eligible unit(s) remain"
        return "no eligible work observed; rescanning sources"


def _first_error_text(errors: object) -> str:
    if isinstance(errors, str):
        return errors
    if isinstance(errors, list) and errors:
        first = errors[0]
        if isinstance(first, dict):
            return str(first.get("message") or first.get("detail") or first)
        return str(first)
    return ""


def run(
    home: Path | str,
    *,
    mechanical_slice: Callable[[Path], dict],
    semantic_slice: Callable[[Path], dict],
    registry: dict | None = None,
    settings: dict | None = None,
    clock: object = None,
    sleep_fn: Callable[[float], None] | None = None,
    stop_requested: Callable[[], bool] | None = None,
    max_slices: int = 0,
    probe_fn: Callable[[Path], dict] | None = None,
    conflict_rows: Callable[[Path], list[dict]] | None = None,
    backlog_fn: Callable[[Path], dict] | None = None,
    owner_id: str | None = None,
    operator_queue: Any = None,
) -> dict:
    """Continue the durable objective until it reaches a truthful terminal state.

    `max_slices` bounds a *process*, never the objective. Reaching it persists
    the objective exactly as it is and returns; the next invocation (or the
    installed supervisor) continues from the same durable cursor.
    """
    declared = settings_from_registry(registry) if settings is None else settings
    # ONE clock for the whole invocation. Every persisted timestamp -- lease
    # heartbeats, retry schedules, report cadence -- is derived from it, because
    # mixing an injected clock with `time.time()` makes a persisted deadline
    # land in the future of the clock that has to honour it. That is not a
    # cosmetic mismatch: a report epoch written from wall time and compared
    # against logical time silently disables the report cadence.
    clk = _as_clock(clock, sleep_fn)
    started_at = clk.now()
    attach = attach_or_start(
        home, registry=registry, settings=declared, now=started_at
    )
    objective = attach["objective"]
    status, objective, detail = load_objective(home)
    if status != "ok" or objective is None:
        raise PalError("STATE_UNRECOVERABLE", f"{CPALL_NAME} is unusable: {detail}")

    recovered = False
    if objective["state"] in TERMINAL_STATES:
        return {
            "ok": True,
            "command": "cpall",
            "objective_id": objective["objective_id"],
            "state": objective["state"],
            "terminal": True,
            "slices": 0,
            "stop_reason": objective["state"],
            "next_action": objective.get("next_action"),
        }

    live_owner = _owner_is_live(objective, now=started_at, settings=declared)
    current_owner = objective.get("owner") or {}
    if live_owner and int(current_owner.get("pid") or 0) not in (0, os.getpid()):
        # Single owner per objective: a second `/goal cpall` attaches to the
        # live objective instead of starting a second worker over the same home.
        return {
            "ok": True,
            "command": "cpall",
            "attached": True,
            "objective_id": objective["objective_id"],
            "state": objective["state"],
            "slices": 0,
            "stop_reason": "ATTACHED_TO_LIVE_OWNER",
            "owner": current_owner,
            "detail": (
                f"cpall already active; attached to existing objective "
                f"{objective['objective_id']} (owner pid {current_owner.get('pid')})"
            ),
            "next_action": "the live owner continues; query `saipal cpall --status`",
        }

    if owner_id is None:
        if attach["recovered_stale_owner"] or not current_owner.get("owner_id"):
            claim_ownership(objective, now=started_at, settings=declared, recovered=True)
            recovered = True
        owner_id = objective["owner"]["owner_id"]
        objective["owner"]["pid"] = os.getpid()
        objective["owner"]["heartbeat_at"] = _iso(started_at)
    elif not owns(objective, owner_id):
        claim_ownership(objective, now=started_at, settings=declared, recovered=True)
        objective["owner"]["owner_id"] = owner_id
        recovered = True

    # A report the wall clock stamped before this clock existed would silence
    # the cadence until the two agreed. Re-stamp rather than trust it.
    previous_epoch = _epoch(objective.get("last_report_at"))
    if previous_epoch is not None and previous_epoch > started_at:
        objective["last_report_at"] = _iso(started_at)
        objective["last_report_epoch"] = started_at

    if attach["resumed"] or recovered:
        report = progress_report(
            objective,
            kind=REPORT_RECOVERY if recovered else REPORT_START,
            now=started_at,
            extras={
                "recovered_stale_owner": bool(attach["recovered_stale_owner"] or recovered),
                "previous_state": attach.get("state"),
            },
        )
        if append_report(home, report):
            objective["reports"]["delivered"] = int(
                objective["reports"].get("delivered") or 0
            ) + 1
        objective["last_report_at"] = _iso(started_at)
        objective["last_report_epoch"] = started_at

    supervisor = CpallRun(
        home,
        mechanical_slice=mechanical_slice,
        semantic_slice=semantic_slice,
        registry=registry,
        settings=declared,
        clock=clk,
        probe_fn=probe_fn,
        conflict_rows=conflict_rows,
        backlog_fn=backlog_fn,
        operator_queue=operator_queue,
    )
    if not int(max_slices):
        max_slices = int(declared.get("max_slices_per_process") or 0)
    supervisor._recompute(objective, save=False)
    objective["state"], reason, klass = derive_state(objective)
    objective["state_reason"] = reason
    objective["state_reason_class"] = klass
    objective["next_action"] = supervisor._next_action(objective)
    save_objective(home, objective, registry=registry)
    return supervisor.run(
        objective=objective, owner_id=owner_id, max_slices=max_slices,
        stop_requested=stop_requested,
    )


def summary_for_report(home: Path | str, *, limit: int = 5) -> dict:
    """The durable report tail, for `status`/`report` surfaces."""
    reports = load_reports(home, limit=200)
    return {
        "reports_total": len(reports),
        "recent": reports[-max(1, int(limit)):],
    }


__all__ = [
    "CPALL_SCHEMA_VERSION",
    "CPALL_STATES",
    "FAMILIES",
    "RESUMABLE_STATES",
    "TERMINAL_STATES",
    "STATE_ACTIVE",
    "STATE_WAITING",
    "STATE_OPERATOR_BLOCKED",
    "STATE_COMPLETED",
    "STATE_SAFETY_STOP",
    "STATE_CANCELLED",
    "attach_or_start",
    "backlog",
    "cancel",
    "classify_failure",
    "conflict_evidence",
    "derive_state",
    "fresh_objective",
    "load_objective",
    "load_reports",
    "objective_path",
    "progress_report",
    "recover",
    "render_report_text",
    "retry_delay",
    "run",
    "save_objective",
    "settings_from_registry",
    "status",
    "summary_for_report",
]
