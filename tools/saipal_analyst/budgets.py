"""Durable cross-run budgets and circuit breakers: `.saipal/analyst/budget.json`.

Per-command budgets cannot bound an unattended loop: a watch that restarts
runs would reset them forever. This module owns the durable ledger:

- FIXED hourly windows (UTC epoch hour) for model attempts and semantic
  units, surviving restart; a failed transport attempt is still an attempt.
- A conservative clock-rollback response: wall time moving backwards freezes
  new model calls until the recorded window catches up, instead of granting
  extra budget. No heuristic "extra allowance" exists.
- A backend circuit breaker (CLOSED/OPEN/HALF_OPEN) driven ONLY by
  transport/backend failures -- never by semantic output. Retryable outages
  reopen on time with exponential backoff; AUTH failures stay open until the
  analyst config materially changes (digest pin) or an operator clears it.
- Per-source circuit state keyed by source id, so one broken source never
  freezes another (consumed by the source-health surfaces).

The ledger is observational/operational state, never semantic authority:
corrupt state is a loud refusal, never a silent reset.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from saipal_engine.errors import PalError
from saipal_engine.paths import atomic_write_json, home_paths, read_json

BUDGET_SCHEMA_VERSION = 1
BUDGET_NAME = "budget.json"

CIRCUIT_CLOSED = "CLOSED"
CIRCUIT_OPEN = "OPEN"
CIRCUIT_HALF_OPEN = "HALF_OPEN"

#: Consecutive transport failures that trip the backend circuit.
CIRCUIT_TRIP_THRESHOLD = 5
#: Base reopen delay for a retryable outage; doubles per re-trip, capped.
CIRCUIT_BASE_OPEN_SECONDS = 300.0
CIRCUIT_MAX_OPEN_SECONDS = 1800.0
#: Wall-clock rollback tolerated before the conservative freeze engages.
CLOCK_SKEW_SECONDS = 5.0

LEDGER_FIELDS = (
    "schema_version",
    "updated_at",
    "windows",
    "last_seen_wall",
    "rollback_freeze",
    "backend_circuit",
    "source_circuits",
)

WINDOW_FIELDS = ("hour", "model_attempts", "units", "input_tokens", "output_tokens")
CIRCUIT_FIELDS = (
    "state",
    "consecutive_failures",
    "opened_at",
    "open_until",
    "open_seconds",
    "failure_class",
    "config_digest",
    "detail",
)


def ledger_path(home: Path | str) -> Path:
    return jobs_ledger_dir(home) / BUDGET_NAME


def jobs_ledger_dir(home: Path | str) -> Path:
    from . import jobs as jobs_mod

    return jobs_mod.journal_dir(home)


def fresh_ledger() -> dict:
    return {
        "schema_version": BUDGET_SCHEMA_VERSION,
        "updated_at": "",
        "windows": {},
        "last_seen_wall": None,
        "rollback_freeze": False,
        "backend_circuit": {
            "state": CIRCUIT_CLOSED,
            "consecutive_failures": 0,
            "opened_at": None,
            "open_until": None,
            "open_seconds": CIRCUIT_BASE_OPEN_SECONDS,
            "failure_class": None,
            "config_digest": None,
        },
        "source_circuits": {},
    }


def load_ledger(home: Path | str) -> dict:
    path = ledger_path(home)
    if not path.exists():
        return fresh_ledger()
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise PalError(
            "VALIDATION_FAILED",
            f"analyst budget ledger is unreadable: {exc}",
            next_action="repair or remove .saipal/analyst/budget.json by hand",
        ) from None
    problems = ledger_problems(payload)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "analyst budget ledger is invalid: " + "; ".join(problems[:5]),
        )
    return payload


def save_ledger(home: Path | str, ledger: dict) -> Path:
    problems = ledger_problems(ledger)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "refusing invalid budget ledger: " + "; ".join(problems[:5]),
        )
    from time import gmtime, strftime

    ledger["updated_at"] = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
    return atomic_write_json(ledger_path(home), ledger, root=home_paths(home).root)


def ledger_problems(payload: object) -> list[str]:
    if not isinstance(payload, dict):
        return ["budget ledger root is not an object"]
    if payload.get("schema_version") != BUDGET_SCHEMA_VERSION:
        return [f"schema_version must be {BUDGET_SCHEMA_VERSION}"]
    for key in sorted(set(payload) - set(LEDGER_FIELDS)):
        return [f"unknown budget ledger field {key!r}"]
    problems: list[str] = []
    windows = payload.get("windows")
    if not isinstance(windows, dict):
        return ["windows must be an object"]
    for hour, window in windows.items():
        if not isinstance(hour, str) or not hour.isdigit():
            problems.append(f"window key {hour!r} must be an epoch-hour integer string")
            continue
        if not isinstance(window, dict):
            problems.append(f"window {hour} is not an object")
            continue
        for key in sorted(set(window) - set(WINDOW_FIELDS)):
            problems.append(f"window {hour} has unknown field {key!r}")
    circuit = payload.get("backend_circuit")
    if not isinstance(circuit, dict):
        problems.append("backend_circuit must be an object")
    else:
        problems.extend(_circuit_problems("backend_circuit", circuit))
    sources = payload.get("source_circuits")
    if not isinstance(sources, dict):
        problems.append("source_circuits must be an object")
    else:
        for source_id, circuit in sources.items():
            problems.extend(_circuit_problems(f"source_circuits[{source_id!r}]", circuit))
    return problems


def _circuit_problems(label: str, circuit: dict) -> list[str]:
    problems: list[str] = []
    for key in sorted(set(circuit) - set(CIRCUIT_FIELDS)):
        problems.append(f"{label} has unknown field {key!r}")
    if circuit.get("state") not in (CIRCUIT_CLOSED, CIRCUIT_OPEN, CIRCUIT_HALF_OPEN):
        problems.append(f"{label}.state {circuit.get('state')!r} is not a circuit state")
    return problems


def _hour(now: float) -> str:
    return str(int(now // 3600))


def _window(ledger: dict, now: float) -> dict:
    windows = ledger.setdefault("windows", {})
    # Keep at most the current and the previous hour: bounded state.
    current = _hour(now)
    previous = str(int(now // 3600) - 1)
    for key in sorted(windows):
        if key not in (current, previous):
            del windows[key]
    return windows.setdefault(
        current,
        {
            "hour": current,
            "model_attempts": 0,
            "units": 0,
            "input_tokens": 0,
            "output_tokens": 0,
        },
    )


def _rollback_recovered(ledger: dict, now: float) -> bool:
    """W2-003: is trusted wall time past the pre-rollback high-water mark?

    The freeze is a RECOVERABLE condition, not a one-way latch: while observed
    time is below the previously trusted high-water mark no new allowance may
    be granted from an older/emptier hour, but once wall time reaches or
    exceeds that mark the freeze clears deterministically -- no operator edit,
    no state deletion, and no model call required first.
    """
    last_seen = ledger.get("last_seen_wall")
    if not isinstance(last_seen, (int, float)):
        return True
    # STRICTLY past the mark: equal-or-earlier time is still inside the
    # suspicious window the freeze exists to cover.
    return now > float(last_seen)


def record_consumption(
    home: Path | str,
    *,
    now: float | None = None,
    model_attempts: int = 0,
    units: int = 0,
    input_tokens: int = 0,
    output_tokens: int = 0,
) -> dict:
    """Charge the durable window. One transport attempt == one charge."""
    ledger = load_ledger(home)
    now = time.time() if now is None else float(now)
    last_seen = ledger.get("last_seen_wall")
    if isinstance(last_seen, (int, float)) and now < float(last_seen) - CLOCK_SKEW_SECONDS:
        # Wall time moved backwards: freeze conservatively. Budget is never
        # granted by suspicious clock movement.
        ledger["rollback_freeze"] = True
    elif ledger.get("rollback_freeze") and _rollback_recovered(ledger, now):
        # W2-003: trusted wall time has caught up with the high-water mark;
        # reconcile the freeze instead of requiring an operator to edit state.
        ledger["rollback_freeze"] = False
    ledger["last_seen_wall"] = max(now, float(last_seen or now))
    window = _window(ledger, now)
    window["model_attempts"] += int(model_attempts)
    window["units"] += int(units)
    window["input_tokens"] += int(input_tokens)
    window["output_tokens"] += int(output_tokens)
    save_ledger(home, ledger)
    return ledger


def window_usage(home: Path | str, now: float | None = None) -> dict:
    ledger = load_ledger(home)
    now = time.time() if now is None else float(now)
    current = (ledger.get("windows") or {}).get(_hour(now)) or {
        "model_attempts": 0,
        "units": 0,
        "input_tokens": 0,
        "output_tokens": 0,
    }
    return {
        "hour": _hour(now),
        "model_attempts": int(current.get("model_attempts") or 0),
        "units": int(current.get("units") or 0),
        "input_tokens": int(current.get("input_tokens") or 0),
        "output_tokens": int(current.get("output_tokens") or 0),
        "rollback_freeze": bool(ledger.get("rollback_freeze")),
    }


def budget_allows(
    home: Path | str,
    *,
    limits: dict,
    now: float | None = None,
) -> tuple[bool, str]:
    """Global hourly gate: (allowed, reason). Read-only."""
    max_attempts = limits.get("max_model_attempts_per_hour")
    max_units = limits.get("max_semantic_units_per_hour")
    if max_attempts is None and max_units is None:
        return True, ""
    ledger = load_ledger(home)
    now = time.time() if now is None else float(now)
    if ledger.get("rollback_freeze"):
        if not _rollback_recovered(ledger, now):
            return False, "wall clock moved backwards; model calls are frozen until trusted time passes the recorded high-water mark"
        # W2-003: the freeze has recovered -- allow, and let the next
        # record_consumption clear the latch durably.
    now = time.time() if now is None else float(now)
    usage = window_usage(home, now)
    if max_attempts is not None and usage["model_attempts"] >= int(max_attempts):
        return False, f"global hourly model attempt budget {max_attempts} reached"
    if max_units is not None and usage["units"] >= int(max_units):
        return False, f"global hourly semantic unit budget {max_units} reached"
    return True, ""


# ---------------------------------------------------------------------------
# Backend circuit breaker
# ---------------------------------------------------------------------------


def _config_digest(home: Path | str) -> str:
    from .config import analyst_config_path

    path = analyst_config_path(home)
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def backend_circuit(home: Path | str) -> dict:
    ledger = load_ledger(home)
    return dict(ledger.get("backend_circuit") or {})


def circuit_allows(home: Path | str, *, now: float | None = None) -> tuple[bool, str]:
    """May a transport attempt start? Read-only."""
    ledger = load_ledger(home)
    circuit = ledger.get("backend_circuit") or {}
    state = circuit.get("state")
    now = time.time() if now is None else float(now)
    if state == CIRCUIT_OPEN:
        open_until = circuit.get("open_until")
        if open_until is None:
            # AUTH-class open: stays until the config materially changes.
            if circuit.get("config_digest") == _config_digest(home):
                return False, f"backend circuit OPEN after {circuit.get('failure_class')}; fix the configuration to half-open it"
            return True, ""
        if float(open_until) > now:
            return False, f"backend circuit OPEN until {open_until:.0f}"
        return True, ""
    if state == CIRCUIT_HALF_OPEN:
        return True, ""
    return True, ""


def record_backend_success(home: Path | str) -> dict:
    ledger = load_ledger(home)
    circuit = ledger.setdefault(
        "backend_circuit",
        {
            "state": CIRCUIT_CLOSED,
            "consecutive_failures": 0,
            "opened_at": None,
            "open_until": None,
            "open_seconds": CIRCUIT_BASE_OPEN_SECONDS,
            "failure_class": None,
            "config_digest": None,
        },
    )
    circuit["state"] = CIRCUIT_CLOSED
    circuit["consecutive_failures"] = 0
    circuit["open_until"] = None
    circuit["failure_class"] = None
    save_ledger(home, ledger)
    return circuit


#: W2-004: circuit policy is driven by the FAILURE CLASS, not a Boolean.
#: Only AUTH is "the configuration is unusable for the whole backend".
#: PERMANENT (e.g. one malformed request / HTTP 400) and LIMIT (e.g. one
#: oversized response) are REQUEST-scoped: the affected job is blocked by the
#: worker, but unrelated units must stay runnable.
CIRCUIT_GLOBAL_CLASSES = frozenset({"AUTH"})
CIRCUIT_TIMED_CLASSES = frozenset({"RETRYABLE"})
CIRCUIT_JOB_SCOPED_CLASSES = frozenset({"PERMANENT", "LIMIT"})


def record_backend_failure(
    home: Path | str,
    *,
    failure_class: str,
    retryable: bool,
    now: float | None = None,
) -> dict:
    """One transport/backend failure. Semantic output failures never land here."""
    ledger = load_ledger(home)
    circuit = ledger.setdefault(
        "backend_circuit",
        {
            "state": CIRCUIT_CLOSED,
            "consecutive_failures": 0,
            "opened_at": None,
            "open_until": None,
            "open_seconds": CIRCUIT_BASE_OPEN_SECONDS,
            "failure_class": None,
            "config_digest": None,
        },
    )
    now = time.time() if now is None else float(now)
    circuit["consecutive_failures"] = int(circuit.get("consecutive_failures") or 0) + 1
    circuit["failure_class"] = failure_class

    if circuit["state"] == CIRCUIT_HALF_OPEN and not retryable:
        # A probe that failed re-trips with a longer open window.
        pass

    consecutive = int(circuit["consecutive_failures"])
    opened_now = False
    if failure_class in CIRCUIT_GLOBAL_CLASSES:
        # AUTH/config: open until the configuration materially changes.
        circuit["state"] = CIRCUIT_OPEN
        circuit["opened_at"] = now
        circuit["open_until"] = None
        circuit["config_digest"] = _config_digest(home)
        opened_now = True
    elif failure_class in CIRCUIT_TIMED_CLASSES and consecutive >= CIRCUIT_TRIP_THRESHOLD:
        open_seconds = min(
            float(circuit.get("open_seconds") or CIRCUIT_BASE_OPEN_SECONDS),
            CIRCUIT_MAX_OPEN_SECONDS,
        )
        circuit["state"] = CIRCUIT_OPEN
        circuit["opened_at"] = now
        circuit["open_until"] = now + open_seconds
        circuit["open_seconds"] = min(open_seconds * 2, CIRCUIT_MAX_OPEN_SECONDS)
        opened_now = True
    # elif PERMANENT/LIMIT: job-scoped only. `_transport_failure` already
    # blocks the affected job; the global circuit stays CLOSED so one bad
    # request or one oversized response can never freeze unrelated work.
    if not opened_now and circuit["state"] == CIRCUIT_OPEN and failure_class in CIRCUIT_TIMED_CLASSES:
        circuit["state"] = CIRCUIT_OPEN
    save_ledger(home, ledger)
    return circuit


def circuit_probe_allowed(home: Path | str, *, now: float | None = None) -> dict:
    """Demote an expired OPEN to HALF_OPEN for one probe."""
    ledger = load_ledger(home)
    circuit = ledger.get("backend_circuit") or {}
    now = time.time() if now is None else float(now)
    if circuit.get("state") == CIRCUIT_OPEN and circuit.get("open_until") is not None:
        if float(circuit["open_until"]) <= now:
            circuit["state"] = CIRCUIT_HALF_OPEN
            save_ledger(home, ledger)
    return circuit


# ---------------------------------------------------------------------------
# Source circuits (one broken source never freezes another)
# ---------------------------------------------------------------------------

#: The material source configuration identity. Transcript/model data never
#: participates: only the operator-owned config fields are digested.
SOURCE_CONFIG_FIELDS = ("id", "kind", "path", "enabled")

#: TRANSIENT failures trip a time-based OPEN with a bounded probe window.
#: CONFIGURATION failures (the configured path is gone) open until the
#: material configuration changes or the operator corrects the filesystem.
SOURCE_FAILURE_TRANSIENT = "TRANSIENT"
SOURCE_FAILURE_CONFIGURATION = "CONFIGURATION"


def source_config_digest(source: dict) -> str:
    """Deterministic digest of the source's material configuration."""
    material = "\n".join(f"{k}={source.get(k)}" for k in SOURCE_CONFIG_FIELDS)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def source_failure_class(source: dict) -> str:
    """CONFIGURATION failure = the configured path is gone; TRANSIENT otherwise."""
    try:
        exists = Path(str(source.get("path") or "")).exists()
    except OSError:
        exists = False
    return SOURCE_FAILURE_CONFIGURATION if not exists else SOURCE_FAILURE_TRANSIENT


def record_source_failure(
    home: Path | str,
    source_id: str,
    *,
    detail: str = "",
    failure_class: str = SOURCE_FAILURE_TRANSIENT,
    config_digest: str | None = None,
    now: float | None = None,
) -> dict:
    """One source dispatch failure. Configuration changes reset the poison."""
    ledger = load_ledger(home)
    circuits = ledger.setdefault("source_circuits", {})
    circuit = circuits.get(source_id)
    if circuit is None:
        circuit = {
            "state": CIRCUIT_CLOSED,
            "consecutive_failures": 0,
            "opened_at": None,
            "open_until": None,
            "open_seconds": CIRCUIT_BASE_OPEN_SECONDS,
            "failure_class": failure_class,
            "config_digest": config_digest,
        }
        circuits[source_id] = circuit
    if config_digest is not None and circuit.get("config_digest") not in (
        None,
        config_digest,
    ):
        # Material configuration change: the old poison never blocks the new
        # configuration. The failure count starts over for the new identity.
        circuit["state"] = CIRCUIT_CLOSED
        circuit["consecutive_failures"] = 0
        circuit["open_until"] = None
    now = time.time() if now is None else float(now)
    circuit["consecutive_failures"] = int(circuit.get("consecutive_failures") or 0) + 1
    circuit["failure_class"] = failure_class
    if config_digest is not None:
        circuit["config_digest"] = config_digest
    if detail:
        circuit["detail"] = detail[:200]
    consecutive = int(circuit["consecutive_failures"])
    if failure_class == SOURCE_FAILURE_CONFIGURATION:
        # A known-invalid configuration stays open: it is recovered only by a
        # material config change (digest above) or an explicit operator
        # correction on the filesystem -- never by polling the dead path.
        circuit["state"] = CIRCUIT_OPEN
        circuit["opened_at"] = now
        circuit["open_until"] = None
    elif consecutive >= CIRCUIT_TRIP_THRESHOLD:
        open_seconds = min(
            float(circuit.get("open_seconds") or CIRCUIT_BASE_OPEN_SECONDS),
            CIRCUIT_MAX_OPEN_SECONDS,
        )
        circuit["state"] = CIRCUIT_OPEN
        circuit["opened_at"] = now
        circuit["open_until"] = now + open_seconds
        circuit["open_seconds"] = min(open_seconds * 2, CIRCUIT_MAX_OPEN_SECONDS)
    save_ledger(home, ledger)
    return circuit


def record_source_success(
    home: Path | str, source_id: str, *, config_digest: str | None = None
) -> dict:
    ledger = load_ledger(home)
    circuits = ledger.setdefault("source_circuits", {})
    circuit = circuits.get(source_id)
    if circuit is not None:
        circuit["state"] = CIRCUIT_CLOSED
        circuit["consecutive_failures"] = 0
        circuit["open_until"] = None
        circuit["failure_class"] = None
        if config_digest is not None:
            circuit["config_digest"] = config_digest
    save_ledger(home, ledger)
    return circuit or {}


def source_circuits(home: Path | str) -> dict:
    return dict(load_ledger(home).get("source_circuits") or {})


def source_circuit_allows(
    home: Path | str,
    source: dict,
    *,
    now: float | None = None,
    path_exists: bool | None = None,
) -> tuple[bool, str]:
    """May this source dispatch? (allowed, reason).

    A due OPEN is demoted to HALF_OPEN for exactly one probe per cycle. While
    OPEN and not due the source is skipped WITHOUT incrementing any failure
    count -- no busy loop. A material configuration change (different config
    digest) re-evaluates the circuit from scratch.
    """
    ledger = load_ledger(home)
    circuits = ledger.get("source_circuits") or {}
    circuit = circuits.get(str(source.get("id") or ""))
    if not isinstance(circuit, dict):
        return True, ""
    state = circuit.get("state")
    if state in (None, CIRCUIT_CLOSED, CIRCUIT_HALF_OPEN):
        return True, ""
    assert state == CIRCUIT_OPEN
    digest = source_config_digest(source)
    if circuit.get("config_digest") not in (None, digest):
        # Material configuration change: the old poison must not block the
        # new configuration.
        return True, ""
    now = time.time() if now is None else float(now)
    open_until = circuit.get("open_until")
    if open_until is None:
        # CONFIGURATION-class open: recover only through an operator
        # correction (the path exists again) -- one cheap existence probe,
        # never an adapter dispatch into a dead path.
        if path_exists is None:
            try:
                path_exists = Path(str(source.get("path") or "")).exists()
            except OSError:
                path_exists = False
        if not path_exists:
            return (
                False,
                f"source circuit OPEN after {circuit.get('failure_class')}; "
                "fix the configuration or restore the path to half-open it",
            )
        circuit["state"] = CIRCUIT_HALF_OPEN
        save_ledger(home, ledger)
        return True, ""
    if float(open_until) > now:
        return False, f"source circuit OPEN until {float(open_until):.0f}"
    circuit["state"] = CIRCUIT_HALF_OPEN
    save_ledger(home, ledger)
    return True, ""
