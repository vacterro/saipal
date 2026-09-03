"""STATE.json -- the carrier state, and the only one.

Recovery is refusal, not repair (PAL-BOOT-02). A state file SAIPAL cannot
understand is left exactly as it was found, because overwriting it would
destroy the evidence an operator needs to understand the failure.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .capability import require_action
from .errors import PalError
from .paths import atomic_write_json, home_paths, read_json, utc_now_iso
from .registry import load_registry, require_mapping, require_string_list

STATE_OK = "ok"
STATE_ABSENT = "absent"
STATE_UNRECOVERABLE = "unrecoverable"

OPTIONAL_STRING_FIELDS = (
    "current_session",
    "current_episode",
    "current_candidate",
    "maintainer_root",
    "last_checkpoint",
    "updated",
)


def fresh_state(*, registry: dict | None = None) -> dict:
    data = registry if registry is not None else load_registry()
    spec = require_mapping(data, "state")
    queue = {name: 0 for name in require_string_list(spec, "queue_fields")}
    return {
        "schema_version": int(spec.get("schema_version", 1)),
        "phase": "IDLE",
        "current_session": None,
        "current_episode": None,
        "current_candidate": None,
        "queue": queue,
        "maintainer_root": None,
        "next_action": "saipal continue",
        "last_checkpoint": None,
        "updated": None,
    }


def validate_state(state: object, *, registry: dict | None = None) -> list[str]:
    """Every reason `state` is unusable, or an empty list."""
    data = registry if registry is not None else load_registry()
    spec = require_mapping(data, "state")

    if not isinstance(state, dict):
        return ["state root is not an object"]

    problems: list[str] = []

    expected_schema = int(spec.get("schema_version", 1))
    if state.get("schema_version") != expected_schema:
        problems.append(
            f"schema_version {state.get('schema_version')!r} != {expected_schema}"
        )

    required = require_string_list(spec, "required_fields")
    known = set(require_string_list(spec, "known_fields"))
    phase_enum = set(require_string_list(spec, "phase_enum"))
    queue_fields = list(require_string_list(spec, "queue_fields"))

    for field in required:
        if field not in state:
            problems.append(f"missing required field {field!r}")
    for field in sorted(set(state) - known):
        problems.append(f"unknown field {field!r}")

    if "phase" in state and state["phase"] not in phase_enum:
        problems.append(f"phase {state['phase']!r} outside {sorted(phase_enum)}")

    if "next_action" in state and not (
        isinstance(state["next_action"], str) and state["next_action"].strip()
    ):
        problems.append("next_action must be a non-empty string")

    for field in OPTIONAL_STRING_FIELDS:
        if field in state and state[field] is not None and not isinstance(state[field], str):
            problems.append(f"{field} must be a string or null")

    if "queue" in state:
        queue = state["queue"]
        if not isinstance(queue, dict):
            problems.append("queue must be an object")
        else:
            for field in queue_fields:
                if field not in queue:
                    problems.append(f"queue missing field {field!r}")
                elif not isinstance(queue[field], int) or isinstance(queue[field], bool):
                    problems.append(f"queue[{field!r}] must be an integer")
                elif queue[field] < 0:
                    problems.append(f"queue[{field!r}] must not be negative")
            for field in sorted(set(queue) - set(queue_fields)):
                problems.append(f"queue has unknown field {field!r}")

    return problems


def load_state(
    home: Path | str, *, registry: dict | None = None
) -> tuple[str, dict[str, Any] | None, str]:
    """`(status, state, detail)` where status is ok / absent / unrecoverable."""
    paths = home_paths(home)
    if not paths.state.exists():
        return STATE_ABSENT, None, ""

    try:
        payload = read_json(paths.state)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return STATE_UNRECOVERABLE, None, f"STATE.json is unreadable: {exc}"

    problems = validate_state(payload, registry=registry)
    if problems:
        return STATE_UNRECOVERABLE, None, "; ".join(problems)
    return STATE_OK, payload, ""


def save_state(
    home: Path | str, state: dict, *, registry: dict | None = None
) -> dict:
    """Validate then atomically replace STATE.json. Raises on a bad state."""
    require_action("write_own_state", registry=registry)

    problems = validate_state(state, registry=registry)
    if problems:
        raise PalError(
            "STATE_UNRECOVERABLE",
            "refusing to write an invalid state: " + "; ".join(problems),
            next_action="the existing STATE.json was left untouched",
        )

    payload = dict(state)
    payload["updated"] = utc_now_iso()
    paths = home_paths(home)
    atomic_write_json(paths.state, payload, root=paths.root)
    return payload
