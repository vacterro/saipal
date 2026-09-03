"""The write boundary (PAL-WRITE-01).

SAIPAL's action namespace is the authority, not the caller's intent. An action
is allowed, reserved for a later wave, or forbidden. Anything unrecognized is
denied, because a boundary that guesses is not a boundary.

A denied action performs zero writes -- that is the whole point.
"""

from __future__ import annotations

from pathlib import Path

from .errors import PalError
from .paths import prove_inside
from .registry import load_registry, require_mapping, require_string_list

CAPABILITY_DENIED = "CAPABILITY_DENIED"
ACTION_RESERVED = "ACTION_RESERVED"
ACTION_OK = "OK"


def action_sets(
    registry: dict | None = None,
) -> tuple[frozenset, frozenset, frozenset]:
    """`(allowed, reserved, forbidden)` straight from the registry."""
    data = registry if registry is not None else load_registry()
    actions = require_mapping(data, "write_actions")
    return (
        frozenset(require_string_list(actions, "allowed")),
        frozenset(require_string_list(actions, "reserved")),
        frozenset(require_string_list(actions, "forbidden")),
    )


def assert_action_capability(
    action: str, *, registry: dict | None = None
) -> tuple[bool, str, str]:
    """`(allowed, code, detail)` for one action.

    Reserved actions are denied with `ACTION_RESERVED` rather than
    `CAPABILITY_DENIED`: the two mean different things and a maintainer reading
    an audit needs to know which one happened.
    """
    allowed, reserved, forbidden = action_sets(registry)

    if action in forbidden:
        return (
            False,
            CAPABILITY_DENIED,
            f"action {action!r} is forbidden forever; SAIPAL never touches the "
            "analyzed project or SAIPEN Core",
        )
    if action in reserved:
        return (
            False,
            ACTION_RESERVED,
            f"action {action!r} is declared but unavailable; no constrained "
            "interface is registered",
        )
    if action in allowed:
        return True, ACTION_OK, ""
    return (
        False,
        CAPABILITY_DENIED,
        f"action {action!r} is outside the closed action set; deny by default",
    )


def require_action(action: str, *, registry: dict | None = None) -> None:
    """Raise `PalError` unless the action is allowed."""
    permitted, code, detail = assert_action_capability(action, registry=registry)
    if not permitted:
        raise PalError(
            code,
            detail,
            next_action="no write was performed",
        ) from None


def guard_home_write(path: Path | str, *, home: Path | str) -> Path:
    """Prove a write target is inside SAIPAL's own home, or refuse."""
    try:
        return prove_inside(home, path)
    except PalError as exc:
        raise PalError(
            exc.code,
            exc.message,
            next_action="SAIPAL writes only inside its own home",
        ) from exc


def may_touch_saipen_core(action: str, *, registry: dict | None = None) -> bool:
    """Always False. Kept as an executable assertion for the test suite."""
    permitted, _, _ = assert_action_capability(action, registry=registry)
    return permitted and action.startswith("mutate_saipen")


def analyst_action_sets(registry: dict | None = None) -> tuple[frozenset, frozenset]:
    """`(allowed, forbidden)` for Layer B, a namespace of its own."""
    data = registry if registry is not None else load_registry()
    actions = require_mapping(data, "analyst_actions")
    return (
        frozenset(require_string_list(actions, "allowed")),
        frozenset(require_string_list(actions, "forbidden")),
    )


def require_analyst_action(action: str, *, registry: dict | None = None) -> None:
    """Raise unless Layer B may perform this action.

    Layer B's namespace is separate from the kernel's on purpose: the analyst may
    `submit_candidate`, and the kernel -- never the analyst -- may `enqueue_audit`.
    Checking it here makes that boundary executable instead of documentary.
    """
    allowed, forbidden = analyst_action_sets(registry)
    if action in allowed:
        return
    detail = (
        f"analyst action {action!r} is forbidden; Layer B submits candidates and "
        "performs zero direct writes"
        if action in forbidden
        else f"analyst action {action!r} is outside the closed analyst set; deny by default"
    )
    raise PalError(CAPABILITY_DENIED, detail, next_action="no write was performed") from None
