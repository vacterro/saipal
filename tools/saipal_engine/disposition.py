"""Disposition-class law made executable (PAL-ANALYSIS-03).

The drift taxonomy says what was observed. The disposition class says what KIND
of defect it is. Those two answers point at different fixes, and conflating them
is how a forensic tool ends up recommending that a correct safety rule be
relaxed because a model ignored it.

This module is the gate. It refuses three specific confusions:

1. a `DRIFT` claim dispositioned as something that is not drift;
2. a disposition proposing a change surface it cannot justify;
3. a model/user/environment failure proposing to weaken the protocol.
"""

from __future__ import annotations

from .registry import load_registry, require_mapping, require_string_list

#: Surfaces where a change relaxes the rules everything else depends on.
#: Reaching these requires a disposition that actually blames the protocol.
PROTOCOL_SURFACES = frozenset(
    {"CORE_PROTOCOL", "PHASE_CONTRACT", "SOURCE_CONTRACT", "EXECUTION_POLICY"}
)


def allowed_targets(disposition: str, *, registry: dict | None = None) -> tuple[str, ...]:
    """The change surfaces this disposition class can justify."""
    data = registry if registry is not None else load_registry()
    mapping = require_mapping(data, "disposition_change_targets")
    if disposition not in mapping:
        return ()
    return require_string_list(mapping, disposition)


def non_drift_dispositions(*, registry: dict | None = None) -> frozenset:
    data = registry if registry is not None else load_registry()
    return frozenset(require_string_list(data, "non_drift_dispositions"))


def weakening_dispositions(*, registry: dict | None = None) -> frozenset:
    """Dispositions that may never propose relaxing the protocol."""
    data = registry if registry is not None else load_registry()
    return frozenset(require_string_list(data, "protocol_weakening_dispositions"))


def disposition_problems(
    verdict: object,
    disposition: object,
    change_target: object,
    *,
    registry: dict | None = None,
) -> list[str]:
    """Every way this disposition/target/verdict triple contradicts itself."""
    data = registry if registry is not None else load_registry()
    problems: list[str] = []
    name = str(disposition or "")
    target = str(change_target or "")
    non_drift = non_drift_dispositions(registry=data)

    if verdict == "DRIFT":
        if name in non_drift:
            problems.append(
                f"a DRIFT verdict cannot be dispositioned {name!r}: that class means "
                "no protocol drift occurred"
            )
        permitted = allowed_targets(name, registry=data)
        if permitted and target and target not in permitted:
            problems.append(
                f"disposition {name!r} cannot justify change_target {target!r}; "
                f"admissible targets are {sorted(permitted)}"
            )
        if target in PROTOCOL_SURFACES and name in weakening_dispositions(registry=data):
            problems.append(
                f"disposition {name!r} may not propose changing {target!r}: never "
                "legalize a model, user or environment failure by weakening a "
                "correct protocol rule (PAL-ANALYSIS-03)"
            )
    else:
        if name not in non_drift:
            problems.append(
                f"a {verdict!r} verdict must carry a non-drift disposition; {name!r} "
                f"claims a defect. Admissible: {sorted(non_drift)}"
            )
    return problems


def preferred_target(disposition: str, *, registry: dict | None = None) -> str:
    """The first admissible surface for this disposition, or `UNKNOWN`.

    Used to report the redirect an audit should carry when a candidate proposed
    a surface its own disposition cannot justify.
    """
    permitted = allowed_targets(disposition, registry=registry)
    return permitted[0] if permitted else "UNKNOWN"
