"""The do-no-harm gate, made load-bearing (PAL-DONOHARM-01).

The old gate matched invariant names as substrings of prose and produced warnings
nobody acted on. Two problems: prose is not evidence, and a warning that blocks
nothing is a comment.

This module answers a structural question instead — *does this proposed change
surface govern a protected invariant?* — and separates two outcomes:

- **warnings**: the fix reaches a protected invariant and the finding says so. It
  proceeds, carrying an explicit warning for the maintainer.
- **blocks**: the fix reaches a protected invariant, the finding does NOT declare
  it, and the disposition does not even blame the protocol. That is the
  "legalize a model failure" case, and it does not qualify.
"""

from __future__ import annotations

from . import disposition as disposition_mod
from .registry import load_registry, require_mapping, require_string_list


def protected_invariants(*, registry: dict | None = None) -> tuple[str, ...]:
    data = registry if registry is not None else load_registry()
    return require_string_list(data, "protected_invariants")


def invariants_governed_by(change_target: str, *, registry: dict | None = None) -> list[str]:
    """The protected invariants a change to this surface could weaken."""
    data = registry if registry is not None else load_registry()
    mapping = require_mapping(data, "protected_invariant_surfaces")
    target = str(change_target or "")
    return [
        invariant
        for invariant in protected_invariants(registry=data)
        if target in require_string_list(mapping, invariant)
    ]


def invariant_rules(invariant: str, *, registry: dict | None = None) -> tuple[str, ...]:
    """The rule ids that carry this invariant, for the audit's DO NOT WEAKEN block."""
    data = registry if registry is not None else load_registry()
    mapping = require_mapping(data, "protected_invariant_rules")
    if invariant not in mapping:
        return ()
    return require_string_list(mapping, invariant)


def assess(finding: dict, *, registry: dict | None = None) -> dict:
    """`{warnings, blocks, invariants}` for a proposed change.

    A finding that names the invariant it touches is doing the right thing: it is
    warned about, not blocked. A finding that reaches a protected invariant
    without naming it, from a disposition that does not blame the protocol, is
    blocked — that is precisely the shape of legalizing a model failure.
    """
    data = registry if registry is not None else load_registry()
    target = str(finding.get("change_target") or "")
    reached = invariants_governed_by(target, registry=data)
    if not reached:
        return {"warnings": [], "blocks": [], "invariants": []}

    declared = {str(name) for name in (finding.get("protected_invariants") or [])}
    disposition = str(finding.get("disposition_class") or "")
    blames_protocol = disposition not in disposition_mod.weakening_dispositions(registry=data)

    warnings: list[str] = []
    blocks: list[str] = []
    for invariant in reached:
        rules = ", ".join(invariant_rules(invariant, registry=data)) or "no declared rule"
        if invariant in declared:
            warnings.append(
                f"a change to {target} could weaken protected invariant {invariant!r} "
                f"({rules}); the finding declares it, so the maintainer must confirm the "
                "fix preserves it"
            )
        elif blames_protocol:
            warnings.append(
                f"a change to {target} could weaken protected invariant {invariant!r} "
                f"({rules}) and the finding does not declare it; redirect the fix or "
                "warn the maintainer explicitly"
            )
        else:
            blocks.append(
                f"disposition {disposition!r} proposes changing {target}, which governs "
                f"protected invariant {invariant!r} ({rules}), without declaring it. "
                "Never weaken a safety or correctness rule because a model failed to "
                "comply (PAL-DONOHARM-01)"
            )
    return {"warnings": warnings, "blocks": blocks, "invariants": reached}
