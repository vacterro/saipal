"""Semantic deliberation: investigator, critic, finalizer.

Asymmetric by design. Every eligible unit gets ONE investigator call. A DRIFT
verdict must survive a critic before it goes anywhere. A NO_DRIFT verdict is
not re-litigated unless the packet carries a high-confidence mechanical signal
or the unit was picked by the deterministic clean-sample. When the two roles
disagree, the finalizer speaks once, and its candidate is the ONLY candidate
that reaches submit.

No function here ever decides semantic truth itself. The model roles reason;
this module only moves text through the output contract and records the path.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Callable

from saipal_analyst import output as output_mod
from saipal_analyst import prompts as prompts_mod

#: The bounded default: one repair attempt per role, never more.
DEFAULT_MAX_REPAIRS = 1

ROLE_INVESTIGATOR = "investigator"
ROLE_CRITIC = "critic"
ROLE_FINALIZER = "finalizer"


@dataclass
class ModelCall:
    """One resolved model call, for provenance and the journal."""

    role: str
    digest: str
    ok: bool
    repaired: bool = False


@dataclass
class Investigation:
    """The outcome of one unit's deliberation."""

    status: str  # CANDIDATE | BLOCKED_OUTPUT
    candidate: dict | None = None
    critic: dict | None = None
    calls: list[ModelCall] = field(default_factory=list)
    path: list[str] = field(default_factory=list)
    original_verdict: str | None = None
    final_verdict: str | None = None
    invalid_outputs: int = 0
    blocked_detail: str = ""

    @property
    def finalizer_changed(self) -> bool:
        return (
            self.original_verdict is not None
            and self.final_verdict is not None
            and self.original_verdict != self.final_verdict
        )


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def run_investigation(
    packet: dict,
    *,
    call: Callable[[str, str], str],
    policy: dict,
    registry: dict | None = None,
    max_repairs: int = DEFAULT_MAX_REPAIRS,
) -> Investigation:
    """Investigate one packet to a submission-ready candidate -- or to a block.

    `call(role, user_text)` performs one model call and returns the raw text.
    The worker owns transport failures; this module only owns the output
    contract. Every call the investigation makes is recorded.
    """
    result = Investigation(status="CANDIDATE")
    result.path.append(ROLE_INVESTIGATOR)

    def invoke(role: str, user: str, *, repaired: bool = False) -> str:
        text = call(role, user)
        result.calls.append(ModelCall(role=role, digest=_digest(text), ok=True, repaired=repaired))
        return text

    def try_with_repair(
        role: str, user: str, parse, reject_note: str
    ) -> tuple[object | None, list[str]]:
        """Parse; on failure, one bounded repair with the SAME packet identity."""
        nonlocal_invalid = 0
        text = invoke(role, user)
        try:
            return parse(text), []
        except output_mod.OutputRejected as first:
            nonlocal_invalid += 1
            result.invalid_outputs += 1
            if max_repairs < 1:
                result.blocked_detail = f"{reject_note}: {first}"
                return None, [str(first)]
            repair_text = invoke(
                role,
                prompts_mod.repair_user_message(packet, text, [str(first)]),
                repaired=True,
            )
            try:
                return parse(repair_text), []
            except output_mod.OutputRejected as second:
                result.invalid_outputs += 1
                result.blocked_detail = (
                    f"{reject_note}: still invalid after repair: {second}"
                )
                return None, [str(first), str(second)]

    candidate, _errors = try_with_repair(
        ROLE_INVESTIGATOR,
        prompts_mod.packet_user_message(packet),
        lambda text: output_mod.validate_candidate(
            output_mod.parse_json_object(text), packet, registry=registry
        ),
        "investigator output",
    )
    if candidate is None:
        result.status = "BLOCKED_OUTPUT"
        return result
    result.original_verdict = candidate["verdict"]
    result.final_verdict = candidate["verdict"]

    need_critic, reason = output_mod.needs_critic(
        candidate, packet, policy=policy, unit_digest=str(packet.get("unit_digest"))
    )
    if need_critic:
        result.path.append(f"critic:{reason}")
        critic = _run_critic(
            result, invoke, try_with_repair, packet, candidate, policy
        )
        if critic is None:
            result.status = "BLOCKED_OUTPUT"
            result.candidate = None
            return result
        result.critic = critic
        candidate = _resolve_disagreement(
            result, invoke, try_with_repair, packet, candidate, critic, policy, registry
        )
        if candidate is None:
            result.status = "BLOCKED_OUTPUT"
            result.candidate = None
            return result

    result.candidate = candidate
    result.final_verdict = candidate["verdict"]
    return result


def resume_from_candidate(
    packet: dict,
    candidate: dict,
    *,
    critic_payload: dict | None,
    call: Callable[[str, str], str],
    policy: dict,
    registry: dict | None = None,
    max_repairs: int = DEFAULT_MAX_REPAIRS,
) -> Investigation:
    """Continue one unit's deliberation from an already-validated candidate.

    Crash-recovery entry point. The gates are the SAME gates fresh execution
    passes: a candidate that needs a critic still gets one (a persisted critic
    payload is reused verbatim instead of being paid for twice), a
    disagreement still goes to the finalizer when policy enables it, and the
    returned candidate is the ONLY one that may reach submit. Recovery never
    weakens the semantic contract.
    """
    result = Investigation(status="CANDIDATE")
    result.path.append(ROLE_INVESTIGATOR)
    result.original_verdict = candidate["verdict"]
    result.final_verdict = candidate["verdict"]

    def invoke(role: str, user: str, *, repaired: bool = False) -> str:
        text = call(role, user)
        result.calls.append(ModelCall(role=role, digest=_digest(text), ok=True, repaired=repaired))
        return text

    def try_with_repair(
        role: str, user: str, parse, reject_note: str
    ) -> tuple[object | None, list[str]]:
        text = invoke(role, user)
        try:
            return parse(text), []
        except output_mod.OutputRejected as first:
            result.invalid_outputs += 1
            if max_repairs < 1:
                result.blocked_detail = f"{reject_note}: {first}"
                return None, [str(first)]
            repair_text = invoke(
                role,
                prompts_mod.repair_user_message(packet, text, [str(first)]),
                repaired=True,
            )
            try:
                return parse(repair_text), []
            except output_mod.OutputRejected as second:
                result.invalid_outputs += 1
                result.blocked_detail = f"{reject_note}: still invalid after repair: {second}"
                return None, [str(first), str(second)]

    need_critic, reason = output_mod.needs_critic(
        candidate, packet, policy=policy, unit_digest=str(packet.get("unit_digest"))
    )
    if need_critic:
        if critic_payload is not None:
            result.path.append(f"critic:recovered")
            critic = critic_payload
        else:
            result.path.append(f"critic:{reason}")
            critic = _run_critic(result, invoke, try_with_repair, packet, candidate, policy)
            if critic is None:
                result.status = "BLOCKED_OUTPUT"
                result.candidate = None
                return result
        result.critic = critic
        candidate = _resolve_disagreement(
            result, invoke, try_with_repair, packet, candidate, critic, policy, registry
        )
        if candidate is None:
            result.status = "BLOCKED_OUTPUT"
            result.candidate = None
            return result

    result.candidate = candidate
    result.final_verdict = candidate["verdict"]
    return result


def _run_critic(result, invoke, try_with_repair, packet, candidate, policy):
    critic, _errors = try_with_repair(
        ROLE_CRITIC,
        prompts_mod.critic_user_message(packet, candidate),
        lambda text: output_mod.parse_critic(text, packet),
        "critic output",
    )
    return critic


def _resolve_disagreement(
    result, invoke, try_with_repair, packet, candidate, critic, policy, registry
):
    decision = critic.get("decision")
    verdict = candidate.get("verdict")

    agrees = decision == "AGREE"
    # DRIFT always needs the finalizer unless the critic agreed outright.
    if verdict == "DRIFT" and agrees:
        result.path.append("critic_agree")
        return candidate
    if verdict == "NO_DRIFT" and decision == "INSUFFICIENT":
        # The critic found no counter-evidence: the clean verdict stands.
        result.path.append("critic_insufficient_kept_no_drift")
        return candidate
    if agrees:
        result.path.append("critic_agree")
        return candidate

    result.path.append("finalizer")
    if not policy.get("finalizer_on_disagreement"):
        # Without a finalizer the disagreement blocks the unit: silence is the
        # only honest output. Never convert disagreement into a verdict here.
        result.blocked_detail = "critic disagreement with finalizer disabled"
        return None

    finalized, _errors = try_with_repair(
        ROLE_FINALIZER,
        prompts_mod.finalizer_user_message(packet, candidate, critic),
        lambda text: output_mod.validate_candidate(
            output_mod.parse_json_object(text), packet, registry=registry
        ),
        "finalizer output",
    )
    if finalized is None:
        return None
    result.path.append("finalizer_decided")
    return finalized
