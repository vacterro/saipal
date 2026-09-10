"""Model output contract: strict parse, identity binding, closed schemas.

A hallucinating model does not get a friendly parser. The reply must BE the
JSON object: no fences, no prose, no "here is the JSON". Parsing is
all-or-nothing; identity fields must equal the packet's; unknown fields are
refused by the kernel's own validator before anything is submitted.
"""

from __future__ import annotations

import json

from saipal_engine import candidates as cand_mod
from saipal_engine.errors import PalError

CRITIC_SCHEMA_VERSION = 1
CRITIC_FIELDS = (
    "schema_version",
    "unit_digest",
    "decision",
    "objections",
    "missed_evidence",
    "reasoning",
)
CRITIC_DECISIONS = ("AGREE", "DISAGREE", "INSUFFICIENT")

MAX_REPLY_CHARS = 512 * 1024


def parse_json_object(text: str, *, max_chars: int = MAX_REPLY_CHARS) -> dict:
    """Parse the ENTIRE reply as one JSON object, or refuse. No salvage."""
    if not isinstance(text, str):
        raise OutputRejected("reply is not text")
    if len(text) > max_chars:
        raise OutputRejected(
            f"reply is {len(text)} chars, over the {max_chars} limit"
        )
    try:
        payload = json.loads(text.strip())
    except ValueError as exc:
        raise OutputRejected(f"reply is not valid JSON: {exc}") from None
    if not isinstance(payload, dict):
        raise OutputRejected("reply must be one JSON object")
    return payload


class OutputRejected(PalError):
    def __init__(self, detail: str):
        super().__init__("CANDIDATE_INADMISSIBLE", detail)


def validate_candidate(
    candidate: object,
    packet: dict,
    *,
    registry: dict | None = None,
) -> dict:
    """Kernel validation + packet identity binding. Returns the candidate.

    Every check the manual `saipal submit` path runs runs here first, so the
    worker never spends a submit on a candidate the kernel would refuse -- and
    then the kernel boundary runs it AGAIN as the final authority.
    """
    if not isinstance(candidate, dict):
        raise OutputRejected("candidate root is not an object")
    problems = cand_mod.candidate_problems(candidate, registry=registry)
    if problems:
        raise OutputRejected("candidate is inadmissible: " + "; ".join(problems))
    problems = _scope_problems(candidate, packet)
    if problems:
        raise OutputRejected("candidate is inadmissible: " + "; ".join(problems))
    _identity_problems(candidate, packet)
    return candidate


def _scope_problems(candidate: dict, packet: dict) -> list[str]:
    """Packet-scope checks the kernel cannot do: it never sees the packet."""
    problems: list[str] = []
    visible = {
        int(event.get("seq"))
        for event in (packet.get("events") or [])
        if isinstance(event, dict) and isinstance(event.get("seq"), int)
    }
    for ref in candidate.get("event_refs") or []:
        if int(ref) not in visible:
            problems.append(f"event ref {ref} is outside the packet's evidence")
    known = _known_rule_ids(packet)
    for rule_id in candidate.get("rule_ids") or []:
        if str(rule_id) not in known:
            problems.append(f"rule id {rule_id!r} does not exist in the packet's law")
    return problems


def _known_rule_ids(packet: dict) -> set[str]:
    known: set[str] = set()

    def absorb(node: object) -> None:
        if isinstance(node, dict):
            for key in ("rule_id", "id", "code"):
                value = node.get(key)
                if isinstance(value, str) and value.strip():
                    known.add(value)
            for value in node.values():
                absorb(value)
        elif isinstance(node, list):
            for item in node:
                absorb(item)
        elif isinstance(node, str):
            # Bare string lists (e.g. a law's rule id list) are ids themselves.
            if node.startswith(("PAL-", "SAI-")):
                known.add(node)

    absorb(packet.get("applicable_law"))
    absorb(packet.get("historical_rule_surface"))
    return known


def _identity_problems(candidate: dict, packet: dict) -> None:
    expected = {
        "unit_digest": str(packet.get("unit_digest") or ""),
        "session_id": str((packet.get("session") or {}).get("session_id") or ""),
        "episode_index": (packet.get("episode") or {}).get("index"),
    }
    slice_index = (packet.get("slice") or {}).get("index")
    if slice_index is not None:
        expected["slice_index"] = slice_index
    for key, want in expected.items():
        got = candidate.get(key)
        if got != want:
            raise OutputRejected(
                f"candidate {key} {got!r} does not match the packet's {want!r}"
            )


def parse_critic(text: str, packet: dict) -> dict:
    """Strict critic parse: closed schema, identity bound to the packet."""
    critic = parse_json_object(text)
    unknown = sorted(set(critic) - set(CRITIC_FIELDS))
    if unknown:
        raise OutputRejected(f"critic has unknown fields {unknown}")
    if critic.get("schema_version") != CRITIC_SCHEMA_VERSION:
        raise OutputRejected(
            f"critic schema_version must be {CRITIC_SCHEMA_VERSION}"
        )
    if critic.get("decision") not in CRITIC_DECISIONS:
        raise OutputRejected(
            f"critic decision {critic.get('decision')!r} outside {list(CRITIC_DECISIONS)}"
        )
    for key in ("objections", "missed_evidence"):
        value = critic.get(key)
        if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
            raise OutputRejected(f"critic {key} must be a list of strings")
    for key in ("unit_digest", "reasoning"):
        if not isinstance(critic.get(key), str) or not critic.get(key).strip():
            raise OutputRejected(f"critic {key} must be a non-empty string")
    if critic["unit_digest"] != packet.get("unit_digest"):
        raise OutputRejected("critic answers a different unit")
    return critic


def needs_critic(
    candidate: dict,
    packet: dict,
    *,
    policy: dict,
    unit_digest: str,
) -> tuple[bool, str]:
    """Asymmetric deliberation: DRIFT always; NO_DRIFT only on policy.

    Sampling is deterministic from the unit digest -- never process-global
    random state -- so the same unit is sampled the same way every run.
    """
    verdict = candidate.get("verdict")
    if verdict == "DRIFT":
        return bool(policy.get("critic_on_drift")), "drift_always"
    if verdict != "NO_DRIFT":
        return False, ""
    if policy.get("critic_on_high_signal_no_drift") and _high_signal(packet):
        return True, "high_signal_no_drift"
    percent = int(policy.get("clean_sample_percent") or 0)
    if percent and _sampled(unit_digest, percent):
        return True, "clean_sample"
    return False, ""


def _high_signal(packet: dict) -> bool:
    for signal in ((packet.get("mechanical_signals") or {}).get("signals") or []):
        confidence = str(signal.get("confidence") or "").upper()
        severity = str(signal.get("severity") or "").upper()
        if confidence == "HIGH" or severity in ("P0", "P1"):
            return True
    return False


def _sampled(unit_digest: str, percent: int) -> bool:
    bucket = int(unit_digest[:8], 16) % 100
    return bucket < percent
