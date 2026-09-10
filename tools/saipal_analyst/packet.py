"""The bounded analysis packet: the ONLY evidence a model ever sees.

Built exclusively from the canonical carrier. The packet adds framing (labels,
attribution) and removes anything a remote analyst must never hold: home paths,
maintainer roots, sink roots, API keys, environment, executable commands, and
the manual CLI's `evidence_command` (an external human agent may use the CLI;
the autonomous worker resolves evidence itself and never tells the model to).

Mechanical signals travel labelled `UNVERIFIED INVESTIGATION HINTS`: they are
priorities for attention, never facts and never verdicts.
"""

from __future__ import annotations

import hashlib
import json

from saipal_engine.errors import PalError

from .config import egress_verdict

PACKET_SCHEMA_VERSION = 1

#: Keys that must never appear anywhere in a packet, at any depth.
FORBIDDEN_PACKET_KEYS = (
    "evidence_command",
    "home",
    "home_path",
    "sink",
    "sink_root",
    "maintainer_root",
    "api_key",
    "api_key_env",
    "endpoint",
    "environment",
    "command",
    "commands",
)

SIGNALS_LABEL = "UNVERIFIED INVESTIGATION HINTS"

#: Packet top-level fields, closed. Unknown = refuse.
PACKET_FIELDS = (
    "packet_schema_version",
    "packet_digest",
    "unit_digest",
    "attribution",
    "session",
    "episode",
    "slice",
    "finality",
    "events",
    "evidence_refs",
    "protocol",
    "applicable_law",
    "historical_rule_surface",
    "mechanical_signals",
    "defence_surface",
    "recurrence",
    "calibration",
)


def build_packet(carrier: dict, *, analyst: dict) -> dict:
    """Derive the packet from one canonical carrier. Zero kernel writes."""
    if not isinstance(carrier, dict) or not carrier.get("session"):
        raise PalError(
            "VALIDATION_FAILED",
            "packet needs an analyze-episodes carrier, not an idle one",
        )
    session = carrier["session"]
    episode = carrier["episode"]
    packet = {
        "packet_schema_version": PACKET_SCHEMA_VERSION,
        "packet_digest": "",
        "unit_digest": carrier["unit_digest"],
        "attribution": {
            "backend_type": analyst.get("backend_type"),
            "model": analyst.get("model"),
            "project": (session.get("project") or {}).get("name"),
            "provider": (session.get("runtime") or {}).get("provider"),
            "runtime_model": (session.get("runtime") or {}).get("model"),
        },
        "session": {
            "session_id": session.get("session_id"),
            "generation": session.get("generation"),
            "adapter": session.get("adapter"),
            "temperature": session.get("temperature"),
            "status": session.get("status"),
        },
        "episode": {
            "index": episode.get("index"),
            "kind": episode.get("kind"),
            "start_seq": episode.get("start_seq"),
            "end_seq": episode.get("end_seq"),
            "trigger_seq": episode.get("trigger_seq"),
            "event_count": episode.get("event_count"),
            "events_truncated": episode.get("events_truncated"),
        },
        "slice": carrier.get("slice"),
        "finality": episode.get("finality"),
        "events": carrier.get("events"),
        "evidence_refs": carrier.get("evidence_refs"),
        "protocol": {
            "binding_status": (carrier.get("protocol") or {}).get("binding_status"),
            "proof_level": (carrier.get("protocol") or {}).get("proof_level"),
            "version": (carrier.get("protocol") or {}).get("version"),
            "violation_claimable": (carrier.get("protocol") or {}).get(
                "violation_claimable"
            ),
            "reason": (carrier.get("protocol") or {}).get("reason"),
        },
        "applicable_law": carrier.get("applicable_law"),
        "historical_rule_surface": carrier.get("historical_rule_surface"),
        "mechanical_signals": {
            "label": SIGNALS_LABEL,
            "hint": (
                "these are deterministic detector signals from the kernel. They "
                "are NOT facts, NOT verdicts and carry no authority. They may "
                "only direct your attention; every conclusion must stand on the "
                "evidence text alone."
            ),
            "signals": carrier.get("signals"),
        },
        "defence_surface": carrier.get("defence_surface"),
        "recurrence": carrier.get("recurrence"),
        "calibration": carrier.get("calibration"),
    }
    packet["packet_digest"] = digest_packet(packet)
    return packet


def digest_packet(packet: dict) -> str:
    payload = {key: value for key, value in packet.items() if key != "packet_digest"}
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def packet_problems(packet: object) -> list[str]:
    """Structural refusals: unknown fields and forbidden content, at any depth."""
    if not isinstance(packet, dict):
        return ["packet root is not an object"]
    problems: list[str] = []
    for key in sorted(set(packet) - set(PACKET_FIELDS)):
        problems.append(f"unknown packet field {key!r}")
    if packet.get("packet_schema_version") != PACKET_SCHEMA_VERSION:
        problems.append(f"packet_schema_version must be {PACKET_SCHEMA_VERSION}")
    for key in FORBIDDEN_PACKET_KEYS:
        if _contains_key(packet, key):
            problems.append(f"packet must not carry {key!r}")
    return problems


def _contains_key(node: object, key: str) -> bool:
    if isinstance(node, dict):
        if key in node:
            return True
        return any(_contains_key(value, key) for value in node.values())
    if isinstance(node, list):
        return any(_contains_key(item, key) for item in node)
    return False


def ensure_egress(config: dict) -> None:
    """Refuse before any bytes are sent if the endpoint is not demonstrably local."""
    allowed, detail = egress_verdict(config)
    if not allowed:
        raise PalError("ANALYST_EGRESS_REFUSED", detail)


def packet_digest_matches(packet: dict) -> bool:
    return digest_packet(packet) == packet.get("packet_digest")
