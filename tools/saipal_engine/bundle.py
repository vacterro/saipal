"""The canonical Session Evidence Bundle (PAL-SESSION-01).

Validation fails closed and returns every problem it found rather than the
first one, because an operator fixing a broken export deserves the whole list.

The transcript guard lives here on purpose: a bundle that carries raw
conversation text is not evidence, it is a second copy of the conversation, and
it is rejected before it can reach an audit.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import PalError
from .paths import read_json, sha256_bytes
from .registry import load_registry, require_mapping, require_string_list

NULLABLE_EVENT_FIELDS = ("ts", "loc", "digest")


def _spec(registry: dict | None = None) -> dict[str, Any]:
    data = registry if registry is not None else load_registry()
    return {
        "schema_version": int(data.get("bundle_schema_version", 1)),
        "required": require_string_list(data, "bundle_required_fields"),
        "optional": require_string_list(data, "bundle_optional_fields"),
        "event_fields": require_string_list(data, "event_fields"),
        "event_types": require_string_list(data, "event_types"),
        "forbidden_event_keys": require_string_list(data, "forbidden_event_keys"),
        "adapters": require_string_list(data, "adapters"),
        "temperatures": require_string_list(data, "temperature_enum"),
        "binding_fields": require_string_list(data, "protocol_binding_fields"),
        "statuses": require_string_list(data, "binding_status"),
        "proof_levels": require_string_list(data, "binding_proof_levels"),
        "budgets": require_mapping(data, "evidence_budgets"),
        "locator_fields": require_string_list(data, "evidence_locator_fields"),
        "locator_sources": require_string_list(data, "evidence_source_kinds"),
        "locator_roles": require_string_list(data, "evidence_roles"),
        "locator_limits": require_mapping(data, "evidence_locator_limits"),
    }


def canonical_bytes(payload: dict) -> bytes:
    """Stable serialization used for the content digest.

    `session_sha256` is normalized away: a bundle cannot contain its own
    digest, so the digest is computed over the document with that field blank
    and later verified against the declared value.
    """
    stripped = {key: value for key, value in payload.items() if key != "session_sha256"}
    stripped["session_sha256"] = None
    return json.dumps(
        stripped, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def bundle_digest(payload: dict) -> str:
    return sha256_bytes(canonical_bytes(payload))


def _longest_string(node: Any) -> int:
    if isinstance(node, str):
        return len(node)
    if isinstance(node, dict):
        return max([_longest_string(v) for v in node.values()] or [0])
    if isinstance(node, (list, tuple)):
        return max([_longest_string(v) for v in node] or [0])
    return 0


def validate_bundle(
    payload: object, *, registry: dict | None = None, digest: str | None = None
) -> list[str]:
    """Every reason this bundle is unusable, or an empty list.

    `digest` lets a caller that already canonicalized the document pass it in.
    Recomputing it here AND in the caller meant two canonical serializations plus
    two SHA-256 passes over every inbox file, every cycle (PERF-002).
    """
    spec = _spec(registry)
    if not isinstance(payload, dict):
        return ["bundle root is not an object"]

    problems: list[str] = []

    if payload.get("schema_version") != spec["schema_version"]:
        problems.append(
            f"schema_version {payload.get('schema_version')!r} != {spec['schema_version']}"
        )

    for field in spec["required"]:
        if field not in payload:
            problems.append(f"missing required field {field!r}")

    known = set(spec["required"]) | set(spec["optional"])
    for field in sorted(set(payload) - known):
        problems.append(f"unknown field {field!r}")

    if "session_id" in payload and not (
        isinstance(payload["session_id"], str) and payload["session_id"].strip()
    ):
        problems.append("session_id must be a non-empty string")

    if "adapter" in payload and payload["adapter"] not in spec["adapters"]:
        problems.append(f"adapter {payload['adapter']!r} outside {list(spec['adapters'])}")

    if "temperature" in payload and payload["temperature"] not in spec["temperatures"]:
        problems.append(
            f"temperature {payload['temperature']!r} outside {list(spec['temperatures'])}"
        )

    for key in ("project", "runtime", "protocol"):
        if key in payload and not isinstance(payload[key], dict):
            problems.append(f"{key} must be an object")

    if isinstance(payload.get("protocol"), dict):
        protocol = payload["protocol"]
        for field in protocol:
            if field not in spec["binding_fields"]:
                problems.append(f"protocol has unknown field {field!r}")
        status = protocol.get("binding_status")
        if status is not None and status not in spec["statuses"]:
            problems.append(f"binding_status {status!r} outside {list(spec['statuses'])}")
        proof_level = protocol.get("proof_level")
        if proof_level is not None and proof_level not in spec["proof_levels"]:
            problems.append(
                f"proof_level {proof_level!r} outside {list(spec['proof_levels'])}"
            )

    declared = payload.get("session_sha256")
    if declared is not None:
        if not isinstance(declared, str):
            problems.append("session_sha256 must be a string or null")
        elif declared != (digest if digest is not None else bundle_digest(payload)):
            problems.append("session_sha256 does not match the bundle content")

    if "events" in payload:
        problems.extend(_validate_events(payload["events"], spec))

    return problems


def _validate_events(events: object, spec: dict) -> list[str]:
    if not isinstance(events, list):
        return ["events must be an array"]

    problems: list[str] = []
    allowed = set(spec["event_fields"])
    limit = int(spec["budgets"].get("max_excerpt_chars", 2000))
    max_keys = int(spec["budgets"].get("max_facts_keys", 32))
    previous: int | None = None

    for index, event in enumerate(events):
        where = f"events[{index}]"
        if not isinstance(event, dict):
            problems.append(f"{where} is not an object")
            continue

        for key in sorted(set(event) - allowed):
            problems.append(f"{where} has unknown field {key!r}")
        for key in spec["forbidden_event_keys"]:
            if key in event:
                problems.append(
                    f"{where} carries forbidden raw-content field {key!r}; "
                    "events hold a digest and structured facts, never the transcript"
                )

        seq = event.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            problems.append(f"{where}.seq must be an integer")
        elif seq < 0:
            problems.append(f"{where}.seq must not be negative")
        elif previous is not None and seq <= previous:
            problems.append(
                f"{where}.seq {seq} does not increase after {previous}"
            )
        if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0:
            previous = seq

        kind = event.get("type")
        if kind not in spec["event_types"]:
            problems.append(f"{where}.type {kind!r} outside the closed event set")

        for field in NULLABLE_EVENT_FIELDS:
            if field in event and event[field] is not None and not isinstance(event[field], str):
                problems.append(f"{where}.{field} must be a string or null")

        locator = event.get("evidence_ref")
        if locator is not None:
            if not isinstance(locator, dict):
                problems.append(f"{where}.evidence_ref must be an object or null")
            else:
                unknown = set(locator) - set(spec["locator_fields"])
                if unknown:
                    problems.append(
                        f"{where}.evidence_ref has unknown fields {sorted(unknown)}"
                    )
                for required in ("source_kind", "source_session_id", "source_digest", "role"):
                    if not isinstance(locator.get(required), str) or not locator[required]:
                        problems.append(f"{where}.evidence_ref.{required} must be non-empty")
                if locator.get("source_kind") not in spec["locator_sources"]:
                    problems.append(f"{where}.evidence_ref source_kind is not registered")
                if locator.get("role") not in spec["locator_roles"]:
                    problems.append(f"{where}.evidence_ref role is not registered")
                max_id = int(spec["locator_limits"]["max_source_id_chars"])
                for key in ("source_session_id", "source_message_id", "source_part_id"):
                    value = locator.get(key)
                    if value is not None and (
                        not isinstance(value, str) or not value or len(value) > max_id
                    ):
                        problems.append(f"{where}.evidence_ref.{key} is invalid or oversized")
                digest = locator.get("source_digest")
                max_digest = int(spec["locator_limits"]["max_source_digest_chars"])
                if isinstance(digest, str) and len(digest) > max_digest:
                    problems.append(f"{where}.evidence_ref.source_digest is oversized")

        facts = event.get("facts")
        if not isinstance(facts, dict):
            problems.append(f"{where}.facts must be an object")
            continue
        if len(facts) > max_keys:
            problems.append(f"{where}.facts has {len(facts)} keys, budget is {max_keys}")
        longest = _longest_string(facts)
        if longest > limit:
            problems.append(
                f"{where}.facts holds a {longest}-char string, budget is {limit}; "
                "store a digest and a short excerpt instead"
            )

    return problems


def parse_bundle(
    payload: object, *, registry: dict | None = None, digest: str | None = None
) -> dict:
    """Validate and return the bundle, or raise `PalError(BUNDLE_INVALID)`."""
    problems = validate_bundle(payload, registry=registry, digest=digest)
    if problems:
        raise PalError(
            "BUNDLE_INVALID",
            "bundle rejected: " + "; ".join(problems),
            next_action="export the session as a canonical bundle (SESSIONS.md)",
        )
    assert isinstance(payload, dict)
    return payload


def load_bundle_with_digest(
    path: Path | str, *, registry: dict | None = None
) -> tuple[dict, str]:
    """`(bundle, content_digest)` from one inbox file, canonicalized ONCE.

    Intake needs both the validated bundle and its digest; asking for them
    separately serialized every bundle twice (PERF-002).
    """
    target = Path(path)
    try:
        payload = read_json(target)
    except OSError as exc:
        raise PalError(
            "INBOX_UNREADABLE", f"cannot read {target.name}: {exc}"
        ) from exc
    except ValueError as exc:
        raise PalError("BUNDLE_INVALID", f"{target.name} is not valid JSON: {exc}") from exc
    digest = bundle_digest(payload) if isinstance(payload, dict) else ""
    return parse_bundle(payload, registry=registry, digest=digest), digest


def load_bundle_file(path: Path | str, *, registry: dict | None = None) -> dict:
    """Read one inbox file. Unreadable is `INBOX_UNREADABLE`, malformed is
    `BUNDLE_INVALID` -- the two mean different things to whoever exported it."""
    bundle, _digest = load_bundle_with_digest(path, registry=registry)
    return bundle


def events_of(bundle: dict) -> list[dict]:
    return list(bundle.get("events") or [])


def prefix_digest(bundle: dict, upto_seq: int) -> str:
    """Digest of the events already analyzed -- the hot-session watermark."""
    prefix = [event for event in events_of(bundle) if int(event["seq"]) <= upto_seq]
    return sha256_bytes(
        json.dumps(prefix, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def event_span(bundle: dict) -> tuple[int, int]:
    events = events_of(bundle)
    if not events:
        return (0, 0)
    sequences = [int(event["seq"]) for event in events]
    return (min(sequences), max(sequences))
