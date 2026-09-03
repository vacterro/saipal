"""Provider-neutral locator construction for JSONL-backed adapters.

A locator is how an audit points back at raw provider evidence without copying
it. All three JSONL providers build the same shape, so the mapping lives once —
including the role mapping, which is easy to get subtly wrong inline (a chained
conditional inside `str(...)` silently binds the wrong way).
"""

from __future__ import annotations

#: Source event types that imply each canonical role. Anything unlisted is
#: `unknown` rather than guessed: a wrong role in an audit is a wrong claim.
_USER_TYPES = frozenset({"user", "user_message", "command"})
_ASSISTANT_TYPES = frozenset({"assistant", "assistant_message"})
_TOOL_TYPES = frozenset({"tool_call", "tool_result"})

ROLES = frozenset({"user", "assistant", "tool", "unknown"})


def role_of(source_type: str, raw: dict) -> str:
    """The canonical role for one raw provider event."""
    declared = raw.get("role")
    if isinstance(declared, str) and declared in ROLES:
        return declared
    kind = str(source_type or "")
    if kind in _USER_TYPES:
        return "user"
    if kind in _ASSISTANT_TYPES:
        return "assistant"
    if kind in _TOOL_TYPES:
        return "tool"
    return "unknown"


def locator(
    *,
    source_kind: str,
    source_type: str,
    raw: dict,
    digest: str,
    default_seq: int,
) -> dict:
    """The registry-shaped evidence locator for one raw provider event."""
    fallback = str(raw.get("seq", default_seq))
    return {
        "source_kind": source_kind,
        "source_session_id": str(raw.get("session_id") or raw.get("id") or fallback),
        "source_message_id": str(raw.get("message_id") or fallback),
        "source_part_id": str(raw.get("part_id") or fallback),
        "source_digest": digest,
        "role": role_of(source_type, raw),
    }
