"""Secret redaction for SAIPAL audit bodies (PAL-AUDIT-03)."""

from __future__ import annotations

import hashlib
import re
from typing import Any

REDACTED_PREFIX = "[REDACTED sha256="

_PATTERN_SPECS: tuple[tuple[str, str], ...] = (
    (r"Bearer\s+[A-Za-z0-9._-]+", "bearer token"),
    (r"(?i)password\s*[:=]\s*\S+", "password assignment"),
    (r"Authorization:\s*\S+", "authorization header"),
    (r"https?://[^:\s]+:[^@\s]+@", "credential-bearing URL"),
    (r"(?i)(?:sk|pk|api[_-]?key|token|secret)[_-]?[A-Za-z0-9_-]{16,}", "generic secret"),
    (r"(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[abp]-[A-Za-z0-9-]{10,})", "vendor key"),
)

PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(spec) for spec, _ in _PATTERN_SPECS
)

_MAX_DEPTH = 10


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _redact_match(match: re.Match[str]) -> str:
    return f"{REDACTED_PREFIX}{_digest(match.group(0))}]"


def redact_text(text: str) -> str:
    out = text
    for pattern in PATTERNS:
        out = pattern.sub(_redact_match, out)
    return out


def has_secrets(text: str) -> bool:
    return any(pattern.search(text) for pattern in PATTERNS)


def _redact_node(node: Any, depth: int) -> Any:
    if depth >= _MAX_DEPTH:
        return node
    if isinstance(node, str):
        return redact_text(node)
    if isinstance(node, dict):
        return {key: _redact_node(value, depth + 1) for key, value in node.items()}
    if isinstance(node, list):
        return [_redact_node(item, depth + 1) for item in node]
    if isinstance(node, tuple):
        return tuple(_redact_node(item, depth + 1) for item in node)
    return node


def redact_dict(data: dict, depth: int = 0) -> dict:
    out = _redact_node(data, depth)
    if not isinstance(out, dict):
        raise ValueError("redact_dict top-level is not a dict after redaction")
    return out


def redact_audit_body(body: str) -> str:
    return redact_text(body)
