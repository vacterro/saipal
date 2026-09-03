from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from saipal_engine import bundle as bundle_mod
from saipal_engine.adapters import locators
from saipal_engine.paths import sha256_file, sha256_text

NAME = "codex"

SOURCE_SUFFIX = ".jsonl"

TYPE_MAP = {
    "user": "USER_MESSAGE",
    "assistant": "ASSISTANT_MESSAGE",
    "command": "COMMAND",
    "tool_call": "TOOL_CALL",
    "tool_result": "TOOL_RESULT",
    "file_read": "FILE_READ",
    "file_write": "FILE_WRITE",
    "state_snapshot": "STATE_SNAPSHOT",
    "board_snapshot": "BOARD_SNAPSHOT",
    "log_event": "LOG_EVENT",
    "git_event": "GIT_EVENT",
    "phase_change": "PHASE_CHANGE",
    "source_event": "SOURCE_EVENT",
    "error": "ERROR",
    "session_boundary": "SESSION_BOUNDARY",
}

EXCERPT_LIMIT = 2000


def discover(source_path: str) -> list[dict]:
    root = Path(source_path)
    if not root.is_dir():
        return []
    return [
        {"path": str(p), "name": p.name, "size": p.stat().st_size}
        for p in sorted(root.iterdir())
        if p.is_file() and p.suffix == SOURCE_SUFFIX and not p.name.startswith(".")
    ]


def identity(file_path: str) -> str:
    return sha256_file(file_path)


def stable_watermark(file_path: str) -> int:
    last_seq = 0
    for line in _read_lines(file_path):
        event = _parse_line(line)
        if event is None:
            continue
        seq = event.get("seq")
        if isinstance(seq, int) and not isinstance(seq, bool):
            last_seq = max(last_seq, seq)
    return last_seq


def normalize(file_path: str) -> dict:
    events: list[dict] = []
    for seq, line in enumerate(_read_lines(file_path), start=1):
        event = _parse_line(line)
        if event is None:
            continue
        events.append(_to_canonical(event, seq))

    return {
        "schema_version": 1,
        "session_id": _session_id(file_path),
        "adapter": NAME,
        "project": {},
        "runtime": {"provider": "openai", "model": "codex", "reasoning_mode": "unknown"},
        "temperature": "HOT",
        "protocol": {"binding_status": "UNKNOWN"},
        "events": events,
    }


def protocol_binding(file_path: str) -> dict:
    return {"binding_status": "UNKNOWN"}


def _read_lines(file_path: str) -> list[str]:
    return [
        line
        for line in Path(file_path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _parse_line(line: str) -> dict | None:
    try:
        payload = json.loads(line)
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def _to_canonical(raw: dict, default_seq: int) -> dict:
    source_type = str(raw.get("type", ""))
    canonical_type = TYPE_MAP.get(source_type, "SOURCE_EVENT")
    content = raw.get("content")
    if content is None:
        content = raw
    text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
    excerpt = text[:EXCERPT_LIMIT]
    digest = sha256_text(text)

    facts: dict[str, Any] = {
        "codex_type": source_type,
        "excerpt": excerpt,
        "digest": digest,
    }
    if len(text) > EXCERPT_LIMIT:
        facts["truncated"] = True
    for key, value in raw.items():
        if key in ("type", "content"):
            continue
        if key not in facts:
            facts[key] = value

    evidence_ref = locators.locator(
        source_kind=NAME,
        source_type=source_type,
        raw=raw,
        digest=digest,
        default_seq=default_seq,
    )

    return {
        "seq": int(raw.get("seq", default_seq)),
        "type": canonical_type,
        "ts": raw.get("ts") if isinstance(raw.get("ts"), str) else None,
        "loc": None,
        "digest": digest,
        "facts": facts,
        "evidence_ref": evidence_ref,
    }


def _session_id(file_path: str) -> str:
    return Path(file_path).stem


def read_evidence(
    source_path: str,
    evidence_ref: dict,
    *,
    before: int = 3,
    after: int = 3,
    registry: dict | None = None,
) -> dict:
    """One bounded read-only evidence window around a Codex event."""
    from saipal_engine.adapters import jsonl_window

    return jsonl_window(
        source_path, evidence_ref, provider=NAME, before=before, after=after
    )