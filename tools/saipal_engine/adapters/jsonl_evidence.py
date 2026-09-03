"""Shared bounded evidence-window reader for JSONL-backed providers.

Claude, Codex and Gemini all persist a session as one JSONL file per session.
The window logic is identical for all three, so it lives here once: locate the
anchor line by digest or part id, then return a bounded neighbourhood around it.

This is read-only by construction. It opens the configured source, reads text,
and returns structured items — it never writes, caches or advances a watermark.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..errors import PalError
from ..paths import sha256_text

#: Hard ceiling on how much raw text one window may carry, independent of the
#: caller's before/after. A provider file can hold a single enormous line, and an
#: evidence window is a quotation, not a dump.
MAX_ITEM_CHARS = 4000
MAX_TOTAL_CHARS = 12000
MAX_ITEMS = 25


def _load_lines(source_path: str) -> list[str]:
    path = Path(source_path)
    if not path.is_file():
        raise PalError(
            "EVIDENCE_NOT_FOUND",
            f"provider source {source_path!r} is not a readable file",
            next_action="check the configured source path",
        )
    try:
        return path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise PalError(
            "EVIDENCE_NOT_FOUND", f"provider source is unreadable: {exc}"
        ) from exc


def _anchor_index(lines: list[str], locator: dict) -> int:
    """Where the locator points, by digest first and part id second.

    Digest wins because it survives reordering, and it must win GLOBALLY rather
    than per line: checking both keys line by line lets an earlier line's part id
    beat a later line's exact digest, which is the collision case digests exist
    to settle. So the digest pass runs over the whole file before the part id is
    consulted at all.

    An unresolvable locator is a refusal, not a silent window over line zero: a
    window that does not contain the cited event is worse than no window.
    """
    target_digest = str(locator.get("source_digest") or "")
    target_part = str(locator.get("source_part_id") or "")

    if target_digest:
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            if sha256_text(line) == target_digest:
                return index
            try:
                payload = json.loads(line)
            except ValueError:
                continue
            content = payload.get("content", payload)
            text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
            if sha256_text(text) == target_digest:
                return index

    if target_part:
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except ValueError:
                continue
            if str(payload.get("seq", index + 1)) == target_part:
                return index

    raise PalError(
        "EVIDENCE_NOT_FOUND",
        "the locator does not resolve to any line in the provider source",
        next_action="re-index the session; the raw source may have changed",
    )


def _clip(payload: object) -> object:
    rendered = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    if len(rendered) <= MAX_ITEM_CHARS:
        return payload
    return {"truncated": True, "excerpt": rendered[:MAX_ITEM_CHARS]}


def jsonl_window(
    source_path: str,
    locator: dict,
    *,
    provider: str,
    before: int = 3,
    after: int = 3,
) -> dict:
    """One bounded `UNTRUSTED EVIDENCE` window around the located event."""
    lines = _load_lines(source_path)
    anchor = _anchor_index(lines, locator)

    start = max(0, anchor - max(0, int(before)))
    end = min(len(lines), anchor + max(0, int(after)) + 1)

    items: list[dict] = []
    total = 0
    for index in range(start, end):
        line = lines[index]
        if not line.strip():
            continue
        if len(items) >= MAX_ITEMS or total >= MAX_TOTAL_CHARS:
            break
        try:
            payload = json.loads(line)
        except ValueError:
            payload = {"unparsed_line": line[:MAX_ITEM_CHARS]}
        clipped = _clip(payload)
        total += len(json.dumps(clipped, ensure_ascii=False))
        items.append(
            {
                "index": index,
                "is_anchor": index == anchor,
                "payload": clipped,
            }
        )

    return {
        "warning": "UNTRUSTED EVIDENCE",
        "provider": provider,
        "session_id": Path(source_path).stem,
        "project": None,
        "model": None,
        "anchor": {"line_index": anchor, "evidence_ref": dict(locator)},
        "items": items,
        "total_items": len(items),
    }
