"""opencode adapter -- reads the real opencode SQLite store.

opencode persists sessions in a SQLite database (`opencode.db`), not JSONL:
`session` (identity, directory, model, timestamps), `message` (role, time,
summary), `part` (text / step-start / reasoning / tool / step-finish / patch).

Evidence rules:
- `reasoning` parts are hidden chain-of-thought and are NEVER admitted
  (PAL-EVIDENCE-01) -- they are dropped before a bundle is built.
- `tool` parts with a `bash` command become COMMAND events (they feed the
  command-route detector); other tool parts become TOOL_CALL/TOOL_RESULT.
- `text` parts become USER_MESSAGE / ASSISTANT_MESSAGE by their message role.
- `step-start`/`step-finish` become SESSION_BOUNDARY markers; `patch` becomes
  FILE_WRITE.

The database is opened read-only (`mode=ro`); SAIPAL never writes to the
analyzed agent's store.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from saipal_engine.errors import PalError
from saipal_engine.paths import sha256_text
from saipal_engine.registry import require_mapping

NAME = "opencode"

HOME_DIRNAME = "opencode"
DB_NAME = "opencode.db"

REF_SEP = "#"

EXCERPT_LIMIT = 2000

TEXT_TO_TYPE = {
    "text": "USER_MESSAGE",
    "reasoning": "ASSISTANT_MESSAGE",
}

TOOL_COMMANDS = ("bash", "powershell", "shell", "terminal", "cmd")

#: A protocol command is a carrier-routed SAIPEN/SAIPAL invocation, never an
#: ordinary shell command the agent happened to execute through a tool. The
#: distinction is load-bearing: `detect_command_route` judges whether a command
#: routed inside the declared command surface, and `git log` was never a
#: candidate for that surface. Feeding it shell commands turns every ordinary
#: tool call into a fabricated COMMAND_ROUTE_DRIFT finding.
PROTOCOL_PROGRAMS = ("saipen", "saipal")

#: Bare repeated-letter shortcuts (CORE.md 1.10's table) plus their Cyrillic
#: twins. A whole-message shortcut IS a protocol command.
PROTOCOL_SHORTCUTS = frozenset(
    {
        "gg", "hh", "ff", "xx", "vv", "zz", "cc", "ccc", "ss", "sss",
        "dd", "aa", "qq", "qqq", "ee", "eee", "pp", "tt", "sc",
        "сс", "ссс", "аа", "ее", "еее", "рр", "хх",
    }
)

#: Shortcuts that legally carry an opaque payload after the key (CORE.md 1.10's
#: control-shortcut payload rule). Whole-token recognition only: `ff topbar` is
#: focus with a payload, `ffmpeg` is not a shortcut.
PAYLOAD_SHORTCUTS = frozenset({"gg", "ff", "vv", "xx", "zz", "dd", "хх"})


def protocol_command(text: str) -> str | None:
    """The canonical protocol command in `text`, or None if it is not one.

    Three shapes count: an explicit `saipen`/`saipal` invocation (optionally
    slash-prefixed), a bare declared shortcut as the whole message, and a
    payload-carrying shortcut whose first whole token is the key. An ordinary
    shell command is NOT a protocol command, however it was executed, and
    neither is prose that merely begins with the product name.
    """
    if not isinstance(text, str):
        return None
    stripped = text.strip()
    if not stripped or "\n" in stripped:
        return None
    head = stripped.lstrip("/").split()
    if not head:
        return None
    first = head[0].lower()
    if first in PROTOCOL_PROGRAMS:
        # `saipal` alone is the bare-continue form; anything after it must look
        # like a subcommand, never prose or a path. Prose that happens to start
        # with the product name ("SAIPAL - this folder is ...") is not a command.
        if len(head) == 1:
            return first
        second = head[1]
        if not _SUBCOMMAND_RE.fullmatch(second):
            return None
        return " ".join([first] + head[1:])
    if len(head) == 1 and first in PROTOCOL_SHORTCUTS:
        return first
    if len(head) > 1 and first in PAYLOAD_SHORTCUTS:
        return " ".join([first] + head[1:])
    return None


#: A subcommand is a plain word: letters, digits, dashes, underscores. A path,
#: a dash-only separator, or punctuation-laden prose is not a subcommand.
_SUBCOMMAND_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")


def _home_candidates() -> list[Path]:
    """Known opencode data-home locations, in discovery preference order."""
    out: list[Path] = []
    import os

    home = Path.home()
    for candidate in (
        Path(os.environ.get("XDG_DATA_HOME") or home / ".local" / "share"),
        home / ".local" / "share",
        home / ".config",
        home / ".opencode",
    ):
        out.append(candidate / HOME_DIRNAME)
    return out


def find_home(*, explicit: Path | str | None = None) -> Path | None:
    """Locate the opencode data directory holding `opencode.db`."""
    if explicit:
        candidate = Path(explicit).expanduser()
        if candidate.is_file() and candidate.name == DB_NAME:
            return candidate.parent
        if (candidate / DB_NAME).is_file():
            return candidate
        return None
    for candidate in _home_candidates():
        if (candidate / DB_NAME).is_file():
            return candidate
    return None


def _open_db(home: Path) -> sqlite3.Connection:
    db = home / DB_NAME
    return sqlite3.connect(f"file:{db}?mode=ro", uri=True)


def discover(source_path: str) -> list[dict]:
    """List sessions in the store, freshest first.

    Each entry carries a virtual reference `path` of the form
    `<db-dir>#<session_id>` that `normalize` parses back.
    """
    home = find_home(explicit=source_path)
    if home is None:
        return []
    try:
        con = _open_db(home)
    except sqlite3.Error:
        return []
    try:
        cur = con.cursor()
        rows = cur.execute(
            "SELECT id, title, directory, agent, model, time_created, "
            "time_updated, time_archived "
            "FROM session ORDER BY time_updated DESC"
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        con.close()

    out: list[dict] = []
    for row in rows:
        session_id, title, directory, agent, model, _tc, updated, archived = row
        model_name = _model_name(model)
        out.append(
            {
                "path": f"{home}{REF_SEP}{session_id}",
                "name": session_id,
                "session_id": session_id,
                "title": title or "",
                "directory": directory or "",
                "agent": agent or "",
                "model": model_name,
                "size": 0,
                "time_updated": updated,
                "archived": bool(archived),
            }
        )
    return out


def _split_ref(file_path: str) -> tuple[Path, str]:
    home_raw, _, session_id = file_path.rpartition(REF_SEP)
    return Path(home_raw), session_id


def identity(file_path: str) -> str:
    home, session_id = _split_ref(file_path)
    try:
        con = _open_db(home)
    except sqlite3.Error:
        return sha256_text(file_path)
    try:
        cur = con.cursor()
        data = cur.execute(
            "SELECT id, session_id, message_id, time_created, data FROM part "
            "WHERE session_id=? ORDER BY time_created, id",
            (session_id,),
        ).fetchall()
    except sqlite3.Error:
        return sha256_text(file_path)
    finally:
        con.close()
    blob = "".join(
        json.dumps(
            {
                "part_id": row[0],
                "session_id": row[1],
                "message_id": row[2],
                "time_created": row[3],
                "data": row[4],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        for row in data
    )
    return sha256_text(blob) if blob else sha256_text(file_path)


def stable_watermark(file_path: str) -> int:
    home, session_id = _split_ref(file_path)
    try:
        con = _open_db(home)
        cur = con.cursor()
        return int(
            cur.execute(
                "SELECT count(*) FROM part WHERE session_id=?", (session_id,)
            ).fetchone()[0]
        )
    except sqlite3.Error:
        return 0
    finally:
        try:
            con.close()
        except sqlite3.Error:
            pass


def _model_name(model: object) -> str:
    if not model:
        return "unknown"
    if isinstance(model, dict):
        return str(model.get("id") or model.get("modelID") or "unknown")
    try:
        parsed = json.loads(str(model))
        if isinstance(parsed, dict):
            return str(parsed.get("id") or parsed.get("modelID") or "unknown")
    except ValueError:
        pass
    return str(model)


def _session_row(home: Path, session_id: str) -> dict | None:
    try:
        con = _open_db(home)
    except sqlite3.Error:
        return None
    try:
        cur = con.cursor()
        row = cur.execute(
            "SELECT id, project_id, directory, path, title, version, agent, model, "
            "time_created, time_updated, time_archived "
            "FROM session WHERE id=?",
            (session_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "session_id": row[0],
            "project_id": row[1],
            "directory": row[2] or "",
            "path": row[3] or "",
            "title": row[4] or "",
            "version": row[5] or "",
            "agent": row[6] or "",
            "model": row[7] or "",
            "time_created": row[8],
            "time_updated": row[9],
            "time_archived": row[10],
        }
    except sqlite3.Error:
        return None
    finally:
        con.close()


def _read_rows(home: Path, session_id: str) -> list[dict]:
    """Provider rows with stable ids, ordered by provider time then part id."""
    try:
        con = _open_db(home)
        cur = con.cursor()
        rows = cur.execute(
            "SELECT m.id, m.session_id, m.time_created, m.data FROM message m "
            "WHERE m.session_id=? ORDER BY m.time_created, m.id",
            (session_id,),
        ).fetchall()
        parts = cur.execute(
            "SELECT p.id, p.session_id, p.message_id, p.time_created, p.data FROM part p "
            "WHERE p.session_id=? ORDER BY p.time_created, p.id",
            (session_id,),
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        try:
            con.close()
        except sqlite3.Error:
            pass

    messages: dict[str, dict] = {}
    for mid, message_session_id, ts, data in rows:
        try:
            messages[mid] = {
                "id": mid,
                "session_id": message_session_id,
                "time": ts,
                "data": json.loads(data),
            }
        except (ValueError, TypeError):
            continue
    out: list[dict] = []
    for part_id, part_session_id, mid, ts, data in parts:
        if not all(isinstance(value, str) and value for value in (part_id, part_session_id, mid)):
            continue
        try:
            payload = json.loads(data)
        except (ValueError, TypeError):
            continue
        msg = messages.get(mid) or {
            "id": mid,
            "session_id": part_session_id,
            "time": ts,
            "data": {},
        }
        out.append(
            {
                "time": ts,
                "part_id": part_id,
                "session_id": part_session_id,
                "message_id": mid,
                "part_raw": data,
                "part": payload,
                "message": msg["data"],
            }
        )
    return out


def _evidence_ref(row: dict, role: str) -> dict:
    return {
        "source_kind": NAME,
        "source_session_id": str(row["session_id"]),
        "source_message_id": str(row["message_id"]),
        "source_part_id": str(row["part_id"]),
        "source_digest": sha256_text(str(row["part_raw"])),
        "role": role if role in ("user", "assistant", "tool") else "unknown",
    }


def _attach_refs(events: list[dict], start: int, evidence_ref: dict) -> None:
    for event in events[start:]:
        event["evidence_ref"] = dict(evidence_ref)


def _evidence_sql_rows(
    cur: sqlite3.Cursor,
    session_id: str,
    anchor_time: int,
    anchor_id: str,
    *,
    before: bool,
    limit: int,
) -> list[tuple]:
    if limit <= 0:
        return []
    relation = "<" if before else ">"
    order = "DESC" if before else "ASC"
    rows = cur.execute(
        "SELECT p.id, p.session_id, p.message_id, p.time_created, p.data, m.data "
        "FROM part p LEFT JOIN message m ON m.id=p.message_id "
        "WHERE p.session_id=? AND json_valid(p.data) "
        "AND COALESCE(json_extract(p.data, '$.type'), '') <> 'reasoning' "
        f"AND (p.time_created {relation} ? OR "
        f"(p.time_created=? AND p.id {relation} ?)) "
        f"ORDER BY p.time_created {order}, p.id {order} LIMIT ?",
        (session_id, anchor_time, anchor_time, anchor_id, limit),
    ).fetchall()
    return list(reversed(rows)) if before else rows


def _bounded_item(row: tuple, *, single_limit: int, remaining: int) -> tuple[dict | None, bool]:
    part_id, session_id, message_id, timestamp, raw_part, raw_message = row
    try:
        part = json.loads(raw_part)
        message = json.loads(raw_message) if raw_message else {}
    except (TypeError, ValueError):
        return None, False
    ptype = str(part.get("type") or "")
    role = str(message.get("role") or ("tool" if ptype == "tool" else "unknown"))
    item = {
        "source_message_id": message_id,
        "source_part_id": part_id,
        "role": role if role in ("user", "assistant", "tool") else "unknown",
        "admissible_type": ptype,
        "digest": sha256_text(str(raw_part)),
        "timestamp": timestamp,
    }
    values: list[tuple[str, str]] = []
    if ptype == "text":
        values.append(("text", str(part.get("text") or "")))
    elif ptype == "tool":
        state = part.get("state") or {}
        values.append(
            ("tool_input", json.dumps(state.get("input") or {}, sort_keys=True, ensure_ascii=False))
        )
        values.append(("tool_output", str(state.get("output") or "")))
        item["tool"] = str(part.get("tool") or "")
        item["status"] = str(state.get("status") or "")
    elif ptype == "patch":
        values.append(("text", json.dumps(part.get("files") or [], ensure_ascii=False)))
    elif ptype in ("step-start", "step-finish"):
        values.append(("text", str(part.get("reason") or ptype)))
    else:
        return None, False

    oversized = False
    left = max(0, remaining)
    for key, value in values:
        take = min(len(value), single_limit, left)
        item[key] = value[:take]
        if take < len(value):
            oversized = True
        left -= take
    return item, oversized


def read_evidence(
    source_ref: str,
    locator: dict,
    *,
    before: int,
    after: int,
    registry: dict,
) -> dict:
    """Return one bounded OpenCode window without exposing reasoning parts."""
    home, session_id = _split_ref(source_ref)
    if locator.get("source_kind") != NAME or locator.get("source_session_id") != session_id:
        raise PalError("EVIDENCE_MISMATCH", "locator does not belong to the indexed source")
    part_id = locator.get("source_part_id")
    message_id = locator.get("source_message_id")
    if not isinstance(part_id, str) or not part_id:
        raise PalError("EVIDENCE_NOT_FOUND", "locator has no provider part id")

    limits = require_mapping(registry, "evidence_window_limits")
    max_items = int(limits["max_evidence_items"])
    before = max(0, min(int(before), max_items - 1))
    after = max(0, min(int(after), max_items - 1 - before))
    try:
        con = _open_db(home)
        cur = con.cursor()
        anchor = cur.execute(
            "SELECT p.id, p.session_id, p.message_id, p.time_created, p.data, m.data "
            "FROM part p LEFT JOIN message m ON m.id=p.message_id "
            "WHERE p.session_id=? AND p.id=?",
            (session_id, part_id),
        ).fetchone()
        if anchor is None:
            raise PalError("EVIDENCE_NOT_FOUND", "provider part no longer exists")
        try:
            anchor_part = json.loads(anchor[4])
        except (TypeError, ValueError) as exc:
            raise PalError("EVIDENCE_INADMISSIBLE", "provider part is malformed") from exc
        if anchor_part.get("type") == "reasoning":
            raise PalError(
                "EVIDENCE_INADMISSIBLE",
                "reasoning parts are outside the evidence surface",
            )
        if message_id and anchor[2] != message_id:
            raise PalError("EVIDENCE_MISMATCH", "locator message id does not match provider data")
        if locator.get("source_digest") != sha256_text(str(anchor[4])):
            raise PalError("EVIDENCE_MISMATCH", "locator digest does not match provider data")
        prior = _evidence_sql_rows(
            cur, session_id, int(anchor[3]), part_id, before=True, limit=before
        )
        following = _evidence_sql_rows(
            cur, session_id, int(anchor[3]), part_id, before=False, limit=after
        )
        reasoning_count = int(
            cur.execute(
                "SELECT count(*) FROM part WHERE session_id=? AND json_valid(data) "
                "AND json_extract(data, '$.type')='reasoning'",
                (session_id,),
            ).fetchone()[0]
        )
    except sqlite3.Error as exc:
        raise PalError("EVIDENCE_NOT_FOUND", f"cannot read provider evidence: {exc}") from exc
    finally:
        try:
            con.close()
        except (UnboundLocalError, sqlite3.Error):
            pass

    raw_rows = [*prior, anchor, *following]
    max_chars = int(limits["max_evidence_chars"])
    single_limit = int(limits["max_single_item_chars"])
    items: list[dict] = []
    chars = 0
    oversized = 0
    unsupported = 0
    for row in raw_rows:
        item, was_oversized = _bounded_item(
            row, single_limit=single_limit, remaining=max_chars - chars
        )
        if item is None:
            unsupported += 1
            continue
        chars += sum(len(str(item.get(key) or "")) for key in ("text", "tool_input", "tool_output"))
        oversized += int(was_oversized)
        items.append(item)
        if chars >= max_chars:
            break

    meta = _session_row(home, session_id) or {}
    envelope = {
        "schema_version": 1,
        "warning": "UNTRUSTED EVIDENCE",
        "session_id": session_id,
        "adapter": NAME,
        "provider": NAME,
        "project": {"name": _project_name(meta), "path": meta.get("directory") or meta.get("path")},
        "model": _model_name(meta.get("model")),
        "anchor": {"event_seq": None, "evidence_ref": dict(locator)},
        "items": items,
        "omitted": {
            "reasoning_parts": reasoning_count,
            "oversized_parts": oversized,
            "unsupported_parts": unsupported,
        },
    }
    stable = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    envelope["window_digest"] = sha256_text(stable)
    envelope["evidence_window_id"] = "evw-" + envelope["window_digest"][:24]
    return envelope


_SAPEN_VERSION_RE = re.compile(r"saipen_version[\"':=\s]*(\d+(?:\.\d+){0,2})")
_GIT_HEAD_RE = re.compile(r"git_head[\"':=\s]*([0-9a-f]{40}(?:[0-9a-f]{24})?)")
_REGISTRY_DIGEST_RE = re.compile(r"registry_sha256[\"':=\s]*([0-9a-f]{64})")


def _binding_from_tool_output(rows: list[dict]) -> dict:
    """Capture an exact protocol fingerprint if a STATE.md read shows one."""
    version = ""
    git_head = ""
    digest = ""
    for row in rows:
        part = row["part"]
        if part.get("type") != "tool":
            continue
        state = part.get("state") or {}
        output = state.get("output")
        if not isinstance(output, str):
            continue
        if version == "":
            m = _SAPEN_VERSION_RE.search(output)
            if m:
                version = m.group(1)
        if git_head == "":
            m = _GIT_HEAD_RE.search(output)
            if m:
                git_head = m.group(1)
        if digest == "":
            m = _REGISTRY_DIGEST_RE.search(output)
            if m:
                digest = m.group(1)
    if version and digest:
        status = "BOUND"
    elif version or git_head:
        status = "PARTIAL"
    else:
        return {"binding_status": "UNKNOWN", "source": "opencode-sqlite"}
    binding: dict[str, Any] = {"binding_status": status, "source": "opencode-sqlite"}
    if version:
        binding["version"] = version
    if git_head:
        binding["git_head"] = git_head
    if digest:
        binding["registry_sha256"] = digest
    return binding


def normalize(file_path: str) -> dict:
    home, session_id = _split_ref(file_path)
    meta = _session_row(home, session_id)
    if meta is None:
        raise ValueError(f"opencode session {session_id!r} not found in {home}")
    rows = _read_rows(home, session_id)

    events: list[dict] = []
    seq = 0
    last_command_seen = False
    closed = bool(meta["time_archived"])

    for row in rows:
        part = row["part"]
        ptype = part.get("type", "")
        if ptype == "reasoning":
            # hidden chain-of-thought: inadmissible evidence, never admitted
            continue
        message = row["message"] or {}
        role = message.get("role", "")
        event_start = len(events)
        evidence_role = "tool" if ptype == "tool" else role
        evidence_ref = _evidence_ref(row, evidence_role)

        if ptype == "text":
            text_value = part.get("text", "")
            canonical = protocol_command(text_value)
            if canonical is not None and role != "assistant":
                # a user-typed protocol command: the real carrier surface
                seq += 1
                events.append(
                    _event(
                        seq,
                        "COMMAND",
                        text_value,
                        _facts(
                            {
                                "canonical": canonical,
                                "role": role,
                                "opencode_type": "text",
                            }
                        ),
                    )
                )
                _attach_refs(events, event_start, evidence_ref)
                continue
            seq += 1
            events.append(
                _event(
                    seq,
                    "ASSISTANT_MESSAGE" if role == "assistant" else "USER_MESSAGE",
                    text_value,
                    _facts({"role": role, "opencode_type": "text"}),
                )
            )
            _attach_refs(events, event_start, evidence_ref)
            continue

        if ptype == "tool":
            tool = part.get("tool", "")
            state = part.get("state") or {}
            status = state.get("status", "")
            inp = state.get("input") or {}
            output = state.get("output")
            raw_command = inp.get("command") if isinstance(inp.get("command"), str) else None
            canonical = protocol_command(raw_command) if raw_command else None
            if tool in TOOL_COMMANDS and canonical is not None:
                # a real protocol command, routed through a shell tool
                seq += 1
                events.append(
                    _event(
                        seq,
                        "COMMAND",
                        raw_command or "",
                        _facts(
                            {
                                "canonical": canonical,
                                "tool": tool,
                                "status": status,
                                "opencode_type": "tool",
                            }
                        ),
                    )
                )
                if status == "error":
                    seq += 1
                    events.append(
                        _event(
                            seq,
                            "ERROR",
                            str(output or "")[:EXCERPT_LIMIT],
                            _facts({"tool": tool, "status": status}),
                        )
                    )
            elif tool in TOOL_COMMANDS and raw_command is not None:
                # ordinary shell work: a tool call, never a protocol command
                seq += 1
                events.append(
                    _event(
                        seq,
                        "TOOL_CALL",
                        raw_command,
                        _facts(
                            {
                                "tool": tool,
                                "status": status,
                                "shell": True,
                                "opencode_type": "tool",
                            }
                        ),
                    )
                )
                if status == "error":
                    seq += 1
                    events.append(
                        _event(
                            seq,
                            "ERROR",
                            str(output or "")[:EXCERPT_LIMIT],
                            _facts({"tool": tool, "status": status}),
                        )
                    )
            else:
                seq += 1
                events.append(
                    _event(
                        seq,
                        "TOOL_CALL",
                        str(inp)[:EXCERPT_LIMIT],
                        _facts({"tool": tool, "status": status, "call_id": part.get("callID")}),
                    )
                )
                if output:
                    seq += 1
                    events.append(
                        _event(
                            seq,
                            "TOOL_RESULT",
                            str(output)[:EXCERPT_LIMIT],
                            _facts({"tool": tool, "status": status}),
                        )
                    )
            _attach_refs(events, event_start, evidence_ref)
            continue

        if ptype in ("step-start", "step-finish"):
            seq += 1
            events.append(
                _event(
                    seq,
                    "SESSION_BOUNDARY",
                    "",
                    _facts(
                        {
                            "kind": "step",
                            "phase": ptype,
                            "reason": part.get("reason"),
                        }
                    ),
                )
            )
            _attach_refs(events, event_start, evidence_ref)
            continue

        if ptype == "patch":
            seq += 1
            events.append(
                _event(
                    seq,
                    "FILE_WRITE",
                    "",
                    _facts({"files": part.get("files"), "hash": part.get("hash")}),
                )
            )
            _attach_refs(events, event_start, evidence_ref)
            continue

        # unknown part type: record as SOURCE_EVENT, never as transcript
        seq += 1
        events.append(
            _event(
                seq,
                "SOURCE_EVENT",
                "",
                _facts({"opencode_type": ptype, "note": "unmapped part type"}),
            )
        )
        _attach_refs(events, event_start, evidence_ref)

    protocol = _binding_from_tool_output(rows)
    closed = closed or _is_closed(rows, events)

    return {
        "schema_version": 1,
        "session_id": session_id,
        "adapter": NAME,
        "project": {"name": _project_name(meta), "path": meta["directory"] or meta["path"]},
        "runtime": {
            "provider": "opencode",
            "model": _model_name(meta["model"]),
            "reasoning_mode": "unknown",
            "agent": meta["agent"],
            "opencode_version": meta["version"],
        },
        "temperature": "COLD" if closed else "HOT",
        "protocol": protocol,
        "events": events,
        "raw_source_ref": file_path,
        "raw_source_sha256": identity(file_path),
    }


def _is_closed(rows: list[dict], events: list[dict]) -> bool:
    if not events:
        return True
    last = events[-1]
    if last.get("type") == "SESSION_BOUNDARY" and (
        last.get("facts") or {}
    ).get("reason") in ("done", "error", "cancel", "cancelled", "stop"):
        return True
    return False


def _project_name(meta: dict) -> str:
    if meta.get("title"):
        return meta["title"]
    directory = meta.get("directory") or meta.get("path") or ""
    return directory.replace("\\", "/").rstrip("/").split("/")[-1] or "unknown"


def _facts(extra: dict) -> dict:
    facts: dict[str, Any] = {}
    for key, value in extra.items():
        if value is None:
            continue
        if key in ("files",) and isinstance(value, list):
            facts[key] = [str(v) for v in value][:16]
        elif key in ("reason",) and value is not None:
            facts[key] = str(value)[:64]
        elif key == "canonical":
            facts[key] = str(value)[:EXCERPT_LIMIT]
        else:
            facts[key] = value
    return facts


def _event(seq: int, etype: str, text: str, facts: dict) -> dict:
    excerpt = text[:EXCERPT_LIMIT]
    return {
        "seq": seq,
        "type": etype,
        "ts": None,
        "loc": None,
        "digest": sha256_text(text) if text else None,
        "facts": dict(facts, excerpt=excerpt, digest=sha256_text(text)) if text else facts,
    }


def protocol_binding(file_path: str) -> dict:
    return normalize(file_path).get("protocol", {"binding_status": "UNKNOWN"})
