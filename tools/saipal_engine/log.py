"""The append-only event log (LOG.jsonl).

One JSON object per line, carrying its own sequence number. The log is
evidence, not authority: a malformed line is counted and skipped, never
repaired, because a log that edits itself cannot be trusted as evidence.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .capability import require_action
from .errors import PalError
from .paths import LOG_NAME, confined_append_line, home_paths, utc_now_iso

TAIL_WINDOW = 65536


def append_event(
    home: Path | str,
    event: str,
    *,
    data: dict | None = None,
    registry: dict | None = None,
) -> dict:
    """Append one event and return the record that was written."""
    require_action("write_own_log", registry=registry)

    paths = home_paths(home)
    # T-127 Defect B: append_event is NOT an owner of home bootstrap. The
    # previous raw `paths.root.mkdir(parents=True, exist_ok=True)` materialized
    # the home recursively through whatever the operating system's pathname
    # resolver found -- so a home whose lexical ancestor was a symlink/junction
    # CREATED external directories and then wrote LOG.jsonl outside the home.
    # A writer path must arrive with an already-established authorized home
    # (`ensure_home` owns materialization, through `confined_mkdir`); the
    # append primitive itself refuses a home reached through an untrusted
    # lexical ancestor before any byte or directory changes.

    record = {
        "seq": last_seq(paths.log) + 1,
        "ts": utc_now_iso(),
        "event": str(event),
        "data": data or {},
    }
    line = (json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")

    # PAL-WRITE-01 (T-125): the append goes through the shared physical
    # confinement primitive. The old direct os.open followed a replaced
    # LOG.jsonl symlink (or a redirected parent) and wrote events outside the
    # home; confined_append_line refuses a final symlink outright (O_NOFOLLOW
    # where available) and binds the open to the verified home fd, so a parent
    # swap after validation cannot redirect the write. Append-only semantics,
    # the single-line write and fsync are preserved; a refusal leaves every
    # external byte untouched.
    try:
        confined_append_line(paths.root, LOG_NAME, line)
    except OSError as exc:
        raise PalError("WRITER_BUSY", f"cannot append to home log: {exc}") from exc
    return record


def last_seq(path: Path | str) -> int:
    """The highest sequence number already durable, or 0 for an empty log.

    Scans backwards in bounded chunks until a record with an integer `seq` is
    found or the file begins. A single window is not enough: a torn or corrupt
    tail longer than one window returned 0, the next append restarted numbering
    at 1, and the append-only log then carried a later event with a smaller `seq`
    than its own history (audit CORE-008).

    A chunk boundary can split a record, so each chunk keeps the bytes before its
    first newline for the next iteration rather than parsing a fragment.
    """
    target = Path(path)
    try:
        size = target.stat().st_size
        if size == 0:
            return 0
        with open(str(target), "rb") as handle:
            position = size
            carry = b""
            while position > 0:
                start = max(0, position - TAIL_WINDOW)
                handle.seek(start)
                chunk = handle.read(position - start) + carry
                position = start
                lines = chunk.split(b"\n")
                # The first element may be the tail of a record whose start lies
                # in the chunk we have not read yet; carry it, unless we are at
                # the beginning of the file, where it is a whole line.
                carry = lines.pop(0) if position > 0 else b""
                for line in reversed(lines):
                    seq = _seq_of(line)
                    if seq is not None:
                        return seq
            seq = _seq_of(carry)
            if seq is not None:
                return seq
    except FileNotFoundError:
        return 0
    except OSError:
        return 0
    return 0


def _seq_of(raw: bytes) -> int | None:
    """The `seq` of one log line, or None when the line proves nothing.

    A torn line has no trustworthy sequence number; an earlier line does.
    """
    line = raw.decode("utf-8", errors="replace").strip()
    if not line:
        return None
    try:
        record = json.loads(line)
    except ValueError:
        return None
    if isinstance(record, dict) and isinstance(record.get("seq"), int) and not isinstance(
        record.get("seq"), bool
    ):
        return record["seq"]
    return None


def read_events(home: Path | str) -> tuple[list[dict], int]:
    """`(events, malformed_count)`. Malformed lines are skipped, never repaired."""
    events: list[dict[str, Any]] = []
    malformed = 0
    for record in _iter_lines(home):
        if isinstance(record, dict):
            events.append(record)
        else:
            malformed += 1
    return events, malformed


def log_stats(home: Path | str) -> tuple[int, int]:
    """`(event_count, malformed_count)` without retaining the log.

    `status` needs two scalars, and getting them through `read_events` decoded and
    kept every record ever written: 100k events measured 0.96s and a 94 MB
    allocation peak for two numbers (PERF-006). Streaming keeps the counters and
    drops each record.
    """
    events = 0
    malformed = 0
    for record in _iter_lines(home):
        if isinstance(record, dict):
            events += 1
        else:
            malformed += 1
    return events, malformed


def _iter_lines(home: Path | str):
    """Yield each log line parsed, or a sentinel string for a malformed one.

    Reads line by line so neither caller has to hold the file in memory. A
    missing or unreadable log yields nothing: absence is not corruption, and it
    is not this function's job to decide which.
    """
    paths = home_paths(home)
    try:
        handle = open(str(paths.log), "rb")
    except FileNotFoundError:
        return
    except OSError:
        return
    with handle:
        for raw in handle:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                yield "<malformed>"
                continue
            yield record if isinstance(record, dict) else "<malformed>"
