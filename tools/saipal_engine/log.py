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
from .paths import home_paths, utc_now_iso

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
    paths.root.mkdir(parents=True, exist_ok=True)

    record = {
        "seq": last_seq(paths.log) + 1,
        "ts": utc_now_iso(),
        "event": str(event),
        "data": data or {},
    }
    line = (json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")

    descriptor = os.open(str(paths.log), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        view = memoryview(line)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write to home log")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as exc:
        raise PalError("WRITER_BUSY", f"cannot append to home log: {exc}") from exc
    finally:
        os.close(descriptor)
    return record


def last_seq(path: Path | str) -> int:
    """The highest sequence number already durable, or 0 for an empty log."""
    target = Path(path)
    try:
        size = target.stat().st_size
        if size == 0:
            return 0
        with open(str(target), "rb") as handle:
            handle.seek(max(0, size - TAIL_WINDOW))
            tail = handle.read().decode("utf-8", errors="replace")
    except FileNotFoundError:
        return 0
    except OSError:
        return 0

    for line in reversed(tail.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            # A torn tail line has no trustworthy sequence number; the previous
            # line does. Keep walking backwards.
            continue
        if isinstance(record, dict) and isinstance(record.get("seq"), int):
            return record["seq"]
    return 0


def read_events(home: Path | str) -> tuple[list[dict], int]:
    """`(events, malformed_count)`. Malformed lines are skipped, never repaired."""
    paths = home_paths(home)
    events: list[dict[str, Any]] = []
    malformed = 0
    try:
        raw = paths.log.read_bytes()
    except FileNotFoundError:
        return events, 0
    except OSError:
        return events, 0

    for line in raw.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            malformed += 1
            continue
        if isinstance(record, dict):
            events.append(record)
        else:
            malformed += 1
    return events, malformed
