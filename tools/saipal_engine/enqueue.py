"""Constrained audit enqueue (PAL-AUDIT-02).

The one external write SAIPAL performs: turn a QUALIFIED finding into an
immutable numbered audit on disk, in the configured maintainer root when set,
else in the local home's audit staging. Idempotent per finding + content digest;
an audit slot is never overwritten.

T-031: the enqueue acquires an audit inbox lock before allocating a number,
writing the file, or recording the entry, so two concurrent publishers cannot
race the same audit id.
"""

from __future__ import annotations

import json
import os
import socket
import time
import uuid
from pathlib import Path

from .capability import require_action
from .errors import PalError
from .paths import (
    AUDIT_LEDGER_NAME,
    AUDIT_STAGING_DIR,
    atomic_write_bytes,
    atomic_write_json,
    home_paths,
    sha256_file,
    sha256_text,
    utc_now_iso,
)

LEDGER_SCHEMA_VERSION = 1
ENTRIES_NAME = "entries.json"
AUDIT_LOCK_NAME = "audit_inbox.lock"
AUDIT_LOCK_TTL_SECONDS = 120


def enqueue_operation_id() -> str:
    return uuid.uuid4().hex


def _maintainer_audit_dir(maintainer_root: Path) -> Path:
    return Path(maintainer_root) / "audit"


def _ledger_path(home: Path, maintainer_root: Path | None) -> Path:
    if maintainer_root is not None:
        return _maintainer_audit_dir(maintainer_root) / Path(AUDIT_LEDGER_NAME).name
    return home_paths(home).audit_ledger


def _audit_dir(home: Path, maintainer_root: Path | None) -> Path:
    if maintainer_root is not None:
        return _maintainer_audit_dir(maintainer_root)
    return home_paths(home).audit_staging


def _root_of(path: Path) -> Path:
    return path.parent.parent


def _entries_path(home: Path, maintainer_root: Path | None) -> Path:
    if maintainer_root is not None:
        return _maintainer_audit_dir(maintainer_root) / ENTRIES_NAME
    return home_paths(home).root / "audit" / ENTRIES_NAME


def _read_entries(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise PalError(
            "VALIDATION_FAILED", f"audit entries ledger is unreadable: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise PalError("VALIDATION_FAILED", "audit entries ledger root is not an object")
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise PalError("VALIDATION_FAILED", "audit entries ledger `entries` is not an array")
    return [entry for entry in entries if isinstance(entry, dict)]


def _write_ledger(ledger_path: Path, entries: list[dict]) -> None:
    payload = {"schema_version": LEDGER_SCHEMA_VERSION, "entries": entries}
    atomic_write_json(ledger_path, payload, root=_root_of(ledger_path))


def _existing_numbers(audit_dir: Path) -> list[int]:
    if not audit_dir.is_dir():
        return []
    return [
        int(path.stem)
        for path in audit_dir.iterdir()
        if path.is_file() and path.suffix == ".md" and path.stem.isdigit()
    ]


def allocate_audit_id(
    home: Path, maintainer_root: Path | None = None, *, private_ledger_home: Path | None = None
) -> int:
    """Next monotonic audit id, durably recorded before use.

    The counter ledger is the source of truth; existing numbered audit files are
    consulted too so a lost or stale counter never collides with a slot on disk.
    """
    ledger_path = _ledger_path(Path(private_ledger_home or home), None) if private_ledger_home is not None else _ledger_path(home, maintainer_root)
    payload = {"schema_version": LEDGER_SCHEMA_VERSION, "next_id": 1}
    if ledger_path.exists():
        try:
            loaded = json.loads(ledger_path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            raise PalError(
                "VALIDATION_FAILED", f"audit counter ledger is unreadable: {exc}"
            ) from exc
        if isinstance(loaded, dict) and isinstance(loaded.get("next_id"), int):
            payload = loaded

    slots = _existing_numbers(_audit_dir(Path(private_ledger_home or home), None) if private_ledger_home is not None else _audit_dir(home, maintainer_root))
    next_id = max(int(payload["next_id"]), max(slots, default=0) + 1)
    payload["next_id"] = next_id + 1
    atomic_write_json(ledger_path, payload, root=_root_of(ledger_path))
    return next_id


def _result_of(entry: dict) -> dict:
    return {
        "audit_number": int(entry["audit_number"]),
        "audit_path": str(entry["audit_path"]),
        "audit_sha256": str(entry["audit_sha256"]),
        "operation_id": str(entry["enqueue_operation_id"]),
    }


class AuditInboxLock:
    """File-based lock protecting audit id allocation + file write + entry recording.

    T-031: PAL-AUDIT-02 step 1 requires acquiring the audit inbox lock before
    allocating a number. Two concurrent publishers that both read the counter
    before either writes it would race to the same ``audit/N.md``. This lock
    serializes the allocate-write-record sequence with stale-takeover semantics
    matching ``HomeLock``.
    """

    def __init__(self, lock_dir: Path, *, ttl: float = AUDIT_LOCK_TTL_SECONDS):
        self.lock_path = lock_dir / AUDIT_LOCK_NAME
        self.ttl = ttl
        self._held = False
        self.detail = ""

    @property
    def held(self) -> bool:
        return self._held

    def _payload(self) -> bytes:
        return (
            json.dumps(
                {
                    "pid": os.getpid(),
                    "host": socket.gethostname(),
                    "created_at": time.time(),
                    "owner": uuid.uuid4().hex,
                },
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")

    def _pid_alive(self, pid: int) -> bool:
        if pid <= 0:
            return False
        if os.name == "nt":
            try:
                import ctypes
                handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
                if handle:
                    ctypes.windll.kernel32.CloseHandle(handle)
                    return True
                return False
            except Exception:
                return True
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        except Exception:
            return True
        return True

    def _take_over_if_stale(self) -> bool:
        try:
            with open(str(self.lock_path), "rb") as handle:
                raw = handle.read()
            payload = json.loads(raw.decode("utf-8-sig"))
            age = time.time() - float(payload.get("created_at", 0))
            pid = int(payload.get("pid", 0))
        except (OSError, ValueError, TypeError, KeyError):
            age, pid = self.ttl + 1, 0
        if self._pid_alive(pid) and age < self.ttl:
            return False
        try:
            os.unlink(str(self.lock_path))
            return True
        except OSError:
            return False

    def acquire(self) -> bool:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        for attempt in (0, 1):
            try:
                descriptor = os.open(
                    str(self.lock_path),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                if attempt == 0 and self._take_over_if_stale():
                    continue
                self.detail = "another publisher holds the audit inbox lock"
                return False
            except OSError as exc:
                raise PalError("WRITER_BUSY", f"cannot create audit inbox lock: {exc}") from exc
            try:
                os.write(descriptor, self._payload())
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._held = True
            self.detail = "acquired"
            return True
        self.detail = "another publisher holds the audit inbox lock"
        return False

    def release(self) -> None:
        if not self._held:
            return
        try:
            os.unlink(str(self.lock_path))
        except OSError:
            pass
        self._held = False

    def __enter__(self) -> AuditInboxLock:
        if not self.acquire():
            raise PalError(
                "WRITER_BUSY",
                self.detail,
                next_action="wait for the running publisher, or remove a stale audit lock by hand",
            )
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.release()
        return False


def enqueue_audit(
    home: Path,
    finding: dict,
    audit_body: str,
    *,
    registry: dict | None = None,
    maintainer_root: Path | None = None,
    private_ledger_home: Path | None = None,
) -> dict:
    require_action("enqueue_audit", registry=registry)

    finding_id = finding.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id:
        raise PalError(
            "VALIDATION_FAILED", "finding is missing a non-empty `finding_id`"
        )

    body_sha = sha256_text(audit_body)
    audit_dir = _audit_dir(home, maintainer_root)
    ledger_home = Path(private_ledger_home or home)
    entries_path = _entries_path(ledger_home, None) if private_ledger_home is not None else _entries_path(home, maintainer_root)
    lock_dir = audit_dir
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock = AuditInboxLock(lock_dir)
    # T-031: retry briefly so a concurrent publisher does not see a hard
    # failure when the lock is legitimately held for a few milliseconds by
    # another enqueue. A stale lock is taken over; a genuinely deadlocked
    # one eventually surfaces WRITER_BUSY.
    max_retries = 50
    retry_delay = 0.01
    acquired = False
    for _ in range(max_retries):
        if lock.acquire():
            acquired = True
            break
        time.sleep(retry_delay)
    if not acquired:
        raise PalError(
            "WRITER_BUSY",
            lock.detail,
            next_action="wait for the running publisher, or remove a stale audit lock by hand",
        )
    try:
        entries = _read_entries(entries_path)

        for entry in entries:
            if (
                entry.get("finding_id") == finding_id
                and entry.get("audit_sha256") == body_sha
            ):
                return _result_of(entry)

        audit_id = allocate_audit_id(
            home, maintainer_root,
            **({"private_ledger_home": ledger_home} if private_ledger_home is not None else {}),
        )
        final_path = audit_dir / f"{audit_id}.md"
        if final_path.exists():
            raise PalError(
                "VALIDATION_FAILED",
                f"audit slot {audit_id}.md already exists; refusing to overwrite",
                next_action="a fresh id will be allocated on the next attempt",
            )

        root = maintainer_root if maintainer_root is not None else home
        payload = audit_body.encode("utf-8")
        atomic_write_bytes(final_path, payload, root=root)

        if sha256_file(final_path) != body_sha:
            raise PalError(
                "VALIDATION_FAILED",
                "audit file digest does not match the enqueued body",
            )

        entry = {
            "finding_id": finding_id,
            "audit_number": audit_id,
            "audit_path": _relative(audit_id, maintainer_root),
            "audit_sha256": body_sha,
            "enqueue_operation_id": enqueue_operation_id(),
            "emitted_at": utc_now_iso(),
        }
        entries.append(entry)
        _write_ledger(entries_path, entries)
        return _result_of(entry)
    finally:
        lock.release()


def verify_audit(path: Path, digest: str) -> bool:
    return path.is_file() and sha256_file(path) == digest


def lookup_receipt(home: Path | str, finding_id: str) -> dict | None:
    for entry in _read_entries(_entries_path(Path(home), None)):
        if entry.get("finding_id") == finding_id:
            return _result_of(entry)
    return None


def _relative(audit_id: int, maintainer_root: Path | None) -> str:
    if maintainer_root is not None:
        return f"audit/{audit_id}.md"
    return f"{AUDIT_STAGING_DIR}/{audit_id}.md"
