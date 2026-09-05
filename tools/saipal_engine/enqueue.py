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
import time
import uuid
from pathlib import Path

from .capability import require_action
from .errors import PalError
from .paths import (
    AUDIT_LEDGER_NAME,
    AUDIT_STAGING_DIR,
    FencedLockFile,
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

#: Where an audit was written. The entries ledger lives in the SAIPAL home for
#: BOTH destinations (PAL-AUDIT-02 keeps private bookkeeping local), so the
#: destination has to be part of the idempotency key: without it a locally staged
#: audit matched by finding + digest and made the later sink publish a no-op that
#: returned the local receipt, which is why a restored sink never received the
#: backlog (audit CORE-007).
TARGET_LOCAL = "local"


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


def _target_of(entry: dict) -> str:
    """Where this ledger entry's audit was written.

    An entry recorded before the field existed was written locally: the sink path
    is newer than the ledger. Defaulting the other way would make a legacy local
    receipt satisfy a sink publish.
    """
    return str(entry.get("target") or TARGET_LOCAL)


def _result_of(entry: dict) -> dict:
    return {
        "audit_number": int(entry["audit_number"]),
        "audit_path": str(entry["audit_path"]),
        "audit_sha256": str(entry["audit_sha256"]),
        "operation_id": str(entry["enqueue_operation_id"]),
    }


class AuditInboxLock:
    """Serializes audit id allocation + file write + entry recording.

    T-031: PAL-AUDIT-02 step 1 requires acquiring the audit inbox lock before
    allocating a number. Two concurrent publishers that both read the counter
    before either writes it would race to the same ``audit/N.md``.

    T-062: the ownership semantics are `FencedLockFile`'s, shared with
    ``HomeLock`` and ``SessionLease`` -- a publisher releases only the lock it
    still owns, so a slow publisher cannot delete its successor's.
    """

    def __init__(self, lock_dir: Path, *, ttl: float = AUDIT_LOCK_TTL_SECONDS):
        self.lock_path = Path(lock_dir) / AUDIT_LOCK_NAME
        self.ttl = ttl
        self._lock = FencedLockFile(
            self.lock_path,
            ttl=ttl,
            busy_detail="another publisher holds the audit inbox lock",
        )

    @property
    def held(self) -> bool:
        return self._lock.held

    @property
    def detail(self) -> str:
        return self._lock.detail

    def acquire(self) -> bool:
        return self._lock.acquire()

    def release(self) -> None:
        self._lock.release()

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
    reserve_number: int | None = None,
) -> dict:
    """Write one numbered audit to the local staging area or a maintainer sink.

    `reserve_number` publishes an audit that ALREADY has an identity: a delivery
    retried after a sink outage must arrive as the audit it was staged as, not as
    a fresh number, or the maintainer receives the same finding twice under two
    names (audit CORE-007).
    """
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
        target = TARGET_LOCAL if maintainer_root is None else str(Path(maintainer_root))

        for entry in entries:
            if (
                entry.get("finding_id") == finding_id
                and entry.get("audit_sha256") == body_sha
                and _target_of(entry) == target
            ):
                if not entry.get("pending"):
                    return _result_of(entry)
                # An earlier attempt allocated this slot and then stopped. Reuse
                # its number rather than allocating another: a fresh id would
                # leave the file it already wrote orphaned in the audit directory
                # with no ledger entry naming it (audit W2-002).
                audit_id = int(entry["audit_number"])
                break
        else:
            entry = None
            audit_id = (
                int(reserve_number)
                if reserve_number is not None
                else allocate_audit_id(
                    home, maintainer_root,
                    **({"private_ledger_home": ledger_home} if private_ledger_home is not None else {}),
                )
            )

        final_path = audit_dir / f"{audit_id}.md"
        if entry is None and final_path.exists():
            raise PalError(
                "VALIDATION_FAILED",
                f"audit slot {audit_id}.md already exists; refusing to overwrite",
                next_action="a fresh id will be allocated on the next attempt",
            )

        if entry is None:
            # The intention is durable BEFORE the file exists, so a crash leaves a
            # recoverable claim on the slot instead of an unreferenced audit.
            entry = {
                "finding_id": finding_id,
                "audit_number": audit_id,
                "audit_path": _relative(audit_id, maintainer_root),
                "audit_sha256": body_sha,
                "target": target,
                "enqueue_operation_id": enqueue_operation_id(),
                "emitted_at": utc_now_iso(),
                "pending": True,
            }
            entries.append(entry)
            _write_ledger(entries_path, entries)

        root = maintainer_root if maintainer_root is not None else home
        payload = audit_body.encode("utf-8")
        atomic_write_bytes(final_path, payload, root=root)

        if sha256_file(final_path) != body_sha:
            raise PalError(
                "VALIDATION_FAILED",
                "audit file digest does not match the enqueued body",
            )

        entry.pop("pending", None)
        entry["emitted_at"] = utc_now_iso()
        _write_ledger(entries_path, entries)
        return _result_of(entry)
    finally:
        lock.release()


def verify_audit(path: Path, digest: str) -> bool:
    return path.is_file() and sha256_file(path) == digest


def lookup_receipt(home: Path | str, finding_id: str) -> dict | None:
    for entry in _read_entries(_entries_path(Path(home), None)):
        if entry.get("finding_id") == finding_id and not entry.get("pending"):
            return _result_of(entry)
    return None


def incomplete_enqueues(home: Path | str, maintainer_root: Path | None = None) -> list[dict]:
    """Slots claimed by an attempt that never confirmed its file.

    A pending entry is the recoverable state: the next `enqueue_audit` for the
    same finding and body reuses the number. Surfacing them is for `doctor` and
    for an operator asking why an audit directory holds a file nothing references.
    """
    return [
        _result_of(entry)
        for entry in _read_entries(_entries_path(Path(home), maintainer_root))
        if entry.get("pending")
    ]


def _relative(audit_id: int, maintainer_root: Path | None) -> str:
    if maintainer_root is not None:
        return f"audit/{audit_id}.md"
    return f"{AUDIT_STAGING_DIR}/{audit_id}.md"
