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

import hashlib
import json
import os
import stat
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
    carries_reparse_attr,
    confined_mkdir,
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


def _norm(path: Path | str) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def _refuse_indirection(part: Path, slot_name: str) -> None:
    """Fail closed on any symlink/junction/reparse indirection node.

    Delegates to the shared paths-module primitive so enqueue and the rest of
    the kernel share ONE node-safety implementation.
    """
    if carries_reparse_attr(part):
        raise PalError(
            "PATH_ESCAPE",
            f"audit path {str(part)!r} at {slot_name} is a symlink/junction/"
            "reparse point; refusing recovery through it",
            next_action="the pending ledger entry is kept and no bytes are touched",
        )


def _inspect_recovered_slot(final_path: Path, intended_root: Path) -> str | None:
    """W2-002 (SRC-005): digest the bytes PHYSICALLY AT the audit slot, or
    return None when the slot is absent, refusing every path-indirection
    escape on the way.

    Regular path predicates (`exists()`, `is_file()`) and `open()` follow
    symlinks, junctions and reparse points, so a recovery path that trusts
    them can accept matching bytes stored OUTSIDE the intended root as the
    immutable audit slot. This inspector proves the physical location first:

      1. the intended physical root is established (fully resolved);
      2. every directory at or below the root along the slot's real path is
         proven to be a real directory (never a symlink/junction/reparse
         point) -- a swapped `audit` or `staging` directory is rejected
         wholesale, not followed;
      3. the final slot itself is lstat'd: symlink/reparse points and
         non-regular nodes are rejected without following them;
      4. the digest is read through a directory-local descriptor opened with
         O_NOFOLLOW where the platform offers it, and the opened node is
         fstat-verified to be the same device/inode the lstat saw (dangling
         or swapped indirection fails closed here);
      5. every resolution/lstat/open/read error fails closed -- the caller
         keeps the pending ledger entry and no bytes are ever written.

    A hardlink alias on the same volume is not path indirection and is out of
    scope for this boundary (the audit covers symlink/reparse escape).
    """
    base = Path(intended_root).resolve()
    base_key = _norm(base)
    slot_abs = Path(os.path.abspath(str(final_path)))

    # The lexical directory chain of the slot, shallowest first.
    chain: list[Path] = []
    probe = slot_abs.parent
    while True:
        chain.append(probe)
        if _norm(probe) == _norm(probe.parent):
            break
        probe = probe.parent
    chain.reverse()

    # (1)+(2): locate the intended root along the REAL path, then prove every
    # directory at or below it is a real directory, never an indirection.
    root_index: int | None = None
    for index, part in enumerate(chain):
        try:
            physical = part.resolve()
        except OSError as exc:
            raise PalError(
                "VALIDATION_FAILED",
                f"audit slot directory {str(part)!r} cannot be resolved: {exc}",
                next_action="the pending ledger entry is kept and no bytes are touched",
            ) from exc
        if _norm(physical) == base_key:
            root_index = index
            break
    if root_index is None:
        raise PalError(
            "PATH_ESCAPE",
            f"audit slot {str(slot_abs)!r} is not confined to root {str(base)!r}",
            next_action="the immutable audit lives only inside the intended root",
        )
    for part in chain[root_index:]:
        try:
            st = os.lstat(str(part))
        except OSError as exc:
            raise PalError(
                "VALIDATION_FAILED",
                f"audit slot directory {str(part)!r} cannot be stated: {exc}",
                next_action="the pending ledger entry is kept and no bytes are touched",
            ) from exc
        if stat.S_ISLNK(st.st_mode):
            raise PalError(
                "PATH_ESCAPE",
                f"audit slot directory {str(part)!r} is a symlink/junction/reparse "
                "point; refusing recovery through it",
                next_action="the pending ledger entry is kept and no bytes are touched",
            )
        _refuse_indirection(part, "a directory of the slot path")
        if not stat.S_ISDIR(st.st_mode):
            raise PalError(
                "PATH_ESCAPE",
                f"audit slot directory {str(part)!r} is not a real directory",
                next_action="the pending ledger entry is kept and no bytes are touched",
            )

    # (3): the final slot itself, judged without following it.
    try:
        st = os.lstat(str(slot_abs))
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PalError(
            "VALIDATION_FAILED",
            f"recovered audit slot {final_path.name} cannot be stated: {exc}",
            next_action="the pending ledger entry is kept and no bytes are touched",
        ) from exc
    if stat.S_ISLNK(st.st_mode):
        raise PalError(
            "PATH_ESCAPE",
            f"audit slot {final_path.name} is a symlink/junction/reparse point; "
            "refusing recovery through it",
            next_action="the pending ledger entry is kept and no bytes are touched",
        )
    _refuse_indirection(slot_abs, "the slot itself")
    if not stat.S_ISREG(st.st_mode):
        raise PalError(
            "VALIDATION_FAILED",
            f"audit slot {final_path.name} is not a regular file; refusing recovery",
            next_action="the pending ledger entry is kept and no bytes are touched",
        )

    # (4): open refusing the indirection itself, then prove the opened node
    # is still the node the lstat saw (dangling swap fails closed here).
    binary = getattr(os, "O_BINARY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(slot_abs), os.O_RDONLY | binary | nofollow)
    except OSError as exc:
        raise PalError(
            "VALIDATION_FAILED",
            f"recovered audit slot {final_path.name} cannot be opened: {exc}",
            next_action="the pending ledger entry is kept and no bytes are touched",
        ) from exc
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise PalError(
                "PATH_ESCAPE",
                f"audit slot {final_path.name} is not a regular file; refusing recovery",
            )
        if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
            raise PalError(
                "PATH_ESCAPE",
                f"audit slot {final_path.name} changed identity during recovery",
            )
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            digest.update(chunk)
    except PalError:
        raise
    except OSError as exc:
        raise PalError(
            "VALIDATION_FAILED",
            f"recovered audit slot {final_path.name} is unreadable: {exc}",
            next_action="the pending ledger entry is kept and no bytes are touched",
        ) from exc
    finally:
        os.close(descriptor)
    return digest.hexdigest()


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
    root = _root_of(ledger_path)
    confined_mkdir(root, ".")
    confined_mkdir(root, ledger_path.parent.name)
    payload = {"schema_version": LEDGER_SCHEMA_VERSION, "entries": entries}
    atomic_write_json(ledger_path, payload, root=root)


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
    ledger_home = Path(private_ledger_home or home)
    if private_ledger_home is not None:
        confined_mkdir(ledger_home, ".")
        confined_mkdir(ledger_home, "audit")
    ledger_path = _ledger_path(ledger_home, None) if private_ledger_home is not None else _ledger_path(home, maintainer_root)
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

    slots = _existing_numbers(_audit_dir(ledger_home, None) if private_ledger_home is not None else _audit_dir(home, maintainer_root))
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

    def __init__(
        self,
        lock_dir: Path,
        *,
        ttl: float = AUDIT_LOCK_TTL_SECONDS,
        confine_under: Path | str | None = None,
    ):
        self.lock_path = Path(lock_dir) / AUDIT_LOCK_NAME
        self.ttl = ttl
        # PAL-WRITE-01 (T-125, Defect C): the already-descended lock directory
        # proves nothing about ancestors ABOVE it -- `home/audit -> outside`
        # sailed through with confine_under=lock_dir and the lock landed in
        # the external tree. The confinement root must be a root the CALLER
        # has established as the trust boundary: the SAIPAL home for local
        # staging, the validated maintainer sink root for an external sink.
        # It defaults to the lock directory's parent's parent... no: it
        # defaults to None, and `enqueue_audit` always passes the explicit
        # root. Direct construction without a root keeps only the lock-dir
        # chain confinement (weakest legacy behavior), which the
        # SinkConfinement controls pin as insufficient for real enqueues.
        self._lock = FencedLockFile(
            self.lock_path,
            ttl=ttl,
            busy_detail="another publisher holds the audit inbox lock",
            confine_under=(
                Path(confine_under) if confine_under is not None else Path(lock_dir)
            ),
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
    # PAL-WRITE-01 (T-125, Defect C): the lock's confinement root is the
    # TRUST root, not the descended lock directory. Local staging is
    # confined to the SAIPAL home; an authorized maintainer sink is confined
    # to the validated sink root. An ancestor symlink (home/audit ->
    # outside) is then refused outright instead of proving nothing.
    confinement_root = maintainer_root if maintainer_root is not None else home
    # T-125 Defect D: the staging directory is materialized through the
    # confinement primitive (home root or validated sink root), never a raw
    # parents=True mkdir that would descend through an ancestor indirection.
    from .paths import confined_mkdir

    confinement_root_resolved = Path(confinement_root).resolve()
    if audit_dir.is_absolute():
        audit_dir_resolved = Path(os.path.abspath(str(audit_dir)))
        if (
            confinement_root_resolved not in audit_dir_resolved.parents
            and audit_dir_resolved != confinement_root_resolved
        ):
            raise PalError(
                "PATH_ESCAPE",
                f"audit directory {str(audit_dir)!r} is not confined to root "
                f"{str(confinement_root_resolved)!r}",
            )
    confined_mkdir(
        confinement_root,
        audit_dir.relative_to(confinement_root_resolved)
        if audit_dir.is_absolute()
        else audit_dir,
    )
    # TARGET B2 (T-125): when the PRIVATE ledger home is separate from the
    # publication sink, its `audit/` surface is materialized EXPLICITLY here,
    # through the confinement primitive, before any allocate_audit_id /
    # atomic_write_json call below. `atomic_write_bytes` writes only into an
    # already-authorized existing parent and never recreates missing parents,
    # so a redirected private ledger refuses with zero external bytes.
    if private_ledger_home is not None:
        confined_mkdir(ledger_home, ".")
        confined_mkdir(ledger_home, "audit")
    lock = AuditInboxLock(lock_dir, confine_under=confinement_root)
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
        root = maintainer_root if maintainer_root is not None else home
        if entry is None and _inspect_recovered_slot(final_path, root) is not None:
            raise PalError(
                "VALIDATION_FAILED",
                f"audit slot {audit_id}.md already exists; refusing to overwrite",
                next_action="a fresh id will be allocated on the next attempt",
            )

        if entry is not None:
            # W2-002 (SRC-005): pending ownership is NOT permission to overwrite
            # the physical slot. A recovered pending entry must distinguish the
            # three crash shapes instead of blindly rewriting the file:
            #   a) slot absent -> the crash preceded the write; write below.
            #   b) slot present with the intended digest -> the crash FOLLOWED
            #      the write; the slot is already correct, never rewrite it,
            #      only finalize the ledger (and keep the original identity so
            #      recovery closes the original transaction, not a new one).
            #   c) slot present with different bytes -> altered, corrupted, or
            #      independently recovered; refuse loudly, keep the pending
            #      entry, and never overwrite/delete/rename the existing file.
            #      Read/digest failure also fails closed (no fall-through).
            # The inspection is UNCONDITIONAL for a pending entry and never
            # gated on Path.exists(): exists() follows indirection, so a
            # dangling symlink at the slot reads as "absent" and would slip
            # past to the guarded write, which creates the symlink's target.
            # _inspect_recovered_slot judges the PHYSICAL node via lstat and
            # refuses every symlink/junction/reparse shape before any digest
            # is trusted or any byte is written.
            existing_digest = _inspect_recovered_slot(final_path, root)
            if existing_digest is not None:
                if existing_digest == str(entry.get("audit_sha256")):
                    entry.pop("pending", None)
                    entry.setdefault("emitted_at", utc_now_iso())
                    _write_ledger(entries_path, entries)
                    return _result_of(entry)
                raise PalError(
                    "EVIDENCE_MISMATCH",
                    (
                        f"audit slot {final_path.name} exists with bytes that do not "
                        f"match the pending audit digest ({str(entry.get('audit_sha256'))[:12]}...)"
                    ),
                    next_action=(
                        "inspect the existing slot by hand; the immutable audit was "
                        "not overwritten and the pending ledger entry is kept"
                    ),
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
