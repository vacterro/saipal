"""Home resolution, guarded atomic writes and the home lock boundary.

Everything SAIPAL writes lives under one home. This module is the only place
that turns a path into bytes on disk, and it refuses anything that resolves
outside the home it was given.

PAL-WRITE-01: SAIPAL may write only inside its own home. Static check-then-
write sequences are not a physical boundary: the namespace can change between
validation and I/O (auditor reproductions A/B/C, ticket T-125). The load-
bearing primitives here therefore bind the WRITE to a directory identity that
was verified immediately before the I/O. See `_open_confined_dir`,
`_confined_parent`, `confined_append_line`, and the platform notes there.

DESCRIPTOR OWNERSHIP CONTRACT (T-127, Defect A). Three functions hand out
descriptors and each one names its single owner:

* `_open_confined_dir` opens the ROOT fd and returns it; the CALLER owns it.
* `_open_confined_parent` returns a NEW parent fd (`os.dup` of the root fd,
  advanced level by level); the CALLER owns it. It never closes a descriptor
  it did not open, and it never closes the caller's `root_fd`.
* `_confined_target_with_root` returns `(parent, parent_fd, root_fd)`; the
  CALLER owns BOTH descriptors.

Every caller closes exactly the descriptors it was handed, in one `finally`,
through the single helper `_close_fd`. Nothing here relies on reference
counting, garbage collection or process exit: a leaked descriptor is a
resource leak the PRIMITIVE caused, not something a later collection may
absorb, and a 1000-operation run of these primitives must leave the process
with a bounded descriptor count (the POSIX lifetime control in
`test_wave_pal_write_01.py` is the red control for that).

"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import math
import os
import socket
import stat
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from .errors import PalError

HOME_DIRNAME = ".saipal"
HOME_ENV_VAR = "SAIPAL_HOME"

STATE_NAME = "STATE.json"
LOG_NAME = "LOG.jsonl"
SOURCES_NAME = "sources.json"

SESSION_INBOX_DIR = "session_inbox"
SESSIONS_DIR = "sessions"
INDEX_NAME = "index.json"

LOCKS_DIR = "locks"
LOCK_NAME = "saipal.lock"
LOCK_TTL_SECONDS = 300

#: How long a lock file that exists but cannot be parsed is assumed to be
#: another run's create-before-payload window rather than a corpse. `O_EXCL`
#: creates the node before the payload is written, so every honest acquisition
#: passes through a moment of being unreadable; treating that moment as stale is
#: how two writers end up admitted (audit W2-001).
# Ownership ceiling: no lock lease may be judged stale on a TTL longer than this.
# Bounds the owner's own policy so a corrupted or hostile sidecar cannot name an
# unbounded lease; the safe fallback (LOCK_TTL_SECONDS) is also bounded by it.
LOCK_MAX_TTL_SECONDS = 30 * 86400

LOCK_CREATE_GRACE_SECONDS = 5.0

#: Windows refuses to unlink or rename a file another handle has open, and every
#: contender reads the lock to judge it. So the node is not always deletable at
#: the instant its owner lets go; a few quick attempts cover the read window.
LOCK_UNLINK_ATTEMPTS = 8
LOCK_UNLINK_DELAY_SECONDS = 0.02

FINDINGS_DIR = "findings"
FINDINGS_CANDIDATES_DIR = "findings/candidates"
FINDINGS_EMITTED_DIR = "findings/emitted"
FINDINGS_INDEX_NAME = "findings/index.json"

AUDIT_STAGING_DIR = "audit/staging"
AUDIT_LEDGER_NAME = "audit/ledger.json"
AUDIT_LEASE_NAME = "audit/lease.json"

RECURRENCE_NAME = "recurrence.json"
TELEMETRY_NAME = "telemetry.json"

#: An unattended run request. `trigger` writes the pending token; a cycle CLAIMS
#: it by renaming, so a request arriving mid-cycle survives (audit CORE-010).
TRIGGER_NAME = "trigger.json"
TRIGGER_CLAIM_NAME = "trigger.claimed"

#: Audits staged locally that a configured sink has not confirmed. Separate from
#: the audit itself: local staging and external delivery are different facts
#: (audit CORE-007).
PUBLICATIONS_NAME = "pending_publications.json"


@dataclass(frozen=True)
class HomePaths:
    """Every path SAIPAL is allowed to touch, resolved once."""

    root: Path
    state: Path
    log: Path
    sources: Path
    session_inbox: Path
    sessions_index: Path
    locks: Path
    lock: Path
    findings_index: Path
    findings_candidates: Path
    findings_emitted: Path
    audit_staging: Path
    audit_ledger: Path
    audit_lease: Path
    recurrence: Path
    telemetry: Path
    trigger: Path
    trigger_claim: Path
    publications: Path

    def rel(self, name: str) -> Path:
        return self.root / name


def home_paths(home: Path | str) -> HomePaths:
    root = Path(home)
    locks = root / LOCKS_DIR
    sessions = root / SESSIONS_DIR
    findings = root / FINDINGS_DIR
    audit = root / "audit"
    return HomePaths(
        root=root,
        state=root / STATE_NAME,
        log=root / LOG_NAME,
        sources=root / SOURCES_NAME,
        session_inbox=root / SESSION_INBOX_DIR,
        sessions_index=sessions / INDEX_NAME,
        locks=locks,
        lock=locks / LOCK_NAME,
        findings_index=findings / "index.json",
        findings_candidates=findings / "candidates",
        findings_emitted=findings / "emitted",
        audit_staging=audit / "staging",
        audit_ledger=audit / "ledger.json",
        audit_lease=audit / "lease.json",
        recurrence=root / RECURRENCE_NAME,
        telemetry=root / TELEMETRY_NAME,
        trigger=root / TRIGGER_NAME,
        trigger_claim=root / TRIGGER_CLAIM_NAME,
        publications=root / PUBLICATIONS_NAME,
    )


def resolve_tool_root() -> Path:
    """The SAIPAL repository root: the directory that owns `tools/`."""
    return Path(__file__).resolve().parents[2]


def resolve_protocol_dir(tool_root: Path | str | None = None) -> Path:
    root = Path(tool_root) if tool_root is not None else resolve_tool_root()
    return root / "saipal"


def resolve_home(
    start: Path | str | None = None,
    explicit: str | Path | None = None,
    env: dict | None = None,
) -> tuple[Path | None, str]:
    """Where SAIPAL's runtime home is, and why.

    Order: explicit `--home`, then `SAIPAL_HOME`, then the nearest ancestor that
    already holds `.saipal/`. Returns `(None, reason)` when nothing was found
    rather than inventing a home nobody asked for; the CLI decides whether the
    tool-root default applies, because only it knows if the command may write.
    """
    if explicit:
        return Path(explicit).expanduser(), "explicit --home"

    source = os.environ if env is None else env
    declared = str(source.get(HOME_ENV_VAR, "") or "").strip()
    if declared:
        return Path(declared).expanduser(), f"{HOME_ENV_VAR} environment variable"

    here = Path(start).resolve() if start else Path.cwd().resolve()
    for candidate in (here, *here.parents):
        nested = candidate / HOME_DIRNAME
        if nested.is_dir():
            return nested, f"ancestor {candidate}"

    return None, (
        f"no {HOME_DIRNAME}/ found in {here} or any ancestor; "
        "run `saipal continue` to materialize one"
    )


# --------------------------------------------------------------------------- #
# digests
# --------------------------------------------------------------------------- #


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with open(str(path), "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def utc_now_iso() -> str:
    """One timestamp format everywhere: `YYYY-MM-DDTHH:MM:SSZ`."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# --------------------------------------------------------------------------- #
# guarded writes
# --------------------------------------------------------------------------- #

#: Pointer-sized HANDLE for the WinAPI reparse probe. ctypes' default int
#: return/argument conversion truncates 64-bit HANDLEs; every CreateFileW /
#: CloseHandle signature is declared with this type explicitly.
if getattr(ctypes, "windll", None) is not None:  # pragma: no cover - platform branch
    W32_HANDLE = ctypes.c_void_p
    import ctypes.wintypes as wintypes  # noqa: PLC0415 - Windows only
else:
    W32_HANDLE = None  # type: ignore[assignment]
    wintypes = None  # type: ignore[assignment]


def _norm_root_key(path: Path | str) -> str:
    """Platform-normalized comparison key for a root/parent path."""
    return os.path.normcase(os.path.normpath(str(path)))


# --------------------------------------------------------------------------- #
# CORE-001 (SRC-010): physical home identity of the ACTIVE writer fence
# --------------------------------------------------------------------------- #

#: The physical identity of every home currently protected by an OUTER writer
#: fence, keyed by the home's lexical root key and the owning thread. `WriterFence`
#: binds this at the moment the real `HomeLock` is taken and keeps it for the
#: fence's complete lifetime. Two consumers read it and both fail CLOSED when the
#: lexical home no longer names that physical directory:
#:
#: * a same-thread reentrant acquisition, so lexical pathname equality alone can
#:   never grant reentrancy after the home was renamed and replaced;
#: * `_open_confined_dir`, the single root-opening boundary every confined
#:   mutating primitive already passes through, so an old holder cannot silently
#:   migrate into a replacement home at the same pathname.
#:
#: The lexical key is the LOOKUP key only; the proof is the `(st_dev, st_ino)`
#: value, exactly as the audit requires -- never a resolved/normalized path.
#: A platform that cannot supply a directory identity stores None and no check
#: is possible there (the documented residual limitation); on POSIX and on
#: Windows NTFS/ReFS an identity is always available.
_ACTIVE_FENCE_IDENTITY: dict[tuple[str, int], tuple[int, int] | None] = {}


def _fence_root_key(root: Path | str) -> str:
    """Absolute, case-normalized lexical key for the active-fence registry.

    A LOOKUP key only -- never a security proof. Two spellings of the same
    lexical home resolve to one key; the proof is the physical identity value.
    """
    return os.path.normcase(os.path.abspath(str(root)))


def _physical_dir_identity(root: Path | str) -> tuple[int, int] | None:
    """The durable physical identity of the directory `root` names right now.

    `(st_dev, st_ino)` is the strongest stdlib identity both POSIX and Windows
    expose: POSIX gives the real device/inode pair, and Windows fills the same
    fields from the volume serial number and the file index. A missing or zero
    component is reported as None -- identity unavailable -- so a caller never
    treats two homes as equal by default.
    """
    try:
        st = os.stat(str(root), follow_symlinks=False)
    except (OSError, TypeError):
        return None
    if not stat.S_ISDIR(st.st_mode):
        return None
    dev = int(getattr(st, "st_dev", 0) or 0)
    ino = int(getattr(st, "st_ino", 0) or 0)
    if ino == 0:
        return None
    return (dev, ino)


def _active_fence_identity(root: Path | str) -> tuple[int, int] | None:
    """The physical identity the current thread's active fence bound for `root`."""
    return _ACTIVE_FENCE_IDENTITY.get((_fence_root_key(root), threading.get_ident()))


def _assert_active_fence_identity(root: Path | str) -> None:
    """Refuse when this thread's active fence protects a DIFFERENT physical home.

    Called from `_open_confined_dir` immediately before a root is opened for a
    confined mutation. When no fence is active for `(root, thread)` -- ordinary
    unfenced primitives, read-only surfaces and the lock bootstrap -- the call is
    a no-op. When a fence is active and the lexical home no longer resolves to the
    identity that fence acquired, the mutation is refused before any byte moves.
    """
    expected = _active_fence_identity(root)
    if expected is None:
        return
    if _physical_dir_identity(root) != expected:
        raise PalError(
            "PATH_ESCAPE",
            f"home {str(root)!r} no longer names the physical directory this "
            "writer fence acquired; refusing to mutate a replacement home",
            next_action="restart the transaction against the current home",
        )


def carries_reparse_attr(path: Path | str) -> bool:
    """True when the node at `path` carries the Windows reparse-point
    attribute (junctions, symlinks, mount points), probed WITHOUT following
    the node. os.lstat reports a junction as a plain directory (S_ISLNK is
    false), so the file-attribute probe is the only portable way to see one
    before following it. Non-Windows platforms return False: POSIX symlinks
    are already visible to os.lstat.

    The WinAPI calls use explicit pointer-sized HANDLE types (W32_HANDLE),
    never ctypes' default int conversion, which truncates 64-bit HANDLEs.
    """
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return False
    kernel32 = windll.kernel32
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    INVALID_HANDLE_VALUE = W32_HANDLE(-1).value
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, W32_HANDLE,
    ]
    kernel32.CreateFileW.restype = W32_HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [W32_HANDLE, ctypes.c_void_p]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [W32_HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.CreateFileW(
        str(path), 0, 7, None, 3,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, None,
    )
    if handle in (INVALID_HANDLE_VALUE, W32_HANDLE(0).value):
        return False

    class _ByHandleInfo(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", ctypes.c_ulong),
            ("_ft", ctypes.c_ulonglong * 3),
            ("dwVolumeSerialNumber", ctypes.c_ulong),
            ("nFileSizeHigh", ctypes.c_ulong),
            ("nFileSizeLow", ctypes.c_ulong),
            ("nNumberOfLinks", ctypes.c_ulong),
            ("nFileIndexHigh", ctypes.c_ulong),
            ("nFileIndexLow", ctypes.c_ulong),
        ]

    info = _ByHandleInfo()
    ok = kernel32.GetFileInformationByHandle(handle, ctypes.byref(info))
    kernel32.CloseHandle(handle)
    if not ok:
        return False
    return bool(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)


def prove_inside(root: Path | str, path: Path | str) -> Path:
    """Resolve `path` and prove it is `root` or lives under `root`."""
    base = Path(root).resolve()
    target = Path(path)
    try:
        resolved = target.resolve()
    except OSError as exc:
        raise PalError(
            "PATH_ESCAPE",
            f"path {str(target)!r} cannot be resolved; refusing the write",
        ) from exc
    if resolved != base and base not in resolved.parents:
        raise PalError(
            "PATH_ESCAPE",
            f"path {str(target)!r} resolves outside home {str(base)!r}",
            next_action="SAIPAL writes only inside its own home",
        )
    return resolved


def _refuse_forbidden_node(node: Path | str, role: str) -> None:
    """Fail closed on any path indirection at `node`.

    Judged WITHOUT following the node: os.lstat sees POSIX symlinks, the
    reparse-attribute probe sees Windows junctions/reparse points that
    lstat misreports as plain directories.
    """
    try:
        st = os.lstat(str(node))
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PalError(
            "PATH_ESCAPE",
            f"{role} {str(node)!r} cannot be stated: {exc}",
            next_action="SAIPAL writes only inside its own home",
        ) from exc
    if stat.S_ISLNK(st.st_mode) or carries_reparse_attr(node):
        raise PalError(
            "PATH_ESCAPE",
            f"{role} {str(node)!r} is a symlink/junction/reparse point; "
            "refusing to write through it",
            next_action="SAIPAL writes only inside its own home",
        )


def _refuse_indirection_final(
    parent: Path, name: str, parent_fd: int | None, role: str
) -> None:
    """Classify the FINAL node at ``parent / name`` WITHOUT following it.

    T-125 Target B4: a pre-existing symlink/junction/reparse node at the
    destination is a confinement REFUSAL (PATH_ESCAPE), never ordinary
    contention and never a ``busy`` result -- reporting it as busy would hide
    an attack behind a normal-looking answer. On POSIX the node is stated
    fd-relatively (``os.stat(name, dir_fd=parent_fd, follow_symlinks=False)``)
    under the ALREADY-VERIFIED parent fd, so classification cannot race the
    path; on Windows the non-following lstat + reparse probe classifies it.
    This is classification ONLY: the create itself stays O_EXCL|O_NOFOLLOW
    under the bound parent fd, so a node appearing after this probe can still
    never be followed.
    """
    if parent_fd is not None:
        try:
            st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError):
            return
        except OSError:
            return
        if stat.S_ISLNK(st.st_mode):
            raise PalError(
                "PATH_ESCAPE",
                f"{role} {str(parent / name)!r} is a symlink; refusing to "
                "write through it",
                next_action="SAIPAL writes only inside its own home",
            )
        return
    _refuse_forbidden_node(parent / name, role)


def _refuse_indirection_ancestors(node: Path | str, *, role: str) -> None:
    """Refuse when `node`'s own node OR any lexical ancestor is an indirection.

    T-127 Defect B: the root binding proved only the FINAL component.
    `os.open(full_root_path, O_NOFOLLOW)` follows every component above the
    last one, so a home whose lexical ancestor is a symlink/junction was
    accepted as "verified" while the bytes landed outside it. On POSIX the
    complete chain is now walked descriptor-relative inside
    `_open_confined_dir`; this helper is the path-based companion (the
    platform fallback), and it is the proof that a real external home cannot
    be reached through a junction on Windows either.

    A MISSING level is not an indirection: the walk stops there, because
    nothing can be traversed through a node that does not exist.
    """
    probe = Path(os.path.abspath(str(node)))
    while True:
        try:
            st = os.lstat(str(probe))
        except FileNotFoundError:
            return
        except OSError as exc:
            raise PalError(
                "PATH_ESCAPE",
                f"{role} {str(probe)!r} cannot be stated: {exc}",
                next_action="SAIPAL writes only inside its own home",
            ) from exc
        if stat.S_ISLNK(st.st_mode) or carries_reparse_attr(probe):
            raise PalError(
                "PATH_ESCAPE",
                f"{role} {str(probe)!r} is reached through a symlink/junction/"
                "reparse point; refusing to write through it",
                next_action="SAIPAL writes only inside its own home",
            )
        parent = probe.parent
        if _norm_root_key(parent) == _norm_root_key(probe):
            return
        probe = parent


def _open_confined_dir(root: Path | str) -> int:
    """Open `root` itself as a directory fd bound to the physical home node.

    This is the load-bearing boundary for PAL-WRITE-01: every confined write
    resolves its parent against THIS fd, so a swap of the home (or any parent)
    between validation and I/O cannot redirect bytes outside -- the write
    follows the verified node, not the mutable path.

    POSIX: the COMPLETE absolute root path is walked component-by-component
    from the trusted filesystem root with non-following descriptor-relative
    opens (T-127 Defect B). O_NOFOLLOW protects only the FINAL component, so
    opening the whole path in one call accepted a home reached through a
    symlinked ancestor; each level is now `os.open(name, O_NOFOLLOW|
    O_DIRECTORY, dir_fd=previous)` instead, and the fstat dev+ino identity of
    the resulting fd is cross-checked against the path (a raced rename is
    caught because the fd still names the OLD node while the path names the
    NEW one). A symlink/junction at ANY level is refused outright.

    Windows: os.open cannot open a directory fd. The node and then every
    lexical ancestor are refused when they are an indirection, and this
    function then raises OSError(EOPNOTSUPP-equivalent) so the caller falls
    back to the strongest-practical path-verified boundary (see
    `_open_confined_parent`). The residual Windows limitation -- a
    non-reparse swap between the final probe and the I/O -- is explicit and
    documented in the module docstring; it is NOT claimed race-free.
    """
    root_path = Path(os.path.abspath(str(root)))
    # CORE-001 (SRC-010): the single root-identity gate. Every confined
    # mutating primitive resolves its physical parent through this function, so
    # binding the check here (rather than in each caller) is what stops an old
    # WriterFence holder from silently migrating into a replacement home. With
    # no active fence for this root+thread it is a no-op.
    _assert_active_fence_identity(root_path)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    binary = getattr(os, "O_BINARY", 0)
    flags = os.O_RDONLY | binary | nofollow | directory
    if os.name != "nt" and (nofollow or directory):
        parts = root_path.parts
        if not parts:
            raise OSError(
                getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
                "directory fd confinement unsupported on this platform",
            )
        fd: int | None = None
        try:
            fd = os.open(str(parts[0]), flags)
            for name in parts[1:]:
                next_fd = os.open(name, flags, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            st_fd = os.fstat(fd)
            st_path = os.stat(str(root_path), follow_symlinks=False)
            if (st_fd.st_dev, st_fd.st_ino) != (st_path.st_dev, st_path.st_ino):
                raise PalError(
                    "PATH_ESCAPE",
                    f"home {str(root_path)!r} changed identity while opening; "
                    "refusing the write",
                    next_action="SAIPAL writes only inside its own home",
                )
            # CORE-001 (SRC-010): prove the fd we will mutate through is the
            # SAME physical directory the active fence acquired. The gate above
            # judged the pathname; this judges the opened node, so a swap in the
            # window between that check and this open cannot smuggle a
            # replacement home past an active holder.
            expected = _active_fence_identity(root_path)
            if expected is not None and (st_fd.st_dev, st_fd.st_ino) != expected:
                raise PalError(
                    "PATH_ESCAPE",
                    f"home {str(root_path)!r} opened a different physical "
                    "directory than this writer fence acquired; refusing the "
                    "write",
                    next_action="restart the transaction against the current home",
                )
        except OSError as exc:
            _close_fd(fd)
            raise PalError(
                "PATH_ESCAPE",
                f"home {str(root_path)!r} cannot be opened as a real directory: {exc}",
                next_action="SAIPAL writes only inside its own home",
            ) from exc
        except BaseException:
            _close_fd(fd)
            raise
        return fd
    # Windows (or an interpreter without O_NOFOLLOW/O_DIRECTORY): verify the
    # root AND its complete lexical ancestor chain are real directories, then
    # report the unsupported fd.
    _refuse_forbidden_node(root_path, "home")
    _refuse_indirection_ancestors(root_path, role="home")
    raise OSError(
        getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
        "directory fd confinement unsupported on this platform",
    )


def _open_confined_parent(
    root: Path | str, parent_relative: Path | str, root_fd: int | None
) -> tuple[Path, int | None]:
    """Open the parent directory `parent_relative` (relative to the opened
    root) and prove it is physically inside the root.

    T-125 Defect A: the argument contract is ONE semantics on every platform
    -- `parent_relative` is the PARENT directory itself, relative to `root`;
    EVERY component of it is opened/walked. (The previous implementation gave
    the POSIX branch a target-relative path and stripped its last component
    there, while the Windows fallback treated the same argument as a parent-
    relative path: nested writes landed one level too high on POSIX.)

    Returns the physical parent plus a directory fd for it when the platform
    supports dir fds (None otherwise). Every level below the root is stated
    WITHOUT following symlinks/junctions; on POSIX each level is opened dir-
    fd-relative with O_NOFOLLOW|O_DIRECTORY so a raced swap cannot be
    smuggled in between levels. A parent that resolves outside the root (or
    through an indirection) raises PATH_ESCAPE and no byte has moved.

    DESCRIPTOR OWNERSHIP (T-127, Defect A): the returned fd is a NEW
    descriptor the CALLER owns and MUST close (`_close_fd`) on every path,
    including its refusal paths. `root_fd` is borrowed and is never closed
    here. The previous version documented no owner, and five callers closed
    only their root fd, so every POSIX call leaked one parent descriptor
    until the process hit EMFILE.
    """
    root_path = Path(root)
    if root_fd is not None:
        # Descriptor-relative walk: each level is opened under the PREVIOUS
        # level's fd, so path components cannot be swapped after validation.
        parts = [
            p for p in Path(parent_relative).parts if p not in (".", "")
        ]
        current_fd = os.dup(root_fd)
        try:
            for part in parts:
                nofollow = getattr(os, "O_NOFOLLOW", 0)
                directory = getattr(os, "O_DIRECTORY", 0)
                next_fd = os.open(
                    part, os.O_RDONLY | nofollow | directory, dir_fd=current_fd
                )
                os.close(current_fd)
                current_fd = next_fd
            joined = str(root_path)
            for part in parts:
                joined = os.path.join(joined, part)
            return Path(joined), current_fd
        except OSError as exc:
            with _suppress_os_error():
                os.close(current_fd)
            raise PalError(
                "PATH_ESCAPE",
                f"parent of {str(parent_relative)!r} cannot be confined inside "
                f"home {str(root_path)!r}: {exc}",
                next_action="SAIPAL writes only inside its own home",
            ) from exc
    # Windows strongest-practical fallback: verify every level of the parent
    # chain from the root down is an EXISTING REAL directory (never a
    # symlink/junction/reparse point). T-125 Target B2: this probe does NOT
    # create missing levels. Every primitive that reaches it has the contract
    # "write into an already-authorized existing parent", and the callers
    # that OWN directory creation materialize through `confined_mkdir`
    # explicitly first (`ensure_home`, `establish_lock_surface`,
    # `enqueue_audit`). A raced non-reparse swap between this probe and the
    # I/O remains the documented residual limitation on this platform. A
    # relative argument is root-relative by contract and must never be
    # resolved against the process CWD.
    rel_path = Path(parent_relative)
    if rel_path.is_absolute():
        parent = Path(os.path.abspath(str(rel_path)))
    else:
        parent = Path(os.path.abspath(str(root_path / rel_path)))
    _prove_windows_chain(root_path, parent, create=False)
    return parent, None


def _prove_windows_chain(root: Path, target: Path, *, create: bool) -> None:
    """Windows fallback: prove every level from `root` down to `target` is a
    REAL directory (never a symlink/junction/reparse point).

    Judgement happens BEFORE any mutation: a level that does not exist is
    created only when `create` is set, and only after the level above has been
    proven real, so a refusal can never create external directories through an
    indirection (T-125 Defect E order). The residual Windows limitation -- a
    non-reparse namespace swap between the last probe and the I/O -- remains
    the documented platform limitation.
    """
    root_key = _norm_root_key(root)
    chain: list[Path] = []
    probe = target
    while True:
        chain.append(probe)
        probe_key = _norm_root_key(probe)
        if probe_key == _norm_root_key(probe.parent):
            break
        probe = probe.parent
    chain.reverse()
    root_index = None
    for index, part in enumerate(chain):
        if _norm_root_key(part) == root_key:
            root_index = index
            break
    if root_index is None:
        raise PalError(
            "PATH_ESCAPE",
            f"path {str(target)!r} is not confined to root {str(root)!r}",
            next_action="SAIPAL writes only inside its own home",
        )
    for depth, part in enumerate(chain[root_index:]):
        try:
            st = os.lstat(str(part))
        except FileNotFoundError:
            if not create:
                raise PalError(
                    "PATH_ESCAPE",
                    f"parent directory {str(part)!r} does not exist inside the root",
                ) from None
            # Materialize the missing level, then re-judge what exists now.
            # The root level is the physical home itself: creating it must
            # also create any still-missing real ancestors (a fresh
            # `--home NEW/deeper/.saipal`), each judged before descending.
            try:
                part.mkdir(exist_ok=True)
            except FileExistsError:
                pass
            except OSError as exc:
                raise PalError(
                    "PATH_ESCAPE",
                    f"parent directory {str(part)!r} cannot be created: {exc}",
                ) from exc
            try:
                st = os.lstat(str(part))
            except OSError as exc:
                raise PalError(
                    "PATH_ESCAPE",
                    f"parent directory {str(part)!r} cannot be stated: {exc}",
                ) from exc
        except OSError as exc:
            raise PalError(
                "PATH_ESCAPE",
                f"parent directory {str(part)!r} cannot be stated: {exc}",
            ) from exc
        if stat.S_ISLNK(st.st_mode) or carries_reparse_attr(part):
            raise PalError(
                "PATH_ESCAPE",
                f"parent directory {str(part)!r} is a symlink/junction/reparse "
                "point; refusing to write through it",
                next_action="SAIPAL writes only inside its own home",
            )
        if not stat.S_ISDIR(st.st_mode):
            raise PalError(
                "PATH_ESCAPE",
                f"parent directory {str(part)!r} is not a directory",
            )


def _confined_fd_write(
    parent_fd: int | None,
    parent: Path,
    name: str,
    flags: int,
    data: bytes,
) -> int:
    """Create/open `name` under the verified parent and write `data` fully.

    POSIX: opened dir-fd-relative with O_NOFOLLOW, so a swapped final symlink
    cannot be followed. Windows: opened by path (the parent was verified
    immediately before), re-verified by identity after open; a parent swap
    that redirected the create outside the verified directory is detected
    and the stray node removed, so zero external bytes survive.
    """
    created_path: Path | None = None
    wants_create = bool(flags & os.O_CREAT)
    if parent_fd is not None:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
    else:
        node_path = parent / name
        descriptor = os.open(str(node_path), flags, 0o600)
        created_path = node_path if wants_create else None
    try:
        if parent_fd is None:
            # Windows: prove the node we opened is not an indirection that
            # appeared after the parent probe.
            st = os.fstat(descriptor)
            try:
                st_path = os.lstat(str(parent / name))
            except OSError:
                st_path = None
            if st_path is not None and (
                stat.S_ISLNK(st_path.st_mode)
                or (st.st_dev, st.st_ino) != (st_path.st_dev, st_path.st_ino)
            ):
                raise PalError(
                    "PATH_ESCAPE",
                    f"destination {str(parent / name)!r} changed identity during "
                    "the write; refusing to continue",
                )
            if created_path is not None:
                # Windows: a raced parent swap between the chain probe and
                # this open resolves the create through the replacement
                # indirection. Resolve the node we actually created; when it
                # no longer sits under the verified parent, remove the stray
                # and refuse so no external byte survives.
                resolved = created_path.resolve()
                expected_prefix = (
                    os.path.normcase(os.path.abspath(str(parent))) + os.sep
                )
                if not os.path.normcase(str(resolved)).startswith(
                    expected_prefix
                ):
                    with _suppress_os_error():
                        os.close(descriptor)
                    with _suppress_os_error():
                        os.unlink(str(created_path))
                    raise PalError(
                        "PATH_ESCAPE",
                        f"parent directory {str(parent)!r} was replaced "
                        "during the create; refusing to continue",
                    )
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write to home file descriptor")
            view = view[written:]
    except BaseException:
        with _suppress_os_error():
            os.close(descriptor)
        raise
    return descriptor


def confined_append_line(root: Path | str, relative: Path | str, line: bytes) -> Path:
    """Append exactly one line to a home file through the physical boundary.

    PAL-WRITE-01 A: the previous implementation opened the path directly, so a
    final symlink (or a swapped parent) carried events outside the home. This
    primitive binds the append to the verified home fd: on POSIX the final
    node is opened O_NOFOLLOW (a symlink is refused outright) and dir-fd-
    relative (a raced parent swap cannot redirect it); on Windows the home and
    parent are verified immediately before the open and the opened node's
    identity is cross-checked. Append-only semantics, O_APPEND and fsync are
    preserved; a refusal leaves every external byte untouched.
    """
    if not line.endswith(b"\n"):
        line = line + b"\n"
    root_fd = None
    parent_fd = None
    try:
        try:
            root_fd = _open_confined_dir(root)
        except OSError:
            root_fd = None
        parent, parent_fd = _open_confined_parent(root, Path(relative).parent, root_fd)
        name = Path(relative).name
        binary = getattr(os, "O_BINARY", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if parent_fd is None:
            # Windows (no O_NOFOLLOW): judge the final node WITHOUT following
            # it first, so an existing or dangling symlink is refused instead
            # of being created through (PAL-WRITE-01 A, dangling control).
            _refuse_forbidden_node(parent / name, "log destination")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | binary | nofollow
        descriptor = _confined_fd_write(parent_fd, parent, name, flags, line)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        # T-127 Defect A: BOTH descriptors this call owns are closed here --
        # the borrowed parent fd first (it exists only for this append), then
        # the root fd. The previous version closed the root fd only, so every
        # POSIX append leaked exactly one descriptor.
        _close_fd(parent_fd)
        _close_fd(root_fd)
    return Path(root) / Path(relative)


def atomic_write_bytes(path: Path | str, data: bytes, *, root: Path | str) -> Path:
    """Write `data` into the home atomically, or raise.

    Refuses a symlinked or non-regular final node, writes to a uniquely named
    temporary in the SAME directory so the rename cannot cross a mount, and
    only then replaces the target.

    The final node is judged BEFORE resolution erases its identity: a final
    symlink is refused even when its target sits inside the root, a dangling
    symlink is refused with its target never created, and every directory on
    the real path below the root is proven real (never a junction/reparse
    point) so parent indirection cannot carry the write outside.

    PAL-WRITE-01 C (T-125): the previous proof was path-based and died to a
    raced parent swap -- the parent was real during validation, then became a
    symlink before the temp-file open, and the bytes escaped. The write is now
    bound to the PHYSICAL home: on POSIX the whole walk (home fd, each parent
    level, temp open, rename) is descriptor-relative with O_NOFOLLOW, so there
    is no re-resolved path left to race. On Windows (no directory fds in
    stdlib Python) the home and every parent level are re-verified immediately
    before the temp open and the replace, and any indirection refuses; the
    residual non-reparse swap window is the documented platform limitation.
    Failures leave the requested node, the parent chain, and every external
    byte untouched.
    """
    lexical = Path(os.path.abspath(str(path)))
    # T-127 Defect B: the root is bound LEXICALLY. `Path(root).resolve()` was
    # used here as the security proof, which ERASES the very indirection being
    # judged -- a home reached through a symlinked ancestor resolved to the
    # external target and then "proved" itself. The lexical root is what the
    # complete-chain walk below proves; the resolved containment check stays
    # as defence in depth.
    root_path = Path(os.path.abspath(str(root)))

    # (0) The requested path must sit under the home LEXICALLY (case-insensitive
    # on Windows), and -- defence in depth -- its resolved form must sit under
    # the resolved home. Both refusals happen BEFORE the physical walk begins.
    relative = _rel_inside(root_path, lexical)
    prove_inside(Path(root).resolve(), lexical)

    # (1) Open the home as a verified directory fd where supported. Refusal
    # leaves every byte (internal and external) untouched.
    root_fd = None
    parent_fd = None
    try:
        try:
            root_fd = _open_confined_dir(root_path)
        except OSError:
            root_fd = None
        # (2) Confine the physical parent inside the opened home. On POSIX
        # this walk is fully descriptor-relative; on Windows it is the
        # reparse-verified chain probe.
        parent, parent_fd = _open_confined_parent(root_path, relative.parent, root_fd)

        # (3) The requested FINAL node, judged WITHOUT following it, and -- on
        # POSIX -- bound to the SAME verified parent fd the replace below uses
        # (CORE-002): a parent namespace swap cannot make the classification
        # inspect one directory while the mutation replaces a node in another.
        final_path = Path(os.path.abspath(str(parent / relative.name)))
        try:
            final_st = _stat_final_node(parent, relative.name, parent_fd)
        except OSError as exc:
            raise PalError(
                "PATH_ESCAPE",
                f"destination {str(lexical)!r} cannot be stated: {exc}",
            ) from exc
        if final_st is not None:
            if stat.S_ISLNK(final_st.st_mode) or carries_reparse_attr(final_path):
                raise PalError(
                    "PATH_ESCAPE",
                    f"path {str(lexical)!r} is a symlink/junction/reparse point; "
                    "refusing to write through it",
                )
            if not stat.S_ISREG(final_st.st_mode):
                raise PalError(
                    "PATH_ESCAPE",
                    f"path {str(lexical)!r} is not a regular file; refusing to replace it",
                )

        # (4) Temp open + write, bound to the verified parent fd.
        tmp_name = f".{relative.name}.{uuid.uuid4().hex}.tmp"
        binary = getattr(os, "O_BINARY", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        descriptor = _confined_fd_write(
            parent_fd,
            parent,
            tmp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary | nofollow,
            data,
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

        # (5) Atomic replace, still under the verified parent. On POSIX the
        # rename is dir-fd-relative: a swapped parent directory cannot
        # participate. On Windows the parent is re-verified first (the
        # residual non-reparse swap window is documented in the module
        # docstring and checkpoint).
        if parent_fd is None:
            _refuse_forbidden_node(parent, "parent directory")
            os.replace(str(parent / tmp_name), str(final_path))
        else:
            os.replace(tmp_name, relative.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        return final_path
    finally:
        # T-127 Defect A: one close path for BOTH owned descriptors.
        _close_fd(parent_fd)
        _close_fd(root_fd)


def atomic_write_json(path: Path | str, payload: object, *, root: Path | str) -> Path:
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
    return atomic_write_bytes(path, (text + "\n").encode("utf-8"), root=root)


def _rel_inside(root: Path, target: Path) -> Path:
    """`target` relative to `root`, refusing anything that is not inside.

    Works on Windows even when a parent of `target` is still missing, because
    it compares the resolved ROOT against the LEXICAL target: no component of
    `target` below the root is resolved, so no missing-directory TypeError is
    possible and no indirection below the root can participate in the decision
    (every such level is judged by `_prove_windows_chain` / the fd walk).
    """
    root_key = _norm_root_key(root)
    target = Path(os.path.abspath(str(target)))
    rel = []
    probe = target
    while True:
        if _norm_root_key(probe) == root_key:
            break
        if _norm_root_key(probe) == _norm_root_key(probe.parent):
            raise PalError(
                "PATH_ESCAPE",
                f"path {str(target)!r} is not confined to root {str(root)!r}",
                next_action="SAIPAL writes only inside its own home",
            )
        rel.append(probe.name)
        probe = probe.parent
    return Path(*reversed(rel))


def _stat_final_node(
    parent: Path, name: str, parent_fd: int | None
) -> object | None:
    """Stat the FINAL node WITHOUT following it, bound to the verified parent.

    CORE-002 (SRC-011): the atomic-write final-node classification used a
    lexical `os.lstat(final_path)` while the actual replace was descriptor-
    relative under `parent_fd`, so a parent namespace swap could make the
    validator inspect a regular/absent node in one directory and then replace a
    symlink/non-regular node in another. When a verified parent fd exists the
    node is stated fd-relatively (`dir_fd=parent_fd, follow_symlinks=False`), so
    classification and mutation observe the SAME physical parent. Returns the
    stat result (or None when the node is absent).
    """
    if parent_fd is not None:
        try:
            return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError):
            return None
    try:
        return os.lstat(str(parent / name))
    except FileNotFoundError:
        return None


def _close_fd(fd: int | None) -> None:
    """Close ONE descriptor this module owns, idempotently and never twice.

    T-127 Defect A: the ONE close path every confinement primitive uses for
    the descriptors it opened or duplicated. `None` is a no-op, so a platform
    without directory fds needs no branch at the call site. A failure to
    close is suppressed on purpose (it is reported by the operation that
already succeeded or already raised), but it is never skipped: the call is
    unconditional, so no path can forget it.
    """
    if fd is not None:
        with _suppress_os_error():
            os.close(fd)


#: Historical name for the root-fd close path, kept so an out-of-tree caller
#: cannot break; the semantics are exactly `_close_fd`'s (T-127).
_close_root_fd = _close_fd


def establish_root(root: Path | str) -> Path:
    """Safely establish a root directory walking component-by-component.

    TARGET 2 (T-125): Root establishment must walk from an already trusted
    physical ancestor. For each component:
      1. bind/open the trusted current parent;
      2. inspect the next component without following indirection;
      3. create exactly one directory level relative to the bound parent;
      4. bind/open the newly created directory;
      5. continue.
    Never calls `mkdir(parents=True)` through an untrusted ancestor chain.
    On POSIX, uses descriptor-relative mkdir/open (O_NOFOLLOW|O_DIRECTORY).
    On Windows, uses non-following reparse probe and level-by-level mkdir.
    """
    root_path = Path(root)
    target_abs = Path(os.path.abspath(str(root_path)))
    parts = target_abs.parts
    if not parts:
        return root_path

    current_path = Path(parts[0])
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    binary = getattr(os, "O_BINARY", 0)
    flags = os.O_RDONLY | binary | nofollow | directory

    if os.name != "nt" and (nofollow or directory):
        try:
            current_fd = os.open(str(current_path), flags)
        except OSError as exc:
            raise PalError(
                "PATH_ESCAPE",
                f"root {str(current_path)!r} cannot be opened as a real directory: {exc}",
                next_action="SAIPAL writes only inside its own home",
            ) from exc

        try:
            for name in parts[1:]:
                # 1. Inspect next component without following indirection
                exists = True
                try:
                    st = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
                except (FileNotFoundError, NotADirectoryError):
                    exists = False
                except OSError as exc:
                    raise PalError(
                        "PATH_ESCAPE",
                        f"cannot inspect path component {name!r} under {str(current_path)!r}: {exc}",
                        next_action="SAIPAL writes only inside its own home",
                    ) from exc

                if exists:
                    if stat.S_ISLNK(st.st_mode):
                        raise PalError(
                            "PATH_ESCAPE",
                            f"path component {name!r} under {str(current_path)!r} is a symlink; "
                            "refusing to traverse or materialize through it",
                            next_action="SAIPAL writes only inside its own home",
                        )
                    if not stat.S_ISDIR(st.st_mode):
                        raise PalError(
                            "PATH_ESCAPE",
                            f"path component {name!r} under {str(current_path)!r} exists and is not a directory",
                            next_action="SAIPAL writes only inside its own home",
                        )
                    try:
                        next_fd = os.open(name, flags, dir_fd=current_fd)
                    except OSError as exc:
                        raise PalError(
                            "PATH_ESCAPE",
                            f"cannot open directory component {name!r} under {str(current_path)!r}: {exc}",
                            next_action="SAIPAL writes only inside its own home",
                        ) from exc
                    try:
                        st_next = os.fstat(next_fd)
                        if (st_next.st_dev, st_next.st_ino) != (st.st_dev, st.st_ino):
                            raise PalError(
                                "PATH_ESCAPE",
                                f"directory component {name!r} under {str(current_path)!r} changed identity while opening",
                                next_action="SAIPAL writes only inside its own home",
                            )
                    except BaseException:
                        os.close(next_fd)
                        raise
                    os.close(current_fd)
                    current_fd = next_fd
                    current_path = current_path / name
                else:
                    # 2. Create exactly one directory level relative to the bound parent
                    try:
                        os.mkdir(name, 0o777, dir_fd=current_fd)
                    except FileExistsError:
                        pass
                    except OSError as exc:
                        raise PalError(
                            "PATH_ESCAPE",
                            f"cannot create directory component {name!r} under {str(current_path)!r}: {exc}",
                            next_action="SAIPAL writes only inside its own home",
                        ) from exc

                    # 3. Bind/open the newly created directory
                    try:
                        next_fd = os.open(name, flags, dir_fd=current_fd)
                    except OSError as exc:
                        raise PalError(
                            "PATH_ESCAPE",
                            f"cannot open newly created directory component {name!r} under {str(current_path)!r}: {exc}",
                            next_action="SAIPAL writes only inside its own home",
                        ) from exc
                    try:
                        st_next = os.fstat(next_fd)
                        if stat.S_ISLNK(st_next.st_mode):
                            raise PalError(
                                "PATH_ESCAPE",
                                f"newly created directory component {name!r} under {str(current_path)!r} is a symlink",
                                next_action="SAIPAL writes only inside its own home",
                            )
                        if not stat.S_ISDIR(st_next.st_mode):
                            raise PalError(
                                "PATH_ESCAPE",
                                f"newly created directory component {name!r} under {str(current_path)!r} is not a directory",
                                next_action="SAIPAL writes only inside its own home",
                            )
                    except BaseException:
                        os.close(next_fd)
                        raise
                    os.close(current_fd)
                    current_fd = next_fd
                    current_path = current_path / name
        finally:
            with _suppress_os_error():
                os.close(current_fd)
        return root_path
    else:
        # Windows fallback: verify level by level without following reparse points
        if carries_reparse_attr(current_path):
            raise PalError(
                "PATH_ESCAPE",
                f"root drive {str(current_path)!r} is a reparse point; refusing to materialize through it",
                next_action="SAIPAL writes only inside its own home",
            )
        for name in parts[1:]:
            next_path = current_path / name
            exists = True
            try:
                st = os.lstat(str(next_path))
            except (FileNotFoundError, NotADirectoryError):
                exists = False
            except OSError as exc:
                raise PalError(
                    "PATH_ESCAPE",
                    f"cannot inspect path component {str(next_path)!r}: {exc}",
                    next_action="SAIPAL writes only inside its own home",
                ) from exc

            if exists:
                if stat.S_ISLNK(st.st_mode) or carries_reparse_attr(next_path):
                    raise PalError(
                        "PATH_ESCAPE",
                        f"path component {str(next_path)!r} is a symlink/junction/reparse point; "
                        "refusing to traverse or materialize through it",
                        next_action="SAIPAL writes only inside its own home",
                    )
                if not stat.S_ISDIR(st.st_mode):
                    raise PalError(
                        "PATH_ESCAPE",
                        f"path component {str(next_path)!r} exists and is not a directory",
                        next_action="SAIPAL writes only inside its own home",
                    )
                current_path = next_path
            else:
                # Re-verify current parent is not a reparse point
                if carries_reparse_attr(current_path) or stat.S_ISLNK(os.lstat(str(current_path)).st_mode):
                    raise PalError(
                        "PATH_ESCAPE",
                        f"parent directory {str(current_path)!r} is a symlink/junction/reparse point; "
                        "refusing to write through it",
                        next_action="SAIPAL writes only inside its own home",
                    )
                try:
                    next_path.mkdir(exist_ok=True)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise PalError(
                        "PATH_ESCAPE",
                        f"cannot create directory component {str(next_path)!r}: {exc}",
                        next_action="SAIPAL writes only inside its own home",
                    ) from exc
                try:
                    st = os.lstat(str(next_path))
                except OSError as exc:
                    raise PalError(
                        "PATH_ESCAPE",
                        f"cannot inspect newly created directory {str(next_path)!r}: {exc}",
                        next_action="SAIPAL writes only inside its own home",
                    ) from exc
                if stat.S_ISLNK(st.st_mode) or carries_reparse_attr(next_path):
                    raise PalError(
                        "PATH_ESCAPE",
                        f"newly created directory {str(next_path)!r} is a symlink/reparse point; "
                        "refusing to write through it",
                        next_action="SAIPAL writes only inside its own home",
                    )
                if not stat.S_ISDIR(st.st_mode):
                    raise PalError(
                        "PATH_ESCAPE",
                        f"newly created directory {str(next_path)!r} exists and is not a directory",
                        next_action="SAIPAL writes only inside its own home",
                    )
                current_path = next_path
        return root_path


def confined_mkdir(root: Path | str, relative: Path | str) -> Path:
    """Create one directory level under the physical root.

    T-125 Defect D/E: raw `mkdir(...)` calls that materialize the home
    through an indirection root create external directories before any guard
    sees them. This primitive creates only through a proven-real parent: on
    POSIX the parent is bound by fd; on Windows the chain is reparse-verified
    before the mkdir. Idempotent (`exist_ok`); a refusal creates nothing.
    """
    root_path = Path(root)
    rel = Path(relative)
    if str(rel) not in ("", "."):
        parts = [p for p in rel.parts if p not in (".", "")]
        if len(parts) != 1:
            # Walk the tree level by level, each through this same primitive.
            current = root_path
            for part in parts:
                current = confined_mkdir(current, part)
            return current
        rel = Path(parts[0])
    if str(rel) in ("", "."):
        return establish_root(root_path)
    root_fd = None
    parent_fd = None
    try:
        try:
            root_fd = _open_confined_dir(root_path)
        except OSError:
            root_fd = None
        parent, parent_fd = _open_confined_parent(root_path, rel.parent, root_fd)
        try:
            if parent_fd is not None:
                try:
                    os.mkdir(rel.name, dir_fd=parent_fd)
                except FileExistsError:
                    pass
            else:
                _prove_windows_chain(
                    root_path, Path(os.path.abspath(str(root_path / rel.parent))),
                    create=False,
                )
                _refuse_forbidden_node(parent / rel.name, "directory target")
                try:
                    (parent / rel.name).mkdir(exist_ok=True)
                except FileExistsError:
                    pass
            st = os.lstat(str(parent / rel.name))
            if stat.S_ISLNK(st.st_mode) or carries_reparse_attr(parent / rel.name):
                raise PalError(
                    "PATH_ESCAPE",
                    f"directory {str(parent / rel.name)!r} is a symlink/junction/"
                    "reparse point; refusing to materialize through it",
                )
            if not stat.S_ISDIR(st.st_mode):
                raise PalError(
                    "PATH_ESCAPE",
                    f"{str(parent / rel.name)!r} exists and is not a directory",
                )
        except OSError as exc:
            raise PalError(
                "PATH_ESCAPE",
                f"cannot create directory {str(root_path / rel)!r}: {exc}",
            ) from exc
        return parent / rel.name
    finally:
        # T-127 Defect A: BOTH owned descriptors, or every POSIX mkdir leaks.
        _close_fd(parent_fd)
        _close_fd(root_fd)


def establish_lock_surface(home: Path | str) -> Path:
    """SAFE bootstrap: materialize the MINIMUM surface a writer lock needs.

    T-125 Target A: the CLI takes the writer fence BEFORE `ensure_home` can
    run, so a completely missing home, or a minimally initialized one
    (``.saipal/config.json`` and nothing else), deadlocked -- the confined
    exclusive create correctly refuses a missing lock parent and nothing had
    materialized it.

    This is the ONE owner of that bootstrap: ONLY the home root and its
    ``locks/`` directory are established, both through the confinement
    primitives (``confined_mkdir``), and only from the writer fence. The full
    layout stays `ensure_home`'s job. An indirection home root or locks
    directory refuses here with zero external mutation, and
    `FencedLockFile` never creates arbitrary parents -- that ownership is
    deliberately NOT part of its contract.
    """
    root = confined_mkdir(home, ".")
    confined_mkdir(root, LOCKS_DIR)
    return root


def confined_create_exclusive(
    root: Path | str,
    relative: Path | str,
    data: bytes,
) -> Path:
    """Create `relative` under the physical root with O_EXCL, or fail.

    T-125 Defect B: the lock create must not re-resolve an attacker-mutable
    pathname after validation. On POSIX the parent is held as a VERIFIED
    directory fd across the open, so a raced parent swap (delete + re-create
    as a symlink) cannot participate: the node is created beside the verified
    directory, never inside whatever replaced the path. A known final
    symlink/junction/reparse node is an explicit PATH_ESCAPE classification
    (T-125 Target B4), while O_EXCL|O_NOFOLLOW keeps the create itself safe
    from a node that appears after that classification; a refusal leaves
    every external byte untouched.
    """
    root_path = Path(root)
    rel = Path(relative)
    parent, parent_fd, root_fd = _confined_target_with_root(root_path, rel)
    try:
        # TARGET B4 (T-125): classify the FINAL node before the create so a
        # known indirection is a security refusal, not ordinary lock
        # contention. Classification only -- see `_refuse_indirection_final`.
        _refuse_indirection_final(
            parent, rel.name, parent_fd, "exclusive-create destination"
        )
        binary = getattr(os, "O_BINARY", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if parent_fd is not None:
            descriptor = os.open(
                rel.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary | nofollow,
                0o600,
                dir_fd=parent_fd,
            )
        else:
            node = parent / rel.name
            try:
                descriptor = os.open(str(node), os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary, 0o600)
            except FileExistsError:
                raise
            # Windows: a raced parent swap between the chain probe and this
            # open resolves the create through the replacement indirection.
            # Resolve the node we actually created; when it no longer sits
            # under the verified parent, remove the stray and refuse so no
            # external byte survives.
            resolved = node.resolve()
            expected_prefix = (
                os.path.normcase(os.path.abspath(str(parent))) + os.sep
            )
            if not os.path.normcase(str(resolved)).startswith(expected_prefix):
                with _suppress_os_error():
                    os.close(descriptor)
                with _suppress_os_error():
                    os.unlink(str(resolved))
                raise PalError(
                    "PATH_ESCAPE",
                    f"parent directory {str(parent)!r} was replaced during "
                    "the create; refusing to continue",
                )
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write to home file descriptor")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        if isinstance(exc, FileExistsError):
            raise
        raise PalError(
            "WRITER_BUSY",
            f"cannot create {str(Path(root) / rel)!r}: {exc}",
        ) from exc
    finally:
        # T-127 Defect A: the exclusive create owns BOTH descriptors handed
        # back by `_confined_target_with_root`.
        _close_fd(parent_fd)
        _close_fd(root_fd)
    return Path(root) / rel


def _confined_target_with_root(
    root: Path | str,
    target: Path | str,
) -> tuple[Path, int | None, int | None]:
    """Like `_confined_target`, but also hands back the root fd so the caller
    can keep the home bound across the mutation and close it afterwards."""
    root_path = Path(root)
    target_path = Path(target)
    if target_path.is_absolute():
        # An absolute target must sit under the root; the chain probe and
        # _rel_inside both re-prove that below.
        physical_target = Path(os.path.abspath(str(target_path)))
    else:
        # A RELATIVE target is root-relative by contract. It must never be
        # resolved against the process CWD (that would confine nothing).
        physical_target = Path(os.path.abspath(str(root_path / target_path)))
    # TARGET B2 (T-125): no implicit parent creation. The parent chain of the
    # target must already exist and be real; the callers that own directory
    # creation call `confined_mkdir` explicitly first. A missing level is
    # therefore a PATH_ESCAPE refusal on EVERY platform instead of a silent
    # recursive mkdir inside a write primitive.
    root_fd = None
    try:
        root_fd = _open_confined_dir(root_path)
    except OSError:
        root_fd = None
    try:
        rel = _rel_inside(Path(root_path).resolve(), physical_target)
        parent, parent_fd = _open_confined_parent(root_path, rel.parent, root_fd)
        return parent, parent_fd, root_fd
    except BaseException:
        _close_root_fd(root_fd)
        raise


def confined_replace(
    root: Path | str,
    source_relative: Path | str,
    target_relative: Path | str,
) -> Path:
    """Rename `source_relative` onto `target_relative`, both under the root.

    T-125 Defect B: the takeover/claim/sidecar renames must not re-resolve a
    mutable pathname after validation. On POSIX both ends are bound to
    verified parent fds (two separate `_open_confined_parent` walks under the
    same root fd; a swap in either parent between walk and rename redirects
    nothing). On Windows both parents are reparse-verified immediately before
    the rename (the documented residual swap window applies).
    """
    root_path = Path(root)
    src_rel = Path(source_relative)
    dst_rel = Path(target_relative)
    src_parent, src_fd, root_fd = _confined_target_with_root(root_path, src_rel)
    try:
        # One walk per end, under the SAME already-verified root fd.
        dst_rel_clean = _rel_inside(
            Path(root_path).resolve(),
            Path(os.path.abspath(str(root_path / dst_rel))),
        )
        dst_parent, dst_fd = _open_confined_parent(
            root_path, dst_rel_clean.parent, root_fd,
        )
        try:
            if os.name == "nt":
                _refuse_forbidden_node(src_parent / src_rel.name, "rename source")
                _refuse_forbidden_node(dst_parent / dst_rel.name, "rename destination")
                os.replace(str(src_parent / src_rel.name), str(dst_parent / dst_rel.name))
            else:
                os.replace(
                    src_rel.name,
                    dst_rel.name,
                    src_dir_fd=src_fd,
                    dst_dir_fd=dst_fd,
                )
        finally:
            if dst_fd is not None:
                with _suppress_os_error():
                    os.close(dst_fd)
    finally:
        if src_fd is not None:
            with _suppress_os_error():
                os.close(src_fd)
        _close_root_fd(root_fd)
    return Path(root) / dst_rel


def confined_unlink(root: Path | str, relative: Path | str, *, missing_ok: bool = True) -> bool:
    """Unlink `relative` under the physical root, refusing indirection.

    T-125 Defect B (release/unlink) and Defect D (authority journal deletion):
    on POSIX the unlink is dir-fd-relative to the VERIFIED parent, so a raced
    parent swap cannot redirect the deletion outside; on Windows the parent is
    reparse-verified and the final node refused if it is an indirection.
    """
    root_path = Path(root)
    rel = Path(relative)
    parent, parent_fd, root_fd = _confined_target_with_root(root_path, rel)
    try:
        node = parent / rel.name
        if parent_fd is None:
            _refuse_forbidden_node(node, "unlink target")
        try:
            if parent_fd is not None:
                os.unlink(rel.name, dir_fd=parent_fd)
            else:
                os.unlink(str(node))
            return True
        except FileNotFoundError:
            if missing_ok:
                return False
            raise
    finally:
        # T-127 Defect A: the unlink owns BOTH descriptors handed back by
        # `_confined_target_with_root`.
        _close_fd(parent_fd)
        _close_fd(root_fd)


#: Upper bound on a node this module reads back for a compare-and-delete
#: verdict. Lock payloads and contested claims are small; a hostile file must
#: not be able to make the verdict allocate without bound.
CLAIM_READ_LIMIT = 65536


def _read_fd_all(fd: int, limit: int) -> bytes:
    """Read up to `limit` bytes from an owned descriptor, from its start."""
    with _suppress_os_error():
        os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = limit
    while remaining > 0:
        try:
            chunk = os.read(fd, remaining)
        except OSError:
            break
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def confined_compare_and_delete(
    root: Path | str,
    relative: Path | str,
    expected: bytes,
) -> tuple[bool, bytes]:
    """Judge one node and delete it only when it still matches `expected`.

    T-127 Defect D: the stale-takeover cleanup used to compare against the
    contested claim through an UNBOUND absolute path and then delete it with
    `_unlink_lock(path)` -- a raw `os.unlink`. The claim had been moved by the
    confined rename into a verified physical directory, but that binding was
    then thrown away, so replacing the lexical parent with an indirection made
    both the READ and the DELETE land on an external, attacker-controlled
    file.

    Here the parent directory is opened ONCE, verified, and held for BOTH the
    read and the delete: `(matched, observed)` answers what the object that was
    actually moved contains, and a parent swap between the two steps cannot
    redirect either half (the unlink is dir-fd-relative to the SAME verified
    parent; a swapped root is refused outright by `_open_confined_parent`).
    The final node is opened O_NOFOLLOW for the read, so the objective judged
    is never a symlink target.
    """
    root_path = Path(root)
    rel = Path(relative)
    parent, parent_fd, root_fd = _confined_target_with_root(root_path, rel)
    observed = b""
    try:
        node = parent / rel.name
        if parent_fd is not None:
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    rel.name,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_BINARY", 0),
                    dir_fd=parent_fd,
                )
            except OSError:
                descriptor = None
            if descriptor is not None:
                try:
                    observed = _read_fd_all(descriptor, CLAIM_READ_LIMIT)
                finally:
                    _close_fd(descriptor)
        else:
            _refuse_forbidden_node(node, "claim cleanup target")
            try:
                with open(str(node), "rb") as handle:
                    observed = handle.read(CLAIM_READ_LIMIT)
            except OSError:
                observed = b""
        if observed != expected:
            return False, observed
        try:
            if parent_fd is not None:
                os.unlink(rel.name, dir_fd=parent_fd)
            else:
                _unlink_lock(node)
        except OSError:
            pass
        return True, observed
    finally:
        _close_fd(parent_fd)
        _close_fd(root_fd)


def read_json(path: Path | str) -> object:
    """Read one JSON document. Malformed input raises ValueError; never guessed."""
    with open(str(path), "rb") as handle:
        raw = handle.read()
    return json.loads(raw.decode("utf-8-sig"))


class _SuppressOsError:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, exc, tb) -> bool:
        return exc_type is not None and issubclass(exc_type, OSError)


def _suppress_os_error() -> _SuppressOsError:
    return _SuppressOsError()


# --------------------------------------------------------------------------- #
# home lock
# --------------------------------------------------------------------------- #


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            handle = ctypes.windll.kernel32.OpenProcess(
                0x1000, False, pid  # PROCESS_QUERY_LIMITED_INFORMATION
            )
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


#: What a lock file looked like when it was inspected.
_LOCK_ABSENT = "absent"
_LOCK_UNREADABLE = "unreadable"
_LOCK_OK = "ok"


def _unlink_lock(path: Path) -> bool:
    """Delete a lock file, retrying past a transient sharing failure.

    Windows refuses to unlink a file while another handle has it open, and every
    contender opens the lock to judge it. A single best-effort unlink therefore
    fails occasionally and strands a released lock, which reads to the next
    publisher as a live one and wedges it until the TTL. `FileNotFoundError`
    means somebody else already removed it -- also success.
    """
    for attempt in range(LOCK_UNLINK_ATTEMPTS):
        try:
            os.unlink(str(path))
            return True
        except FileNotFoundError:
            return True
        except OSError:
            if attempt == LOCK_UNLINK_ATTEMPTS - 1:
                return not path.exists()
            time.sleep(LOCK_UNLINK_DELAY_SECONDS)
    return not path.exists()


def _valid_ttl(value: object) -> float | None:
    """Strict owner-policy TTL: finite, positive, bounded. Anything else is None.

    A malformed/non-positive/NaN/infinite/unbounded TTL must never be trusted as
    lease truth (audit T-120/CONTROL-E). Booleans are rejected explicitly:
    ``isinstance(True, int)`` is True, so a stray ``True`` would validate as 1.0.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        ttl = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(ttl) or ttl <= 0 or ttl > LOCK_MAX_TTL_SECONDS:
        return None
    return ttl


class FencedLockFile:
    """One lock file whose holder can PROVE it still owns it.

    The filesystem node is not proof of ownership: ownership can change after
    acquisition. A lock that unlinks whatever node happens to be present will
    eventually delete a successor's live lock and admit two writers (audit
    W2-001). So an acquisition mints an owner token, keeps it, and release
    unlinks only when the on-disk owner is still that token.

    Three quieter rules follow from the same reasoning:

    - `O_EXCL` creates the node before the payload is written, so every honest
      acquisition is briefly unreadable. Inside `grace` an unreadable lock means
      "another run is mid-acquisition", not "debris";
    - a dead owner is recovered without waiting out the TTL, so the PID is
      checked first -- but only when the lock was taken on this host, because a
      foreign PID probed locally answers about an unrelated process;
    - takeover is fenced by a rename, so two contenders cannot both claim one
      corpse, and the claimed bytes are compared against the bytes judged stale.

    This is the ONLY lock mechanism; `HomeLock`, `SessionLease` and
    `AuditInboxLock` are wrappers over it.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        ttl: float = LOCK_TTL_SECONDS,
        grace: float = LOCK_CREATE_GRACE_SECONDS,
        busy_detail: str = "another run holds this lock",
        confine_under: Path | str | None = None,
    ):
        self.path = Path(path)
        self.ttl = float(ttl)
        self.grace = float(grace)
        self.busy_detail = busy_detail
        #: PAL-WRITE-01 (T-125): when set, every mutation this lock performs
        #: (acquire create, stale takeover rename, lease sidecar write) is
        #: refused unless the lock's parent chain is physically confined under
        #: this root and the final node is not a symlink/junction/reparse
        #: point. HomeLock/SessionLease pass the home; AuditInboxLock passes
        #: its audit-dir root.
        self._confine_under = Path(confine_under) if confine_under is not None else None
        self.token: str | None = None
        self.stale_taken_over = False
        self.detail = ""
        self._held = False

    def _establish_parent(self) -> None:
        """Establish the lock's OWN parent directory through `confined_mkdir`.

        T-125 Target A/B: taking the first lock on a home whose ``locks/``
        directory does not exist yet must be possible, and it must be possible
        SAFELY. This is deliberately the BOUNDED part of this class's
        contract: exactly the directory chain that holds this lock file is
        established -- never an unrelated or arbitrary parent -- and only
        through the confinement primitive, so a symlinked/junction/reparse
        level refuses with ZERO external mutation.

        `HomeLock` additionally owns the explicit writer-fence bootstrap of
        the home root and ``locks/`` (`establish_lock_surface`); this method is
        what lets the other wrappers (`SessionLease`, `AuditInboxLock`) and
        direct callers work on a minimally materialized home.
        """
        root = self._confine_under
        if root is None:
            # No confinement root above the lock directory: the lock's own
            # directory is exactly what must exist. It is created as ONE level
            # under a parent that must already exist and be real -- never with
            # a `mkdir(parents=True)` that could descend through a symlinked
            # home, and never through an indirection at the lock dir itself.
            parent = self.path.parent
            _refuse_forbidden_node(parent, "lock directory")
            confined_mkdir(parent.parent, parent.name)
            return
        rel = _rel_inside(
            Path(root).resolve(), Path(os.path.abspath(str(self.path)))
        )
        if str(rel.parent) not in ("", "."):
            confined_mkdir(root, rel.parent)

    @property
    def held(self) -> bool:
        return self._held

    # -- payload ----------------------------------------------------------- #

    def _payload_bytes(self, token: str, extra: dict | None = None) -> bytes:
        # `ttl` is part of the immutable owner identity written once at
        # acquisition: the OWNER's lease policy. It is never rewritten after
        # this single O_EXCL write (T-110), and it is what contenders must
        # judge the lease against -- never their own constructor ttl.
        payload = {
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "created_at": time.time(),
            "owner": token,
            "ttl": self.ttl,
        }
        payload.update(extra or {})
        return (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")

    def _lease_fresh_bytes(self) -> dict:
        """The sidecar freshness record a refresh may write.

        Refreshing must never rewrite the lock node: the owner payload is the
        FENCING IDENTITY and is immutable once acquired (T-110). Lease freshness
        lives beside the lock in `.<name>.lease`, carrying the owning token --
        so a stale touch from a dethroned owner can be recognized and ignored,
        and takeover can discard freshness that does not name the current owner.
        """
        return {"owner": self.token, "ttl": self.ttl, "renewed_at": time.time()}

    def _lease_side_path(self) -> Path:
        return self.path.parent / f".{self.path.name}.lease"

    def _write_lease_freshness(self) -> bool:
        """Publish the sidecar heartbeat. Never touches the lock node itself.

        A transient sharing violation on the sidecar rename (the same Windows
        read-window `_unlink_lock` retries past) must not read as ownership
        loss: the lock node still names this owner, so a failed heartbeat is
        DELAYED freshness, never a lost lease. Retry briefly; only a persistent
        failure returns False, and even then the caller's `owns_on_disk` check
        decides ownership, not this write.
        """
        payload = (json.dumps(self._lease_fresh_bytes(), sort_keys=True) + "\n").encode(
            "utf-8"
        )
        # PAL-WRITE-01 (T-125, Defect B): the sidecar write goes through the
        # confined create/replace primitives under the confinement root, so
        # neither the temp write nor the replace re-resolves an attacker-
        # mutable pathname. A refusal means delayed freshness -- never a lost
        # lease -- exactly like a transient sharing failure.
        root = self._confine_under or self.path.parent
        side_rel = _rel_inside(
            Path(root).resolve(),
            Path(os.path.abspath(str(self._lease_side_path()))),
        )
        tmp_rel = None
        # A transient sharing violation on the sidecar rename must not read
        # as ownership loss: retry briefly, exactly like the pre-T-125
        # path-based loop did. Confinement is identical on every attempt.
        for attempt in range(LOCK_UNLINK_ATTEMPTS):
            try:
                tmp_rel = side_rel.with_name(
                    f".{self.path.name}.lease.{uuid.uuid4().hex}"
                )
                confined_create_exclusive(root, tmp_rel, payload)
                confined_replace(root, tmp_rel, side_rel)
                return True
            except (PalError, OSError):
                if tmp_rel is not None:
                    with _suppress_os_error():
                        try:
                            confined_unlink(root, tmp_rel)
                        except (OSError, PalError):
                            pass
                if attempt == LOCK_UNLINK_ATTEMPTS - 1:
                    return False
                time.sleep(LOCK_UNLINK_DELAY_SECONDS)
        return False

    def _read_lease_freshness(self) -> dict | None:
        try:
            raw = self._lease_side_path().read_bytes()
        except (FileNotFoundError, OSError):
            return None
        try:
            payload = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, ValueError):
            return None
        return payload if isinstance(payload, dict) else None

    def _lease_age_seconds(self) -> float | None:
        """Age of the freshest lease record naming the CURRENT on-disk owner.

        None means "no usable freshness surface": the caller falls back to the
        lock file's own mtime, which is the pre-sidecar behavior and stays
        crash-recoverable (a crashed holder's mtime simply ages past the TTL).
        """
        payload = self._read_lease_freshness()
        if not payload:
            return None
        try:
            renewed_at = float(payload.get("renewed_at") or 0)
        except (TypeError, ValueError):
            return None
        state, on_disk, _raw = self._inspect()
        if state != _LOCK_OK:
            return None
        if str(on_disk.get("owner") or "") != str(payload.get("owner") or ""):
            # The freshness record does not name the lock's current owner:
            # a dethroned old owner's last touch, or debris. Ignore it --
            # a stale touch must never make a successor look fresh.
            return None
        return max(0.0, time.time() - renewed_at)

    def _inspect(self) -> tuple[str, dict | None, bytes]:
        """`(state, payload, raw)` for the lock file as it is right now."""
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return _LOCK_ABSENT, None, b""
        except OSError:
            return _LOCK_UNREADABLE, None, b""
        try:
            payload = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, ValueError):
            return _LOCK_UNREADABLE, None, raw
        if not isinstance(payload, dict):
            return _LOCK_UNREADABLE, None, raw
        return _LOCK_OK, payload, raw

    def _age_on_disk(self) -> float:
        """How long ago the CURRENT owner last proved it is alive.

        The sidecar lease record is authoritative while it names the current
        on-disk owner; the lock node's own mtime is the fallback (the
        pre-sidecar behavior) and keeps staleness crash-recoverable when no
        sidecar exists yet.
        """
        lease_age = self._lease_age_seconds()
        if lease_age is not None:
            return lease_age
        try:
            return max(0.0, time.time() - self.path.stat().st_mtime)
        except OSError:
            return self.grace + 1.0

    # -- staleness --------------------------------------------------------- #

    def _effective_ttl(self, payload: dict) -> float:
        """The lease expiry threshold a contender must judge the CURRENT owner by.

        Ownership policy, never contender policy: the expiry threshold comes from
        the owner's own lease record, in precedence order:

        1. the sidecar heartbeat naming the current on-disk owner -- the live
           owner TTL (validated finite/positive/bounded);
        2. the immutable node payload ttl set at acquisition -- owner truth that
           survives the pre-first-refresh window even with no sidecar yet;
        3. the module default -- a legacy node with no recorded TTL.

        A contender's own ``self.ttl`` is deliberately NEVER consulted: a small
        contender TTL must not shorten a live owner's lease (audit T-120/CONTROL-A).
        A sidecar that names a DIFFERENT (old) owner is ignored, so a stale
        predecessor cannot keep a successor alive or kill it early (CONTROL-D).
        """
        side = self._read_lease_freshness()
        if side and str(side.get("owner") or "") == str(payload.get("owner") or ""):
            ttl = _valid_ttl(side.get("ttl"))
            if ttl is not None:
                return ttl
        node_ttl = _valid_ttl(payload.get("ttl"))
        if node_ttl is not None:
            return node_ttl
        return LOCK_TTL_SECONDS

    def _payload_is_stale(self, payload: dict) -> bool:
        try:
            pid = int(payload.get("pid", 0))
        except (TypeError, ValueError):
            return True
        host = str(payload.get("host") or "")
        # PID before TTL: a crashed owner should not wedge the home for the rest
        # of the TTL. An impossible pid is dead by definition; a real pid is only
        # probed when the lock was taken on this host.
        if pid <= 0:
            return True
        if host == socket.gethostname() and not _pid_alive(pid):
            return True
        # Liveness/age goes through the sidecar-aware clock: while the current
        # owner keeps refreshing its sidecar record the lock is not stale, and
        # once a dethroned owner's record no longer names the current owner the
        # node's own mtime decides (T-110: the payload is immutable, so the old
        # `created_at` field can no longer be relied on for renewal).
        #
        # The expiry threshold is the CURRENT OWNER's TTL (sidecar, then node
        # payload, then default) -- never the contender's. See `_effective_ttl`.
        return self._age_on_disk() >= self._effective_ttl(payload)

    def _stale_now(self) -> tuple[bool, bytes]:
        """`(is_stale, raw)` -- the bytes are what the verdict was formed on."""
        state, payload, raw = self._inspect()
        if state == _LOCK_ABSENT:
            return True, raw
        if state == _LOCK_UNREADABLE:
            # Either a live acquisition between create and write, or debris a
            # crash left behind. Time tells them apart; guessing "debris" here is
            # exactly the create-window steal this class exists to prevent.
            return self._age_on_disk() >= self.grace, raw
        assert payload is not None
        return self._payload_is_stale(payload), raw

    def _take_over_if_stale(self) -> bool:
        """Claim a stale lock, or lose the race without destroying anything."""
        stale, judged = self._stale_now()
        if not stale:
            return False
        # PAL-WRITE-01 (T-125, Defect B): a takeover must never rename or
        # delete through an indirection. The claim rename goes through the
        # confined replace primitive under the confinement root (or the lock's
        # own parent when no root is set), so the physical parent verified at
        # the fd level is what the rename lands in -- a raced parent swap
        # cannot redirect the claim outside. A symlinked lock node is refused
        # by the primitive itself; the external target keeps its bytes.
        try:
            root = self._confine_under or self.path.parent
            node_rel = _rel_inside(
                Path(root).resolve(), Path(os.path.abspath(str(self.path)))
            )
            claim = node_rel.with_name(f".{self.path.name}.contested.{uuid.uuid4().hex}")
            confined_replace(root, node_rel, claim)
        except PalError:
            raise
        except OSError:
            # Somebody else claimed it first, or a contender
            # still holds the node open. All mean "not ours"; nothing moved.
            return False
        # T-127 Defect D: judge and clean up the contested claim through the
        # SAME verified physical parent the rename used. The previous code
        # rebuilt `self.path.parent / claim.name` (an unbound absolute path),
        # read it, and deleted it with a raw unlink -- so replacing the lexical
        # locks parent with an indirection after the confined rename made the
        # read AND the delete hit an external attacker file, while the truly
        # moved claim stayed behind in the original physical directory.
        matched, claimed = confined_compare_and_delete(root, claim, judged)
        if matched:
            # The old owner's freshness record is dead with its node: takeover
            # discards it so the new owner's lease age derives from its own
            # acquisition (mtime fallback until its first refresh). The
            # discard is confined (a raced parent swap cannot redirect this
            # unlink outside the home) and best-effort: a refusal here is
            # delayed cleanup, never a lost claim.
            with _suppress_os_error():
                try:
                    confined_unlink(
                        root, node_rel.with_name(f".{self.path.name}.lease")
                    )
                except (OSError, PalError):
                    pass
            return True
        # The node changed between the verdict and the rename (or the claim was
        # no longer readable), so what we moved aside was somebody else's live
        # lock. Put it back if the slot is still empty; never overwrite whatever
        # took its place. Successor fencing is preserved: `confined_replace`
        # binds both ends to verified parents, so a lost takeover can neither
        # delete nor overwrite a successor's live lock.
        if not self.path.exists():
            with _suppress_os_error():
                try:
                    confined_replace(root, claim, node_rel)
                except OSError:
                    pass
        return False

    # -- lifecycle --------------------------------------------------------- #

    def acquire(self) -> bool:
        # TARGET 5 (T-125): explicit non-following final-node classification
        # so actual competing regular lock -> ordinary busy semantics, while
        # symlink/junction/reparse lock node -> PalError(PATH_ESCAPE).
        try:
            st = os.lstat(str(self.path))
            if stat.S_ISLNK(st.st_mode) or carries_reparse_attr(self.path):
                raise PalError(
                    "PATH_ESCAPE",
                    f"lock node {str(self.path)!r} is a symlink/junction/reparse point; "
                    "refusing to write through it",
                    next_action="SAIPAL writes only inside its own home",
                )
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise PalError(
                "PATH_ESCAPE",
                f"lock node {str(self.path)!r} cannot be stated: {exc}",
                next_action="SAIPAL writes only inside its own home",
            ) from exc

        # PAL-WRITE-01 (T-125, Defect B): the create goes through the confined
        # exclusive-create primitive under the confinement root, so the
        # physical parent is verified and bound at the fd level immediately
        # before the O_EXCL open -- a deterministic parent swap between the
        # final confinement check and os.open (auditor reproduction B) creates
        # the node beside the verified directory, never inside whatever
        # replaced the path.
        #
        # TARGET A (T-125): the lock's own parent directory is established
        # through the confinement primitive first, so the first lock of a
        # minimally initialized home is takeable while an indirection still
        # refuses with zero external mutation.
        self._establish_parent()
        root = self._confine_under or self.path.parent
        rel = _rel_inside(
            Path(root).resolve(), Path(os.path.abspath(str(self.path)))
        )
        try:
            confined_create_exclusive(root, rel, self._payload_bytes(uuid.uuid4().hex))
        except FileExistsError:
            descriptor_acquired = False
            for attempt in (0, 1):
                takeover = attempt == 0 and self._take_over_if_stale()
                self.stale_taken_over = self.stale_taken_over or takeover
                if takeover:
                    try:
                        confined_create_exclusive(
                            root, rel, self._payload_bytes(uuid.uuid4().hex)
                        )
                        descriptor_acquired = True
                        break
                    except FileExistsError:
                        continue
                break
        except OSError as exc:
            raise PalError(
                "WRITER_BUSY", f"cannot create lock {self.path.name}: {exc}"
            ) from exc
        else:
            descriptor_acquired = True
        if not descriptor_acquired:
            self.detail = self.busy_detail
            return False
        # The token is whatever the O_EXCL payload carried: re-derive it from
        # the node so the in-memory state can never drift from the disk.
        try:
            payload = json.loads(self.path.read_bytes().decode("utf-8-sig"))
            self.token = str(payload.get("owner") or "")
        except (OSError, ValueError):
            self.token = ""
        if not self.token:
            with _suppress_os_error():
                try:
                    confined_unlink(root, rel)
                except OSError:
                    pass
            self.detail = self.busy_detail
            return False
        self._held = True
        self.detail = "acquired"
        # Our acquisition owns the freshness surface from this moment: any
        # previous owner's sidecar record is discarded so lease age derives
        # from our own heartbeat cadence, never a ghost's.
        with _suppress_os_error():
            try:
                confined_unlink(
                    root,
                    rel.parent / f".{self.path.name}.lease",
                )
            except OSError:
                pass
        return True

    def owns_on_disk(self) -> bool:
        """Is the lock on disk still the one this instance acquired?"""
        if not self._held or self.token is None:
            return False
        state, payload, _raw = self._inspect()
        return state == _LOCK_OK and str((payload or {}).get("owner") or "") == self.token

    def refresh(self, ttl: float | None = None) -> bool:
        """Renew lease freshness WITHOUT rewriting the lock node (T-110).

        The lock node's owner payload is the fencing identity and is immutable
        once acquired. The old implementation re-wrote the node after an
        `owns_on_disk()` check, so a successor that took the path between the
        check and the destructive `O_TRUNC` write had its owner token destroyed
        -- the old owner stole the lease back (TOCTOU). Refresh therefore only:

        1. re-checks ownership (cheap early exit for the common case);
        2. writes the SIDEcar freshness record naming our token -- losing the
           path at worst delays or touches harmless metadata, it can never
           overwrite a successor's owner identity;
        3. re-reads ownership AFTER the touch and returns False if a successor
           has the node (the successor's takeover replaces/deletes the node and
           its own next acquisition refreshes the sidecar under its token).

        A dethroned owner's stale sidecar touch is ignored by staleness
        (`_lease_age_seconds` requires the record to name the current owner).

        False is reserved for an AFFIRMATIVE ownership read (absent node or a
        foreign owner). A transient unreadable node -- the same Windows sharing
        window `_unlink_lock` retries past -- is retried once, and a transient
        sidecar-write failure is retried inside `_write_lease_freshness` and
        then only degrades freshness: a healthy owner must not stop for
        filesystem noise, and a genuinely dethroned owner is still fenced by
        the next renewal's affirmative read plus the contender-side stale
        takeover.
        """
        if not self._held or self.token is None:
            return False
        if not self.owns_on_disk():
            # One retry past a transient unreadable node: False is proven only
            # when the read itself succeeds and names another owner (or the
            # node is gone).
            time.sleep(LOCK_UNLINK_DELAY_SECONDS)
            if not self.owns_on_disk():
                return False
        if ttl is not None:
            # refresh(ttl=...) must change the EFFECTIVE expiry threshold, not
            # merely a dead field (CONTROL-C): the sidecar record this method
            # writes is checked FIRST by `_effective_ttl`, so this write is what
            # a contender will judge the lease against. A ttl that fails strict
            # validation is refused loudly rather than silently ignored.
            validated = _valid_ttl(ttl)
            if validated is None:
                raise PalError(
                    "VALIDATION_FAILED",
                    f"refresh ttl={ttl!r} is not a finite positive bounded number "
                    f"(<= {LOCK_MAX_TTL_SECONDS}s)",
                )
            self.ttl = validated
        if not self._write_lease_freshness():
            # Delayed freshness, not proven loss: the node still names this
            # owner. One more attempt; after that ownership, not freshness,
            # decides the verdict.
            if not self._write_lease_freshness():
                return self.owns_on_disk()
        return self.owns_on_disk()

    def release(self) -> None:
        """Unlink the lock only while we still own it."""
        if not self._held:
            return
        token = self.token
        self._held = False
        self.token = None
        state, payload, _raw = self._inspect()
        if state == _LOCK_ABSENT:
            self.detail = "lock was already gone"
            return
        if state == _LOCK_UNREADABLE:
            # Our own torn write, or a successor mid-acquisition. Either way the
            # bytes do not prove ownership, and the create grace will recover it.
            self.detail = "lock is unreadable; left in place"
            return
        if str((payload or {}).get("owner") or "") != token:
            self.detail = "lock is owned by another run; left in place"
            return
        # PAL-WRITE-01 (T-125, Defect B): the release unlink goes through the
        # confined primitive under the confinement root, so a raced parent
        # swap cannot redirect the deletion outside. The retry-until-quiet
        # behavior of _unlink_lock is preserved: a transient sharing window
        # (Windows readers) is filesystem noise, not ownership truth.
        root = self._confine_under or self.path.parent
        rel = _rel_inside(Path(root).resolve(), Path(os.path.abspath(str(self.path))))
        if self._confined_unlink_with_retry(root, rel) or not self.path.exists():
            self.detail = "released"
            # Our own release: the freshness sidecar dies with the lease.
            with _suppress_os_error():
                try:
                    self._confined_unlink_with_retry(
                        root,
                        rel.parent / f".{self.path.name}.lease",
                    )
                except OSError:
                    pass
        else:
            # The file could not be removed (a contender holds it open). It is
            # still ours by content, so the create grace and TTL recover it; what
            # must not happen is a caller believing the slot is free.
            self.detail = "lock could not be removed; it will expire"

    def _confined_unlink_with_retry(
        self, root: Path, rel: Path
    ) -> bool:
        """confined_unlink with the transient sharing-window retry loop that
        `_unlink_lock` historically provided (Windows refuses to unlink a
        node another handle has open; a single attempt strands released
        locks). Confinement behavior is identical on every attempt.

        CORE-001 (SRC-010): a confined-unlink refusal is a REFUSED cleanup,
        never an exception out of `release`. If the home pathname was replaced
        while this lock was held, the identity gate refuses the unlink; the
        lock simply stays behind in its real physical home and ages out, which
        is the safe outcome -- the replacement home must receive no mutation."""
        for attempt in range(LOCK_UNLINK_ATTEMPTS):
            try:
                return confined_unlink(root, rel)
            except (OSError, PalError):
                if attempt == LOCK_UNLINK_ATTEMPTS - 1:
                    return not self.path.exists()
                time.sleep(LOCK_UNLINK_DELAY_SECONDS)
        return not self.path.exists()


class HomeLock:
    """One exclusive writer per home, with fenced stale takeover.

    A crash leaves a lock file behind. That lock is stale when its owner process
    is gone or when it has outlived the TTL, either of which lets the next run
    take over instead of wedging the home forever. `FencedLockFile` owns the
    mechanics; this class owns only where the file lives.
    """

    BUSY = "another SAIPAL run holds the home lock"

    def __init__(
        self,
        home: Path | str,
        *,
        ttl: float = LOCK_TTL_SECONDS,
        blocking: bool = False,
    ):
        self.paths = home_paths(home)
        self.ttl = ttl
        self.blocking = blocking
        # PAL-WRITE-01 (T-125): the home lock refuses a redirected locks dir
        # or a symlinked lock node outright.
        self._lock = FencedLockFile(
            self.paths.lock,
            ttl=ttl,
            busy_detail=self.BUSY,
            confine_under=self.paths.root,
        )

    @property
    def held(self) -> bool:
        return self._lock.held

    @property
    def detail(self) -> str:
        return self._lock.detail

    @property
    def stale_taken_over(self) -> bool:
        return self._lock.stale_taken_over

    def acquire(self) -> bool:
        # TARGET A (T-125): the writer fence owns the SAFE bootstrap. The CLI
        # takes this fence BEFORE `ensure_home` runs, so a missing home or a
        # minimally initialized home (config.json only, no locks/) used to
        # deadlock. Only the minimum surface required to take the FIRST lock
        # is established here -- the home root and locks/ -- through the
        # confinement primitives; an indirection refuses with zero external
        # mutation. `ensure_home` still owns the full layout.
        establish_lock_surface(self.paths.root)
        return self._lock.acquire()

    def release(self) -> None:
        self._lock.release()

    def __enter__(self) -> HomeLock:
        if not self.acquire():
            raise PalError(
                "WRITER_BUSY",
                self.detail,
                next_action="wait for the running cycle, or remove a wedged lock by hand",
            )
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.release()
        return False


# --------------------------------------------------------------------------- #
# CORE-001: one common writer fence for every mutation of shared .saipal state
# --------------------------------------------------------------------------- #

#: Reentrancy guard for the common writer fence (audit CORE-001).
#:
#: The OS-level FencedLockFile already refuses a second acquirer from ANY
#: process; the one hazard it cannot see is the SAME THREAD nesting a second
#: acquisition of the same node (lock files are not reentrant). Intake callers
#: legitimately arrive already holding HomeLock, so the shared session-index
#: transactions below must not deadlock against them. The depth is tracked
#: PER THREAD: the owning thread reenters freely, while any other thread --
#: even in this process -- must take the real file fence or fail WRITER_BUSY,
#: exactly like a foreign process.
_WRITER_FENCE_DEPTH: dict[tuple[str, int], int] = {}


class WriterFence:
    """The common mutation lease over one home's shared durable state.

    CORE-001 proved the durable data loss: the analyst worker called
    `submit_candidate` with NO writer lock while a concurrent HomeLock-protected
    `continue` imported a new generation; the worker's stale index save then
    erased the intake. One shared mutation lease now covers every transaction
    that touches shared state -- submit, intake, rebind, analyst config --
    while paid model/network reasoning stays OUTSIDE it.

    Semantics:

    - Cross-process: the underlying HomeLock/FencedLockFile fence. A second
      process either serializes behind it or fails WRITER_BUSY.
    - Same-process: reentrant via a depth counter, so HomeLock callers can
      drive shared transactions without deadlocking (nested acquisition of
      the same node is what the file lock cannot express).
    - Stale-save defense: when the holder of the OUTER process fence is a
      long-lived section (a whole watch cycle), inner transactions verify at
      commit time that the session index was not replaced under them and
      re-merge instead of blindly overwriting (see
      `saipal_engine.submit.submit_candidate`).
    """

    def __init__(self, home: Path | str):
        self.paths = home_paths(home)
        self._home = Path(home)
        self._lock: HomeLock | None = None
        self._depth = 0
        self._thread_key: tuple[str, int] | None = None
        #: CORE-001 (SRC-010): the physical home identity the OUTER acquisition
        #: bound, retained for this fence's whole lifetime.
        self._identity: tuple[int, int] | None = None

    def acquire(self) -> bool:
        key = (str(self.paths.lock), threading.get_ident())
        depth = _WRITER_FENCE_DEPTH.get(key, 0)
        if depth > 0:
            # CORE-001 (SRC-010): lexical pathname equality is NOT proof of
            # reentrancy. The active fence must still protect the SAME physical
            # directory before a nested acquisition is granted; after a
            # rename-and-replace of the home this refuses instead of reentering
            # into the replacement. An identity the platform cannot supply
            # (None) keeps the historical lexical reentrancy, since there is
            # nothing stronger to prove it with on that platform.
            active_key = (_fence_root_key(self._home), threading.get_ident())
            bound = _ACTIVE_FENCE_IDENTITY.get(active_key)
            if bound is not None and _physical_dir_identity(self._home) != bound:
                raise PalError(
                    "PATH_ESCAPE",
                    f"home {str(self._home)!r} no longer names the physical "
                    "directory this writer fence acquired; refusing to reenter "
                    "a replacement home",
                    next_action="restart the transaction against the current home",
                )
            _WRITER_FENCE_DEPTH[key] = depth + 1
            self._depth = depth + 1
            self._thread_key = key
            return True
        lock = HomeLock(self._home)
        if not lock.acquire():
            return False
        self._lock = lock
        self._depth = 1
        self._thread_key = key
        _WRITER_FENCE_DEPTH[key] = 1
        # Bind the physical home the real lock protects for the fence lifetime.
        self._identity = _physical_dir_identity(self._home)
        _ACTIVE_FENCE_IDENTITY[(_fence_root_key(self._home), threading.get_ident())] = (
            self._identity
        )
        return True

    def release(self) -> None:
        key = self._thread_key or (str(self.paths.lock), threading.get_ident())
        depth = _WRITER_FENCE_DEPTH.get(key, 0)
        if depth <= 1:
            _WRITER_FENCE_DEPTH.pop(key, None)
            active_key = (
                _fence_root_key(self._home),
                threading.get_ident(),
            )
            _ACTIVE_FENCE_IDENTITY.pop(active_key, None)
            if self._lock is not None:
                self._lock.release()
                self._lock = None
            self._depth = 0
            self._thread_key = None
            self._identity = None
        else:
            _WRITER_FENCE_DEPTH[key] = depth - 1
            self._depth = depth - 1

    def __enter__(self) -> "WriterFence":
        if not self.acquire():
            raise PalError(
                "WRITER_BUSY",
                HomeLock.BUSY,
                next_action="wait for the running cycle, or remove a wedged lock by hand",
            )
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.release()
        return False


def writer_fence(home: Path | str) -> WriterFence:
    """Acquire the common writer fence for one mutating transaction."""
    return WriterFence(home)
