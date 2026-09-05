"""Home resolution, guarded atomic writes and the home lock boundary.

Everything SAIPAL writes lives under one home. This module is the only place
that turns a path into bytes on disk, and it refuses anything that resolves
outside the home it was given.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
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


def atomic_write_bytes(path: Path | str, data: bytes, *, root: Path | str) -> Path:
    """Write `data` into the home atomically, or raise.

    Refuses a symlinked or non-regular final node, writes to a uniquely named
    temporary in the SAME directory so the rename cannot cross a mount, and
    only then replaces the target.
    """
    resolved = prove_inside(root, path)
    parent = resolved.parent
    parent.mkdir(parents=True, exist_ok=True)

    if resolved.is_symlink():
        raise PalError(
            "PATH_ESCAPE",
            f"path {str(resolved)!r} is a symlink; refusing to write through it",
        )
    if resolved.exists() and not resolved.is_file():
        raise PalError(
            "PATH_ESCAPE",
            f"path {str(resolved)!r} is not a regular file; refusing to replace it",
        )

    tmp_path = parent / f".{resolved.name}.{uuid.uuid4().hex}.tmp"
    binary = getattr(os, "O_BINARY", 0)
    descriptor = os.open(
        str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary, 0o600
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write to home file descriptor")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        with _suppress_os_error():
            os.close(descriptor)
        with _suppress_os_error():
            os.unlink(str(tmp_path))
        raise
    os.close(descriptor)
    os.replace(str(tmp_path), str(resolved))
    return resolved


def atomic_write_json(path: Path | str, payload: object, *, root: Path | str) -> Path:
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
    return atomic_write_bytes(path, (text + "\n").encode("utf-8"), root=root)


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
    ):
        self.path = Path(path)
        self.ttl = float(ttl)
        self.grace = float(grace)
        self.busy_detail = busy_detail
        self.token: str | None = None
        self.stale_taken_over = False
        self.detail = ""
        self._held = False

    @property
    def held(self) -> bool:
        return self._held

    # -- payload ----------------------------------------------------------- #

    def _payload_bytes(self, token: str, extra: dict | None = None) -> bytes:
        payload = {
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "created_at": time.time(),
            "owner": token,
        }
        payload.update(extra or {})
        return (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")

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
        try:
            return max(0.0, time.time() - self.path.stat().st_mtime)
        except OSError:
            return self.grace + 1.0

    # -- staleness --------------------------------------------------------- #

    def _payload_is_stale(self, payload: dict) -> bool:
        try:
            pid = int(payload.get("pid", 0))
            age = time.time() - float(payload.get("created_at", 0))
            ttl = float(payload.get("ttl", self.ttl))
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
        return age >= ttl

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
        claim = self.path.parent / f".{self.path.name}.contested.{uuid.uuid4().hex}"
        try:
            os.replace(str(self.path), str(claim))
        except OSError:
            # Either somebody else claimed it first, or a contender still holds
            # the node open. Both mean "not ours"; nothing was destroyed.
            return False
        try:
            claimed = claim.read_bytes()
        except OSError:
            claimed = b""
        if claimed == judged:
            _unlink_lock(claim)
            return True
        # The node changed between the verdict and the rename, so what we moved
        # aside was somebody else's live lock. Put it back if the slot is still
        # empty; never overwrite whatever took its place.
        if not self.path.exists():
            with _suppress_os_error():
                os.replace(str(claim), str(self.path))
        return False

    # -- lifecycle --------------------------------------------------------- #

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for attempt in (0, 1):
            token = uuid.uuid4().hex
            try:
                descriptor = os.open(
                    str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
            except FileExistsError:
                takeover = attempt == 0 and self._take_over_if_stale()
                self.stale_taken_over = self.stale_taken_over or takeover
                if takeover:
                    continue
                self.detail = self.busy_detail
                return False
            except OSError as exc:
                raise PalError(
                    "WRITER_BUSY", f"cannot create lock {self.path.name}: {exc}"
                ) from exc
            try:
                os.write(descriptor, self._payload_bytes(token))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self.token = token
            self._held = True
            self.detail = "acquired"
            return True
        self.detail = self.busy_detail
        return False

    def owns_on_disk(self) -> bool:
        """Is the lock on disk still the one this instance acquired?"""
        if not self._held or self.token is None:
            return False
        state, payload, _raw = self._inspect()
        return state == _LOCK_OK and str((payload or {}).get("owner") or "") == self.token

    def refresh(self, ttl: float | None = None) -> bool:
        """Rewrite our own payload, keeping the SAME token.

        A refresh that mints a new owner throws away the only thing that makes
        release safe, so the token is preserved and a lock we no longer own is
        refused rather than stolen back.
        """
        if not self._held or self.token is None:
            return False
        if not self.owns_on_disk():
            return False
        if ttl is not None:
            self.ttl = float(ttl)
        data = self._payload_bytes(self.token, {"ttl": self.ttl})
        try:
            descriptor = os.open(str(self.path), os.O_WRONLY | os.O_TRUNC, 0o600)
        except OSError:
            return False
        try:
            os.write(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return True

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
        if _unlink_lock(self.path):
            self.detail = "released"
        else:
            # The file could not be removed (a contender holds it open). It is
            # still ours by content, so the create grace and TTL recover it; what
            # must not happen is a caller believing the slot is free.
            self.detail = "lock could not be removed; it will expire"


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
        self._lock = FencedLockFile(self.paths.lock, ttl=ttl, busy_detail=self.BUSY)

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
