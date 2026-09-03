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

FINDINGS_DIR = "findings"
FINDINGS_CANDIDATES_DIR = "findings/candidates"
FINDINGS_EMITTED_DIR = "findings/emitted"
FINDINGS_INDEX_NAME = "findings/index.json"

AUDIT_STAGING_DIR = "audit/staging"
AUDIT_LEDGER_NAME = "audit/ledger.json"
AUDIT_LEASE_NAME = "audit/lease.json"

RECURRENCE_NAME = "recurrence.json"
TELEMETRY_NAME = "telemetry.json"


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


class HomeLock:
    """One exclusive writer per home, with stale takeover.

    A crash leaves a lock file behind. That lock is stale when its owner pid is
    gone or when it has outlived the TTL, either of which lets the next run take
    over instead of wedging the home forever.
    """

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
        self.stale_taken_over = False
        self.detail = ""
        self._held = False

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

    def acquire(self) -> bool:
        self.paths.locks.mkdir(parents=True, exist_ok=True)
        for attempt in (0, 1):
            try:
                descriptor = os.open(
                    str(self.paths.lock),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                takeover = attempt == 0 and self._take_over_if_stale()
                self.stale_taken_over = self.stale_taken_over or takeover
                if takeover:
                    continue
                self.detail = "another SAIPAL run holds the home lock"
                return False
            except OSError as exc:
                raise PalError("WRITER_BUSY", f"cannot create home lock: {exc}") from exc
            try:
                os.write(descriptor, self._payload())
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._held = True
            self.detail = "acquired"
            return True
        self.detail = "another SAIPAL run holds the home lock"
        return False

    def _take_over_if_stale(self) -> bool:
        try:
            with open(str(self.paths.lock), "rb") as handle:
                raw = handle.read()
            payload = json.loads(raw.decode("utf-8-sig"))
            age = time.time() - float(payload.get("created_at", 0))
            pid = int(payload.get("pid", 0))
        except (OSError, ValueError, TypeError, KeyError):
            age, pid = self.ttl + 1, 0
        if _pid_alive(pid) and age < self.ttl:
            return False
        with _suppress_os_error():
            os.unlink(str(self.paths.lock))
            return True
        return False

    def release(self) -> None:
        if not self._held:
            return
        with _suppress_os_error():
            os.unlink(str(self.paths.lock))
        self._held = False

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
