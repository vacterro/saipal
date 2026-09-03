"""Hardening for SAIPAL Wave I.

Context budget, safety valves, concurrency leases, atomic telemetry.
"""

from __future__ import annotations

import json
import os
import socket
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .capability import require_action
from .errors import PalError
from .paths import atomic_write_json, home_paths, read_json


@dataclass
class Budget:
    max_sessions: int = 50
    max_events: int = 5000
    max_candidates: int = 100
    max_context_bytes: int = 262144
    time_limit_seconds: float = 3600
    max_audits: int = 10


def check_budget(
    context: dict, *, budget: Budget | None = None
) -> tuple[bool, str]:
    cap = budget or Budget()
    if not isinstance(context, dict):
        return False, "context is not an object"

    sessions = context.get("sessions")
    if isinstance(sessions, list) and len(sessions) > cap.max_sessions:
        return False, f"sessions {len(sessions)} exceeds budget {cap.max_sessions}"

    events = context.get("events")
    if isinstance(events, list) and len(events) > cap.max_events:
        return False, f"events {len(events)} exceeds budget {cap.max_events}"

    candidates = context.get("candidates")
    if isinstance(candidates, list) and len(candidates) > cap.max_candidates:
        return False, f"candidates {len(candidates)} exceeds budget {cap.max_candidates}"

    raw_bytes = context.get("context_bytes")
    if isinstance(raw_bytes, int) and raw_bytes > cap.max_context_bytes:
        return False, f"context_bytes {raw_bytes} exceeds budget {cap.max_context_bytes}"

    return True, ""


@dataclass
class SafetyValve:
    max_cycles: int = 100
    time_limit_seconds: float = 3600
    max_audits_per_cycle: int = 10


def check_safety_valves(
    safety: SafetyValve,
    cycle_count: int,
    elapsed: float,
    audits_emitted: int,
) -> tuple[bool, str]:
    if cycle_count > safety.max_cycles:
        return False, f"cycle_count {cycle_count} exceeds max_cycles {safety.max_cycles}"
    if elapsed > safety.time_limit_seconds:
        return (
            False,
            f"elapsed {elapsed}s exceeds time_limit_seconds {safety.time_limit_seconds}",
        )
    if audits_emitted > safety.max_audits_per_cycle:
        return (
            False,
            f"audits_emitted {audits_emitted} exceeds max_audits_per_cycle "
            f"{safety.max_audits_per_cycle}",
        )
    return True, ""


def _pid_alive(pid: int) -> bool:
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


class SessionLease:
    def __init__(self, home: Path | str, session_id: str, *, ttl: float = 300):
        self.paths = home_paths(home)
        self.session_id = str(session_id)
        self.ttl = float(ttl)
        self.path = self.paths.locks / f"lease-{self.session_id}.json"
        self._held = False

    @property
    def held(self) -> bool:
        return self._held

    def _payload(self, *, ttl: float) -> dict[str, Any]:
        return {
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "created_at": time.time(),
            "owner": uuid.uuid4().hex,
            "ttl": float(ttl),
        }

    def _read(self) -> dict | None:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError:
            return None
        try:
            payload = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, ValueError):
            return None
        return payload if isinstance(payload, dict) else None

    def _stale(self, payload: dict) -> bool:
        try:
            pid = int(payload.get("pid", 0))
            age = time.time() - float(payload.get("created_at", 0))
            ttl = float(payload.get("ttl", self.ttl))
        except (TypeError, ValueError):
            return True
        if age >= ttl:
            return True
        return not _pid_alive(pid)

    def acquire(self, home: Path | str | None = None, session_id: str | None = None, ttl: float | None = None) -> bool:
        if home is not None:
            self.paths = home_paths(home)
            self.session_id = str(session_id or self.session_id)
            self.path = self.paths.locks / f"lease-{self.session_id}.json"
        if ttl is not None:
            self.ttl = float(ttl)
        self.paths.locks.mkdir(parents=True, exist_ok=True)
        existing = self._read()
        if existing is not None and not self._stale(existing):
            return False
        if existing is not None:
            with _suppress_os_error():
                os.unlink(str(self.path))
        data = json.dumps(self._payload(ttl=self.ttl), sort_keys=True).encode("utf-8")
        try:
            descriptor = os.open(
                str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
        except FileExistsError:
            return False
        except OSError as exc:
            raise PalError("WRITER_BUSY", f"cannot create session lease: {exc}") from exc
        try:
            os.write(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._held = True
        return True

    def release(self) -> None:
        if not self._held:
            return
        with _suppress_os_error():
            os.unlink(str(self.path))
        self._held = False

    def is_expired(self) -> bool:
        payload = self._read()
        if payload is None:
            return True
        return self._stale(payload)

    def refresh(self, ttl: float = 300) -> bool:
        if not self._held:
            return False
        self.ttl = float(ttl)
        data = json.dumps(self._payload(ttl=self.ttl), sort_keys=True).encode("utf-8")
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


def init() -> dict:
    return {
        "sessions_analyzed": 0,
        "events_analyzed": 0,
        "bytes_loaded": 0,
        "rule_bytes_loaded": 0,
        "findings_created": 0,
        "findings_rejected": 0,
        "audits_emitted": 0,
        "avg_context_per_episode": 0.0,
    }


def increment(telemetry: dict, key: str, amount: int = 1) -> dict:
    if not isinstance(telemetry, dict):
        telemetry = init()
    current = telemetry.get(key, 0)
    if isinstance(current, (int, float)) and not isinstance(current, bool):
        telemetry[key] = current + amount
    else:
        telemetry[key] = amount
    return telemetry


def record_context(
    telemetry: dict, episode_count: int, context_bytes: int
) -> dict:
    if not isinstance(telemetry, dict):
        telemetry = init()
    telemetry["avg_context_per_episode"] = (
        float(context_bytes) / float(episode_count)
        if episode_count > 0
        else 0.0
    )
    return telemetry


def load_telemetry(home: Path | str) -> dict:
    paths = home_paths(home)
    if not paths.telemetry.exists():
        return init()
    try:
        payload = read_json(paths.telemetry)
    except (OSError, ValueError, UnicodeDecodeError):
        return init()
    return payload if isinstance(payload, dict) else init()


def save_telemetry(home: Path | str, telemetry: dict) -> dict:
    require_action("write_own_cache")
    payload = telemetry if isinstance(telemetry, dict) else init()
    paths = home_paths(home)
    atomic_write_json(paths.telemetry, payload, root=paths.root)
    return payload


class _SuppressOsError:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, exc, tb) -> bool:
        return exc_type is not None and issubclass(exc_type, OSError)


def _suppress_os_error() -> _SuppressOsError:
    return _SuppressOsError()
