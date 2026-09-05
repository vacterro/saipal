"""Hardening for SAIPAL Wave I.

Context budget, safety valves, concurrency leases, atomic telemetry.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .capability import require_action
from .paths import (
    FencedLockFile,
    atomic_write_json,
    home_paths,
    read_json,
    sha256_text,
)


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


class SessionLease:
    """One analyzer per session, over the shared fenced lock primitive.

    Ownership, staleness and takeover are `FencedLockFile`'s (audit W2-001); this
    class owns where the lease file lives and when it is released.

    The filename is a digest of the session id, never the id itself (audit
    CORE-004). A session id is external provider data: `foo/bar` is a valid
    identifier and used to turn into a path, so a schema-valid bundle crashed the
    primary analysis path. Hashing also sidesteps Windows reserved names, length
    limits and case-insensitive aliasing in one step; sanitizing a few characters
    would not.
    """

    def __init__(self, home: Path | str, session_id: str, *, ttl: float = 300):
        self.paths = home_paths(home)
        self.session_id = str(session_id)
        self.ttl = float(ttl)
        self.path = self.paths.locks / self._lease_name(self.session_id)
        self._lock = self._new_lock()

    @staticmethod
    def _lease_name(session_id: str) -> str:
        """A flat, filesystem-safe, collision-free name for any session id."""
        return f"lease-{sha256_text(str(session_id))}.json"

    def _new_lock(self) -> FencedLockFile:
        return FencedLockFile(
            self.path,
            ttl=self.ttl,
            busy_detail=f"another cycle holds the lease for session {self.session_id!r}",
        )

    @property
    def held(self) -> bool:
        return self._lock.held

    @property
    def token(self) -> str | None:
        return self._lock.token

    def acquire(
        self,
        home: Path | str | None = None,
        session_id: str | None = None,
        ttl: float | None = None,
    ) -> bool:
        if home is not None:
            self.paths = home_paths(home)
            self.session_id = str(session_id or self.session_id)
        if ttl is not None:
            self.ttl = float(ttl)
        self.path = self.paths.locks / self._lease_name(self.session_id)
        if not self._lock.held:
            self._lock = self._new_lock()
        elif self._lock.path != self.path:
            # Re-targeting a held lease would abandon the old lock file with no
            # owner able to release it.
            return False
        return self._lock.acquire()

    def release(self) -> None:
        self._lock.release()

    def is_expired(self) -> bool:
        stale, _raw = self._lock._stale_now()
        return stale

    def refresh(self, ttl: float = 300) -> bool:
        return self._lock.refresh(ttl)

    def __enter__(self) -> SessionLease:
        """Held-lease regions use `with`, so every exit releases exactly once.

        Manually balancing `release()` across each `return`/`continue`/raise is
        how the missing-bundle path leaked a lease and blocked its session until
        stale recovery (audit CORE-004). Entering assumes the caller already
        acquired: acquisition can legitimately fail, and a context manager that
        raised on contention would turn a normal skip into an exception.
        """
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.release()
        return False


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
