"""T-106 shared operational clock: wall/monotonic/sleep in one place.

Supervisor schedules, budget windows and circuit breakers all need time, but
each module previously reached for time.time() itself, so a test that wanted
to advance an hour had to inject `now=` into every call site. One abstraction
owns the three operations; operational scheduling uses it, forensic
timestamps keep their own (never rewritten) surfaces. All long-run tests use
a fake logical clock -- no real sleeps, ever.
"""

from __future__ import annotations

import time
from typing import Callable


class OperationalClock:
    """wall_now / monotonic_now / sleep for operational scheduling only."""

    __slots__ = ("_wall", "_monotonic", "_sleep", "_offset")

    def __init__(
        self,
        *,
        wall: Callable[[], float] | None = None,
        monotonic: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._wall = wall if wall is not None else time.time
        self._monotonic = monotonic if monotonic is not None else time.monotonic
        self._sleep = sleep if sleep is not None else time.sleep
        self._offset = 0.0

    def wall_now(self) -> float:
        return float(self._wall()) + self._offset

    def monotonic_now(self) -> float:
        return float(self._monotonic()) + self._offset

    def sleep(self, seconds: float) -> None:
        if seconds <= 0:
            return
        self._sleep(seconds)

    def advance(self, seconds: float) -> float:
        """Advance the logical clock by `seconds` (fake-time test control)."""
        self._offset += float(seconds)
        return self._offset


class FrozenClock(OperationalClock):
    """A logical clock that never moves unless advanced or slept: tests zero."""

    __slots__ = ("_virtual",)

    def __init__(self, start: float = 1_000_000.0) -> None:
        super().__init__(wall=lambda: 0.0, monotonic=lambda: 0.0, sleep=None)
        self._virtual = float(start)
        # FrozenClock owns its sleep: sleeping a logical duration ADVANCES the
        # logical clock instead of waiting (ROLE 35: soak time must advance).
        super().__setattr__("_sleep", self._advance_sleep)

    def _advance_sleep(self, seconds: float) -> None:
        if seconds > 0:
            self.advance(seconds)

    def wall_now(self) -> float:
        return self._virtual + self._offset

    def monotonic_now(self) -> float:
        return self._virtual + self._offset
