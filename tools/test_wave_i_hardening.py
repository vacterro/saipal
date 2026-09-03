"""Wave I acceptance bar: hardening.

Context budget, safety valves, session leases, telemetry, and the
`analyze_sessions` idempotency contract: a second pass over an exhausted
session index must do zero new work.
"""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import bundle as bundle_mod
from saipal_engine import hardening as hard
from saipal_engine import sessions as sessions_mod
from saipal_engine.pipeline import analyze_sessions

COLD = "conformant-cold.json"


class HardeningBudget(unittest.TestCase):
    def test_budget_defaults(self) -> None:
        budget = hard.Budget()
        self.assertGreater(budget.max_sessions, 0)
        self.assertGreater(budget.max_events, 0)
        self.assertGreater(budget.max_candidates, 0)
        self.assertGreater(budget.max_context_bytes, 0)

    def test_check_budget_trips(self) -> None:
        budget = hard.Budget(max_events=10, max_sessions=2,
                             max_candidates=3, max_context_bytes=100)
        ok, _ = hard.check_budget({"events": [1, 2]}, budget=budget)
        self.assertTrue(ok)
        bad, reason = hard.check_budget(
            {"events": list(range(20))}, budget=budget,
        )
        self.assertFalse(bad)
        self.assertIn("exceeds budget", reason)

        bad_ctx, reason_ctx = hard.check_budget(
            {"context_bytes": 10_000}, budget=budget,
        )
        self.assertFalse(bad_ctx)
        self.assertIn("context_bytes", reason_ctx)


class SafetyValves(unittest.TestCase):
    def test_safety_valves(self) -> None:
        ok, _ = hard.check_safety_valves(
            hard.SafetyValve(max_cycles=1), cycle_count=1,
            elapsed=0, audits_emitted=0,
        )
        self.assertTrue(ok)
        bad, reason = hard.check_safety_valves(
            hard.SafetyValve(max_cycles=1), cycle_count=2,
            elapsed=0, audits_emitted=0,
        )
        self.assertFalse(bad)
        self.assertIn("cycle_count", reason)

        bad_time, reason_time = hard.check_safety_valves(
            hard.SafetyValve(time_limit_seconds=10), cycle_count=1,
            elapsed=20, audits_emitted=0,
        )
        self.assertFalse(bad_time)
        self.assertIn("elapsed", reason_time)

        bad_aud, reason_aud = hard.check_safety_valves(
            hard.SafetyValve(max_audits_per_cycle=1), cycle_count=1,
            elapsed=0, audits_emitted=5,
        )
        self.assertFalse(bad_aud)
        self.assertIn("audits_emitted", reason_aud)


class SessionLease(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_session_lease_acquire_release(self) -> None:
        lease = hard.SessionLease(self.home, "sess-A")
        self.assertTrue(lease.acquire())
        self.assertTrue(lease.held)
        # second acquire while held must fail
        self.assertFalse(lease.acquire())
        # release, re-acquire works again
        lease.release()
        self.assertFalse(lease.held)
        self.assertTrue(lease.acquire())
        lease.release()

    def test_lease_stale_takeover(self) -> None:
        session_id = "sess-stale"
        locks = self.home / "locks"
        locks.mkdir(parents=True, exist_ok=True)
        lease_path = locks / f"lease-{session_id}.json"
        # dead pid + ancient timestamp => stale on every ttl
        lease_path.write_text(
            json.dumps(
                {
                    "pid": 9_999_999,
                    "host": "nowhere",
                    "created_at": time.time() - 99_999,
                    "owner": "dead",
                    "ttl": 300,
                }
            ),
            encoding="utf-8",
        )
        lease = hard.SessionLease(self.home, session_id)
        self.assertTrue(
            lease.acquire(),
            "a stale lease must be stealable by a fresh acquire",
        )
        self.assertTrue(lease.held)
        lease.release()


class TelemetryPersistence(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_telemetry_persists(self) -> None:
        telemetry = hard.load_telemetry(self.home)
        # unknown key starts at 0, but increment must work and survive
        hard.increment(telemetry, "sessions_analyzed", amount=7)
        hard.increment(telemetry, "events_analyzed", amount=42)
        hard.save_telemetry(self.home, telemetry)

        reloaded = hard.load_telemetry(self.home)
        self.assertEqual(reloaded["sessions_analyzed"], 7)
        self.assertEqual(reloaded["events_analyzed"], 42)


class AnalyzeIdempotent(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_long_backlog_resumes(self) -> None:
        """A second analyze_sessions over an exhausted index must be a no-op.

        `continue` already analyzed this import, so the first explicit run
        here also finds nothing to do. Reset the per-record `analysis` flag
        to simulate a fresh import, then prove the second run is idempotent.
        """
        support.put_inbox(self.home, COLD)
        support.run_saipal("continue", home=self.home)

        status, index, _detail = sessions_mod.load_index(self.home)
        self.assertEqual(status, "ok")
        assert index is not None
        self.assertGreater(len(index["sessions"]), 0)
        # wipe per-record analysis so the first explicit run does the work
        for record in index["sessions"]:
            record.pop("analysis", None)
            record["last_analyzed_seq"] = 0
        sessions_mod.save_index(self.home, index)

        first = analyze_sessions(self.home, index)
        self.assertGreaterEqual(first["sessions_analyzed"], 1)
        self.assertTrue(
            index["sessions"][0].get("analysis", {}).get("episodes_exhausted"),
            "first run must mark the session as exhausted",
        )

        second = analyze_sessions(self.home, index)
        self.assertEqual(
            second["sessions_analyzed"], 0,
            "the second run over an exhausted backlog must analyze zero sessions",
        )
        self.assertEqual(second["events_analyzed"], 0)


if __name__ == "__main__":
    unittest.main()
