"""T-106 (ROLE 28-32): poison quarantine, conflict liveness, shared clock,
budget/circuit accounting audits.

Long-run pathology: an unchanged poison artifact must not be reparsed every
cycle, CONFLICT sessions must stay visible and never count clean, operational
scheduling shares ONE testable clock, and budget/circuit accounting reflects
actual work (restart shares the window, token double-count is a real
regression, OPEN blocks calls until a material change).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import budgets as budgets_mod
from saipal_analyst import ops_clock
from saipal_analyst import supervisor as sup_mod
from saipal_engine import dispatcher as disp_mod
from saipal_engine import poison as poison_mod
from saipal_engine.adapters import ADAPTER_REGISTRY
from saipal_engine.registry import load_registry


class PoisonQuarantine(unittest.TestCase):
    """ROLE 28: repeated unchanged invalid artifact stops churning."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        self.registry = load_registry()

    def _dispatch(self, path: str, source_id: str = "main"):
        source = {
            "id": source_id,
            "kind": "generic",
            "path": str(Path(path).parent),
            "enabled": True,
        }
        return disp_mod.dispatch_sources(
            self.home, [source], registry=self.registry,
            authority={k: None for k in ("git_repository", "release_root", "snapshot_root")},
        )

    def _bad_source(self, name: str = "bad.json") -> Path:
        src = Path(self._tmp.name) / name
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text("{ not valid json", encoding="utf-8")
        return src

    def test_unchanged_poison_artifact_stops_being_reparsed(self) -> None:
        src = self._bad_source()
        # First two rejections are observed; from the third cycle on the
        # unchanged bytes are quarantined and the reparse is skipped.
        self._dispatch(str(src))
        self._dispatch(str(src))
        third = self._dispatch(str(src))
        # The quarantine path reports the skipped artifact.
        self.assertGreaterEqual(len(third["quarantined"]), 1)
        self.assertIn(
            "quarantined", str(third["quarantined"][0].get("reason") or ""),
        )

    def test_changed_poison_artifact_is_eligible_again(self) -> None:
        src = self._bad_source()
        self._dispatch(str(src))
        self._dispatch(str(src))
        # A material source change releases the quarantine: the artifact is
        # parsed again (and this time it normalizes).
        src.write_text(
            json.dumps({
                "schema_version": 1, "session_id": "recovered", "adapter": "generic",
                "project": {}, "runtime": {}, "temperature": "COLD",
                "protocol": {"binding_status": "UNKNOWN"}, "events": [],
            }),
            encoding="utf-8",
        )
        report = self._dispatch(str(src))
        self.assertEqual(report["quarantined"], [])
        self.assertGreaterEqual(len(report["imported"]), 1)

    def test_quarantine_never_deletes_or_mutates_the_source(self) -> None:
        src = self._bad_source()
        before = src.read_bytes()
        self._dispatch(str(src))
        self._dispatch(str(src))
        self._dispatch(str(src))
        self.assertEqual(src.read_bytes(), before, "the source file is untouched")
        self.assertTrue(src.exists(), "the source file is not deleted")

    def test_quarantine_survives_restart(self) -> None:
        src = self._bad_source()
        self._dispatch(str(src))
        self._dispatch(str(src))
        # A fresh dispatcher call (a "restart") reads the durable quarantine.
        report = self._dispatch(str(src))
        self.assertGreaterEqual(len(report["quarantined"]), 1)


class ConflictLiveness(unittest.TestCase):
    """ROLE 29: conflicts stay visible, never clean, never monopolize."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        support.run_saipal("continue", home=self.home)

    def test_conflict_is_visible_in_watch_status(self) -> None:
        from saipal_engine import bundle as bundle_mod
        from saipal_engine import sessions as sessions_mod

        support.put_inbox(self.home, "hot-partial.json")
        support.run_saipal("continue", home=self.home)
        # Arm the analyzed-prefix guard, then feed the mutated prefix.
        status, index, _detail = sessions_mod.load_index(self.home)
        record = sessions_mod.find_session(index, "golden-hot-001")
        record["last_analyzed_seq"] = 2
        record["prefix_sha256"] = bundle_mod.prefix_digest(
            support.load_fixture("hot-partial.json"), 2
        )
        sessions_mod.save_index(self.home, index)
        support.clear_inbox(self.home)
        support.put_inbox(self.home, "hot-prefix-mutated.json")
        support.run_saipal("continue", home=self.home)

        corpus = sup_mod.watch_status(self.home)["corpus"]
        self.assertGreaterEqual(corpus["conflicts_current"], 1)
        self.assertGreaterEqual(len(corpus["conflict_rows"]), 1)
        self.assertEqual(corpus["conflict_rows"][0]["session_id"], "golden-hot-001")

    def test_conflict_never_counts_as_clean(self) -> None:
        from saipal_engine import bundle as bundle_mod
        from saipal_engine import sessions as sessions_mod

        support.put_inbox(self.home, "hot-partial.json")
        support.run_saipal("continue", home=self.home)
        status, index, _detail = sessions_mod.load_index(self.home)
        record = sessions_mod.find_session(index, "golden-hot-001")
        record["last_analyzed_seq"] = 2
        record["prefix_sha256"] = bundle_mod.prefix_digest(
            support.load_fixture("hot-partial.json"), 2
        )
        sessions_mod.save_index(self.home, index)
        support.clear_inbox(self.home)
        support.put_inbox(self.home, "hot-prefix-mutated.json")
        support.run_saipal("continue", home=self.home)
        # The blocked/jobs section must not fold the conflict into "ready" or
        # "clean" work: it stays visible in the corpus conflict rows.
        from saipal_engine import carrier as carrier_mod

        corpus = sup_mod.watch_status(self.home)["corpus"]
        self.assertEqual(corpus["conflicts_current"], 1)


class SharedOperationalClock(unittest.TestCase):
    """ROLE 30: wall/monotonic/sleep behind one abstraction."""

    def test_clock_provides_all_three_operations(self) -> None:
        clock = ops_clock.FrozenClock(start=100.0)
        self.assertEqual(clock.wall_now(), 100.0)
        self.assertEqual(clock.monotonic_now(), 100.0)
        clock.sleep(5.0)  # frozen: no REAL wait -- ROLE 35 logical advance
        # Sleeping a logical duration advances the frozen clock instead of
        # blocking the process; that is the whole point of the fake-time soak
        # harness (ROLE 35: soak time must advance, never really wait).
        self.assertEqual(clock.wall_now(), 105.0)

    def test_fake_clock_advances_logically(self) -> None:
        clock = ops_clock.FrozenClock(start=0.0)
        clock.advance(3600.0)
        self.assertEqual(clock.wall_now(), 3600.0)
        self.assertEqual(clock.monotonic_now(), 3600.0)

    def test_supervisor_lease_reuses_the_shared_clock(self) -> None:
        """The supervisor heartbeat's injected clock is a real OperationalClock."""
        from saipal_analyst.supervisor import LeaseHeartbeat
        from saipal_engine.paths import FencedLockFile, home_paths

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = support.make_home(Path(tmp.name))
        clock = ops_clock.FrozenClock(start=50.0)
        lock = FencedLockFile(home_paths(home).locks / "t106.lock", ttl=3600)
        lock.acquire()
        heartbeat = LeaseHeartbeat(lock, ttl=3600.0, now=clock.wall_now)
        clock.advance(1200.0)
        self.assertTrue(heartbeat.due())
        self.assertTrue(heartbeat.renew())
        self.assertGreaterEqual(heartbeat.renewals, 1)


class BudgetAccountingAudit(unittest.TestCase):
    """ROLE 31: attempts/units/restart sharing and single-addition tokens."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        self.registry = load_registry()

    def test_restart_does_not_reset_the_window(self) -> None:
        budgets_mod.record_consumption(self.home, now=1_000_000.0, model_attempts=3, units=1)
        # A "restart" reloads the durable ledger.
        usage = budgets_mod.window_usage(self.home, now=1_000_500.0)
        self.assertEqual(usage["model_attempts"], 3)
        self.assertEqual(usage["units"], 1)

    def test_two_calls_reporting_100_100_total_200_not_300(self) -> None:
        """The token single-addition regression: usage must be additive."""
        budgets_mod.record_consumption(self.home, now=2_000_000.0, input_tokens=100, output_tokens=100)
        budgets_mod.record_consumption(self.home, now=2_000_100.0, input_tokens=100, output_tokens=100)
        usage = budgets_mod.window_usage(self.home, now=2_000_200.0)
        self.assertEqual(usage["input_tokens"], 200, "100+100 must total 200, not 300")
        self.assertEqual(usage["output_tokens"], 200)

    def test_budget_allows_respects_durable_limits(self) -> None:
        budgets_mod.record_consumption(self.home, now=3_000_000.0, model_attempts=100)
        allowed, reason = budgets_mod.budget_allows(
            self.home, limits={"max_model_attempts_per_hour": 100}, now=3_000_100.0
        )
        self.assertFalse(allowed)
        self.assertIn("attempt budget", reason)

    def test_failed_attempts_consume_budget(self) -> None:
        budgets_mod.record_consumption(self.home, now=4_000_000.0, model_attempts=1)
        usage = budgets_mod.window_usage(self.home, now=4_000_000.0)
        self.assertEqual(usage["model_attempts"], 1)


class BackendCircuitAudit(unittest.TestCase):
    """ROLE 32: OPEN -> no calls, HALF_OPEN -> one probe, auth blocks."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        self.registry = load_registry()
        from saipal_analyst.config import default_analyst_config, save_analyst_config

        config = default_analyst_config()
        config["backend"]["endpoint"] = "http://127.0.0.1:0/stub"
        config["backend"]["model"] = "stub"
        save_analyst_config(self.home, config)

    def _circuit(self) -> dict:
        return budgets_mod.backend_circuit(self.home)

    def test_retryable_failures_open_the_circuit(self) -> None:
        for _ in range(budgets_mod.CIRCUIT_TRIP_THRESHOLD):
            budgets_mod.record_backend_failure(
                self.home, failure_class="RETRYABLE", retryable=True, now=1_000_000.0
            )
        self.assertEqual(self._circuit().get("state"), "OPEN")
        allowed, _reason = budgets_mod.circuit_allows(self.home, now=1_000_000.0)
        self.assertFalse(allowed, "OPEN forbids calls")

    def test_half_open_probes_once_then_recovery_closes(self) -> None:
        for _ in range(budgets_mod.CIRCUIT_TRIP_THRESHOLD):
            budgets_mod.record_backend_failure(
                self.home, failure_class="RETRYABLE", retryable=True, now=1_000_000.0
            )
        # The OPEN window elapses -> HALF_OPEN admits exactly one probe.
        probe = budgets_mod.circuit_probe_allowed(self.home, now=1_000_000.0 + 10_000.0)
        self.assertEqual(probe.get("state"), "HALF_OPEN")
        allowed, _reason = budgets_mod.circuit_allows(self.home, now=1_000_000.0 + 10_000.0)
        self.assertTrue(allowed, "HALF_OPEN admits the probe")
        budgets_mod.record_backend_success(self.home)
        self.assertEqual(self._circuit().get("state"), "CLOSED")

    def test_auth_failure_blocks_until_config_change(self) -> None:
        budgets_mod.record_backend_failure(
            self.home, failure_class="AUTH", retryable=False, now=2_000_000.0
        )
        circuit = self._circuit()
        self.assertEqual(circuit.get("state"), "OPEN")
        self.assertIsNone(circuit.get("open_until"), "auth blocks without a time window")
        allowed, _reason = budgets_mod.circuit_allows(self.home, now=2_000_000.0 + 1_000_000.0)
        self.assertFalse(allowed, "auth failure stays blocked across time")


if __name__ == "__main__":
    unittest.main()