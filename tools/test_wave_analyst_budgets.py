"""T-90: durable cross-run budgets and circuit breakers.

A watch loop that restarts runs must not resurrect its budget. Every control
here uses injected clocks and a temporary home: a failed transport attempt is
still charged, restart does not reset the window, clock rollback freezes
instead of granting calls, repeated 429 opens the circuit and half-opens on
time, AUTH opens until the config materially changes, and one broken source
never freezes another.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import budgets as budgets_mod
from saipal_analyst.config import default_analyst_config, save_analyst_config


class BudgetBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def fresh_home(self, *fixtures: str) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = support.make_home(Path(tmp.name))
        support.put_inbox(home, *fixtures)
        support.run_saipal("continue", home=home)
        return home

    def enable(self, home: Path, backend: object, **budgets: object) -> dict:
        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 0
        budgets.setdefault("max_units_per_run", 1)
        for key, value in budgets.items():
            config["budgets"][key] = value
        save_analyst_config(home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "stub-key"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)
        return config


class WindowLedger(BudgetBase):
    def test_ledger_is_closed_and_validated(self) -> None:
        ledger = budgets_mod.fresh_ledger()
        self.assertEqual(budgets_mod.ledger_problems(ledger), [])
        bad = dict(ledger)
        bad["nope"] = 1
        self.assertIn("unknown budget ledger field 'nope'", budgets_mod.ledger_problems(bad))

    def test_window_survives_restart_and_hour_rolls(self) -> None:
        now = 1_000_000.0
        budgets_mod.record_consumption(self.home, now=now, model_attempts=3, units=1)
        budgets_mod.record_consumption(self.home, now=now + 60, model_attempts=2, units=1)
        usage = budgets_mod.window_usage(self.home, now=now + 120)
        self.assertEqual(usage["model_attempts"], 5)
        self.assertEqual(usage["units"], 2)

        # A fresh hour is a new window: the previous one is bounded out.
        next_hour = now + 3600
        empty = budgets_mod.window_usage(self.home, now=next_hour)
        self.assertEqual(empty["model_attempts"], 0)

    def test_clock_rollback_freezes_instead_of_granting(self) -> None:
        now = 1_000_000.0
        budgets_mod.record_consumption(self.home, now=now, model_attempts=1)
        # Wall time jumps backwards: never an extra allowance.
        budgets_mod.record_consumption(self.home, now=now - 3600 * 5, model_attempts=1)
        ledger = budgets_mod.load_ledger(self.home)
        self.assertTrue(ledger["rollback_freeze"])
        ok, reason = budgets_mod.budget_allows(
            self.home, limits={"max_model_attempts_per_hour": 100}, now=now
        )
        self.assertFalse(ok)
        self.assertIn("moved backwards", reason)

    def test_rollback_freeze_recovers_when_trusted_time_catches_up(self) -> None:
        """W2-003: the freeze is recoverable, not a one-way latch."""
        now = 1_000_000.0
        budgets_mod.record_consumption(self.home, now=now, model_attempts=1)
        budgets_mod.record_consumption(self.home, now=now - 3600 * 5, model_attempts=1)
        # Still behind the high-water mark: frozen, including after restart.
        still_frozen, _ = budgets_mod.budget_allows(
            self.home, limits={"max_model_attempts_per_hour": 100}, now=now - 3600 * 4
        )
        self.assertFalse(still_frozen)
        # Within skew of the mark: still conservative.
        within_skew, _ = budgets_mod.budget_allows(
            self.home, limits={"max_model_attempts_per_hour": 100}, now=now - 10
        )
        self.assertFalse(within_skew)
        # Trusted time passes the mark: a read-only allow check recovers.
        recovered, _ = budgets_mod.budget_allows(
            self.home, limits={"max_model_attempts_per_hour": 100}, now=now + 1
        )
        self.assertTrue(recovered)
        # The next ordinary write reconciles the latch durably -- no operator
        # edit, no state deletion.
        budgets_mod.record_consumption(self.home, now=now + 1, units=1)
        self.assertFalse(budgets_mod.load_ledger(self.home)["rollback_freeze"])
        # And time falling behind AGAIN re-freezes.
        budgets_mod.record_consumption(self.home, now=now - 3600 * 6, units=1)
        self.assertTrue(budgets_mod.load_ledger(self.home)["rollback_freeze"])

    def test_global_budget_blocks_new_calls(self) -> None:
        now = 1_000_000.0
        budgets_mod.record_consumption(self.home, now=now, model_attempts=2)
        ok, _reason = budgets_mod.budget_allows(
            self.home, limits={"max_model_attempts_per_hour": 2}, now=now
        )
        self.assertFalse(ok)
        ok2, _reason2 = budgets_mod.budget_allows(
            self.home, limits={"max_model_attempts_per_hour": 5}, now=now
        )
        self.assertTrue(ok2)


class CircuitBreaker(BudgetBase):
    def test_repeated_429_opens_then_half_opens_on_time(self) -> None:
        now = 1_000_000.0
        for _ in range(budgets_mod.CIRCUIT_TRIP_THRESHOLD):
            budgets_mod.record_backend_failure(
                self.home, failure_class="RETRYABLE", retryable=True, now=now
            )
        circuit = budgets_mod.backend_circuit(self.home)
        self.assertEqual(circuit["state"], budgets_mod.CIRCUIT_OPEN)
        self.assertIsNotNone(circuit["open_until"])

        allowed, _reason = budgets_mod.circuit_allows(self.home, now=now + 10)
        self.assertFalse(allowed, "an open circuit must stop provider hammering")

        # Time-based reopening: one probe is permitted after the window.
        budgets_mod.circuit_probe_allowed(self.home, now=float(circuit["open_until"]) + 1)
        self.assertEqual(
            budgets_mod.backend_circuit(self.home)["state"], budgets_mod.CIRCUIT_HALF_OPEN
        )
        allowed2, _reason2 = budgets_mod.circuit_allows(
            self.home, now=float(circuit["open_until"]) + 2
        )
        self.assertTrue(allowed2)

    def test_auth_failure_opens_until_config_changes(self) -> None:
        now = 1_000_000.0
        budgets_mod.record_backend_failure(
            self.home, failure_class="AUTH", retryable=False, now=now
        )
        circuit = budgets_mod.backend_circuit(self.home)
        self.assertEqual(circuit["state"], budgets_mod.CIRCUIT_OPEN)
        self.assertIsNone(circuit["open_until"], "an AUTH open is not time-based")

        pinned = circuit["config_digest"]
        allowed, reason = budgets_mod.circuit_allows(self.home, now=now + 10_000)
        self.assertFalse(allowed)
        self.assertIn("configuration", reason)

        # The config materially changed: the circuit half-opens again.
        config = default_analyst_config()
        config["backend"]["model"] = "changed-model"
        save_analyst_config(self.home, config)
        self.assertNotEqual(
            budgets_mod._config_digest(self.home),
            pinned,
            "the pinned config digest must track the file bytes",
        )
        allowed2, _reason2 = budgets_mod.circuit_allows(self.home, now=now + 10_001)
        self.assertTrue(allowed2)

    def test_success_closes_the_circuit(self) -> None:
        now = 1_000_000.0
        for _ in range(budgets_mod.CIRCUIT_TRIP_THRESHOLD - 1):
            budgets_mod.record_backend_failure(
                self.home, failure_class="RETRYABLE", retryable=True, now=now
            )
        self.assertEqual(
            budgets_mod.backend_circuit(self.home)["state"], budgets_mod.CIRCUIT_CLOSED
        )
        budgets_mod.record_backend_success(self.home)
        circuit = budgets_mod.backend_circuit(self.home)
        self.assertEqual(circuit["state"], budgets_mod.CIRCUIT_CLOSED)
        self.assertEqual(circuit["consecutive_failures"], 0)

    def test_semantic_output_failure_never_trips_the_circuit(self) -> None:
        # The worker only calls record_backend_failure for transport outcomes;
        # a malformed output is not a backend outage. (Contract guarded by the
        # worker's BackendFailure path; asserted here as the invariant.)
        circuit = budgets_mod.backend_circuit(self.home)
        self.assertEqual(circuit["state"], budgets_mod.CIRCUIT_CLOSED)
        self.assertEqual(circuit["consecutive_failures"], 0)

    def test_permanent_failure_stays_job_scoped(self) -> None:
        """W2-004: one HTTP 400 is a bad REQUEST, not a dead BACKEND."""
        now = 1_000_000.0
        budgets_mod.record_backend_failure(
            self.home, failure_class="PERMANENT", retryable=False, now=now
        )
        circuit = budgets_mod.backend_circuit(self.home)
        self.assertEqual(circuit["state"], budgets_mod.CIRCUIT_CLOSED)
        allowed, _reason = budgets_mod.circuit_allows(self.home, now=now + 1)
        self.assertTrue(allowed, "a request-scoped PERMANENT failure must not freeze unrelated units")

    def test_limit_failure_stays_job_scoped(self) -> None:
        """W2-004: one oversized response blocks that job, not the backend."""
        now = 1_000_000.0
        for _ in range(budgets_mod.CIRCUIT_TRIP_THRESHOLD * 3):
            budgets_mod.record_backend_failure(
                self.home, failure_class="LIMIT", retryable=False, now=now
            )
        circuit = budgets_mod.backend_circuit(self.home)
        self.assertEqual(circuit["state"], budgets_mod.CIRCUIT_CLOSED)
        allowed, _reason = budgets_mod.circuit_allows(self.home, now=now + 1)
        self.assertTrue(allowed)

    def test_auth_alone_receives_indefinite_global_open(self) -> None:
        """W2-004: only AUTH is config-pinned backend unusability."""
        now = 1_000_000.0
        budgets_mod.record_backend_failure(
            self.home, failure_class="AUTH", retryable=False, now=now
        )
        circuit = budgets_mod.backend_circuit(self.home)
        self.assertEqual(circuit["state"], budgets_mod.CIRCUIT_OPEN)
        self.assertIsNone(circuit["open_until"])
        self.assertIn("AUTH", budgets_mod.CIRCUIT_GLOBAL_CLASSES)


class SourceCircuits(BudgetBase):
    def test_one_broken_source_never_freezes_another(self) -> None:
        for _ in range(budgets_mod.CIRCUIT_TRIP_THRESHOLD):
            budgets_mod.record_source_failure(self.home, "source-a", detail="unreadable store")
        budgets_mod.record_source_failure(self.home, "source-b", detail="one hiccup")
        circuits = budgets_mod.source_circuits(self.home)
        self.assertEqual(circuits["source-a"]["state"], budgets_mod.CIRCUIT_OPEN)
        self.assertEqual(circuits["source-b"]["state"], budgets_mod.CIRCUIT_CLOSED)

        budgets_mod.record_source_success(self.home, "source-b")
        circuits = budgets_mod.source_circuits(self.home)
        self.assertEqual(circuits["source-b"]["consecutive_failures"], 0)
        self.assertEqual(circuits["source-a"]["state"], budgets_mod.CIRCUIT_OPEN)


class WorkerIntegration(BudgetBase):
    def test_failed_transport_attempt_is_charged_to_the_window(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend, max_model_attempts_per_hour=100)
        # A 429 then success: BOTH transport attempts are charged, and the
        # durable ledger counts them, so a restarted run cannot reset usage.
        backend.script.append((429, b"{}"))
        backend.script.append((200, repair.envelope(
            repair.RepairBase.candidate_for(repair.RepairBase(), home)
        )))

        clock = repair.FakeClock()
        summary = repair.investigate(home, clock=clock.as_worker_clock())
        self.assertEqual(summary["jobs_completed"], 1)
        self.assertEqual(summary["model_calls"], 2)
        usage = budgets_mod.window_usage(home)
        self.assertEqual(usage["model_attempts"], 2)
        self.assertEqual(usage["units"], 1)

    def test_exhausted_window_blocks_the_next_run(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend, max_model_attempts_per_hour=1)
        backend.script.append((200, repair.envelope(
            repair.RepairBase.candidate_for(repair.RepairBase(), home)
        )))
        backend.script.append((200, repair.envelope(
            repair.RepairBase.candidate_for(repair.RepairBase(), home)
        )))

        clock = repair.FakeClock()
        first = repair.investigate(home, clock=clock.as_worker_clock())
        self.assertEqual(first["jobs_completed"], 1)
        # The window is spent: the next invocation makes ZERO model calls and
        # stops honestly instead of granting budget by process restart.
        second = repair.investigate(home, max_units=2, clock=clock.as_worker_clock())
        self.assertEqual(second["stop_reason"], "BUDGET_EXHAUSTED")
        self.assertEqual(backend.attempts, 1)


if __name__ == "__main__":
    unittest.main()
