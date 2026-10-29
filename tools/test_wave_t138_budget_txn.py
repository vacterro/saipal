"""T-138: the budget ledger is one serialized cross-writer transaction.

`budget.json` is mutated by several read-modify-write paths -- consumption
windows, the backend circuit, and the per-source circuits. Each did
load_ledger -> mutate -> save_ledger, and `atomic_write_json` makes only the
final REPLACE atomic, not the whole transaction. Two writers both read
generation N and independently publish N+1, so the later save silently
discards the earlier mutation: the ledger exists specifically to make budget
and circuit state durable across processes, so a silent lost update is a
correctness failure.

The repair routes every mutator through `budgets.mutate_ledger`, which runs
the whole load/validate/mutate/save under the common writer fence (the
CORE-001 HomeLock lease, reused: cross-process exclusive, same-thread
reentrant, physical-home-identity and PAL-WRITE confined). Model/network work
never runs under it. These controls prove: two same-ledger charges both
commit (A), consumption never overwrites a circuit transition or vice versa
(B, C), a real second process serializes rather than losing a charge (D),
authoritative accounting under contention is not swallowed (E), legitimate
reentrancy still commits exactly once (F), no network runs under the fence
(G), and concurrent stress strands no temp file (H).
"""

from __future__ import annotations

import os
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import budgets as budgets_mod
from saipal_engine.errors import PalError
from saipal_engine.paths import writer_fence


class _TxnBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        # Materialize the ledger once so every racing writer reads a real
        # generation N rather than the fresh-ledger default.
        budgets_mod.record_consumption(self.home, units=0)

    def _run_racing(self, workers, *, load_gate_timeout: float = 0.25):
        """Run `workers` concurrently, forcing every thread to reach its ledger
        load before any of them proceeds.

        The gate makes the stale-read window deterministic instead of timing
        dependent: pre-fix, both threads load generation N and the loser's save
        clobbers the winner; post-fix, only the fence holder proceeds past the
        real load while the loser retries fence acquisition, so both mutations
        commit. The short gate timeout lets the fence holder proceed while the
        loser is still contending, rather than deadlocking the barrier.
        """
        gate = threading.Barrier(len(workers))
        original = budgets_mod.load_ledger

        def gated_load(home):
            try:
                gate.wait(timeout=load_gate_timeout)
            except threading.BrokenBarrierError:
                pass
            return original(home)

        budgets_mod.load_ledger = gated_load
        self.addCleanup(setattr, budgets_mod, "load_ledger", original)
        errors: list[Exception] = []

        def wrap(fn):
            def run():
                try:
                    fn()
                except Exception as exc:  # noqa: BLE001 -- surfaced to the test
                    errors.append(exc)

            return run

        threads = [threading.Thread(target=wrap(fn)) for fn in workers]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        budgets_mod.load_ledger = original
        return errors


class ControlA_SameLedgerLostUpdate(_TxnBase):
    def test_two_concurrent_unit_charges_both_commit(self) -> None:
        errors = self._run_racing(
            [
                lambda: budgets_mod.record_consumption(self.home, units=1),
                lambda: budgets_mod.record_consumption(self.home, units=1),
            ]
        )
        self.assertEqual(errors, [], f"a charge raised instead of serializing: {errors}")
        usage = budgets_mod.window_usage(self.home)
        # Pre-fix this is 1 (LOST_UPDATE); post-fix both durable units survive.
        self.assertEqual(usage["units"], 2)


class ControlB_ConsumptionVsSourceCircuit(_TxnBase):
    def test_consumption_and_source_success_both_survive(self) -> None:
        # Seed a source circuit so record_source_success has state to transition.
        for _ in range(budgets_mod.CIRCUIT_TRIP_THRESHOLD):
            budgets_mod.record_source_failure(self.home, "source-x", detail="down")
        self.assertEqual(
            budgets_mod.source_circuits(self.home)["source-x"]["state"],
            budgets_mod.CIRCUIT_OPEN,
        )
        errors = self._run_racing(
            [
                lambda: budgets_mod.record_consumption(self.home, model_attempts=1),
                lambda: budgets_mod.record_source_success(self.home, "source-x"),
            ]
        )
        self.assertEqual(errors, [], f"a mutator raised: {errors}")
        usage = budgets_mod.window_usage(self.home)
        circuit = budgets_mod.source_circuits(self.home)["source-x"]
        self.assertEqual(usage["model_attempts"], 1, "the model attempt was overwritten")
        self.assertEqual(
            circuit["state"],
            budgets_mod.CIRCUIT_CLOSED,
            "the source success transition was overwritten",
        )
        self.assertEqual(circuit["consecutive_failures"], 0)


class ControlC_ConsumptionVsBackendCircuit(_TxnBase):
    def test_consumption_and_backend_failure_both_survive(self) -> None:
        errors = self._run_racing(
            [
                lambda: budgets_mod.record_consumption(self.home, units=1),
                lambda: budgets_mod.record_backend_failure(
                    self.home, failure_class="RETRYABLE", retryable=True
                ),
            ]
        )
        self.assertEqual(errors, [], f"a mutator raised: {errors}")
        usage = budgets_mod.window_usage(self.home)
        circuit = budgets_mod.backend_circuit(self.home)
        self.assertEqual(usage["units"], 1, "the consumption charge was overwritten")
        self.assertEqual(
            int(circuit["consecutive_failures"]),
            1,
            "the backend failure transition was overwritten by consumption",
        )


_CHILD_PROGRAM = textwrap.dedent(
    """
    import sys, time
    sys.path.insert(0, {tools!r})
    from saipal_analyst import budgets as b
    home = sys.argv[1]
    start = float(sys.argv[2])
    # Both processes wake at the same wall instant to overlap their windows.
    now = time.time()
    if now < start:
        time.sleep(start - now)
    for _ in range({charges}):
        b.record_consumption(home, units=1)
    """
)


class ControlD_RealCrossProcessBoundary(unittest.TestCase):
    def test_two_processes_charge_without_loss(self) -> None:
        import subprocess

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = support.make_home(Path(tmp.name))
        budgets_mod.record_consumption(home, units=0)

        charges = 25
        program = _CHILD_PROGRAM.format(
            tools=str(support.TOOLS_DIR), charges=charges
        )
        start = time.time() + 0.5
        procs = [
            subprocess.Popen(
                [sys.executable, "-B", "-c", program, str(home), f"{start:.3f}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(2)
        ]
        outs = [p.communicate(timeout=120) for p in procs]
        for proc, (out, err) in zip(procs, outs):
            self.assertEqual(
                proc.returncode, 0, f"child failed: {out!r} {err!r}"
            )
        usage = budgets_mod.window_usage(home)
        # Two real processes, each charging `charges` durable units: no charge
        # is lost to an interleaved stale save.
        self.assertEqual(usage["units"], 2 * charges)


class ControlE_WriterContention(_TxnBase):
    def test_accounting_under_held_fence_does_not_silently_drop(self) -> None:
        """A held fence must make an authoritative charge WAIT then commit, or
        (if genuinely wedged) raise WRITER_BUSY -- never silently succeed with
        the charge dropped.

        The fence is held from another thread for a bounded interval. The charge
        must retry across that window and still land, so the durable unit is
        never lost.
        """
        released = threading.Event()
        holding = threading.Event()

        def hold():
            with writer_fence(self.home):
                holding.set()
                # Hold well under the budget retry budget so the charge retries
                # and then commits rather than exhausting its bound.
                time.sleep(0.15)
            released.set()

        holder = threading.Thread(target=hold)
        holder.start()
        self.assertTrue(holding.wait(timeout=5), "fence was never acquired")
        # This runs while the fence is held: it must not swallow the contention.
        budgets_mod.record_consumption(self.home, units=1)
        holder.join(timeout=5)
        self.assertTrue(released.is_set())
        self.assertEqual(budgets_mod.window_usage(self.home)["units"], 1)

    def test_wedged_fence_surfaces_writer_busy(self) -> None:
        """If the fence stays held past the whole retry budget the charge does
        NOT silently succeed: it raises WRITER_BUSY, which the worker turns into
        a structured stop rather than a swallowed charge."""
        original = budgets_mod.BUDGET_TXN_RETRIES
        budgets_mod.BUDGET_TXN_RETRIES = 3
        self.addCleanup(setattr, budgets_mod, "BUDGET_TXN_RETRIES", original)
        with writer_fence(self.home):
            # A DIFFERENT thread cannot reenter this thread's fence; it must fail.
            result: dict = {}

            def charge():
                try:
                    budgets_mod.record_consumption(self.home, units=1)
                    result["ok"] = True
                except PalError as exc:
                    result["code"] = exc.code

            t = threading.Thread(target=charge)
            t.start()
            t.join(timeout=5)
        self.assertEqual(
            result.get("code"),
            "WRITER_BUSY",
            f"a wedged fence must surface WRITER_BUSY, got {result!r}",
        )


class ControlF_NestedReentrancy(_TxnBase):
    def test_mutation_inside_held_fence_commits_once(self) -> None:
        # A legitimate caller already holding the fence (intake/rebind/setup)
        # drives a budget mutation. Reentrancy is valid and the charge lands
        # exactly once.
        before = budgets_mod.window_usage(self.home)["units"]
        with writer_fence(self.home):
            budgets_mod.record_consumption(self.home, units=1)
            # Still inside the same fence: a second mutation also reenters.
            budgets_mod.record_backend_failure(
                self.home, failure_class="RETRYABLE", retryable=True
            )
        usage = budgets_mod.window_usage(self.home)
        self.assertEqual(usage["units"], before + 1)
        self.assertEqual(
            int(budgets_mod.backend_circuit(self.home)["consecutive_failures"]), 1
        )


class ControlG_NoNetworkUnderFence(_TxnBase):
    def test_no_transport_call_while_fence_held(self) -> None:
        """The serialized section is a small local filesystem transaction. The
        common writer fence must NOT be held while the provider transport runs
        (NON_GOAL: no provider/network call under the fence).

        This runs the real worker against a stub backend and asserts the fence
        depth for this home is zero at the moment transport is entered.
        """
        import test_wave_analyst_repair as repair
        from saipal_analyst import openai_compatible as transport_mod
        from saipal_analyst.config import (
            default_analyst_config,
            save_analyst_config,
        )
        from saipal_engine import paths as paths_mod

        # Build a fresh analyzable home the same way the budgets suite does.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = support.make_home(Path(tmp.name))
        support.put_inbox(home, "conformant-cold.json")
        support.run_saipal("continue", home=home)

        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 0
        config["budgets"]["max_units_per_run"] = 1
        save_analyst_config(home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "stub-key"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)
        backend.script.append(
            (200, repair.envelope(repair.RepairBase.candidate_for(repair.RepairBase(), home)))
        )

        observed: list[int] = []
        lock_key = str(paths_mod.home_paths(home).lock)
        original_call = transport_mod.call

        def spy_call(*args, **kwargs):
            depth = sum(
                v
                for (path, _tid), v in paths_mod._WRITER_FENCE_DEPTH.items()
                if path == lock_key
            )
            observed.append(depth)
            return original_call(*args, **kwargs)

        transport_mod.call = spy_call
        self.addCleanup(setattr, transport_mod, "call", original_call)

        clock = repair.FakeClock()
        summary = repair.investigate(home, clock=clock.as_worker_clock())
        transport_mod.call = original_call

        self.assertGreaterEqual(len(observed), 1, "transport was never exercised")
        self.assertTrue(
            all(depth == 0 for depth in observed),
            f"the writer fence was held during transport: depths {observed}",
        )
        self.assertEqual(summary.get("model_calls", 0), len(observed))


class ControlH_TempResidue(_TxnBase):
    def test_no_temp_file_stranded_after_concurrent_stress(self) -> None:
        workers = [
            (lambda: budgets_mod.record_consumption(self.home, units=1)) for _ in range(6)
        ]
        # Several rounds of contended charges.
        for _ in range(8):
            errors = self._run_racing(workers, load_gate_timeout=0.1)
            self.assertEqual(errors, [], f"a charge raised under stress: {errors}")
        journal_dir = budgets_mod.jobs_ledger_dir(self.home)
        residue = list(journal_dir.glob(".budget.json.*.tmp"))
        self.assertEqual(residue, [], f"stranded budget temp files: {residue}")


if __name__ == "__main__":
    unittest.main()
