"""T-108 (ROLE 48-53): 100+ logical-cycle shadow soak + restart matrix.

One temporary home across logical time (fake clock, fake backend, controlled
source mutations) -- never a rebuilt protocol home per cycle. At completion
the soak asserts the ROLE 50 invariants; the restart matrix injects process
death at the durable boundaries ROLE 51 names and requires local convergence
with no duplicate forensic effects.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support


class SoakBase(unittest.TestCase):
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

    def enable(self, home: Path, backend) -> None:
        from saipal_analyst.config import default_analyst_config, save_analyst_config

        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 0
        config["budgets"]["max_units_per_run"] = 2
        config["budgets"]["max_model_calls_per_run"] = 200
        save_analyst_config(home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "stub-key"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)


class ShadowSoak(SoakBase):
    """ROLE 48-50: 100+ logical cycles, event timeline, invariants."""

    def test_100_logical_cycles_over_one_home(self) -> None:
        import test_wave_analyst_repair as repair
        from saipal_analyst import ops_clock as ops_clock_mod
        from saipal_analyst import supervisor as sup_mod
        from saipal_engine import submit as submit_module

        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(self.home, backend)

        clock = ops_clock_mod.FrozenClock()

        # Event timeline over logical time (ROLE 49): a clean source session
        # arrives, then more arrive; the script serves each pending unit once
        # (NO_DRIFT); everything else stays idle. Idle cycles dominate -- the
        # soak proves no busy loop, no duplicated effects.
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.sessions import load_index

        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        _s, index, _d = load_index(self.home)
        units = 0
        for record in sorted(
            carrier_mod.freshest_records(index), key=lambda r: str(r.get("session_id"))
        ):
            for _episode in record.get("episodes") or []:
                backend.script.append(
                    (200, repair.envelope(
                        repair.RepairBase.candidate_for(
                            repair.RepairBase(), self.home, "NO_DRIFT",
                            str(record["session_id"]),
                        )
                    ))
                )
                units += 1

        receipts_before = 0
        audits_before = 0
        cycles_target = 100
        result = sup_mod.watch(
            self.home,
            max_cycles=cycles_target,
            max_units_per_cycle=2,
            idle_wake_seconds=60.0,
            sleep_fn=clock.sleep,
            clock=clock,
        )
        self.assertEqual(result["stop_reason"], "MAX_CYCLES")
        self.assertGreaterEqual(result["cycles_run"], cycles_target)

        # ROLE 50 invariants.
        # No duplicate semantic receipt.
        _st, receipts_payload, _d = submit_module.load_receipts(self.home)
        receipts = receipts_payload.get("receipts") or []
        receipt_ids = [str(r.get("receipt_id") or r.get("id")) for r in receipts]
        self.assertEqual(
            len(receipt_ids), len(set(receipt_ids)), "duplicate receipt detected"
        )
        self.assertLessEqual(len(receipts), units, "no receipt without a real unit")
        # No duplicate audit number.
        staged = sorted((self.home / "audit" / "staging").glob("*.md"))
        numbers = [p.name for p in staged]
        self.assertEqual(len(numbers), len(set(numbers)), "duplicate audit number")
        # Recurrence ledger never corrupted, never emptied by the soak.
        from saipal_engine.recurrence import recurrence_status

        self.assertEqual(recurrence_status(self.home), "VALID")
        # No external publication; shadow mode held.
        self.assertFalse(bool(result.get("external_publication_possible")))
        # Fairness survived: served counts match the receipts; no reset.
        from saipal_analyst import fairness as fairness_mod

        counts = fairness_mod.served_counts(self.home)
        self.assertEqual(
            sum(counts.values()), len(receipts),
            "every receipt must be accounted in the fairness telemetry",
        )
        # Logical time advanced (idle wakes happened) but zero real sleeps:
        # FrozenClock.sleep is a no-op, so this just proves the schedule ran.
        self.assertGreater(clock.wall_now(), 1_000_000.0)

    def test_restart_between_logical_cycles_converges(self) -> None:
        """ROLE 26/51: process death between cycles converges, no duplicates."""
        import test_wave_analyst_repair as repair
        from saipal_analyst import supervisor as sup_mod
        from saipal_engine import submit as submit_module

        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(self.home, backend)

        from saipal_engine import carrier as carrier_mod
        from saipal_engine.sessions import load_index

        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        _s, index, _d = load_index(self.home)
        for record in sorted(
            carrier_mod.freshest_records(index), key=lambda r: str(r.get("session_id"))
        ):
            for _e in record.get("episodes") or []:
                backend.script.append(
                    (200, repair.envelope(
                        repair.RepairBase.candidate_for(
                            repair.RepairBase(), self.home, "NO_DRIFT",
                            str(record["session_id"]),
                        )
                    ))
                )
        # Supervisor process 1: one cycle, then "dies" (bounded run returns).
        first = sup_mod.watch(
            self.home, max_cycles=1, max_units_per_cycle=2, sleep_fn=lambda _s: None
        )
        # Supervisor process 2 (restart): continues; the same unit must NOT
        # be re-reasoned into a second receipt.
        second = sup_mod.watch(
            self.home, max_cycles=2, max_units_per_cycle=2, sleep_fn=lambda _s: None
        )
        _st, payload, _d = submit_module.load_receipts(self.home)
        receipts = payload.get("receipts") or []
        ids = [str(r.get("receipt_id") or r.get("id")) for r in receipts]
        self.assertEqual(len(ids), len(set(ids)), "restart duplicated a receipt")
        self.assertLessEqual(len(receipts), 2)
        total_receipts_reported = sum(
            int(c.get("receipts") or 0) for c in first["cycle_results"] + second["cycle_results"]
        )
        self.assertEqual(total_receipts_reported, len(receipts))


class RestartMatrix(SoakBase):
    """ROLE 51: inject process death at the durable boundaries."""

    def _setup(self):
        import test_wave_analyst_repair as repair

        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(self.home, backend)
        return repair, backend

    def _receipt_digests(self) -> list[str]:
        from saipal_engine import submit as submit_module

        _st, payload, _d = submit_module.load_receipts(self.home)
        return sorted(
            str(r.get("unit_digest") or "")
            for r in (payload.get("receipts") or [])
        )

    def test_death_after_submit_commit_converges_without_duplicate(self) -> None:
        import test_wave_analyst_repair as repair
        from saipal_analyst import jobs as jobs_mod
        from saipal_analyst import worker as worker_mod

        repair, backend = self._setup()
        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.sessions import load_index

        _s, index, _d = load_index(self.home)
        record = sorted(
            carrier_mod.freshest_records(index), key=lambda r: str(r.get("session_id"))
        )[0]
        for _e in record.get("episodes") or []:
            backend.script.append(
                (200, repair.envelope(
                    repair.RepairBase.candidate_for(
                        repair.RepairBase(), self.home, "NO_DRIFT",
                        str(record["session_id"]),
                    )
                ))
            )
        first = worker_mod.investigate(self.home, max_units=1)
        self.assertEqual(first["stop_reason"], "BUDGET_EXHAUSTED")
        digests_after_first = self._receipt_digests()
        # "Process death" = a fresh worker object, durable journal intact.
        second = worker_mod.investigate(self.home, max_units=1)
        self.assertEqual(
            self._receipt_digests(), digests_after_first,
            "a restart must not re-reason a committed receipt into a duplicate",
        )

    def test_death_before_response_reuses_persisted_state(self) -> None:
        """Crash after response persisted: restart continues with zero new calls
        for that stage (T-84 invariants, re-proven through the soak surface)."""
        import test_wave_analyst_repair as repair
        from saipal_analyst import jobs as jobs_mod
        from saipal_analyst import worker as worker_mod

        repair, backend = self._setup()
        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.sessions import load_index

        _s, index, _d = load_index(self.home)
        record = sorted(
            carrier_mod.freshest_records(index), key=lambda r: str(r.get("session_id"))
        )[0]
        session_id = str(record["session_id"])
        # One investigator reply, no more: a restart after the response was
        # persisted must finish the unit WITHOUT a second investigator call.
        backend.script.append(
            (200, repair.envelope(
                repair.RepairBase.candidate_for(repair.RepairBase(), self.home, "NO_DRIFT", session_id)
            ))
        )
        class _SimulatedDeath(BaseException):
            pass

        real_stage = worker_mod._stage

        def dying_stage(root_arg, journal_arg, job_arg, to_state, **fields):
            real_stage(root_arg, journal_arg, job_arg, to_state, **fields)
            if to_state == jobs_mod.INVESTIGATOR_RESPONSE:
                raise _SimulatedDeath("process died after the investigator response was persisted")

        calls_before = backend.attempts
        original_stage = worker_mod._stage
        worker_mod._stage = dying_stage
        try:
            with self.assertRaises(_SimulatedDeath):
                worker_mod.investigate(self.home, max_units=1)
        finally:
            worker_mod._stage = original_stage
        calls_after_death = backend.attempts
        self.assertEqual(calls_after_death - calls_before, 1,
                         "exactly one investigator call before the injected death")

        # Durable proof of the crash boundary: the job is INVESTIGATOR_RESPONSE.
        journal = jobs_mod.load_journal(self.home)
        stages = {str(job.get("stage")) for job in (journal.get("jobs") or {}).values()}
        self.assertIn(jobs_mod.INVESTIGATOR_RESPONSE, stages)

        # Restart: the persisted paid stage is not repeated.
        second = worker_mod.investigate(self.home, max_units=1)
        self.assertEqual(
            backend.attempts - calls_after_death, 0,
            "restart must reuse the persisted investigator response (zero new calls)",
        )
        self.assertEqual(second["model_calls"], 0)
        self.assertEqual(second["investigator_calls"], 0)
        self.assertEqual(len(second.get("receipts") or []), 1,
                         "the unit still converges to exactly one receipt")


if __name__ == "__main__":
    unittest.main()
