"""T-89: fair semantic backlog scheduling.

A 500-episode session must not consume the run budget while other sessions
receive zero investigation. Fairness is least-served-first across sessions,
durable across restart, deterministic; mechanical hints may order work but
never decide semantic verdict authority.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import fairness as fairness_mod
from saipal_analyst.config import default_analyst_config, save_analyst_config


class FairnessState(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def test_schema_is_closed(self) -> None:
        state = fairness_mod.fresh_state()
        self.assertEqual(fairness_mod.state_problems(state), [])
        state["nope"] = 1
        self.assertIn("unknown fairness field 'nope'", fairness_mod.state_problems(state))

    def test_service_counts_survive_restart(self) -> None:
        fairness_mod.record_service(self.home, "ses-a")
        fairness_mod.record_service(self.home, "ses-a")
        fairness_mod.record_service(self.home, "ses-b")
        counts = fairness_mod.served_counts(self.home)
        self.assertEqual(counts, {"ses-a": 2, "ses-b": 1})

    def test_rank_is_least_served_first_with_deterministic_ties(self) -> None:
        served = {"big": 3, "small": 0, "mid": 1}
        ordered = sorted(
            ("big", "small", "mid", "newcomer"),
            key=lambda s: fairness_mod.fairness_rank(s, served),
        )
        self.assertEqual(ordered[0], "newcomer")
        self.assertEqual(ordered[1], "small")
        self.assertEqual(ordered[-1], "big")

    def test_service_sequence_is_bounded(self) -> None:
        for index in range(fairness_mod.MAX_SERVICE_SEQUENCE + 10):
            fairness_mod.record_service(self.home, f"s-{index % 5}")
        state = fairness_mod.load_state(self.home)
        self.assertLessEqual(
            len(state["service_sequence"]), fairness_mod.MAX_SERVICE_SEQUENCE
        )


class FairScheduling(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def _home_with(self, *fixtures: str) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = support.make_home(Path(tmp.name))
        support.put_inbox(home, *fixtures)
        support.run_saipal("continue", home=home)
        return home

    def test_small_sessions_served_before_the_giant_consumes_the_budget(self) -> None:
        import test_wave_analyst_repair as repair

        # The giant: 4 pending episodes. The small ones: 1-2 each. A run
        # budget of 3 units must serve every session, not 3 slices of one.
        home = self._home_with(
            "conformant-cold.json",
            "no-finding-normal.json",
            "agent-noncompliance-command-route.json",
        )
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 0
        config["budgets"]["max_units_per_run"] = 3
        save_analyst_config(home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "k"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)

        clock = repair.FakeClock()
        from saipal_analyst.worker import investigate

        # All sessions are least-served (0): deterministic rank is session id
        # order. Queue one valid body per session in that exact order.
        for session_id in sorted(("ses-keys",)):
            pass
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.sessions import load_index

        _status, index, _d = load_index(home)
        for record in sorted(
            carrier_mod.freshest_records(index),
            key=lambda r: str(r.get("session_id")),
        ):
            backend.script.append(
                (200, repair.envelope(
                    repair.RepairBase.candidate_for(
                        repair.RepairBase(), home, "NO_DRIFT", str(record["session_id"])
                    )
                ))
            )
        summary = investigate(home, clock=clock.as_worker_clock())
        served_sessions = {
            repair_entry.get("session_id")
            for repair_entry in summary["receipts"]
        }
        self.assertGreaterEqual(
            len(served_sessions),
            2,
            "least-served-first must spread the run budget across sessions",
        )
        counts = fairness_mod.served_counts(home)
        self.assertEqual(sum(counts.values()), summary["units"])

    def test_fairness_state_survives_restart(self) -> None:
        import test_wave_analyst_repair as repair

        home = self._home_with("conformant-cold.json", "no-finding-normal.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 0
        config["budgets"]["max_units_per_run"] = 1
        save_analyst_config(home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "k"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)

        clock = repair.FakeClock()
        from saipal_analyst.worker import investigate

        from saipal_engine import carrier as carrier_mod
        from saipal_engine.sessions import load_index

        _status, index, _d = load_index(home)
        ordered = sorted(
            carrier_mod.freshest_records(index),
            key=lambda r: str(r.get("session_id")),
        )
        # Run 1 serves the first (least-served) session; run 2 serves the
        # next one -- fairness continues from the durable counts.
        backend.script.append(
            (200, repair.envelope(
                repair.RepairBase.candidate_for(
                    repair.RepairBase(), home, "NO_DRIFT", str(ordered[0]["session_id"])
                )
            ))
        )
        investigate(home, clock=clock.as_worker_clock())
        counts_first = fairness_mod.served_counts(home)
        # The next run continues fairness from the durable counts: the same
        # session is not re-favoured after a process restart.
        backend.script.append(
            (200, repair.envelope(
                repair.RepairBase.candidate_for(
                    repair.RepairBase(), home, "NO_DRIFT", str(ordered[-1]["session_id"])
                )
            ))
        )
        investigate(home, max_units=1, clock=clock.as_worker_clock())
        counts_second = fairness_mod.served_counts(home)
        self.assertGreater(sum(counts_second.values()), sum(counts_first.values()))
        first_served = [s for s, c in counts_first.items() if c > 0]
        for session in first_served:
            # A served session's count only grew -- never reset to zero.
            self.assertGreaterEqual(counts_second.get(session, 0), counts_first[session])

    def test_hint_severity_never_flips_a_verdict(self) -> None:
        # Structural control: the packet carries signals only as labelled
        # hints, and needs_critic is the ONLY gate between a verdict and its
        # critic. A high-severity signal can order work; it cannot manufacture
        # DRIFT -- the investigator still decides, the critic still confirms.
        import test_wave_analyst_repair as repair
        from saipal_analyst import output as output_module
        from saipal_engine import carrier as carrier_mod

        home = self._home_with("agent-noncompliance-command-route.json")
        packet = carrier_mod.build_carrier(home)
        clean = {
            "schema_version": 1,
            "verdict": "NO_DRIFT",
            "unit_digest": packet["unit_digest"],
            "session_id": packet["session"]["session_id"],
            "episode_index": packet["episode"]["index"],
            "slice_index": packet["slice"]["index"],
            "disposition_class": "NO_DRIFT",
            "reasoning": "clean",
            "event_refs": [packet["events"][0]["seq"]],
        }
        candidate = output_module.validate_candidate(clean, packet)
        # A clean verdict stays clean no matter how loud the hints are: the
        # hint table can only add a critic pass, never a verdict.
        need, reason = output_module.needs_critic(
            candidate,
            packet,
            policy={"critic_on_high_signal_no_drift": True},
            unit_digest=packet["unit_digest"],
        )
        self.assertIn(reason, ("high_signal_no_drift", "clean_sample", ""))
        self.assertEqual(candidate["verdict"], "NO_DRIFT")


if __name__ == "__main__":
    unittest.main()
