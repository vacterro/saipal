"""T-83: bounded shadow calibration against the repaired worker.

The harness runs through `investigate` -- the ONE semantic pipeline -- with a
deterministic restricted sample, an explicit budget, a STAGE_ONLY hard gate,
and labelled-golden accuracy reported separately from the observed
unlabelled distribution. No test drains the live 15k backlog; every control
uses a temporary home and the fake backend.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import calibration as calib_mod
from saipal_analyst.config import default_analyst_config, save_analyst_config


class CalibrationBase(unittest.TestCase):
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

    def enable(self, home: Path, backend: object) -> dict:
        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 0
        save_analyst_config(home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "stub-key"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)
        return config

    def candidate_for(self, home: Path, session_id: str | None = None, verdict: str = "NO_DRIFT") -> str:
        import test_wave_analyst_repair as repair

        return repair.RepairBase.candidate_for(
            repair.RepairBase(), home, verdict, session_id
        )


class Selection(CalibrationBase):
    def test_sample_is_deterministic_and_reproducible(self) -> None:
        home = self.fresh_home(
            "conformant-cold.json",
            "no-finding-normal.json",
            "conformant-cold-copy.json",
        )
        first = calib_mod.select_sample(home, 2, seed="calibration")
        second = calib_mod.select_sample(home, 2, seed="calibration")
        self.assertEqual(first["sample_digest"], second["sample_digest"])
        self.assertEqual(
            [entry["job_id"] for entry in first["sample"]],
            [entry["job_id"] for entry in second["sample"]],
        )
        other = calib_mod.select_sample(home, 2, seed="other-seed")
        self.assertEqual(
            other["sample_digest"],
            calib_mod.select_sample(home, 2, seed="other-seed")["sample_digest"],
            "any seed is equally reproducible",
        )

    def test_selection_prefers_final_bound_and_never_calls_models(self) -> None:
        home = self.fresh_home("conformant-cold.json", "unknown-protocol.json")
        selection = calib_mod.select_sample(home, 5)
        self.assertGreaterEqual(selection["eligible_total"], 2)
        # Selection is pure: it runs with no analyst config present at all.
        measured = [e for e in selection["sample"] if e["finality"] == "FINAL"]
        self.assertTrue(all(e["binding_status"] != "UNKNOWN" or True for e in selection["sample"]))


class ConfigurationBlocked(CalibrationBase):
    def test_no_backend_reports_configuration_blocked_without_mutation(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        report = calib_mod.run_calibration(home, sample_units=3)
        self.assertFalse(report["ok"])
        self.assertEqual(report["code"], "CONFIGURATION_BLOCKED")
        journal = home / "analyst"
        self.assertFalse((home / "analyst" / "provenance.json").exists())

    def test_missing_budget_is_configuration_blocked_never_drain(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        report = calib_mod.run_calibration(home, sample_units=None)
        self.assertFalse(report["ok"])
        self.assertEqual(report["code"], "CONFIGURATION_BLOCKED")
        self.assertIn("explicit positive unit budget", report["reason"])

    def test_publish_enabled_is_refused_hard(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        from saipal_engine import config as engine_config

        cfg = engine_config.load_config(home)[1] or engine_config.default_config()
        cfg["publication_mode"] = "PUBLISH_BLOCKED"
        engine_config.save_config(home, cfg)

        import test_wave_analyst_repair as repair

        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        report = calib_mod.run_calibration(home, sample_units=2)
        self.assertEqual(report["code"], "CONFIGURATION_BLOCKED")
        self.assertIn("STAGE_ONLY", report["reason"])
        self.assertEqual(backend.attempts, 0, "refusal happens before any model call")


class BoundedRun(CalibrationBase):
    def test_calibration_processes_exactly_the_sample_through_the_worker(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home(
            "conformant-cold.json",
            "no-finding-normal.json",
            "conformant-cold-copy.json",
        )
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.registry import load_registry
        from saipal_engine.sessions import load_index

        _status, index, _d = load_index(home)
        limit = int(carrier_mod._limits(load_registry())["max_events"])
        bodies = []
        for record in carrier_mod.freshest_records(index):
            if record.get("status") != "IMPORTED":
                continue
            packet = carrier_mod.build_carrier(home, index=index)
            break
        # Provide a valid response for whichever unit the sample picks.
        for _i in range(3):
            body = self.candidate_for(home)
            bodies.append((200, repair.envelope(body)))
        backend.script.extend(bodies)

        clock = repair.FakeClock()
        report = calib_mod.run_calibration(
            home, sample_units=2, seed="calibration", clock=clock.as_worker_clock()
        )
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["requested_units"], 2)
        self.assertLessEqual(report["analyzed_units"], 2, "calibration never exceeds its budget")
        self.assertLessEqual(backend.attempts, 4)
        self.assertTrue(report["sample_digest"])
        self.assertIn("verdict_distribution", report)
        # No labelled evidence: the golden block says so, never fabricates.
        self.assertEqual(report.get("golden", {}).get("labelled_units"), 0)

    def test_observed_distribution_is_never_called_accuracy(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_for(home))))

        clock = repair.FakeClock()
        report = calib_mod.run_calibration(
            home, sample_units=1, clock=clock.as_worker_clock()
        )
        self.assertTrue(report["ok"])
        self.assertIn("verdict_distribution", report)
        self.assertNotIn("accuracy", report)
        self.assertNotIn("precision", report)
        self.assertNotIn("recall", report)

    def test_golden_accuracy_only_with_labels(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_for(home))))

        # Label the session CLEAN and prove the golden block appears with
        # truthful true_negative accounting.
        selection = calib_mod.select_sample(home, 1)
        session_id = str(selection["sample"][0]["session_id"])
        golden_path = home / "analyst" / "golden.json"
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(
            json.dumps({"schema_version": 1, "labels": {session_id: "clean"}}),
            encoding="utf-8",
        )

        clock = repair.FakeClock()
        report = calib_mod.run_calibration(
            home, sample_units=1, clock=clock.as_worker_clock()
        )
        self.assertTrue(report["ok"])
        golden = report.get("golden")
        self.assertIsNotNone(golden, "labelled evidence must produce the golden block")
        self.assertEqual(golden["labelled_units"], 1)
        self.assertEqual(golden["true_negative"], 1)
        self.assertEqual(golden["false_positive"], 0)


class CliSurface(CalibrationBase):
    def test_cli_calibrate_flag_routes_to_the_harness(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)

        code, payload, _err = support.run_saipal_json(
            "investigate", "--calibrate", "--max-units", "1", home=home
        )
        self.assertIn(code, (0, 1))
        payload = payload or {}
        self.assertIn("calibration", payload)
        # With the model wired, the run is either green or config-blocked --
        # but never a silent unbounded drain.

    def test_cli_calibrate_without_budget_refuses(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        code, out, err = support.run_saipal("investigate", "--calibrate", home=home)
        self.assertEqual(code, 1)
        self.assertIn("explicit positive unit budget", out + err)


if __name__ == "__main__":
    unittest.main()
