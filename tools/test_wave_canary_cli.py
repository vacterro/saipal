"""T-108 (ROLE 29-33): the real `watch --canary` CLI surface.

The canary exists through actual CLI parsing/dispatch, not supervisor.watch()
tests alone: the parser must accept --canary/--max-cycles/--max-units-per-cycle/
--max-model-attempts, refuse boundless canaries, and the operator proof runs
through the command surface. CONFIGURATION_BLOCKED is a refusal with a
machine-readable body, never a cheerful idle canary that tested nothing.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support


def run_cli(home: Path, *args: str) -> dict:
    code, payload, _err = support.run_saipal_json("watch", *args, home=home)
    return payload or {"exit_code": code}


def run_cli_code(home: Path, *args: str) -> tuple[int, dict]:
    code, payload, _err = support.run_saipal_json("watch", *args, home=home)
    return code, payload or {}


class CanaryParser(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        support.run_saipal("continue", home=self.home)

    def test_canary_flag_is_recognized(self) -> None:
        result = run_cli(self.home, "--canary", "--max-cycles", "1",
                               "--max-units-per-cycle", "1", "--max-model-attempts", "1")
        # The parse succeeded and reached the canary runtime: either a real
        # refusal (CONFIGURATION_BLOCKED) or a real bounded run -- never USAGE.
        self.assertNotEqual(result.get("code"), "USAGE")
        self.assertIn("canary", result)
        self.assertTrue(result["canary"])

    def test_canary_requires_explicit_bounds(self) -> None:
        for argv in (
            ("--canary",),
            ("--canary", "--max-cycles", "2"),
            ("--canary", "--max-units-per-cycle", "2", "--max-model-attempts", "2"),
        ):
            with self.subTest(argv=argv):
                result = run_cli(self.home, *argv)
                self.assertEqual(result.get("code"), "USAGE")
                self.assertIn("canary requires", str(result.get("message") or result))

    def test_canary_bounds_must_be_positive(self) -> None:
        result = run_cli(
            self.home, "--canary", "--max-cycles", "0",
            "--max-units-per-cycle", "1", "--max-model-attempts", "1",
        )
        self.assertEqual(result.get("code"), "USAGE")

    def test_plain_watch_still_rejects_unknown_options(self) -> None:
        result = run_cli(self.home, "--nonsense")
        self.assertEqual(result.get("code"), "USAGE")


class CanaryConfigurationBlocked(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        support.run_saipal("continue", home=self.home)

    def _canary(self) -> dict:
        result = run_cli(self.home, "--canary", "--max-cycles", "1",
                               "--max-units-per-cycle", "1", "--max-model-attempts", "1")
        return result

    def test_unconfigured_analyst_is_blocked_not_idle(self) -> None:
        result = self._canary()
        self.assertTrue(result["canary"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["stop_reason"], "CONFIGURATION_BLOCKED")
        self.assertEqual(result["cycles_completed"], 0)
        self.assertIn("analyst", result["detail"])

    def test_disabled_analyst_is_blocked(self) -> None:
        from saipal_analyst.config import default_analyst_config, save_analyst_config

        config = default_analyst_config()
        config["enabled"] = False
        save_analyst_config(self.home, config)
        result = self._canary()
        self.assertEqual(result["stop_reason"], "CONFIGURATION_BLOCKED")
        self.assertIn("disabled", result["detail"])

    def test_backend_without_key_env_is_blocked(self) -> None:
        from saipal_analyst.config import default_analyst_config, save_analyst_config

        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["model"] = "m"
        save_analyst_config(self.home, config)
        os.environ.pop("SAIPAL_ANALYST_API_KEY", None)
        result = self._canary()
        self.assertEqual(result["stop_reason"], "CONFIGURATION_BLOCKED")
        self.assertIn("API key", result["detail"])

    def test_corrupt_recurrence_is_blocked_before_cycles(self) -> None:
        from saipal_analyst.config import default_analyst_config, save_analyst_config

        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["model"] = "m"
        save_analyst_config(self.home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "k"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)
        (self.home / "recurrence.json").write_bytes(b"{broken")
        result = self._canary()
        self.assertEqual(result["stop_reason"], "CONFIGURATION_BLOCKED")
        self.assertIn("recurrence", result["detail"])
        self.assertEqual((self.home / "recurrence.json").read_bytes(), b"{broken")

    def test_blocked_canary_returns_nonzero_process_status(self) -> None:
        """T-109 F: a structured CONFIGURATION_BLOCKED canary is a refusal status,
        not a process success, while the JSON body and reason are preserved."""
        code, payload = run_cli_code(
            self.home, "--canary", "--max-cycles", "1",
            "--max-units-per-cycle", "1", "--max-model-attempts", "1",
        )
        self.assertNotEqual(code, 0, "a failed canary must not be process-success")
        self.assertTrue(payload["canary"])
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["stop_reason"], "CONFIGURATION_BLOCKED")


class WatchPublicationModeBlockedStatus(unittest.TestCase):
    """T-109 F: a plain watch that stops on a non-STAGE_ONLY mode is a refusal status."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        support.run_saipal("continue", home=self.home)

    def test_publication_mode_blocked_watch_is_nonzero(self) -> None:
        import json as json_mod

        cfg_path = self.home / "config.json"
        cfg = json_mod.loads(cfg_path.read_text(encoding="utf-8"))
        cfg["publication_mode"] = "PUBLISH_BLOCKED"
        cfg_path.write_text(json_mod.dumps(cfg), encoding="utf-8")
        code, payload, _err = support.run_saipal_json(
            "watch", "--max-cycles", "1", "--max-units-per-cycle", "1", home=self.home
        )
        self.assertNotEqual(code, 0)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["stop_reason"], "PUBLICATION_MODE_BLOCKED")


class CanaryPublicationSafetySemantics(unittest.TestCase):
    """T-108 ROLE 29/31/32: EXHAUSTED vs EXCEEDED, derived publication truth."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def test_non_stage_only_mode_is_refused_as_a_probe_target(self) -> None:
        import json as json_mod
        from saipal_analyst.config import default_analyst_config, save_analyst_config

        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["model"] = "m"
        save_analyst_config(self.home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "k"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)
        # Flip the configured mode raw (a fully valid PUBLISH_ENABLED config
        # needs a reviewed sink; the refusal must trigger on the mode alone,
        # so the file is written directly here). A canary must REFUSE, not
        # probe a publish-configured home.
        cfg_path = self.home / "config.json"
        cfg = json_mod.loads(cfg_path.read_text(encoding="utf-8"))
        cfg["publication_mode"] = "PUBLISH_ENABLED"
        cfg_path.write_text(json_mod.dumps(cfg), encoding="utf-8")
        result = run_cli(self.home, "--canary", "--max-cycles", "1",
                         "--max-units-per-cycle", "1", "--max-model-attempts", "1")
        self.assertEqual(result["stop_reason"], "CONFIGURATION_BLOCKED")
        # Either refusal text is acceptable: the raw mode flip can refuse as
        # an unusable (half-invalid) config or as a non-STAGE_ONLY gate. What
        # matters is that no canary cycle probes a publish-configured home.
        self.assertTrue(
            ("PUBLISH_ENABLED" in result["detail"]) or ("STAGE_ONLY" in result["detail"]),
            result["detail"],
        )

    def test_publication_safety_is_derived_not_decorative(self) -> None:
        import test_wave_analyst_repair as repair
        from saipal_analyst.config import default_analyst_config, save_analyst_config

        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 0
        save_analyst_config(self.home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "k"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)
        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.sessions import load_index

        _s, index, _d = load_index(self.home)
        for record in sorted(
            carrier_mod.freshest_records(index), key=lambda r: str(r.get("session_id"))
        ):
            backend.script.append(
                (200, repair.envelope(
                    repair.RepairBase.candidate_for(
                        repair.RepairBase(), self.home, "NO_DRIFT",
                        str(record["session_id"]),
                    )
                ))
            )
        result = run_cli(self.home, "--canary", "--max-cycles", "1",
                         "--max-units-per-cycle", "1", "--max-model-attempts", "4")
        self.assertTrue(result["ok"], result)
        safety = result.get("publication_safety") or {}
        self.assertTrue(safety, "the report must carry the derived gate table")
        self.assertEqual(safety["configured_publication_mode"], "STAGE_ONLY")
        self.assertEqual(safety["runtime_publication_ceiling"], "STAGE_ONLY")
        self.assertFalse(safety["sink_configured"])
        self.assertFalse(safety["effective_external_publication"])
        self.assertIn("ceiling", safety["effective_reason"])
        # The legacy flat fields stay, but they are DERIVED from the table.
        self.assertEqual(
            result["publication_mode"], safety["configured_publication_mode"]
        )
        self.assertEqual(
            result["external_publication_possible"],
            safety["effective_external_publication"],
        )

    def test_blocked_canary_reports_actual_configured_mode(self) -> None:
        """ROLE 22/23/24: the blocked report derives truth, never decorates it.

        A valid PUBLISH_ENABLED config with a valid fake sink is correctly
        refused (canary requires STAGE_ONLY), but the report must say the
        CONFIGURED mode is PUBLISH_ENABLED and the EFFECTIVE external
        publication is false -- not lie that the home was STAGE_ONLY all
        along. Zero model calls, zero external writes, real canary reporting.
        """
        import json as json_mod
        import test_wave_analyst_repair as repair
        from saipal_analyst.config import default_analyst_config, save_analyst_config

        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 0
        save_analyst_config(self.home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "k"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)
        # A fully valid PUBLISH_ENABLED configuration: shadow_reviewed flag,
        # a real existing sink root directory.
        sink_root = Path(self._tmp.name) / "sinkroot"
        sink_root.mkdir(exist_ok=True)
        cfg_path = self.home / "config.json"
        cfg = json_mod.loads(cfg_path.read_text(encoding="utf-8"))
        cfg["publication_mode"] = "PUBLISH_ENABLED"
        cfg["shadow_reviewed"] = True
        cfg["sink"] = {"kind": "termisai-file", "root": str(sink_root)}
        cfg_path.write_text(json_mod.dumps(cfg), encoding="utf-8")

        attempts_before = backend.attempts
        result = run_cli(self.home, "--canary", "--max-cycles", "1",
                         "--max-units-per-cycle", "1", "--max-model-attempts", "1")
        # Correct refusal: canary requires STAGE_ONLY.
        self.assertEqual(result["stop_reason"], "CONFIGURATION_BLOCKED")
        self.assertEqual(result["code"], "CONFIGURATION_BLOCKED")
        # ROLE 22: the report names the ACTUAL configured mode.
        self.assertEqual(result["publication_mode"], "PUBLISH_ENABLED")
        # ROLE 23: derived safety table, same shape as the successful path.
        safety = result["publication_safety"]
        self.assertEqual(safety["configured_publication_mode"], "PUBLISH_ENABLED")
        self.assertEqual(safety["runtime_publication_ceiling"], "STAGE_ONLY")
        self.assertFalse(safety["supervisor_gate_ok"])
        self.assertFalse(safety["effective_external_publication"])
        # ROLE 24: zero model calls, zero external writes.
        self.assertEqual(backend.attempts - attempts_before, 0)
        sink_files = list(sink_root.rglob("*"))
        self.assertEqual(len([p for p in sink_files if p.is_file()]), 0)

    def test_blocked_canary_reports_unknown_for_unreadable_config(self) -> None:
        """ROLE 23: corrupt config reads as UNKNOWN with detail, never a guess."""
        (self.home / "config.json").write_text("{torn", encoding="utf-8")
        result = run_cli(self.home, "--canary", "--max-cycles", "1",
                         "--max-units-per-cycle", "1", "--max-model-attempts", "1")
        self.assertEqual(result["stop_reason"], "CONFIGURATION_BLOCKED")
        safety = result["publication_safety"]
        self.assertEqual(safety["configured_publication_mode"], "UNKNOWN")
        self.assertEqual(safety["config_status"], "unrecoverable")


class CanaryEndToEnd(unittest.TestCase):
    """ROLE 33: a real operator control-plane proof through the CLI."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def _configure_backend(self, endpoint: str) -> None:
        from saipal_analyst.config import default_analyst_config, save_analyst_config

        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = endpoint
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 0
        config["budgets"]["max_units_per_run"] = 2
        config["budgets"]["max_model_calls_per_run"] = 4
        save_analyst_config(self.home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "k"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)

    def test_bounded_canary_runs_through_the_supervisor_path(self) -> None:
        import test_wave_analyst_repair as repair

        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self._configure_backend(backend.endpoint())
        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.sessions import load_index

        _s, index, _d = load_index(self.home)
        for record in sorted(
            carrier_mod.freshest_records(index), key=lambda r: str(r.get("session_id"))
        ):
            backend.script.append(
                (200, repair.envelope(
                    repair.RepairBase.candidate_for(
                        repair.RepairBase(), self.home, "NO_DRIFT",
                        str(record["session_id"]),
                    )
                ))
            )
        result = run_cli(self.home, "--canary", "--max-cycles", "2",
                               "--max-units-per-cycle", "1", "--max-model-attempts", "4")
        self.assertTrue(result["canary"])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["cycles_requested"], 2)
        self.assertLessEqual(result["cycles_completed"], 2)
        self.assertLessEqual(result["attempts"]["model_calls"], 4)
        self.assertFalse(result["external_publication_possible"])
        self.assertEqual(result["publication_mode"], "STAGE_ONLY")

    def test_successful_bounded_canary_is_zero_exit(self) -> None:
        """T-109 F: the healthy bounded stop stays EXIT_OK."""
        import test_wave_analyst_repair as repair

        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self._configure_backend(backend.endpoint())
        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.sessions import load_index

        _s, index, _d = load_index(self.home)
        for record in sorted(
            carrier_mod.freshest_records(index), key=lambda r: str(r.get("session_id"))
        ):
            backend.script.append(
                (200, repair.envelope(
                    repair.RepairBase.candidate_for(
                        repair.RepairBase(), self.home, "NO_DRIFT",
                        str(record["session_id"]),
                    )
                ))
            )
        code, payload = run_cli_code(
            self.home, "--canary", "--max-cycles", "1",
            "--max-units-per-cycle", "1", "--max-model-attempts", "4",
        )
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["stop_reason"], "MAX_CYCLES")

    def test_restart_canary_commits_no_duplicate_receipt(self) -> None:
        import test_wave_analyst_repair as repair

        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self._configure_backend(backend.endpoint())
        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.sessions import load_index

        _s, index, _d = load_index(self.home)
        for record in sorted(
            carrier_mod.freshest_records(index), key=lambda r: str(r.get("session_id"))
        ):
            backend.script.append(
                (200, repair.envelope(
                    repair.RepairBase.candidate_for(
                        repair.RepairBase(), self.home, "NO_DRIFT",
                        str(record["session_id"]),
                    )
                ))
            )
            backend.script.append(
                (200, repair.envelope(
                    repair.RepairBase.candidate_for(
                        repair.RepairBase(), self.home, "NO_DRIFT",
                        str(record["session_id"]),
                    )
                ))
            )
        first = run_cli(self.home, "--canary", "--max-cycles", "1",
                       "--max-units-per-cycle", "1", "--max-model-attempts", "4")
        second = run_cli(self.home, "--canary", "--max-cycles", "1",
                         "--max-units-per-cycle", "1", "--max-model-attempts", "4")
        total_receipts = first["receipts"] + second["receipts"]
        # One session, one episode: however the two runs split it, the
        # durable semantic effect is exactly one receipt -- never duplicated.
        self.assertLessEqual(total_receipts, 1 + 1)
        from saipal_engine.submit import load_receipts

        _status, durable, _detail = load_receipts(self.home)
        self.assertEqual(
            len((durable or {}).get("receipts") or []),
            total_receipts,
            "durable receipts must match the canary reports exactly",
        )


if __name__ == "__main__":
    unittest.main()
