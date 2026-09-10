"""T-76: the analyst runtime exists outside the kernel, configured fail-closed.

The deterministic kernel must never import the analyst runtime, and the analyst
runtime must never ship a default that silently sends session evidence to a
model endpoint. Both invariants are executable, not documentary: one red control
scans the kernel sources, the rest torture the config schema until it refuses.
"""

from __future__ import annotations

import ast
import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import config as analyst_config
from saipal_analyst.doctor import doctor_report
from saipal_engine.errors import PalError

TOOL_ROOT = support.tool_root()
KERNEL_DIR = TOOL_ROOT / "tools" / "saipal_engine"
SAIPAL_CLI = TOOL_ROOT / "tools" / "saipal.py"


def base_config() -> dict:
    return analyst_config.default_analyst_config()


class KernelStaysModelFree(unittest.TestCase):
    """Layer A never calls a model: the import graph proves it."""

    def test_kernel_never_imports_the_analyst_runtime(self) -> None:
        offenders = [
            path.name
            for path in sorted(KERNEL_DIR.glob("*.py"))
            if "saipal_analyst" in path.read_text(encoding="utf-8")
        ]
        self.assertEqual(offenders, [])

    def test_kernel_has_no_provider_surfaces(self) -> None:
        markers = ("chat/completions", "openai", "api_key")
        offenders = [
            f"{path.name}: {marker}"
            for path in sorted(KERNEL_DIR.glob("*.py"))
            for marker in markers
            if marker in path.read_text(encoding="utf-8").lower()
        ]
        self.assertEqual(offenders, [])

    def test_cli_imports_the_runtime_lazily(self) -> None:
        tree = ast.parse(SAIPAL_CLI.read_text(encoding="utf-8"))
        for node in tree.body:
            names = set()
            if isinstance(node, ast.Import):
                names = {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                names = {node.module or ""}
            self.assertNotIn(
                "saipal_analyst",
                {name.split(".")[0] for name in names},
                "saipal.py must import the analyst runtime lazily",
            )


class ConfigSchema(unittest.TestCase):
    def test_default_is_disabled_and_loopback(self) -> None:
        config = base_config()
        self.assertEqual(analyst_config.validate_analyst_config(config), [])
        self.assertFalse(config["enabled"])
        self.assertFalse(config["egress"]["allow_remote_evidence"])
        self.assertTrue(analyst_config.endpoint_is_local(config["backend"]["endpoint"]))
        self.assertEqual(config["backend"]["api_key_env"], "SAIPAL_ANALYST_API_KEY")

    def test_unknown_top_level_field_rejected(self) -> None:
        config = base_config()
        config["publish"] = True
        self.assertIn(
            "unknown analyst config field 'publish'",
            analyst_config.validate_analyst_config(config),
        )

    def test_unknown_nested_fields_rejected(self) -> None:
        config = base_config()
        config["backend"]["api_key"] = "sk-super-secret"
        config["backend"]["tools"] = [{"type": "shell"}]
        config["egress"]["allowed_hosts"] = ["*"]
        config["budgets"]["max_dollars"] = 5
        config["deliberation"]["auto_approve"] = True
        problems = analyst_config.validate_analyst_config(config)
        for fragment in (
            "backend has unknown field 'api_key'",
            "backend has unknown field 'tools'",
            "egress has unknown field 'allowed_hosts'",
            "budgets has unknown field 'max_dollars'",
            "deliberation has unknown field 'auto_approve'",
        ):
            self.assertIn(fragment, problems)
        # The secret key never survives anywhere near a stored shape.
        self.assertNotIn("api_key", base_config()["backend"])

    def test_invalid_backend_type_and_endpoint_rejected(self) -> None:
        config = base_config()
        config["backend"]["type"] = "anthropic_native"
        self.assertIn(
            "backend.type 'anthropic_native' outside ['openai_compatible']",
            analyst_config.validate_analyst_config(config),
        )
        config = base_config()
        config["backend"]["endpoint"] = "ftp://example.invalid/v1"
        self.assertIn(
            "backend.endpoint must be an absolute http(s) URL",
            analyst_config.validate_analyst_config(config),
        )
        config = base_config()
        config["enabled"] = True
        config["backend"]["model"] = "  "
        self.assertIn(
            "backend.model must be a non-empty string",
            analyst_config.validate_analyst_config(config),
        )

    def test_api_key_env_must_be_a_name(self) -> None:
        config = base_config()
        config["backend"]["api_key_env"] = "not an env name"
        self.assertIn(
            "backend.api_key_env must be an environment variable NAME",
            analyst_config.validate_analyst_config(config),
        )

    def test_budgets_must_be_explicit_and_positive(self) -> None:
        config = base_config()
        del config["budgets"]["max_wall_seconds"]
        self.assertIn(
            "budgets.max_wall_seconds must be a positive number",
            analyst_config.validate_analyst_config(config),
        )
        config = base_config()
        config["budgets"]["max_units_per_run"] = 0
        config["budgets"]["max_retries_per_unit"] = -1
        problems = analyst_config.validate_analyst_config(config)
        self.assertIn("budgets.max_units_per_run must be a positive integer", problems)
        self.assertIn("budgets.max_retries_per_unit must be a positive integer", problems)

    def test_temperature_and_sample_bounds(self) -> None:
        config = base_config()
        config["backend"]["temperature"] = 9.5
        self.assertIn(
            "backend.temperature must be a number between 0 and 2",
            analyst_config.validate_analyst_config(config),
        )
        config = base_config()
        config["deliberation"]["clean_sample_percent"] = 101
        self.assertIn(
            "deliberation.clean_sample_percent must be an integer 0..100",
            analyst_config.validate_analyst_config(config),
        )


class LocalEndpointPolicy(unittest.TestCase):
    def test_loopback_hosts_are_local(self) -> None:
        for endpoint in (
            "http://localhost:8080/v1/chat/completions",
            "http://127.0.0.1:11434/v1/chat/completions",
            "http://127.9.9.9:1/x",
            "http://[::1]:8000/v1/chat/completions",
        ):
            self.assertTrue(analyst_config.endpoint_is_local(endpoint), endpoint)

    def test_lan_and_named_hosts_are_not_local(self) -> None:
        for endpoint in (
            "http://192.168.1.10:8080/v1/chat/completions",
            "http://10.0.0.5/v1/chat/completions",
            "http://172.16.0.1/v1/chat/completions",
            "http://my-box.lan:8080/v1/chat/completions",
            "http://[fe80::1]/v1/chat/completions",
            "not a url",
        ):
            self.assertFalse(analyst_config.endpoint_is_local(endpoint), endpoint)

    def test_egress_refusal_names_endpoint_and_flag(self) -> None:
        config = base_config()
        config["backend"]["endpoint"] = "http://api.example.invalid/v1/chat/completions"
        allowed, detail = analyst_config.egress_verdict(config)
        self.assertFalse(allowed)
        self.assertIn("api.example.invalid", detail)
        self.assertIn("allow_remote_evidence", detail)

        config["egress"]["allow_remote_evidence"] = True
        allowed, detail = analyst_config.egress_verdict(config)
        self.assertTrue(allowed)
        self.assertEqual(detail, "")


class PersistedConfig(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = support.make_home(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_absent_config_is_absent_not_default(self) -> None:
        status, payload, _detail = analyst_config.load_analyst_config(self.home)
        self.assertEqual(status, "absent")
        self.assertIsNone(payload)

    def test_save_then_load_roundtrip(self) -> None:
        analyst_config.save_analyst_config(self.home, base_config())
        status, payload, _detail = analyst_config.load_analyst_config(self.home)
        self.assertEqual(status, "ok")
        self.assertEqual(payload, base_config())

    def test_save_refuses_invalid_and_writes_nothing(self) -> None:
        config = base_config()
        config["enabled"] = "yes"
        with self.assertRaises(PalError):
            analyst_config.save_analyst_config(self.home, config)
        self.assertFalse(analyst_config.analyst_config_path(self.home).exists())

    def test_unreadable_config_is_unrecoverable(self) -> None:
        path = analyst_config.analyst_config_path(self.home)
        path.write_text("{not json", encoding="utf-8")
        status, _payload, detail = analyst_config.load_analyst_config(self.home)
        self.assertEqual(status, "unrecoverable")
        self.assertIn("unreadable", detail)


class Doctor(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def doctor(self) -> dict:
        return doctor_report(self.home, registry=support.load_registry_copy())

    def test_absent_config_reports_and_mutates_nothing(self) -> None:
        before = support.tree_digest(self.home)
        report = self.doctor()
        self.assertFalse(report["ok"])
        self.assertIn("absent", report["config_problems"][0])
        self.assertEqual(support.tree_digest(self.home), before)

    def test_disabled_config_is_healthy(self) -> None:
        analyst_config.save_analyst_config(self.home, base_config())
        report = self.doctor()
        self.assertTrue(report["ok"])
        self.assertFalse(report["enabled"])
        self.assertTrue(report["endpoint_local"])
        self.assertFalse(report["api_key_env_present"])

    def test_enabled_without_key_reports_env_not_value(self) -> None:
        config = base_config()
        config["enabled"] = True
        config["backend"]["model"] = "stub-model"
        analyst_config.save_analyst_config(self.home, config)
        report = self.doctor()
        self.assertFalse(report["ok"])
        self.assertIn("SAIPAL_ANALYST_API_KEY", report["config_problems"][0])
        self.assertIn("is not set", report["config_problems"][0])
        # The report knows presence, never value.
        self.assertFalse(report["api_key_env_present"])
        self.assertNotIn("sk-", json.dumps(report))

    def test_remote_endpoint_fails_doctor_without_flag(self) -> None:
        config = base_config()
        config["backend"]["endpoint"] = "http://api.example.invalid/v1/chat/completions"
        config["backend"]["model"] = "stub-model"
        analyst_config.save_analyst_config(self.home, config)
        report = self.doctor()
        self.assertFalse(report["ok"])
        self.assertFalse(report["endpoint_local"])
        self.assertIn("allow_remote_evidence", report["config_problems"][0])

    def test_enabled_remote_requires_key_and_flag_together(self) -> None:
        config = base_config()
        config["enabled"] = True
        config["backend"]["model"] = "stub-model"
        config["backend"]["endpoint"] = "http://api.example.invalid/v1/chat/completions"
        analyst_config.save_analyst_config(self.home, config)
        problems = " | ".join(self.doctor()["config_problems"])
        self.assertIn("SAIPAL_ANALYST_API_KEY", problems)
        self.assertIn("allow_remote_evidence", problems)


class CliSurface(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_setup_creates_disabled_config(self) -> None:
        code, _out, err = support.run_saipal("analyst-setup", home=self.home)
        self.assertEqual(code, 0, err)
        status, payload, _detail = analyst_config.load_analyst_config(self.home)
        self.assertEqual(status, "ok")
        self.assertFalse(payload["enabled"])

    def test_second_setup_changes_nothing(self) -> None:
        support.run_saipal("analyst-setup", home=self.home)
        code, out, _err = support.run_saipal("analyst-setup", home=self.home)
        self.assertEqual(code, 0)
        self.assertIn("present", out)
        self.assertIn("no change", out)

    def test_enable_refused_without_model(self) -> None:
        support.run_saipal("analyst-setup", home=self.home)
        code, _out, _err = support.run_saipal(
            "analyst-setup", "--enable", home=self.home
        )
        self.assertEqual(code, 1)
        status, payload, _detail = analyst_config.load_analyst_config(self.home)
        self.assertEqual(status, "ok")
        self.assertFalse(payload["enabled"], "a failed enable must not half-write")

    def test_enable_with_model_persists(self) -> None:
        support.run_saipal("analyst-setup", home=self.home)
        path = analyst_config.analyst_config_path(self.home)
        config = json.loads(path.read_text(encoding="utf-8"))
        config["backend"]["model"] = "stub-model"
        path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        code, _out, err = support.run_saipal(
            "analyst-setup", "--enable", home=self.home
        )
        self.assertEqual(code, 0, err)
        _status, payload, _d = analyst_config.load_analyst_config(self.home)
        self.assertTrue(payload["enabled"])

    def test_setup_rejects_unknown_option(self) -> None:
        code, _out, _err = support.run_saipal("analyst-setup --explode", home=self.home)
        self.assertEqual(code, 2)

    def test_doctor_exit_codes_follow_health(self) -> None:
        code, _out, _err = support.run_saipal("analyst-doctor", home=self.home)
        self.assertEqual(code, 1)
        support.run_saipal("analyst-setup", home=self.home)
        code, _out, _err = support.run_saipal("analyst-doctor", home=self.home)
        self.assertEqual(code, 0)
        _code, payload, _err = support.run_saipal_json("analyst-doctor", home=self.home)
        self.assertEqual(_code, 0)
        self.assertTrue(payload["ok"])

    def test_doctor_never_mutates_the_home(self) -> None:
        support.run_saipal("analyst-setup", home=self.home)
        before = support.tree_digest(self.home)
        support.run_saipal("analyst-doctor", home=self.home)
        self.assertEqual(support.tree_digest(self.home), before)

    def test_setup_never_touches_publication_config(self) -> None:
        support.run_saipal("setup", "--mode", "PUBLISH_BLOCKED", home=self.home)
        support.run_saipal("analyst-setup", home=self.home)
        from saipal_engine.config import load_config

        _status, payload, _detail = load_config(self.home)
        self.assertEqual(payload["publication_mode"], "PUBLISH_BLOCKED")


if __name__ == "__main__":
    unittest.main()
