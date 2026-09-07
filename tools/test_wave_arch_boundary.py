"""T-032: the semantic architecture boundary (ARCHITECTURE.md).

Layer A (deterministic kernel) never calls provider-specific semantic logic.
Layer B (replaceable analyst agent) never writes arbitrary project files — it
submits structured candidates back to Layer A through a constrained boundary.

This test proves the boundary is structural, not documentary.
"""

from __future__ import annotations

import ast
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pal_test_support as support
import saipal
from saipal_engine import capability
from saipal_engine.registry import load_registry, require_mapping, require_string_list

_ENGINE = Path(__file__).resolve().parent / "saipal_engine"
_PROTOCOL = Path(__file__).resolve().parent.parent / "saipal"


class LayerABoundary(unittest.TestCase):
    """Layer A and Layer B are structurally separated."""

    def setUp(self) -> None:
        self.registry = load_registry()

    def test_analyst_py_is_a_signal_generator_not_semantic(self) -> None:
        """analyst.py docstring must declare itself a signal generator, not a
        semantic analyst. The deterministic detector pass is useful, but it
        is NOT the real semantic analyst."""
        path = _ENGINE / "analyst.py"
        text = path.read_text(encoding="utf-8")
        self.assertIn(
            "signal generator", text,
            "analyst.py must declare its role as signal generator",
        )
        self.assertIn(
            "NOT a semantic analyst", text,
            "analyst.py must not claim to be the semantic analyst",
        )

    def test_no_provider_specific_imports_in_kernel_modules(self) -> None:
        """Layer A kernel modules must not import provider-specific semantic
        logic (openai, anthropic, google.generativeai, etc). Adapters are the
        only provider-facing surface, and they normalize into the canonical
        form — they do not embed semantic reasoning."""
        provider_patterns = (
            "import openai",
            "import anthropic",
            "import google.generativeai",
            "from openai",
            "from anthropic",
            "from google.generativeai",
            "import vertexai",
            "from vertexai",
        )
        skip = {"adapters", "__pycache__", ".pytest_cache"}
        for path in _ENGINE.rglob("*.py"):
            if any(part in skip for part in path.parts):
                continue
            if "adapters" in path.parts:
                continue  # adapters are the provider-facing surface
            text = path.read_text(encoding="utf-8")
            for pattern in provider_patterns:
                self.assertNotIn(
                    pattern, text,
                    f"{path.name} must not import provider logic ({pattern})",
                )

    def test_analyst_module_has_no_file_writes(self) -> None:
        """The signal generator (analyst.py) must not write files. It returns
        structured data; the pipeline (Layer A) decides what to persist."""
        path = _ENGINE / "analyst.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute):
                    method = func.attr
                    self.assertNotIn(
                        method, ("write", "open"),
                        f"analyst.py must not call .{method}() — it returns data, not files",
                    )

    def test_capability_boundary_allows_only_kernel_writes(self) -> None:
        """Layer B has zero direct writes; submission and enqueue are distinct."""
        kernel = require_mapping(self.registry, "write_actions")
        analyst = require_mapping(self.registry, "analyst_actions")
        kernel_allowed = set(kernel["allowed"])
        analyst_allowed = set(analyst["allowed"])
        analyst_forbidden = set(analyst["forbidden"])

        self.assertEqual(
            analyst_allowed,
            {"read_carrier", "read_evidence", "submit_candidate"},
        )
        self.assertIn("enqueue_audit", kernel_allowed)
        self.assertNotIn("enqueue_audit", analyst_allowed)
        self.assertIn("enqueue_audit", analyst_forbidden)
        self.assertFalse(analyst_allowed & kernel_allowed)

        for action in ("write_own_state", "write_own_index", "write_own_log"):
            self.assertIn(action, kernel_allowed)
            self.assertIn(action, analyst_forbidden)

        # Everything that touches the analyzed project or SAIPEN Core is forbidden
        forbidden = set(kernel["forbidden"])
        for action in (
            "mutate_analyzed_project",
            "mutate_saipen_state",
            "edit_saipen_protocol",
            "edit_emitted_audit",
            "delete_emitted_audit",
        ):
            self.assertIn(action, forbidden)

    def test_every_cmd_next_carrier_is_registry_owned(self) -> None:
        """Exercise every branch: emitted carrier set equals the registry enum."""
        carriers = set(require_string_list(self.registry, "next_carriers"))
        base = {
            "home": "X", "phase": "IDLE", "sources": 0, "sessions": 0,
            "current_session": None, "current_candidate": None,
            "sessions_conflict": 0,
        }
        scenarios = (
            {},
            {"current_session": "s1"},
            {"current_candidate": "c1"},
            {"sessions_conflict": 1},
            {"sessions": 1},
            {"sources": 1},
        )
        # The analyze-episodes pick is refined by the analysis carrier (T-040):
        # "sessions are indexed" only means analysis work if an episode is
        # actually pending, so the builder is stubbed to report one here. The
        # mechanical pick table is what this test owns.
        pending = {
            "carrier": "analyze-episodes",
            "session": {"session_id": "s1"},
            "episode": {"index": 0},
        }
        emitted = set()
        for changes in scenarios:
            payload = {**base, **changes}
            with mock.patch.object(saipal, "_load_read_only", return_value=payload):
                with mock.patch(
                    "saipal_engine.carrier.build_carrier", return_value=pending
                ):
                    _code, result = saipal.cmd_next(Path("X"), self.registry)
            emitted.add(result["carrier"])
        self.assertEqual(emitted, carriers)

    def test_exact_skill_json_next_command_executes(self) -> None:
        """Red control: execute the exact canonical command printed by SKILL."""
        skill = (_PROTOCOL / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("carrier = saipal --json next", skill)
        with tempfile.TemporaryDirectory() as td:
            home = support.make_home(Path(td))
            support.run_saipal("continue", home=home)
            code, out, err = support.run_saipal("--json", "next", home=home)
        self.assertEqual(code, 0, err)
        self.assertIn(json.loads(out)["carrier"], self.registry["next_carriers"])

    def test_architecture_doc_exists_and_owns_the_boundary(self) -> None:
        """ARCHITECTURE.md must exist and declare the two-layer boundary."""
        path = _PROTOCOL / "ARCHITECTURE.md"
        self.assertTrue(path.exists(), "ARCHITECTURE.md must exist")
        text = path.read_text(encoding="utf-8")
        self.assertIn("Layer A", text)
        self.assertIn("Layer B", text)
        self.assertIn("signal generator", text)
        self.assertIn("replaceable analyst agent", text)
        self.assertIn("submit_candidate", text)
        self.assertIn("cannot call `enqueue_audit` directly", text)

    def test_installed_skill_manifest_is_the_detective_loop(self) -> None:
        """The Freebuff-installable skill (`skills/saipal/SKILL.md`) must stay
        the canonical detective + reporter loop: frontmatter for `/saipal`
        routing, the exact next/submit commands, and the honesty rules that
        keep a report from overclaiming."""
        skill = Path(__file__).resolve().parent.parent / "skills" / "saipal" / "SKILL.md"
        self.assertTrue(skill.exists(), "skills/saipal/SKILL.md must exist")
        text = skill.read_text(encoding="utf-8")
        self.assertIn("name: saipal", text)
        self.assertIn('Trigger on "saipal"', text)
        for command in (
            "saipal.py cc",
            "saipal.py --json next",
            "saipal.py --json submit candidate.json",
            "saipal.py report",
        ):
            self.assertIn(command, text, f"the skill must name {command}")
        for honesty in ("DRIFT_SUSPECTED", "NOT_EXAMINED", "NO_DRIFT", "owner"):
            self.assertIn(honesty, text, f"the skill must bind {honesty}")

    def test_manifest_lists_architecture_doc(self) -> None:
        """The runtime manifest must list ARCHITECTURE.md and agent protocol docs."""
        import json
        manifest_path = _PROTOCOL / "MANIFEST.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        files = {entry["src"] for entry in manifest.get("files", [])}
        self.assertIn("saipal/ARCHITECTURE.md", files)
        self.assertIn("saipal/SKILL.md", files)
        self.assertIn("saipal/INDEX.md", files)
        self.assertIn("saipal/ANALYSIS.md", files)

    def test_agent_protocol_docs_exist_and_own_rules(self) -> None:
        """SKILL.md, INDEX.md, ANALYSIS.md must exist and declare rules."""
        for name, rule in (
            ("SKILL.md", "PAL-SKILL-01"),
            ("INDEX.md", "PAL-INDEX-01"),
            ("ANALYSIS.md", "PAL-ANALYSIS-01"),
        ):
            path = _PROTOCOL / name
            self.assertTrue(path.exists(), f"{name} must exist")
            text = path.read_text(encoding="utf-8")
            self.assertIn(rule, text, f"{name} must declare {rule}")

    def test_disposition_class_enum_in_registry(self) -> None:
        """The disposition_class enum must be in the registry."""
        classes = self.registry.get("disposition_class", [])
        self.assertEqual(len(classes), 10)
        self.assertIn("PROTOCOL_DEFECT", classes)
        self.assertIn("NO_DRIFT", classes)
        self.assertIn("MODEL_NONCOMPLIANCE", classes)
        self.assertIn("USER_OVERRIDE", classes)
        self.assertIn("ENVIRONMENT_FAILURE", classes)


if __name__ == "__main__":
    unittest.main()
