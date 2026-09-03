"""T-050: the field-aware audit quality gate (PAL-AUDIT-03).

The gate mapped each of the 12 required questions to a SECTION and passed if the
section said anything. Two questions share a section, so a blank `models` field
passed on the strength of a populated `projects` field beside it — the exact
unroutable audit T-049 set out to prevent, waved through by its own gate.

The gate now names the fields that answer each question, and requires all of them.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import audits as audits_mod
from saipal_engine import law as law_mod
from saipal_engine.registry import load_registry

DRIFT = "agent-noncompliance-command-route.json"


def _finding(**overrides) -> dict:
    finding = {
        "finding_id": "PAL-0001",
        "rule_ids": list(law_mod.resolve_law("COMMAND_ROUTE_DRIFT")["rule_ids"]),
        "root_cause": "the command routed outside the closed surface",
        "severity": "P2",
        "confidence": "MEDIUM",
        "change_target": "ENGINE",
        "drift_class": "COMMAND_ROUTE_DRIFT",
        "causal_key": "command outside rout surface",
        "occurrences": [{"session_id": "s1", "episode_id": 0, "event_refs": [1]}],
        "protocol_bindings": [{"binding_status": "BOUND", "version": "7.231.9"}],
        "protected_invariants": ["verify"],
        "harm_warnings": [],
        "disposition_class": "ENGINE_ENFORCEMENT_GAP",
        "analyst_reasoning": "the token is absent from the declared surface",
        "alternatives": ["the adapter mislabelled a shell command"],
        "missing_evidence": ["the registry snapshot at the time"],
    }
    finding.update(overrides)
    return finding


def _record(**overrides) -> dict:
    record = {
        "session_id": "ses_abc",
        "generation": 1,
        "adapter": "opencode",
        "temperature": "COLD",
        "imported_at": "2026-01-01T00:00:00Z",
        "project": {"name": "SAIPAL", "root_fingerprint": "fp1", "git_head": "abc1234"},
        "runtime": {"provider": "openai", "model": "gpt-5", "agent": "build"},
    }
    record.update(overrides)
    return record


class FieldMapping(unittest.TestCase):
    """The mapping is complete and points at fields the builder actually emits."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self.body = audits_mod.build_audit_body(
            _finding(), _record(), {"adapter": "opencode", "protocol": {}},
            registry=self.registry,
        )

    def test_every_question_names_the_fields_that_answer_it(self) -> None:
        for question in audits_mod.QUALITY_QUESTIONS:
            self.assertIn(question, audits_mod._QUESTION_TO_FIELDS, question)
            self.assertTrue(audits_mod._QUESTION_TO_FIELDS[question], question)

    def test_every_named_field_exists_in_the_rendered_body(self) -> None:
        """A gate checking a field the builder never writes would fail forever."""
        for question, fields in audits_mod._QUESTION_TO_FIELDS.items():
            section = audits_mod._QUESTION_TO_SECTION[question]
            block = audits_mod._section_block(self.body, section)
            self.assertIsNotNone(block, section)
            values = audits_mod._field_values(block)
            for name in fields:
                self.assertIn(name, values, f"{question} -> {section}.{name}")

    def test_a_complete_body_answers_every_question(self) -> None:
        self.assertEqual(audits_mod.audit_quality_gate(self.body, _finding()), [])

    def test_field_values_folds_a_multi_line_value(self) -> None:
        block = "\n- binding: {\n  \"version\": \"7.0\"\n}\n- next: x\n"
        values = audits_mod._field_values(block)
        self.assertIn("version", values["binding"])
        self.assertEqual(values["next"], "x")

    def test_field_values_ignores_comments_and_blanks(self) -> None:
        values = audits_mod._field_values("\n<!-- note -->\n\n- a: 1\n")
        self.assertEqual(values, {"a": "1"})


class BlankFieldsAreRefused(unittest.TestCase):
    """One blank field fails its question, even beside a populated neighbour."""

    def setUp(self) -> None:
        self.registry = load_registry()

    def body(self, finding: dict, record: dict, bundle: dict | None = None) -> str:
        return audits_mod.build_audit_body(
            finding, record,
            bundle if bundle is not None else {"adapter": "opencode", "protocol": {}},
            registry=self.registry,
        )

    def test_a_blank_models_field_fails_its_own_question(self) -> None:
        """The T-049 regression, now caught: projects populated, models empty."""
        body = self.body(_finding(), _record(runtime={}), {"adapter": "opencode", "protocol": {}})
        missing = audits_mod.audit_quality_gate(body, _finding())
        self.assertIn("Which model/project/adapter?", missing)
        self.assertNotIn("Where?", missing, "the neighbour question is still answered")

    def test_a_blank_owner_documents_field_fails_which_rule_applied(self) -> None:
        body = self.body(_finding(rule_ids=["PAL-NOT-99"]), _record())
        missing = audits_mod.audit_quality_gate(body, _finding())
        self.assertIn("Which rule applied?", missing)

    def test_missing_rule_ids_fails_which_rule_applied(self) -> None:
        body = self.body(_finding(rule_ids=[]), _record())
        self.assertIn("Which rule applied?", audits_mod.audit_quality_gate(body, _finding()))

    def test_a_blank_protected_invariants_field_fails_do_not_weaken(self) -> None:
        body = self.body(_finding(protected_invariants=[]), _record())
        self.assertIn(
            "What must not be weakened?", audits_mod.audit_quality_gate(body, _finding())
        )

    def test_a_blank_root_cause_fails_several_questions(self) -> None:
        body = self.body(_finding(root_cause=""), _record())
        missing = audits_mod.audit_quality_gate(body, _finding())
        self.assertIn("What was observed?", missing)
        self.assertIn("What happened?", missing)

    def test_a_blank_change_target_fails_the_fix_surface_question(self) -> None:
        body = self.body(_finding(change_target=""), _record())
        self.assertIn(
            "Where is the likely fix surface?",
            audits_mod.audit_quality_gate(body, _finding()),
        )

    def test_an_unknown_placeholder_value_is_not_an_answer(self) -> None:
        body = self.body(_finding(change_target="UNKNOWN"), _record())
        self.assertIn(
            "Where is the likely fix surface?",
            audits_mod.audit_quality_gate(body, _finding()),
        )

    def test_a_missing_section_fails_its_questions(self) -> None:
        body = self.body(_finding(), _record())
        truncated = body.split("## DO NOT WEAKEN")[0]
        self.assertIn(
            "What must not be weakened?",
            audits_mod.audit_quality_gate(truncated, _finding()),
        )

    def test_a_body_failing_any_question_never_passes_the_gate(self) -> None:
        body = self.body(_finding(), _record(runtime={}))
        self.assertFalse(audits_mod.passes_quality_gate(body, _finding()))


class GateHoldsInThePipeline(unittest.TestCase):
    """A real emitted audit satisfies the stricter gate."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_the_drift_fixture_still_emits_one_audit(self) -> None:
        support.put_inbox(self.home, DRIFT)
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["audits_emitted"], 1, "the gate must not block real work")

    def test_the_emitted_audit_passes_the_gate_it_was_built_for(self) -> None:
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)
        staged = sorted((self.home / "audit" / "staging").glob("*.md"))
        self.assertTrue(staged)
        text = staged[0].read_text(encoding="utf-8")
        self.assertEqual(audits_mod.audit_quality_gate(text, {}), [])


if __name__ == "__main__":
    unittest.main()
