"""T-051: cross-model / cross-project recurrence as a decision (PAL-FINDING-02).

Recurrence tables existed and nothing read them. That leaves the most important
distinction in the whole system unmade: one model drifting where another complied
under the same rule is evidence about that model, while the same drift across
several models under one protocol version is evidence about the protocol.

Get it wrong in the second direction and real defects stay open. Get it wrong in
the first and a correct rule gets relaxed because a model ignored it.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import audits as audits_mod
from saipal_engine import carrier as carrier_mod
from saipal_engine import recurrence as recurrence_mod
from saipal_engine import submit as submit_mod
from saipal_engine.registry import load_registry

DRIFT_CLASS = "COMMAND_ROUTE_DRIFT"
CLEAN = "no-finding-normal.json"


def _occurrence(model: str, project: str, *, conformant: bool, session: str) -> dict:
    return {
        "session_id": session,
        "adapter": model,
        "provider": "openai",
        "model_family": model,
        "project": project,
        "protocol_version": "7.231.9",
        "drift_class": DRIFT_CLASS,
        "confidence": "MEDIUM",
        "severity": "P2",
        "conformant": conformant,
        "imported_at": "2026-01-01T00:00:00Z",
    }


def _ledger(*occurrences: dict) -> dict:
    return {
        "schema_version": 1,
        "by_finding": {
            "fp1": {
                "finding_id": "PAL-0001",
                "fingerprint": "fp1",
                "causal_key": "command outside rout surface",
                "drift_class": DRIFT_CLASS,
                "severity": "P2",
                "confidence": "MEDIUM",
                "last_fix_version": "",
                "occurrences": list(occurrences),
            }
        },
        "by_rule": {},
    }


class SpreadClassification(unittest.TestCase):
    """The verdict, over every arrangement that changes the answer."""

    def spread(self, *occurrences: dict) -> dict:
        return recurrence_mod.spread(_ledger(*occurrences), DRIFT_CLASS)

    def test_no_occurrences_is_unknown(self) -> None:
        result = recurrence_mod.spread(_ledger(), DRIFT_CLASS)
        self.assertEqual(result["classification"], "UNKNOWN")
        self.assertIn("no drift occurrences", result["guidance"])

    def test_a_conformant_only_ledger_is_unknown(self) -> None:
        result = self.spread(_occurrence("gpt", "alpha", conformant=True, session="s1"))
        self.assertEqual(result["classification"], "UNKNOWN")

    def test_one_model_one_project_is_single_model(self) -> None:
        result = self.spread(_occurrence("gpt", "alpha", conformant=False, session="s1"))
        self.assertEqual(result["classification"], "SINGLE_MODEL")
        self.assertTrue(result["isolated_to_one_model"])
        self.assertFalse(result["contradicted_by_a_clean_model"])

    def test_two_drifting_models_is_cross_model(self) -> None:
        result = self.spread(
            _occurrence("gpt", "alpha", conformant=False, session="s1"),
            _occurrence("claude", "alpha", conformant=False, session="s2"),
        )
        self.assertEqual(result["classification"], "CROSS_MODEL")
        self.assertEqual(result["drifting_models"], ["claude", "gpt"])
        self.assertIn("protocol or its executable enforcement", result["guidance"])

    def test_one_model_across_projects_is_cross_project(self) -> None:
        result = self.spread(
            _occurrence("gpt", "alpha", conformant=False, session="s1"),
            _occurrence("gpt", "beta", conformant=False, session="s2"),
        )
        self.assertEqual(result["classification"], "CROSS_PROJECT")
        self.assertIn("that model's guidance", result["guidance"])

    def test_many_models_and_projects_is_cross_both(self) -> None:
        result = self.spread(
            _occurrence("gpt", "alpha", conformant=False, session="s1"),
            _occurrence("claude", "beta", conformant=False, session="s2"),
        )
        self.assertEqual(result["classification"], "CROSS_MODEL_AND_PROJECT")

    def test_a_clean_model_beside_a_drifting_one_is_the_decisive_case(self) -> None:
        """The distinction that stops a correct rule being relaxed."""
        result = self.spread(
            _occurrence("gpt", "alpha", conformant=False, session="s1"),
            _occurrence("claude", "alpha", conformant=True, session="s2"),
        )
        self.assertEqual(result["classification"], "SINGLE_MODEL")
        self.assertTrue(result["contradicted_by_a_clean_model"])
        self.assertEqual(result["clean_models"], ["claude"])
        self.assertIn("model noncompliance", result["guidance"])
        self.assertIn("over changing the protocol", result["guidance"])

    def test_a_lone_model_with_no_comparison_says_so(self) -> None:
        result = self.spread(_occurrence("gpt", "alpha", conformant=False, session="s1"))
        self.assertIn("no comparison available", result["guidance"])
        self.assertIn("unproven", result["guidance"])

    def test_occurrence_count_reflects_only_drift(self) -> None:
        result = self.spread(
            _occurrence("gpt", "alpha", conformant=False, session="s1"),
            _occurrence("gpt", "alpha", conformant=True, session="s2"),
        )
        self.assertEqual(result["occurrences"], 1)

    def test_another_drift_class_is_not_counted(self) -> None:
        ledger = _ledger(_occurrence("gpt", "alpha", conformant=False, session="s1"))
        result = recurrence_mod.spread(ledger, "PHASE_SKIP")
        self.assertEqual(result["classification"], "UNKNOWN")


class CarrierCarriesTheSpread(unittest.TestCase):
    """The analyst reasons from the spread, so the carrier must hand it over."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, CLEAN)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_the_carrier_reports_a_spread_verdict(self) -> None:
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertIn("spread", unit["recurrence"])
        self.assertIn("classification", unit["recurrence"]["spread"])

    def test_the_carrier_still_validates(self) -> None:
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertEqual(carrier_mod.carrier_problems(unit, registry=self.registry), [])

    def test_an_empty_ledger_yields_an_unknown_spread(self) -> None:
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertEqual(unit["recurrence"]["spread"]["classification"], "UNKNOWN")


class SpreadTravelsToTheAudit(unittest.TestCase):
    """What the analyst reasoned against is what the audit records."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, CLEAN)
        support.run_saipal("continue", home=self.home)
        self.unit = carrier_mod.build_carrier(self.home, registry=self.registry)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def drift(self, **overrides) -> dict:
        payload = {
            "schema_version": 1,
            "verdict": "DRIFT",
            "unit_digest": self.unit["unit_digest"],
            "session_id": self.unit["session"]["session_id"],
            "episode_index": self.unit["episode"]["index"],
            "disposition_class": "ENGINE_ENFORCEMENT_GAP",
            "reasoning": "the engine accepted a route outside the closed surface",
            "rule_ids": ["PAL-CMD-01"],
            "event_refs": [self.unit["episode"]["start_seq"]],
            "drift_class": DRIFT_CLASS,
            "severity": "P2",
            "confidence": "MEDIUM",
            "change_target": "ENGINE",
            "root_cause": "the closed command surface was not consulted",
            "challenge": {
                "prosecutor": "PAL-CMD-01 names the surface; this route is not in it",
                "defender": "the adapter may have mislabelled a shell command",
                "winner": "prosecutor",
                "loser_rejection": "the adapter recorded a canonical protocol token",
            },
            "alternatives": ["the adapter mislabelled a shell command"],
        }
        payload.update(overrides)
        return payload

    def test_the_finding_records_the_spread_it_was_judged_against(self) -> None:
        import json

        receipt = submit_mod.submit_candidate(
            self.home, self.drift(), registry=self.registry
        )
        findings = json.loads(
            (self.home / "findings" / "index.json").read_text(encoding="utf-8")
        )["findings"]
        finding = next(f for f in findings if f["finding_id"] == receipt["finding_id"])
        self.assertIn("recurrence_spread", finding)
        self.assertIn("classification", finding["recurrence_spread"])

    def test_the_audit_body_renders_the_spread_and_its_guidance(self) -> None:
        body = audits_mod.build_audit_body(
            {
                "finding_id": "PAL-0001",
                "rule_ids": ["PAL-CMD-01"],
                "root_cause": "the closed command surface was not consulted",
                "severity": "P2",
                "confidence": "MEDIUM",
                "change_target": "ENGINE",
                "drift_class": DRIFT_CLASS,
                "occurrences": [{"session_id": "s1", "episode_id": 0, "event_refs": [1]}],
                "protocol_bindings": [{"binding_status": "BOUND"}],
                "protected_invariants": ["verify"],
                "harm_warnings": [],
                "recurrence_spread": recurrence_mod.spread(
                    _ledger(
                        _occurrence("gpt", "alpha", conformant=False, session="s1"),
                        _occurrence("claude", "alpha", conformant=True, session="s2"),
                    ),
                    DRIFT_CLASS,
                ),
            },
            {"session_id": "s1", "imported_at": "2026-01-01T00:00:00Z",
             "runtime": {"provider": "openai", "model": "gpt"},
             "project": {"name": "alpha"}},
            {"adapter": "generic", "protocol": {}},
            registry=self.registry,
        )
        self.assertIn("SINGLE_MODEL", body)
        self.assertIn("compliant: claude", body)
        self.assertIn("model noncompliance", body)

    def test_an_absent_spread_renders_empty_rather_than_guessing(self) -> None:
        body = audits_mod.build_audit_body(
            {
                "finding_id": "PAL-0002",
                "rule_ids": ["PAL-CMD-01"],
                "root_cause": "x",
                "occurrences": [],
                "protocol_bindings": [{"binding_status": "BOUND"}],
                "protected_invariants": ["verify"],
                "harm_warnings": [],
            },
            {"session_id": "s1", "imported_at": "2026-01-01T00:00:00Z"},
            {"adapter": "generic", "protocol": {}},
            registry=self.registry,
        )
        self.assertIn("- spread:\n", body)


class LiveLedger(unittest.TestCase):
    """Recorded occurrences drive the same verdict through the real ledger."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_two_models_recorded_live_classify_as_cross_model(self) -> None:
        finding = {
            "finding_id": "PAL-0001",
            "fingerprint": "fp-live",
            "causal_key": "command outside rout surface",
            "drift_class": DRIFT_CLASS,
            "severity": "P2",
            "confidence": "MEDIUM",
        }
        for model, session in (("gpt", "s1"), ("claude", "s2")):
            recurrence_mod.record_occurrence(
                self.home,
                finding,
                {
                    "session_id": session,
                    "adapter": model,
                    "runtime": {"provider": "openai"},
                    "project": {"name": "alpha"},
                    "conformant": False,
                },
            )
        data = recurrence_mod.load_recurrence(self.home)
        result = recurrence_mod.spread(data, DRIFT_CLASS)
        self.assertEqual(result["classification"], "CROSS_MODEL")
        self.assertEqual(result["drifting_models"], ["claude", "gpt"])


if __name__ == "__main__":
    unittest.main()
