"""T-045: the do-no-harm gate as a gate (PAL-DONOHARM-01).

The old gate matched invariant names inside prose and emitted warnings nobody
acted on. Two failures in one: prose is not evidence, and a warning that blocks
nothing is a comment.

The gate now asks a structural question -- does this change surface govern a
protected invariant? -- and blocks the one case that matters: a fix reaching a
protected invariant, undeclared, from a disposition that does not even blame the
protocol. That is what "never weaken a rule because a model failed" means.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import carrier as carrier_mod
from saipal_engine import donoharm
from saipal_engine import findings as findings_mod
from saipal_engine import pipeline as pipeline_mod
from saipal_engine import submit as submit_mod
from saipal_engine.registry import load_registry, require_mapping, require_string_list

CLEAN = "no-finding-normal.json"


class RegistryLaw(unittest.TestCase):
    """The invariant/surface mapping is registry-owned and complete."""

    def setUp(self) -> None:
        self.registry = load_registry()

    def test_every_protected_invariant_declares_its_surfaces(self) -> None:
        invariants = set(require_string_list(self.registry, "protected_invariants"))
        mapping = require_mapping(self.registry, "protected_invariant_surfaces")
        self.assertEqual(set(mapping), invariants)

    def test_every_protected_invariant_declares_its_rules(self) -> None:
        invariants = set(require_string_list(self.registry, "protected_invariants"))
        mapping = require_mapping(self.registry, "protected_invariant_rules")
        self.assertEqual(set(mapping), invariants)

    def test_every_invariant_rule_has_an_owner_document(self) -> None:
        owners = require_mapping(self.registry, "rule_owners")
        mapping = require_mapping(self.registry, "protected_invariant_rules")
        for invariant in mapping:
            for rule in require_string_list(mapping, invariant):
                self.assertIn(rule, owners, f"{invariant} -> {rule}")

    def test_every_declared_surface_is_a_real_change_target(self) -> None:
        targets = set(require_string_list(self.registry, "change_target_enum"))
        mapping = require_mapping(self.registry, "protected_invariant_surfaces")
        for invariant in mapping:
            for surface in require_string_list(mapping, invariant):
                self.assertIn(surface, targets)

    def test_the_legacy_constant_still_matches_the_registry(self) -> None:
        """A caller with no registry must not get a stale invariant list."""
        self.assertEqual(
            set(findings_mod.PROTECTED),
            set(require_string_list(self.registry, "protected_invariants")),
        )

    def test_core_protocol_governs_every_invariant(self) -> None:
        """CORE is where all of them ultimately live; nothing may slip past it."""
        for invariant in require_string_list(self.registry, "protected_invariants"):
            self.assertIn(
                invariant,
                donoharm.invariants_governed_by("CORE_PROTOCOL", registry=self.registry),
            )


class Assessment(unittest.TestCase):
    """warnings vs blocks: the difference is declaring what you are touching."""

    def setUp(self) -> None:
        self.registry = load_registry()

    def assess(self, **finding) -> dict:
        return donoharm.assess(finding, registry=self.registry)

    def test_a_harmless_surface_raises_nothing(self) -> None:
        result = self.assess(change_target="DOCUMENTATION", disposition_class="PROTOCOL_DEFECT")
        self.assertEqual(result, {"warnings": [], "blocks": [], "invariants": []})

    def test_an_engine_change_raises_nothing(self) -> None:
        result = self.assess(change_target="ENGINE", disposition_class="MODEL_NONCOMPLIANCE")
        self.assertEqual(result["invariants"], [])

    def test_a_declared_invariant_warns_rather_than_blocks(self) -> None:
        result = self.assess(
            change_target="SOURCE_CONTRACT",
            disposition_class="PROTOCOL_DEFECT",
            protected_invariants=["source_closure", "provenance"],
        )
        self.assertTrue(result["warnings"])
        self.assertEqual(result["blocks"], [])
        self.assertIn("must confirm", result["warnings"][0])

    def test_an_undeclared_invariant_from_a_protocol_defect_warns(self) -> None:
        """A real protocol defect may reach CORE; it is warned, not silenced."""
        result = self.assess(
            change_target="CORE_PROTOCOL", disposition_class="PROTOCOL_DEFECT"
        )
        self.assertTrue(result["warnings"])
        self.assertEqual(result["blocks"], [])

    def test_an_undeclared_invariant_from_a_model_failure_blocks(self) -> None:
        result = self.assess(
            change_target="CORE_PROTOCOL", disposition_class="MODEL_NONCOMPLIANCE"
        )
        self.assertTrue(result["blocks"])
        self.assertIn("Never weaken", result["blocks"][0])

    def test_a_user_override_reaching_the_execution_policy_blocks(self) -> None:
        result = self.assess(
            change_target="EXECUTION_POLICY", disposition_class="USER_OVERRIDE"
        )
        self.assertTrue(result["blocks"])

    def test_declaring_the_invariant_converts_a_block_into_a_warning(self) -> None:
        """Owning the risk is the difference; the finding is not suppressed."""
        blocked = self.assess(
            change_target="PHASE_CONTRACT", disposition_class="MODEL_NONCOMPLIANCE"
        )
        declared = self.assess(
            change_target="PHASE_CONTRACT",
            disposition_class="MODEL_NONCOMPLIANCE",
            protected_invariants=["verify", "review", "recovery_precedence", "cold_continuation"],
        )
        self.assertTrue(blocked["blocks"])
        self.assertEqual(declared["blocks"], [])
        self.assertTrue(declared["warnings"])

    def test_the_warning_names_the_rules_that_carry_the_invariant(self) -> None:
        result = self.assess(
            change_target="SOURCE_CONTRACT",
            disposition_class="PROTOCOL_DEFECT",
            protected_invariants=["source_closure", "provenance"],
        )
        text = " ".join(result["warnings"])
        self.assertIn("PAL-", text, "a warning must cite the rule it protects")

    def test_invariant_rules_are_reported_for_a_real_invariant(self) -> None:
        self.assertTrue(donoharm.invariant_rules("verify", registry=self.registry))

    def test_invariant_rules_of_an_unknown_invariant_is_empty(self) -> None:
        self.assertEqual(donoharm.invariant_rules("vibes", registry=self.registry), ())


class LifecycleIntegration(unittest.TestCase):
    """The block reaches the lifecycle: BLOCKED, not QUALIFIED, and no audit."""

    def setUp(self) -> None:
        self.registry = load_registry()

    def _finding(self, **overrides) -> dict:
        finding = {
            "finding_id": "PAL-0001",
            "fingerprint": "f" * 32,
            "state": "OBSERVED",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P1",
            "confidence": "HIGH",
            "change_target": "CORE_PROTOCOL",
            "rule_ids": ["PAL-CMD-01"],
            "root_cause": "the route left the closed surface",
            "protected_invariants": [],
            "harm_warnings": [],
            "occurrences": [{"session_id": "s1", "episode_id": 0, "event_refs": [1]}],
            "protocol_bindings": [{"binding_status": "BOUND"}],
            "alternatives": ["adapter noise"],
            "mechanical_confidence": "HIGH",
            "disposition_class": "MODEL_NONCOMPLIANCE",
            "audit": None,
        }
        finding.update(overrides)
        return finding

    def test_a_model_failure_reaching_core_is_blocked_not_qualified(self) -> None:
        finding = self._finding()
        pipeline_mod.advance_to_qualified({}, finding)
        self.assertEqual(finding["state"], "BLOCKED")
        self.assertTrue(finding["harm_blocks"])

    def test_a_blocked_finding_never_passes_the_qualification_threshold(self) -> None:
        finding = self._finding()
        pipeline_mod.advance_to_qualified({}, finding)
        self.assertFalse(
            findings_mod.qualification_threshold(finding, registry=self.registry)
        )

    def test_a_protocol_defect_reaching_core_still_qualifies_with_warnings(self) -> None:
        finding = self._finding(disposition_class="PROTOCOL_DEFECT")
        pipeline_mod.advance_to_qualified({}, finding)
        self.assertEqual(finding["state"], "QUALIFIED")
        self.assertTrue(finding["harm_warnings"])
        self.assertNotIn("harm_blocks", finding)

    def test_a_harmless_surface_qualifies_with_no_warnings(self) -> None:
        finding = self._finding(change_target="ENGINE")
        pipeline_mod.advance_to_qualified({}, finding)
        self.assertEqual(finding["state"], "QUALIFIED")
        self.assertEqual(finding["harm_warnings"], [])

    def test_a_qualified_finding_always_declares_its_invariants(self) -> None:
        finding = self._finding(change_target="ENGINE")
        pipeline_mod.advance_to_qualified({}, finding)
        self.assertTrue(finding["protected_invariants"])


class EndToEnd(unittest.TestCase):
    """Through the real submission boundary: no audit escapes the gate."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, CLEAN)
        support.run_saipal("continue", home=self.home)
        self.carrier = carrier_mod.build_carrier(self.home, registry=self.registry)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def drift(self, **overrides) -> dict:
        unit = self.carrier
        payload = {
            "schema_version": 1,
            "verdict": "DRIFT",
            "unit_digest": unit["unit_digest"],
            "session_id": unit["session"]["session_id"],
            "episode_index": unit["episode"]["index"],
            "disposition_class": "PROTOCOL_DEFECT",
            "reasoning": "the source contract permits an intake that never closes",
            "rule_ids": ["PAL-EVIDENCE-01"],
            "event_refs": [unit["episode"]["start_seq"]],
            "drift_class": "SOURCE_CLOSURE_FALSE_GREEN",
            "severity": "P1",
            "confidence": "HIGH",
            "change_target": "SOURCE_CONTRACT",
            "root_cause": "closure is not required before an episode ends",
            "challenge": {
                "prosecutor": "the contract admits an unclosed intake as green",
                "defender": "the adapter may have dropped the closure event",
                "winner": "prosecutor",
                "loser_rejection": "every later event was recorded, so nothing was dropped",
            },
            "alternatives": ["the adapter dropped the closure event"],
            "protected_invariants": ["source_closure"],
        }
        payload.update(overrides)
        return payload

    def _finding(self, receipt: dict) -> dict:
        findings = json.loads(
            (self.home / "findings" / "index.json").read_text(encoding="utf-8")
        )["findings"]
        return next(f for f in findings if f["finding_id"] == receipt["finding_id"])

    def test_a_declared_protocol_defect_qualifies_and_carries_its_warning(self) -> None:
        receipt = submit_mod.submit_candidate(
            self.home, self.drift(), registry=self.registry
        )
        finding = self._finding(receipt)
        self.assertIn(finding["state"], ("QUALIFIED", "EMITTED"))
        self.assertTrue(finding["harm_warnings"])

    def test_a_legal_engine_fix_from_a_model_failure_proceeds(self) -> None:
        """The contrast case: ENGINE governs no protected invariant, so no gate fires."""
        receipt = submit_mod.submit_candidate(
            self.home,
            self.drift(
                disposition_class="MODEL_NONCOMPLIANCE",
                change_target="ENGINE",
                protected_invariants=[],
            ),
            registry=self.registry,
        )
        finding = self._finding(receipt)
        self.assertNotEqual(finding["state"], "BLOCKED")
        self.assertEqual(finding["harm_warnings"], [])

    def test_an_undeclared_protocol_defect_is_warned_not_blocked(self) -> None:
        receipt = submit_mod.submit_candidate(
            self.home, self.drift(protected_invariants=[]), registry=self.registry
        )
        finding = self._finding(receipt)
        self.assertTrue(finding["harm_warnings"])
        self.assertNotIn("harm_blocks", finding)

    def test_the_two_gates_are_independent_layers_for_one_law(self) -> None:
        """A model failure aimed at a protected surface is refused twice over.

        T-043 refuses it at the candidate boundary, so it never reaches the
        lifecycle. T-045's block is the second layer: if a future candidate path
        skipped that check, the finding still cannot qualify. Both are asserted
        here so removing either one fails a test rather than quietly narrowing
        the law to a single point of enforcement.
        """
        from saipal_engine.errors import PalError

        payload = self.drift(
            disposition_class="MODEL_NONCOMPLIANCE",
            change_target="SOURCE_CONTRACT",
            protected_invariants=[],
        )
        with self.assertRaises(PalError) as raised:
            submit_mod.submit_candidate(self.home, payload, registry=self.registry)
        self.assertEqual(raised.exception.code, "CANDIDATE_INADMISSIBLE")

        smuggled = {
            "change_target": "SOURCE_CONTRACT",
            "disposition_class": "MODEL_NONCOMPLIANCE",
            "protected_invariants": [],
        }
        self.assertTrue(donoharm.assess(smuggled, registry=self.registry)["blocks"])


if __name__ == "__main__":
    unittest.main()
