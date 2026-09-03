"""T-043: disposition-class separation, enforced (PAL-ANALYSIS-03).

The taxonomy says what was seen. The disposition says what kind of defect it is.
The whole value of the distinction is that it stops one specific failure: a model
ignoring a clear rule, and the resulting audit proposing that the rule be relaxed.

These tests are the executable form of "never legalize a model failure by
weakening a correct safety rule".
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import candidates as cand_mod
from saipal_engine import carrier as carrier_mod
from saipal_engine import disposition as disp
from saipal_engine import submit as submit_mod
from saipal_engine.errors import PalError
from saipal_engine.registry import load_registry, require_mapping, require_string_list

CLEAN = "no-finding-normal.json"


class RegistryLaw(unittest.TestCase):
    """The mapping is registry-owned, complete and internally consistent."""

    def setUp(self) -> None:
        self.registry = load_registry()

    def test_every_disposition_class_declares_its_change_surfaces(self) -> None:
        classes = set(require_string_list(self.registry, "disposition_class"))
        mapping = require_mapping(self.registry, "disposition_change_targets")
        self.assertEqual(set(mapping), classes, "every class needs a target list")

    def test_every_declared_target_is_in_the_change_target_enum(self) -> None:
        targets = set(require_string_list(self.registry, "change_target_enum"))
        mapping = require_mapping(self.registry, "disposition_change_targets")
        for name in mapping:
            for target in require_string_list(mapping, name):
                self.assertIn(target, targets, f"{name} -> {target}")

    def test_non_drift_dispositions_are_real_classes(self) -> None:
        classes = set(require_string_list(self.registry, "disposition_class"))
        for name in disp.non_drift_dispositions(registry=self.registry):
            self.assertIn(name, classes)

    def test_no_non_drift_disposition_can_reach_a_protocol_surface(self) -> None:
        """The structural guarantee, checked over the whole table."""
        mapping = require_mapping(self.registry, "disposition_change_targets")
        for name in disp.weakening_dispositions(registry=self.registry):
            allowed = set(require_string_list(mapping, name))
            overlap = allowed & disp.PROTOCOL_SURFACES
            self.assertFalse(
                overlap,
                f"{name} may not be allowed to change {sorted(overlap)}",
            )

    def test_only_protocol_defect_may_reach_core_protocol(self) -> None:
        mapping = require_mapping(self.registry, "disposition_change_targets")
        reaching = {
            name
            for name in mapping
            if "CORE_PROTOCOL" in require_string_list(mapping, name)
        }
        self.assertEqual(reaching, {"PROTOCOL_DEFECT"})

    def test_preferred_target_names_the_redirect(self) -> None:
        self.assertEqual(
            disp.preferred_target("MODEL_NONCOMPLIANCE", registry=self.registry), "ENGINE"
        )
        self.assertEqual(
            disp.preferred_target("USER_OVERRIDE", registry=self.registry), "NO_CHANGE"
        )
        self.assertEqual(
            disp.preferred_target("not-a-class", registry=self.registry), "UNKNOWN"
        )


class Gate(unittest.TestCase):
    """The three confusions, refused by name."""

    def setUp(self) -> None:
        self.registry = load_registry()

    def problems(self, verdict: str, disposition: str, target: str | None) -> list[str]:
        return disp.disposition_problems(
            verdict, disposition, target, registry=self.registry
        )

    def test_a_protocol_defect_may_change_the_protocol(self) -> None:
        self.assertEqual(self.problems("DRIFT", "PROTOCOL_DEFECT", "CORE_PROTOCOL"), [])

    def test_an_engine_gap_may_change_the_engine(self) -> None:
        self.assertEqual(self.problems("DRIFT", "ENGINE_ENFORCEMENT_GAP", "ENGINE"), [])

    def test_model_noncompliance_may_not_weaken_core_protocol(self) -> None:
        found = self.problems("DRIFT", "MODEL_NONCOMPLIANCE", "CORE_PROTOCOL")
        self.assertTrue(any("never" in problem for problem in found))

    def test_user_override_may_not_weaken_the_execution_policy(self) -> None:
        found = self.problems("DRIFT", "USER_OVERRIDE", "EXECUTION_POLICY")
        self.assertTrue(found)

    def test_environment_failure_may_not_weaken_the_source_contract(self) -> None:
        self.assertTrue(self.problems("DRIFT", "ENVIRONMENT_FAILURE", "SOURCE_CONTRACT"))

    def test_an_engine_gap_may_not_change_the_adapter(self) -> None:
        found = self.problems("DRIFT", "ENGINE_ENFORCEMENT_GAP", "ADAPTER")
        self.assertTrue(any("cannot justify" in problem for problem in found))

    def test_a_drift_verdict_may_not_be_dispositioned_no_drift(self) -> None:
        found = self.problems("DRIFT", "NO_DRIFT", "NO_CHANGE")
        self.assertTrue(any("cannot be dispositioned" in problem for problem in found))

    def test_a_drift_verdict_may_not_be_dispositioned_user_override(self) -> None:
        """A legal user override is not drift; it is why the finding dies."""
        self.assertTrue(self.problems("DRIFT", "USER_OVERRIDE", "NO_CHANGE"))

    def test_a_no_drift_verdict_may_not_claim_a_defect(self) -> None:
        found = self.problems("NO_DRIFT", "PROTOCOL_DEFECT", None)
        self.assertTrue(any("must carry a non-drift" in problem for problem in found))

    def test_a_no_drift_verdict_with_a_non_drift_class_is_fine(self) -> None:
        self.assertEqual(self.problems("NO_DRIFT", "NO_DRIFT", None), [])

    def test_insufficient_evidence_is_a_non_drift_disposition(self) -> None:
        self.assertEqual(
            self.problems("INSUFFICIENT_EVIDENCE", "INSUFFICIENT_EVIDENCE", None), []
        )


class CandidateIntegration(unittest.TestCase):
    """The gate runs inside candidate validation, before any lifecycle work."""

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
            "disposition_class": "ENGINE_ENFORCEMENT_GAP",
            "reasoning": "the engine accepted an intake that never closed",
            "rule_ids": ["PAL-CMD-01"],
            "event_refs": [unit["episode"]["start_seq"]],
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P2",
            "confidence": "MEDIUM",
            "change_target": "ENGINE",
            "root_cause": "no closure event was required before the episode ended",
            "challenge": {
                "prosecutor": "PAL-CMD-01 names the closed surface; this route was not in it",
                "defender": "the adapter may have dropped the closure event",
                "winner": "prosecutor",
                "loser_rejection": "every later event was recorded, so nothing was dropped",
            },
            "alternatives": ["the adapter dropped a closure event"],
            "contrary_evidence": [],
            "missing_evidence": ["the operator note for this run"],
            "protected_invariants": ["source_closure"],
        }
        payload.update(overrides)
        return payload

    def test_a_consistent_candidate_is_admissible(self) -> None:
        self.assertEqual(
            cand_mod.candidate_problems(self.drift(), registry=self.registry), []
        )

    def test_a_model_failure_proposing_a_core_change_is_inadmissible(self) -> None:
        payload = self.drift(
            disposition_class="MODEL_NONCOMPLIANCE", change_target="CORE_PROTOCOL"
        )
        problems = cand_mod.candidate_problems(payload, registry=self.registry)
        self.assertTrue(any("never" in problem for problem in problems))

    def test_the_submit_boundary_refuses_it_and_writes_nothing(self) -> None:
        """Red control, end to end: the audit that would relax CORE never exists."""
        payload = self.drift(
            disposition_class="MODEL_NONCOMPLIANCE", change_target="CORE_PROTOCOL"
        )
        before = support.tree_digest(self.home)
        with self.assertRaises(PalError) as raised:
            submit_mod.submit_candidate(self.home, payload, registry=self.registry)
        self.assertEqual(raised.exception.code, "CANDIDATE_INADMISSIBLE")
        self.assertEqual(support.tree_digest(self.home), before)

    def test_the_same_model_failure_pointed_at_the_engine_is_accepted(self) -> None:
        """The finding is not suppressed -- it is redirected to a defensible surface."""
        payload = self.drift(
            disposition_class="MODEL_NONCOMPLIANCE", change_target="ENGINE"
        )
        receipt = submit_mod.submit_candidate(
            self.home, payload, registry=self.registry
        )
        self.assertEqual(receipt["verdict"], "DRIFT")
        self.assertIsNotNone(receipt["finding_id"])

    def test_a_no_drift_receipt_claiming_a_protocol_defect_is_inadmissible(self) -> None:
        unit = self.carrier
        payload = {
            "schema_version": 1,
            "verdict": "NO_DRIFT",
            "unit_digest": unit["unit_digest"],
            "session_id": unit["session"]["session_id"],
            "episode_index": unit["episode"]["index"],
            "disposition_class": "PROTOCOL_DEFECT",
            "reasoning": "nothing contradicted the protocol here",
        }
        problems = cand_mod.candidate_problems(payload, registry=self.registry)
        self.assertTrue(any("non-drift disposition" in problem for problem in problems))


if __name__ == "__main__":
    unittest.main()
