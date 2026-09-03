"""T-044: the mechanical defence surface (PAL-ANALYSIS-02).

A defender pass is only worth requiring if it must engage with the facts. The
kernel already sees a user override, a later recovery, an adapter normalization,
a tool failure, an owner document or a still-HOT session. If a DRIFT claim never
answers one of those, the challenge was theatre.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import candidates as cand_mod
from saipal_engine import carrier as carrier_mod
from saipal_engine import defence as defence_mod
from saipal_engine import submit as submit_mod
from saipal_engine.errors import PalError
from saipal_engine.registry import load_registry

MITIGATIONS = "defence-mitigations.json"
HOT = "hot-partial.json"


def _event(seq: int, etype: str, facts: dict) -> dict:
    return {"seq": seq, "type": etype, "ts": None, "loc": None, "digest": None, "facts": facts}


class Derivation(unittest.TestCase):
    """Each mitigation is derived from a specific observable, and only that one."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self.episode = {"index": 0, "start_seq": 1, "end_seq": 10}

    def surface(self, events: list[dict], record: dict | None = None) -> list[str]:
        return [
            entry["code"]
            for entry in defence_mod.defence_surface(
                {"events": events}, self.episode, record, registry=self.registry
            )
        ]

    def test_a_clean_span_raises_no_mitigation(self) -> None:
        self.assertEqual(self.surface([_event(1, "USER_MESSAGE", {"chars": 5})]), [])

    def test_a_user_override_is_a_mitigation(self) -> None:
        self.assertEqual(
            self.surface([_event(1, "USER_MESSAGE", {"override": True})]),
            ["USER_OVERRIDE"],
        )

    def test_a_falsy_override_flag_is_not_a_mitigation(self) -> None:
        """Red control: `override: false` is the absence of an override."""
        self.assertEqual(self.surface([_event(1, "USER_MESSAGE", {"override": False})]), [])

    def test_a_non_boolean_override_is_not_a_mitigation(self) -> None:
        self.assertEqual(self.surface([_event(1, "USER_MESSAGE", {"override": "yes"})]), [])

    def test_a_recovery_error_is_a_mitigation(self) -> None:
        self.assertEqual(
            self.surface([_event(2, "ERROR", {"kind": "recovery"})]), ["LATER_RECOVERY"]
        )

    def test_an_adapter_normalization_snapshot_is_a_mitigation(self) -> None:
        self.assertEqual(
            self.surface([_event(3, "STATE_SNAPSHOT", {"kind": "adapter_normalization"})]),
            ["ADAPTER_NORMALIZATION"],
        )

    def test_a_tool_environment_failure_is_a_mitigation(self) -> None:
        self.assertEqual(
            self.surface([_event(4, "TOOL_RESULT", {"env_failure": True})]),
            ["ENVIRONMENT_FAILURE"],
        )

    def test_an_owner_document_boundary_is_a_mitigation(self) -> None:
        self.assertEqual(
            self.surface([_event(5, "SESSION_BOUNDARY", {"kind": "owner_doc"})]),
            ["SOURCE_OWNER_DOCUMENT"],
        )

    def test_a_hot_session_is_a_session_level_mitigation(self) -> None:
        codes = self.surface([_event(1, "USER_MESSAGE", {})], {"temperature": "HOT"})
        self.assertEqual(codes, ["SESSION_STILL_HOT"])

    def test_a_cold_session_raises_no_temperature_mitigation(self) -> None:
        codes = self.surface([_event(1, "USER_MESSAGE", {})], {"temperature": "COLD"})
        self.assertEqual(codes, [])

    def test_events_outside_the_episode_are_ignored(self) -> None:
        """The defence surface belongs to this episode, not the whole session."""
        codes = self.surface([_event(99, "USER_MESSAGE", {"override": True})])
        self.assertEqual(codes, [])

    def test_a_repeated_mitigation_is_reported_once(self) -> None:
        codes = self.surface(
            [
                _event(1, "USER_MESSAGE", {"override": True}),
                _event(2, "USER_MESSAGE", {"override": True}),
            ]
        )
        self.assertEqual(codes, ["USER_OVERRIDE"])

    def test_every_mitigation_carries_its_raising_event(self) -> None:
        surface = defence_mod.defence_surface(
            {"events": [_event(7, "ERROR", {"kind": "recovery"})]},
            self.episode,
            None,
            registry=self.registry,
        )
        self.assertEqual(surface[0]["seq"], 7)
        self.assertTrue(surface[0]["description"])

    def test_every_declared_rule_has_a_description(self) -> None:
        for code, description in defence_mod.DEFENCE_RULES:
            self.assertTrue(description, code)
        self.assertEqual(
            len(defence_mod.DEFENCE_CODES), len(defence_mod.DEFENCE_RULES),
            "duplicate defence code",
        )


class Accounting(unittest.TestCase):
    """What the candidate addressed, and what it invented."""

    def test_unaddressed_reports_what_was_skipped(self) -> None:
        surface = [{"code": "USER_OVERRIDE"}, {"code": "LATER_RECOVERY"}]
        candidate = {"addressed_defences": ["USER_OVERRIDE"]}
        self.assertEqual(defence_mod.unaddressed(candidate, surface), ["LATER_RECOVERY"])

    def test_addressing_everything_leaves_nothing(self) -> None:
        surface = [{"code": "USER_OVERRIDE"}]
        candidate = {"addressed_defences": ["USER_OVERRIDE"]}
        self.assertEqual(defence_mod.unaddressed(candidate, surface), [])

    def test_an_empty_surface_needs_no_addressing(self) -> None:
        self.assertEqual(defence_mod.unaddressed({}, []), [])

    def test_an_invented_code_is_reported(self) -> None:
        self.assertEqual(
            defence_mod.unknown_codes({"addressed_defences": ["I_CHECKED_EVERYTHING"]}),
            ["I_CHECKED_EVERYTHING"],
        )

    def test_real_codes_are_not_reported_as_unknown(self) -> None:
        self.assertEqual(
            defence_mod.unknown_codes({"addressed_defences": ["USER_OVERRIDE"]}), []
        )


class CarrierAndSubmission(unittest.TestCase):
    """The surface reaches the analyst, and an unanswered claim is refused."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, MITIGATIONS)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def unit(self) -> dict:
        return carrier_mod.build_carrier(self.home, registry=self.registry)

    def drift(self, unit: dict, **overrides) -> dict:
        payload = {
            "schema_version": 1,
            "verdict": "DRIFT",
            "unit_digest": unit["unit_digest"],
            "session_id": unit["session"]["session_id"],
            "episode_index": unit["episode"]["index"],
            "disposition_class": "ENGINE_ENFORCEMENT_GAP",
            "reasoning": "the route left the closed surface and nothing repaired it",
            "rule_ids": ["PAL-CMD-01"],
            "event_refs": [unit["episode"]["start_seq"]],
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P2",
            "confidence": "MEDIUM",
            "change_target": "ENGINE",
            "root_cause": "the engine accepted a token outside the declared surface",
            "challenge": {
                "prosecutor": "PAL-CMD-01 names the closed surface; this token is not in it",
                "defender": "the user may have authorized it, or the adapter mislabelled it",
                "winner": "prosecutor",
                "loser_rejection": "the override predates the command and names another action",
            },
            "alternatives": ["the adapter mislabelled a shell command"],
        }
        payload.update(overrides)
        return payload

    def no_drift(self, unit: dict) -> dict:
        return {
            "schema_version": 1,
            "verdict": "NO_DRIFT",
            "unit_digest": unit["unit_digest"],
            "session_id": unit["session"]["session_id"],
            "episode_index": unit["episode"]["index"],
            "disposition_class": "NO_DRIFT",
            "reasoning": "nothing in the span contradicted the protocol",
        }

    def test_the_carrier_carries_the_defence_surface(self) -> None:
        unit = self.unit()
        self.assertIn("defence_surface", unit)
        self.assertEqual(
            [entry["code"] for entry in unit["defence_surface"]], ["USER_OVERRIDE"]
        )
        self.assertEqual(
            cand_mod.candidate_problems(self.drift(unit), registry=self.registry), []
        )

    def test_a_claim_ignoring_the_surface_is_refused_with_zero_writes(self) -> None:
        unit = self.unit()
        before = support.tree_digest(self.home)
        with self.assertRaises(PalError) as raised:
            submit_mod.submit_candidate(self.home, self.drift(unit), registry=self.registry)
        self.assertEqual(raised.exception.code, "CANDIDATE_OUT_OF_SCOPE")
        self.assertIn("USER_OVERRIDE", raised.exception.message)
        self.assertEqual(support.tree_digest(self.home), before)

    def test_a_claim_addressing_the_surface_is_accepted(self) -> None:
        unit = self.unit()
        receipt = submit_mod.submit_candidate(
            self.home,
            self.drift(unit, addressed_defences=["USER_OVERRIDE"]),
            registry=self.registry,
        )
        self.assertEqual(receipt["verdict"], "DRIFT")
        self.assertIsNotNone(receipt["finding_id"])

    def test_addressing_the_wrong_mitigation_does_not_satisfy_the_gate(self) -> None:
        """Red control: naming *a* code is not naming *the* code."""
        unit = self.unit()
        with self.assertRaises(PalError) as raised:
            submit_mod.submit_candidate(
                self.home,
                self.drift(unit, addressed_defences=["LATER_RECOVERY"]),
                registry=self.registry,
            )
        self.assertIn("USER_OVERRIDE", raised.exception.message)

    def test_an_invented_defence_code_is_inadmissible(self) -> None:
        unit = self.unit()
        problems = cand_mod.candidate_problems(
            self.drift(unit, addressed_defences=["ALL_OF_THEM"]), registry=self.registry
        )
        self.assertTrue(any("unknown code" in problem for problem in problems))

    def test_a_no_drift_receipt_may_not_carry_addressed_defences(self) -> None:
        unit = self.unit()
        payload = self.no_drift(unit)
        payload["addressed_defences"] = ["USER_OVERRIDE"]
        problems = cand_mod.candidate_problems(payload, registry=self.registry)
        self.assertTrue(
            any("only admissible on a DRIFT verdict" in problem for problem in problems)
        )

    def test_a_no_drift_receipt_needs_no_defence_accounting(self) -> None:
        unit = self.unit()
        receipt = submit_mod.submit_candidate(
            self.home, self.no_drift(unit), registry=self.registry
        )
        self.assertEqual(receipt["verdict"], "NO_DRIFT")

    def test_the_addressed_codes_survive_onto_the_finding(self) -> None:
        import json

        unit = self.unit()
        receipt = submit_mod.submit_candidate(
            self.home,
            self.drift(unit, severity="P1", addressed_defences=["USER_OVERRIDE"]),
            registry=self.registry,
        )
        findings = json.loads(
            (self.home / "findings" / "index.json").read_text(encoding="utf-8")
        )["findings"]
        finding = next(f for f in findings if f["finding_id"] == receipt["finding_id"])
        self.assertEqual(finding["challenge"]["addressed_defences"], ["USER_OVERRIDE"])

    def test_a_multi_mitigation_episode_requires_all_of_them(self) -> None:
        """The second episode of the fixture raises two distinct mitigations."""
        unit = self.unit()
        submit_mod.submit_candidate(self.home, self.no_drift(unit), registry=self.registry)
        second = self.unit()
        codes = {entry["code"] for entry in second["defence_surface"]}
        self.assertGreaterEqual(len(codes), 2, "fixture must raise several mitigations")
        with self.assertRaises(PalError):
            submit_mod.submit_candidate(
                self.home,
                self.drift(second, addressed_defences=[sorted(codes)[0]]),
                registry=self.registry,
            )
        receipt = submit_mod.submit_candidate(
            self.home,
            self.drift(second, addressed_defences=sorted(codes)),
            registry=self.registry,
        )
        self.assertEqual(receipt["verdict"], "DRIFT")


class HotSessionDefence(unittest.TestCase):
    """A still-growing session is itself a defence the analyst must answer."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, HOT)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_a_hot_session_raises_the_incompleteness_defence(self) -> None:
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertEqual(unit["session"]["temperature"], "HOT")
        codes = {entry["code"] for entry in unit["defence_surface"]}
        self.assertIn("SESSION_STILL_HOT", codes)


if __name__ == "__main__":
    unittest.main()
