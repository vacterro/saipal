"""T-046: HOT provisional / COLD final semantic policy (PAL-SESSION-06).

A COLD session is finished, so a verdict about it is a verdict about the whole
truth. A HOT session's last episode is a sentence still being written: reasoning
about it is useful, but publishing an audit about it is publishing a conclusion
drawn from half the evidence.

So the tail of a HOT session is PROVISIONAL: the finding is recorded, the
watermark does not pass it, and no audit leaves the home until the evidence is
final.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import bundle as bundle_mod
from saipal_engine import carrier as carrier_mod
from saipal_engine import sessions as sessions_mod
from saipal_engine import submit as submit_mod
from saipal_engine.registry import load_registry, require_string_list

HOT = "hot-partial.json"
HOT_EXTENDED = "hot-extended.json"
COLD = "conformant-cold.json"
DRIFT = "agent-noncompliance-command-route.json"


class Finality(unittest.TestCase):
    """Which episode can still change, decided structurally."""

    def setUp(self) -> None:
        self.registry = load_registry()

    def record(self, temperature: str, count: int = 3) -> dict:
        return {
            "temperature": temperature,
            "episodes": [{"index": index} for index in range(count)],
        }

    def test_the_enum_is_registry_owned(self) -> None:
        self.assertEqual(
            set(require_string_list(self.registry, "episode_finality")),
            {"FINAL", "PROVISIONAL"},
        )

    def test_every_episode_of_a_cold_session_is_final(self) -> None:
        record = self.record("COLD")
        for episode in record["episodes"]:
            self.assertEqual(carrier_mod.episode_finality(record, episode), "FINAL")

    def test_the_tail_of_a_hot_session_is_provisional(self) -> None:
        record = self.record("HOT")
        self.assertEqual(
            carrier_mod.episode_finality(record, {"index": 2}), "PROVISIONAL"
        )

    def test_an_earlier_hot_episode_is_final(self) -> None:
        """An episode closed by a later boundary cannot grow any more."""
        record = self.record("HOT")
        self.assertEqual(carrier_mod.episode_finality(record, {"index": 0}), "FINAL")
        self.assertEqual(carrier_mod.episode_finality(record, {"index": 1}), "FINAL")

    def test_a_single_episode_hot_session_is_provisional(self) -> None:
        record = self.record("HOT", count=1)
        self.assertEqual(
            carrier_mod.episode_finality(record, {"index": 0}), "PROVISIONAL"
        )

    def test_a_session_with_no_episodes_is_final(self) -> None:
        self.assertEqual(
            carrier_mod.episode_finality({"temperature": "HOT", "episodes": []}, {"index": 0}),
            "FINAL",
        )


class CarrierReportsFinality(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_a_hot_session_reports_final_early_and_provisional_at_the_tail(self) -> None:
        """Only the growing tail is provisional; earlier episodes are closed."""
        support.put_inbox(self.home, HOT)
        support.run_saipal("continue", home=self.home)
        record = support.sessions_of(self.home)[0]
        self.assertEqual(record["temperature"], "HOT")
        episodes = record["episodes"]
        self.assertGreater(len(episodes), 1, "fixture must have a closed episode + tail")

        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertEqual(unit["episode"]["index"], episodes[0]["index"])
        self.assertEqual(unit["episode"]["finality"], "FINAL")

        self.assertEqual(
            carrier_mod.episode_finality(record, episodes[-1]), "PROVISIONAL"
        )

    def test_a_cold_carrier_declares_its_episode_final(self) -> None:
        support.put_inbox(self.home, COLD)
        support.run_saipal("continue", home=self.home)
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertEqual(unit["session"]["temperature"], "COLD")
        self.assertEqual(unit["episode"]["finality"], "FINAL")

    def test_finality_survives_the_carrier_shape_check(self) -> None:
        support.put_inbox(self.home, HOT)
        support.run_saipal("continue", home=self.home)
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertEqual(carrier_mod.carrier_problems(unit, registry=self.registry), [])


class ProvisionalSubmission(unittest.TestCase):
    """A verdict on a growing tail is recorded but never published."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, HOT)
        support.run_saipal("continue", home=self.home)
        self.unit = self._advance_to_the_tail()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _advance_to_the_tail(self) -> dict:
        """Work through the closed episodes so the pending unit is the growing tail.

        Only the LAST episode of a HOT session is provisional; the earlier ones
        were closed by a later boundary and are ordinary final work.
        """
        for _ in range(20):
            unit = carrier_mod.build_carrier(self.home, registry=self.registry)
            self.assertIsNotNone(unit["session"], "the HOT fixture must be pending")
            if unit["episode"]["finality"] == "PROVISIONAL":
                return unit
            submit_mod.submit_candidate(
                self.home, self.no_drift(unit), registry=self.registry
            )
        raise AssertionError("no provisional episode was ever offered")

    def drift(self, unit: dict, **overrides) -> dict:
        payload = {
            "schema_version": 1,
            "verdict": "DRIFT",
            "unit_digest": unit["unit_digest"],
            "session_id": unit["session"]["session_id"],
            "episode_index": unit["episode"]["index"],
            "disposition_class": "ENGINE_ENFORCEMENT_GAP",
            "reasoning": "the engine accepted a route outside the closed surface",
            "rule_ids": ["PAL-CMD-01"],
            "event_refs": [unit["episode"]["start_seq"]],
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P1",
            "confidence": "HIGH",
            "change_target": "ENGINE",
            "root_cause": "the closed command surface was not consulted",
            "challenge": {
                "prosecutor": "PAL-CMD-01 names the surface; the observed route is not in it",
                "defender": "the session is still HOT, so the episode may be incomplete",
                "winner": "prosecutor",
                "loser_rejection": "the route already executed; a later event cannot unexecute it",
            },
            "alternatives": ["the adapter mislabelled a shell command"],
            "addressed_defences": [
                entry["code"] for entry in unit.get("defence_surface") or []
            ],
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
            "reasoning": "nothing in the span so far contradicted the protocol",
        }

    def record(self) -> dict:
        return next(
            r for r in support.sessions_of(self.home) if r["session_id"] == "golden-hot-001"
        )

    def findings(self) -> list[dict]:
        path = self.home / "findings" / "index.json"
        if not path.exists():
            return []
        return json.loads(path.read_text(encoding="utf-8"))["findings"]

    def test_the_setup_landed_on_a_provisional_tail(self) -> None:
        self.assertEqual(self.unit["episode"]["finality"], "PROVISIONAL")
        self.assertEqual(self.unit["session"]["temperature"], "HOT")

    def test_a_provisional_submission_is_accepted_and_labelled(self) -> None:
        receipt = submit_mod.submit_candidate(
            self.home, self.drift(self.unit), registry=self.registry
        )
        self.assertEqual(receipt["finality"], "PROVISIONAL")
        self.assertIsNotNone(receipt["finding_id"])

    def test_a_provisional_submission_emits_no_audit(self) -> None:
        """Red control: the whole point. Half the evidence, no publication."""
        receipt = submit_mod.submit_candidate(
            self.home, self.drift(self.unit), registry=self.registry
        )
        self.assertIsNone(receipt["audit"])
        staging = self.home / "audit" / "staging"
        staged = list(staging.glob("*.md")) if staging.is_dir() else []
        self.assertEqual(staged, [], "a provisional finding must not stage an audit")

    def test_a_provisional_finding_records_why_it_is_held(self) -> None:
        receipt = submit_mod.submit_candidate(
            self.home, self.drift(self.unit), registry=self.registry
        )
        finding = next(
            f for f in self.findings() if f["finding_id"] == receipt["finding_id"]
        )
        self.assertEqual(finding["episode_finality"], "PROVISIONAL")
        self.assertIn("HOT", finding["provisional_hold"])

    def test_a_provisional_submission_does_not_advance_the_watermark(self) -> None:
        before = carrier_mod.semantic_state(self.record())
        submit_mod.submit_candidate(
            self.home, self.drift(self.unit), registry=self.registry
        )
        after = carrier_mod.semantic_state(self.record())
        self.assertEqual(
            after["next_episode_index"], before["next_episode_index"],
            "a growing episode must be offered again once it has grown",
        )
        self.assertEqual(after["provisional"], before["provisional"] + 1)

    def test_the_unchanged_provisional_unit_is_not_re_offered(self) -> None:
        """Material-change rule (PAL-SESSION-06): a tail judged provisionally
        at this exact position is not handed out again without a delta."""
        submit_mod.submit_candidate(
            self.home, self.drift(self.unit), registry=self.registry
        )
        again = carrier_mod.build_carrier(self.home, registry=self.registry)
        if again.get("session"):
            self.assertNotEqual(
                again["session"]["session_id"], self.unit["session"]["session_id"],
                "an unchanged HOT tail must not be re-offered",
            )
        else:
            self.assertEqual(again["carrier"], "idle")

    def test_a_provisional_no_drift_receipt_also_holds_position(self) -> None:
        before = carrier_mod.semantic_state(self.record())
        receipt = submit_mod.submit_candidate(
            self.home, self.no_drift(self.unit), registry=self.registry
        )
        after = carrier_mod.semantic_state(self.record())
        self.assertEqual(receipt["finality"], "PROVISIONAL")
        self.assertEqual(after["next_episode_index"], before["next_episode_index"])
        self.assertEqual(after["no_drift"], before["no_drift"] + 1)

    def test_the_receipt_records_the_finality_it_was_judged_under(self) -> None:
        submit_mod.submit_candidate(
            self.home, self.drift(self.unit), registry=self.registry
        )
        _status, payload, _detail = submit_mod.load_receipts(self.home)
        self.assertEqual(payload["receipts"][-1]["finality"], "PROVISIONAL")

    def test_a_duplicate_provisional_submission_reports_its_finality(self) -> None:
        first = submit_mod.submit_candidate(
            self.home, self.drift(self.unit), registry=self.registry
        )
        second = submit_mod.submit_candidate(
            self.home, self.drift(self.unit), registry=self.registry
        )
        self.assertTrue(second["duplicate"])
        self.assertEqual(second["finality"], first["finality"])


class FinalSubmission(unittest.TestCase):
    """A COLD session publishes normally: the policy is a hold, not a block."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)
        self.unit = carrier_mod.build_carrier(self.home, registry=self.registry)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_a_cold_submission_is_final_and_advances(self) -> None:
        record_before = support.sessions_of(self.home)[0]
        before = carrier_mod.semantic_state(record_before)
        receipt = submit_mod.submit_candidate(
            self.home,
            {
                "schema_version": 1,
                "verdict": "NO_DRIFT",
                "unit_digest": self.unit["unit_digest"],
                "session_id": self.unit["session"]["session_id"],
                "episode_index": self.unit["episode"]["index"],
                "disposition_class": "NO_DRIFT",
                "reasoning": "the span routed through the declared surface",
            },
            registry=self.registry,
        )
        after = carrier_mod.semantic_state(support.sessions_of(self.home)[0])
        self.assertEqual(receipt["finality"], "FINAL")
        self.assertEqual(after["next_episode_index"], before["next_episode_index"] + 1)


class ProvisionalBecomesFinal(unittest.TestCase):
    """When the session grows and closes, a held finding stops being held."""

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

    def test_a_grown_session_has_a_longer_or_later_tail(self) -> None:
        """The tail is where growth lands, so that is what must have changed."""
        before = support.sessions_of(self.home)[0]["episodes"][-1]
        support.clear_inbox(self.home)
        support.put_inbox(self.home, HOT_EXTENDED)
        support.run_saipal("continue", home=self.home)
        after = support.sessions_of(self.home)[0]["episodes"][-1]
        self.assertNotEqual(
            (before["start_seq"], before["end_seq"]),
            (after["start_seq"], after["end_seq"]),
            "the growing tail must reflect the new events",
        )

    def test_a_finding_re_raised_against_final_evidence_loses_its_hold(self) -> None:
        record = support.sessions_of(self.home)[0]
        self.assertEqual(record["temperature"], "HOT")

        # Same root cause, first raised provisionally, then re-raised once the
        # same session is COLD. merge_candidates matches on fingerprint, so the
        # second submission is the same finding -- and it must be releasable.
        from saipal_engine import findings as findings_mod

        index = findings_mod.empty_index()
        candidate = {
            "detector": "analyst",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "rule_ids": ["PAL-CMD-01"],
            "change_target": "ENGINE",
            "root_cause": "the closed command surface was not consulted",
            "episode_finality": "PROVISIONAL",
            "semantic_confirmation": {
                "receipt_id": "rcp-finality",
                "verdict": "DRIFT",
                "session_id": record["session_id"],
                "episode_index": 0,
                "unit_digest": "f" * 64,
                "protocol_binding": {"binding_status": "BOUND"},
            },
        }
        first = findings_mod.merge_candidates(index, [candidate], record)[0]
        self.assertEqual(first["episode_finality"], "PROVISIONAL")
        first["provisional_hold"] = "held"
        findings_mod.merge_candidates(
            index, [dict(candidate, episode_finality="FINAL")], record
        )
        self.assertEqual(first["episode_finality"], "FINAL")
        self.assertNotIn("provisional_hold", first)


class MutatedHotEvidenceStillWins(unittest.TestCase):
    """A HOT prefix that changed is a CONFLICT, and that outranks provisional work."""

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

    def test_a_conflicted_hot_session_is_not_offered_as_provisional(self) -> None:
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        bundle = bundle_mod.load_bundle_file(
            self.home / "session_inbox" / HOT, registry=self.registry
        )
        for record in index["sessions"]:
            if record["session_id"] == "golden-hot-001":
                record["last_analyzed_seq"] = 2
                record["prefix_sha256"] = bundle_mod.prefix_digest(bundle, 2)
        sessions_mod.save_index(self.home, index, registry=self.registry)
        support.clear_inbox(self.home)
        support.put_inbox(self.home, "hot-prefix-mutated.json")
        support.run_saipal("continue", home=self.home)

        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        if unit["session"] is not None:
            self.assertNotEqual(unit["session"]["session_id"], "golden-hot-001")


if __name__ == "__main__":
    unittest.main()
