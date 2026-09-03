"""T-042: the constrained submission boundary (PAL-ANALYSIS-05).

`submit` is the analyst's only write path and the place where a replaceable
model meets a kernel that must not be talked into anything. So the tests are
mostly refusals, and each refusal must be a RESULT: a code, a reason, and not one
byte written.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import carrier as carrier_mod
from saipal_engine import sessions as sessions_mod
from saipal_engine import submit as submit_mod
from saipal_engine.errors import PalError
from saipal_engine.registry import load_registry

CLEAN = "no-finding-normal.json"
CONFLICT_BASE = "hot-partial.json"
CONFLICT_MUTATED = "hot-prefix-mutated.json"


class SubmitBase(unittest.TestCase):
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

    def no_drift(self, carrier: dict | None = None, **overrides) -> dict:
        unit = carrier or self.carrier
        payload = {
            "schema_version": 1,
            "verdict": "NO_DRIFT",
            "unit_digest": unit["unit_digest"],
            "session_id": unit["session"]["session_id"],
            "episode_index": unit["episode"]["index"],
            "disposition_class": "NO_DRIFT",
            "reasoning": "every command in the span routed through the declared surface",
            "event_refs": [unit["episode"]["start_seq"]],
        }
        payload.update(overrides)
        return payload

    def drift(self, carrier: dict | None = None, **overrides) -> dict:
        unit = carrier or self.carrier
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
                "loser_rejection": "later events were all recorded, so nothing was dropped",
            },
            "alternatives": ["the adapter dropped a closure event"],
            "contrary_evidence": [],
            "missing_evidence": ["the operator note for this run"],
            "protected_invariants": ["source_closure"],
        }
        payload.update(overrides)
        return payload

    def submit(self, candidate: dict) -> dict:
        return submit_mod.submit_candidate(self.home, candidate, registry=self.registry)

    def record(self) -> dict:
        return support.sessions_of(self.home)[0]


class AcceptedSubmission(SubmitBase):
    """An admissible candidate is absorbed and the watermark moves once."""

    def test_a_no_drift_receipt_advances_the_semantic_watermark(self) -> None:
        before = carrier_mod.semantic_state(self.record())
        receipt = self.submit(self.no_drift())
        after = carrier_mod.semantic_state(self.record())
        self.assertEqual(receipt["verdict"], "NO_DRIFT")
        self.assertFalse(receipt["duplicate"])
        self.assertEqual(
            after["next_episode_index"], before["next_episode_index"] + 1
        )
        self.assertEqual(after["no_drift"], before["no_drift"] + 1)
        self.assertIsNone(receipt["finding_id"])

    def test_a_no_drift_receipt_records_negative_evidence(self) -> None:
        self.submit(self.no_drift())
        payload = json.loads((self.home / "recurrence.json").read_text(encoding="utf-8"))
        self.assertTrue(payload["by_finding"], "negative evidence must be recorded")

    def test_a_drift_candidate_becomes_a_finding_through_the_lifecycle(self) -> None:
        receipt = self.submit(self.drift())
        self.assertEqual(receipt["verdict"], "DRIFT")
        self.assertIsNotNone(receipt["finding_id"])
        findings = json.loads(
            (self.home / "findings" / "index.json").read_text(encoding="utf-8")
        )["findings"]
        finding = next(f for f in findings if f["finding_id"] == receipt["finding_id"])
        self.assertEqual(finding["state"], "QUALIFIED")
        self.assertEqual(finding["disposition_class"], "ENGINE_ENFORCEMENT_GAP")
        self.assertIn("harm_warnings", finding)

    def test_the_analyst_challenge_survives_into_the_finding(self) -> None:
        """The mechanical template must not overwrite real reasoning."""
        receipt = self.submit(self.drift(severity="P1"))
        findings = json.loads(
            (self.home / "findings" / "index.json").read_text(encoding="utf-8")
        )["findings"]
        finding = next(f for f in findings if f["finding_id"] == receipt["finding_id"])
        self.assertEqual(finding["challenge"]["decided"], "prosecutor")
        self.assertIn("closed surface", finding["challenge"]["pass_a"])

    def test_submission_is_idempotent_per_unit_verdict_and_reasoning(self) -> None:
        first = self.submit(self.no_drift())
        state_after_first = carrier_mod.semantic_state(self.record())
        second = self.submit(self.no_drift())
        self.assertEqual(first["receipt_id"], second["receipt_id"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(
            carrier_mod.semantic_state(self.record())["next_episode_index"],
            state_after_first["next_episode_index"],
            "a duplicate submission must not advance the watermark twice",
        )

    def test_a_receipt_is_durable(self) -> None:
        receipt = self.submit(self.no_drift())
        status, payload, _detail = submit_mod.load_receipts(self.home)
        self.assertEqual(status, "ok")
        self.assertEqual(payload["receipts"][0]["receipt_id"], receipt["receipt_id"])

    def test_submission_is_logged(self) -> None:
        self.submit(self.no_drift())
        events = [
            json.loads(line)
            for line in (self.home / "LOG.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertTrue(any(e["event"] == "candidate_submitted" for e in events))

    def test_working_through_every_episode_exhausts_the_session(self) -> None:
        while True:
            unit = carrier_mod.build_carrier(self.home, registry=self.registry)
            if unit["carrier"] != "analyze-episodes" or unit["session"] is None:
                break
            self.submit(self.no_drift(unit))
        self.assertTrue(carrier_mod.semantic_state(self.record())["exhausted"])
        final = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertEqual(final["carrier"], "idle")


class RefusedSubmission(SubmitBase):
    """Every refusal is a result with a code, and writes nothing."""

    def assert_refused(self, candidate: object, code: str) -> None:
        before = support.tree_digest(self.home)
        with self.assertRaises(PalError) as raised:
            submit_mod.submit_candidate(self.home, candidate, registry=self.registry)
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(
            support.tree_digest(self.home), before, "a refusal must write nothing"
        )

    def test_a_non_object_candidate_is_refused(self) -> None:
        self.assert_refused("looks fine", "VALIDATION_FAILED")

    def test_a_malformed_candidate_is_refused_as_inadmissible(self) -> None:
        payload = self.no_drift()
        del payload["reasoning"]
        self.assert_refused(payload, "CANDIDATE_INADMISSIBLE")

    def test_an_unknown_field_is_refused(self) -> None:
        self.assert_refused(
            self.no_drift(patch="diff --git a/CORE.md"), "CANDIDATE_INADMISSIBLE"
        )

    def test_a_no_drift_receipt_carrying_a_claim_is_refused(self) -> None:
        self.assert_refused(
            self.no_drift(change_target="CORE_PROTOCOL"), "CANDIDATE_INADMISSIBLE"
        )

    def test_a_stale_unit_digest_is_refused_as_out_of_scope(self) -> None:
        self.assert_refused(self.no_drift(unit_digest="0" * 64), "CANDIDATE_OUT_OF_SCOPE")

    def test_an_event_outside_the_episode_is_refused(self) -> None:
        outside = self.carrier["episode"]["end_seq"] + 500
        self.assert_refused(
            self.drift(event_refs=[outside]), "CANDIDATE_OUT_OF_SCOPE"
        )

    def test_an_unindexed_session_is_refused(self) -> None:
        self.assert_refused(
            self.no_drift(session_id="ses-that-never-existed"), "EVIDENCE_NOT_FOUND"
        )

    def test_an_unindexed_episode_is_refused(self) -> None:
        self.assert_refused(self.no_drift(episode_index=4242), "EVIDENCE_NOT_FOUND")

    def test_a_candidate_answering_another_episode_is_refused(self) -> None:
        """Red control: right session, wrong episode, still refused."""
        record = self.record()
        if len(record["episodes"]) < 2:
            self.skipTest("fixture has a single episode")
        payload = self.no_drift(episode_index=1)
        self.assert_refused(payload, "CANDIDATE_OUT_OF_SCOPE")

    def test_unreadable_receipts_refuse_instead_of_being_overwritten(self) -> None:
        (self.home / submit_mod.RECEIPTS_NAME).write_text("{", encoding="utf-8")
        with self.assertRaises(PalError) as raised:
            self.submit(self.no_drift())
        self.assertEqual(raised.exception.code, "VALIDATION_FAILED")
        self.assertEqual(
            (self.home / submit_mod.RECEIPTS_NAME).read_text(encoding="utf-8"), "{"
        )


class ConflictedSessionIsFrozen(unittest.TestCase):
    """Reasoning about mutated evidence is refused, not merged."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, CONFLICT_BASE)
        support.run_saipal("continue", home=self.home)
        self.unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self._force_conflict()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _force_conflict(self) -> None:
        from saipal_engine import bundle as bundle_mod

        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        bundle = bundle_mod.load_bundle_file(
            self.home / "session_inbox" / CONFLICT_BASE, registry=self.registry
        )
        for record in index["sessions"]:
            if record["session_id"] == "golden-hot-001":
                record["last_analyzed_seq"] = 2
                record["prefix_sha256"] = bundle_mod.prefix_digest(bundle, 2)
        sessions_mod.save_index(self.home, index, registry=self.registry)
        support.clear_inbox(self.home)
        support.put_inbox(self.home, CONFLICT_MUTATED)
        support.run_saipal("continue", home=self.home)

    def test_a_conflicted_session_refuses_submissions(self) -> None:
        candidate = {
            "schema_version": 1,
            "verdict": "NO_DRIFT",
            "unit_digest": self.unit["unit_digest"],
            "session_id": "golden-hot-001",
            "episode_index": self.unit["episode"]["index"],
            "disposition_class": "NO_DRIFT",
            "reasoning": "nothing in the span contradicted the protocol",
        }
        before = support.tree_digest(self.home)
        with self.assertRaises(PalError) as raised:
            submit_mod.submit_candidate(self.home, candidate, registry=self.registry)
        self.assertEqual(raised.exception.code, "SESSION_CONFLICT")
        self.assertEqual(support.tree_digest(self.home), before)


class SubmitCommand(SubmitBase):
    """The CLI surface: a file, stdin, and honest exit codes."""

    def _write(self, candidate: dict, name: str = "cand.json") -> Path:
        path = self.tmp / name
        path.write_text(json.dumps(candidate), encoding="utf-8")
        return path

    def test_submit_from_a_file_returns_a_receipt(self) -> None:
        path = self._write(self.no_drift())
        code, payload, err = support.run_saipal_json("submit", str(path), home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["verdict"], "NO_DRIFT")
        self.assertTrue(payload["receipt_id"].startswith("rcp-"))

    def test_submit_refuses_a_bad_candidate_with_exit_one(self) -> None:
        payload = self.no_drift()
        del payload["reasoning"]
        path = self._write(payload, "bad.json")
        code, result, _err = support.run_saipal_json("submit", str(path), home=self.home)
        self.assertEqual(code, 1)
        self.assertEqual(result["code"], "CANDIDATE_INADMISSIBLE")

    def test_submit_without_an_argument_is_a_usage_error(self) -> None:
        code, result, _err = support.run_saipal_json("submit", home=self.home)
        self.assertEqual(code, 2)
        self.assertEqual(result["code"], "USAGE")

    def test_submit_with_two_arguments_is_a_usage_error(self) -> None:
        path = self._write(self.no_drift())
        code, result, _err = support.run_saipal_json(
            "submit", str(path), str(path), home=self.home
        )
        self.assertEqual(code, 2)
        self.assertEqual(result["code"], "USAGE")

    def test_submit_refuses_invalid_json(self) -> None:
        path = self.tmp / "broken.json"
        path.write_text("{ not json", encoding="utf-8")
        code, result, _err = support.run_saipal_json("submit", str(path), home=self.home)
        self.assertEqual(code, 1)
        self.assertEqual(result["code"], "VALIDATION_FAILED")

    def test_submit_refuses_an_absent_file(self) -> None:
        code, result, _err = support.run_saipal_json(
            "submit", str(self.tmp / "nope.json"), home=self.home
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["code"], "VALIDATION_FAILED")

    def test_the_full_next_submit_loop_closes(self) -> None:
        """The loop SKILL.md prescribes, executed exactly: next -> submit -> next."""
        _code, first, _err = support.run_saipal_json("next", home=self.home)
        unit = first["analysis_carrier"]
        path = self._write(self.no_drift(unit), "loop.json")
        code, receipt, err = support.run_saipal_json("submit", str(path), home=self.home)
        self.assertEqual(code, 0, err)
        _code, second, _err = support.run_saipal_json("next", home=self.home)
        if second.get("analysis_carrier"):
            self.assertNotEqual(
                second["analysis_carrier"]["episode"]["index"],
                unit["episode"]["index"],
                "the loop must advance to a different unit",
            )
        else:
            self.assertEqual(second["carrier"], "idle")


class ReceiptIdentity(unittest.TestCase):
    """The idempotency key binds unit, verdict and reasoning -- nothing else."""

    def test_the_same_verdict_and_reasoning_on_one_unit_is_one_receipt(self) -> None:
        base = {"unit_digest": "a" * 64, "verdict": "NO_DRIFT", "reasoning": "clean"}
        self.assertEqual(submit_mod.receipt_id(base), submit_mod.receipt_id(dict(base)))

    def test_a_different_verdict_on_one_unit_is_a_different_receipt(self) -> None:
        first = {"unit_digest": "a" * 64, "verdict": "NO_DRIFT", "reasoning": "clean"}
        second = dict(first, verdict="DRIFT")
        self.assertNotEqual(submit_mod.receipt_id(first), submit_mod.receipt_id(second))

    def test_different_reasoning_on_one_unit_is_a_different_receipt(self) -> None:
        first = {"unit_digest": "a" * 64, "verdict": "NO_DRIFT", "reasoning": "clean"}
        second = dict(first, reasoning="clean, on reflection")
        self.assertNotEqual(submit_mod.receipt_id(first), submit_mod.receipt_id(second))

    def test_a_different_unit_is_a_different_receipt(self) -> None:
        first = {"unit_digest": "a" * 64, "verdict": "NO_DRIFT", "reasoning": "clean"}
        second = dict(first, unit_digest="b" * 64)
        self.assertNotEqual(submit_mod.receipt_id(first), submit_mod.receipt_id(second))


class MultiGenerationSessionIsAddressable(unittest.TestCase):
    """A re-imported session must still be submittable (dogfooding regression).

    A COLD artifact that changed becomes a new generation of the same session, so
    one session id can hold several records. `next` hands over the freshest one;
    `submit` used to rebuild the FIRST index match, so for every such session the
    two unit digests could never agree and every submission was refused as stale.
    That made the analyst loop unusable on exactly the sessions that were re-read.
    """

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        # A second, different COLD artifact for the same session id: a new
        # generation of one session, which is what the index is designed to hold.
        support.put_inbox(self.home, "cold-changed-v2.json")
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _generations(self) -> list[int]:
        return sorted(
            int(record["generation"])
            for record in support.sessions_of(self.home)
            if record["session_id"] == "golden-cold-001"
        )

    def test_the_fixture_really_produced_two_generations(self) -> None:
        """Red control: without two generations this whole class proves nothing."""
        self.assertEqual(self._generations(), [1, 2])

    def test_find_unit_selects_the_generation_next_hands_over(self) -> None:
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        self.assertEqual(status, "ok")
        offered, episode = carrier_mod.next_unit(index, self.registry)
        self.assertEqual(offered["session_id"], "golden-cold-001")
        addressed, _episode = carrier_mod.find_unit(
            index, "golden-cold-001", int(episode["index"])
        )
        self.assertEqual(addressed["generation"], offered["generation"])
        self.assertEqual(
            carrier_mod.unit_digest(addressed, episode),
            carrier_mod.unit_digest(offered, episode),
        )

    def test_a_candidate_for_the_offered_unit_is_accepted(self) -> None:
        _code, payload, _err = support.run_saipal_json("next", home=self.home)
        unit = payload["analysis_carrier"]
        candidate = {
            "schema_version": 1,
            "verdict": "NO_DRIFT",
            "unit_digest": unit["unit_digest"],
            "session_id": unit["session"]["session_id"],
            "episode_index": unit["episode"]["index"],
            "disposition_class": "NO_DRIFT",
            "reasoning": "the re-imported generation carries the same conformant span",
        }
        path = self.tmp / "gen.json"
        path.write_text(json.dumps(candidate), encoding="utf-8")
        code, receipt, err = support.run_saipal_json("submit", str(path), home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(receipt["verdict"], "NO_DRIFT")


class NoHindsightSurvivesSubmission(SubmitBase):
    """An analyst cannot assert its way past the no-hindsight gate."""

    def test_an_unbound_session_caps_analyst_confidence(self) -> None:
        # A home holding only the unbound fixture, so the pending unit is that
        # session and the assertion is not at the mercy of intake ordering.
        home = support.make_home(self.tmp, ".saipal-unbound")
        support.run_saipal("continue", home=home)
        support.put_inbox(home, "unknown-protocol.json")
        support.run_saipal("continue", home=home)

        unit = carrier_mod.build_carrier(home, registry=self.registry)
        self.assertIsNotNone(unit["session"], "the unbound fixture must be pending")
        self.assertEqual(unit["protocol"]["binding_status"], "UNKNOWN")
        self.assertFalse(unit["protocol"]["violation_claimable"])

        receipt = submit_mod.submit_candidate(
            home, self.drift(unit, confidence="HIGH"), registry=self.registry
        )
        findings = json.loads(
            (home / "findings" / "index.json").read_text(encoding="utf-8")
        )["findings"]
        finding = next(f for f in findings if f["finding_id"] == receipt["finding_id"])
        self.assertEqual(
            finding["confidence"], "LOW",
            "an unbound session cannot carry a HIGH-confidence violation claim",
        )
        self.assertIsNone(receipt["audit"], "no audit may leave on an unbound claim")


if __name__ == "__main__":
    unittest.main()
