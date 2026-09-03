"""T-041: the structured semantic candidate -- the only thing Layer B may submit.

The candidate is where a replaceable model's reasoning meets a kernel that must
not be talked into anything. So the tests are mostly red controls: an unknown
field, a verdict outside the closed set, a no-drift receipt smuggling a claim, a
claim with no challenge, evidence pointing outside the episode, a stale unit.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import candidates as cand
from saipal_engine import capability as cap_mod
from saipal_engine import carrier as carrier_mod
from saipal_engine.errors import PalError
from saipal_engine.registry import load_registry

DRIFT_FIXTURE = "agent-noncompliance-command-route.json"


def _drift(carrier: dict) -> dict:
    return {
        "schema_version": 1,
        "verdict": "DRIFT",
        "unit_digest": carrier["unit_digest"],
        "session_id": carrier["session"]["session_id"],
        "episode_index": carrier["episode"]["index"],
        "disposition_class": "MODEL_NONCOMPLIANCE",
        "reasoning": "the command left the closed surface and no later event repaired it",
        "rule_ids": ["PAL-CMD-01"],
        "event_refs": [carrier["episode"]["start_seq"]],
        "drift_class": "COMMAND_ROUTE_DRIFT",
        "severity": "P2",
        "confidence": "MEDIUM",
        "change_target": "ENGINE",
        "root_cause": "the carrier did not recognize the token as a declared subcommand",
        "challenge": {
            "prosecutor": "PAL-CMD-01 names the closed surface; the observed token is not in it",
            "defender": "the user may have typed a shell command the adapter mislabelled",
            "winner": "prosecutor",
            "loser_rejection": "the adapter recorded a canonical protocol token, not a shell string",
        },
        "alternatives": ["adapter normalization mislabelled a shell command"],
        "contrary_evidence": [],
        "missing_evidence": ["the registry snapshot at the time of the command"],
        "protected_invariants": ["verify"],
    }


def _no_drift(carrier: dict) -> dict:
    return {
        "schema_version": 1,
        "verdict": "NO_DRIFT",
        "unit_digest": carrier["unit_digest"],
        "session_id": carrier["session"]["session_id"],
        "episode_index": carrier["episode"]["index"],
        "disposition_class": "NO_DRIFT",
        "reasoning": "every command in the span routed through the declared surface",
        "event_refs": [carrier["episode"]["start_seq"]],
    }


class CandidateBase(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, DRIFT_FIXTURE)
        support.run_saipal("continue", home=self.home)
        self.carrier = carrier_mod.build_carrier(self.home, registry=self.registry)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def problems(self, candidate: dict) -> list[str]:
        return cand.candidate_problems(candidate, registry=self.registry)


class Shape(CandidateBase):
    """A valid candidate validates; a malformed one names every reason."""

    def test_a_complete_drift_candidate_is_admissible(self) -> None:
        self.assertEqual(self.problems(_drift(self.carrier)), [])

    def test_a_no_drift_receipt_is_admissible(self) -> None:
        self.assertEqual(self.problems(_no_drift(self.carrier)), [])

    def test_a_non_object_candidate_is_refused(self) -> None:
        self.assertEqual(
            cand.candidate_problems("looks fine to me", registry=self.registry),
            ["candidate root is not an object"],
        )

    def test_an_unknown_field_is_refused(self) -> None:
        payload = _drift(self.carrier)
        payload["patch"] = "diff --git a/CORE.md"
        self.assertTrue(any("unknown candidate field" in p for p in self.problems(payload)))

    def test_a_missing_required_field_is_refused(self) -> None:
        payload = _no_drift(self.carrier)
        del payload["reasoning"]
        self.assertTrue(any("missing required field" in p for p in self.problems(payload)))

    def test_a_wrong_schema_version_is_refused(self) -> None:
        payload = _no_drift(self.carrier)
        payload["schema_version"] = 2
        self.assertTrue(any("schema_version" in p for p in self.problems(payload)))

    def test_a_verdict_outside_the_closed_set_is_refused(self) -> None:
        payload = _no_drift(self.carrier)
        payload["verdict"] = "PROBABLY_FINE"
        self.assertTrue(any("verdict" in p for p in self.problems(payload)))

    def test_a_disposition_outside_the_closed_set_is_refused(self) -> None:
        payload = _no_drift(self.carrier)
        payload["disposition_class"] = "VIBES"
        self.assertTrue(any("disposition_class" in p for p in self.problems(payload)))

    def test_a_negative_episode_index_is_refused(self) -> None:
        payload = _no_drift(self.carrier)
        payload["episode_index"] = -1
        self.assertTrue(any("episode_index" in p for p in self.problems(payload)))

    def test_a_non_integer_episode_index_is_refused(self) -> None:
        payload = _no_drift(self.carrier)
        payload["episode_index"] = "first"
        self.assertTrue(any("episode_index must be an integer" in p for p in self.problems(payload)))

    def test_a_non_integer_event_ref_is_refused(self) -> None:
        payload = _drift(self.carrier)
        payload["event_refs"] = ["seq 1"]
        self.assertTrue(any("must be an integer" in p for p in self.problems(payload)))

    def test_oversized_reasoning_is_refused(self) -> None:
        limit = int(self.registry["candidate_limits"]["max_reasoning_chars"])
        payload = _no_drift(self.carrier)
        payload["reasoning"] = "x" * (limit + 1)
        self.assertTrue(any("exceeds" in p for p in self.problems(payload)))

    def test_too_many_list_items_is_refused(self) -> None:
        limit = int(self.registry["candidate_limits"]["max_list_items"])
        payload = _drift(self.carrier)
        payload["alternatives"] = [f"alternative {index}" for index in range(limit + 2)]
        self.assertTrue(any("exceeds" in p for p in self.problems(payload)))

    def test_too_many_event_refs_is_refused(self) -> None:
        limit = int(self.registry["candidate_limits"]["max_event_refs"])
        payload = _drift(self.carrier)
        payload["event_refs"] = list(range(1, limit + 3))
        self.assertTrue(any("event_refs exceeds" in p for p in self.problems(payload)))

    def test_normalize_drops_nothing_valid_and_keeps_the_closed_set(self) -> None:
        payload = _drift(self.carrier)
        normalized = cand.normalize_candidate(payload, registry=self.registry)
        self.assertEqual(self.problems(normalized), [])
        self.assertEqual(set(normalized) - set(self.registry["candidate_fields"]), set())
        self.assertEqual(normalized["rule_ids"], payload["rule_ids"])


class ClaimDiscipline(CandidateBase):
    """A DRIFT claim carries its burden; a NO_DRIFT receipt may not smuggle one."""

    def test_a_drift_verdict_without_a_rule_is_refused(self) -> None:
        payload = _drift(self.carrier)
        payload["rule_ids"] = []
        self.assertTrue(any("at least one rule id" in p for p in self.problems(payload)))

    def test_a_drift_verdict_without_an_event_is_refused(self) -> None:
        payload = _drift(self.carrier)
        payload["event_refs"] = []
        self.assertTrue(any("at least one event" in p for p in self.problems(payload)))

    def test_a_drift_verdict_without_a_challenge_is_refused(self) -> None:
        payload = _drift(self.carrier)
        del payload["challenge"]
        self.assertTrue(any("challenge" in p for p in self.problems(payload)))

    def test_a_challenge_missing_the_defender_is_refused(self) -> None:
        payload = _drift(self.carrier)
        del payload["challenge"]["defender"]
        self.assertTrue(
            any("challenge.defender is required" in p for p in self.problems(payload))
        )

    def test_a_challenge_without_a_loser_rejection_is_refused(self) -> None:
        payload = _drift(self.carrier)
        payload["challenge"]["loser_rejection"] = "   "
        self.assertTrue(
            any("challenge.loser_rejection is required" in p for p in self.problems(payload))
        )

    def test_a_challenge_winner_outside_the_two_passes_is_refused(self) -> None:
        payload = _drift(self.carrier)
        payload["challenge"]["winner"] = "both"
        self.assertTrue(any("challenge.winner" in p for p in self.problems(payload)))

    def test_an_unknown_challenge_field_is_refused(self) -> None:
        payload = _drift(self.carrier)
        payload["challenge"]["verdict_override"] = "HIGH"
        self.assertTrue(
            any("challenge has unknown field" in p for p in self.problems(payload))
        )

    def test_a_drift_verdict_without_an_alternative_is_refused(self) -> None:
        """PAL-ANALYSIS-02: a claim with no alternative was never challenged."""
        payload = _drift(self.carrier)
        payload["alternatives"] = []
        self.assertTrue(any("alternative explanation" in p for p in self.problems(payload)))

    def test_a_drift_verdict_outside_the_taxonomy_is_refused(self) -> None:
        payload = _drift(self.carrier)
        payload["drift_class"] = "VIBES_DRIFT"
        self.assertTrue(any("outside the taxonomy" in p for p in self.problems(payload)))

    def test_a_drift_verdict_with_an_unknown_change_target_is_refused(self) -> None:
        payload = _drift(self.carrier)
        payload["change_target"] = "WHATEVER_IS_EASIEST"
        self.assertTrue(any("change_target" in p for p in self.problems(payload)))

    def test_a_no_drift_receipt_may_not_carry_a_drift_class(self) -> None:
        """Red control: a finding with the label filed off is still a finding."""
        payload = _no_drift(self.carrier)
        payload["drift_class"] = "COMMAND_ROUTE_DRIFT"
        self.assertTrue(
            any("only admissible on a DRIFT verdict" in p for p in self.problems(payload))
        )

    def test_a_no_drift_receipt_may_not_carry_a_change_target(self) -> None:
        payload = _no_drift(self.carrier)
        payload["change_target"] = "CORE_PROTOCOL"
        self.assertTrue(
            any("only admissible on a DRIFT verdict" in p for p in self.problems(payload))
        )

    def test_insufficient_evidence_may_not_carry_a_claim(self) -> None:
        payload = _no_drift(self.carrier)
        payload["verdict"] = "INSUFFICIENT_EVIDENCE"
        payload["disposition_class"] = "INSUFFICIENT_EVIDENCE"
        payload["confidence"] = "HIGH"
        self.assertTrue(
            any("only admissible on a DRIFT verdict" in p for p in self.problems(payload))
        )

    def test_insufficient_evidence_without_a_claim_is_admissible(self) -> None:
        payload = _no_drift(self.carrier)
        payload["verdict"] = "INSUFFICIENT_EVIDENCE"
        payload["disposition_class"] = "INSUFFICIENT_EVIDENCE"
        payload["missing_evidence"] = ["the SESSION_BOUNDARY that should close the intake"]
        self.assertEqual(self.problems(payload), [])


class EpisodeScope(CandidateBase):
    """A candidate answers the unit it was handed, over that unit's evidence."""

    def scope(self, candidate: dict, carrier: dict | None = None) -> list[str]:
        return cand.episode_scope_problems(
            candidate, carrier or self.carrier, registry=self.registry
        )

    def test_a_matching_candidate_is_in_scope(self) -> None:
        self.assertEqual(self.scope(_drift(self.carrier)), [])

    def test_another_session_is_out_of_scope(self) -> None:
        payload = _drift(self.carrier)
        payload["session_id"] = "some-other-session"
        self.assertTrue(any("is not the carrier's session" in p for p in self.scope(payload)))

    def test_another_episode_is_out_of_scope(self) -> None:
        payload = _drift(self.carrier)
        payload["episode_index"] = self.carrier["episode"]["index"] + 7
        self.assertTrue(any("is not the carrier's episode" in p for p in self.scope(payload)))

    def test_a_stale_unit_digest_is_refused(self) -> None:
        """Red control: evidence that changed under the analyst invalidates reasoning."""
        payload = _drift(self.carrier)
        payload["unit_digest"] = "0" * 64
        self.assertTrue(any("unit_digest does not match" in p for p in self.scope(payload)))

    def test_an_event_outside_the_span_is_refused(self) -> None:
        payload = _drift(self.carrier)
        payload["event_refs"] = [self.carrier["episode"]["end_seq"] + 500]
        self.assertTrue(any("outside the episode span" in p for p in self.scope(payload)))

    def test_an_idle_carrier_has_no_unit_to_answer(self) -> None:
        idle = {"carrier": "idle", "session": None}
        self.assertEqual(
            cand.episode_scope_problems(_drift(self.carrier), idle, registry=self.registry),
            ["carrier does not name an analysis unit"],
        )

    def test_the_unit_digest_tracks_evidence_not_context(self) -> None:
        """Recurrence and calibration move constantly; the digest must not."""
        record = support.sessions_of(self.home)[0]
        episode = record["episodes"][0]
        first = carrier_mod.unit_digest(record, episode)
        again = carrier_mod.unit_digest(dict(record), dict(episode))
        self.assertEqual(first, again)
        mutated = dict(record)
        mutated["bundle_sha256"] = "f" * 64
        self.assertNotEqual(carrier_mod.unit_digest(mutated, episode), first)


class AnalystCapability(unittest.TestCase):
    """Layer B's namespace is separate, and enforced by code, not prose."""

    def setUp(self) -> None:
        self.registry = load_registry()

    def test_submit_candidate_is_the_analyst_write_path(self) -> None:
        cap_mod.require_analyst_action("submit_candidate", registry=self.registry)

    def test_read_actions_are_permitted(self) -> None:
        for action in ("read_carrier", "read_evidence"):
            cap_mod.require_analyst_action(action, registry=self.registry)

    def test_the_analyst_may_never_enqueue_an_audit(self) -> None:
        """Red control: the audit write belongs to the kernel alone."""
        with self.assertRaises(PalError) as raised:
            cap_mod.require_analyst_action("enqueue_audit", registry=self.registry)
        self.assertEqual(raised.exception.code, "CAPABILITY_DENIED")

    def test_the_analyst_may_never_write_kernel_state(self) -> None:
        for action in ("write_own_state", "write_own_index", "write_own_log"):
            with self.assertRaises(PalError):
                cap_mod.require_analyst_action(action, registry=self.registry)

    def test_an_invented_analyst_action_is_denied_by_default(self) -> None:
        with self.assertRaises(PalError) as raised:
            cap_mod.require_analyst_action("just_this_once", registry=self.registry)
        self.assertIn("outside the closed analyst set", raised.exception.message)


if __name__ == "__main__":
    unittest.main()
