"""T-048: the causal key -- one root cause, one finding (PAL-ROOTCAUSE-01).

Identity used to be a hash of 120 raw characters of prose. That makes dedupe a
function of wording: two analysts describing one defect differently create two
findings, and a single rephrase splits a recurrence chain in half. Recurrence is
the signal that tells a maintainer "this keeps happening", so splitting it is the
most expensive silent failure in the pipeline.

These tests pin both directions: paraphrases of one mechanism must converge, and
genuinely different mechanisms must stay apart.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import causal
from saipal_engine import findings as findings_mod
from saipal_engine import recurrence as recurrence_mod


class Normalization(unittest.TestCase):
    """What the key keeps, and what it deliberately throws away."""

    def test_empty_input_yields_an_empty_key(self) -> None:
        self.assertEqual(causal.normalize_cause(""), "")
        self.assertEqual(causal.normalize_cause(None), "")

    def test_case_and_punctuation_do_not_matter(self) -> None:
        self.assertEqual(
            causal.normalize_cause("Command ROUTED outside the surface!"),
            causal.normalize_cause("command routed outside surface"),
        )

    def test_word_order_does_not_matter(self) -> None:
        self.assertEqual(
            causal.normalize_cause("the closed surface rejected the route"),
            causal.normalize_cause("the route rejected the closed surface"),
        )

    def test_filler_words_are_dropped(self) -> None:
        self.assertEqual(
            causal.normalize_cause("the command was simply not really validated"),
            causal.normalize_cause("command not validated"),
        )

    def test_digests_are_not_part_of_identity(self) -> None:
        """A per-session digest in the prose must not fork the finding."""
        first = causal.normalize_cause("bundle a1b2c3d4e5f6 was accepted unvalidated")
        second = causal.normalize_cause("bundle f6e5d4c3b2a1 was accepted unvalidated")
        self.assertEqual(first, second)

    def test_session_ids_are_not_part_of_identity(self) -> None:
        first = causal.normalize_cause("ses_fa8e2f1d6ffe skipped the closure event")
        second = causal.normalize_cause("ses_zz11223344aa skipped the closure event")
        self.assertEqual(first, second)

    def test_ticket_ids_and_numbers_are_not_part_of_identity(self) -> None:
        first = causal.normalize_cause("T-101 advanced past seq 42 without a receipt")
        second = causal.normalize_cause("T-999 advanced past seq 7 without a receipt")
        self.assertEqual(first, second)

    def test_paths_are_not_part_of_identity(self) -> None:
        first = causal.normalize_cause(r"wrote V:\proj\STATE.md outside the home")
        second = causal.normalize_cause("wrote /srv/other/STATE.md outside the home")
        self.assertEqual(first, second)

    def test_inflections_converge(self) -> None:
        self.assertEqual(
            causal.normalize_cause("the carrier routes commands"),
            causal.normalize_cause("the carrier routed a command"),
        )

    def test_the_key_is_bounded(self) -> None:
        long = " ".join(f"distinct{index}" for index in range(200))
        self.assertLessEqual(len(causal.normalize_cause(long).split()), causal.MAX_TOKENS)

    def test_different_mechanisms_stay_different(self) -> None:
        """The important negative: normalization must not merge real defects."""
        route = causal.normalize_cause("the command routed outside the closed surface")
        closure = causal.normalize_cause("the source receipt never received a closure event")
        self.assertNotEqual(route, closure)

    def test_a_stopword_only_description_yields_an_empty_key(self) -> None:
        self.assertEqual(causal.normalize_cause("it was the one that did"), "")


class KeyExtraction(unittest.TestCase):
    """Where the key comes from when the analyst said little."""

    def test_root_cause_is_preferred(self) -> None:
        key = causal.causal_key(
            {"root_cause": "closure never required", "observed": {"summary": "other"}}
        )
        self.assertEqual(key, causal.normalize_cause("closure never required"))

    def test_the_hypothesis_is_the_fallback(self) -> None:
        key = causal.causal_key({"root_cause_hypothesis": "closure never required"})
        self.assertEqual(key, causal.normalize_cause("closure never required"))

    def test_observed_facts_are_the_last_resort(self) -> None:
        key = causal.causal_key({"observed": {"canonical": "saipen teleport"}})
        self.assertTrue(key)

    def test_a_candidate_with_nothing_has_an_empty_key(self) -> None:
        self.assertEqual(causal.causal_key({}), "")

    def test_an_empty_root_cause_falls_through(self) -> None:
        key = causal.causal_key({"root_cause": "   ", "observed": {"summary": "phase skipped"}})
        self.assertTrue(key)


class Fingerprint(unittest.TestCase):
    """Identity is mechanism + law + surface, never session or wording."""

    def base(self, **overrides) -> dict:
        candidate = {
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "rule_ids": ["PAL-CMD-01"],
            "change_target": "ENGINE",
            "root_cause": "the command routed outside the closed surface",
        }
        candidate.update(overrides)
        return candidate

    def test_a_paraphrase_is_the_same_finding(self) -> None:
        """The whole ticket, in one assertion."""
        first = findings_mod.fingerprint_of(self.base())
        second = findings_mod.fingerprint_of(
            self.base(root_cause="Outside the closed surface, the command was routed.")
        )
        self.assertEqual(first, second)

    def test_rule_order_does_not_change_identity(self) -> None:
        first = findings_mod.fingerprint_of(self.base(rule_ids=["PAL-CMD-01", "PAL-CMD-02"]))
        second = findings_mod.fingerprint_of(self.base(rule_ids=["PAL-CMD-02", "PAL-CMD-01"]))
        self.assertEqual(first, second)

    def test_a_different_drift_class_is_a_different_finding(self) -> None:
        self.assertNotEqual(
            findings_mod.fingerprint_of(self.base()),
            findings_mod.fingerprint_of(self.base(drift_class="PHASE_SKIP")),
        )

    def test_a_different_change_target_is_a_different_finding(self) -> None:
        self.assertNotEqual(
            findings_mod.fingerprint_of(self.base()),
            findings_mod.fingerprint_of(self.base(change_target="CORE_PROTOCOL")),
        )

    def test_a_different_mechanism_is_a_different_finding(self) -> None:
        self.assertNotEqual(
            findings_mod.fingerprint_of(self.base()),
            findings_mod.fingerprint_of(
                self.base(root_cause="the source receipt never received a closure event")
            ),
        )

    def test_the_session_is_not_part_of_identity(self) -> None:
        self.assertEqual(
            findings_mod.fingerprint_of(self.base(session_id="s1")),
            findings_mod.fingerprint_of(self.base(session_id="s2")),
        )

    def test_the_fingerprint_is_a_stable_length(self) -> None:
        self.assertEqual(len(findings_mod.fingerprint_of(self.base())), 32)


class DedupeAndRecurrence(unittest.TestCase):
    """One mechanism described twice is one finding with two occurrences."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def candidate(self, root_cause: str, episode_id: int | None = None) -> dict:
        """An analyst-confirmed candidate: the only shape that may create a finding."""
        return {
            "detector": "analyst",
            "episode_id": episode_id,
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "rule_ids": ["PAL-CMD-01"],
            "change_target": "ENGINE",
            "root_cause": root_cause,
            "mechanical_confidence": "LOW",
            "semantic_confirmation": {
                "receipt_id": "rcp-test",
                "verdict": "DRIFT",
                "session_id": "s1",
                "episode_index": episode_id if episode_id is not None else 0,
                "unit_digest": "u" * 64,
            },
        }

    def test_two_paraphrases_merge_into_one_finding(self) -> None:
        index = findings_mod.empty_index()
        findings_mod.merge_candidates(
            index, [self.candidate("the command routed outside the closed surface")],
            {"session_id": "s1"},
        )
        findings_mod.merge_candidates(
            index,
            [self.candidate("Outside the closed surface the commands were routed")],
            {"session_id": "s2"},
        )
        self.assertEqual(len(index["findings"]), 1, "a paraphrase must not fork")
        self.assertEqual(len(index["findings"][0]["occurrences"]), 2)

    def test_two_mechanisms_stay_two_findings(self) -> None:
        index = findings_mod.empty_index()
        findings_mod.merge_candidates(
            index, [self.candidate("the command routed outside the closed surface", episode_id=0)],
            {"session_id": "s1"},
        )
        findings_mod.merge_candidates(
            index, [self.candidate("the source receipt never received a closure event", episode_id=1)],
            {"session_id": "s1"},
        )
        self.assertEqual(len(index["findings"]), 2)

    def test_a_finding_records_its_causal_key(self) -> None:
        index = findings_mod.empty_index()
        created = findings_mod.merge_candidates(
            index, [self.candidate("the command routed outside the closed surface")],
            {"session_id": "s1"},
        )[0]
        self.assertTrue(created["causal_key"])
        self.assertEqual(
            created["causal_key"],
            causal.normalize_cause("the command routed outside the closed surface"),
        )

    def test_a_finding_index_carrying_a_causal_key_still_validates(self) -> None:
        index = findings_mod.empty_index()
        findings_mod.merge_candidates(
            index, [self.candidate("closure was never required")], {"session_id": "s1"}
        )
        self.assertEqual(findings_mod.validate_index(index), [])

    def test_recurrence_groups_the_paraphrases_together(self) -> None:
        """The payoff: one chain the maintainer can actually read as a trend."""
        index = findings_mod.empty_index()
        first = findings_mod.merge_candidates(
            index, [self.candidate("the command routed outside the closed surface")],
            {"session_id": "s1"},
        )[0]
        recurrence_mod.record_occurrence(
            self.home, first, {"session_id": "s1", "adapter": "generic", "conformant": False}
        )
        second = findings_mod.merge_candidates(
            index,
            [self.candidate("Outside the closed surface, a command was routed.")],
            {"session_id": "s2"},
        )
        # merge answered with the finding the paraphrase stood on.
        self.assertEqual(
            [row["finding_id"] for row in second], [first["finding_id"]]
        )
        recurrence_mod.record_occurrence(
            self.home, first, {"session_id": "s2", "adapter": "generic", "conformant": False}
        )
        data = recurrence_mod.load_recurrence(self.home)
        self.assertEqual(len(data["by_finding"]), 1, "one chain, not two")
        entry = next(iter(data["by_finding"].values()))
        self.assertEqual(len(entry["occurrences"]), 2)
        self.assertTrue(entry["causal_key"])

    def test_cross_project_recurrence_sees_one_class(self) -> None:
        index = findings_mod.empty_index()
        finding = findings_mod.merge_candidates(
            index, [self.candidate("the command routed outside the closed surface")],
            {"session_id": "s1"},
        )[0]
        for project in ("alpha", "beta"):
            recurrence_mod.record_occurrence(
                self.home,
                finding,
                {
                    "session_id": f"s-{project}",
                    "adapter": "generic",
                    "project": {"name": project},
                    "conformant": False,
                },
            )
        data = recurrence_mod.load_recurrence(self.home)
        rows = recurrence_mod.cross_project_recurrence(data, "COMMAND_ROUTE_DRIFT")
        self.assertEqual({row["project"] for row in rows}, {"alpha", "beta"})


if __name__ == "__main__":
    unittest.main()
