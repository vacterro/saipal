"""T-73: one evidence occurrence, one recurrence row.

An episode that drifts has TWO writers. The deterministic pass records it from
the pipeline with no write key (`record_batch`), and an analyst DRIFT
confirmation of that same episode merges onto that same finding and records it
again keyed by its receipt (`submit._absorb_drift`). The two keys never agreed,
so the ledger held two rows for one event and `by_rule` counted it twice --
inflating exactly the conformance rates, spread and carrier projection a
maintainer routes by.

The fix gives the row the anchor the finding already dedupes on: which session,
which episode, which events. The write key stays the crash-recovery identity
(audit W2-002); callers with no evidence to anchor keep their historical
append-only semantics.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import carrier as carrier_mod
from saipal_engine import recurrence as recurrence_mod
from saipal_engine import sessions as sessions_mod
from saipal_engine import submit as submit_mod
from saipal_engine.registry import load_registry

DRIFT = "agent-noncompliance-command-route.json"
SESSION = "golden-agent-noncompliance-001"
DRIFT_EPISODE = 2  # the episode carrying 'saipen nope --force' at seq 5
DRIFT_EVENT = 5


class LedgerBase(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def ledger(self) -> dict:
        return recurrence_mod.load_recurrence(self.home)

    def rows(self) -> list[dict]:
        return [
            row
            for entry in (self.ledger().get("by_finding") or {}).values()
            for row in entry.get("occurrences") or []
        ]


class OneEventIsOneRow(LedgerBase):
    """The reproduction, end to end through the real CLI and the real submit."""

    def stage_drift(self) -> None:
        """Stamped fixture: the release claim verifies against the declared
        authority, so the session is BOUND and a DRIFT verdict may create a
        finding at all. A PARTIAL unit cannot carry protocol drift."""
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)

    def unit(self) -> dict:
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        self.assertEqual(status, "ok")
        return carrier_mod.build_carrier(
            self.home,
            registry=self.registry,
            index=index,
            session_id=SESSION,
            episode_index=DRIFT_EPISODE,
        )

    def confirmation(self) -> dict:
        unit = self.unit()
        return {
            "schema_version": 1,
            "verdict": "DRIFT",
            "unit_digest": unit["unit_digest"],
            "session_id": unit["session"]["session_id"],
            "episode_index": unit["episode"]["index"],
            "slice_index": unit["slice"]["index"],
            "disposition_class": "ENGINE_ENFORCEMENT_GAP",
            "reasoning": (
                "the engine executed an undeclared command with a force flag "
                "and the edit landed on the protocol core"
            ),
            "rule_ids": ["PAL-CMD-01", "PAL-CMD-02", "PAL-CMD-03"],
            "event_refs": [DRIFT_EVENT],
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P3",
            "confidence": "MEDIUM",
            "change_target": "ENGINE",
            "root_cause": (
                "an undeclared command with a force flag was executed "
                "against the protocol core"
            ),
            "challenge": {
                "prosecutor": "PAL-CMD-01 names the closed surface; this route was not on it",
                "defender": "the raw token may be a user alias the adapter normalized",
                "winner": "prosecutor",
                "loser_rejection": "the canonical form was recorded verbatim with --force",
            },
            "alternatives": ["the user invoked the command through a shell alias"],
            "protected_invariants": ["destructive_confirmation"],
        }

    def findings(self) -> list[dict]:
        path = self.home / "findings" / "index.json"
        if not path.is_file():
            return []
        return json.loads(path.read_text(encoding="utf-8"))["findings"]

    def test_the_mechanical_pass_anchors_no_row(self) -> None:
        """Triage raises signals, never drift rows: only a semantic verdict
        writes a drift occurrence, and it is anchored to the evidence."""
        self.stage_drift()
        self.assertEqual(self.rows(), [], "a mechanical pass writes no drift row")
        submit_mod.submit_candidate(
            self.home, self.confirmation(), registry=self.registry
        )
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["evidence_anchor"], [f"{DRIFT_EPISODE}:{DRIFT_EVENT}"])

    def test_an_analyst_confirmation_adds_no_second_row(self) -> None:
        """One event, two writers would be the double count; the confirmation
        is the only writer now, and a retry merges onto the same row."""
        self.stage_drift()
        self.assertEqual(self.rows(), [], "precondition: no mechanical row exists")

        receipt = submit_mod.submit_candidate(
            self.home, self.confirmation(), registry=self.registry
        )
        self.assertFalse(receipt["duplicate"], "precondition: a fresh submission")
        self.assertEqual(
            receipt["finding_id"],
            self.findings()[0]["finding_id"],
            "precondition: the confirmation created the finding",
        )
        self.assertEqual(len(self.rows()), 1, "one event may not be counted twice")

    def test_the_rule_buckets_are_not_double_counted_either(self) -> None:
        """The rates a maintainer routes by come from `by_rule`, not the rows."""
        self.stage_drift()
        self.assertEqual(self.ledger()["by_rule"], {})
        submit_mod.submit_candidate(self.home, self.confirmation(), registry=self.registry)
        self.assertEqual(
            self.ledger()["by_rule"]["PAL-CMD-01"], {"total": 1, "drift": 1}
        )

    def test_the_spread_still_sees_exactly_one_occurrence(self) -> None:
        self.stage_drift()
        submit_mod.submit_candidate(self.home, self.confirmation(), registry=self.registry)
        spread = recurrence_mod.spread(self.ledger(), "COMMAND_ROUTE_DRIFT")
        self.assertEqual(spread["occurrences"], 1)
        self.assertEqual(spread["classification"], "SINGLE_MODEL")

    def test_a_resubmitted_confirmation_is_still_one_row(self) -> None:
        self.stage_drift()
        submit_mod.submit_candidate(self.home, self.confirmation(), registry=self.registry)
        again = submit_mod.submit_candidate(
            self.home, self.confirmation(), registry=self.registry
        )
        self.assertTrue(again["duplicate"])
        self.assertEqual(len(self.rows()), 1)


class TheAnchorIsTheEvidenceNotTheWrite(LedgerBase):
    """The primitive, driven directly: which rows converge and which do not."""

    def session(self, session_id: str = "s1") -> dict:
        return {
            "session_id": session_id,
            "adapter": "generic",
            "project": {"name": "P"},
            "protocol": {"version": "1.0.0"},
        }

    def finding(self, *occurrences: dict, fingerprint: str = "fp") -> dict:
        return {
            "finding_id": "PAL-0001",
            "fingerprint": fingerprint,
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "rule_ids": ["PAL-CMD-01"],
            "occurrences": list(occurrences),
        }

    def occurrence(self, session_id: str = "s1", episode: int = 2, refs=(5,)) -> dict:
        return {
            "session_id": session_id,
            "episode_id": episode,
            "event_refs": list(refs),
        }

    def count(self) -> int:
        return len(self.rows())

    def test_an_unkeyed_write_then_a_keyed_one_is_one_row(self) -> None:
        """Exactly the two writers: the pipeline batch, then the keyed submit."""
        finding = self.finding(self.occurrence())
        recurrence_mod.record_batch(self.home, self.session(), [finding])
        recurrence_mod.record_occurrence(
            self.home, finding, self.session(), occurrence_id="rcp-1"
        )
        self.assertEqual(self.count(), 1)

    def test_the_keyed_write_may_come_first(self) -> None:
        finding = self.finding(self.occurrence())
        recurrence_mod.record_occurrence(
            self.home, finding, self.session(), occurrence_id="rcp-1"
        )
        recurrence_mod.record_batch(self.home, self.session(), [finding])
        self.assertEqual(self.count(), 1)

    def test_a_second_episode_is_a_second_occurrence(self) -> None:
        """Convergence must not swallow real recurrence inside one session."""
        first = self.finding(self.occurrence())
        recurrence_mod.record_batch(self.home, self.session(), [first])
        grown = self.finding(self.occurrence(), self.occurrence(episode=7, refs=(19,)))
        recurrence_mod.record_batch(self.home, self.session(), [grown])
        self.assertEqual(self.count(), 2)

    def test_the_same_episode_in_another_session_is_another_occurrence(self) -> None:
        finding = self.finding(
            self.occurrence(), self.occurrence(session_id="s2")
        )
        recurrence_mod.record_batch(self.home, self.session("s1"), [finding])
        recurrence_mod.record_batch(self.home, self.session("s2"), [finding])
        self.assertEqual(self.count(), 2)
        self.assertEqual(
            {row["session_id"] for row in self.rows()}, {"s1", "s2"}
        )

    def test_the_event_order_does_not_decide_identity(self) -> None:
        recurrence_mod.record_batch(
            self.home, self.session(), [self.finding(self.occurrence(refs=(5, 9)))]
        )
        recurrence_mod.record_occurrence(
            self.home,
            self.finding(self.occurrence(refs=(9, 5))),
            self.session(),
            occurrence_id="rcp-1",
        )
        self.assertEqual(self.count(), 1)

    def test_a_different_event_in_one_episode_is_a_different_occurrence(self) -> None:
        recurrence_mod.record_batch(
            self.home, self.session(), [self.finding(self.occurrence(refs=(5,)))]
        )
        recurrence_mod.record_batch(
            self.home, self.session(), [self.finding(self.occurrence(refs=(6,)))]
        )
        self.assertEqual(self.count(), 2)

    def test_two_findings_on_one_event_stay_two_chains(self) -> None:
        """The anchor is scoped to a fingerprint, never global to the event."""
        recurrence_mod.record_batch(
            self.home,
            self.session(),
            [
                self.finding(self.occurrence(), fingerprint="fp-a"),
                self.finding(self.occurrence(), fingerprint="fp-b"),
            ],
        )
        self.assertEqual(sorted(self.ledger()["by_finding"]), ["fp-a", "fp-b"])
        self.assertEqual(self.count(), 2)

    def test_a_finding_with_no_evidence_stays_append_only(self) -> None:
        """Red control for the fallback: no anchor means the old semantics.

        A synthetic finding carries no occurrences to anchor on, and the
        deterministic negative-evidence path has none either. Silently deduping
        those would make an unkeyed caller lose writes it is entitled to.
        """
        finding = self.finding()
        recurrence_mod.record_batch(self.home, self.session(), [finding])
        recurrence_mod.record_batch(self.home, self.session(), [finding])
        self.assertEqual(self.count(), 2)

    def test_negative_evidence_stays_append_only(self) -> None:
        recurrence_mod.record_negative(self.home, self.session())
        recurrence_mod.record_negative(self.home, self.session())
        self.assertEqual(self.count(), 2)

    def test_the_write_key_still_dedupes_a_crash_retry(self) -> None:
        """W2-002 must survive the new key: an anchorless retry still converges."""
        finding = self.finding()
        for _ in range(3):
            recurrence_mod.record_occurrence(
                self.home, finding, self.session(), occurrence_id="rcp-1"
            )
        self.assertEqual(self.count(), 1)
        self.assertEqual(self.ledger()["by_rule"]["PAL-CMD-01"]["total"], 1)

    def test_a_deduped_write_saves_nothing(self) -> None:
        finding = self.finding(self.occurrence())
        recurrence_mod.record_batch(self.home, self.session(), [finding])
        before = (self.home / "recurrence.json").stat().st_mtime_ns
        result = recurrence_mod.record_occurrence(
            self.home, finding, self.session(), occurrence_id="rcp-1"
        )
        self.assertEqual(len(result["by_finding"]["fp"]["occurrences"]), 1)
        self.assertEqual((self.home / "recurrence.json").stat().st_mtime_ns, before)

    def test_a_ledger_entry_passed_back_claims_no_anchor(self) -> None:
        """`detect_regression` shapes an occurrence from a LEDGER entry, whose
        rows carry no episode or events; that must not read as an anchor."""
        recurrence_mod.record_batch(
            self.home, self.session(), [self.finding(self.occurrence())]
        )
        entry = self.ledger()["by_finding"]["fp"]
        entry["last_fix_version"] = "0.9.0"
        regression = recurrence_mod.detect_regression(
            self.ledger() | {"by_finding": {"fp": entry}}, "fp", self.session()
        )
        self.assertIsNotNone(regression)
        self.assertNotIn("evidence_anchor", regression["occurrence"])


if __name__ == "__main__":
    unittest.main()
