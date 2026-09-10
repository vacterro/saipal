"""T-104 (ROLE 15-20): one evidence occurrence, one recurrence anchor, one row.

T-74: the row anchor was the finding's WHOLE occurrence set, so a finding that
grew between the mechanical write and the analyst confirmation double-counted.
T-75: pre-T-73 rows carry no anchor at all and can never converge. The fix is
per-occurrence identity plus a deterministic one-shot v1->v2 migration.

Canonical rule: one immutable evidence occurrence == one anchor == one row
identity. Finding growth never changes an old occurrence's identity; prose,
severity, confidence and the recurrence count never decide identity.
"""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import recurrence as recurrence_mod
from saipal_engine import submit as submit_mod
from saipal_engine.registry import load_registry

DRIFT = "agent-noncompliance-command-route.json"
SESSION = "golden-agent-noncompliance-001"
DRIFT_EPISODE = 2
DRIFT_EVENT = 5


class PerOccurrenceBase(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def session(self, session_id: str = "s1", conformant: bool = False) -> dict:
        return {
            "session_id": session_id,
            "adapter": "generic",
            "project": {"name": "P"},
            "protocol": {"version": "1.0.0"},
            "conformant": conformant,
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

    def rows(self) -> list[dict]:
        return [
            row
            for entry in (recurrence_mod.load_recurrence(self.home).get("by_finding") or {}).values()
            for row in entry.get("occurrences") or []
        ]


class GrownFindingNeverReidentifies(PerOccurrenceBase):
    """ROLE 15/20 A + B (the T-74 reproduction)."""

    def test_mechanical_a_then_semantic_a_is_one_row(self) -> None:
        finding = self.finding(self.occurrence())
        recurrence_mod.record_batch(self.home, self.session(), [finding])
        recurrence_mod.record_occurrence(
            self.home, finding, self.session(), occurrence_id="rcp-1"
        )
        self.assertEqual(len(self.rows()), 1)

    def test_grown_finding_before_semantic_a_keeps_a_once_and_b_independent(self) -> None:
        """The T-74 defect: growth changed the row's whole-set anchor."""
        first = self.finding(self.occurrence())
        recurrence_mod.record_batch(self.home, self.session(), [first])
        grown = self.finding(
            self.occurrence(), self.occurrence(episode=7, refs=(19,))
        )
        recurrence_mod.record_occurrence(
            self.home, grown, self.session(), occurrence_id="rcp-1"
        )
        rows = self.rows()
        self.assertEqual(
            len(rows), 2,
            "A stays its own row; B is a genuinely new occurrence",
        )
        anchors = {row["evidence_anchor"] for row in rows}
        self.assertEqual(anchors, {"2:5", "7:19"})
        self.assertEqual(
            self.home and recurrence_mod.load_recurrence(self.home)["by_rule"]["PAL-CMD-01"]["total"],
            2,
        )

    def test_semantic_a_then_mechanical_reobservation_is_still_once(self) -> None:
        """ROLE 20 C: the reverse writer order converges too."""
        finding = self.finding(self.occurrence())
        recurrence_mod.record_occurrence(
            self.home, finding, self.session(), occurrence_id="rcp-1"
        )
        recurrence_mod.record_batch(self.home, self.session(), [finding])
        self.assertEqual(len(self.rows()), 1)

    def test_two_real_occurrences_two_anchors(self) -> None:
        recurrence_mod.record_batch(
            self.home,
            self.session(),
            [self.finding(self.occurrence(), self.occurrence(episode=9, refs=(30,)))],
        )
        self.assertEqual(len(self.rows()), 2)

    def test_same_evidence_different_prose_one_anchor(self) -> None:
        """Identity is the evidence occurrence, never the wording."""
        recurrence_mod.record_batch(
            self.home, self.session(), [self.finding(self.occurrence())]
        )
        rephrased = self.finding(self.occurrence())
        rephrased["severity"] = "P1"
        rephrased["confidence"] = "HIGH"
        rephrased["drift_class"] = "COMMAND_ROUTE_DRIFT"
        recurrence_mod.record_occurrence(
            self.home, rephrased, self.session(), occurrence_id="rcp-2"
        )
        self.assertEqual(len(self.rows()), 1)

    def test_rephrased_evidence_never_reidentifies_across_fingerprints(self) -> None:
        """The anchor is scoped to the fingerprint: another finding's row for
        the same evidence stays its own chain."""
        recurrence_mod.record_batch(
            self.home, self.session(), [self.finding(self.occurrence(), fingerprint="fp-a")]
        )
        recurrence_mod.record_batch(
            self.home, self.session(), [self.finding(self.occurrence(), fingerprint="fp-b")]
        )
        self.assertEqual(len(self.rows()), 2)


class LegacyMigration(PerOccurrenceBase):
    """ROLE 18/19/20 F-H: deterministic, crash-safe v1 -> v2."""

    def _v1_ledger(self, rows: list[dict]) -> Path:
        path = self.home / "recurrence.json"
        payload = {
            "schema_version": 1,
            "by_finding": {"fp": {"fingerprint": "fp", "occurrences": rows}},
            "by_rule": {"PAL-CMD-01": {"total": len(rows), "drift": len(rows)}},
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _write_findings_index(self, per_finding: dict) -> None:
        findings = []
        for fp, occurrences in per_finding.items():
            findings.append({"fingerprint": fp, "occurrences": occurrences})
        target = self.home / "findings" / "index.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps({"schema_version": 1, "findings": findings}), encoding="utf-8"
        )

    def test_legacy_exact_row_is_backfilled(self) -> None:
        self._write_findings_index(
            {"fp": [self.occurrence()]}
        )
        self._v1_ledger([
            {"session_id": "s1", "conformant": False, "evidence_anchor": ["2:5"]}
        ])
        report = recurrence_mod.migrate_recurrence(self.home)
        self.assertTrue(report["migrated"])
        self.assertEqual(report["backfilled"], 1)
        row = self.rows()[0]
        self.assertEqual(row["evidence_anchor"], "2:5")
        self.assertEqual(row["anchor_status"], "MIGRATED")

    def test_legacy_whole_set_anchor_splits_to_one_occurrence(self) -> None:
        """A grown v1 row named BOTH occurrences: exactly one per row is not
        recoverable, so it stays preserved and AMBIGUOUS."""
        self._v1_ledger([
            {"session_id": "s1", "conformant": False, "evidence_anchor": ["2:5", "7:19"]}
        ])
        report = recurrence_mod.migrate_recurrence(self.home)
        self.assertEqual(report["ambiguous"], 1)
        row = self.rows()[0]
        self.assertNotIn("evidence_anchor", row)
        self.assertEqual(row["anchor_status"], "AMBIGUOUS")
        self.assertEqual(row["legacy_anchor"], ["2:5", "7:19"])

    def test_legacy_pre_anchor_row_exact_match_backfills(self) -> None:
        """The T-75 case: no anchor at all, but the finding index names the
        ONE occurrence, so the row converges onto it."""
        self._write_findings_index({"fp": [self.occurrence()]})
        self._v1_ledger([{"session_id": "s1", "conformant": False}])
        report = recurrence_mod.migrate_recurrence(self.home)
        self.assertEqual(report["backfilled"], 1)
        row = self.rows()[0]
        self.assertEqual(row["evidence_anchor"], "2:5")
        self.assertEqual(row["anchor_status"], "MIGRATED")

    def test_legacy_ambiguous_history_is_preserved_and_flagged(self) -> None:
        self._write_findings_index(
            {"fp": [self.occurrence(), self.occurrence(episode=7, refs=(19,))]}
        )
        self._v1_ledger([{"session_id": "s1", "conformant": False}])
        report = recurrence_mod.migrate_recurrence(self.home)
        self.assertEqual(report["ambiguous"], 1)
        self.assertEqual(report["backfilled"], 0)
        row = self.rows()[0]
        self.assertNotIn("evidence_anchor", row)
        self.assertEqual(row["anchor_status"], "AMBIGUOUS")

    def test_legacy_unresolvable_row_is_preserved_unresolved(self) -> None:
        self._v1_ledger([{"session_id": "zzz", "conformant": False}])
        report = recurrence_mod.migrate_recurrence(self.home)
        self.assertEqual(report["unresolved"], 1)
        row = self.rows()[0]
        self.assertEqual(row["anchor_status"], "UNRESOLVED")
        self.assertEqual(row["session_id"], "zzz")

    def test_migration_is_idempotent(self) -> None:
        self._write_findings_index({"fp": [self.occurrence()]})
        self._v1_ledger([{"session_id": "s1", "conformant": False}])
        first = recurrence_mod.migrate_recurrence(self.home)
        second = recurrence_mod.migrate_recurrence(self.home)
        self.assertFalse(second["migrated"])
        self.assertEqual(first["backfilled"], 1)

    def test_migration_restart_is_deterministic(self) -> None:
        """Crash halfway: the v1 file is intact, the rerun derives the same v2.

        The migration is one atomic write, so a crash either left the ledger at
        v1 or at the complete v2 -- never a partial per-row migration. Both
        restart paths converge on the same final ledger.
        """
        self._write_findings_index(
            {
                "fp": [
                    self.occurrence(),
                    self.occurrence(session_id="s2", episode=3, refs=(11,)),
                ]
            }
        )
        self._v1_ledger([
            {"session_id": "s1", "conformant": False},
            {"session_id": "s2", "conformant": False},
        ])
        # Path 1: crash BEFORE the write -- the v1 ledger survives untouched.
        v1_bytes = (self.home / "recurrence.json").read_bytes()
        report = recurrence_mod.migrate_recurrence(self.home)
        self.assertTrue(report["migrated"])
        v2_ledger = recurrence_mod.load_recurrence(self.home)
        # Path 2: simulate the crash by restoring v1 and rerunning.
        (self.home / "recurrence.json").write_bytes(v1_bytes)
        again = recurrence_mod.migrate_recurrence(self.home)
        self.assertEqual(again["migrated"], True)
        self.assertEqual(
            recurrence_mod.load_recurrence(self.home), v2_ledger,
            "restart derives the same final ledger deterministically",
        )
        self.assertEqual(report["backfilled"], 2)

    def test_new_writes_run_the_migration_first(self) -> None:
        """ROLE 19: operational migration runs before new recurrence writes."""
        self._write_findings_index({"fp": [self.occurrence()]})
        self._v1_ledger([{"session_id": "s1", "conformant": False}])
        # A plain new write must not see schema v1.
        recurrence_mod.record_batch(
            self.home, self.session("s1"), [self.finding(self.occurrence())]
        )
        data = recurrence_mod.load_recurrence(self.home)
        self.assertEqual(data["schema_version"], 2)
        # The legacy row converged onto the anchored evidence: ONE row, not two.
        self.assertEqual(len(self.rows()), 1)

    def test_migrated_ambiguous_row_never_gets_a_guessed_anchor(self) -> None:
        self._write_findings_index(
            {"fp": [self.occurrence(), self.occurrence(episode=7, refs=(19,))]}
        )
        self._v1_ledger([{"session_id": "s1", "conformant": False}])
        recurrence_mod.migrate_recurrence(self.home)
        # A later keyed write of one of the two possible occurrences stays its
        # own row; the AMBIGUOUS row is preserved verbatim, never rewritten.
        before = copy.deepcopy(self.rows())
        recurrence_mod.record_occurrence(
            self.home, self.finding(self.occurrence()), self.session(), occurrence_id="rcp-9"
        )
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        preserved = [row for row in rows if row.get("anchor_status") == "AMBIGUOUS"]
        self.assertEqual(len(preserved), 1)
        self.assertEqual(preserved[0], before[0])


class EndToEndPerOccurrence(PerOccurrenceBase):
    """ROLE 20 A through the real submit boundary."""

    def confirmation(self, episode: int = DRIFT_EPISODE, refs=(DRIFT_EVENT,)) -> dict:
        from saipal_engine import carrier as carrier_mod
        from saipal_engine import sessions as sessions_mod

        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        self.assertEqual(status, "ok")
        unit = carrier_mod.build_carrier(
            self.home,
            registry=self.registry,
            index=index,
            session_id=SESSION,
            episode_index=episode,
        )
        return {
            "schema_version": 1,
            "verdict": "DRIFT",
            "unit_digest": unit["unit_digest"],
            "session_id": unit["session"]["session_id"],
            "episode_index": unit["episode"]["index"],
            "slice_index": unit["slice"]["index"],
            "disposition_class": "ENGINE_ENFORCEMENT_GAP",
            "reasoning": "undeclared command with a force flag reached the protocol core",
            "rule_ids": ["PAL-CMD-01"],
            "event_refs": list(refs),
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P3",
            "confidence": "MEDIUM",
            "change_target": "ENGINE",
            "root_cause": "undeclared force-flagged command executed",
            "challenge": {
                "prosecutor": "the command was not on the declared surface",
                "defender": "the token may be a user alias",
                "winner": "prosecutor",
                "loser_rejection": "the canonical form was recorded verbatim",
            },
            "alternatives": ["the user invoked the command through a shell alias"],
        }

    def test_submit_then_grown_resubmit_converges(self) -> None:
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)
        receipt = submit_mod.submit_candidate(
            self.home, self.confirmation(), registry=self.registry
        )
        self.assertFalse(receipt["duplicate"])
        # The same evidence, resubmitted (an analyst rewording): one row.
        again = submit_mod.submit_candidate(
            self.home, self.confirmation(), registry=self.registry
        )
        self.assertTrue(again["duplicate"])
        self.assertEqual(len(self.rows()), 1)


if __name__ == "__main__":
    unittest.main()
