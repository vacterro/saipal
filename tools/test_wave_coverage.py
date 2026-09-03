"""T-047: no-drift receipts and true semantic exhaustion (PAL-ANALYSIS-06).

`exhausted` is a cursor claim. The cursor is advanced by the same code path that
would skip an episode on a bug, so as evidence of work it is worth nothing.

Coverage is derived from receipts instead: per episode, was a verdict recorded,
and was it recorded against final evidence? That makes "we analyzed this session"
a checkable statement, and it makes a cursor/receipt disagreement visible instead
of averaged away.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import carrier as carrier_mod
from saipal_engine import coverage as coverage_mod
from saipal_engine import sessions as sessions_mod
from saipal_engine import submit as submit_mod
from saipal_engine.registry import load_registry

CLEAN = "no-finding-normal.json"
HOT = "hot-partial.json"


class SessionCoverage(unittest.TestCase):
    """Per-session accounting, straight from the receipt list."""

    def record(self, count: int = 3, **overrides) -> dict:
        record = {
            "session_id": "s1",
            "temperature": "COLD",
            "status": "IMPORTED",
            "episodes": [{"index": index} for index in range(count)],
        }
        record.update(overrides)
        return record

    def test_no_receipts_means_everything_pending(self) -> None:
        row = coverage_mod.session_coverage(self.record(), None)
        self.assertEqual((row["final"], row["provisional"], row["pending"]), (0, 0, 3))
        self.assertFalse(row["truly_exhausted"])

    def test_a_final_receipt_counts_as_judged(self) -> None:
        row = coverage_mod.session_coverage(
            self.record(), {0: [{"finality": "FINAL"}]}
        )
        self.assertEqual((row["final"], row["provisional"], row["pending"]), (1, 0, 2))

    def test_a_provisional_receipt_is_work_but_not_a_conclusion(self) -> None:
        row = coverage_mod.session_coverage(
            self.record(), {0: [{"finality": "PROVISIONAL"}]}
        )
        self.assertEqual((row["final"], row["provisional"], row["pending"]), (0, 1, 2))
        self.assertFalse(row["truly_exhausted"])

    def test_a_later_final_receipt_supersedes_a_provisional_one(self) -> None:
        row = coverage_mod.session_coverage(
            self.record(),
            {0: [{"finality": "PROVISIONAL"}, {"finality": "FINAL"}]},
        )
        self.assertEqual((row["final"], row["provisional"]), (1, 0))

    def test_every_episode_judged_is_truly_exhausted(self) -> None:
        row = coverage_mod.session_coverage(
            self.record(count=2),
            {0: [{"finality": "FINAL"}], 1: [{"finality": "FINAL"}]},
        )
        self.assertTrue(row["truly_exhausted"])
        self.assertEqual(row["pending"], 0)

    def test_a_session_with_no_episodes_is_not_exhausted(self) -> None:
        """Nothing to judge is not the same as judged; it is an intake question."""
        row = coverage_mod.session_coverage(self.record(count=0), None)
        self.assertFalse(row["truly_exhausted"])

    def test_a_receipt_with_no_finality_is_treated_as_final(self) -> None:
        """Receipts written before finality existed are final by definition."""
        row = coverage_mod.session_coverage(self.record(count=1), {0: [{}]})
        self.assertEqual(row["final"], 1)

    def test_a_malformed_episode_index_is_ignored_not_crashed(self) -> None:
        row = coverage_mod.session_coverage(self.record(count=1), {})
        self.assertEqual(row["pending"], 1)

    def test_the_cursor_claim_is_reported_alongside_the_truth(self) -> None:
        record = self.record(count=2, semantic={"next_episode_index": 2, "exhausted": True})
        row = coverage_mod.session_coverage(record, None)
        self.assertTrue(row["claimed_exhausted"])
        self.assertFalse(row["truly_exhausted"])


class HomeCoverage(unittest.TestCase):
    """Across the home, and through the real submission path."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _index(self) -> dict | None:
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        return index if status == "ok" else None

    def no_drift(self, unit: dict) -> dict:
        return {
            "schema_version": 1,
            "verdict": "NO_DRIFT",
            "unit_digest": unit["unit_digest"],
            "session_id": unit["session"]["session_id"],
            "episode_index": unit["episode"]["index"],
            "disposition_class": "NO_DRIFT",
            "reasoning": "the span routed through the declared surface",
        }

    def test_an_empty_home_reports_zero_coverage(self) -> None:
        report = coverage_mod.coverage(self.home, self._index())
        self.assertEqual(report["episodes_total"], 0)
        self.assertEqual(report["receipts_total"], 0)
        self.assertEqual(report["cursor_claims_more_than_receipts"], [])

    def test_an_imported_session_starts_fully_pending(self) -> None:
        support.put_inbox(self.home, CLEAN)
        support.run_saipal("continue", home=self.home)
        report = coverage_mod.coverage(self.home, self._index())
        self.assertGreater(report["episodes_total"], 0)
        self.assertEqual(report["episodes_final"], 0)
        self.assertEqual(report["episodes_pending"], report["episodes_total"])

    def test_working_the_session_moves_pending_to_final(self) -> None:
        support.put_inbox(self.home, CLEAN)
        support.run_saipal("continue", home=self.home)
        while True:
            unit = carrier_mod.build_carrier(self.home, registry=self.registry)
            if unit["session"] is None:
                break
            submit_mod.submit_candidate(
                self.home, self.no_drift(unit), registry=self.registry
            )
        report = coverage_mod.coverage(self.home, self._index())
        self.assertEqual(report["episodes_pending"], 0)
        self.assertEqual(report["episodes_final"], report["episodes_total"])
        self.assertEqual(report["sessions_truly_exhausted"], 1)
        self.assertEqual(report["cursor_claims_more_than_receipts"], [])

    def test_a_hot_tail_lands_in_provisional_not_final(self) -> None:
        support.put_inbox(self.home, HOT)
        support.run_saipal("continue", home=self.home)
        for _ in range(20):
            unit = carrier_mod.build_carrier(self.home, registry=self.registry)
            if unit["session"] is None:
                break
            submit_mod.submit_candidate(
                self.home, self.no_drift(unit), registry=self.registry
            )
            if unit["episode"]["finality"] == "PROVISIONAL":
                break
        report = coverage_mod.coverage(self.home, self._index())
        self.assertGreaterEqual(report["episodes_provisional"], 1)
        self.assertEqual(report["sessions_truly_exhausted"], 0)

    def test_a_forged_exhaustion_flag_is_reported_as_a_discrepancy(self) -> None:
        """Red control: the flag says done, the receipts say nothing was judged."""
        support.put_inbox(self.home, CLEAN)
        support.run_saipal("continue", home=self.home)
        index = self._index()
        index["sessions"][0]["semantic"] = {
            "next_episode_index": 99,
            "exhausted": True,
            "submitted": 0,
            "no_drift": 0,
        }
        sessions_mod.save_index(self.home, index, registry=self.registry)
        report = coverage_mod.coverage(self.home, self._index())
        self.assertEqual(
            report["cursor_claims_more_than_receipts"], ["golden-no-finding-normal-001"]
        )
        self.assertEqual(report["episodes_final"], 0)

    def test_unreadable_receipts_degrade_to_zero_rather_than_crashing(self) -> None:
        support.put_inbox(self.home, CLEAN)
        support.run_saipal("continue", home=self.home)
        (self.home / submit_mod.RECEIPTS_NAME).write_text("{", encoding="utf-8")
        report = coverage_mod.coverage(self.home, self._index())
        self.assertEqual(report["receipts_total"], 0)

    def test_a_superseded_generation_is_not_counted_twice(self) -> None:
        """Only the freshest generation is outstanding work.

        Counting every generation made `pending` unreachable -- a re-imported
        session's episodes were owed forever -- and counted the single receipt for
        an episode once per generation, so `judged` could exceed reality.
        """
        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, "cold-changed-v2.json")
        support.run_saipal("continue", home=self.home)
        generations = [
            record["generation"]
            for record in support.sessions_of(self.home)
            if record["session_id"] == "golden-cold-001"
        ]
        self.assertEqual(sorted(generations), [1, 2], "the fixture must re-import")

        index = self._index()
        fresh = [
            record for record in index["sessions"]
            if record["session_id"] == "golden-cold-001" and record["generation"] == 2
        ][0]
        report_before = coverage_mod.coverage(self.home, index)
        self.assertEqual(
            report_before["episodes_total"], len(fresh["episodes"]),
            "a superseded generation must not add outstanding episodes",
        )
        self.assertEqual(len(report_before["sessions"]), 1)

        while True:
            unit = carrier_mod.build_carrier(self.home, registry=self.registry)
            if unit["session"] is None:
                break
            submit_mod.submit_candidate(
                self.home, self.no_drift(unit), registry=self.registry
            )
        report = coverage_mod.coverage(self.home, self._index())
        self.assertEqual(report["episodes_pending"], 0)
        self.assertEqual(report["episodes_final"], report["episodes_total"])
        self.assertEqual(report["sessions_truly_exhausted"], 1)


class StatusReportsCoverage(unittest.TestCase):
    """`status` reports checkable progress, and stays read-only doing it."""

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

    def test_status_json_carries_semantic_coverage(self) -> None:
        code, payload, err = support.run_saipal_json("status", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertIn("semantic", payload)
        self.assertIn("episodes_total", payload["semantic"])

    def test_status_human_output_names_the_progress(self) -> None:
        code, out, err = support.run_saipal("status", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertIn("semantic:", out)
        self.assertIn("episodes judged", out)

    def test_status_reports_the_discrepancy_line_when_it_exists(self) -> None:
        index = sessions_mod.load_index(self.home, registry=self.registry)[1]
        index["sessions"][0]["semantic"] = {
            "next_episode_index": 99, "exhausted": True, "submitted": 0, "no_drift": 0
        }
        sessions_mod.save_index(self.home, index, registry=self.registry)
        code, out, err = support.run_saipal("status", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertIn("semantic_discrepancy:", out)

    def test_status_remains_read_only(self) -> None:
        before = support.tree_digest(self.home)
        support.run_saipal("status", home=self.home)
        self.assertEqual(support.tree_digest(self.home), before)

    def test_status_output_stays_compact(self) -> None:
        code, out, _err = support.run_saipal("status", home=self.home)
        self.assertEqual(code, 0)
        self.assertLess(len(out), 2000, "status dumped too much")


class NoDriftIsAFirstClassResult(unittest.TestCase):
    """A clean session must be provable, not merely unaccused."""

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

    def test_a_fully_clean_session_leaves_receipts_and_no_findings(self) -> None:
        while True:
            unit = carrier_mod.build_carrier(self.home, registry=self.registry)
            if unit["session"] is None:
                break
            submit_mod.submit_candidate(
                self.home,
                {
                    "schema_version": 1,
                    "verdict": "NO_DRIFT",
                    "unit_digest": unit["unit_digest"],
                    "session_id": unit["session"]["session_id"],
                    "episode_index": unit["episode"]["index"],
                    "disposition_class": "NO_DRIFT",
                    "reasoning": "every command routed through the declared surface",
                },
                registry=self.registry,
            )
        _status, receipts, _detail = submit_mod.load_receipts(self.home)
        self.assertTrue(receipts["receipts"])
        self.assertTrue(
            all(r["verdict"] == "NO_DRIFT" for r in receipts["receipts"])
        )
        findings_path = self.home / "findings" / "index.json"
        findings = (
            json.loads(findings_path.read_text(encoding="utf-8"))["findings"]
            if findings_path.exists()
            else []
        )
        self.assertEqual(findings, [], "a clean session must produce no finding")
        report = coverage_mod.coverage(
            self.home, sessions_mod.load_index(self.home, registry=self.registry)[1]
        )
        self.assertEqual(report["sessions_truly_exhausted"], 1)


if __name__ == "__main__":
    unittest.main()
