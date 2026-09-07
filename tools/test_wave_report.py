"""The drift report: the detective's answer, and what it may not claim.

`saipal report` is the surface an operator (or an agent speaking to one) reads
instead of joining three JSON files by hand. Two properties carry the weight:

1. it writes nothing, so it can be run at any point in a cycle;
2. its verdict cannot look clean when nothing was examined -- a report over an
   unjudged home says `NOT_EXAMINED`, because "no drift found" beside zero
   judged episodes is the tool reporting its own idleness.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support

DRIFT = "agent-noncompliance-command-route.json"
CLEAN = "no-finding-normal.json"
UNBOUND = "unknown-protocol.json"


class ReportBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def report(self) -> dict:
        code, payload, err = support.run_saipal_json("report", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        return payload


class ReportVerdict(ReportBase):
    def test_an_empty_home_reports_no_evidence(self) -> None:
        payload = self.report()
        self.assertEqual(payload["verdict"], "NO_EVIDENCE")
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["next_action"], "saipal continue")

    def test_an_unjudged_clean_session_is_not_examined_not_clean(self) -> None:
        """The honesty case: silence is not the same as a clean verdict."""
        support.put_inbox(self.home, CLEAN)
        support.run_saipal("continue", home=self.home)
        payload = self.report()
        self.assertEqual(payload["verdict"], "NOT_EXAMINED")
        self.assertEqual(payload["counts"]["total"], 0)
        self.assertEqual(payload["coverage"]["episodes_final"], 0)
        self.assertGreater(payload["coverage"]["episodes_pending"], 0)

    def test_a_judged_clean_session_reports_no_drift_so_far(self) -> None:
        support.put_inbox(self.home, CLEAN)
        support.run_saipal("continue", home=self.home)
        _code, nxt, _err = support.run_saipal_json("next", home=self.home)
        assert nxt is not None
        unit = nxt["analysis_carrier"]
        candidate = {
            "schema_version": 1,
            "verdict": "NO_DRIFT",
            "unit_digest": unit["unit_digest"],
            "session_id": unit["session"]["session_id"],
            "episode_index": unit["episode"]["index"],
            "disposition_class": "NO_DRIFT",
            "reasoning": "the episode routes a declared command and closes; nothing contradicts a governing rule",
        }
        path = self.tmp / "clean.json"
        path.write_text(json.dumps(candidate), encoding="utf-8")
        code, _receipt, err = support.run_saipal_json("submit", str(path), home=self.home)
        self.assertEqual(code, 0, err)
        payload = self.report()
        self.assertEqual(payload["verdict"], "NO_DRIFT_SO_FAR")
        self.assertGreater(payload["coverage"]["episodes_final"], 0)

    def test_an_emitted_audit_reports_drift(self) -> None:
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)
        support.submit_drift(self.home, support.next_unit(self.home))
        payload = self.report()
        self.assertEqual(payload["verdict"], "DRIFT_REPORTED")
        self.assertEqual(payload["counts"]["emitted"], 1)
        self.assertEqual(payload["staged_audits"], ["1.md"])
        self.assertIn("maintainer", payload["next_action"])

    def test_a_clean_verdict_still_points_at_the_unexamined_remainder(self) -> None:
        """Red control: "no drift" must not read as "nothing left to do"."""
        support.put_inbox(self.home, CLEAN)
        support.run_saipal("continue", home=self.home)
        payload = self.report()
        self.assertGreater(payload["coverage"]["episodes_pending"], 0)
        self.assertIn("unexamined", payload["next_action"])
        self.assertNotIn("maintainer", payload["next_action"])

    def test_an_internal_only_finding_reports_suspicion_not_drift(self) -> None:
        """A MEDIUM-confirmed finding stays internal; the verdict must not claim an audit."""
        support.put_inbox(self.home, "source-closure-false-green.json")
        support.run_saipal("continue", home=self.home)
        unit = support.next_unit(self.home)
        self.assertIsNotNone(unit)
        support.submit_drift(
            self.home, unit,
            drift_class="SOURCE_CLOSURE_FALSE_GREEN", severity="P2", confidence="MEDIUM",
            disposition_class="ENGINE_ENFORCEMENT_GAP",
            rule_ids=["PAL-EVIDENCE-01"],
            reasoning="a source intake was accepted without a closure event",
            root_cause="the intake lacked a closure event",
        )
        payload = self.report()
        self.assertEqual(payload["verdict"], "DRIFT_SUSPECTED")
        self.assertEqual(payload["counts"]["emitted"], 0)
        self.assertEqual(payload["staged_audits"], [])


class ReportContent(ReportBase):
    def setUp(self) -> None:
        super().setUp()
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)
        support.submit_drift(self.home, support.next_unit(self.home))
        self.payload = self.report()
        self.finding = self.payload["findings"][0]

    def test_every_finding_names_its_rule_and_owner_document(self) -> None:
        self.assertTrue(self.finding["rule_ids"])
        self.assertTrue(self.finding["owner_documents"])
        for document in self.finding["owner_documents"]:
            self.assertTrue(document.startswith("saipal/"), document)

    def test_attribution_answers_who_drifted(self) -> None:
        attribution = self.finding["attribution"]
        self.assertTrue(attribution["sessions"])
        self.assertTrue(attribution["models"], "the report must name the model")
        self.assertTrue(attribution["projects"], "the report must name the project")

    def test_the_finding_carries_identity_a_maintainer_can_route(self) -> None:
        for field in (
            "finding_id", "state", "drift_class", "severity", "confidence",
            "change_target", "causal_key", "occurrences",
        ):
            self.assertIsNotNone(self.finding[field], field)
        self.assertEqual(self.finding["state"], "EMITTED")
        self.assertEqual(self.finding["audit"]["audit_number"], 1)

    def test_the_report_is_not_a_transcript(self) -> None:
        """Red control: a report is an index, never a second copy of the session."""
        blob = json.dumps(self.payload)
        for key in ("transcript", "\"raw\"", "tool_output", "excerpt"):
            self.assertNotIn(key, blob)

    def test_the_human_render_leads_with_the_verdict(self) -> None:
        code, out, err = support.run_saipal("report", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith("verdict: DRIFT_REPORTED"), out[:120])
        self.assertIn(self.finding["finding_id"], out)
        self.assertIn("judged:", out, "coverage must travel with the verdict")


class ReportIsReadOnly(ReportBase):
    def test_report_writes_nothing(self) -> None:
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)
        before = support.tree_digest(self.home)
        self.report()
        self.assertEqual(support.tree_digest(self.home), before, "report mutated the home")

    def test_report_refuses_a_home_that_does_not_exist(self) -> None:
        missing = self.tmp / "absent" / ".saipal"
        code, payload, _err = support.run_saipal_json("report", home=missing)
        self.assertEqual(code, 3)
        assert payload is not None
        self.assertEqual(payload["code"], "NO_HOME")
        self.assertFalse(missing.exists(), "a read-only command never creates a home")

    def test_report_takes_no_arguments(self) -> None:
        code, payload, _err = support.run_saipal_json("report", "everything", home=self.home)
        self.assertEqual(code, 2)
        assert payload is not None
        self.assertEqual(payload["code"], "USAGE")


class ReportRespectsTheNoHindsightGate(ReportBase):
    def test_an_unbound_session_never_reports_an_emitted_audit(self) -> None:
        support.put_inbox(self.home, UNBOUND)
        support.run_saipal("continue", home=self.home)
        payload = self.report()
        self.assertEqual(payload["counts"]["emitted"], 0)
        self.assertEqual(payload["staged_audits"], [])
        for finding in payload["findings"]:
            self.assertNotEqual(finding["confidence"], "HIGH")


if __name__ == "__main__":
    unittest.main()
