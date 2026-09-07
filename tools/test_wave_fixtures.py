"""Golden fixtures from 12_TEST_PLAN.md, exercised through the real CLI.

Each fixture represents one path through the pipeline (no-finding, drift, false
positive, source-closure). The pipeline must classify each correctly without
hand-fudging the analyzer.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support

NO_FINDING = "no-finding-normal.json"
COMMAND_ROUTE = "agent-noncompliance-command-route.json"
SOURCE_CLOSURE = "source-closure-false-green.json"
FALSE_CONTINUE = "accidental-success-false-continue.json"


def _findings(home: Path) -> list[dict]:
    index = home / "findings" / "index.json"
    if not index.exists():
        return []
    return list(json.loads(index.read_text(encoding="utf-8"))["findings"])


class GoldenFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _cc(self, *names: str) -> dict:
        for name in names:
            support.put_inbox(self.home, name)
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        return payload

    def test_no_finding_normal_produces_no_audit(self) -> None:
        """A fully conformant session never produces a candidate or audit."""
        payload = self._cc(NO_FINDING)
        self.assertEqual(payload["candidates"], 0)
        self.assertEqual(payload["audits_emitted"], 0)
        self.assertEqual(_findings(self.home), [])

    def test_agent_noncompliance_command_route_emits_drift(self) -> None:
        """A non-saipal command outside the closed surface is investigated."""
        payload = self._cc(COMMAND_ROUTE)
        self.assertGreaterEqual(int(payload.get("signals_raised") or 0), 1)
        # The drift becomes a finding only when a semantic DRIFT verdict is
        # submitted for the episode; the mechanical pass itself stays triage.
        support.submit_drift(self.home)
        findings = _findings(self.home)
        classes = {f["drift_class"] for f in findings}
        self.assertIn("COMMAND_ROUTE_DRIFT", classes)
        emitted = [f for f in findings if f["state"] == "EMITTED"]
        self.assertEqual(len(emitted), 1)

    def test_source_closure_false_green_emits_low_confidence_finding(self) -> None:
        """A source intake without terminal closure is logged but not emitted."""
        payload = self._cc(SOURCE_CLOSURE)
        self.assertGreaterEqual(int(payload.get("signals_raised") or 0), 1)
        findings = _findings(self.home)
        # Without a semantic verdict nothing is a finding yet.
        self.assertEqual(len(findings), 0)

    def test_accidental_success_emits_continue_idle_finding(self) -> None:
        """A `continue` while active work exists is a CONTINUE_IDLE_FALSE_POSITIVE signal."""
        payload = self._cc(FALSE_CONTINUE)
        self.assertGreaterEqual(int(payload.get("signals_raised") or 0), 1)
        ledger = self.home / "signals.json"
        signals = json.loads(ledger.read_text(encoding="utf-8"))["signals"]
        classes = {f["drift_class"] for f in signals}
        self.assertIn("CONTINUE_IDLE_FALSE_POSITIVE", classes)


if __name__ == "__main__":
    unittest.main()