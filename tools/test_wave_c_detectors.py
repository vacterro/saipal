"""Wave C: the comparison kernel, exercised through the real CLI.

Conformant sessions produce no candidate. Mechanical drift is detected. The
no-hindsight rule and unknown-binding confidence limits are enforced.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import bundle as bundle_mod
from saipal_engine import sessions as sessions_mod

COLD = "conformant-cold.json"


def _drift_bundle(drift_class: str = "PHASE_ILLEGALITY", **overrides) -> dict:
    events = [
        {"seq": 1, "type": "USER_MESSAGE", "ts": None, "loc": None, "digest": None,
         "facts": {}},
        {"seq": 2, "type": "PHASE_CHANGE", "ts": None, "loc": None, "digest": None,
         "facts": {"from_phase": "PLAN", "to_phase": "NOPE"}},
        {"seq": 3, "type": "STATE_SNAPSHOT", "ts": None, "loc": None, "digest": None,
         "facts": {"active_work": "T-1"}},
        {"seq": 4, "type": "SESSION_BOUNDARY", "ts": None, "loc": None, "digest": None,
         "facts": {}},
    ]
    payload = {
        "schema_version": 1,
        "session_id": overrides.pop("session_id", "drift-001"),
        "adapter": "generic",
        "project": {"name": "X", "git_head": "x", "root_fingerprint": "fx"},
        "runtime": {"provider": "openai", "model": "gpt-x", "reasoning_mode": "unknown"},
        "temperature": "COLD",
        "protocol": {"version": "7.231.9", "binding_status": "BOUND",
                     "git_head": "deadbeef", "registry_sha256": "b" * 64},
        "events": events,
        **overrides,
    }
    payload["session_sha256"] = bundle_mod.bundle_digest(payload)
    return payload


def _findings(home: Path) -> list[dict]:
    index = (home / "findings" / "index.json")
    if not index.exists():
        return []
    return list(json.loads(index.read_text(encoding="utf-8"))["findings"])


class ComparisonKernel(unittest.TestCase):
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

    # -- acceptance bar 1: conformant produces no candidate ---------------- #

    def test_conformant_session_produces_no_candidate(self) -> None:
        payload = self._cc(COLD)
        self.assertEqual(payload["candidates"], 0)
        self.assertEqual(_findings(self.home), [])
        self.assertEqual(payload["audits_emitted"], 0)

    # -- acceptance bar 2: command drift is detected ----------------------- #

    def test_illegal_phase_transition_is_detected(self) -> None:
        support.write_inbox(self.home, "drift.json", _drift_bundle())
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        self.assertGreaterEqual(payload["candidates"], 1)
        findings = _findings(self.home)
        self.assertTrue(any(f["drift_class"] == "PHASE_ILLEGALITY" for f in findings))

    def test_conformant_phase_edge_is_not_flagged(self) -> None:
        """PLAN->BUILD is legal in SAIPEN CORE.md 1.6 and must not fire."""
        payload = {
            "schema_version": 1,
            "session_id": "legal-phase-001",
            "adapter": "generic",
            "project": {"name": "X"},
            "runtime": {"provider": "openai", "model": "gpt-x"},
            "temperature": "COLD",
            "protocol": {"version": "7.231.9", "binding_status": "BOUND"},
            "events": [
                {"seq": 1, "type": "PHASE_CHANGE", "facts": {"from_phase": "PLAN", "to_phase": "BUILD"}},
                {"seq": 2, "type": "SESSION_BOUNDARY", "facts": {}},
            ],
        }
        payload["session_sha256"] = bundle_mod.bundle_digest(payload)
        support.write_inbox(self.home, "legal.json", payload)
        code, result, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert result is not None
        self.assertEqual(result["candidates"], 0)

    # -- acceptance bar 4: user override suppresses the finding ------------ #

    def test_user_override_suppresses_false_drift(self) -> None:
        payload = _drift_bundle(
            session_id="override-001",
            events=[
                {"seq": 1, "type": "USER_MESSAGE", "facts": {"override": True,
                                                              "text": "do the illegal thing"}},
                {"seq": 2, "type": "PHASE_CHANGE", "facts": {"from_phase": "PLAN", "to_phase": "NOPE"}},
                {"seq": 3, "type": "SESSION_BOUNDARY", "facts": {}},
            ],
        )
        support.write_inbox(self.home, "override.json", payload)
        code, result, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert result is not None
        self.assertEqual(result["candidates"], 0)

    # -- acceptance bar 5: unknown binding limits confidence --------------- #

    def test_unknown_binding_never_reaches_high_confidence_audit(self) -> None:
        payload = _drift_bundle(
            session_id="unbound-001",
            protocol={"version": None, "binding_status": "UNKNOWN"},
        )
        support.write_inbox(self.home, "unbound.json", payload)
        code, result, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert result is not None
        self.assertEqual(result["audits_emitted"], 0, "UNKNOWN binding must not emit a HIGH audit")
        for finding in _findings(self.home):
            self.assertNotEqual(finding["confidence"], "HIGH")

    # -- acceptance bar 6: old session / new rule -------------------------- #

    def test_old_session_against_new_rule_no_historical_violation(self) -> None:
        """A rule that did not exist in the governing version cannot violate it.

        When the protocol binding is UNKNOWN, no historical violation may be
        claimed and nothing is emitted -- that is the mechanical no-hindsight
        gate. (A BOUND session under a known rule may emit; see Wave E/G.)
        """
        payload = _drift_bundle(
            session_id="oldsess-001",
            protocol={"version": None, "binding_status": "UNKNOWN"},
        )
        support.write_inbox(self.home, "old.json", payload)
        code, result, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert result is not None
        self.assertEqual(result["audits_emitted"], 0)
        self.assertGreaterEqual(result["candidates"], 1)

    # -- acceptance bar 9: no audit without qualifying drift ----------------- #

    def test_audit_requires_qualifying_drift(self) -> None:
        """A conformant session (no mechanical drift) produces no audit."""
        payload = self._cc(COLD)
        self.assertEqual(payload["audits_emitted"], 0)


if __name__ == "__main__":
    unittest.main()
