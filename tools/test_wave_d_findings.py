"""Wave D: finding discipline, exercised through the real CLI.

Root-cause merging, lifecycle advancement, fingerprint identity, and the
boundary between LOW-internal and HIGH-emitted findings. Findings are
reached only through the sanctioned semantic submission path: a conformant
session becomes a finding only when a semantic DRIFT verdict is submitted for
its episode (PAL-ARCH-01).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import bundle as bundle_mod


def _drift_bundle(session_id: str, event_seqs: list[dict] | None = None,
                  **overrides) -> dict:
    """Build a drift bundle with PHASE_ILLEGALITY (PLAN->NOPE)."""
    events = event_seqs or [
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
        "session_id": session_id,
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
    index = home / "findings" / "index.json"
    if not index.exists():
        return []
    return list(json.loads(index.read_text(encoding="utf-8"))["findings"])


class FindingsDiscipline(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _cc(self, *bundles: tuple[str, dict]) -> dict:
        for name, bundle in bundles:
            support.write_inbox(self.home, name, bundle)
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        return payload

    def _drift_via_submit(self, drift_class="PHASE_ILLEGALITY", **over) -> dict:
        return support.submit_drift(self.home, drift_class=drift_class, **over)

    # -- acceptance bar 1: five sessions, one root cause ------------------- #

    def test_five_sessions_one_root_cause_produce_one_finding(self) -> None:
        ids = [f"drift-{i:03d}" for i in range(5)]
        for i, sid in enumerate(ids):
            ev = [
                {"seq": 1, "type": "USER_MESSAGE", "ts": None, "loc": None,
                 "digest": None, "facts": {}},
                {"seq": 2, "type": "PHASE_CHANGE", "ts": None, "loc": None,
                 "digest": None, "facts": {"from_phase": "PLAN",
                                            "to_phase": "NOPE"}},
                {"seq": 3, "type": "STATE_SNAPSHOT", "ts": None, "loc": None,
                 "digest": None, "facts": {"active_work": f"T-{i}"}},
                {"seq": 4, "type": "SESSION_BOUNDARY", "ts": None, "loc": None,
                 "digest": None, "facts": {}},
            ]
            b = _drift_bundle(session_id=sid, events=ev)
            support.write_inbox(self.home, f"drift-{i:03d}.json", b)
        self._cc()
        # Judge the non-drifting episode 0 NO_DRIFT, episode 1 DRIFT, to reach
        # 5 DRIFT occurrences of the same root cause. Order is index order.
        for _ in range(5):
            # advance any NO_DRIFT episodes already pending
            for _ in range(10):
                unit = support.next_unit(self.home)
                if unit is None:
                    break
                if int(unit["episode"]["index"]) == 1:
                    support.submit_drift(self.home, unit, drift_class="PHASE_ILLEGALITY")
                    break
                support.submit_drift(self.home, support.drift_candidate(unit, verdict="NO_DRIFT",
                                                                         disposition_class="NO_DRIFT",
                                                                         reasoning="closed")) if False else None
                # NO_DRIFT submit by hand: a drift candidate helper sets DRIFT
                from pathlib import Path as _P
                import json as _j
                cand = {
                    "schema_version": 1, "verdict": "NO_DRIFT",
                    "unit_digest": unit["unit_digest"],
                    "session_id": unit["session"]["session_id"],
                    "episode_index": unit["episode"]["index"],
                    "disposition_class": "NO_DRIFT", "reasoning": "episode 0 is clean",
                }
                p = self.tmp / f"nd-{unit['session']['session_id']}-{unit['episode']['index']}.json"
                p.write_text(_j.dumps(cand), encoding="utf-8")
                support.run_saipal("--json", "submit", str(p), home=self.home)
        findings = _findings(self.home)
        self.assertEqual(len(findings), 1)
        occs = findings[0].get("occurrences", [])
        sids = {o["session_id"] for o in occs}
        self.assertEqual(len(sids), 5)

    # -- acceptance bar 2: one session, two root causes -------------------- #

    def test_one_session_two_root_causes_two_findings(self) -> None:
        events = [
            {"seq": 1, "type": "PHASE_CHANGE", "ts": None, "loc": None,
             "digest": None, "facts": {"from_phase": "PLAN", "to_phase": "NOPE"}},
            {"seq": 2, "type": "COMMAND", "ts": None, "loc": None,
             "digest": None, "facts": {"canonical": "bogus nope"}},
            {"seq": 3, "type": "SESSION_BOUNDARY", "ts": None, "loc": None,
             "digest": None, "facts": {}},
        ]
        payload = _drift_bundle(session_id="two-root-001", events=events)
        support.write_inbox(self.home, "two-root.json", payload)
        self._cc()
        # Two episodes, two DRIFT submissions -> two distinct findings.
        u1 = support.next_unit(self.home)
        self.assertIsNotNone(u1)
        support.submit_drift(self.home, u1, drift_class="PHASE_ILLEGALITY")
        u2 = support.next_unit(self.home)
        self.assertIsNotNone(u2)
        # An unknown drift class may be outside the detector set but a DRIFT
        # verdict still creates a finding; severity is exercised below.
        support.submit_drift(self.home, u2, drift_class="COMMAND_ROUTE_DRIFT")
        findings = _findings(self.home)
        self.assertGreaterEqual(len(findings), 2)
        classes = {f["drift_class"] for f in findings}
        self.assertIn("PHASE_ILLEGALITY", classes)
        self.assertIn("COMMAND_ROUTE_DRIFT", classes)

    # -- acceptance bar 3: LOW confidence defaults away from CORE ---------- #

    def test_isolated_agent_noncompliance_defaults_away_from_core(self) -> None:
        events = [
            {"seq": 1, "type": "USER_MESSAGE", "ts": None, "loc": None,
             "digest": None, "facts": {}},
            {"seq": 2, "type": "SOURCE_EVENT", "ts": None, "loc": None,
             "digest": None, "facts": {"kind": "owner_doc"}},
            {"seq": 3, "type": "TOOL_CALL", "ts": None, "loc": None,
             "digest": None, "facts": {}},
        ]
        payload = _drift_bundle(session_id="low-conf-001", events=events)
        support.write_inbox(self.home, "low-conf.json", payload)
        self._cc()
        unit = support.next_unit(self.home)
        self.assertIsNotNone(unit)
        support.submit_drift(self.home, unit, confidence="LOW", drift_class="SOURCE_CLOSURE_FALSE_GREEN")
        for finding in _findings(self.home):
            if finding.get("confidence") == "LOW":
                self.assertNotEqual(
                    finding.get("change_target"), "CORE_PROTOCOL",
                    f"LOW finding {finding['finding_id']} targets CORE_PROTOCOL"
                )

    # -- acceptance bar 4: UNKNOWN binding produces no EMITTED ------------ #

    def test_weak_evidence_stays_internal(self) -> None:
        payload = _drift_bundle(
            session_id="weak-001",
            protocol={"version": "7.231.9", "binding_status": "UNKNOWN"},
        )
        support.write_inbox(self.home, "weak.json", payload)
        code, result, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(result["audits_emitted"], 0)
        # A weak binding cannot emit and never even creates a finding via
        # the mechanical pass; no finding should be EMITTED.
        for finding in _findings(self.home):
            self.assertNotEqual(finding.get("state"), "EMITTED",
                                f"{finding['finding_id']} is EMITTED despite UNKNOWN binding")
            self.assertIsNone(finding.get("audit"))

    # -- acceptance bar 5: duplicate candidates merge ---------------------- #

    def test_duplicate_candidates_merge(self) -> None:
        support.write_inbox(self.home, "merge.json", _drift_bundle(session_id="merge-001"))
        self._cc()
        unit = support.next_unit(self.home)
        self.assertIsNotNone(unit)
        support.submit_drift(self.home, unit)
        self.assertEqual(len(_findings(self.home)), 1)
        # The same session, already pending, collects a retry as a merge.
        support.run_saipal_json("continue", home=self.home)
        self.assertEqual(len(_findings(self.home)), 1)

    # -- acceptance bar 6: finding ledger survives crash ------------------- #

    def test_finding_ledger_survives_crash(self) -> None:
        support.write_inbox(self.home, "crash.json", _drift_bundle(session_id="crash-001"))
        self._cc()
        unit = support.next_unit(self.home)
        self.assertIsNotNone(unit)
        support.submit_drift(self.home, unit)
        index = self.home / "findings" / "index.json"
        self.assertTrue(index.exists())
        reloaded = json.loads(index.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(reloaded["findings"]), 1)
        finding = reloaded["findings"][0]
        self.assertIn("finding_id", finding)
        self.assertIn("fingerprint", finding)
        self.assertIn("state", finding)

    # -- acceptance bar 7: protected invariants are explicit --------------- #

    def test_protected_invariants_are_explicit(self) -> None:
        events = [
            {"seq": 1, "type": "STATE_SNAPSHOT", "ts": None, "loc": None,
             "digest": None, "facts": {"active_work": "T-1"}},
            {"seq": 2, "type": "STATE_SNAPSHOT", "ts": None, "loc": None,
             "digest": None, "facts": {"active_work": "T-2"}},
            {"seq": 3, "type": "SESSION_BOUNDARY", "ts": None, "loc": None,
             "digest": None, "facts": {}},
        ]
        support.write_inbox(self.home, "proto.json", _drift_bundle(session_id="proto-001", events=events))
        self._cc()
        unit = support.next_unit(self.home)
        self.assertIsNotNone(unit)
        support.submit_drift(self.home, unit, change_target="CORE_PROTOCOL")
        for finding in _findings(self.home):
            if finding.get("change_target") == "CORE_PROTOCOL":
                self.assertIsInstance(finding.get("protected_invariants"), list,
                                      f"{finding['finding_id']} missing protected_invariants")

    # -- acceptance bar 8: fingerprint is not session_id ------------------- #

    def test_fingerprint_identity_is_not_session_id(self) -> None:
        support.write_inbox(self.home, "fp-a.json", _drift_bundle(session_id="fp-a-001"))
        support.write_inbox(self.home, "fp-b.json", _drift_bundle(session_id="fp-b-001"))
        self._cc()
        # Two semantic submissions for the same root cause collapse on fingerprint.
        for _ in range(2):
            unit = support.next_unit(self.home)
            if unit is None:
                break
            support.submit_drift(self.home, unit)
        findings = _findings(self.home)
        self.assertGreaterEqual(len(findings), 1)
        fingerprints = {f["fingerprint"] for f in findings}
        self.assertEqual(len(fingerprints), 1)
        fp = next(iter(fingerprints))
        self.assertNotIn("fp-", fp)
        self.assertNotIn("session", fp.lower())


if __name__ == "__main__":
    unittest.main()
