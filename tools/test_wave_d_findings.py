"""Wave D: finding discipline, exercised through the real CLI.

Root-cause merging, lifecycle advancement, fingerprint identity, and the
boundary between LOW-internal and HIGH-emitted findings.
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

        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None

        findings = _findings(self.home)
        self.assertEqual(len(findings), 1)
        occs = findings[0].get("occurrences", [])
        self.assertEqual(len(occs), 5)
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
        # PHASE_CHANGE opens episode 0, COMMAND opens episode 1.
        # Episode 0: [1..1] -> detect_phase_illegality fires.
        # Episode 1: [2..2] -> detect_command_route fires.
        support.write_inbox(self.home, "two-root.json", payload)
        code, result, err = support.run_saipal_json("continue", home=self.home)

        self.assertEqual(code, 0, err)
        assert result is not None
        self.assertGreaterEqual(result["candidates"], 2)

        findings = _findings(self.home)
        self.assertGreaterEqual(len(findings), 2)
        classes = {f["drift_class"] for f in findings}
        self.assertIn("PHASE_ILLEGALITY", classes)
        self.assertIn("COMMAND_ROUTE_DRIFT", classes)

    # -- acceptance bar 3: LOW confidence defaults away from CORE ---------- #

    def test_isolated_agent_noncompliance_defaults_away_from_core(self) -> None:
        # SOURCE_CLOSURE_FALSE_GREEN produces LOW mechanical confidence.
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
        support.run_saipal_json("continue", home=self.home)

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
        assert result is not None
        self.assertEqual(result["audits_emitted"], 0)

        for finding in _findings(self.home):
            self.assertNotEqual(
                finding.get("state"), "EMITTED",
                f"{finding['finding_id']} is EMITTED despite UNKNOWN binding"
            )
            self.assertIsNone(finding.get("audit"),
                              f"{finding['finding_id']} has audit set despite UNKNOWN binding")

    # -- acceptance bar 5: duplicate candidates merge ---------------------- #

    def test_duplicate_candidates_merge(self) -> None:
        payload = _drift_bundle(session_id="merge-001")
        support.write_inbox(self.home, "merge.json", payload)
        support.run_saipal_json("continue", home=self.home)
        self.assertEqual(len(_findings(self.home)), 1)

        # Second run sees the same session already analyzed (episodes_exhausted).
        support.run_saipal_json("continue", home=self.home)
        self.assertEqual(len(_findings(self.home)), 1)

    # -- acceptance bar 6: finding ledger survives crash ------------------- #

    def test_finding_ledger_survives_crash(self) -> None:
        payload = _drift_bundle(session_id="crash-001")
        support.write_inbox(self.home, "crash.json", payload)
        support.run_saipal_json("continue", home=self.home)

        # Reload the index fresh (simulates a crash / restart).
        index = self.home / "findings" / "index.json"
        self.assertTrue(index.exists())
        reloaded = json.loads(index.read_text(encoding="utf-8"))
        self.assertIn("findings", reloaded)
        self.assertGreaterEqual(len(reloaded["findings"]), 1)
        finding = reloaded["findings"][0]
        self.assertIn("finding_id", finding)
        self.assertIn("fingerprint", finding)
        self.assertIn("state", finding)

    # -- acceptance bar 7: protected invariants are explicit --------------- #

    def test_protected_invariants_are_explicit(self) -> None:
        # ACTIVE_WORK_PREEMPTION targets CORE_PROTOCOL.
        events = [
            {"seq": 1, "type": "STATE_SNAPSHOT", "ts": None, "loc": None,
             "digest": None, "facts": {"active_work": "T-1"}},
            {"seq": 2, "type": "STATE_SNAPSHOT", "ts": None, "loc": None,
             "digest": None, "facts": {"active_work": "T-2"}},
            {"seq": 3, "type": "SESSION_BOUNDARY", "ts": None, "loc": None,
             "digest": None, "facts": {}},
        ]
        payload = _drift_bundle(session_id="proto-001", events=events)
        support.write_inbox(self.home, "proto.json", payload)
        support.run_saipal_json("continue", home=self.home)

        for finding in _findings(self.home):
            if finding.get("change_target") == "CORE_PROTOCOL":
                self.assertIsInstance(
                    finding.get("protected_invariants"), list,
                    f"{finding['finding_id']} missing protected_invariants list"
                )

    # -- acceptance bar 8: fingerprint is not session_id ------------------- #

    def test_fingerprint_identity_is_not_session_id(self) -> None:
        base = _drift_bundle(session_id="fp-a-001")
        support.write_inbox(self.home, "fp-a.json", base)
        support.write_inbox(self.home, "fp-b.json",
                            _drift_bundle(session_id="fp-b-001"))
        support.run_saipal_json("continue", home=self.home)

        findings = _findings(self.home)
        self.assertGreaterEqual(len(findings), 1)
        fingerprints = {f["fingerprint"] for f in findings}
        # All findings share the same drift -> same fingerprint.
        self.assertEqual(len(fingerprints), 1)
        # Fingerprint is not a session_id.
        fp = next(iter(fingerprints))
        self.assertNotIn("fp-", fp)
        self.assertNotIn("session", fp.lower())


if __name__ == "__main__":
    unittest.main()
