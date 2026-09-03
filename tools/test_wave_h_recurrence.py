"""Wave H acceptance bar: recurrence intelligence.

Sessions are observed; the same finding is observed again from a different
model; the same fingerprint shows up after a fix version. The recurrence
file is the only place that turns repeated observation into evidence.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import hardening as hard
from saipal_engine import recurrence as recur


def _home(tmp: Path) -> Path:
    home = support.make_home(tmp)
    support.run_saipal("continue", home=home)
    return home


def _finding(**overrides) -> dict:
    base = {
        "finding_id": "f-test-1",
        "fingerprint": "fp-test-1",
        "drift_class": "DESTRUCTIVE_GATE_DRIFT",
        "rule_ids": ["R-RM-FORCE", "R-NO-CONFIRM"],
        "severity": "P1",
        "confidence": "HIGH",
    }
    base.update(overrides)
    return base


def _session(**overrides) -> dict:
    base = {
        "session_id": "sess-test-1",
        "adapter": "claude:anthropic",
        "runtime": {"provider": "anthropic"},
        "project": {"id": "proj-a"},
        "protocol": {"version": "7.900.0"},
        "conformant": False,
    }
    base.update(overrides)
    return base


def _occurrence(*, sid: str, model: str, conformant: bool, version: str) -> dict:
    return {
        "session_id": sid,
        "model_family": model,
        "provider": model,
        "project": "p",
        "protocol_version": version,
        "drift_class": "DESTRUCTIVE_GATE_DRIFT",
        "confidence": "HIGH",
        "severity": "P1",
        "conformant": conformant,
        "imported_at": "",
    }


class RecurrenceBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)


class RecurrenceShape(RecurrenceBase):
    def test_empty_recurrence(self) -> None:
        data = recur.empty_recurrence()
        self.assertIsInstance(data, dict)
        self.assertIn("by_finding", data)
        self.assertIn("by_rule", data)
        self.assertEqual(data["by_finding"], {})
        self.assertEqual(data["by_rule"], {})


class RecurrenceRecord(RecurrenceBase):
    def setUp(self) -> None:
        super().setUp()
        self.home = _home(self.tmp)

    def test_record_occurrence_and_save_load(self) -> None:
        data = recur.record_occurrence(
            self.home, _finding(), _session(),
        )
        self.assertIsInstance(data, dict)
        self.assertIn("fp-test-1", data["by_finding"])
        bucket = data["by_finding"]["fp-test-1"]
        self.assertEqual(bucket["drift_class"], "DESTRUCTIVE_GATE_DRIFT")
        self.assertEqual(len(bucket["occurrences"]), 1)
        self.assertEqual(data["by_rule"]["R-RM-FORCE"]["total"], 1)

        loaded = recur.load_recurrence(self.home)
        self.assertEqual(loaded, data, "save+load must round-trip")

    def test_negative_evidence_is_tracked(self) -> None:
        before = recur.load_recurrence(self.home)
        recur.record_negative(
            self.home,
            _session(session_id="sess-conform-1", conformant=True),
        )
        after = recur.load_recurrence(self.home)
        bucket = after["by_finding"].get("CONFORMANT")
        self.assertIsNotNone(bucket)
        self.assertGreater(
            len(bucket["occurrences"]), 0,
            "record_negative must grow the conformant counter",
        )
        # the file changed, so it cannot equal the pre-call snapshot
        self.assertNotEqual(before, after)


class RecurrenceAnalysis(unittest.TestCase):
    """Pure-function tests: no filesystem, just a hand-built data dict."""

    def _data(self) -> dict:
        occs = [
            _occurrence(sid="s1", model="claude", conformant=False, version="7.900.0"),
            _occurrence(sid="s2", model="claude", conformant=True, version="7.900.0"),
            _occurrence(sid="s3", model="claude", conformant=False, version="7.910.0"),
            _occurrence(sid="s4", model="local", conformant=False, version="7.900.0"),
            _occurrence(sid="s5", model="local", conformant=True, version="7.900.0"),
        ]
        return {
            "schema_version": recur.SCHEMA_VERSION,
            "by_finding": {
                "fp1": {
                    "finding_id": "f1",
                    "fingerprint": "fp1",
                    "drift_class": "DESTRUCTIVE_GATE_DRIFT",
                    "severity": "P1",
                    "confidence": "HIGH",
                    "last_fix_version": "",
                    "occurrences": occs,
                }
            },
            "by_rule": {},
        }

    def test_cross_model_recurrence(self) -> None:
        rows = recur.cross_model_recurrence(self._data(), "DESTRUCTIVE_GATE_DRIFT")
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertIn("model", row)
            self.assertIn("drift", row)
            self.assertIn("total", row)
            self.assertIn("rate", row)
            self.assertGreaterEqual(row["rate"], 0.0)
            self.assertLessEqual(row["rate"], 1.0)
        # 2 drift of 3 total for claude, 1 drift of 2 total for local
        by_model = {row["model"]: row for row in rows}
        self.assertEqual(by_model["claude"]["drift"], 2)
        self.assertEqual(by_model["claude"]["total"], 3)
        self.assertEqual(by_model["local"]["drift"], 1)
        self.assertEqual(by_model["local"]["total"], 2)

    def test_before_after_analysis(self) -> None:
        result = recur.before_after_analysis(
            self._data(), "DESTRUCTIVE_GATE_DRIFT", "7.999.0",
        )
        self.assertIn("before", result)
        self.assertIn("after", result)
        for side in ("before", "after"):
            self.assertIn("rate", result[side])
            self.assertIn("sessions", result[side])
            self.assertIn("occurrences", result[side])
        # versions 7.900/7.910 are < 7.999, so all 5 are "before"
        self.assertEqual(result["before"]["occurrences"], 5)
        self.assertEqual(result["after"]["occurrences"], 0)

    def test_regression_detection(self) -> None:
        data = {
            "schema_version": recur.SCHEMA_VERSION,
            "by_finding": {
                "fp1": {
                    "finding_id": "f1",
                    "fingerprint": "fp1",
                    "drift_class": "DESTRUCTIVE_GATE_DRIFT",
                    "severity": "P1",
                    "confidence": "HIGH",
                    "last_fix_version": "7.999.0",
                    "occurrences": [],
                }
            },
            "by_rule": {},
        }
        # new session at a version >= the fix -> regression flagged
        after_fix = _session(session_id="s9", protocol={"version": "8.200.0"})
        result = recur.detect_regression(data, "fp1", after_fix)
        self.assertIsNotNone(result)
        self.assertTrue(result["regression"])
        self.assertEqual(result["original_finding_id"], "f1")
        self.assertEqual(result["last_fix_version"], "7.999.0")

        # new session below the fix -> not a regression
        before_fix = _session(session_id="s10", protocol={"version": "7.500.0"})
        self.assertIsNone(recur.detect_regression(data, "fp1", before_fix))

        # unknown fingerprint -> None
        self.assertIsNone(recur.detect_regression(data, "fp-missing", after_fix))


class HardeningTelemetry(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_telemetry(self) -> None:
        telemetry = hard.load_telemetry(self.home)
        self.assertIsInstance(telemetry, dict)
        self.assertEqual(telemetry.get("sessions_analyzed", -1), 0)
        hard.increment(telemetry, "sessions_analyzed")
        hard.increment(telemetry, "sessions_analyzed", amount=4)
        self.assertEqual(telemetry["sessions_analyzed"], 5)
        hard.save_telemetry(self.home, telemetry)
        reloaded = hard.load_telemetry(self.home)
        self.assertEqual(reloaded["sessions_analyzed"], 5)


class RecurrencePipelineWiring(unittest.TestCase):
    """T-010 red control: the runtime pipeline writes the recurrence ledger.

    Wave H was previously dead code -- record_occurrence/record_negative were
    only exercised directly by unit tests, never by `saipal continue`. This
    proves a drift session writes a drift occurrence and a conformant session
    writes negative evidence, both through the real CLI.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _drift_bundle(self, session_id: str = "pipeline-drift-001") -> dict:
        return {
            "schema_version": 1,
            "session_id": session_id,
            "adapter": "generic",
            "project": {"name": "P", "git_head": "h", "root_fingerprint": "f"},
            "runtime": {"provider": "openai", "model": "gpt-x", "reasoning_mode": "unknown"},
            "temperature": "COLD",
            "protocol": {"version": "7.231.9", "binding_status": "BOUND",
                         "git_head": "deadbeef", "registry_sha256": "b" * 64},
            "events": [
                {"seq": 1, "type": "PHASE_CHANGE", "facts": {"from_phase": "PLAN", "to_phase": "NOPE"}},
                {"seq": 2, "type": "SESSION_BOUNDARY", "facts": {}},
            ],
        }

    def _recurrence(self) -> dict:
        return recur.load_recurrence(self.home)

    def test_pipeline_writes_drift_occurrence(self) -> None:
        payload = self._drift_bundle()
        support.write_inbox(self.home, "drift.json", payload)
        code, result, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert result is not None
        self.assertGreaterEqual(result["candidates"], 1)

        data = self._recurrence()
        self.assertNotEqual(data, recur.empty_recurrence())
        # some finding fingerprint carries a non-conformant drift occurrence
        found_drift = any(
            occ.get("session_id") == "pipeline-drift-001"
            and occ.get("conformant") is False
            for bucket in data["by_finding"].values()
            for occ in bucket.get("occurrences", [])
        )
        self.assertTrue(found_drift, "pipeline must record the drift occurrence")

    def test_pipeline_writes_negative_evidence(self) -> None:
        support.put_inbox(self.home, "conformant-cold.json")
        code, result, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert result is not None
        self.assertEqual(result["candidates"], 0)

        data = self._recurrence()
        bucket = data["by_finding"].get("CONFORMANT")
        self.assertIsNotNone(bucket, "conformant session must record negative evidence")
        sessions = {occ.get("session_id") for occ in bucket["occurrences"]}
        self.assertIn("golden-cold-001", sessions)


if __name__ == "__main__":
    unittest.main()
