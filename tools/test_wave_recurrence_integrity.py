"""T-119 (ROLE 3-12): corrupt recurrence is a LOUD refusal, never empty history.

W2-001: load_recurrence reclassified a PRESENT unreadable or invalid ledger as
empty, so the next ordinary write (record_negative) replaced the whole history
with one new row. The repair: ABSENT is empty; PRESENT unreadable/invalid is
INVALID -- every mutation refuses with zero writes, read-only surfaces report
INVALID without repair, and mutating startup refuses before new effects.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import recurrence as recurrence_mod
from saipal_engine.errors import PalError

CORRUPT_BYTES = b"{broken-history"


class IntegrityBase(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = None
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        self.ledger = self.home / "recurrence.json"

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


class CorruptLedgerNeverBecomesEmptyHistory(IntegrityBase):
    """ROLE 3/6/7 A + B: the W2-001 reproduction, now red-tested."""

    def _corrupt(self, payload: bytes = CORRUPT_BYTES) -> None:
        self.ledger.write_bytes(payload)

    def _assert_refusal(self, call, *args, **kwargs) -> None:
        before = self.ledger.read_bytes()
        with self.assertRaises(PalError) as ctx:
            call(*args, **kwargs)
        self.assertEqual(ctx.exception.code, "VALIDATION_FAILED")
        self.assertIn("recurrence.json", ctx.exception.message)
        self.assertIn("untouched", ctx.exception.message)
        self.assertEqual(self.ledger.read_bytes(), before, "zero writes on refusal")

    def test_record_negative_refuses_on_malformed_json(self) -> None:
        self._corrupt()
        self._assert_refusal(
            recurrence_mod.record_negative, self.home, self.session()
        )

    def test_record_occurrence_refuses_on_malformed_json(self) -> None:
        self._corrupt()
        self._assert_refusal(
            recurrence_mod.record_occurrence,
            self.home,
            self.finding(self.occurrence()),
            self.session(),
        )

    def test_record_batch_refuses_on_malformed_json(self) -> None:
        self._corrupt()
        self._assert_refusal(
            recurrence_mod.record_batch,
            self.home,
            self.session(),
            [self.finding(self.occurrence())],
        )

    def test_wrong_root_type_refuses(self) -> None:
        self._corrupt(b"[1, 2, 3]")
        self._assert_refusal(
            recurrence_mod.record_negative, self.home, self.session()
        )

    def test_wrong_finding_shape_refuses(self) -> None:
        self._corrupt(
            json.dumps(
                {
                    "schema_version": 2,
                    "by_finding": {"fp": ["not-an-entry"]},
                    "by_rule": {},
                }
            ).encode()
        )
        self._assert_refusal(
            recurrence_mod.record_negative, self.home, self.session()
        )

    def test_wrong_rule_counter_shape_refuses(self) -> None:
        self._corrupt(
            json.dumps(
                {
                    "schema_version": 2,
                    "by_finding": {},
                    "by_rule": {"PAL-CMD-01": "not-a-counter"},
                }
            ).encode()
        )
        self._assert_refusal(
            recurrence_mod.record_negative, self.home, self.session()
        )

    def test_unknown_schema_version_refuses(self) -> None:
        self._corrupt(
            json.dumps(
                {"schema_version": 99, "by_finding": {}, "by_rule": {}}
            ).encode()
        )
        self._assert_refusal(
            recurrence_mod.record_negative, self.home, self.session()
        )

    def test_migrate_refuses_on_corrupt_bytes(self) -> None:
        self._corrupt()
        self._assert_refusal(recurrence_mod.migrate_recurrence, self.home)

    def test_absent_still_bootstraps(self) -> None:
        data = recurrence_mod.load_recurrence(self.home)
        self.assertEqual(data["schema_version"], 2)
        self.assertEqual(data["by_finding"], {})
        recurrence_mod.record_negative(self.home, self.session())
        ledger = json.loads(self.ledger.read_text(encoding="utf-8"))
        self.assertEqual(ledger["schema_version"], 2)


class ValidLedgersStillWork(IntegrityBase):
    """ROLE 10 D + E: valid v1 migrates, valid v2 writes."""

    def test_valid_v1_migrates_deterministically(self) -> None:
        self.ledger.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "by_finding": {
                        "fp": {"fingerprint": "fp", "occurrences": [
                            {"session_id": "s1", "conformant": False},
                        ]},
                    },
                    "by_rule": {"PAL-CMD-01": {"total": 1, "drift": 1}},
                }
            ),
            encoding="utf-8",
        )
        report = recurrence_mod.migrate_recurrence(self.home)
        self.assertEqual(report["migrated"], True)
        self.assertEqual(report["unresolved"], 1)  # no finding index: preserved
        data = recurrence_mod.load_recurrence(self.home)
        self.assertEqual(data["schema_version"], 2)
        row = data["by_finding"]["fp"]["occurrences"][0]
        self.assertEqual(row["anchor_status"], "UNRESOLVED")

    def test_valid_v2_writes_normally(self) -> None:
        recurrence_mod.record_occurrence(
            self.home, self.finding(self.occurrence()), self.session()
        )
        rows = (
            recurrence_mod.load_recurrence(self.home)["by_finding"]["fp"]["occurrences"]
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["evidence_anchor"], "2:5")


class ReadOnlyStatusNeverRepairs(IntegrityBase):
    """ROLE 8 G: report/doctor truth without a single write."""

    def test_status_reports_invalid_zero_writes(self) -> None:
        self.ledger.write_bytes(CORRUPT_BYTES)
        self.assertEqual(recurrence_mod.recurrence_status(self.home), "INVALID")
        self.assertEqual(self.ledger.read_bytes(), CORRUPT_BYTES)

    def test_status_reports_absent_and_valid(self) -> None:
        self.assertEqual(recurrence_mod.recurrence_status(self.home), "ABSENT")
        recurrence_mod.record_negative(self.home, self.session())
        self.assertEqual(recurrence_mod.recurrence_status(self.home), "VALID")

    def test_carrier_packet_reports_invalid_without_load(self) -> None:
        from saipal_engine import carrier as carrier_mod

        self.ledger.write_bytes(CORRUPT_BYTES)
        packet = carrier_mod._recurrence(self.home, "COMMAND_ROUTE_DRIFT", 5)
        self.assertEqual(packet["recurrence_status"], "INVALID")
        self.assertEqual(self.ledger.read_bytes(), CORRUPT_BYTES)


class MutatingStartupRefusesBeforeEffects(IntegrityBase):
    """ROLE 9: watch/investigate/continue refuse before new semantic effects."""

    def _corrupt(self) -> None:
        (self.home / "recurrence.json").write_bytes(CORRUPT_BYTES)

    def test_watch_stops_config_blocked_before_cycles(self) -> None:
        from saipal_analyst import supervisor as supervisor_mod

        self._corrupt()
        result = supervisor_mod.watch(
            self.home, max_cycles=3, sleep_fn=lambda _s: None
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["stop_reason"], "CONFIGURATION_BLOCKED")
        self.assertEqual(result["cycles_run"], 0)
        self.assertEqual(self.ledger.read_bytes(), CORRUPT_BYTES)

    def test_worker_loop_stops_before_first_unit(self) -> None:
        from saipal_analyst import config as analyst_config_mod
        from saipal_analyst import worker as worker_mod

        self._corrupt()
        config = analyst_config_mod.default_analyst_config()
        config["enabled"] = True
        config["backend"]["model"] = "stub-model"
        self.home / "analyst.json"
        (self.home / analyst_config_mod.ANALYST_CONFIG_NAME).write_text(
            json.dumps(config), encoding="utf-8"
        )
        result = worker_mod.investigate(self.home)
        self.assertEqual(result["stop_reason"], "ERROR")
        self.assertIn("corrupt", result["detail"])
        self.assertEqual(result["units"], 0)
        self.assertEqual(self.ledger.read_bytes(), CORRUPT_BYTES)


if __name__ == "__main__":
    unittest.main()
