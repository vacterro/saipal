"""Wave A: LOG.jsonl is append-only evidence, not authority."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from saipal_engine import capability
from saipal_engine.errors import PalError
from saipal_engine.log import append_event, last_seq, read_events

import pal_test_support as support


class LogContract(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = support.make_home(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_first_event_is_sequence_one(self) -> None:
        record = append_event(self.home, "cycle", data={"phase": "IDLE"})
        self.assertEqual(record["seq"], 1)
        self.assertEqual(record["event"], "cycle")

    def test_sequence_is_monotonic_across_restarts(self) -> None:
        for _ in range(3):
            append_event(self.home, "cycle")
        events, malformed = read_events(self.home)
        self.assertEqual(malformed, 0)
        self.assertEqual([e["seq"] for e in events], [1, 2, 3])

    def test_each_record_carries_a_timestamp(self) -> None:
        record = append_event(self.home, "cycle")
        self.assertRegex(record["ts"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_malformed_lines_are_counted_and_skipped_not_repaired(self) -> None:
        append_event(self.home, "first")
        with open(str(self.home / "LOG.jsonl"), "a", encoding="utf-8") as handle:
            handle.write("{ this line got torn in half\n")
        append_event(self.home, "third")

        events, malformed = read_events(self.home)
        self.assertEqual(malformed, 1)
        self.assertEqual([e["event"] for e in events], ["first", "third"])
        # The torn line is discarded, so it cannot consume a sequence number:
        # numbering resumes from the last record SAIPAL can actually read.
        self.assertEqual([e["seq"] for e in events], [1, 2])

    def test_torn_tail_does_not_corrupt_the_sequence(self) -> None:
        append_event(self.home, "first")
        with open(str(self.home / "LOG.jsonl"), "a", encoding="utf-8") as handle:
            handle.write('{"seq": 2, "event": "half-wri')
        self.assertEqual(last_seq(self.home / "LOG.jsonl"), 1)

    def test_empty_and_missing_logs_read_as_zero(self) -> None:
        self.assertEqual(last_seq(self.home / "LOG.jsonl"), 0)
        events, malformed = read_events(self.home)
        self.assertEqual((events, malformed), ([], 0))

    def test_blank_lines_are_not_events(self) -> None:
        append_event(self.home, "first")
        with open(str(self.home / "LOG.jsonl"), "a", encoding="utf-8") as handle:
            handle.write("\n\n")
        events, malformed = read_events(self.home)
        self.assertEqual(len(events), 1)
        self.assertEqual(malformed, 0)

    def test_red_control_requires_the_write_action(self) -> None:
        """Forbid `write_own_log` in the registry; the append must refuse."""
        mutated = support.load_registry_copy()
        actions = mutated["write_actions"]
        actions["forbidden"] = sorted(set(actions["forbidden"]) | {"write_own_log"})
        actions["allowed"] = [a for a in actions["allowed"] if a != "write_own_log"]

        # The gate lives in `capability`; that is whose registry lookup counts.
        with mock.patch.object(capability, "load_registry", return_value=mutated):
            with self.assertRaises(PalError) as caught:
                append_event(self.home, "cycle")

        self.assertEqual(caught.exception.code, "CAPABILITY_DENIED")
        self.assertFalse((self.home / "LOG.jsonl").exists(), "nothing may be appended")

    def test_red_control_digest_sensitivity(self) -> None:
        """The log really is bytes on disk -- prove a change is observable."""
        append_event(self.home, "cycle")
        before = support.tree_digest(self.home)
        append_event(self.home, "cycle")
        self.assertNotEqual(before, support.tree_digest(self.home))


if __name__ == "__main__":
    unittest.main()
