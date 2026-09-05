"""T-066 / audits CORE-007, CORE-008, CORE-010: the unattended loop tells the truth.

CORE-007 -- under `PUBLISH_ENABLED` a sink failure staged the audit locally and
then advanced the finding to `EMITTED` anyway, so a transient maintainer-sink
outage permanently lost delivery: nothing recorded that the sink never saw it.

CORE-008 -- `last_seq` read only the final 64 KiB, so a longer torn tail returned
0, the next append restarted numbering at 1, and the append-only log carried a
later event with a smaller `seq` than its own history.

CORE-010 -- `_continue_cycle` deleted whatever `trigger.json` existed at the END
of the cycle, so a trigger arriving mid-cycle was acknowledged as scheduled and
then discarded without ever causing the run it asked for.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pal_test_support as support
from saipal_engine import log as log_mod
from saipal_engine import publications as pub_mod
from saipal_engine.paths import home_paths
from saipal_engine.registry import load_registry

DRIFT = "agent-noncompliance-command-route.json"
CLEAN = "no-finding-normal.json"


def record(seq: int, **extra) -> bytes:
    payload = {"seq": seq, "ts": "2026-01-01T00:00:00Z", "event": "e", "data": {}}
    payload.update(extra)
    return (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")


class LastSeqSurvivesATornTail(unittest.TestCase):
    """CORE-008: monotonic append identity must not depend on one window."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.log = Path(self._tmp.name) / "LOG.jsonl"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_an_absent_log_starts_at_zero(self) -> None:
        self.assertEqual(log_mod.last_seq(self.log), 0)

    def test_an_empty_log_starts_at_zero(self) -> None:
        self.log.write_bytes(b"")
        self.assertEqual(log_mod.last_seq(self.log), 0)

    def test_a_normal_log_reports_its_last_record(self) -> None:
        self.log.write_bytes(record(1) + record(2) + record(3))
        self.assertEqual(log_mod.last_seq(self.log), 3)

    def test_a_torn_final_line_falls_back_to_the_previous(self) -> None:
        self.log.write_bytes(record(7) + b'{"seq": 8, "ts": ')
        self.assertEqual(log_mod.last_seq(self.log), 7)

    def test_a_garbage_tail_longer_than_one_window_is_scanned_past(self) -> None:
        """The audit's reproduction: >64 KiB of garbage returned 0 before."""
        self.log.write_bytes(record(41) + b"x" * (log_mod.TAIL_WINDOW + 10) + b"\n")
        self.assertEqual(log_mod.last_seq(self.log), 41)

    def test_a_multi_chunk_garbage_tail_is_scanned_past(self) -> None:
        self.log.write_bytes(record(41) + b"x" * (log_mod.TAIL_WINDOW * 4) + b"\n")
        self.assertEqual(log_mod.last_seq(self.log), 41)

    def test_a_record_straddling_a_chunk_boundary_is_read_whole(self) -> None:
        """A chunk split mid-record must not be parsed as a fragment."""
        padding = b"\n" * (log_mod.TAIL_WINDOW - 20)
        self.log.write_bytes(
            padding + record(5, pad="y" * 60) + b"z" * (log_mod.TAIL_WINDOW + 100)
        )
        self.assertEqual(log_mod.last_seq(self.log), 5)

    def test_a_single_line_without_a_trailing_newline_still_counts(self) -> None:
        self.log.write_bytes(record(99).rstrip(b"\n"))
        self.assertEqual(log_mod.last_seq(self.log), 99)

    def test_a_whole_log_of_garbage_is_zero(self) -> None:
        self.log.write_bytes(b"x" * (log_mod.TAIL_WINDOW * 2))
        self.assertEqual(log_mod.last_seq(self.log), 0)

    def test_a_boolean_seq_is_not_a_sequence_number(self) -> None:
        """`True` is an int in Python; it is not evidence of position."""
        self.log.write_bytes(record(4) + record(True))
        self.assertEqual(log_mod.last_seq(self.log), 4)

    def test_appending_after_a_long_torn_tail_keeps_numbering_monotonic(self) -> None:
        """Red control: the whole point -- the next event must be 42, not 1."""
        with tempfile.TemporaryDirectory() as tmp:
            home = support.make_home(Path(tmp))
            log_path = home_paths(home).log
            log_path.write_bytes(record(41) + b"x" * (log_mod.TAIL_WINDOW + 10) + b"\n")
            written = log_mod.append_event(home, "after_the_tear")
            self.assertEqual(written["seq"], 42)
            events, malformed = log_mod.read_events(home)
            sequences = [event["seq"] for event in events]
            self.assertEqual(sequences, sorted(sequences), "seq must never go backwards")
            self.assertGreaterEqual(malformed, 1, "the garbage is still reported, not repaired")


class PendingPublicationLedger(unittest.TestCase):
    """CORE-007: the primitive that remembers an undelivered audit."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = support.make_home(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def entry(self, **overrides) -> dict:
        payload = {
            "finding_id": "PAL-0001",
            "audit_number": 1,
            "audit_path": "audit/staging/1.md",
            "audit_sha256": "a" * 64,
            "reason": "sink root is not a directory",
        }
        payload.update(overrides)
        return pub_mod.record_pending(self.home, **payload)

    def test_an_absent_ledger_has_nothing_pending(self) -> None:
        self.assertEqual(pub_mod.pending(self.home), [])

    def test_a_recorded_failure_is_pending(self) -> None:
        self.entry()
        outstanding = pub_mod.pending(self.home)
        self.assertEqual([row["audit_number"] for row in outstanding], [1])
        self.assertEqual(outstanding[0]["status"], pub_mod.PENDING)

    def test_recording_the_same_audit_twice_counts_attempts(self) -> None:
        self.entry()
        again = self.entry()
        self.assertEqual(again["attempts"], 2)
        self.assertEqual(len(pub_mod.pending(self.home)), 1)

    def test_marking_published_clears_it(self) -> None:
        self.entry()
        pub_mod.mark_published(self.home, audit_number=1, audit_sha256="a" * 64)
        self.assertEqual(pub_mod.pending(self.home), [])

    def test_a_different_audit_is_a_separate_row(self) -> None:
        self.entry()
        self.entry(audit_number=2, audit_path="audit/staging/2.md", audit_sha256="b" * 64)
        self.assertEqual(len(pub_mod.pending(self.home)), 2)

    def test_a_corrupt_ledger_refuses_mutation_and_keeps_its_bytes(self) -> None:
        """Red control: overwriting it would drop every undelivered audit."""
        from saipal_engine.errors import PalError

        path = home_paths(self.home).publications
        path.write_text("{ not json", encoding="utf-8")
        before = path.read_bytes()
        with self.assertRaises(PalError):
            self.entry()
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(pub_mod.pending(self.home), [], "corruption is not a pending list")


class SinkOutageIsRetried(unittest.TestCase):
    """CORE-007 end to end: an outage stages, a restored sink receives."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        self.sink_root = self.tmp / "maintainer"
        self._make_sink()
        self._configure()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _make_sink(self) -> None:
        audit = self.sink_root / "audit"
        audit.mkdir(parents=True, exist_ok=True)
        (audit / "MANIFEST.json").write_text(
            json.dumps({"kind": "saipen-audit-inbox"}), encoding="utf-8"
        )

    def _break_sink(self) -> None:
        import shutil

        shutil.rmtree(self.sink_root)

    def _configure(self) -> None:
        config = self.home / "config.json"
        payload = json.loads(config.read_text(encoding="utf-8"))
        payload["publication_mode"] = "PUBLISH_ENABLED"
        payload["shadow_reviewed"] = True
        payload["sink"] = {"kind": "termisai-file", "root": str(self.sink_root)}
        config.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def cycle(self) -> dict:
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        return payload

    def sink_audits(self) -> list[str]:
        audit = self.sink_root / "audit"
        if not audit.is_dir():
            return []
        return sorted(p.name for p in audit.glob("*.md"))

    def staged_audits(self) -> list[str]:
        staging = self.home / "audit" / "staging"
        if not staging.is_dir():
            return []
        return sorted(p.name for p in staging.glob("*.md"))

    def findings(self) -> list[dict]:
        path = self.home / "findings" / "index.json"
        if not path.exists():
            return []
        return json.loads(path.read_text(encoding="utf-8"))["findings"]

    def test_a_healthy_sink_publishes_immediately(self) -> None:
        support.put_inbox(self.home, DRIFT)
        self.cycle()
        self.assertEqual(self.sink_audits(), ["1.md"])
        self.assertEqual(pub_mod.pending(self.home), [], "a delivered audit is not pending")
        self.assertEqual(self.findings()[0]["audit"]["delivery"], pub_mod.PUBLISHED)

    def test_a_vanished_sink_stages_once_and_records_a_pending_delivery(self) -> None:
        """The audit's reproduction, first half."""
        self._break_sink()
        support.put_inbox(self.home, DRIFT)
        self.cycle()
        self.assertEqual(self.staged_audits(), ["1.md"], "exactly one local staged audit")
        outstanding = pub_mod.pending(self.home)
        self.assertEqual([row["audit_number"] for row in outstanding], [1])

    def test_the_finding_says_staged_not_delivered(self) -> None:
        """Red control: EMITTED must not read as "the maintainer has it"."""
        self._break_sink()
        support.put_inbox(self.home, DRIFT)
        self.cycle()
        finding = self.findings()[0]
        self.assertEqual(finding["state"], "EMITTED", "the audit exists locally")
        self.assertEqual(
            finding["audit"]["delivery"], pub_mod.PENDING,
            "delivery must be distinguishable from local staging",
        )

    def test_a_restored_sink_receives_that_exact_audit(self) -> None:
        """The audit's reproduction, second half: it used to stay empty forever."""
        self._break_sink()
        support.put_inbox(self.home, DRIFT)
        self.cycle()
        staged_digest = (self.home / "audit" / "staging" / "1.md").read_text(encoding="utf-8")

        self._make_sink()
        payload = self.cycle()
        self.assertEqual(payload["publication_retry"]["published"], 1)
        self.assertEqual(self.sink_audits(), ["1.md"])
        self.assertEqual(
            (self.sink_root / "audit" / "1.md").read_text(encoding="utf-8"),
            staged_digest,
            "the retry must publish the SAME body, not a rebuilt one",
        )
        self.assertEqual(pub_mod.pending(self.home), [])

    def test_further_cycles_create_no_duplicates(self) -> None:
        self._break_sink()
        support.put_inbox(self.home, DRIFT)
        self.cycle()
        self._make_sink()
        self.cycle()
        self.cycle()
        self.cycle()
        self.assertEqual(self.sink_audits(), ["1.md"])
        self.assertEqual(self.staged_audits(), ["1.md"])

    def test_a_still_absent_sink_keeps_the_delivery_pending(self) -> None:
        self._break_sink()
        support.put_inbox(self.home, DRIFT)
        self.cycle()
        payload = self.cycle()
        self.assertEqual(payload["publication_retry"]["published"], 0)
        self.assertEqual(payload["publication_retry"]["still_pending"], 1)
        self.assertEqual(len(pub_mod.pending(self.home)), 1)

    def test_the_retry_reuses_the_audit_number(self) -> None:
        self._break_sink()
        support.put_inbox(self.home, DRIFT)
        self.cycle()
        self._make_sink()
        self.cycle()
        self.assertEqual(
            [row["audit_number"] for row in pub_mod.pending(self.home)], [],
        )
        self.assertEqual(self.sink_audits(), ["1.md"], "never a fresh number on retry")


class TriggerIsClaimedAtCycleStart(unittest.TestCase):
    """CORE-010: a mid-cycle trigger must survive the cycle it arrived during."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        self.paths = home_paths(self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def trigger(self) -> dict:
        code, payload, err = support.run_saipal_json("trigger", home=self.home)
        self.assertEqual(code, 0, err)
        return payload

    def test_a_trigger_before_the_cycle_is_consumed_by_it(self) -> None:
        self.trigger()
        self.assertTrue(self.paths.trigger.exists())
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertTrue(payload["trigger_claimed"])
        self.assertFalse(self.paths.trigger.exists())
        self.assertFalse(self.paths.trigger_claim.exists())

    def test_a_cycle_without_a_trigger_claims_nothing(self) -> None:
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertFalse(payload["trigger_claimed"])

    def test_rapid_triggers_coalesce_into_one_pending_token(self) -> None:
        first = self.trigger()
        second = self.trigger()
        self.assertFalse(first["coalesced"])
        self.assertTrue(second["coalesced"])

    def test_a_trigger_arriving_mid_cycle_survives(self) -> None:
        """The audit's lost wakeup, driven through the real claim/release pair."""
        import saipal

        self.trigger()
        claimed = saipal._claim_trigger(self.home)
        self.assertTrue(claimed)
        self.assertFalse(self.paths.trigger.exists(), "the claim moved the token")
        self.assertTrue(self.paths.trigger_claim.exists())

        # A new request arrives while the cycle is still running.
        mid = self.trigger()
        self.assertFalse(mid["coalesced"], "the pending slot is free again")

        saipal._release_trigger(self.home)
        self.assertFalse(self.paths.trigger_claim.exists())
        self.assertTrue(
            self.paths.trigger.exists(),
            "a mid-cycle trigger must remain pending for the next cycle",
        )

    def test_that_surviving_trigger_drives_a_second_cycle(self) -> None:
        import saipal

        self.trigger()
        saipal._claim_trigger(self.home)
        self.trigger()
        saipal._release_trigger(self.home)
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertTrue(payload["trigger_claimed"], "the survivor caused a run")
        self.assertFalse(self.paths.trigger.exists())

    def test_several_mid_cycle_triggers_coalesce_to_one_next_cycle(self) -> None:
        import saipal

        self.trigger()
        saipal._claim_trigger(self.home)
        self.trigger()
        for _ in range(3):
            self.assertTrue(self.trigger()["coalesced"])
        saipal._release_trigger(self.home)
        self.assertTrue(self.paths.trigger.exists())
        code, payload, _err = support.run_saipal_json("continue", home=self.home)
        self.assertTrue(payload["trigger_claimed"])
        code, payload, _err = support.run_saipal_json("continue", home=self.home)
        self.assertFalse(payload["trigger_claimed"], "three requests are one run")

    def test_a_trigger_written_during_a_real_cycle_survives_it(self) -> None:
        """The lost wakeup through the REAL cycle, not just the claim helpers.

        The trigger is written from inside intake, i.e. after the cycle has
        claimed its own token and before the cycle ends -- exactly the window in
        which the old end-of-cycle delete swallowed it.
        """
        import saipal

        self.trigger()
        real_import = saipal.import_inbox
        wrote = {"done": False}

        def import_then_trigger(*args, **kwargs):
            result = real_import(*args, **kwargs)
            if not wrote["done"]:
                wrote["done"] = True
                support.run_saipal("trigger", home=self.home)
            return result

        with mock.patch.object(saipal, "import_inbox", import_then_trigger):
            code, payload = saipal._continue_cycle(self.home, self.registry)
        self.assertEqual(code, 0)
        self.assertTrue(wrote["done"], "the mid-cycle trigger must actually have been written")
        self.assertTrue(payload["trigger_claimed"], "the pre-cycle trigger was consumed")
        self.assertTrue(
            self.paths.trigger.exists(),
            "the mid-cycle trigger must remain pending for the next cycle",
        )

        code, second = saipal._continue_cycle(self.home, self.registry)
        self.assertEqual(code, 0)
        self.assertTrue(second["trigger_claimed"], "the survivor caused its own run")
        self.assertFalse(self.paths.trigger.exists())

    def test_a_crashed_cycle_leaves_the_claim_for_the_next_one(self) -> None:
        """A claimed request is still owed a run; the claim is adopted, not dropped."""
        import saipal

        self.trigger()
        saipal._claim_trigger(self.home)
        self.assertTrue(self.paths.trigger_claim.exists())
        # No release: the cycle died. The next cycle must honour the claim.
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertTrue(payload["trigger_claimed"], "an orphan claim is still a request")
        self.assertFalse(self.paths.trigger_claim.exists())

    def test_the_claim_is_atomic_between_two_contenders(self) -> None:
        import saipal

        self.trigger()
        self.assertTrue(saipal._claim_trigger(self.home))
        # A second cycle sees the same claim rather than a second token.
        self.assertTrue(saipal._claim_trigger(self.home))
        self.assertFalse(self.paths.trigger.exists())
        saipal._release_trigger(self.home)
        self.assertFalse(self.paths.trigger_claim.exists())

    def test_release_without_a_claim_touches_nothing(self) -> None:
        import saipal

        self.trigger()
        saipal._release_trigger(self.home)
        self.assertTrue(
            self.paths.trigger.exists(), "an unclaimed trigger must not be deleted"
        )

    def test_a_clean_cycle_still_records_no_trigger(self) -> None:
        support.put_inbox(self.home, CLEAN)
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertFalse(payload["trigger_claimed"])


if __name__ == "__main__":
    unittest.main()
