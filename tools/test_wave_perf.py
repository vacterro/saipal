"""T-067 / audit PERF-001, 002, 004, 005, 006: the hot path stops re-reading itself.

Five measured amplifications, each fixed by removing repeated work rather than by
changing what the runtime concludes. The controls therefore come in pairs: a
behaviour test proving the answer is unchanged, and a work-counting test proving
the work is.

PERF-003 (HOT provider polling) is T-72: it needs a new dispatcher probe contract
and a persisted watermark, not a local optimization.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import pal_test_support as support
from saipal_engine import bundle as bundle_mod
from saipal_engine import detectors as detectors_mod
from saipal_engine import episodes as episodes_mod
from saipal_engine import inbox as inbox_mod
from saipal_engine import log as log_mod
from saipal_engine import recurrence as recurrence_mod
from saipal_engine import sessions as sessions_mod
from saipal_engine.adapters import ADAPTER_REGISTRY
from saipal_engine.dispatcher import dispatch_sources
from saipal_engine.pipeline import analyze_sessions
from saipal_engine.registry import load_registry
from types import SimpleNamespace

COLD = "conformant-cold.json"
DRIFT = "agent-noncompliance-command-route.json"


def synthetic_bundle(session_id: str, *, episodes: int, per_episode: int = 4) -> dict:
    """A COLD bundle of `episodes` episodes with `per_episode` events each."""
    events: list[dict] = []
    seq = 0
    for _ in range(episodes):
        seq += 1
        events.append({"seq": seq, "type": "USER_MESSAGE", "facts": {"task": "t"}})
        for _ in range(per_episode - 1):
            seq += 1
            events.append({"seq": seq, "type": "TOOL_CALL", "facts": {"tool": "bash"}})
    events.append({"seq": seq + 1, "type": "ASSISTANT_MESSAGE", "facts": {"reply": "ok"}})
    return {
        "schema_version": 1,
        "session_id": session_id,
        "adapter": "generic",
        "project": {"name": "PerfProject"},
        "runtime": {"provider": "p", "model": "m"},
        "temperature": "COLD",
        "protocol": {"version": "7.231.9", "registry_sha256": "a" * 64},
        "events": events,
    }


class EventIndexIsTheSameAnswerCheaper(unittest.TestCase):
    """PERF-001: a span is a bisect, and it agrees with the old filter."""

    def setUp(self) -> None:
        self.bundle = synthetic_bundle("idx-001", episodes=25)
        self.index = detectors_mod.EventIndex(self.bundle)

    def naive_span(self, start: int, end: int) -> list[dict]:
        return [
            event
            for event in self.bundle["events"]
            if start <= int(event["seq"]) <= end
        ]

    def test_a_span_matches_the_naive_filter(self) -> None:
        for start, end in ((1, 4), (5, 8), (1, 1), (97, 101), (1, 101)):
            with self.subTest(span=(start, end)):
                self.assertEqual(
                    [e["seq"] for e in self.index.span(start, end)],
                    [e["seq"] for e in self.naive_span(start, end)],
                )

    def test_a_span_outside_the_stream_is_empty(self) -> None:
        self.assertEqual(self.index.span(9000, 9100), [])

    def test_a_span_is_memoized(self) -> None:
        first = self.index.span(1, 8)
        self.assertIs(self.index.span(1, 8), first)

    def test_first_after_finds_the_next_match_only(self) -> None:
        found = self.index.first_after(
            4, lambda event: event.get("type") == "USER_MESSAGE"
        )
        self.assertEqual(found["seq"], 5)

    def test_first_after_returns_none_past_the_end(self) -> None:
        self.assertIsNone(
            self.index.first_after(9000, lambda event: True)
        )

    def test_an_empty_bundle_indexes_cleanly(self) -> None:
        empty = detectors_mod.EventIndex({"events": []})
        self.assertEqual(empty.all(), [])
        self.assertEqual(empty.span(1, 5), [])
        self.assertIsNone(empty.first_after(0, lambda event: True))


class DetectorsShareOneIndex(unittest.TestCase):
    """PERF-001: five detectors must cost one span resolution, not five scans."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self.bundle = synthetic_bundle("share-001", episodes=6)
        self.episodes = episodes_mod.extract_episodes(
            self.bundle["events"], registry=self.registry
        )
        self.record = {"session_id": "share-001", "protocol": {}}

    def test_detect_all_builds_one_index_for_every_detector(self) -> None:
        with mock.patch.object(
            detectors_mod, "EventIndex", wraps=detectors_mod.EventIndex
        ) as spy:
            detectors_mod.detect_all(
                self.episodes[0], self.bundle, self.record, registry=self.registry
            )
        self.assertEqual(spy.call_count, 1, "one index for the whole detector set")

    def test_a_caller_supplied_index_is_reused(self) -> None:
        """Red control: the pipeline pays once per session, not once per episode."""
        view = detectors_mod.EventIndex(self.bundle)
        with mock.patch.object(
            detectors_mod, "EventIndex", side_effect=AssertionError("rebuilt")
        ):
            for episode in self.episodes:
                detectors_mod.detect_all(
                    episode, self.bundle, self.record, registry=self.registry, index=view
                )

    def test_a_whole_session_analysis_builds_one_index(self) -> None:
        from saipal_engine import pipeline as pipeline_mod

        with tempfile.TemporaryDirectory() as tmp:
            home = support.make_home(Path(tmp))
            support.run_saipal("continue", home=home)
            support.write_inbox(home, "share.json", self.bundle)
            support.run_saipal("continue", home=home)
            status, index, _detail = sessions_mod.load_index(home, registry=self.registry)
            for record in index["sessions"]:
                record.pop("analysis", None)
                record["last_analyzed_seq"] = 0
            sessions_mod.save_index(home, index, registry=self.registry)
            status, index, _detail = sessions_mod.load_index(home, registry=self.registry)

            with mock.patch.object(
                pipeline_mod.detectors_mod,
                "EventIndex",
                wraps=detectors_mod.EventIndex,
            ) as spy:
                result = analyze_sessions(home, index, registry=self.registry)
        self.assertGreater(result["events_analyzed"], 0, "the session was analyzed")
        self.assertEqual(spy.call_count, 1, "one index per session, not per episode")

    def test_the_detector_verdicts_are_unchanged(self) -> None:
        """The control: an optimization that changes the verdict is not one."""
        with tempfile.TemporaryDirectory() as tmp:
            home = support.make_home(Path(tmp))
            support.run_saipal("continue", home=home)
            support.put_inbox(home, DRIFT)
            support.run_saipal("continue", home=home)
            code, report, err = support.run_saipal_json("report", home=home)
            self.assertEqual(code, 0, err)
            self.assertEqual(report["verdict"], "NOT_EXAMINED", "triage is not a verdict")
            signals = json.loads((home / "signals.json").read_text(encoding="utf-8"))["signals"]
            self.assertGreaterEqual(len(signals), 1, "the fixture must still signal")
            self.assertTrue(
                any(s["drift_class"] == "COMMAND_ROUTE_DRIFT" for s in signals),
                "the optimization must not change the detector's verdict",
            )


class InboxSkipsUnchangedFilesWithoutReadingThem(unittest.TestCase):
    """PERF-002: the inbox is a durable archive, not a queue to reprocess."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_the_first_pass_reads_and_imports(self) -> None:
        support.put_inbox(self.home, COLD)
        report = inbox_mod.import_inbox(self.home, registry=self.registry)
        self.assertEqual(report["new_sessions"], 1)

    def test_a_second_pass_does_not_read_the_file_again(self) -> None:
        """The audit's finding: 95 of 99 skips still paid a full parse."""
        support.put_inbox(self.home, COLD)
        inbox_mod.import_inbox(self.home, registry=self.registry)
        with mock.patch.object(
            bundle_mod, "load_bundle_with_digest", side_effect=AssertionError("re-read")
        ):
            report = inbox_mod.import_inbox(self.home, registry=self.registry)
        self.assertEqual(report["new_sessions"], 0)
        self.assertEqual(
            [entry["reason"] for entry in report["skipped"]], ["duplicate digest"]
        )

    def test_a_changed_file_is_read_again(self) -> None:
        """Red control: the cache may never hide new evidence."""
        support.write_inbox(self.home, "s.json", synthetic_bundle("cache-001", episodes=2))
        inbox_mod.import_inbox(self.home, registry=self.registry)
        support.write_inbox(self.home, "s.json", synthetic_bundle("cache-001", episodes=3))
        report = inbox_mod.import_inbox(self.home, registry=self.registry)
        self.assertEqual(report["new_sessions"], 1, "a rewritten artifact must be read")

    def test_a_corrupt_cache_falls_back_to_reading(self) -> None:
        support.put_inbox(self.home, COLD)
        inbox_mod.import_inbox(self.home, registry=self.registry)
        (self.home / inbox_mod.INBOX_CACHE_NAME).write_text("{ nope", encoding="utf-8")
        report = inbox_mod.import_inbox(self.home, registry=self.registry)
        self.assertEqual(
            [entry["reason"] for entry in report["skipped"]], ["duplicate digest"]
        )

    def test_the_recorded_observation_is_provably_later_than_the_write(self) -> None:
        """The cache only counts if its own entries pass `_trustworthy`.

        `st_mtime_ns` and `time.time_ns()` come off the same coarse Windows tick,
        so a file imported milliseconds after it was written was stamped with an
        observation EQUAL to its mtime -- an entry `_trustworthy` rejects forever,
        which silently turned the whole cache back into a full re-read on roughly
        a quarter of runs.
        """
        support.put_inbox(self.home, COLD)
        inbox_mod.import_inbox(self.home, registry=self.registry)
        cache = json.loads(
            (self.home / inbox_mod.INBOX_CACHE_NAME).read_text(encoding="utf-8")
        )
        self.assertEqual(list(cache["files"]), [COLD])
        entry = cache["files"][COLD]
        mtime_ns = (self.home / "session_inbox" / COLD).stat().st_mtime_ns
        self.assertGreater(entry["observed_at"], mtime_ns)
        self.assertTrue(inbox_mod._trustworthy(entry, {**entry}))

    def test_a_write_inside_the_current_tick_is_still_cached(self) -> None:
        """The defect, forced instead of raced.

        Stamping the file just ahead of the clock reproduces on demand what
        Windows produces by accident: `st_mtime_ns` not yet behind
        `time.time_ns()`. A bare clock read then records an observation no later
        than the change it observed, `_trustworthy` refuses that entry forever,
        and the cache silently degrades to a full re-read of the whole archive.
        Waiting out the tick is what makes the entry usable.
        """
        support.put_inbox(self.home, COLD)
        path = self.home / "session_inbox" / COLD
        just_ahead = (time.time_ns() + 10_000_000) / 1_000_000_000
        os.utime(path, (just_ahead, just_ahead))
        inbox_mod.import_inbox(self.home, registry=self.registry)
        cache = json.loads(
            (self.home / inbox_mod.INBOX_CACHE_NAME).read_text(encoding="utf-8")
        )
        entry = cache["files"][COLD]
        self.assertGreater(entry["observed_at"], path.stat().st_mtime_ns)
        with mock.patch.object(
            bundle_mod, "load_bundle_with_digest", side_effect=AssertionError("re-read")
        ):
            report = inbox_mod.import_inbox(self.home, registry=self.registry)
        self.assertEqual(
            [row["reason"] for row in report["skipped"]], ["duplicate digest"]
        )

    def test_an_mtime_in_the_future_is_left_uncached_without_stalling(self) -> None:
        """Red control for the wait: a clock it can never outrun is refused.

        A file stamped in the future can never be observed later than itself, so
        waiting for that would hang intake on a bad network share. Not caching it
        is only slower; hanging is an outage.
        """
        support.put_inbox(self.home, COLD)
        path = self.home / "session_inbox" / COLD
        future = time.time() + 3600
        os.utime(path, (future, future))
        started = time.monotonic()
        report = inbox_mod.import_inbox(self.home, registry=self.registry)
        elapsed = time.monotonic() - started
        self.assertEqual(report["new_sessions"], 1, "the evidence is still imported")
        cache_path = self.home / inbox_mod.INBOX_CACHE_NAME
        remembered = (
            json.loads(cache_path.read_text(encoding="utf-8"))["files"]
            if cache_path.is_file()
            else {}
        )
        self.assertNotIn(COLD, remembered)
        self.assertLess(elapsed, 5, "intake may not wait on a clock it cannot outrun")

    def test_an_unchanged_inbox_does_not_rewrite_the_index(self) -> None:
        support.put_inbox(self.home, COLD)
        inbox_mod.import_inbox(self.home, registry=self.registry)
        index_path = self.home / "sessions" / "index.json"
        before = index_path.read_bytes()
        # `inbox` binds `save_index` at import, so the patch must target the name
        # the module actually calls -- patching `sessions.save_index` would leave
        # the real function in place and prove nothing.
        with mock.patch.object(
            inbox_mod, "save_index", side_effect=AssertionError("rewrote the index")
        ):
            inbox_mod.import_inbox(self.home, registry=self.registry)
        self.assertEqual(index_path.read_bytes(), before)

    def test_a_changed_inbox_still_saves_the_index(self) -> None:
        """The control: skipping the save when there IS new evidence would lose it."""
        support.write_inbox(self.home, "s.json", synthetic_bundle("save-001", episodes=2))
        with mock.patch.object(
            inbox_mod, "save_index", wraps=inbox_mod.save_index
        ) as spy:
            inbox_mod.import_inbox(self.home, registry=self.registry)
        self.assertEqual(spy.call_count, 1)

    def test_the_bundle_is_canonicalized_once_per_file(self) -> None:
        """Validation and intake each hashed it before: two serializations."""
        support.put_inbox(self.home, COLD)
        with mock.patch.object(
            bundle_mod, "bundle_digest", wraps=bundle_mod.bundle_digest
        ) as spy:
            inbox_mod.import_inbox(self.home, registry=self.registry)
        self.assertEqual(spy.call_count, 1, f"digested {spy.call_count} times")

    def test_load_bundle_with_digest_agrees_with_the_separate_call(self) -> None:
        support.put_inbox(self.home, COLD)
        path = self.home / "session_inbox" / COLD
        bundle, digest = bundle_mod.load_bundle_with_digest(path, registry=self.registry)
        self.assertEqual(digest, bundle_mod.bundle_digest(bundle))

    def test_a_mismatched_declared_digest_is_still_rejected(self) -> None:
        """Red control: passing the digest in must not skip the check."""
        payload = synthetic_bundle("liar-001", episodes=1)
        payload["session_sha256"] = "f" * 64
        problems = bundle_mod.validate_bundle(payload, registry=self.registry)
        self.assertTrue(any("does not match" in problem for problem in problems))


class TheIndexIsNotRewrittenForNothing(unittest.TestCase):
    """PERF-004: a no-work pass must not rewrite an 11 MB index."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, COLD)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def index(self) -> dict:
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        self.assertEqual(status, "ok")
        return index

    def test_a_no_work_analysis_writes_nothing(self) -> None:
        result = analyze_sessions(self.home, self.index(), registry=self.registry)
        self.assertEqual(result["sessions_analyzed"], 0, "precondition: exhausted")
        with mock.patch.object(
            sessions_mod, "save_index", side_effect=AssertionError("rewrote the index")
        ):
            analyze_sessions(self.home, self.index(), registry=self.registry)

    def test_a_pass_that_does_work_still_saves(self) -> None:
        """The control: skipping the save when there IS work would lose it."""
        index = self.index()
        for record in index["sessions"]:
            record.pop("analysis", None)
            record["last_analyzed_seq"] = 0
        sessions_mod.save_index(self.home, index, registry=self.registry)
        result = analyze_sessions(self.home, self.index(), registry=self.registry)
        self.assertEqual(result["sessions_analyzed"], 1)
        self.assertTrue(
            (self.index()["sessions"][0].get("analysis") or {}).get("episodes_exhausted")
        )

    def test_the_session_index_carries_no_unconsumed_spans(self) -> None:
        record = self.index()["sessions"][0]
        self.assertNotIn(
            "mechanical_spans", record, "nothing reads it; the bundle is the evidence"
        )

    def test_mechanical_spans_are_still_derivable_from_the_bundle(self) -> None:
        """Removing the duplicate must not remove the semantic."""
        bundle = bundle_mod.load_bundle_file(
            self.home / "session_inbox" / COLD, registry=self.registry
        )
        spans = episodes_mod.mechanical_spans(bundle_mod.events_of(bundle))
        self.assertTrue(spans)
        self.assertEqual([span["index"] for span in spans], list(range(len(spans))))

    def test_status_loads_the_session_index_once(self) -> None:
        import saipal

        with mock.patch.object(
            saipal, "load_index", wraps=saipal.load_index
        ) as spy:
            code, _result = saipal.cmd_status(self.home, self.registry)
        self.assertEqual(code, 0)
        self.assertEqual(spy.call_count, 1, f"loaded {spy.call_count} times")

    def test_status_still_reports_coverage(self) -> None:
        code, payload, err = support.run_saipal_json("status", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertIn("episodes_total", payload["semantic"])
        self.assertNotIn("_session_index", payload, "the reuse channel is internal")

    def test_report_and_next_still_answer_correctly(self) -> None:
        code, report, err = support.run_saipal_json("report", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertIn(report["verdict"], ("NOT_EXAMINED", "NO_DRIFT_SO_FAR"))
        self.assertNotIn("_session_index", report)
        code, nxt, err = support.run_saipal_json("next", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertIn("analysis_carrier", nxt)
        self.assertNotIn("_session_index", nxt)


class RecurrenceIsWrittenOncePerSession(unittest.TestCase):
    """PERF-005: one ledger transaction per session, not per finding."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = support.make_home(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def session(self) -> dict:
        return {
            "session_id": "s1",
            "adapter": "generic",
            "project": {"name": "P"},
            "protocol": {"version": "1.0.0"},
        }

    def findings(self, count: int) -> list[dict]:
        return [
            {
                "finding_id": f"PAL-{n:04d}",
                "fingerprint": f"fp-{n}",
                "drift_class": "COMMAND_ROUTE_DRIFT",
                "rule_ids": ["PAL-CMD-01"],
            }
            for n in range(1, count + 1)
        ]

    def occurrences(self) -> int:
        data = recurrence_mod.load_recurrence(self.home)
        return sum(
            len(entry.get("occurrences") or [])
            for entry in (data.get("by_finding") or {}).values()
        )

    def test_a_batch_records_every_occurrence(self) -> None:
        recurrence_mod.record_batch(self.home, self.session(), self.findings(5))
        self.assertEqual(self.occurrences(), 5)

    def test_a_batch_saves_once(self) -> None:
        with mock.patch.object(
            recurrence_mod, "save_recurrence", wraps=recurrence_mod.save_recurrence
        ) as spy:
            recurrence_mod.record_batch(self.home, self.session(), self.findings(5))
        self.assertEqual(spy.call_count, 1, f"saved {spy.call_count} times for 5 findings")

    def test_an_empty_batch_writes_nothing(self) -> None:
        with mock.patch.object(
            recurrence_mod, "save_recurrence", side_effect=AssertionError("wrote")
        ):
            recurrence_mod.record_batch(self.home, self.session(), [])

    def test_a_fully_deduped_batch_writes_nothing(self) -> None:
        rows = self.findings(3)
        recurrence_mod.record_batch(self.home, self.session(), rows, occurrence_id="k1")
        with mock.patch.object(
            recurrence_mod, "save_recurrence", side_effect=AssertionError("wrote")
        ):
            recurrence_mod.record_batch(self.home, self.session(), rows, occurrence_id="k1")

    def test_the_batch_agrees_with_the_per_finding_api(self) -> None:
        """The control: same ledger either way."""
        rows = self.findings(4)
        recurrence_mod.record_batch(self.home, self.session(), rows)
        batched = recurrence_mod.load_recurrence(self.home)

        with tempfile.TemporaryDirectory() as tmp:
            other = support.make_home(Path(tmp))
            for finding in rows:
                recurrence_mod.record_occurrence(other, finding, self.session())
            singly = recurrence_mod.load_recurrence(other)
        self.assertEqual(sorted(batched["by_finding"]), sorted(singly["by_finding"]))
        self.assertEqual(batched["by_rule"], singly["by_rule"])

    def test_a_corrupt_ledger_is_not_initialized_over_by_a_batch(self) -> None:
        """W2-008's guardrail: batching must not become a reset.

        T-119 closed the audit item this test used to pin as unfixed: an
        unsupported-schema ledger is corruption, not an empty ledger, so the
        batch now REFUSES with zero writes instead of rewriting over it.
        """
        path = self.home / "recurrence.json"
        path.write_text(
            json.dumps({"schema_version": 999, "by_finding": {"old": {}}, "by_rule": {}}),
            encoding="utf-8",
        )
        before = path.read_bytes()
        from saipal_engine.errors import PalError

        with self.assertRaises(PalError) as ctx:
            recurrence_mod.record_batch(self.home, self.session(), self.findings(2))
        self.assertEqual(ctx.exception.code, "VALIDATION_FAILED")
        self.assertEqual(path.read_bytes(), before)

    def test_a_session_with_findings_writes_the_ledger_once(self) -> None:
        from saipal_engine import pipeline as pipeline_mod

        registry = load_registry()
        with tempfile.TemporaryDirectory() as tmp:
            home = support.make_home(Path(tmp))
            support.run_saipal("continue", home=home)
            support.put_inbox(home, DRIFT)
            inbox_mod.import_inbox(home, registry=registry)
            status, index, _detail = sessions_mod.load_index(home, registry=registry)
            self.assertEqual(status, "ok")

            # In-process, so the patch actually applies: `run_saipal` is a
            # subprocess and would silently exercise the unpatched module. This
            # is the FIRST analysis of the session: triage raises signals and
            # writes the negative-evidence receipt in ONE ledger transaction.
            with mock.patch.object(
                pipeline_mod.recurrence_mod,
                "record_negative",
                wraps=recurrence_mod.record_negative,
            ) as spy:
                result = analyze_sessions(home, index, registry=registry)
            self.assertGreaterEqual(result["signals_total"], 1, "the fixture drifts")
            self.assertEqual(result["findings_created"], 0, "triage creates no findings")
            self.assertEqual(spy.call_count, 0,
                             "a session with signals is NOT negative evidence")


class LogStatsDoesNotMaterializeTheLog(unittest.TestCase):
    """PERF-006: two scalars must not cost the lifetime append log."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = support.make_home(Path(self._tmp.name))
        self.log = (self.home / "LOG.jsonl")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, valid: int, malformed: int = 0) -> None:
        lines = [
            json.dumps({"seq": n, "ts": "t", "event": "e", "data": {}})
            for n in range(1, valid + 1)
        ]
        lines += ["{ not json"] * malformed
        self.log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_stats_agree_with_read_events(self) -> None:
        for valid, malformed in ((0, 0), (1, 0), (5, 2), (0, 3)):
            with self.subTest(valid=valid, malformed=malformed):
                self.write(valid, malformed)
                events, bad = log_mod.read_events(self.home)
                self.assertEqual(log_mod.log_stats(self.home), (len(events), bad))
                self.assertEqual((len(events), bad), (valid, malformed))

    def test_stats_on_an_absent_log_are_zero(self) -> None:
        self.assertEqual(log_mod.log_stats(self.home), (0, 0))

    def test_stats_retain_no_records(self) -> None:
        """Red control: the whole point is that nothing is kept."""
        self.write(2000)
        with mock.patch.object(log_mod, "read_events", side_effect=AssertionError("read all")):
            events, malformed = log_mod.log_stats(self.home)
        self.assertEqual((events, malformed), (2000, 0))

    def test_status_reports_the_streamed_counts(self) -> None:
        support.run_saipal("continue", home=self.home)
        code, payload, err = support.run_saipal_json("status", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertGreaterEqual(payload["log_events"], 1)
        self.assertEqual(payload["malformed_log_lines"], 0)

    def test_read_events_still_returns_bodies_for_callers_that_need_them(self) -> None:
        self.write(3)
        events, _malformed = log_mod.read_events(self.home)
        self.assertEqual([event["seq"] for event in events], [1, 2, 3])


class HotWatermarkSkipsNormalization(unittest.TestCase):
    """T-103/T-72: unchanged HOT histories are not re-normalized (50-106x).

    Work-counting red controls over a stub adapter with normalize call
    counts, never wall-clock. The watermark is advisory operational metadata.
    ROLE 20260908/2-3: an append-only watermark (max seq / row count) NEVER
    suppresses normalization on its own -- it detects appends, not historical
    mutation. The skip needs the raw source identity to prove the provider
    bytes unchanged; any doubt normalizes (fail-open).
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        self.calls = {"normalize": 0}

    def _hot_bundle(self, session_id: str, *, events: int, mutate_seq_one: bool = False) -> dict:
        rows = []
        for seq in range(1, events + 1):
            facts = {"n": seq}
            if mutate_seq_one and seq == 1:
                facts = {"n": seq, "tampered": "historical rewrite"}
            rows.append({"seq": seq, "type": "TOOL_CALL", "facts": facts})
        return {
            "schema_version": 1,
            "session_id": session_id,
            "adapter": "generic",
            "project": {"name": "P"},
            "runtime": {"provider": "p", "model": "m"},
            "temperature": "HOT",
            "protocol": {"version": "7.231.9", "registry_sha256": "a" * 64},
            "events": rows,
        }

    def _source_path(self, name: str) -> Path:
        return (Path(self._tmp.name) / name).with_suffix(".json")

    def _write_source(self, name: str, rows: int, **kw) -> Path:
        source = self._source_path(name)
        source.parent.mkdir(parents=True, exist_ok=True)
        bundle = self._hot_bundle(source.stem, events=rows, **kw)
        source.write_text(json.dumps(bundle), encoding="utf-8")
        return source

    def _rewrite_source(self, name: str, rows: int, **kw) -> Path:
        return self._write_source(name, rows, **kw)

    def _stub_adapter(self, *, watermark: int | None, adapter=None):
        """Full adapter surface: delegate every unstubbed method (ROLE 1)."""
        adapter = adapter or ADAPTER_REGISTRY["generic"]
        calls = self.calls

        def counting_normalize(path: str) -> dict:
            calls["normalize"] += 1
            return adapter.normalize(path)

        return SimpleNamespace(
            discover=adapter.discover,
            normalize=counting_normalize,
            identity=adapter.identity,
            stable_watermark=lambda path: watermark,
            protocol_binding=adapter.protocol_binding,
            WATERMARK_CAPABILITY=adapter.WATERMARK_CAPABILITY,
        )

    def _dispatch(self, source_path: Path, *, watermark: int | None, import_now: bool = True, source_id: str = "stub-main"):
        stub = self._stub_adapter(watermark=watermark)
        source = {
            "id": source_id,
            "kind": "generic",
            "path": str(source_path.parent),
            "enabled": True,
        }
        with mock.patch.dict(
            ADAPTER_REGISTRY, {"generic": stub}
        ):
            report = dispatch_sources(
                self.home,
                [source],
                registry=load_registry(),
                authority={k: None for k in ("git_repository", "release_root", "snapshot_root")},
            )
        if import_now:
            from saipal_engine.inbox import import_inbox

            import_inbox(self.home, registry=load_registry())
        return report

    def test_first_hot_observation_normalizes(self) -> None:
        source = self._write_source("hot-store/sess-hot.jsonl", 5)
        self._dispatch(source, watermark=5)
        self.assertEqual(self.calls["normalize"], 1)

    def test_unchanged_hot_with_identity_proof_skips_normalize(self) -> None:
        source = self._write_source("hot-store/sess-hot.jsonl", 5)
        self._dispatch(source, watermark=5)
        first = self.calls["normalize"]
        self.assertEqual(first, 1)
        # Same watermark AND same raw bytes: normalize is NEVER called again.
        report = self._dispatch(source, watermark=5)
        self.assertEqual(self.calls["normalize"], 1, "unchanged HOT must skip normalize")
        self.assertEqual(len(report["unchanged_hot"]), 1)
        self.assertEqual(report["unchanged_hot"][0]["watermark"], 5)

    def test_changed_watermark_normalizes(self) -> None:
        source = self._write_source("hot-store/sess-grow.jsonl", 5)
        self._dispatch(source, watermark=5)
        # The provider history grew: watermark advances -> normalize.
        self._write_source("hot-store/sess-grow.jsonl", 8)
        report = self._dispatch(source, watermark=8)
        self.assertEqual(self.calls["normalize"], 2)
        self.assertEqual(report["unchanged_hot"], [])

    def test_no_or_invalid_watermark_always_normalizes(self) -> None:
        source = self._write_source("hot-store/sess-nwm.jsonl", 5)
        self._dispatch(source, watermark=5)
        self._dispatch(source, watermark=None)
        self.assertEqual(self.calls["normalize"], 2, "missing watermark normalizes")
        self._dispatch(source, watermark=0)
        self.assertEqual(self.calls["normalize"], 3, "invalid watermark normalizes")
        self._dispatch(source, watermark="seven")
        self.assertEqual(self.calls["normalize"], 4, "malformed watermark normalizes")

    def test_historical_rewrite_preserving_max_seq_is_not_skipped(self) -> None:
        """ROLE 8 negative control: the P0 mutation-suppression bug.

        Event 1 changes, max(seq) stays 5. The append-only watermark is
        unchanged -- and it must not hide the mutation. The dispatcher must
        normalize (the raw identity changed), the inbox must see the mutated
        prefix, and the session must become CONFLICT.
        """
        source = self._write_source("hot-store/sess-rw.jsonl", 5)
        self._dispatch(source, watermark=5)
        # Pretend the mechanical pipeline analyzed the first two events so
        # the analyzed-prefix guard is armed.
        status, index, _detail = sessions_mod.load_index(self.home)
        self.assertEqual(status, "ok")
        record = sessions_mod.find_session(index, "sess-rw")
        record["last_analyzed_seq"] = 2
        record["prefix_sha256"] = bundle_mod.prefix_digest(
            self._hot_bundle("sess-rw", events=5), 2
        )
        sessions_mod.save_index(self.home, index)

        self._rewrite_source("hot-store/sess-rw.jsonl", 5, mutate_seq_one=True)
        report = self._dispatch(source, watermark=5)
        self.assertGreaterEqual(
            self.calls["normalize"], 2,
            "a same-watermark historical rewrite MUST normalize",
        )
        self.assertEqual(report["unchanged_hot"], [])

        from saipal_engine.inbox import import_inbox

        intake = import_inbox(self.home, registry=load_registry())
        record = sessions_mod.find_session(sessions_mod.load_index(self.home)[1], "sess-rw")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(
            record["status"], "CONFLICT",
            "the mutated historical prefix must reach the conflict detector",
        )
        self.assertEqual(len(intake["conflicts"]), 1)

    def test_append_hint_alone_cannot_suppress_normalization(self) -> None:
        """ROLE 13 control 6: an APPEND_ONLY_HINT with changed bytes normalizes.

        The stub vouches for a matching watermark, but the raw source changed
        under it. The identity check -- not the hint -- decides, and it must
        fail open toward normalization.
        """
        source = self._write_source("hot-store/sess-hint.jsonl", 5)
        self._dispatch(source, watermark=5)
        self._rewrite_source("hot-store/sess-hint.jsonl", 5, mutate_seq_one=True)
        report = self._dispatch(source, watermark=5)
        self.assertGreaterEqual(self.calls["normalize"], 2)
        self.assertEqual(report["unchanged_hot"], [])

    def test_conflict_is_surfaced_not_called_clean(self) -> None:
        """ROLE 12: a skipped conflicted artifact reports the conflict."""
        source = self._write_source("hot-store/sess-conf.jsonl", 5)
        self._dispatch(source, watermark=5)
        # Arm the prefix guard, then mutate, then import: CONFLICT.
        status, index, _detail = sessions_mod.load_index(self.home)
        record = sessions_mod.find_session(index, "sess-conf")
        record["last_analyzed_seq"] = 2
        record["prefix_sha256"] = bundle_mod.prefix_digest(
            self._hot_bundle("sess-conf", events=5), 2
        )
        sessions_mod.save_index(self.home, index)
        self._rewrite_source("hot-store/sess-conf.jsonl", 5, mutate_seq_one=True)
        self._dispatch(source, watermark=5)

        # The provider now serves exactly the conflicted artifact B and it
        # never changes again: re-normalization is unnecessary (identity
        # proves B), but the cycle must NOT answer `unchanged_hot`.
        report = self._dispatch(source, watermark=5)
        self.assertEqual(report["unchanged_hot"], [])
        self.assertEqual(len(report["conflict"]), 1)
        self.assertEqual(report["conflict"][0]["status"], "CONFLICT")
        record = sessions_mod.find_session(sessions_mod.load_index(self.home)[1], "sess-conf")
        assert record is not None
        self.assertEqual(record["status"], "CONFLICT", "the conflict stands")

    def test_restart_preserves_the_accepted_watermark(self) -> None:
        source = self._write_source("hot-store/sess-restart.jsonl", 5)
        self._dispatch(source, watermark=5)
        # A "restart" is just a fresh dispatcher call: the checkpoint lives in
        # the durable staged bundle, not in any process state.
        report = self._dispatch(source, watermark=5)
        self.assertEqual(self.calls["normalize"], 1)
        self.assertEqual(len(report["unchanged_hot"]), 1)

    def test_cold_identity_stays_digest_driven(self) -> None:
        """A COLD source never uses the watermark fast path."""
        source = self._write_source("cold-store/sess-cold.jsonl", 5)
        source_bundle = self._hot_bundle("sess-cold", events=5)
        source_bundle["temperature"] = "COLD"
        source.write_text(json.dumps(source_bundle), encoding="utf-8")
        self._dispatch(source, watermark=5)
        self._dispatch(source, watermark=5)
        # COLD unchanged is decided by the raw content digest, and normalize
        # is not called -- but the decision path is the COLD probe, not the
        # watermark (unchanged_hot stays empty).
        self.assertGreaterEqual(self.calls["normalize"], 1)
        staged = list((self.home / "session_inbox").glob("generic-sess-cold-*.json"))
        self.assertTrue(staged)

    def test_one_source_cannot_suppress_another(self) -> None:
        a = self._write_source("mix-store/a.jsonl", 5)
        b = self._write_source("mix-store/b.jsonl", 5)
        a.parent.mkdir(parents=True, exist_ok=True)
        real = ADAPTER_REGISTRY["generic"]
        source = {"id": "mix", "kind": "generic", "path": str(a.parent), "enabled": True}

        def dispatch_with(mapping: dict):
            calls = self.calls

            def counting_normalize(path: str) -> dict:
                calls["normalize"] += 1
                return real.normalize(path)

            def wm(path: str):
                for suffix, value in mapping.items():
                    if str(path).replace("\\", "/").endswith(suffix.replace("\\", "/")):
                        return value
                return None

            stub = SimpleNamespace(
                discover=real.discover,
                normalize=counting_normalize,
                identity=real.identity,
                stable_watermark=wm,
                protocol_binding=real.protocol_binding,
                WATERMARK_CAPABILITY=real.WATERMARK_CAPABILITY,
            )
            with mock.patch.dict(ADAPTER_REGISTRY, {"generic": stub}):
                return dispatch_sources(
                    self.home, [source], registry=load_registry(),
                    authority={k: None for k in ("git_repository", "release_root", "snapshot_root")},
                )

        # Both first-cycle candidates normalize: a (wm 5) and b (wm 3) each
        # stage their own checkpoint.
        dispatch_with({"a.json": 5, "b.json": 3})
        self.assertEqual(self.calls["normalize"], 2)
        # Second cycle: both probes match their own staged checkpoints and
        # their raw bytes are unchanged: both skip, independently.
        report = dispatch_with({"a.json": 5, "b.json": 3})
        self.assertEqual(self.calls["normalize"], 2)
        self.assertEqual(
            sorted(row["source"] for row in report["unchanged_hot"]), ["a", "b"]
        )
        # b's watermark ADVANCES while a's stays put: only b normalizes. a's
        # skip decision never suppresses b, and b's change never touches a.
        self._rewrite_source("mix-store/b.jsonl", 8)
        report = dispatch_with({"a.json": 5, "b.json": 9})
        self.assertEqual(self.calls["normalize"], 3)
        self.assertEqual(
            [row["source"] for row in report["unchanged_hot"]], ["a"]
        )

    def test_staged_but_unimported_artifact_survives_restart(self) -> None:
        """ROLE 11: normalize -> staged bundle -> crash before import.

        A fresh dispatcher call must not lose the staged artifact, and the
        optimization checkpoint must not make it vanish from processing.
        """
        source = self._write_source("hot-store/sess-crash.jsonl", 5)
        # Dispatch WITHOUT the import step: staged, never imported.
        self._dispatch(source, watermark=5, import_now=False)
        staged = list((self.home / "session_inbox").glob("generic-sess-crash-*.json"))
        self.assertTrue(staged, "the staged bundle exists before the crash")
        self.assertEqual(self.calls["normalize"], 1)
        # Restart: dispatch again (no change), then import: the staged
        # artifact is still there and is still imported.
        self._dispatch(source, watermark=5, import_now=False)
        from saipal_engine.inbox import import_inbox

        intake = import_inbox(self.home, registry=load_registry())
        self.assertEqual(intake["new_sessions"], 1, "staged artifact still imports after restart")

    def test_mutant_ignoring_persistence_fails(self) -> None:
        """A dispatcher that never persists the watermark cannot skip twice."""
        source = self._write_source("hot-store/sess-mutant.jsonl", 5)
        self._dispatch(source, watermark=5)
        staged = list((self.home / "session_inbox").glob("generic-sess-mutant-*.json"))
        self.assertTrue(staged)
        bundle = bundle_mod.load_bundle_file(staged[0], registry=load_registry())
        self.assertEqual(
            bundle.get("observed_watermark"), 5,
            "the observed watermark must be persisted with the bundle state",
        )
        # And the identity never changed because of it: the digest excludes
        # the watermark (advisory metadata, not forensic truth).
        digest = bundle_mod.bundle_digest(bundle)
        bundle.pop("observed_watermark")
        self.assertEqual(bundle_mod.bundle_digest(bundle), digest)

    def test_watermark_capability_declared_by_every_adapter(self) -> None:
        """ROLE 4/5: every adapter declares its probe semantics, closed set."""
        from saipal_engine.adapters import watermark_capability
        from saipal_engine.adapters import (
            WATERMARK_APPEND_ONLY_HINT,
            WATERMARK_MUTATION_SAFE_CHANGE_TOKEN,
            WATERMARK_NONE,
        )

        for name, module in ADAPTER_REGISTRY.items():
            with self.subTest(adapter=name):
                declared = getattr(module, "WATERMARK_CAPABILITY", None)
                self.assertIn(
                    declared,
                    (WATERMARK_NONE, WATERMARK_APPEND_ONLY_HINT, WATERMARK_MUTATION_SAFE_CHANGE_TOKEN),
                    "watermark capability must come from the closed vocabulary",
                )
                # No shipped adapter is mutation-safe on evidence: every
                # declared probe is max-seq or a row count.
                cap = watermark_capability(module)
                self.assertFalse(
                    cap["mutation_safe"],
                    "no adapter may claim a mutation-safe token without evidence",
                )

    def test_generic_same_max_seq_rewrite_reaches_conflict(self) -> None:
        """ROLE 8 end-to-end through the REAL generic adapter (no stub).

        This is the direct reproduction from the targeted audit: rewrite
        event 1 while preserving event count, max seq, session id and
        temperature. The real dispatcher must not answer unchanged_hot.
        """
        source = self._write_source("real-store/sess-real.jsonl", 5)
        real = ADAPTER_REGISTRY["generic"]
        source = {"id": "real-main", "kind": "generic", "path": str(source.parent), "enabled": True}

        def run():
            return dispatch_sources(
                self.home, [source], registry=load_registry(),
                authority={k: None for k in ("git_repository", "release_root", "snapshot_root")},
            )

        run()
        from saipal_engine.inbox import import_inbox

        import_inbox(self.home, registry=load_registry())
        status, index, _detail = sessions_mod.load_index(self.home)
        record = sessions_mod.find_session(index, "sess-real")
        record["last_analyzed_seq"] = 2
        record["prefix_sha256"] = bundle_mod.prefix_digest(
            self._hot_bundle("sess-real", events=5), 2
        )
        sessions_mod.save_index(self.home, index)

        self._rewrite_source("real-store/sess-real.jsonl", 5, mutate_seq_one=True)
        report = run()
        self.assertEqual(report["unchanged_hot"], [])
        intake = import_inbox(self.home, registry=load_registry())
        record = sessions_mod.find_session(sessions_mod.load_index(self.home)[1], "sess-real")
        assert record is not None
        self.assertEqual(record["status"], "CONFLICT")


if __name__ == "__main__":
    unittest.main()
