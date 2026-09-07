"""T-064 / audits CORE-003 + CORE-004: budget accounting, resume, and lease safety.

Two defects in one pass over `analyze_sessions`:

CORE-003 -- the event budget was charged only on the candidate-producing path, so
a conformant session cost nothing and could not be bounded; the persisted
`next_episode_index` was written but never read, so every budget-limited cycle
reprocessed episode 0 forever; `episodes_exhausted` came from a global
`budget_hit`; and a tripped budget did not end the cycle, so later sessions were
counted and rewritten from a budget already spent.

CORE-004 -- `SessionLease` built its filename from the raw session id, so a
schema-valid bundle whose id contained a path separator crashed the primary
analysis path, and several post-acquire exits leaked the lease.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pal_test_support as support
from saipal_engine import hardening as hard
from saipal_engine import pipeline as pipeline_mod
from saipal_engine import sessions as sessions_mod
from saipal_engine.pipeline import analyze_sessions
from saipal_engine.registry import load_registry

COLD = "conformant-cold.json"
DRIFT = "agent-noncompliance-command-route.json"

#: Episodes per synthetic fixture, and the event span they cover.
EPISODES = 6
SPAN = EPISODES + 1


def cold_bundle(session_id: str, *, episodes: int = EPISODES) -> dict:
    """A COLD bundle of exactly `episodes` episodes.

    `USER_MESSAGE` opens an episode, so N of them is N episodes -- the shape
    budget accounting has to be measured against. The trailing
    `ASSISTANT_MESSAGE` is deliberate: it keeps the last event off a boundary, so
    this fixture does not also depend on T-71 (a session ending ON a boundary
    currently loses that final event, which is a separate defect).
    """
    events = [
        {"seq": index, "type": "USER_MESSAGE", "facts": {"task": f"step {index}"}}
        for index in range(1, episodes + 1)
    ]
    events.append(
        {"seq": episodes + 1, "type": "ASSISTANT_MESSAGE", "facts": {"reply": "done"}}
    )
    return {
        "schema_version": 1,
        "session_id": session_id,
        "adapter": "generic",
        "project": {"name": "BudgetProject"},
        "runtime": {"provider": "p", "model": "m"},
        "temperature": "COLD",
        "protocol": {"version": "7.231.9", "registry_sha256": "a" * 64},
        "events": events,
    }


class LeaseFilenameIsSafe(unittest.TestCase):
    """A session id is external data, never a path (audit CORE-004)."""

    HOSTILE = (
        "foo/bar",
        "back\\slash",
        "drive:colon",
        "trailing.dot.",
        "with spaces",
        "ünïcödé-ідентифікатор",
        "CON",
        "a" * 400,
        "../escape",
    )

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        self.locks = self.home / "locks"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_a_hostile_id_yields_one_flat_lease_file(self) -> None:
        for session_id in self.HOSTILE:
            with self.subTest(session_id=session_id):
                lease = hard.SessionLease(self.home, session_id)
                self.assertEqual(
                    lease.path.parent, self.locks, "the lease must not alter the tree"
                )
                self.assertTrue(lease.acquire(), f"cannot lease {session_id!r}")
                try:
                    self.assertTrue(lease.path.is_file())
                finally:
                    lease.release()

    def test_a_hostile_id_creates_no_subdirectory(self) -> None:
        lease = hard.SessionLease(self.home, "foo/bar/baz")
        self.assertTrue(lease.acquire())
        try:
            self.assertEqual(
                [p for p in self.locks.iterdir() if p.is_dir()],
                [],
                "a session id must never become directory structure",
            )
        finally:
            lease.release()

    def test_distinct_ids_never_share_a_lease_file(self) -> None:
        seen = {hard.SessionLease(self.home, sid).path for sid in self.HOSTILE}
        self.assertEqual(len(seen), len(self.HOSTILE))

    def test_ids_differing_only_in_case_do_not_alias(self) -> None:
        """Windows filenames are case-insensitive; session ids are not."""
        lower = hard.SessionLease(self.home, "session-a")
        upper = hard.SessionLease(self.home, "SESSION-A")
        self.assertNotEqual(lower.path, upper.path)
        self.assertTrue(lower.acquire())
        try:
            self.assertTrue(upper.acquire(), "two distinct ids must not contend")
            upper.release()
        finally:
            lower.release()

    def test_the_lease_name_is_deterministic(self) -> None:
        first = hard.SessionLease(self.home, "stable-id").path
        second = hard.SessionLease(self.home, "stable-id").path
        self.assertEqual(first, second)

    def test_the_raw_id_is_not_in_the_filename(self) -> None:
        lease = hard.SessionLease(self.home, "foo/bar")
        self.assertNotIn("foo", lease.path.name)
        self.assertEqual(lease.session_id, "foo/bar", "diagnostics keep the real id")

    def test_a_hostile_id_survives_the_whole_analysis_path(self) -> None:
        """The audit's reproduction: import then analyze, with `foo/bar`."""
        support.write_inbox(self.home, "hostile.json", cold_bundle("foo/bar"))
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["intake"]["new_sessions"], 1)
        record = [
            r for r in support.sessions_of(self.home) if r["session_id"] == "foo/bar"
        ][0]
        self.assertTrue(
            record.get("analysis", {}).get("episodes_exhausted"),
            "the hostile-id session must actually have been analyzed",
        )


class LeaseLifetime(unittest.TestCase):
    """Every exit from a held-lease region releases exactly once."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def leases(self) -> list[Path]:
        locks = self.home / "locks"
        return sorted(p for p in locks.iterdir() if p.name.startswith("lease-"))

    def _import_then_break_bundle(self) -> dict:
        support.put_inbox(self.home, COLD)
        support.run_saipal("continue", home=self.home)
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        self.assertEqual(status, "ok")
        for record in index["sessions"]:
            record.pop("analysis", None)
            record["last_analyzed_seq"] = 0
        sessions_mod.save_index(self.home, index, registry=self.registry)
        return index

    def test_a_missing_bundle_releases_the_lease(self) -> None:
        """The audit's leak: `continue` on a vanished bundle kept the lease."""
        index = self._import_then_break_bundle()
        (self.home / "session_inbox" / COLD).unlink()
        result = analyze_sessions(self.home, index, registry=self.registry)
        self.assertEqual(result["sessions_analyzed"], 0)
        self.assertEqual(self.leases(), [], "a skipped session must not hold a lease")

    def test_an_unreadable_bundle_releases_the_lease(self) -> None:
        index = self._import_then_break_bundle()
        (self.home / "session_inbox" / COLD).write_text("{ not json", encoding="utf-8")
        result = analyze_sessions(self.home, index, registry=self.registry)
        self.assertEqual(result["sessions_analyzed"], 0)
        self.assertEqual(self.leases(), [])

    def test_a_normal_pass_releases_the_lease(self) -> None:
        index = self._import_then_break_bundle()
        analyze_sessions(self.home, index, registry=self.registry)
        self.assertEqual(self.leases(), [])

    def test_an_exception_mid_analysis_still_releases_the_lease(self) -> None:
        """Red control: no `finally`, and a raise strands the session forever."""
        index = self._import_then_break_bundle()
        with mock.patch.object(
            pipeline_mod, "_candidates_for_session", side_effect=RuntimeError("boom")
        ):
            with self.assertRaises(RuntimeError):
                analyze_sessions(self.home, index, registry=self.registry)
        self.assertEqual(self.leases(), [], "an exception must not leak a lease")

    def test_a_held_lease_makes_the_pass_skip_that_session(self) -> None:
        index = self._import_then_break_bundle()
        held = hard.SessionLease(self.home, "golden-cold-001")
        self.assertTrue(held.acquire())
        try:
            result = analyze_sessions(self.home, index, registry=self.registry)
            self.assertEqual(result["sessions_analyzed"], 0)
        finally:
            held.release()

    def test_the_lease_context_manager_releases_once(self) -> None:
        lease = hard.SessionLease(self.home, "ctx")
        self.assertTrue(lease.acquire())
        with lease:
            self.assertTrue(lease.held)
        self.assertFalse(lease.held)
        self.assertFalse(lease.path.exists())
        lease.release()  # idempotent


class BudgetChargesEveryAnalyzedEpisode(unittest.TestCase):
    """CORE-003: no-drift work is work, and it costs budget."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.write_inbox(self.home, "budget.json", cold_bundle("budget-001"))
        support.run_saipal("continue", home=self.home)
        self._reset_analysis()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _reset_analysis(self) -> None:
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        self.assertEqual(status, "ok")
        for record in index["sessions"]:
            record.pop("analysis", None)
            record["last_analyzed_seq"] = 0
        sessions_mod.save_index(self.home, index, registry=self.registry)

    def index(self) -> dict:
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        self.assertEqual(status, "ok")
        return index

    def record(self) -> dict:
        return [
            r for r in support.sessions_of(self.home) if r["session_id"] == "budget-001"
        ][0]

    def analysis(self) -> dict:
        return self.record().get("analysis") or {}

    def test_a_no_drift_session_charges_its_events(self) -> None:
        """Red control: this returned 0 before, so max_events bounded nothing."""
        result = analyze_sessions(self.home, self.index(), registry=self.registry)
        self.assertEqual(result["findings_created"], 0, "the fixture must be conformant")
        self.assertGreater(
            result["events_analyzed"], 0, "analyzed evidence must cost budget"
        )

    def test_events_analyzed_equals_the_telemetry_delta(self) -> None:
        before = hard.load_telemetry(self.home).get("events_analyzed", 0)
        result = analyze_sessions(self.home, self.index(), registry=self.registry)
        after = hard.load_telemetry(self.home).get("events_analyzed", 0)
        self.assertEqual(result["events_analyzed"], after - before)

    def test_a_tight_budget_stops_after_one_episode(self) -> None:
        budget = hard.Budget(max_events=1)
        result = analyze_sessions(
            self.home, self.index(), registry=self.registry, budget=budget
        )
        self.assertEqual(result["events_analyzed"], 1)
        self.assertEqual(self.analysis()["next_episode_index"], 1)
        self.assertFalse(self.analysis()["episodes_exhausted"])

    def test_repeated_tight_cycles_advance_monotonically(self) -> None:
        """The defect in one loop: the cursor used to be pinned at 1 forever."""
        budget = hard.Budget(max_events=1)
        seen = []
        for _ in range(8):
            analyze_sessions(
                self.home, self.index(), registry=self.registry, budget=budget
            )
            seen.append(
                (
                    self.analysis()["next_episode_index"],
                    self.analysis()["analyzed_up_to_seq"],
                )
            )
            if self.analysis()["episodes_exhausted"]:
                break
        cursors = [c for c, _seq in seen]
        self.assertEqual(cursors, sorted(cursors), "the cursor must never go backwards")
        self.assertEqual(len(set(cursors)), len(cursors), "no cycle may repeat work")
        self.assertTrue(self.analysis()["episodes_exhausted"])
        self.assertEqual(self.analysis()["next_episode_index"], EPISODES)

    def test_the_total_charge_across_cycles_equals_the_span(self) -> None:
        budget = hard.Budget(max_events=1)
        charged = 0
        for _ in range(10):
            result = analyze_sessions(
                self.home, self.index(), registry=self.registry, budget=budget
            )
            charged += result["events_analyzed"]
            if self.analysis()["episodes_exhausted"]:
                break
        self.assertEqual(
            charged, SPAN, "every event of the span is charged exactly once"
        )

    def test_an_exhausted_session_is_not_re_analyzed(self) -> None:
        analyze_sessions(self.home, self.index(), registry=self.registry)
        second = analyze_sessions(self.home, self.index(), registry=self.registry)
        self.assertEqual(second["sessions_analyzed"], 0)
        self.assertEqual(second["events_analyzed"], 0)

    def test_a_full_budget_exhausts_the_session_in_one_cycle(self) -> None:
        result = analyze_sessions(self.home, self.index(), registry=self.registry)
        self.assertEqual(result["sessions_analyzed"], 1)
        self.assertTrue(self.analysis()["episodes_exhausted"])
        self.assertEqual(self.analysis()["next_episode_index"], EPISODES)

    def test_an_episode_bigger_than_the_whole_budget_still_runs(self) -> None:
        """Otherwise it starves: every later cycle makes the same refusal."""
        # A home of its own: with the shared home's session still pending, the
        # budget would trip on THAT session and never reach this one.
        home = support.make_home(self.tmp, ".saipal-big")
        support.run_saipal("continue", home=home)
        big = cold_bundle("big-001", episodes=1)
        big["events"] += [
            {"seq": seq, "type": "TOOL_CALL", "facts": {"n": seq}}
            for seq in range(3, 40)
        ]
        support.write_inbox(home, "big.json", big)
        support.run_saipal("continue", home=home)
        status, index, _detail = sessions_mod.load_index(home, registry=self.registry)
        self.assertEqual(status, "ok")
        for record in index["sessions"]:
            record.pop("analysis", None)
            record["last_analyzed_seq"] = 0
        sessions_mod.save_index(home, index, registry=self.registry)

        status, index, _detail = sessions_mod.load_index(home, registry=self.registry)
        result = analyze_sessions(
            home, index, registry=self.registry, budget=hard.Budget(max_events=1)
        )
        self.assertGreater(
            result["events_analyzed"], 1, "an oversized episode must not starve"
        )
        big_record = [
            r for r in support.sessions_of(home) if r["session_id"] == "big-001"
        ][0]
        self.assertTrue(big_record["analysis"]["episodes_exhausted"])

    def test_a_corrupt_cursor_does_not_skip_the_tail(self) -> None:
        index = self.index()
        for record in index["sessions"]:
            record["analysis"] = {
                "episodes_exhausted": False,
                "last_analyzed_at": None,
                "analyzed_up_to_seq": 0,
                "next_episode_index": "soon",
            }
        sessions_mod.save_index(self.home, index, registry=self.registry)
        result = analyze_sessions(self.home, self.index(), registry=self.registry)
        self.assertEqual(
            result["events_analyzed"], SPAN, "a malformed cursor restarts safely"
        )

    def test_a_partial_cycle_does_not_vote_the_session_clean(self) -> None:
        """Red control: "no finding yet" is not "no finding in this session".

        Negative evidence feeds the recurrence ledger's conformance rates, so a
        budget-limited pass recording it would let a cycle vote clean on episodes
        it never read.
        """
        from saipal_engine import recurrence as recurrence_mod

        # setUp's `continue` already analyzed this session once, so the ledger
        # holds its verdict. Clear it: the baseline this test needs is "no
        # conformance verdict recorded yet".
        (self.home / "recurrence.json").unlink(missing_ok=True)

        analyze_sessions(
            self.home, self.index(), registry=self.registry, budget=hard.Budget(max_events=1)
        )
        self.assertFalse(self.analysis()["episodes_exhausted"], "precondition: partial")
        partial = recurrence_mod.load_recurrence(self.home)
        self.assertEqual(
            partial.get("by_finding") or {},
            {},
            "a partial pass must record no conformance verdict",
        )

        for _ in range(10):
            analyze_sessions(self.home, self.index(), registry=self.registry)
            if self.analysis()["episodes_exhausted"]:
                break
        finished = recurrence_mod.load_recurrence(self.home)
        self.assertTrue(
            finished.get("by_finding"),
            "a finished conformant session IS negative evidence",
        )

    def test_a_cursor_past_the_end_closes_the_record(self) -> None:
        index = self.index()
        for record in index["sessions"]:
            record["analysis"] = {
                "episodes_exhausted": False,
                "last_analyzed_at": None,
                "analyzed_up_to_seq": 0,
                "next_episode_index": 9999,
            }
        sessions_mod.save_index(self.home, index, registry=self.registry)
        result = analyze_sessions(self.home, self.index(), registry=self.registry)
        self.assertEqual(result["events_analyzed"], 0)
        self.assertTrue(self.analysis()["episodes_exhausted"])

    def test_exhaustion_is_the_records_own_cursor_not_the_cycle_budget(self) -> None:
        """Red control: a finished record must not be reopened by a spent budget.

        `episodes_exhausted: not budget_hit` conflates two different facts. Here a
        one-episode session is fully analyzed AND the cycle budget trips on the
        same pass, so the two disagree: the record is complete, the cycle is not.
        Deriving the flag from the cycle would re-analyze finished evidence on
        every later cycle (audit CORE-003).
        """
        home = support.make_home(self.tmp, ".saipal-onecycle")
        support.run_saipal("continue", home=home)
        support.write_inbox(home, "one.json", cold_bundle("one-001", episodes=1))
        support.run_saipal("continue", home=home)
        status, index, _detail = sessions_mod.load_index(home, registry=self.registry)
        self.assertEqual(status, "ok")
        for record in index["sessions"]:
            record.pop("analysis", None)
            record["last_analyzed_seq"] = 0
        sessions_mod.save_index(home, index, registry=self.registry)

        # max_audits=0 trips the per-cycle valve on the first episode, whatever
        # that episode produced -- so budget_hit is True while the record's own
        # cursor has reached its end.
        status, index, _detail = sessions_mod.load_index(home, registry=self.registry)
        analyze_sessions(
            home, index, registry=self.registry, budget=hard.Budget(max_audits=0)
        )
        record = [r for r in support.sessions_of(home) if r["session_id"] == "one-001"][0]
        self.assertEqual(record["analysis"]["next_episode_index"], 1)
        self.assertTrue(
            record["analysis"]["episodes_exhausted"],
            "a record whose every episode was analyzed is exhausted, budget or not",
        )

        status, index, _detail = sessions_mod.load_index(home, registry=self.registry)
        second = analyze_sessions(home, index, registry=self.registry)
        self.assertEqual(
            second["events_analyzed"], 0, "finished evidence must not be re-analyzed"
        )


class ABudgetHitEndsTheCycle(unittest.TestCase):
    """A spent budget must not reach into a session it never analyzed."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.write_inbox(self.home, "a.json", cold_bundle("session-A"))
        support.write_inbox(self.home, "b.json", cold_bundle("session-B"))
        support.run_saipal("continue", home=self.home)
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        self.assertEqual(status, "ok")
        for record in index["sessions"]:
            record.pop("analysis", None)
            record["last_analyzed_seq"] = 0
        sessions_mod.save_index(self.home, index, registry=self.registry)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def index(self) -> dict:
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        self.assertEqual(status, "ok")
        return index

    def records(self) -> dict[str, dict]:
        return {r["session_id"]: r for r in support.sessions_of(self.home)}

    def test_only_one_session_is_counted_when_the_budget_trips(self) -> None:
        result = analyze_sessions(
            self.home, self.index(), registry=self.registry, budget=hard.Budget(max_events=1)
        )
        self.assertEqual(result["sessions_analyzed"], 1)

    def test_the_untouched_session_keeps_no_analysis_block(self) -> None:
        """Red control: it used to be entered and rewritten from a spent budget."""
        analyze_sessions(
            self.home, self.index(), registry=self.registry, budget=hard.Budget(max_events=1)
        )
        records = self.records()
        touched = [sid for sid, r in records.items() if r.get("analysis")]
        self.assertEqual(len(touched), 1, f"exactly one session may be touched: {touched}")
        untouched = next(sid for sid in records if sid not in touched)
        self.assertIsNone(records[untouched].get("analysis"))
        self.assertEqual(records[untouched]["last_analyzed_seq"], 0)

    def test_the_next_cycle_picks_up_the_untouched_session(self) -> None:
        for _ in range(20):
            analyze_sessions(
                self.home,
                self.index(),
                registry=self.registry,
                budget=hard.Budget(max_events=1),
            )
            records = self.records()
            if all(
                (r.get("analysis") or {}).get("episodes_exhausted") for r in records.values()
            ):
                break
        for session_id, record in self.records().items():
            self.assertTrue(
                record["analysis"]["episodes_exhausted"], f"{session_id} never finished"
            )

    def test_a_generous_budget_still_analyzes_both(self) -> None:
        result = analyze_sessions(self.home, self.index(), registry=self.registry)
        self.assertEqual(result["sessions_analyzed"], 2)
        self.assertEqual(result["events_analyzed"], 2 * SPAN)


class BudgetArithmetic(unittest.TestCase):
    """The two helpers everything above rests on."""

    def test_room_for_one_more_episode(self) -> None:
        budget = hard.Budget(max_events=10)
        started = pipeline_mod.time.monotonic()
        self.assertFalse(pipeline_mod._budget_exhausted(budget, 0, started, 3))
        self.assertFalse(pipeline_mod._budget_exhausted(budget, 7, started, 3))
        self.assertTrue(pipeline_mod._budget_exhausted(budget, 8, started, 3))

    def test_the_first_episode_is_never_refused(self) -> None:
        budget = hard.Budget(max_events=1)
        started = pipeline_mod.time.monotonic()
        self.assertFalse(pipeline_mod._budget_exhausted(budget, 0, started, 900))

    def test_an_expired_time_budget_stops_everything(self) -> None:
        budget = hard.Budget(max_events=1000, time_limit_seconds=0)
        started = pipeline_mod.time.monotonic()
        self.assertTrue(pipeline_mod._budget_exhausted(budget, 0, started, 1))

    def test_the_resume_cursor_is_clamped(self) -> None:
        self.assertEqual(pipeline_mod._resume_cursor({}, 6), 0)
        self.assertEqual(
            pipeline_mod._resume_cursor({"analysis": {"next_episode_index": 3}}, 6), 3
        )
        self.assertEqual(
            pipeline_mod._resume_cursor({"analysis": {"next_episode_index": 99}}, 6), 6
        )
        self.assertEqual(
            pipeline_mod._resume_cursor({"analysis": {"next_episode_index": -4}}, 6), 0
        )
        self.assertEqual(
            pipeline_mod._resume_cursor({"analysis": {"next_episode_index": "x"}}, 6), 0
        )


class DriftStillReachesAnAudit(unittest.TestCase):
    """The control for all of the above: real findings still reach an audit --
    through the sanctioned semantic path, never through triage."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_the_drift_fixture_still_emits_an_audit(self) -> None:
        support.put_inbox(self.home, DRIFT)
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["audits_emitted"], 0, "triage never emits")
        code, report, err = support.run_saipal_json("report", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(report["verdict"], "NOT_EXAMINED")
        support.submit_drift(self.home, support.next_unit(self.home))
        code, report, err = support.run_saipal_json("report", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(report["verdict"], "DRIFT_REPORTED")
        self.assertEqual(report["counts"]["emitted"], 1)


if __name__ == "__main__":
    unittest.main()
