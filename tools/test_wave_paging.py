"""T-68: carrier episode paging -- a long episode is judged in slices, not truncated.

`carrier_limits.max_events` is 200. A real 900-event episode used to be handed
over as its first 200 events with `events_truncated: true` and no way to ask for
the rest, so an honest analyst could only ever answer INSUFFICIENT_EVIDENCE about
it -- forever, because the position never moved past an episode it could not
finish reading.

The span is now handed over in consecutive bounded slices. Two properties carry
the weight: the slices COVER the span exactly (no skipped event, no overlap), and
an episode closes only when its LAST slice is judged.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import carrier as carrier_mod
from saipal_engine import coverage as coverage_mod
from saipal_engine import candidates as cand_mod
from saipal_engine import sessions as sessions_mod
from saipal_engine import submit as submit_mod
from saipal_engine.errors import PalError
from saipal_engine.registry import load_registry

#: Long enough that the old single-window carrier could show under a quarter of
#: it, and not a multiple of the limit, so the last slice is a short one.
LONG_SPAN = 900


def long_bundle(session_id: str = "paged-001", *, temperature: str = "COLD") -> dict:
    """One session whose whole span is a single episode of `LONG_SPAN` events.

    Only the opening event is a boundary, so the segmenter produces exactly one
    episode -- which is the case that made truncation fatal.
    """
    events = [
        {"seq": 1, "type": "USER_MESSAGE", "facts": {"task": "audit the protocol"}}
    ]
    events += [
        {"seq": seq, "type": "TOOL_CALL", "facts": {"tool": "bash", "n": seq}}
        for seq in range(2, LONG_SPAN + 1)
    ]
    return {
        "schema_version": 1,
        "session_id": session_id,
        "adapter": "generic",
        "project": {"name": "PagedProject"},
        "runtime": {"provider": "p", "model": "m"},
        "temperature": temperature,
        "protocol": {"version": "7.231.9", "registry_sha256": "a" * 64},
        "events": events,
    }


class PagedBase(unittest.TestCase):
    TEMPERATURE = "COLD"

    def setUp(self) -> None:
        self.registry = load_registry()
        self.limit = int(self.registry["carrier_limits"]["max_events"])
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.write_inbox(
            self.home, "paged.json", long_bundle(temperature=self.TEMPERATURE)
        )
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def carrier(self) -> dict:
        return carrier_mod.build_carrier(self.home, registry=self.registry)

    def record(self) -> dict:
        return support.sessions_of(self.home)[0]

    def index(self) -> dict | None:
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        return index if status == "ok" else None

    def no_drift(self, unit: dict, **overrides) -> dict:
        payload = {
            "schema_version": 1,
            "verdict": "NO_DRIFT",
            "unit_digest": unit["unit_digest"],
            "session_id": unit["session"]["session_id"],
            "episode_index": unit["episode"]["index"],
            "slice_index": unit["slice"]["index"],
            "disposition_class": "NO_DRIFT",
            "reasoning": f"slice {unit['slice']['index']} contradicts no governing rule",
            "event_refs": [unit["slice"]["start_seq"]],
        }
        payload.update(overrides)
        return payload

    def submit(self, candidate: dict) -> dict:
        return submit_mod.submit_candidate(self.home, candidate, registry=self.registry)


class TheSpanIsOneLongEpisode(PagedBase):
    """Precondition: without a single long episode this whole file proves nothing."""

    def test_the_fixture_is_one_episode_of_the_whole_span(self) -> None:
        episodes = self.record()["episodes"]
        self.assertEqual(len(episodes), 1)
        self.assertEqual((episodes[0]["start_seq"], episodes[0]["end_seq"]), (1, LONG_SPAN))

    def test_intake_records_the_span_size_on_the_episode(self) -> None:
        """Coverage must know how many slices an episode needs without the bundle."""
        self.assertEqual(self.record()["episodes"][0]["event_count"], LONG_SPAN)

    def test_the_span_needs_more_than_one_carrier_window(self) -> None:
        self.assertGreater(LONG_SPAN, self.limit)


class SlicesCoverTheSpan(PagedBase):
    """The red control the ticket asks for: a slice cursor cannot skip events."""

    def _slices(self) -> list[dict]:
        out: list[dict] = []
        for index in range(carrier_mod.slice_count(LONG_SPAN, self.limit)):
            unit = carrier_mod.build_carrier(
                self.home,
                registry=self.registry,
                session_id="paged-001",
                episode_index=0,
                slice_index=index,
            )
            out.append(unit)
        return out

    def test_the_slice_count_is_derived_from_the_span_and_the_limit(self) -> None:
        expected = -(-LONG_SPAN // self.limit)
        self.assertEqual(self.carrier()["slice"]["count"], expected)

    def test_every_event_of_the_span_appears_in_exactly_one_slice(self) -> None:
        seen: list[int] = []
        for unit in self._slices():
            seen += [int(event["seq"]) for event in unit["events"]]
        self.assertEqual(
            seen, list(range(1, LONG_SPAN + 1)),
            "the slices must tile the span in order, with no gap and no overlap",
        )

    def test_each_slice_is_within_the_registry_window(self) -> None:
        for unit in self._slices():
            self.assertLessEqual(len(unit["events"]), self.limit)
            self.assertGreater(len(unit["events"]), 0)

    def test_only_the_last_slice_reports_no_remainder(self) -> None:
        units = self._slices()
        for unit in units[:-1]:
            self.assertTrue(unit["episode"]["events_truncated"])
            self.assertFalse(unit["slice"]["final_slice"])
        self.assertFalse(units[-1]["episode"]["events_truncated"])
        self.assertTrue(units[-1]["slice"]["final_slice"])

    def test_each_slice_has_its_own_unit_digest(self) -> None:
        """Otherwise one receipt would answer every slice of the episode."""
        digests = [unit["unit_digest"] for unit in self._slices()]
        self.assertEqual(len(set(digests)), len(digests))

    def test_a_slice_index_past_the_end_clamps_to_the_last_slice(self) -> None:
        unit = carrier_mod.build_carrier(
            self.home,
            registry=self.registry,
            session_id="paged-001",
            episode_index=0,
            slice_index=999,
        )
        self.assertTrue(unit["slice"]["final_slice"])
        self.assertEqual(unit["slice"]["index"], unit["slice"]["count"] - 1)

    def test_the_carrier_is_still_the_declared_shape(self) -> None:
        self.assertEqual(
            carrier_mod.carrier_problems(self.carrier(), registry=self.registry), []
        )


class JudgingSliceBySlice(PagedBase):
    """The ticket's verify: N slices, one receipt each, no forced INSUFFICIENT_EVIDENCE."""

    def test_the_first_carrier_is_the_first_slice(self) -> None:
        unit = self.carrier()
        self.assertEqual(unit["slice"]["index"], 0)
        self.assertEqual(unit["slice"]["offset"], 0)
        self.assertEqual(unit["slice"]["span_event_count"], LONG_SPAN)

    def test_a_judged_slice_hands_over_the_next_one(self) -> None:
        first = self.carrier()
        self.submit(self.no_drift(first))
        second = self.carrier()
        self.assertEqual(second["episode"]["index"], first["episode"]["index"])
        self.assertEqual(second["slice"]["index"], 1)
        self.assertEqual(second["slice"]["start_seq"], first["slice"]["end_seq"] + 1)

    def test_a_non_final_slice_does_not_close_the_episode(self) -> None:
        """Red control: judging a prefix must not mark the episode judged."""
        self.submit(self.no_drift(self.carrier()))
        state = carrier_mod.semantic_state(self.record())
        self.assertEqual(state["next_episode_index"], 0)
        self.assertEqual(state["next_slice_index"], 1)
        self.assertFalse(state["exhausted"])
        report = coverage_mod.coverage(self.home, self.index(), registry=self.registry)
        self.assertEqual(report["episodes_final"], 0)
        self.assertEqual(report["slices_final"], 1)
        self.assertFalse(report["sessions"][0]["truly_exhausted"])

    def test_working_every_slice_closes_the_episode_and_the_session(self) -> None:
        verdicts = []
        for _ in range(50):
            unit = self.carrier()
            if unit["session"] is None:
                break
            receipt = self.submit(self.no_drift(unit))
            verdicts.append((receipt["slice_index"], receipt["verdict"]))
        expected = carrier_mod.slice_count(LONG_SPAN, self.limit)
        self.assertEqual(
            verdicts, [(index, "NO_DRIFT") for index in range(expected)],
            "each slice must be judged exactly once, in order",
        )
        self.assertEqual(self.carrier()["carrier"], "idle")
        report = coverage_mod.coverage(self.home, self.index(), registry=self.registry)
        self.assertEqual(report["slices_final"], expected)
        self.assertEqual(report["slices_pending"], 0)
        self.assertEqual(report["episodes_pending"], 0)
        self.assertEqual(report["episodes_final"], report["episodes_total"])
        self.assertEqual(report["sessions_truly_exhausted"], 1)
        self.assertNotIn(
            "INSUFFICIENT_EVIDENCE", {verdict for _index, verdict in verdicts},
            "no slice may be forced into INSUFFICIENT_EVIDENCE by truncation",
        )

    def test_every_receipt_records_which_slice_it_answered(self) -> None:
        for _ in range(3):
            self.submit(self.no_drift(self.carrier()))
        _status, payload, _detail = submit_mod.load_receipts(self.home)
        rows = payload["receipts"]
        self.assertEqual([row["slice_index"] for row in rows], [0, 1, 2])
        for row in rows:
            self.assertEqual(
                row["slice_count"], carrier_mod.slice_count(LONG_SPAN, self.limit)
            )

    def test_a_re_judged_earlier_slice_never_drags_the_cursor_back(self) -> None:
        """Red control: re-reasoning is allowed; losing the tail is not."""
        first = self.carrier()
        self.submit(self.no_drift(first))
        second = self.carrier()
        self.submit(self.no_drift(second))
        again = self.submit(self.no_drift(first, reasoning="second look at slice 0"))
        self.assertEqual(again["slice_index"], 0)
        state = carrier_mod.semantic_state(self.record())
        self.assertEqual(state["next_slice_index"], 2)
        self.assertEqual(self.carrier()["slice"]["index"], 2)


class SliceScopeIsEnforced(PagedBase):
    """An analyst may only cite what its own slice showed it."""

    def scope(self, candidate: dict, unit: dict) -> list[str]:
        return cand_mod.episode_scope_problems(candidate, unit, registry=self.registry)

    def test_an_event_from_a_later_slice_is_out_of_scope(self) -> None:
        unit = self.carrier()
        outside = unit["slice"]["end_seq"] + 1
        problems = self.scope(self.no_drift(unit, event_refs=[outside]), unit)
        self.assertTrue(any("outside the slice span" in p for p in problems))

    def test_a_candidate_naming_another_slice_is_out_of_scope(self) -> None:
        unit = self.carrier()
        problems = self.scope(self.no_drift(unit, slice_index=3), unit)
        self.assertTrue(any("is not the carrier's slice" in p for p in problems))

    def test_a_stale_slice_digest_is_refused_with_zero_writes(self) -> None:
        """Answering slice 0 while the carrier stands on slice 1 is stale reasoning."""
        first = self.carrier()
        self.submit(self.no_drift(first))
        stale = self.no_drift(first, reasoning="answering the slice I already answered")
        stale["slice_index"] = 1
        before = support.tree_digest(self.home)
        with self.assertRaises(PalError) as raised:
            self.submit(stale)
        self.assertEqual(raised.exception.code, "CANDIDATE_OUT_OF_SCOPE")
        self.assertEqual(support.tree_digest(self.home), before)

    def test_a_negative_slice_index_is_inadmissible(self) -> None:
        problems = cand_mod.candidate_problems(
            self.no_drift(self.carrier(), slice_index=-1), registry=self.registry
        )
        self.assertTrue(any("slice_index must not be negative" in p for p in problems))

    def test_a_non_integer_slice_index_is_inadmissible(self) -> None:
        problems = cand_mod.candidate_problems(
            self.no_drift(self.carrier(), slice_index="second"), registry=self.registry
        )
        self.assertTrue(any("slice_index must be an integer" in p for p in problems))

    def test_a_candidate_without_a_slice_index_still_answers_slice_zero(self) -> None:
        """Backwards compatibility: a single-slice episode never needed the field."""
        unit = self.carrier()
        payload = self.no_drift(unit)
        del payload["slice_index"]
        receipt = self.submit(payload)
        self.assertEqual(receipt["slice_index"], 0)


class PagedHotTail(PagedBase):
    """A growing episode is still paged, and still never closes."""

    TEMPERATURE = "HOT"

    def test_the_tail_is_provisional_and_paged(self) -> None:
        unit = self.carrier()
        self.assertEqual(unit["episode"]["finality"], "PROVISIONAL")
        self.assertGreater(unit["slice"]["count"], 1)

    def test_a_provisional_slice_advances_the_slice_but_not_the_episode(self) -> None:
        unit = self.carrier()
        receipt = self.submit(self.no_drift(unit))
        self.assertEqual(receipt["finality"], "PROVISIONAL")
        state = carrier_mod.semantic_state(self.record())
        self.assertEqual(state["next_episode_index"], 0)
        self.assertEqual(state["next_slice_index"], 1)
        self.assertFalse(state["exhausted"])

    def test_a_fully_judged_provisional_episode_is_never_truly_exhausted(self) -> None:
        """Red control: half a sentence read in full is still half a sentence."""
        for _ in range(carrier_mod.slice_count(LONG_SPAN, self.limit) + 2):
            unit = self.carrier()
            if unit["session"] is None:
                break
            self.submit(self.no_drift(unit))
        report = coverage_mod.coverage(self.home, self.index(), registry=self.registry)
        self.assertEqual(report["sessions_truly_exhausted"], 0)
        self.assertEqual(report["episodes_final"], 0)
        self.assertGreaterEqual(report["episodes_provisional"], 1)


class PagingReachesTheOperatorSurface(PagedBase):
    def test_next_json_carries_the_slice(self) -> None:
        code, payload, err = support.run_saipal_json("next", home=self.home)
        self.assertEqual(code, 0, err)
        window = payload["analysis_carrier"]["slice"]
        self.assertEqual(window["index"], 0)
        self.assertEqual(window["span_event_count"], LONG_SPAN)

    def test_next_human_output_names_the_slice(self) -> None:
        code, out, err = support.run_saipal("next", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertIn("slice: 1/", out)
        self.assertIn("more remain", out)

    def test_status_reports_slice_progress(self) -> None:
        code, out, err = support.run_saipal("status", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertIn("slices:", out)

    def test_status_json_counts_slices(self) -> None:
        code, payload, err = support.run_saipal_json("status", home=self.home)
        self.assertEqual(code, 0, err)
        semantic = payload["semantic"]
        self.assertEqual(
            semantic["slices_total"], carrier_mod.slice_count(LONG_SPAN, self.limit)
        )
        self.assertEqual(semantic["slices_final"], 0)

    def test_the_cli_loop_closes_over_a_paged_episode(self) -> None:
        """The whole point, through the real command surface."""
        for _ in range(50):
            code, payload, err = support.run_saipal_json("next", home=self.home)
            self.assertEqual(code, 0, err)
            unit = payload.get("analysis_carrier")
            if unit is None:
                break
            path = self.tmp / "candidate.json"
            path.write_text(json.dumps(self.no_drift(unit)), encoding="utf-8")
            code, receipt, err = support.run_saipal_json(
                "submit", str(path), home=self.home
            )
            self.assertEqual(code, 0, err)
        code, payload, err = support.run_saipal_json("report", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["verdict"], "NO_DRIFT_SO_FAR")
        self.assertEqual(payload["coverage"]["episodes_pending"], 0)
        self.assertEqual(payload["coverage"]["slices_pending"], 0)
        self.assertEqual(payload["next_action"], "saipal continue")

    def test_an_untouched_paged_episode_reports_not_examined(self) -> None:
        code, payload, err = support.run_saipal_json("report", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["verdict"], "NOT_EXAMINED")
        self.assertIn("unexamined", payload["next_action"])

    def test_a_half_judged_episode_still_points_at_the_remaining_slices(self) -> None:
        """Red control: an episode-only remainder reads 0 while slices are owed."""
        self.submit(self.no_drift(self.carrier()))
        code, payload, err = support.run_saipal_json("report", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["coverage"]["episodes_pending"], 0)
        self.assertGreater(payload["coverage"]["slices_pending"], 0)
        self.assertIn("slice(s) are still unexamined", payload["next_action"])


class SliceCountArithmetic(unittest.TestCase):
    """The one calculation everything else rests on."""

    def test_an_empty_span_is_still_one_slice(self) -> None:
        self.assertEqual(carrier_mod.slice_count(0, 200), 1)

    def test_a_span_inside_the_limit_is_one_slice(self) -> None:
        self.assertEqual(carrier_mod.slice_count(200, 200), 1)

    def test_one_event_over_the_limit_is_two_slices(self) -> None:
        self.assertEqual(carrier_mod.slice_count(201, 200), 2)

    def test_a_ragged_span_rounds_up(self) -> None:
        self.assertEqual(carrier_mod.slice_count(900, 200), 5)

    def test_a_nonsense_limit_degrades_to_one_slice(self) -> None:
        self.assertEqual(carrier_mod.slice_count(900, 0), 1)

    def test_a_malformed_span_degrades_to_one_slice(self) -> None:
        self.assertEqual(carrier_mod.slice_count("many", 200), 1)

    def test_an_episode_without_a_recorded_count_uses_its_span_width(self) -> None:
        """A record written before intake stored event_count must still page."""
        episode = {"index": 0, "start_seq": 1, "end_seq": 900}
        self.assertEqual(carrier_mod.episode_slice_count({}, episode, 200), 5)


if __name__ == "__main__":
    unittest.main()
