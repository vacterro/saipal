"""Wave B: episode boundary hooks (PAL-SESSION-05).

Segmentation marks where episodes begin. It does not look inside one, compare
one to anything, or conclude anything about one -- that is Wave C's job.
"""

from __future__ import annotations

import unittest
from unittest import mock

import pal_test_support as support
from saipal_engine import bundle as bundle_mod
from saipal_engine import episodes as episodes_mod

COLD = "conformant-cold.json"


def _event(seq: int, kind: str, **facts):
    return {"seq": seq, "type": kind, "ts": None, "loc": None, "digest": None, "facts": facts}


class EpisodeBoundaries(unittest.TestCase):
    def setUp(self) -> None:
        self.events = bundle_mod.events_of(support.load_fixture(COLD))

    def test_every_boundary_kind_is_marked_once(self) -> None:
        marks = episodes_mod.boundary_marks(self.events)
        self.assertEqual(
            [m["kind"] for m in marks],
            ["user_task", "command", "phase_change", "work_switch", "source_intake", "recovery"],
        )

    def test_episodes_cover_the_whole_stream_without_gaps(self) -> None:
        episodes = episodes_mod.extract_episodes(self.events)
        self.assertEqual(len(episodes), 6)
        self.assertEqual(episodes[0]["start_seq"], 1)
        self.assertEqual(episodes[-1]["end_seq"], 11)
        for previous, following in zip(episodes, episodes[1:]):
            self.assertEqual(previous["end_seq"] + 1, following["start_seq"])

    def test_every_event_lands_in_exactly_one_episode(self) -> None:
        """T-71: the tail used to be dropped when the last event was a boundary."""
        for stream in (
            self.events,
            [_event(1, "USER_MESSAGE"), _event(2, "TOOL_CALL"), _event(3, "COMMAND")],
            [_event(1, "COMMAND")],
            [_event(1, "USER_MESSAGE"), _event(2, "PHASE_CHANGE")],
            [_event(1, "TOOL_CALL"), _event(2, "SOURCE_EVENT")],
        ):
            with self.subTest(last=stream[-1]["type"]):
                episodes = episodes_mod.extract_episodes(stream)
                covered = [
                    seq
                    for episode in episodes
                    for seq in range(episode["start_seq"], episode["end_seq"] + 1)
                ]
                self.assertEqual(
                    covered,
                    [int(event["seq"]) for event in stream],
                    "every event must belong to exactly one episode, in order",
                )
                self.assertEqual(
                    sum(e["event_count"] for e in episodes),
                    len(stream),
                    "the recorded counts must add up to the stream",
                )

    def test_a_stream_ending_on_a_boundary_keeps_its_last_event(self) -> None:
        """Red control: the exact defect, in the smallest possible stream."""
        episodes = episodes_mod.extract_episodes(
            [_event(1, "USER_MESSAGE"), _event(2, "COMMAND")]
        )
        self.assertEqual(
            [(e["kind"], e["start_seq"], e["end_seq"]) for e in episodes],
            [("command", 1, 1), ("terminal_task", 2, 2)],
        )

    def test_episode_is_named_by_the_boundary_that_opened_it(self) -> None:
        episodes = episodes_mod.extract_episodes(self.events)
        self.assertEqual(
            [(e["kind"], e["start_seq"], e["end_seq"]) for e in episodes],
            [
                ("command", 1, 1),
                ("phase_change", 2, 4),
                ("work_switch", 5, 6),
                ("source_intake", 7, 7),
                ("recovery", 8, 8),
                ("terminal_task", 9, 11),
            ],
        )

    def test_indices_are_contiguous(self) -> None:
        episodes = episodes_mod.extract_episodes(self.events)
        self.assertEqual([e["index"] for e in episodes], list(range(len(episodes))))

    def test_empty_stream_has_no_episodes(self) -> None:
        self.assertEqual(episodes_mod.extract_episodes([]), [])

    def test_single_event_is_one_terminal_episode(self) -> None:
        episodes = episodes_mod.extract_episodes([_event(1, "USER_MESSAGE")])
        self.assertEqual(len(episodes), 1)
        self.assertEqual(episodes[0]["kind"], "terminal_task")
        self.assertEqual((episodes[0]["start_seq"], episodes[0]["end_seq"]), (1, 1))

    def test_stream_without_boundaries_is_one_episode(self) -> None:
        events = [_event(1, "USER_MESSAGE"), _event(2, "ASSISTANT_MESSAGE")]
        episodes = episodes_mod.extract_episodes(events)
        self.assertEqual(len(episodes), 1)
        self.assertEqual(episodes[0]["kind"], "terminal_task")
        self.assertEqual(episodes[0]["trigger_seq"], None)


class BoundaryTriggers(unittest.TestCase):
    def test_work_switch_needs_an_actual_change(self) -> None:
        events = [
            _event(1, "STATE_SNAPSHOT", active_work="T-1"),
            _event(2, "STATE_SNAPSHOT", active_work="T-1"),
        ]
        self.assertEqual(episodes_mod.boundary_marks(events), [])

    def test_first_snapshot_does_not_count_as_a_switch(self) -> None:
        events = [_event(1, "STATE_SNAPSHOT", active_work="T-1")]
        self.assertEqual(episodes_mod.boundary_marks(events), [])

    def test_work_switch_uses_the_alternate_key_too(self) -> None:
        events = [
            _event(1, "STATE_SNAPSHOT", work="T-1"),
            _event(2, "STATE_SNAPSHOT", work="T-2"),
        ]
        self.assertEqual([m["kind"] for m in episodes_mod.boundary_marks(events)], ["work_switch"])

    def test_plain_error_is_not_a_recovery(self) -> None:
        events = [_event(1, "ERROR", message="tool exploded")]
        self.assertEqual(episodes_mod.boundary_marks(events), [])

    def test_recovery_flag_marks_a_recovery(self) -> None:
        self.assertEqual(
            [m["kind"] for m in episodes_mod.boundary_marks([_event(1, "ERROR", recovery=True)])],
            ["recovery"],
        )

    def test_recovery_kind_marks_a_recovery(self) -> None:
        event = _event(1, "ERROR")
        event["facts"]["kind"] = "recovery"
        self.assertEqual(
            [m["kind"] for m in episodes_mod.boundary_marks([event])],
            ["recovery"],
        )

    def test_command_marks_a_command_boundary(self) -> None:
        self.assertEqual(
            [m["kind"] for m in episodes_mod.boundary_marks([_event(1, "COMMAND")])], ["command"]
        )

    def test_new_user_message_marks_a_semantic_task(self) -> None:
        self.assertEqual(
            episodes_mod.boundary_marks([_event(1, "USER_MESSAGE")]),
            [{"seq": 1, "kind": "user_task"}],
        )

    def test_provider_step_storm_is_one_semantic_episode(self) -> None:
        events = [_event(1, "USER_MESSAGE")]
        seq = 1
        for index in range(20):
            seq += 1
            marker = _event(seq, "SESSION_BOUNDARY", phase="step-start")
            marker["facts"]["kind"] = "step"
            events.append(marker)
            seq += 1
            events.append(_event(seq, "TOOL_CALL", tool=f"tool-{index}"))
        seq += 1
        events.append(_event(seq, "ASSISTANT_MESSAGE"))
        semantic = episodes_mod.extract_episodes(events)
        mechanical = episodes_mod.mechanical_spans(events)
        self.assertEqual(len(semantic), 1)
        self.assertEqual((semantic[0]["start_seq"], semantic[0]["end_seq"]), (1, seq))
        self.assertEqual(len(mechanical), 21)


class RegistryDriven(unittest.TestCase):
    def test_red_control_boundary_kinds_follow_the_registry(self) -> None:
        """Take `command` out of the closed set and it must stop opening episodes."""
        events = [_event(1, "USER_MESSAGE"), _event(2, "COMMAND"), _event(3, "TOOL_CALL")]
        self.assertEqual(
            [m["kind"] for m in episodes_mod.boundary_marks(events)],
            ["user_task", "command"],
        )

        mutated = support.load_registry_copy()
        mutated["episode_boundary_kinds"] = [
            k for k in mutated["episode_boundary_kinds"] if k != "command"
        ]
        with mock.patch.object(episodes_mod, "load_registry", return_value=mutated):
            self.assertEqual(
                [m["kind"] for m in episodes_mod.boundary_marks(events)],
                ["user_task"],
            )

    def test_unknown_kind_never_leaks_into_episodes(self) -> None:
        events = bundle_mod.events_of(support.load_fixture(COLD))
        episodes = episodes_mod.extract_episodes(events)
        allowed = set(support.load_registry_copy()["episode_boundary_kinds"])
        for episode in episodes:
            self.assertIn(episode["kind"], allowed)


if __name__ == "__main__":
    unittest.main()
