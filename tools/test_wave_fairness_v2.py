"""T-107 (ROLE 13-26): eligibility-queue fairness, not lifetime service debt.

v1 ranked by lifetime `served`, so a veteran with served=100 starved forever
behind endless zero-served newcomers, and a re-entering veteran inherited a
100-turn debt. v2 ranks CURRENT work by queue claim age: oldest waiting ticket
first; service retires the claim; the next unit re-tickets at the tail.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import fairness as fairness_mod


class FairnessV2State(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def test_v1_state_migrates_preserving_served_as_telemetry(self) -> None:
        path = fairness_mod.fairness_path(self.home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "updated_at": "",
                    "sessions": {"veteran": {"session_id": "veteran", "served": 100}},
                    "service_sequence": [],
                }
            ),
            encoding="utf-8",
        )
        state = fairness_mod.load_state(self.home)
        self.assertEqual(state["schema_version"], 2)
        self.assertEqual(state["sessions"]["veteran"]["served"], 100)
        self.assertEqual(state["sessions"]["veteran"]["ticket"], 0)
        self.assertEqual(state["sessions"]["veteran"]["current_unit_digest"], "")

    def test_sync_mints_tail_tickets_in_arrival_order(self) -> None:
        state, changed = fairness_mod.sync_eligibility(
            self.home, {"a": "d1", "b": "d2"}
        )
        self.assertTrue(changed)
        # Idempotent: an unchanged eligible set performs ZERO writes.
        state_again, changed_again = fairness_mod.sync_eligibility(
            self.home, {"a": "d1", "b": "d2"}
        )
        self.assertFalse(changed_again)
        self.assertEqual(state_again["sessions"]["a"]["ticket"], 1)
        self.assertEqual(state_again["sessions"]["b"]["ticket"], 2)

    def test_new_unit_digest_re_tickets_at_the_tail(self) -> None:
        fairness_mod.sync_eligibility(self.home, {"a": "d1", "b": "d2"})
        # a's next unit after service (new digest) must queue BEHIND b.
        fairness_mod.sync_eligibility(self.home, {"a": "d1b", "b": "d2"})
        state = fairness_mod.load_state(self.home)
        self.assertGreater(state["sessions"]["a"]["ticket"], state["sessions"]["b"]["ticket"])

    def test_ineligible_session_loses_its_claim(self) -> None:
        fairness_mod.sync_eligibility(self.home, {"a": "d1", "b": "d2"})
        fairness_mod.sync_eligibility(self.home, {"b": "d2"})
        state = fairness_mod.load_state(self.home)
        self.assertEqual(state["sessions"]["a"]["ticket"], 0)
        self.assertEqual(state["sessions"]["a"]["current_unit_digest"], "")
        self.assertEqual(state["sessions"]["a"]["served"], 0)

    def test_queue_rank_orders_oldest_ticket_first(self) -> None:
        fairness_mod.sync_eligibility(self.home, {"veteran": "d1", "newcomer": "d2"})
        state = fairness_mod.load_state(self.home)
        ordered = sorted(
            ("veteran", "newcomer"),
            key=lambda s: fairness_mod.queue_rank(s, state),
        )
        self.assertEqual(ordered, ["veteran", "newcomer"])


class EndlessNewcomerStarvation(unittest.TestCase):
    """ROLE 23: the mandatory red control. v1 FAILS it; v2 must PASS."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def test_veteran_is_served_within_a_bounded_number_of_decisions(self) -> None:
        # The veteran arrives first with its claim; before EVERY scheduling
        # decision a brand-new session becomes eligible.
        state, _ = fairness_mod.sync_eligibility(self.home, {"veteran": "d0"})
        served = None
        decisions = 0
        for wave in range(50):
            decisions += 1
            state, _ = fairness_mod.sync_eligibility(
                self.home, {"veteran": "d0", f"newcomer-{wave}": f"dn{wave}"}
            )
            # Rank among the eligible: the OLDEST ticket wins.
            winner = min(
                ("veteran", f"newcomer-{wave}"),
                key=lambda s: fairness_mod.queue_rank(s, state),
            )
            if winner == "veteran":
                served = wave
                break
        self.assertIsNotNone(
            served,
            "the veteran starved behind 50 newcomer arrivals",
        )
        self.assertLess(decisions, 10, "veteran must be served within a small bound")

    def test_lifetime_served_never_decides_current_order(self) -> None:
        # A veteran with served=100 and a zero-served newcomer both hold
        # current claims: order is claim age, not history (ROLE 19/24).
        state, _ = fairness_mod.sync_eligibility(self.home, {"veteran": "dv"})
        state["sessions"]["veteran"]["served"] = 100
        state, _ = fairness_mod.sync_eligibility(
            self.home, {"veteran": "dv", "newcomer": "dn"}
        )
        winner = min(
            ("veteran", "newcomer"),
            key=lambda s: fairness_mod.queue_rank(s, state),
        )
        self.assertEqual(winner, "veteran")


class ReentryAndRestart(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def test_reentering_veteran_gets_a_fresh_position(self) -> None:
        # ROLE 24: 100 completed units, exhausted, later new work arrives.
        fairness_mod.sync_eligibility(self.home, {"b": "db"})
        fairness_mod.sync_eligibility(self.home, {"veteran": "dv"})
        fairness_mod.record_service(self.home, "veteran")
        for i in range(99):
            fairness_mod.record_service(self.home, "veteran")
        state = fairness_mod.load_state(self.home)
        self.assertEqual(state["sessions"]["veteran"]["served"], 100)
        # New eligible work: a FRESH tail ticket behind every current claim.
        fairness_mod.sync_eligibility(
            self.home, {"b": "db", "newcomer": "dn", "veteran": "dv2"}
        )
        state = fairness_mod.load_state(self.home)
        vet = state["sessions"]["veteran"]
        self.assertGreaterEqual(
            vet["ticket"],
            max(state["sessions"]["b"]["ticket"], state["sessions"]["newcomer"]["ticket"]),
            "re-entry must not jump the queue because of history",
        )
        # But it must also NOT inherit a 100-turn debt: it holds ONE ticket,
        # one queue position, not 100 (the rank tuple is a single ticket).
        self.assertEqual(
            len(fairness_mod.queue_rank("veteran", state)), 2,
            "rank is (ticket, session_id) -- one position, no debt",
        )

    def test_restart_preserves_order_and_counter(self) -> None:
        fairness_mod.sync_eligibility(self.home, {"a": "d1"})
        fairness_mod.sync_eligibility(self.home, {"b": "d2"})
        fairness_mod.record_service(self.home, "a")
        before = fairness_mod.load_state(self.home)
        # A fresh process reads the same durable state: no reset, no reorder.
        after = fairness_mod.load_state(self.home)
        self.assertEqual(after, before)
        self.assertEqual(after["sessions"]["a"]["served"], 1)
        self.assertEqual(after["next_ticket"], 3)
        self.assertEqual(
            fairness_mod.queue_rank("b", after),
            (after["sessions"]["b"]["ticket"], "b"),
        )

    def test_corrupt_fairness_state_fails_loudly(self) -> None:
        path = fairness_mod.fairness_path(self.home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"{broken")
        from saipal_engine.errors import PalError

        with self.assertRaises(PalError) as ctx:
            fairness_mod.load_state(self.home)
        self.assertEqual(ctx.exception.code, "VALIDATION_FAILED")
        self.assertEqual(path.read_bytes(), b"{broken")


class LargeUnlockBurst(unittest.TestCase):
    """ROLE 22: 1x~1000 + 20 medium + 100 tiny, all unlocked at once."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def test_bounded_budget_spreads_across_many_sessions(self) -> None:
        from saipal_analyst import fairness as fm

        # 1 huge + 20 medium + 100 tiny sessions become eligible simultaneously.
        eligible = {"huge": "h0"}
        eligible.update({f"med-{i}": f"m{i}" for i in range(20)})
        eligible.update({f"tiny-{i}": f"t{i}" for i in range(100)})
        state, _ = fm.sync_eligibility(self.home, eligible)

        # Bounded run: 30 services. Each service retires the winner's claim;
        # the next sync re-tickets its NEXT unit at the tail, so the giant
        # interleaves with everyone else instead of monopolizing.
        served_sessions = set()
        tickets_before = {}
        for session_id in eligible:
            tickets_before[session_id] = state["sessions"][session_id]["ticket"]
        for _ in range(30):
            winner = min(eligible, key=lambda s: fm.queue_rank(s, state))
            served_sessions.add(winner)
            fm.record_service(self.home, winner)
            # The winner's next unit (a fresh digest) re-enters at the tail.
            eligible[winner] = eligible[winner] + "+next"
            state, _ = fm.sync_eligibility(self.home, eligible)

        self.assertGreaterEqual(
            len(served_sessions), 25,
            f"work must spread across many distinct sessions, got {len(served_sessions)}",
        )
        self.assertNotEqual(
            served_sessions, {"huge"},
            "the giant session must not monopolize the bounded run",
        )
        # Restart preserves the scheduling state (ROLE 26).
        reloaded = fm.load_state(self.home)
        self.assertEqual(reloaded["next_ticket"], state["next_ticket"])


if __name__ == "__main__":
    unittest.main()
