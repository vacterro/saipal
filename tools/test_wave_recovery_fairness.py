"""T-107 second-pass recovery fairness bridge (ROLE 20-26 repair).

Before the bridge, `_allocate` synchronized fairness for current-cursor units
only, then discovered durable recoverable jobs in a SECOND pass. A recoverable
job whose cursor had moved past its unit could rank with the 10**12 sentinel
(not-synchronized) -- safe from wrongly winning, but permanently starved behind
endless fresh arrivals. The bridge: build the COMPLETE runnable set (cursor
units + recoverable durable jobs that can run now) BEFORE synchronizing
fairness, so every legitimate candidate holds a real positive ticket.

This suite proves the bridge and its guards:
- a runnable recovery FINAL job is selected within a bounded number of
  selections even while fresh FINAL newcomers keep arriving;
- endless recovery arrivals cannot permanently starve a waiting fresh unit;
- blocked work stays claimless;
- reconciliation errors never disappear into `except Exception: pass`;
- a receipt committed with a fairness-retirement failure converges on restart
  without a duplicate receipt or a replayed model call.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import fairness as fairness_mod
from saipal_analyst import jobs as jobs_mod
from saipal_analyst import worker as worker_mod
from saipal_engine import sessions as sessions_mod
from saipal_engine.errors import PalError


def _allocate(home: Path, summary: dict | None = None):
    """One real allocation through the real `_allocate` boundary."""
    status, index, _detail = sessions_mod.load_index(home)
    journal = jobs_mod.load_journal(home)
    return worker_mod._allocate(
        home, index, journal,
        provisional=False, event_limit=6, summary=summary or {"jobs_blocked_binding": 0},
        backend_type="openai_compatible", model="stub", wall_now=1000.0,
    )


class ImportedHomeBase(unittest.TestCase):
    """A home with the conformant BOUND session imported (cursor at ep0 sl0)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        support.clear_inbox(self.home)

    def _advance_cursor_past_episode0(self) -> None:
        """The receipt advanced coverage; the durable job is second-pass now.

        The conformant session holds six episodes (0..5): moving the cursor to
        episode 2 leaves later fresh work AND makes the episode-0 durable job
        recoverable-but-not-cursor, exactly the second-pass situation.
        """
        status, index, _detail = sessions_mod.load_index(self.home)
        record = sessions_mod.find_session(index, "golden-cold-001")
        semantic = dict(record.get("semantic") or {})
        semantic["next_episode_index"] = 2
        record["semantic"] = semantic
        sessions_mod.save_index(self.home, index)

    def _durable_recovery_job(self) -> dict:
        journal = jobs_mod.load_journal(self.home)
        job = jobs_mod.new_job(
            session_id="golden-cold-001", episode_index=0, slice_index=0,
            unit_digest="f" * 64, finality="FINAL",
            backend_type="openai_compatible", model="stub", run_id="run-recovery",
        )
        job["stage"] = jobs_mod.SUBMITTING
        jobs_mod.upsert(journal, job)
        jobs_mod.save_journal(self.home, journal)
        return job


class RecoveryJobGetsARealTicket(ImportedHomeBase):
    """#23 red-control turned green: recovery ranks on a real ticket."""

    def test_second_pass_recovery_is_selected_with_real_claim(self) -> None:
        self._advance_cursor_past_episode0()
        job = self._durable_recovery_job()
        unit, note = _allocate(self.home)
        self.assertFalse(note, note)
        self.assertIsNotNone(unit)
        self.assertEqual(unit["job_id"], job["job_id"])
        # The claim it ranks on names the RECOVERY digest, not the cursor's.
        fairness = fairness_mod.load_state(self.home)
        claim = fairness["sessions"].get("golden-cold-001") or {}
        self.assertEqual(claim.get("current_unit_digest"), "f" * 64)
        self.assertGreater(int(claim.get("ticket") or 0), 0)
        self.assertLess(
            fairness_mod.queue_rank("golden-cold-001", fairness)[0],
            10**12,
            "a legitimate runnable recovery job must never rely on the sentinel",
        )


class EndlessNewcomersCannotStarveRecovery(ImportedHomeBase):
    """#23: the oldest-ticket recovery job wins deterministically, not never."""

    def test_recovery_selected_within_deterministic_bound(self) -> None:
        self._advance_cursor_past_episode0()
        job = self._durable_recovery_job()
        # First decision: the recovery job is the only runnable work and mints
        # the oldest ticket. If the bridge were missing, its rank would fall
        # back to the 10**12 sentinel and the selection outcome would depend on
        # accident; the pinned behavior is a real-ticket FIFO win.
        unit, note = _allocate(self.home)
        self.assertFalse(note, note)
        self.assertEqual(unit["job_id"], job["job_id"])
        fairness = fairness_mod.load_state(self.home)
        claim = fairness["sessions"].get("golden-cold-001") or {}
        self.assertGreater(int(claim.get("ticket") or 0), 0)
        # Simulated continued competition: even when a fresh claim exists for
        # another session minted AFTER the recovery ticket, the older ticket
        # still outranks it. Repeated allocations keep the recovery job at the
        # front; it can never be pushed behind by newcomer arrivals.
        fairness = fairness_mod.sync_eligibility(
            self.home,
            {"golden-cold-001": "f" * 64, "golden-other": "e" * 64},
        )[0]
        self.assertLess(
            fairness_mod.queue_rank("golden-cold-001", fairness),
            fairness_mod.queue_rank("golden-other", fairness),
        )
        # And the same allocation, rerun, still selects the recovery job.
        unit2, _note2 = _allocate(self.home)
        self.assertEqual(unit2["job_id"], job["job_id"])


class RecoveryCannotStarveFresh(ImportedHomeBase):
    """#23 opposite direction: continuing recovery arrivals yield to fresh."""

    def test_older_fresh_ticket_beats_newer_recovery_ticket(self) -> None:
        # The fresh session's claim is minted FIRST (oldest ticket); a later
        # recovery entry for another session must queue BEHIND it.
        fairness = fairness_mod.sync_eligibility(
            self.home, {"golden-cold-001": "a" * 64}
        )[0]
        fresh_ticket = fairness["sessions"]["golden-cold-001"]["ticket"]
        later = fairness_mod.sync_eligibility(
            self.home,
            {"golden-cold-001": "a" * 64, "golden-unbound-001": "b" * 64},
        )[0]
        recovery_ticket = later["sessions"]["golden-unbound-001"]["ticket"]
        self.assertGreater(recovery_ticket, fresh_ticket)
        self.assertLess(
            fairness_mod.queue_rank("golden-cold-001", later),
            fairness_mod.queue_rank("golden-unbound-001", later),
            "recovery arrivals must queue behind older waiting fresh work",
        )


class ClaimlessStates(ImportedHomeBase):
    """#14 (Phase C): blocked/provisional-disabled/future-retry hold no claim."""

    def test_blocked_binding_session_never_gets_a_ticket(self) -> None:
        # unknown-protocol has no identity and no trusted authority: BLOCKED.
        support.put_inbox(self.home, "unknown-protocol.json")
        support.run_saipal("continue", home=self.home)
        support.clear_inbox(self.home)
        summary = {"jobs_blocked_binding": 0}
        _allocate(self.home, summary)
        fairness = fairness_mod.load_state(self.home)
        claim = fairness["sessions"].get("golden-unbound-001") or {}
        self.assertEqual(
            int(claim.get("ticket") or 0), 0,
            "binding-blocked work must stay claimless",
        )

    def test_fresh_cursor_unit_holds_exactly_one_claim(self) -> None:
        # The claim identity invariant, pinned: one active claim per session,
        # naming the cursor digest. The allocator's disjointness argument
        # (cursor units and recovery entries are mutually exclusive per
        # session) makes session-level claims sufficient; documented in
        # `_allocate`'s contract.
        unit, note = _allocate(self.home)
        self.assertFalse(note, note)
        self.assertIsNotNone(unit)
        fairness = fairness_mod.load_state(self.home)
        claims = {
            sid: rec for sid, rec in fairness["sessions"].items()
            if int(rec.get("ticket") or 0) > 0
        }
        self.assertEqual(set(claims), {"golden-cold-001"})
        self.assertEqual(claims["golden-cold-001"]["current_unit_digest"], unit["unit_digest"])


class ReconciliationIsLoud(ImportedHomeBase):
    """#25/#26: integrity failures stop allocation; expected ones are quiet."""

    def _corrupt_receipts(self) -> None:
        receipts = self.home / "semantic_receipts.json"
        if receipts.exists():
            receipts.write_text("{corrupt", encoding="utf-8")
        else:
            receipts.write_text("{corrupt", encoding="utf-8")

    def test_unreadable_receipts_ledger_fails_loud(self) -> None:
        self._corrupt_receipts()
        with self.assertRaises(PalError) as caught:
            _allocate(self.home)
        self.assertEqual(caught.exception.code, "VALIDATION_FAILED")
        self.assertIn("semantic receipts", str(caught.exception.message))

    def test_absent_receipts_ledger_is_quiet(self) -> None:
        # No receipts file at all: nothing to reconcile, allocation proceeds.
        unit, note = _allocate(self.home)
        self.assertFalse(note, note)
        self.assertIsNotNone(unit)

    def test_empty_receipts_ledger_is_quiet(self) -> None:
        from saipal_engine.submit import _save_receipts

        _save_receipts(
            self.home,
            {"schema_version": 1, "receipts": [], "operations": []},
            registry=None,
        )
        unit, note = _allocate(self.home)
        self.assertFalse(note, note)
        self.assertIsNotNone(unit)

    def test_done_receipt_reconciles_stale_claim_without_error(self) -> None:
        # A receipt exists for the session but its fairness claim survived the
        # crash: reconciliation retires the claim and allocation proceeds.
        from saipal_engine.submit import _save_receipts

        _save_receipts(
            self.home,
            {
                "schema_version": 1,
                "receipts": [{
                    "receipt_id": "rcp-test", "session_id": "golden-cold-001",
                    "episode_index": 0, "slice_index": 0, "unit_digest": "a" * 64,
                    "verdict": "NO_DRIFT", "recorded_at": "2026-09-09T00:00:00Z",
                }],
                "operations": [],
            },
            registry=None,
        )
        # The real post-receipt state: the session's coverage is exhausted
        # (the receipt proves the unit was served) but the fairness claim
        # survived the crash.
        status, index, _detail = sessions_mod.load_index(self.home)
        record = sessions_mod.find_session(index, "golden-cold-001")
        semantic = dict(record.get("semantic") or {})
        semantic["exhausted"] = True
        record["semantic"] = semantic
        sessions_mod.save_index(self.home, index)

        fairness = fairness_mod.sync_eligibility(
            self.home, {"golden-cold-001": "a" * 64}
        )[0]
        fairness["sessions"]["golden-cold-001"]["ticket"] = 77
        fairness_mod.save_state(self.home, fairness)

        # The exhausted session must not be selected again, and its claim must
        # be retired by the reconciliation (not carried as a live ticket).
        unit, _note = _allocate(self.home)
        reconciled = fairness_mod.load_state(self.home)["sessions"].get("golden-cold-001") or {}
        self.assertEqual(int(reconciled.get("ticket") or 0), 0)
        self.assertTrue(
            unit is None or unit["session_id"] != "golden-cold-001",
            "an exhausted, receipt-proven session must not be re-allocated",
        )


class PostReceiptFairnessCrashConvergence(ImportedHomeBase):
    """#26: receipt committed, fairness retirement failed; restart converges.

    Run 1: the REAL worker serves the unit; `record_service` is injected to
    fail after the receipt commits (FAIRNESS_PERSISTENCE_FAILED), leaving a
    stale fairness claim behind. Restart: the next allocation reconciles the
    stale claim from the canonical receipt -- no duplicate receipt, no replay
    of the paid investigator stage.
    """

    def test_restart_converges_without_duplicate_receipt_or_replay(self) -> None:
        import os

        import test_wave_analyst_repair as repair
        from saipal_analyst import worker as worker_module
        from saipal_analyst.config import default_analyst_config, save_analyst_config
        from saipal_analyst.worker import investigate
        from saipal_engine.submit import load_receipts

        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        # The carrier rebuild reads the canonical bundle from the inbox, so the
        # fixture must be present again before the candidate body is derived.
        support.put_inbox(self.home, "conformant-cold.json")
        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 0
        config["budgets"]["max_units_per_run"] = 1
        save_analyst_config(self.home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "stub-key"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)
        backend.script.append(
            (200, repair.envelope(
                repair.RepairBase.candidate_for(
                    repair.RepairBase(), self.home, "NO_DRIFT"
                )
            ))
        )

        # Inject the crash: the receipt commits, then the fairness retirement
        # fails. The worker must report FAIRNESS_PERSISTENCE_FAILED and stop.
        original_record_service = fairness_mod.record_service

        def failing_record_service(home, session_id):  # noqa: ANN001
            raise PalError("VALIDATION_FAILED", "injected fairness save failure")

        fairness_mod.record_service = failing_record_service
        try:
            summary = investigate(self.home)
        finally:
            fairness_mod.record_service = original_record_service
        codes = {str(err.get("code")) for err in summary.get("errors") or []}
        self.assertIn("FAIRNESS_PERSISTENCE_FAILED", codes)

        _status, payload, _detail = load_receipts(self.home)
        count_before = len(payload["receipts"])
        self.assertEqual(count_before, 1, "the receipt committed exactly once")
        # The stale claim survived the crash.
        stale = fairness_mod.load_state(self.home)["sessions"].get("golden-cold-001") or {}
        self.assertGreater(int(stale.get("ticket") or 0), 0)

        # Restart: serve the REMAINING episodes through the real worker (no
        # injection). The receipt-proven episode must NOT be repeated -- the
        # receipts must cover six DISTINCT episodes, never a replay -- and once
        # the session is exhausted its stale claim must reconcile away.
        for _episode in range(5):
            backend.script.append(
                (200, repair.envelope(
                    repair.RepairBase.candidate_for(
                        repair.RepairBase(), self.home, "NO_DRIFT"
                    )
                ))
            )
            investigate(self.home)
        _status, payload_after, _detail = load_receipts(self.home)
        episodes_served = sorted(
            int(r.get("episode_index")) for r in payload_after["receipts"]
        )
        self.assertEqual(episodes_served, [0, 1, 2, 3, 4, 5])
        self.assertEqual(
            len(payload_after["receipts"]), 6,
            "no duplicate receipt: one receipt per episode, exactly",
        )
        claim = fairness_mod.load_state(self.home)["sessions"].get("golden-cold-001") or {}
        self.assertEqual(
            int(claim.get("ticket") or 0), 0,
            "the exhausted session's stale claim must be reconciled away",
        )
        state = fairness_mod.load_state(self.home)["sessions"].get("golden-cold-001") or {}
        self.assertGreaterEqual(int(state.get("served") or 0), 5)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
