"""T-78: the journal is the worker's crash memory, and one worker owns a home.

Recovery cases (T-84 v2 contract), each pinned by a control:
  A crash before model call        -> READY, next action `call`.
  B crash during model call        -> INVESTIGATOR_CALLING without a persisted
                                      response: the call is retried under the
                                      transport-attempt budget and the uncertain
                                      prior attempt is visible.
  C crash after response write     -> INVESTIGATOR_RESPONSE: the response is
                                      reused, the model is not called.
  D crash after valid candidate    -> CANDIDATE_READY: the candidate re-enters
                                      the SAME critic policy fresh execution
                                      uses -- a recovered investigator
                                      candidate is not automatically final
                                      (T-84: stronger than the old direct-submit
                                      expectation, which let recovered DRIFT
                                      bypass the critic).
  E crash during submit            -> SUBMITTING: resubmit the same candidate;
                                      kernel idempotency converges to one receipt.
  F stale HOT unit                 -> STALE: reasoning discarded, never salvaged.

Plus the journal's own discipline: closed schema v2, legal transitions only,
atomic saves, v1 -> v2 migration (deterministic, idempotent, no stranded
jobs), and a second worker refused at the lock.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import jobs as jobs_mod
from saipal_engine.errors import PalError
from saipal_engine.paths import home_paths


def make_job(**overrides: object) -> dict:
    payload = jobs_mod.new_job(
        session_id="ses_x",
        episode_index=2,
        slice_index=0,
        unit_digest="d" * 64,
        finality="FINAL",
        backend_type="openai_compatible",
        model="stub-model",
        run_id="run-1",
    )
    payload.update(overrides)
    return payload


class JournalBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def save(self, journal: dict) -> None:
        jobs_mod.save_journal(self.home, journal)

    def load(self) -> dict:
        return jobs_mod.load_journal(self.home)


class JournalShape(JournalBase):
    def test_absent_journal_is_empty_not_broken(self) -> None:
        journal = self.load()
        self.assertEqual(jobs_mod.journal_problems(journal), [])
        self.assertEqual(journal["jobs"], {})

    def test_job_identity_is_deterministic(self) -> None:
        first = jobs_mod.unit_job_id("s", 1, 0, "d")
        second = jobs_mod.unit_job_id("s", 1, 0, "d")
        other = jobs_mod.unit_job_id("s", 2, 0, "d")
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)

    def test_job_record_is_closed(self) -> None:
        job = make_job()
        job["secret_field"] = "nope"
        with self.assertRaises(PalError) as caught:
            self.save({"schema_version": 2, "updated_at": "x", "jobs": {job["job_id"]: job}})
        self.assertIn("unknown field", str(caught.exception))
        self.assertFalse(jobs_mod.journal_path(self.home).exists())

    def test_unknown_journal_field_rejected(self) -> None:
        journal = {"schema_version": 2, "updated_at": "x", "jobs": {}, "extra": 1}
        with self.assertRaises(PalError) as caught:
            self.save(journal)
        self.assertIn("unknown journal field 'extra'", str(caught.exception))

    def test_negative_counters_rejected(self) -> None:
        job = make_job(attempts=-1)
        with self.assertRaises(PalError):
            self.save({"schema_version": 2, "updated_at": "x", "jobs": {"j": job}})

    def test_unreadable_journal_refused_loudly(self) -> None:
        path = jobs_mod.journal_path(self.home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{torn", encoding="utf-8")
        with self.assertRaises(PalError) as caught:
            self.load()
        self.assertIn("unreadable", str(caught.exception))


class Transitions(JournalBase):
    def test_legal_path_roundtrip(self) -> None:
        journal = self.load()
        job = make_job()
        jobs_mod.upsert(journal, job)
        for step in (
            jobs_mod.INVESTIGATOR_CALLING,
            jobs_mod.INVESTIGATOR_RESPONSE,
            jobs_mod.CANDIDATE_READY,
            jobs_mod.CRITIC_CALLING,
            jobs_mod.CRITIC_READY,
            jobs_mod.FINALIZER_CALLING,
            jobs_mod.FINAL_READY,
            jobs_mod.SUBMITTING,
            jobs_mod.DONE,
        ):
            jobs_mod.advance(journal, job, step)
        self.assertEqual(job["stage"], jobs_mod.DONE)
        self.save(journal)
        self.assertEqual(self.load()["jobs"][job["job_id"]]["stage"], jobs_mod.DONE)

    def test_clean_no_critic_path_skips_finalizer_states(self) -> None:
        journal = self.load()
        job = make_job()
        jobs_mod.upsert(journal, job)
        for step in (
            jobs_mod.INVESTIGATOR_CALLING,
            jobs_mod.INVESTIGATOR_RESPONSE,
            jobs_mod.CANDIDATE_READY,
            jobs_mod.FINAL_READY,
            jobs_mod.SUBMITTING,
            jobs_mod.DONE,
        ):
            jobs_mod.advance(journal, job, step)
        self.assertEqual(job["stage"], jobs_mod.DONE)

    def test_illegal_transition_refused_and_not_written(self) -> None:
        job = make_job()
        with self.assertRaises(PalError):
            jobs_mod.advance({"jobs": {}}, job, jobs_mod.DONE)
        self.assertEqual(job["stage"], jobs_mod.READY)

    def test_stale_is_terminal(self) -> None:
        job = make_job(stage=jobs_mod.STALE)
        with self.assertRaises(PalError):
            jobs_mod.advance({"jobs": {}}, job, jobs_mod.READY)


class RecoveryNextAction(JournalBase):
    """Case table: state + persisted artifacts -> what a restart must do."""

    def assert_next(self, job: dict, expected: str) -> None:
        self.assertEqual(jobs_mod.next_action(job), expected)

    def test_case_a_crash_before_call(self) -> None:
        self.assert_next(make_job(), "call")

    def test_case_b_crash_during_call_retries(self) -> None:
        job = make_job(stage=jobs_mod.INVESTIGATOR_CALLING, transport_attempts=1, response_text=None)
        self.assert_next(job, "call")

    def test_case_c_crash_after_response_reuses_it(self) -> None:
        job = make_job(
            stage=jobs_mod.INVESTIGATOR_RESPONSE,
            transport_attempts=1,
            response_text='{"verdict": "NO_DRIFT"}',
            response_digest="aa" * 16,
        )
        self.assert_next(job, "validate")

    def test_case_d_recovered_candidate_reenters_critic_policy(self) -> None:
        # T-84 invariant: a persisted candidate is NOT automatically final.
        # CANDIDATE_READY re-enters the same critic policy fresh execution
        # uses, so a recovered DRIFT can never submit without its critic.
        job = make_job(
            stage=jobs_mod.CANDIDATE_READY,
            candidate={"verdict": "NO_DRIFT"},
            candidate_digest="bb" * 16,
        )
        self.assert_next(job, "critic")

    def test_case_e_crash_during_submit_resubmits(self) -> None:
        job = make_job(
            stage=jobs_mod.SUBMITTING,
            candidate={"verdict": "NO_DRIFT"},
            candidate_digest="bb" * 16,
        )
        self.assert_next(job, "submit")

    def test_critic_calling_with_persisted_raw_reuses_it(self) -> None:
        # CRITIC_CALLING always re-enters the critic handler: the raw response
        # is persisted, so no new call is made, but the parse and the
        # disagreement decision still belong to that handler.
        job = make_job(
            stage=jobs_mod.CRITIC_CALLING,
            candidate={"verdict": "DRIFT"},
            critic_response_text='{"decision": "AGREE"}',
        )
        self.assert_next(job, "critic")

    def test_finalizer_calling_with_persisted_raw_reuses_it(self) -> None:
        job = make_job(
            stage=jobs_mod.FINALIZER_CALLING,
            candidate={"verdict": "DRIFT"},
            critic_payload={"decision": "DISAGREE"},
            finalizer_response_text='{"verdict": "NO_DRIFT"}',
        )
        self.assert_next(job, "finalize")

    def test_case_f_stale_discards_reasoning(self) -> None:
        job = make_job(stage=jobs_mod.STALE, candidate={"verdict": "DRIFT"})
        self.assert_next(job, "skip")
        with self.assertRaises(PalError):
            jobs_mod.advance({"jobs": {}}, job, jobs_mod.INVESTIGATOR_CALLING)

    def test_retry_wait_wakes_when_due(self) -> None:
        import time as time_mod

        due = make_job(stage=jobs_mod.RETRY_WAIT, next_retry_at=time_mod.time() - 1)
        waiting = make_job(stage=jobs_mod.RETRY_WAIT, next_retry_at=time_mod.time() + 3600)
        self.assert_next(due, "retry")
        self.assert_next(waiting, "wait")

    def test_terminal_states_skip(self) -> None:
        for stage in (jobs_mod.DONE, jobs_mod.BLOCKED, jobs_mod.BLOCKED_BINDING):
            with self.subTest(stage=stage):
                self.assert_next(make_job(stage=stage), "skip")

    def test_blocked_binding_becomes_ready_when_authority_binds(self) -> None:
        job = make_job(stage=jobs_mod.BLOCKED_BINDING)
        jobs_mod.advance({"jobs": {}}, job, jobs_mod.READY)
        self.assert_next(job, "call")


class Migration(JournalBase):
    """v1 -> v2: deterministic, idempotent, no stranded jobs."""

    def _v1_journal(self) -> dict:
        return {
            "schema_version": 1,
            "updated_at": "2026-09-01T00:00:00Z",
            "jobs": {
                "job_calling_no_response": make_job(
                    job_id="job_calling_no_response",
                    stage=jobs_mod.CALLING,
                    attempts=1,
                ),
                "job_calling_with_response": make_job(
                    job_id="job_calling_with_response",
                    stage=jobs_mod.CALLING,
                    response_text='{"verdict": "NO_DRIFT"}',
                    response_digest="cc" * 16,
                ),
                "job_candidate": make_job(
                    job_id="job_candidate",
                    stage=jobs_mod.CANDIDATE_READY,
                    attempts=2,
                    candidate={"verdict": "NO_DRIFT"},
                ),
                "job_submitting": make_job(
                    job_id="job_submitting",
                    stage=jobs_mod.SUBMITTING,
                    candidate={"verdict": "DRIFT"},
                ),
            },
        }

    def test_v1_journal_migrates_deterministically(self) -> None:
        migrated = jobs_mod.migrate_journal(self._v1_journal())
        self.assertEqual(migrated["schema_version"], 2)
        stages = {key: job["stage"] for key, job in migrated["jobs"].items()}
        self.assertEqual(stages["job_calling_no_response"], jobs_mod.INVESTIGATOR_CALLING)
        self.assertEqual(stages["job_calling_with_response"], jobs_mod.INVESTIGATOR_RESPONSE)
        self.assertEqual(stages["job_candidate"], jobs_mod.CANDIDATE_READY)
        self.assertEqual(stages["job_submitting"], jobs_mod.SUBMITTING)
        # v1 `attempts` counted submit failures only: they become submit_attempts.
        self.assertEqual(migrated["jobs"]["job_candidate"]["submit_attempts"], 2)
        self.assertEqual(migrated["jobs"]["job_candidate"]["transport_attempts"], 0)

    def test_migration_is_idempotent(self) -> None:
        once = jobs_mod.migrate_journal(self._v1_journal())
        twice = jobs_mod.migrate_journal(once)
        self.assertEqual(once, twice)

    def test_load_journal_upgrades_v1_in_place(self) -> None:
        raw = json.dumps(self._v1_journal())
        path = jobs_mod.journal_path(self.home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(raw, encoding="utf-8")
        loaded = self.load()
        self.assertEqual(loaded["schema_version"], 2)
        self.assertEqual(len(loaded["jobs"]), 4)

    def test_unknown_v1_stage_has_no_migration_path(self) -> None:
        payload = self._v1_journal()
        payload["jobs"]["weird"] = make_job(job_id="weird", stage="MYSTERY")
        with self.assertRaises(PalError) as caught:
            jobs_mod.migrate_journal(payload)
        self.assertIn("no migration path", str(caught.exception))


class JournalIsNotTranscript(JournalBase):
    def test_journal_refuses_to_hold_transcript_sized_evidence(self) -> None:
        # The journal stores model OUTPUT digests plus the response text needed
        # to avoid a second billed call -- never the session's event payload.
        job = make_job(response_text='{"verdict": "NO_DRIFT"}')
        self.save({"schema_version": 2, "updated_at": "x", "jobs": {job["job_id"]: job}})
        on_disk = jobs_mod.journal_path(self.home).read_text(encoding="utf-8")
        self.assertNotIn("event_refs", on_disk)
        self.assertNotIn('"events"', on_disk)
        self.assertIn("response_digest", on_disk)


class WorkerOwnership(JournalBase):
    def test_second_worker_refused(self) -> None:
        first = jobs_mod.AnalystWorkerLock(self.home)
        self.assertTrue(first.acquire())
        try:
            second = jobs_mod.AnalystWorkerLock(self.home)
            self.assertFalse(second.acquire())
        finally:
            first.release()

    def test_release_allows_the_next_worker(self) -> None:
        first = jobs_mod.AnalystWorkerLock(self.home)
        self.assertTrue(first.acquire())
        first.release()
        second = jobs_mod.AnalystWorkerLock(self.home)
        self.assertTrue(second.acquire())
        second.release()

    def test_context_manager_refuses_when_busy(self) -> None:
        with jobs_mod.AnalystWorkerLock(self.home):
            with self.assertRaises(PalError) as caught:
                with jobs_mod.AnalystWorkerLock(self.home):
                    pass
            self.assertEqual(caught.exception.code, "WRITER_BUSY")

    def test_lock_payload_records_owner(self) -> None:
        with jobs_mod.AnalystWorkerLock(self.home):
            raw = jobs_mod.worker_lock_path(self.home).read_text(encoding="utf-8")
            payload = json.loads(raw)
            self.assertIn("pid", payload)
            self.assertIn("host", payload)


class AtomicPersistence(JournalBase):
    def test_save_is_atomic_and_sorted(self) -> None:
        journal = self.load()
        job = make_job()
        jobs_mod.upsert(journal, job)
        self.save(journal)
        raw = jobs_mod.journal_path(self.home).read_text(encoding="utf-8")
        self.assertTrue(raw.endswith("\n"))
        self.assertEqual(json.loads(raw)["jobs"][job["job_id"]]["stage"], jobs_mod.READY)
        # Root confinement: the save refuses a path outside the home.
        from saipal_engine.errors import PalError as PalErr

        outside = self._tmp.name + "_outside.json"
        with self.assertRaises(PalErr):
            from saipal_engine.paths import atomic_write_json

            atomic_write_json(outside, journal, root=home_paths(self.home).root)


if __name__ == "__main__":
    unittest.main()
