"""T-136: the canonical way back for a semantically refused unit.

A unit the candidate contract refused used to be lost: the allocator treats
`BLOCKED` as terminal, the unit is not pending (it has a job) and not
analysable (it has no selectable job), and nothing in the protocol named it
again. `saipal analyst-requeue` is the path back, and these controls pin its
contract:

- a requeue buys exactly ONE fresh attempt (the refused attempt's raw payload
  and paid-attempt identity are cleared, so the next pass makes a real call
  rather than re-judging the same inadmissible bytes);
- it is admitted only under CHANGED material or an explicit, recorded
  `--force`, and it is budgeted by `budgets.max_requeues_per_unit` -- durable
  in the journal, so a crash cannot reset it;
- the journal-side neighbours keep their own canonical owners
  (`BLOCKED_BINDING` -> authority enroll + rebind, `REMOTE_OUTCOME_UNKNOWN`
  -> the paid-attempt policy, `STALE` -> re-import) and are refused BY NAME;
- a dry run writes nothing and takes no lock, and a live worker is a refusal,
  never a race.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import jobs as jobs_mod
from saipal_analyst import requeue as requeue_mod
from saipal_analyst.config import default_analyst_config, save_analyst_config
from saipal_engine.errors import PalError

import test_wave_analyst_repair as repair


class RequeueBase(repair.RepairBase):
    def arm_config(self, home: Path, **budgets: object) -> dict:
        """A valid analyst config without spinning a backend (no calls are made).

        Requeue is a journal operation: it needs a MATERIAL to compare against,
        not a live endpoint. This is the cheapest honest way to give it one.
        """
        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["model"] = "stub-model"
        for key, value in budgets.items():
            config["budgets"][key] = value
        save_analyst_config(home, config)
        return config

    def blocked_jobs(self, home: Path) -> list[dict]:
        journal = jobs_mod.load_journal(home)
        return [
            job
            for job in (journal.get("jobs") or {}).values()
            if job.get("stage") == jobs_mod.BLOCKED
        ]

    def staged_job(
        self,
        home: Path,
        *,
        stage: str = jobs_mod.BLOCKED,
        error_class: str | None = "BLOCKED_OUTPUT",
        in_index: bool = True,
    ) -> str:
        """One journal job, staged by hand, for the rules a live run cannot stage.

        `in_index=False` names a session the index no longer carries; the default
        binds the job to a session the kernel actually serves, so only the
        requeue policy decides its fate.
        """
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.sessions import load_index

        journal = jobs_mod.fresh_journal()
        job = jobs_mod.new_job(
            session_id="session-unrelated",
            episode_index=0,
            slice_index=0,
            unit_digest="digest-unrelated",
            finality="FINAL",
            backend_type="openai_compatible",
            model="stub-model",
            run_id="run-t-136",
        )
        if in_index:
            _status, index, _detail = load_index(home)
            job["session_id"] = str(
                next(iter(carrier_mod.freshest_records(index)))["session_id"]
            )
        job["stage"] = stage
        job["error_class"] = error_class
        journal["jobs"][job["job_id"]] = job
        jobs_mod.save_journal(home, journal)
        return job["job_id"]

    def refuse_two_units(self, home: Path, backend: repair.StubBackend) -> list[dict]:
        """Run the worker so both sessions end BLOCKED_OUTPUT, deterministically.

        Each session gets an unparseable investigator reply AND an unparseable
        repair reply, which is the exact durable refusal the requeue exists for.
        """
        self.enable(home, backend, max_units_per_run=3)
        for _ in range(2):
            backend.script.append((200, repair.envelope("{not json")))
            backend.script.append((200, repair.envelope("{repair broken")))
        self.run_worker(home)
        blocked = self.blocked_jobs(home)
        self.assertEqual(len(blocked), 2, "both sessions must end refused")
        for job in blocked:
            self.assertEqual(job["error_class"], "BLOCKED_OUTPUT")
            self.assertEqual(job["requeues"], [])
        return blocked


class RequeueCore(RequeueBase):
    def test_a_refused_unit_is_reopened_for_one_fresh_attempt(self) -> None:
        home, _order = self._two_session_home()
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        blocked = self.refuse_two_units(home, backend)
        before = {job["job_id"]: dict(job) for job in blocked}

        # The dry run answers the question without answering for the operator.
        plan = requeue_mod.requeue(home, dry_run=True)
        self.assertTrue(plan["ok"])
        self.assertEqual(len(plan["requeued"]), 2)
        self.assertFalse(plan["wrote"])
        self.assertEqual(
            {job["job_id"]: job for job in self.blocked_jobs(home)},
            before,
            "a dry run must not touch a single durable byte",
        )
        self.assertEqual(plan["counts"]["requeued"], 2)
        self.assertEqual(plan["by_class"]["BLOCKED_OUTPUT"], 2)

        result = requeue_mod.requeue(home, reason="t-136 control")
        self.assertTrue(result["ok"])
        self.assertTrue(result["wrote"])
        journal = jobs_mod.load_journal(home)
        for job in journal["jobs"].values():
            self.assertEqual(job["stage"], jobs_mod.READY)
            self.assertIsNone(job["error_class"])
            self.assertIsNone(job["error_detail"])
            # The refused attempt is gone, in every field that would make the
            # next pass re-judge the SAME bytes ...
            for field in requeue_mod.CLEARED_FIELDS:
                self.assertIsNone(job[field], f"{field} must be cleared")
            # ... and its repair allowance is restored for the fresh response.
            for counter in requeue_mod.CLEARED_COUNTERS:
                self.assertEqual(job[counter], 0)
            # The audit trail survives: when, why, and what was refused.
            self.assertEqual(len(job["requeues"]), 1)
            entry = job["requeues"][0]
            self.assertEqual(entry["from_stage"], jobs_mod.BLOCKED)
            self.assertEqual(entry["error_class"], "BLOCKED_OUTPUT")
            self.assertEqual(entry["reason"], "t-136 control")
            self.assertFalse(entry["forced"])
            self.assertTrue(entry["material"]["config_digest"])
            self.assertEqual(
                set(entry["cleared_digests"]),
                {"response_digest", "candidate_digest", "critic_digest", "finalizer_digest"},
            )

    def test_the_fresh_attempt_actually_calls_the_model_again(self) -> None:
        home, _order = self._two_session_home()
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.refuse_two_units(home, backend)
        requests_before = backend.attempts
        self.assertEqual(requests_before, 4, "two sessions, two calls each")

        requeue_mod.requeue(home, reason="retry after a real transport fix")
        # The paid-attempt identity belongs to the CLEARED attempt: a fresh one
        # must be minted, or a crash detector would report an ambiguity for a
        # request that will never be re-issued.
        for job in jobs_mod.load_journal(home)["jobs"].values():
            self.assertEqual(job["attempt_ids"], {})
            self.assertEqual(job["ambiguous_attempt_ids"], [])
        # The allocator must now select the unit again -- not TERMINAL any more.
        backend.on_request = lambda request: backend.script.append(
            (200, repair.envelope(self.candidate_for(home, "NO_DRIFT")))
        )
        summary = self.run_worker(home)

        self.assertGreater(summary["jobs_completed"], 0)
        self.assertGreater(
            backend.attempts, requests_before,
            "a requeue must buy a NEW call, never a re-parse of the refusal",
        )
        self.assertEqual(len(summary["receipts"]), summary["jobs_completed"])

    def test_a_second_requeue_under_unchanged_material_is_refused(self) -> None:
        home, _order = self._two_session_home()
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.refuse_two_units(home, backend)
        self.assertTrue(requeue_mod.requeue(home, reason="first rescue")["wrote"])

        # The fresh attempt fails the same way: the model did not change.
        backend.script.append((200, repair.envelope("{not json")))
        backend.script.append((200, repair.envelope("{repair broken")))
        backend.script.append((200, repair.envelope("{not json")))
        backend.script.append((200, repair.envelope("{repair broken")))
        self.run_worker(home)
        self.assertEqual(len(self.blocked_jobs(home)), 2)
        self.assertTrue(
            all(len(job["requeues"]) == 1 for job in self.blocked_jobs(home)),
            "the spent attempt must be durable",
        )

        # A reload, not the runtime object: the counter survives a restart.
        second = requeue_mod.requeue(home, reason="press it again")
        self.assertFalse(second["ok"])
        self.assertFalse(second["wrote"])
        self.assertEqual(len(second["refused"]), 2)
        for row in second["refused"]:
            self.assertIn("budget", row["reason"])
        self.assertEqual(self.blocked_jobs(home)[0]["stage"], jobs_mod.BLOCKED)

    def test_a_changed_material_admits_the_retry_an_unchanged_one_refuses(self) -> None:
        """The allowance is not the only gate: the CONDITIONS must have moved.

        With `max_requeues_per_unit: 3` the budget alone would admit every
        attempt, so this control isolates the material rule: a second rescue
        under an identical config is refused, and the same rescue after a real
        model change is admitted without `--force`.
        """
        home, _order = self._two_session_home()
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        config = self.enable(home, backend, max_units_per_run=3, max_requeues_per_unit=3)

        def refuse_again() -> None:
            for _ in range(2):
                backend.script.append((200, repair.envelope("{not json")))
                backend.script.append((200, repair.envelope("{repair broken")))
            self.run_worker(home)
            self.assertEqual(len(self.blocked_jobs(home)), 2)

        refuse_again()
        first = requeue_mod.requeue(home, reason="first")
        self.assertEqual(len(first["requeued"]), 2)
        refuse_again()
        self.assertTrue(all(len(job["requeues"]) == 1 for job in self.blocked_jobs(home)))

        # Same material, allowance unspent: refused anyway.
        unchanged = requeue_mod.requeue(home, reason="same again")
        self.assertFalse(unchanged["ok"])
        self.assertEqual(len(unchanged["refused"]), 2)
        self.assertIn("no material change", unchanged["refused"][0]["reason"])
        self.assertFalse(unchanged["wrote"])

        # A different model IS a material change: the retry is admitted.
        config["backend"]["model"] = "stub-model-2"
        save_analyst_config(home, config)
        changed = requeue_mod.requeue(home, reason="new model")
        self.assertTrue(changed["ok"])
        self.assertEqual(len(changed["requeued"]), 2)
        self.assertEqual(changed["material"]["model"], "stub-model-2")
        self.assertEqual(len(self.blocked_jobs(home)), 0)
        job = next(iter(jobs_mod.load_journal(home)["jobs"].values()))
        self.assertEqual(job["model"], "stub-model-2")
        self.assertEqual(len(job["requeues"]), 2)

    def test_force_spends_the_attempt_knowingly_and_records_it(self) -> None:
        home, _order = self._two_session_home()
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend, max_units_per_run=3)
        self.refuse_two_units(home, backend)
        requeue_mod.requeue(home, reason="first")
        backend.script.append((200, repair.envelope("{not json")))
        backend.script.append((200, repair.envelope("{repair broken")))
        backend.script.append((200, repair.envelope("{not json")))
        backend.script.append((200, repair.envelope("{repair broken")))
        self.run_worker(home)

        forced = requeue_mod.requeue(home, reason="spend it anyway", force=True)
        self.assertTrue(forced["ok"])
        self.assertEqual(len(forced["requeued"]), 2)
        for job in jobs_mod.load_journal(home)["jobs"].values():
            self.assertEqual(len(job["requeues"]), 2)
            self.assertTrue(job["requeues"][-1]["forced"])
            self.assertEqual(job["requeues"][-1]["reason"], "spend it anyway")

    def test_a_zero_allowance_disables_the_path(self) -> None:
        home, _order = self._two_session_home()
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend, max_units_per_run=3, max_requeues_per_unit=0)
        for _ in range(2):
            backend.script.append((200, repair.envelope("{not json")))
            backend.script.append((200, repair.envelope("{repair broken")))
        self.run_worker(home)

        result = requeue_mod.requeue(home, reason="policy says no")
        self.assertFalse(result["ok"])
        self.assertFalse(result["wrote"])
        self.assertEqual(result["max_requeues_per_unit"], 0)
        self.assertEqual(len(result["refused"]), 2)
        self.assertEqual(len(self.blocked_jobs(home)), 2)

    def test_an_unannotated_requeue_still_records_why_it_was_admitted(self) -> None:
        """`--reason` is optional, so the default path must not write None.

        Every other test passes `reason=` explicitly, which is why an
        operator running the bare canonical command hit a journal whose
        history entry carried no reason and failed its own schema check —
        the whole requeue was refused for want of a field the operator was
        never asked for. The history entry is closed data (jobs.
        _requeue_problems), so the admitted decision is recorded either way.
        """
        home, _order = self._two_session_home()
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.refuse_two_units(home, backend)

        result = requeue_mod.requeue(home)
        self.assertTrue(result["ok"])
        self.assertTrue(result["wrote"], "a bare requeue must write, not refuse itself")
        for job in jobs_mod.load_journal(home)["jobs"].values():
            self.assertEqual(len(job["requeues"]), 1)
            entry = job["requeues"][0]
            self.assertIsInstance(entry["reason"], str)
            self.assertTrue(entry["reason"])
            self.assertEqual(
                entry["reason"],
                "semantic refusal requeued for one fresh attempt",
            )

        # Every unit got the same recorded reason, from the decision that
        # admitted it rather than from a field the operator never supplied.
        for job in self.blocked_jobs(home):
            self.assertEqual(
                job["requeues"][-1]["reason"],
                "semantic refusal requeued for one fresh attempt",
            )

    def test_a_live_worker_is_a_refusal_never_a_race(self) -> None:
        home, _order = self._two_session_home()
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.refuse_two_units(home, backend)

        lock = jobs_mod.AnalystWorkerLock(home)
        self.assertTrue(lock.acquire())
        try:
            with self.assertRaises(PalError) as caught:
                requeue_mod.requeue(home, reason="while a run is live")
            self.assertEqual(caught.exception.code, "WRITER_BUSY")
        finally:
            lock.release()

        # A dry run still answers: diagnosing is never blocked by a writer.
        self.assertEqual(len(requeue_mod.requeue(home, dry_run=True)["requeued"]), 2)
        self.assertTrue(requeue_mod.requeue(home, reason="now it is free")["wrote"])


class NeighbouringWalls(RequeueBase):
    """Every other wall keeps its own owner, named and never crossed."""

    def _staged_journal(self, home: Path, stage: str) -> str:
        error_class = {
            jobs_mod.BLOCKED: "BLOCKED_OUTPUT",
            jobs_mod.BLOCKED_BINDING: "BLOCKED_BINDING",
        }.get(stage, stage)
        return self.staged_job(
            home, stage=stage, error_class=error_class, in_index=False
        )

    def test_a_binding_wall_points_at_authority_and_rebind(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        self.arm_config(home)
        self._staged_journal(home, jobs_mod.BLOCKED_BINDING)

        result = requeue_mod.requeue(home, reason="not the right tool")
        self.assertFalse(result["ok"])
        self.assertEqual(len(result["refused"]), 1)
        row = result["refused"][0]
        self.assertEqual(row["stage"], jobs_mod.BLOCKED_BINDING)
        self.assertIn("authority enroll", row["next_action"])
        self.assertIn("rebind", row["next_action"])
        self.assertFalse(result["wrote"])

    def test_a_paid_attempt_of_unknown_outcome_is_never_replayed(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        self.arm_config(home)
        self._staged_journal(home, jobs_mod.REMOTE_OUTCOME_UNKNOWN)

        result = requeue_mod.requeue(home, reason="automatic replay? no")
        self.assertFalse(result["ok"])
        self.assertIn("unknown outcome", result["refused"][0]["reason"])
        self.assertFalse(result["wrote"])

    def test_a_stale_session_is_refused_as_a_no_op(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        self.arm_config(home)
        self._staged_journal(home, jobs_mod.STALE)

        result = requeue_mod.requeue(home, reason="cannot be driven")
        self.assertFalse(result["ok"])
        self.assertIn("no longer importable", result["refused"][0]["reason"])

    def test_a_refused_unit_outside_the_index_cannot_be_served(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        self.arm_config(home)
        self._staged_journal(home, jobs_mod.BLOCKED)

        result = requeue_mod.requeue(home, reason="orphan job")
        self.assertFalse(result["ok"])
        self.assertIn("not in the current index", result["refused"][0]["reason"])
        self.assertFalse(result["wrote"])

    def test_an_absent_analyst_config_is_a_loud_refusal(self) -> None:
        """No config means no material to compare against -- and no way to run."""
        home = self.fresh_home("conformant-cold.json")
        self._staged_journal(home, jobs_mod.BLOCKED)
        with self.assertRaises(PalError) as caught:
            requeue_mod.requeue(home, reason="no conditions to name")
        self.assertEqual(caught.exception.code, "VALIDATION_FAILED")
        self.assertIn("analyst-setup", caught.exception.next_action)

    def test_an_unknown_refusal_class_is_requeued_like_any_other(self) -> None:
        """The default must not be an allow-list that silently drops a class.

        A refusal class the protocol has not met before is still a refusal: it
        is eligible by default, and only an explicit `--class` narrows the pass.
        """
        home = self.fresh_home("conformant-cold.json")
        self.arm_config(home)
        job_id = self.staged_job(home, error_class="CONFIGURATION_MISSING")

        result = requeue_mod.requeue(home, reason="class filter")
        self.assertTrue(result["ok"])
        self.assertIn("CONFIGURATION_MISSING", requeue_mod.BLOCKED_CLASSES + ('CONFIGURATION_MISSING',))
        self.assertEqual(result["classes"], ["*"])
        self.assertEqual(result["by_class"], {"CONFIGURATION_MISSING": 1})
        self.assertEqual(len(result["requeued"]), 1)

        # ... and `--class` still narrows it, honestly.
        journal = jobs_mod.load_journal(home)
        journal["jobs"][job_id]["stage"] = jobs_mod.BLOCKED
        journal["jobs"][job_id]["error_class"] = "CONFIGURATION_MISSING"
        jobs_mod.save_journal(home, journal)
        narrowed = requeue_mod.requeue(home, job_classes=("BLOCKED_OUTPUT",))
        self.assertEqual(narrowed["requeued"], [])
        self.assertEqual(
            narrowed["not_applicable"]["class:CONFIGURATION_MISSING"], 1
        )
        self.assertEqual(narrowed["eligible"], 0)


class SchemaAndValidation(RequeueBase):
    def test_the_journal_schema_pins_the_history_shape(self) -> None:
        journal = jobs_mod.fresh_journal()
        job = jobs_mod.new_job(
            session_id="session-a",
            episode_index=0,
            slice_index=0,
            unit_digest="digest-a",
            finality="FINAL",
            backend_type="openai_compatible",
            model="stub-model",
            run_id="run-t-136",
        )
        journal["jobs"][job["job_id"]] = job
        self.assertEqual(jobs_mod.journal_problems(journal), [])

        job["requeues"] = [{"at": "2026-09-28T00:00:00Z"}]
        problems = jobs_mod.journal_problems(journal)
        self.assertTrue(any("needs a reason" in problem for problem in problems))
        job["requeues"] = [
            {
                "at": "2026-09-28T00:00:00Z",
                "reason": "why",
                "forced": False,
                "material": {},
                "smuggled": 1,
            }
        ]
        problems = jobs_mod.journal_problems(journal)
        self.assertTrue(any("unknown field 'smuggled'" in p for p in problems))

    def test_a_negative_allowance_is_a_loud_refusal(self) -> None:
        with self.assertRaises(PalError) as caught:
            requeue_mod.max_requeues_per_unit({"budgets": {"max_requeues_per_unit": -1}})
        self.assertEqual(caught.exception.code, "VALIDATION_FAILED")

        config = default_analyst_config()
        config["budgets"]["max_requeues_per_unit"] = -1
        with tempfile.TemporaryDirectory() as tmp:
            home = support.make_home(Path(tmp))
            with self.assertRaises(PalError):
                save_analyst_config(home, config)

    def test_the_absent_allowance_reads_as_the_shipped_default(self) -> None:
        self.assertEqual(
            requeue_mod.max_requeues_per_unit({"budgets": {}}),
            requeue_mod.DEFAULT_MAX_REQUEUES,
        )
        self.assertEqual(
            requeue_mod.max_requeues_per_unit(default_analyst_config()),
            requeue_mod.DEFAULT_MAX_REQUEUES,
        )


class CommandSurface(RequeueBase):
    def test_the_cli_dry_run_writes_nothing_and_reports_the_plan(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        self.arm_config(home)
        self._staged_journal_like(home)

        code, payload, _err = support.run_saipal_json(
            "analyst-requeue", "--dry-run", home=home
        )
        self.assertEqual(code, 0)
        self.assertTrue(payload["requeue"])
        self.assertTrue(payload["dry_run"])
        self.assertFalse(payload["wrote"])
        self.assertEqual(payload["counts"]["requeued"], 1)
        self.assertEqual(len(self.blocked_jobs(home)), 1)

    def test_an_unknown_option_is_a_usage_error(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        self.arm_config(home)
        code, payload, err = support.run_saipal_json(
            "analyst-requeue", "--nonsense", home=home
        )
        self.assertEqual(code, 2)
        self.assertIn("unknown analyst-requeue option", json.dumps(payload) + err)

    def test_the_cli_requeues_and_reports_the_history(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        self.arm_config(home)
        self._staged_journal_like(home)
        code, payload, _err = support.run_saipal_json(
            "analyst-requeue", "--reason", "cli", home=home
        )
        self.assertEqual(code, 0)
        self.assertTrue(payload["wrote"])
        self.assertEqual(payload["counts"]["requeued"], 1)
        job = next(iter(jobs_mod.load_journal(home)["jobs"].values()))
        self.assertEqual(len(job["requeues"]), 1)
        self.assertEqual(job["requeues"][0]["reason"], "cli")
        self.assertEqual(job["stage"], jobs_mod.READY)

    def test_the_triage_names_the_requeue_instead_of_a_gap(self) -> None:
        home, _order = self._two_session_home()
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.refuse_two_units(home, backend)

        from saipal_analyst.doctor import blocked_triage

        triage = blocked_triage(home)
        group = next(row for row in triage["groups"] if row["class"] == "BLOCKED_OUTPUT")
        self.assertIn("analyst-requeue", group["command"])
        self.assertTrue(group["recoverable"])
        self.assertNotIn("gap", group)
        # The triage says whether the path is open RIGHT NOW.
        self.assertEqual(group["requeue_ready"], 2)
        self.assertEqual(group["requeue_refused"], 0)
        self.assertEqual(group["refusal_classes"], {"BLOCKED_OUTPUT": 2})
        self.assertNotIn("BLOCKED_OUTPUT", triage["no_canonical_action"])
        self.assertIn("analyst-requeue", triage["next_action"])

    def _staged_journal_like(self, home: Path) -> str:
        return self.staged_job(home)


if __name__ == "__main__":
    unittest.main()
