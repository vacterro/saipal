"""T-82: telemetry truth and analyst provenance, receipt-linked.

Every control drives the REAL worker; no control is satisfied by inspecting a
hand-built ledger. Telemetry is observational truth: a model call never
counts as examined work, coverage counts only committed receipts, usage is
reported only when the provider actually reported it, and read-only status
surfaces make no network calls and need no key.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pal_test_support as support
from saipal_analyst import jobs as jobs_mod
from saipal_analyst import provenance as provenance_mod
from saipal_analyst.config import default_analyst_config, save_analyst_config
from saipal_engine import submit as submit_module


class TelemetryBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def fresh_home(self, *fixtures: str) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = support.make_home(Path(tmp.name))
        support.put_inbox(home, *fixtures)
        support.run_saipal("continue", home=home)
        return home

    def enable(self, home: Path, backend: object, **budgets: object) -> dict:
        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 0
        budgets.setdefault("max_units_per_run", 1)
        for key, value in budgets.items():
            config["budgets"][key] = value
        save_analyst_config(home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "stub-key"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)
        return config

    def candidate_json(self, home: Path) -> str:
        import test_wave_analyst_repair as repair

        return repair.RepairBase.candidate_for(repair.RepairBase(), home, "NO_DRIFT")

    def critic_json(self, home: Path, decision: str = "AGREE") -> str:
        import test_wave_analyst_repair as repair

        return repair.RepairBase.critic_json(repair.RepairBase(), home, decision)

    def run_worker(self, home: Path) -> dict:
        import test_wave_analyst_repair as repair

        return repair.investigate(home)


class ProvenanceDurability(TelemetryBase):
    def test_committed_receipt_carries_durable_provenance(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_json(home))))

        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1)
        receipt_id = summary["receipts"][0]["receipt_id"]

        ledger = provenance_mod.load_ledger(home)
        record = ledger["records"].get(receipt_id)
        self.assertIsNotNone(record, "every committed receipt carries provenance")
        self.assertEqual(record["model"], "stub-model")
        self.assertEqual(record["backend_type"], "openai_compatible")
        self.assertEqual(record["deliberation_path"], ["investigator"])
        self.assertTrue(record["investigator_digest"])

    def test_provenance_carries_critic_and_finalizer_digests(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("agent-noncompliance-command-route.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(
            repair.RepairBase.candidate_for(repair.RepairBase(), home, "DRIFT")
        )))
        backend.script.append((200, repair.envelope(self.critic_json(home, "DISAGREE"))))
        backend.script.append((200, repair.envelope(
            repair.RepairBase.candidate_for(repair.RepairBase(), home, "NO_DRIFT")
        )))

        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1)
        ledger = provenance_mod.load_ledger(home)
        record = ledger["records"][summary["receipts"][0]["receipt_id"]]
        self.assertEqual(record["deliberation_path"], ["investigator", "critic", "finalizer"])
        self.assertTrue(record["critic_digest"])
        self.assertTrue(record["finalizer_digest"])

    def test_post_submit_provenance_crash_is_reconciled(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_json(home))))

        real_record = provenance_mod.record_provenance

        def record_then_die(home_arg: Path, record: dict) -> dict:
            raise repair.CrashError("provenance write crashed")

        with mock.patch.object(provenance_mod, "record_provenance", record_then_die):
            with self.assertRaises(repair.CrashError):
                self.run_worker(home)

        # The kernel receipt is truth and already committed.
        _status, receipts_payload, _detail = submit_module.load_receipts(home)
        self.assertIsNotNone(receipts_payload)
        self.assertEqual(len(receipts_payload.get("receipts") or []), 1)

        # The journal still names the receipt; the restart resubmits the SAME
        # candidate (kernel idempotency converges to one receipt) and writes
        # the provenance link on the normal path -- no extra model call
        # beyond the resubmit, no duplicate receipt.
        backend.script.append((200, repair.envelope(self.candidate_json(home))))
        summary = self.run_worker(home)
        self.assertEqual(backend.attempts, 1, "recovery makes zero model calls")
        _status, receipts_after, _detail = submit_module.load_receipts(home)
        self.assertEqual(len(receipts_after.get("receipts") or []), 1)
        ledger = provenance_mod.load_ledger(home)
        receipt_id = summary["receipts"][0]["receipt_id"]
        self.assertIn(receipt_id, ledger["records"])
        journal = jobs_mod.load_journal(home)
        missing = provenance_mod.missing_links(journal, ledger)
        self.assertEqual(missing, [], "no receipt may stay without its link")

    def test_reconcile_rebuilds_missing_links_from_journal_alone(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_json(home))))
        self.run_worker(home)

        # Simulate a torn provenance write: the receipt is committed, the
        # journal is DONE, but the ledger lost the record.
        ledger = provenance_mod.load_ledger(home)
        ledger["records"] = {}
        provenance_mod.save_ledger(home, ledger)

        result = provenance_mod.reconcile_provenance(home)
        self.assertEqual(result["reconciled"], 1)
        self.assertEqual(result["missing"], [])

    def test_receipt_without_link_is_a_loud_discrepancy(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_json(home))))
        summary = self.run_worker(home)
        receipt_id = summary["receipts"][0]["receipt_id"]

        ledger = provenance_mod.load_ledger(home)
        self.assertIn(receipt_id, ledger["records"])
        ledger["records"].pop(receipt_id)
        provenance_mod.save_ledger(home, ledger)

        journal = jobs_mod.load_journal(home)
        missing = provenance_mod.missing_links(journal, provenance_mod.load_ledger(home))
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["receipt_id"], receipt_id)

    def test_ledger_schema_is_closed_and_validated(self) -> None:
        ledger = provenance_mod.fresh_ledger()
        self.assertEqual(provenance_mod.ledger_problems(ledger), [])
        bad = dict(ledger)
        bad["unknown_field"] = 1
        problems = provenance_mod.ledger_problems(bad)
        self.assertIn("unknown provenance field 'unknown_field'", problems)

    def test_no_secret_or_transcript_in_provenance(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_json(home))))
        self.run_worker(home)

        raw = provenance_mod.provenance_path(home).read_text(encoding="utf-8")
        for forbidden in ("stub-key", "SAIPAL_ANALYST_API_KEY", "Authorization", "event_refs"):
            self.assertNotIn(forbidden, raw)
        self.assertNotIn(str(home), raw)


class TelemetryTruth(TelemetryBase):
    def test_summary_reports_run_and_usage_truth(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_json(home))))

        summary = self.run_worker(home)
        self.assertEqual(summary["runs_started"], 1)
        self.assertEqual(summary["runs_completed"], 1)
        self.assertEqual(summary["submit_attempts"], 1)
        self.assertEqual(summary["submit_successes"], 1)
        self.assertEqual(summary["stale_refusals"], 0)
        self.assertEqual(summary["kernel_refusals"], 0)
        # The stub backend reports usage on every call: truthfully available.
        self.assertTrue(summary["usage_available"])
        self.assertGreater(summary["total_tokens"], 0)
        self.assertEqual(summary["jobs"], {"DONE": 1})

    def test_usage_absent_is_reported_absent_not_zero_cost(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)

        no_usage = json.dumps(
            {
                "id": "r1",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": self.candidate_json(home)}}],
            }
        ).encode("utf-8")
        backend.script.append((200, no_usage))

        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1)
        self.assertFalse(
            summary["usage_available"],
            "missing provider usage must never read as zero-cost inference",
        )

    def test_model_call_never_counts_as_examined_work(self) -> None:
        import test_wave_analyst_repair as repair
        from saipal_engine import coverage as coverage_mod
        from saipal_engine.registry import load_registry
        from saipal_engine.sessions import load_index

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((429, b"{}"))  # model call, no verdict

        clock = repair.FakeClock()
        summary = self.run_worker(home)
        self.assertEqual(summary["model_calls"] >= 1, True)
        self.assertEqual(summary["jobs_completed"], 0)
        self.assertEqual(len(summary["receipts"]), 0)

        _status, index, _d = load_index(home)
        coverage = coverage_mod.coverage(home, index, registry=load_registry())
        # No committed receipt: coverage must show zero semantic progress for
        # the failed call -- a model call is not examined work.
        self.assertEqual(coverage.get("final_receipts", coverage.get("receipts_total", 0)), 0)

    def test_read_only_status_needs_no_key_and_makes_no_calls(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        os.environ.pop("SAIPAL_ANALYST_API_KEY", None)

        before = backend.attempts
        _code, payload, _err = support.run_saipal_json("analyst-status", home=home)
        self.assertEqual(backend.attempts, before, "status must make zero model calls")
        self.assertIsNotNone(payload)
        self.assertTrue(payload["ok"])
        self.assertIn("jobs_summary", payload)

    def test_journal_migration_write_is_not_triggered_by_status(self) -> None:
        # A v1 journal on disk must stay byte-identical across a read-only
        # status: load_journal upgrades in MEMORY, and only the worker saves.
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        job = jobs_mod.new_job(
            session_id="s",
            episode_index=0,
            slice_index=0,
            unit_digest="d" * 64,
            finality="FINAL",
            backend_type="openai_compatible",
            model="m",
            run_id="r",
        )
        v1 = {
            "schema_version": 1,
            "updated_at": "2026-09-01T00:00:00Z",
            "jobs": {job["job_id"]: job},
        }
        path = jobs_mod.journal_path(home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(v1, indent=2), encoding="utf-8")
        before = path.read_bytes()

        support.run_saipal_json("analyst-status", home=home)
        self.assertEqual(path.read_bytes(), before, "read-only status must not migrate the journal")


if __name__ == "__main__":
    unittest.main()
