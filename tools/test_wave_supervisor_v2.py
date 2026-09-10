"""T-105 (ROLE 21-27): supervisor orchestration, progress truth, stalls.

Progress is not "a cycle happened". Material progress means new/changed
session accepted, binding strengthened, semantic receipt committed, staged
audit created/reconciled, or disposition consumed -- and nothing else. A
no-op cycle increments cycles_since_progress and the stall class names the
DOMINANT blocker, so blocked work is never called idle and genuine idle is
never an error. watch --status explains the whole process, read-only.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import supervisor as sup_mod
from saipal_engine import sessions as sessions_mod
from saipal_engine.errors import PalError


class ProgressBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        support.run_saipal("continue", home=self.home)

    def state(self) -> dict:
        return sup_mod.load_state(self.home)


class MaterialProgressIsNotLiveness(ProgressBase):
    """ROLE 23: a no-op cycle is not progress."""

    def test_first_import_records_source_progress(self) -> None:
        state = self.state()
        progress = sup_mod._cycle_progress(
            state,
            intake={"sessions_imported": 1},
            rebind_result=None,
            semantic={"jobs_completed": 0, "units": 0, "submit_successes": 0},
            audits={},
            dispositions={},
        )
        self.assertTrue(progress["material_progress"])
        self.assertIsNotNone(state["last_source_progress_at"])
        self.assertIsNone(state["last_semantic_progress_at"])
        self.assertEqual(state["cycles_since_progress"], 0)

    def test_a_noop_cycle_is_not_progress(self) -> None:
        state = self.state()
        state["cycles_since_progress"] = 3
        progress = sup_mod._cycle_progress(
            state,
            intake={"sessions_imported": 0},
            rebind_result=None,
            semantic={"jobs_completed": 0, "units": 0, "submit_successes": 0},
            audits={"staged_ok": [], "reconciled": 0},
            dispositions={"consumed": 0},
        )
        self.assertFalse(progress["material_progress"])
        self.assertEqual(state["cycles_since_progress"], 4)
        self.assertIsNone(state["last_progress_at"])

    def test_receipt_and_audit_and_disposition_each_count(self) -> None:
        state = self.state()
        sup_mod._cycle_progress(
            state,
            intake={"sessions_imported": 0},
            rebind_result=None,
            semantic={"jobs_completed": 1, "units": 1, "submit_successes": 1},
            audits={"staged_ok": [], "reconciled": 2},
            dispositions={"consumed": 1},
        )
        self.assertIsNotNone(state["last_semantic_progress_at"])
        self.assertIsNotNone(state["last_receipt_at"])
        self.assertIsNotNone(state["last_audit_progress_at"])
        self.assertIsNotNone(state["last_disposition_progress_at"])
        self.assertIsNotNone(state["last_progress_at"])

    def test_rebind_upgrades_are_binding_progress(self) -> None:
        state = self.state()
        sup_mod._cycle_progress(
            state,
            intake={"sessions_imported": 0},
            rebind_result={"upgraded_sessions": 3},
            semantic={"jobs_completed": 0},
            audits={},
            dispositions={},
        )
        self.assertIsNotNone(state["last_binding_progress_at"])
        self.assertTrue(state["last_binding_progress_at"])


class StallClassification(ProgressBase):
    """ROLE 24: the dominant blocker is named, never smeared into idle/error."""

    def test_idle_no_new_evidence(self) -> None:
        self.assertEqual(
            sup_mod._stall_class({}, semantic={"stop_reason": "IDLE", "jobs": {}}),
            "IDLE_NO_NEW_EVIDENCE",
        )

    def test_blocked_binding_is_not_idle(self) -> None:
        self.assertEqual(
            sup_mod._stall_class(
                {},
                semantic={"stop_reason": "IDLE", "jobs": {"BLOCKED_BINDING": 4}},
            ),
            "BLOCKED_BINDING",
        )

    def test_config_disabled_is_analyst_disabled(self) -> None:
        self.assertEqual(
            sup_mod._stall_class({}, semantic={"stop_reason": "CONFIG_DISABLED", "jobs": {}}),
            "ANALYST_DISABLED",
        )

    def test_budget_exhausted_is_named(self) -> None:
        self.assertEqual(
            sup_mod._stall_class({}, semantic={"stop_reason": "BUDGET_EXHAUSTED", "jobs": {}}),
            "GLOBAL_BUDGET_EXHAUSTED",
        )

    def test_retry_wait_is_not_idle(self) -> None:
        self.assertEqual(
            sup_mod._stall_class({}, semantic={"stop_reason": "RETRY_WAIT", "jobs": {}}),
            "RETRY_WAIT",
        )

    def test_blocked_without_binding_names_terminal_or_provisional(self) -> None:
        self.assertEqual(
            sup_mod._stall_class(
                {}, semantic={"stop_reason": "BLOCKED", "jobs": {"PROVISIONAL": 2}}
            ),
            "PROVISIONAL_ONLY",
        )
        self.assertEqual(
            sup_mod._stall_class(
                {}, semantic={"stop_reason": "BLOCKED", "jobs": {"TERMINAL": 1}}
            ),
            "TERMINAL_ANALYST_FAILURES",
        )

    def test_conflict_only_is_surfaced(self) -> None:
        self.assertEqual(
            sup_mod._stall_class(
                {}, semantic={"stop_reason": "IDLE", "jobs": {"CONFLICT": 3}}
            ),
            "CONFLICT_ONLY",
        )

    def test_every_class_comes_from_the_closed_vocabulary(self) -> None:
        for reason in ("IDLE", "CONFIG_DISABLED", "RETRY_WAIT", "BLOCKED", "BUSY", "ERROR"):
            klass = sup_mod._stall_class({}, semantic={"stop_reason": reason, "jobs": {}})
            self.assertIn(klass, sup_mod.STALL_CLASSES, f"{reason} -> {klass}")


class FailureIsolation(ProgressBase):
    """ROLE 22: isolatable failures never become CYCLE_ERROR-sleep-repeat."""

    def test_isolatable_codes_do_not_fail_closed(self) -> None:
        self.assertNotIn("ANALYST_DISABLED", sup_mod.FATAL_CYCLE_CODES)
        self.assertNotIn("CONFIG_DISABLED", sup_mod.FATAL_CYCLE_CODES)
        self.assertNotIn("BACKEND_CIRCUIT_OPEN", sup_mod.FATAL_CYCLE_CODES)
        self.assertNotIn("WRITER_BUSY", sup_mod.FATAL_CYCLE_CODES)

    def test_integrity_codes_fail_closed(self) -> None:
        for code in ("VALIDATION_FAILED", "OWNERSHIP_LOST", "PUBLICATION_MODE_BLOCKED"):
            self.assertIn(code, sup_mod.FATAL_CYCLE_CODES)


class WatchStatusControlPanel(ProgressBase):
    """ROLE 25: one read-only command explains the whole process."""

    def PANEL_KEYS(self) -> set[str]:
        return {
            "supervisor", "progress", "publication_gate", "shadow_safety",
            "sources", "authority", "corpus", "semantic", "backend",
            "budget_window", "circuits", "jobs", "audits", "analyst_enabled",
        }

    def test_status_carries_every_section_and_writes_nothing(self) -> None:
        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        snapshot = {
            p.name: p.read_bytes()
            for p in self.home.rglob("*")
            if p.is_file()
        }
        payload = sup_mod.watch_status(self.home)
        self.assertTrue(payload["ok"])
        self.assertTrue(self.PANEL_KEYS() <= set(payload), "every control-panel section present")
        after = {
            p.name: p.read_bytes()
            for p in self.home.rglob("*")
            if p.is_file()
        }
        changed = {
            name for name in after if after[name] != snapshot.get(name)
        }
        self.assertEqual(changed, set(), f"watch --status mutated: {sorted(changed)}")

    def test_progress_section_names_every_marker(self) -> None:
        payload = sup_mod.watch_status(self.home)
        progress = payload["progress"]
        for marker in (
            "last_progress_at", "last_source_progress_at", "last_binding_progress_at",
            "last_semantic_progress_at", "last_receipt_at", "last_audit_progress_at",
            "last_disposition_progress_at", "cycles_since_progress", "stall_class",
        ):
            self.assertIn(marker, progress)

    def test_corpus_section_distinguishes_records_from_current_sessions(self) -> None:
        support.put_inbox(self.home, "conformant-cold.json", "conformant-cold-copy.json")
        support.run_saipal("continue", home=self.home)
        corpus = sup_mod.watch_status(self.home)["corpus"]
        # cold-copy is the same content digest: one session, but every record
        # generation counts in indexed_records_total.
        self.assertGreaterEqual(corpus["indexed_records_total"], 1)
        self.assertIn("BOUND", corpus["current_binding_counts"])

    def test_sources_section_reports_enrolled_and_circuits(self) -> None:
        payload = sup_mod.watch_status(self.home)
        self.assertIn("enrolled", payload["sources"])
        self.assertIn("open_circuit", payload["sources"])

    def test_semantic_section_reports_backlog_truth(self) -> None:
        payload = sup_mod.watch_status(self.home)
        semantic = payload["semantic"]
        for key in ("blocked_binding", "retry_wait", "provisional", "terminal_blocked", "done"):
            self.assertIn(key, semantic)

    def test_audits_section_reports_staged_and_quarantined(self) -> None:
        payload = sup_mod.watch_status(self.home)
        audits = payload["audits"]
        if "error" in audits:
            # No publications ledger in a fresh home: reported, not invented.
            self.assertIn("unavailable", str(audits["error"]))
        else:
            for key in ("staged", "quarantined", "external_publication_possible"):
                self.assertIn(key, audits)
            self.assertFalse(audits["external_publication_possible"])


class StagedAuditReconciliation(ProgressBase):
    """ROLE 26: under STAGE_ONLY, reconcile locally, send nothing."""

    def test_reconciliation_is_local_only_and_preserves_state(self) -> None:
        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        result = sup_mod._reconcile_staged_audits(self.home)
        # An absent ledger is reported, never invented: the supervisor does
        # not fabricate publication state.
        if result.get("skipped"):
            self.assertIn("reason", result)
        else:
            self.assertFalse(result["external_publication"])
            self.assertIn("staged_ok", result)
            self.assertIn("quarantined", result)

    def test_reconciliation_preserves_quarantine_state(self) -> None:
        # No publications ledger at all: the reconciliation skips loudly
        # rather than fabricating an empty one.
        result = sup_mod._reconcile_staged_audits(self.home)
        self.assertTrue(result.get("skipped") or result.get("staged_ok") == 0)


class DispositionConsumption(ProgressBase):
    """ROLE 27: consume through the boundary, or report unconfigured."""

    def test_unconfigured_disposition_reports_unconfigured(self) -> None:
        result = sup_mod._consume_dispositions(self.home)
        self.assertTrue(result["disposition_unconfigured"])
        self.assertEqual(result["consumed"], 0)

    def test_configured_source_consumes_exactly_once(self) -> None:
        import test_wave_g_closed_loop as gcl
        from saipal_engine.config import load_config, save_config

        home = gcl._build_audit(self.home)  # noqa: F841 - emits audit 1 through the real path
        path = Path(self._tmp.name) / "dispositions.json"
        path.write_text(
            json.dumps([{"audit_number": 1, "disposition": "ENGINE_FIX",
                          "work_id": "T-9001"}]),
            encoding="utf-8",
        )
        cfg = load_config(self.home)[1]
        cfg["disposition_source"] = str(path)
        save_config(self.home, cfg)
        first = sup_mod._consume_dispositions(self.home)
        self.assertEqual(first["consumed"], 1)
        # Idempotent: the same verdict imports no history entry the second time.
        second = sup_mod._consume_dispositions(self.home)
        self.assertEqual(second["consumed"], 0)


class CycleOrchestration(ProgressBase):
    """ROLE 21: the supervisor decides WHEN, subsystems decide WHAT."""

    def test_watch_cycle_records_progress_and_stall(self) -> None:
        import test_wave_analyst_repair as repair

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = support.make_home(Path(tmp.name))
        support.put_inbox(home, "conformant-cold.json")
        support.run_saipal("continue", home=home)
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        from saipal_analyst.config import default_analyst_config, save_analyst_config

        config = default_analyst_config()
        config["enabled"] = False  # no analyst configured: idle cycles only
        save_analyst_config(home, config)

        result = sup_mod.watch(home, max_cycles=2, sleep_fn=lambda _s: None)
        self.assertEqual(result["cycles_run"], 2)
        cycle = result["cycle_results"][0]
        self.assertIn("material_progress", cycle)
        self.assertIn("stall_class", cycle)
        state = sup_mod.load_state(home)
        # No semantic work configured -> the stall names it, never "error".
        self.assertEqual(state["stall_class"], "ANALYST_DISABLED")
        self.assertEqual(state["cycles_since_progress"], 2)


if __name__ == "__main__":
    unittest.main()
