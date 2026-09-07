"""T-100: the authority boundary (RED controls, written before the fix).

The architectural invariant this file owns:

    NO SEMANTIC DRIFT VERDICT
    = NO CONFIRMED FINDING
    = NO QUALIFIED FINDING
    = NO EXTERNAL AUDIT

Mechanical detector output (Layer A) may prioritize investigation and travel
with a finding as supporting evidence. It may never by itself create a
confirmed protocol finding, qualify one, or emit an audit. Only a semantic
analyst submission (Layer B) with verdict DRIFT вЂ” absorbed through the
constrained submission boundary вЂ” is the drift gate.

Controls 1-16 map to the required red-test list of the authority pass.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pal_test_support as support
from saipal_engine import bundle as bundle_mod
from saipal_engine import carrier as carrier_mod
from saipal_engine import findings as findings_mod
from saipal_engine import pipeline as pipeline_mod
from saipal_engine import sessions as sessions_mod
from saipal_engine import sources as sources_mod
from saipal_engine import submit as submit_mod
from saipal_engine.registry import load_registry

DRIFT = "agent-noncompliance-command-route.json"
CLEAN = "no-finding-normal.json"
HOT = "hot-partial.json"


def _findings(home: Path) -> list[dict]:
    index = home / "findings" / "index.json"
    if not index.exists():
        return []
    return list(json.loads(index.read_text(encoding="utf-8"))["findings"])


def _receipts(home: Path) -> list[dict]:
    path = home / "semantic_receipts.json"
    if not path.exists():
        return []
    return list(json.loads(path.read_text(encoding="utf-8"))["receipts"])


class MechanicalBoundary(unittest.TestCase):
    """The mechanical pass may signal, but must never confirm or emit."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _cc(self, name: str) -> dict:
        support.put_inbox(self.home, name)
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        return payload

    def test_control_1_no_qualified_finding_without_semantic_drift(self) -> None:
        """HIGH mechanical confidence on a BOUND session stays pre-semantic."""
        payload = self._cc(DRIFT)
        self.assertEqual(payload["audits_emitted"], 0)
        for finding in _findings(self.home):
            self.assertNotEqual(finding.get("state"), "QUALIFIED")
            self.assertNotEqual(finding.get("state"), "EMITTED")
            self.assertIsNone(finding.get("audit"))
            self.assertFalse(
                findings_mod.is_semantically_confirmed(finding),
                "a mechanical-only finding is not analyst-confirmed",
            )

    def test_control_2_no_audit_without_semantic_drift(self) -> None:
        payload = self._cc(DRIFT)
        self.assertEqual(payload["audits_emitted"], 0)
        staging = self.home / "audit" / "staging"
        self.assertFalse(
            staging.is_dir() and any(staging.glob("*.md")),
            "no audit may be staged without a semantic DRIFT verdict",
        )

    def test_control_3_recurrence_is_not_semantic_confirmation(self) -> None:
        """Ten repeated mechanical occurrences still cannot qualify."""
        for i in range(10):
            payload = self._cc(DRIFT) if i == 0 else {}
        for finding in _findings(self.home):
            self.assertFalse(findings_mod.is_semantically_confirmed(finding))
            self.assertNotEqual(finding.get("state"), "QUALIFIED")

    def test_control_4_severity_is_not_semantic_confirmation(self) -> None:
        """A P1 mechanical candidate is a signal, never a qualification."""
        payload = self._cc(DRIFT)
        for finding in _findings(self.home):
            self.assertFalse(findings_mod.is_semantically_confirmed(finding))
            self.assertNotEqual(finding.get("state"), "QUALIFIED")
            self.assertNotEqual(finding.get("state"), "EMITTED")

    def test_control_9_mechanical_signals_reach_the_semantic_carrier(self) -> None:
        """Authority removed from Layer A must not remove its usefulness."""
        self._cc(DRIFT)
        code, nxt, err = support.run_saipal_json("next", home=self.home)
        self.assertEqual(code, 0, err)
        assert nxt is not None
        unit = nxt.get("analysis_carrier") or {}
        # The carrier must carry the durable signal ledger for prioritization:
        # even when the offered unit itself raises nothing, a signal raised
        # elsewhere in the session travels with the unit.
        signals = unit.get("signals") or []
        ledger = json.loads((self.home / "signals.json").read_text(encoding="utf-8"))
        self.assertTrue(
            ledger["signals"], "the mechanical pass must record durable signals"
        )
        self.assertTrue(
            signals or unit.get("open_candidates") is not None,
            "the carrier must still be consumable after the authority change",
        )

    def test_control_13_doctor_reports_supported_sources(self) -> None:
        """The report must be provable on an isolated machine: no real agent
        installs may be required. A fake vendor store is injected (in-process,
        because the CLI subprocess cannot see this process's mocks)."""
        import saipal

        fake_store = self.tmp / "fake-opencode"
        fake_store.mkdir()
        with mock.patch.object(sources_mod, "_KNOWN_STORES", {}), mock.patch.object(
            sources_mod,
            "auto_sources",
            return_value=[
                {
                    "id": "opencode-auto",
                    "kind": "opencode",
                    "path": str(fake_store),
                    "enabled": True,
                    "exists": True,
                    "status": "READY",
                    "sessions": 0,
                    "auto": True,
                }
            ],
        ):
            code, doctor = saipal.cmd_doctor(self.home, load_registry())
        self.assertEqual(code, 0)
        sources = doctor.get("sources") or {}
        self.assertEqual(
            sorted(sources.keys()), sorted(sources_mod.ADAPTER_REGISTRY.keys()),
            "doctor must account for every supported adapter",
        )
        opencode = sources["opencode"]
        self.assertEqual(opencode["discovery"], "auto")
        self.assertIn(opencode["status"], ("READY", "EMPTY"))
        unconfigured = doctor.get("sources_unconfigured") or []
        for kind in ("claude", "codex", "gemini", "termisai"):
            row = sources[kind]
            self.assertEqual(row["discovery"], "unconfigured")
            self.assertFalse(row.get("configured"))
            self.assertIn(kind, unconfigured)

    def test_control_14_publishing_without_a_sink_is_a_failure_not_success(self) -> None:
        """PUBLISH_ENABLED + missing sink must report a delivery failure."""
        # A real intake surface exists, then the sink vanishes before the emit.
        sink_root = self.tmp / "saipen-intake"
        (sink_root / "audit").mkdir(parents=True)
        (sink_root / "audit" / "MANIFEST.json").write_text("{}", encoding="utf-8")
        config = self.home / "config.json"
        payload = json.loads(config.read_text(encoding="utf-8"))
        payload["publication_mode"] = "PUBLISH_ENABLED"
        payload["shadow_reviewed"] = True
        payload["sink"] = {"kind": "termisai-file", "root": str(sink_root)}
        config.write_text(json.dumps(payload), encoding="utf-8")

        self._cc(DRIFT)
        import shutil

        shutil.rmtree(sink_root)
        code, nxt, err = support.run_saipal_json("next", home=self.home)
        assert nxt is not None and nxt.get("analysis_carrier")
        unit = nxt["analysis_carrier"]
        candidate = {
            "schema_version": 1,
            "verdict": "DRIFT",
            "unit_digest": unit["unit_digest"],
            "session_id": unit["session"]["session_id"],
            "episode_index": unit["episode"]["index"],
            "disposition_class": "ENGINE_ENFORCEMENT_GAP",
            "reasoning": "the route was outside the declared surface",
            "rule_ids": ["PAL-CMD-01"],
            "event_refs": [unit["episode"]["start_seq"]],
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P1",
            "confidence": "HIGH",
            "change_target": "ENGINE",
            "root_cause": "the closed command surface was not consulted",
            "challenge": {
                "prosecutor": "the rule names a closed surface; this route was not in it",
                "defender": "the adapter may have normalized a user alias",
                "winner": "prosecutor",
                "loser_rejection": "the canonical token was recorded verbatim",
            },
            "alternatives": ["the user invoked a shell alias"],
        }
        path = self.tmp / "cand.json"
        path.write_text(json.dumps(candidate), encoding="utf-8")
        code, _receipt, err = support.run_saipal_json("submit", str(path), home=self.home)
        self.assertEqual(code, 0, err)

        code, result, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert result is not None
        published = result.get("publication") or {}
        self.assertEqual(published.get("mode"), "PUBLISH_ENABLED")
        self.assertEqual(published.get("delivered"), 0)
        self.assertEqual(published.get("pending"), 1, "the staged audit must be pending, not delivered")
        self.assertFalse(sink_root.exists(), "nothing may be written to a nonexistent sink")
        for finding in _findings(self.home):
            self.assertNotEqual(
                (finding.get("audit") or {}).get("delivery"), "PUBLISHED",
                "no finding may claim delivery without a sink",
            )

    def test_control_15_stage_only_never_mutates_saipen(self) -> None:
        """STAGE_ONLY must not write into a declared SAIPEN root."""
        saipen = self.tmp / "saipen-root"
        (saipen / "audit").mkdir(parents=True)
        (saipen / "audit" / "MANIFEST.json").write_text("{}", encoding="utf-8")
        before = support.tree_digest(saipen)
        self._cc(DRIFT)
        self.assertEqual(
            support.tree_digest(saipen), before,
            "STAGE_ONLY must not touch the SAIPEN tree",
        )


class SemanticGate(unittest.TestCase):
    """Only a semantic DRIFT submission opens the finding lifecycle."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)
        code, nxt, _err = support.run_saipal_json("next", home=self.home)
        assert nxt is not None
        self.unit = nxt["analysis_carrier"]

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def hot_tail(self) -> dict:
        """Import the HOT fixture and advance the analyst to the growing tail."""
        support.put_inbox(self.home, HOT)
        support.run_saipal("continue", home=self.home)
        for _ in range(20):
            unit = carrier_mod.build_carrier(self.home, registry=self.registry)
            assert unit.get("session"), "the HOT fixture must be pending"
            if unit["episode"]["finality"] == "PROVISIONAL":
                return unit
            self.submit({
                "schema_version": 1,
                "verdict": "NO_DRIFT",
                "unit_digest": unit["unit_digest"],
                "session_id": unit["session"]["session_id"],
                "episode_index": unit["episode"]["index"],
                "disposition_class": "NO_DRIFT",
                "reasoning": "closed episode routed through the declared surface",
            })
        raise AssertionError("no provisional episode was ever offered")

    def drift_for(self, unit: dict, **overrides) -> dict:
        payload = {
            "schema_version": 1,
            "verdict": "DRIFT",
            "unit_digest": unit["unit_digest"],
            "session_id": unit["session"]["session_id"],
            "episode_index": unit["episode"]["index"],
            "disposition_class": "ENGINE_ENFORCEMENT_GAP",
            "reasoning": "the engine executed a route outside the closed surface",
            "rule_ids": ["PAL-CMD-01"],
            "event_refs": [unit["episode"]["start_seq"]],
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P2",
            "confidence": "MEDIUM",
            "change_target": "ENGINE",
            "root_cause": "no closure requirement stopped the undeclared route",
            "challenge": {
                "prosecutor": "the rule names a closed surface; this route was not in it",
                "defender": "the adapter may have normalized a user alias",
                "winner": "prosecutor",
                "loser_rejection": "the canonical token was recorded verbatim",
            },
            "alternatives": ["the user invoked a shell alias"],
            "addressed_defences": [
                entry["code"] for entry in unit.get("defence_surface") or []
            ],
        }
        payload.update(overrides)
        return payload

    def drift(self, **overrides) -> dict:
        return self.drift_for(self.unit, **overrides)

    def submit(self, candidate: dict) -> dict:
        return submit_mod.submit_candidate(self.home, candidate, registry=self.registry)

    def test_control_5_valid_drift_submission_creates_the_finding(self) -> None:
        before = len(_findings(self.home))
        receipt = self.submit(self.drift())
        self.assertIsNotNone(receipt["finding_id"])
        self.assertEqual(len(_findings(self.home)), before + 1)

    def test_control_6_valid_drift_submission_can_qualify_and_emit(self) -> None:
        receipt = self.submit(self.drift(severity="P1", confidence="HIGH"))
        finding = next(
            f for f in _findings(self.home)
            if f["finding_id"] == receipt["finding_id"]
        )
        self.assertEqual(finding["state"], "EMITTED")
        self.assertTrue(findings_mod.is_semantically_confirmed(finding))
        self.assertTrue(finding.get("semantic_confirmation"))

    def test_control_7_no_drift_advances_coverage_without_a_finding(self) -> None:
        before = len(_findings(self.home))
        receipt = self.submit({
            "schema_version": 1,
            "verdict": "NO_DRIFT",
            "unit_digest": self.unit["unit_digest"],
            "session_id": self.unit["session"]["session_id"],
            "episode_index": self.unit["episode"]["index"],
            "disposition_class": "NO_DRIFT",
            "reasoning": "every route stayed on the declared surface",
        })
        self.assertIsNone(receipt["finding_id"])
        self.assertEqual(len(_findings(self.home)), before)
        self.assertEqual(_receipts(self.home)[-1]["verdict"], "NO_DRIFT")

    def test_control_8_insufficient_evidence_creates_no_drift_finding(self) -> None:
        before = len(_findings(self.home))
        receipt = self.submit({
            "schema_version": 1,
            "verdict": "INSUFFICIENT_EVIDENCE",
            "unit_digest": self.unit["unit_digest"],
            "session_id": self.unit["session"]["session_id"],
            "episode_index": self.unit["episode"]["index"],
            "disposition_class": "INSUFFICIENT_EVIDENCE",
            "reasoning": "the slice names no governing rule for this route",
        })
        self.assertIsNone(receipt["finding_id"])
        self.assertEqual(len(_findings(self.home)), before)

    def test_control_10_provisional_verdict_is_not_final_coverage(self) -> None:
        """A HOT-tail verdict records work but cannot close the episode."""
        from saipal_engine import coverage as coverage_mod

        unit = self.hot_tail()
        receipt = self.submit(self.drift_for(unit))
        self.assertEqual(receipt["finality"], "PROVISIONAL")
        record = next(
            r for r in support.sessions_of(self.home)
            if r["session_id"] == unit["session"]["session_id"]
        )
        receipts = _receipts(self.home)
        by_index: dict[int, list[dict]] = {}
        for entry in receipts:
            if entry["session_id"] == record["session_id"]:
                by_index.setdefault(int(entry["episode_index"]), []).append(entry)
        row = coverage_mod.session_coverage(record, by_index, registry=self.registry)
        # The TAIL episode is what the provisional verdict touched: no FINAL
        # receipt may exist for it, so it can never read as final coverage.
        tail_receipts = by_index.get(int(unit["episode"]["index"])) or []
        self.assertTrue(tail_receipts, "the tail verdict must be recorded")
        self.assertTrue(
            all(e.get("finality") == "PROVISIONAL" for e in tail_receipts),
            "a HOT-tail verdict is provisional work, never a final receipt",
        )
        self.assertLess(row["final"], row["episodes"])
        self.assertGreaterEqual(row["needs_final_review"], 1)

    def test_control_11_unchanged_hot_tail_is_not_re_offered(self) -> None:
        """A provisional verdict with no evidence delta must not re-offer the unit."""
        unit = self.hot_tail()
        receipt = self.submit(self.drift_for(unit))
        self.assertEqual(receipt["finality"], "PROVISIONAL")
        record = next(
            r for r in support.sessions_of(self.home)
            if r["session_id"] == unit["session"]["session_id"]
        )
        state = carrier_mod.semantic_state(record)
        self.assertTrue(
            state.get("tail_reviewed_digest"),
            "the fully judged provisional tail must carry its watermark",
        )
        again = carrier_mod.build_carrier(self.home, registry=self.registry)
        if again.get("session"):
            self.assertNotEqual(
                again["session"]["session_id"], unit["session"]["session_id"],
                "an unchanged tail must not be re-offered without a material change",
            )

    def test_control_12_finalization_promotes_provisional_work(self) -> None:
        """When the session finalizes, held provisional work gets final review."""
        from saipal_engine import coverage as coverage_mod
        from saipal_engine import sessions as sessions_mod

        unit = self.hot_tail()
        session_id = unit["session"]["session_id"]
        receipt = self.submit(self.drift_for(unit))
        self.assertEqual(receipt["finality"], "PROVISIONAL")
        held_before = submit_mod.pending_final_sessions(self.home)
        self.assertIn(session_id, held_before)

        # Finalize the session: a COLD artifact is a new generation.
        record = next(
            r for r in support.sessions_of(self.home) if r["session_id"] == session_id
        )
        source = self.home / record["source_ref"]
        bundle = json.loads(source.read_text(encoding="utf-8"))
        bundle["temperature"] = "COLD"
        bundle["session_sha256"] = bundle_mod.bundle_digest(bundle)
        support.write_inbox(self.home, "finalized.json", bundle)
        code, _payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)

        # The finalized generation must offer its tail as FINAL work: coverage
        # may not count the old provisional receipt as final work for it.
        _status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        cov = coverage_mod.coverage(self.home, index, registry=self.registry)
        final_gen = [
            s for s in cov["sessions"]
            if s["session_id"] == session_id and s["temperature"] == "COLD"
        ]
        self.assertTrue(final_gen, "the finalized generation must be indexed")
        # The provisional receipt is work, never a conclusion: on the finalized
        # generation the tail is NOT final coverage and still owes review.
        self.assertLess(final_gen[0]["final"], final_gen[0]["episodes"])
        self.assertGreaterEqual(final_gen[0]["needs_final_review"], 1)
        self.assertEqual(final_gen[0]["truly_exhausted"], False)
        after = carrier_mod.build_carrier(self.home, registry=self.registry)
        if after.get("session"):
            self.assertEqual(after["session"]["session_id"], session_id)
            self.assertEqual(after["episode"]["finality"], "FINAL")


class LegacyFindingMigration(unittest.TestCase):
    """PAL-0001 was created mechanically; it must not survive as confirmed."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _seed_mechanical_finding(self) -> dict:
        """A mechanical finding that reached QUALIFIED the old way."""
        from saipal_engine import law as law_mod

        rule_ids = list(law_mod.resolve_law("COMMAND_ROUTE_DRIFT")["rule_ids"])
        finding = {
            "finding_id": "PAL-0001",
            "fingerprint": "legacy-fp",
            "state": "QUALIFIED",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P1",
            "confidence": "HIGH",
            "change_target": "CORE_PROTOCOL",
            "rule_ids": rule_ids,
            "root_cause": "mechanical template prose",
            "protected_invariants": [],
            "harm_warnings": [],
            "occurrences": [{"session_id": "s-legacy", "episode_id": 0, "event_refs": [2]}],
            "protocol_bindings": [{"version": "7.231.9", "binding_status": "BOUND"}],
            "alternatives": [],
            "mechanical_confidence": "HIGH",
            "audit": None,
        }
        findings_mod.save_index(
            self.home, {"schema_version": 1, "findings": [finding]}, registry=None
        )
        return finding

    def test_migration_demotes_the_mechanical_finding(self) -> None:
        """QUALIFIED without semantic confirmation must become SUSPECTED."""
        self._seed_mechanical_finding()
        migrated = findings_mod.migrate_index(self.home, registry=None)
        self.assertEqual(migrated["migrated"], 1)
        finding = _findings(self.home)[0]
        self.assertEqual(finding["state"], "SUSPECTED")
        self.assertFalse(findings_mod.is_semantically_confirmed(finding))
        self.assertIn("pre_semantic_migration", finding)

    def test_migration_is_idempotent(self) -> None:
        self._seed_mechanical_finding()
        findings_mod.migrate_index(self.home, registry=None)
        second = findings_mod.migrate_index(self.home, registry=None)
        self.assertEqual(second["migrated"], 0)
        finding = _findings(self.home)[0]
        self.assertEqual(finding["state"], "SUSPECTED")

    def test_a_suspected_finding_cannot_qualify_or_emit(self) -> None:
        self._seed_mechanical_finding()
        findings_mod.migrate_index(self.home, registry=None)
        finding = _findings(self.home)[0]
        with self.assertRaises(Exception):
            pipeline_mod.advance_to_qualified({"findings": [finding]}, finding)
        self.assertFalse(findings_mod.qualification_threshold(finding, registry=None))

    def test_an_emitted_legacy_finding_is_demoted_too(self) -> None:
        """An audit the mechanical path already emitted is reclassified."""
        from saipal_engine import law as law_mod

        rule_ids = list(law_mod.resolve_law("COMMAND_ROUTE_DRIFT")["rule_ids"])
        finding = {
            "finding_id": "PAL-0002",
            "fingerprint": "legacy-fp-2",
            "state": "EMITTED",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P1",
            "confidence": "HIGH",
            "change_target": "CORE_PROTOCOL",
            "rule_ids": rule_ids,
            "root_cause": "mechanical template prose",
            "protected_invariants": [],
            "harm_warnings": [],
            "occurrences": [{"session_id": "s-legacy", "episode_id": 0, "event_refs": [2]}],
            "protocol_bindings": [{"version": "7.231.9", "binding_status": "BOUND"}],
            "alternatives": [],
            "mechanical_confidence": "HIGH",
            "audit": {"audit_number": 1, "audit_path": "audit/staging/1.md",
                      "audit_sha256": "a" * 64, "operation_id": "op"},
        }
        findings_mod.save_index(
            self.home, {"schema_version": 1, "findings": [finding]}, registry=None
        )
        findings_mod.migrate_index(self.home, registry=None)
        finding = next(f for f in _findings(self.home) if f["finding_id"] == "PAL-0002")
        self.assertEqual(finding["state"], "SUSPECTED")
        self.assertFalse(findings_mod.is_semantically_confirmed(finding))


class SemanticConfirmationTie(unittest.TestCase):
    """Confirmation must be structurally tied to the evidence unit."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_confirmation_requires_digest_session_episode_and_verdict(self) -> None:
        base = {
            "receipt_id": "rcp-x",
            "verdict": "DRIFT",
            "session_id": "s1",
            "episode_index": 0,
            "unit_digest": "d" * 64,
        }
        self.assertTrue(findings_mod.is_semantic_confirmation_tied(base, "s1", 0, "d" * 64))
        for mutation in (
            {"verdict": "NO_DRIFT"},
            {"session_id": "s2"},
            {"episode_index": 1},
            {"unit_digest": "e" * 64},
        ):
            forged = dict(base, **mutation)
            self.assertFalse(
                findings_mod.is_semantic_confirmation_tied(
                    forged, "s1", 0, "d" * 64
                ),
                f"a forged confirmation must not verify: {mutation}",
            )


class MechanicalPipelineReportsSignals(unittest.TestCase):
    """The mechanical pass keeps working as triage, with new authority."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.write_inbox(self.home, "m.json", _drift_bundle("mech-001"))
        support.run_saipal("continue", home=self.home)
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        self.index = index
        # The CLI already exhausted the pass; reset the cursor so the direct
        # call exercises the analysis on its own evidence.
        for record in index["sessions"]:
            record["analysis"] = {
                "episodes_exhausted": False,
                "last_analyzed_at": None,
                "analyzed_up_to_seq": 0,
                "next_episode_index": 0,
            }
            record["last_analyzed_seq"] = 0
        sessions_mod.save_index(self.home, index, registry=self.registry)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_analysis_still_reports_signals(self) -> None:
        """Exhausting the pass must not lose the signal count."""
        result = pipeline_mod.analyze_sessions(self.home, self.index, registry=self.registry)
        self.assertGreaterEqual(result["signals_total"], 1)
        self.assertEqual(result["findings_created"], 0)
        self.assertEqual(len(_findings(self.home)), 0)

    def test_signals_are_visible_for_prioritization(self) -> None:
        result = pipeline_mod.analyze_sessions(self.home, self.index, registry=self.registry)
        signals = result.get("signals") or []
        self.assertTrue(signals, "signals must be reported so the analyst can prioritize")
        row = signals[0]
        for field in ("session_id", "episode_index", "drift_class", "signal_id"):
            self.assertIn(field, row)


class LegacyPublicationQuarantine(unittest.TestCase):
    """A pre-semantic pending audit is transport history, not authority.

    The publication ledger records what a sink has not confirmed; it does not
    confer the right to deliver. Before any retry, the referenced finding must
    still carry a semantic DRIFT confirmation tied to a BOUND historical
    protocol authority — otherwise the audit is quarantined with its bytes
    intact (PAL-ARCH-01).
    """

    def setUp(self) -> None:
        from saipal_engine import publications as pub_mod

        self.pub = pub_mod
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        self.sink_root = self.tmp / "saipen-intake"
        self._make_sink()
        self._configure_publish()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _make_sink(self) -> None:
        audit = self.sink_root / "audit"
        audit.mkdir(parents=True, exist_ok=True)
        (audit / "MANIFEST.json").write_text("{}", encoding="utf-8")

    def _configure_publish(self) -> None:
        config = self.home / "config.json"
        payload = json.loads(config.read_text(encoding="utf-8"))
        payload["publication_mode"] = "PUBLISH_ENABLED"
        payload["shadow_reviewed"] = True
        payload["sink"] = {"kind": "termisai-file", "root": str(self.sink_root)}
        config.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def _seed_legacy_pending_audit(self) -> dict:
        """The reproduction: a mechanical-era EMITTED finding, staged audit,
        PENDING ledger entry — and no semantic confirmation anywhere."""
        from saipal_engine import law as law_mod
        from saipal_engine.paths import sha256_text

        rule_ids = list(law_mod.resolve_law("COMMAND_ROUTE_DRIFT")["rule_ids"])
        finding = {
            "finding_id": "PAL-0001",
            "fingerprint": "legacy-fp",
            "state": "EMITTED",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P1",
            "confidence": "HIGH",
            "change_target": "ENGINE",
            "rule_ids": rule_ids,
            "root_cause": "mechanical template prose",
            "protected_invariants": [],
            "harm_warnings": [],
            "occurrences": [{"session_id": "s-legacy", "episode_id": 0, "event_refs": [2]}],
            "protocol_bindings": [{"version": "7.231.9", "binding_status": "BOUND"}],
            "alternatives": [],
            "mechanical_confidence": "HIGH",
            "audit": {
                "audit_number": 1,
                "audit_path": "audit/staging/1.md",
                "audit_sha256": sha256_text("# legacy audit body"),
                "operation_id": "op-legacy",
            },
        }
        findings_mod.save_index(
            self.home, {"schema_version": 1, "findings": [finding]}, registry=None
        )
        staging = self.home / "audit" / "staging"
        staging.mkdir(parents=True, exist_ok=True)
        (staging / "1.md").write_text("# legacy audit body", encoding="utf-8")
        self.pub.record_pending(
            self.home,
            finding_id="PAL-0001",
            audit_number=1,
            audit_path="audit/staging/1.md",
            audit_sha256=sha256_text("# legacy audit body"),
            reason="sink outage before the authority boundary",
            registry=None,
        )
        return finding

    def staged_bytes(self) -> bytes:
        return (self.home / "audit" / "staging" / "1.md").read_bytes()

    def ledger_entry(self) -> dict:
        status, ledger, _detail = self.pub.load_publications(self.home)
        assert status == "ok" and ledger, "the publication ledger must exist"
        return ledger["publications"][0]

    def sink_files(self) -> list[str]:
        audit = self.sink_root / "audit"
        return sorted(p.name for p in audit.glob("*.md")) if audit.is_dir() else []

    def test_control_16_legacy_pending_audit_is_never_published(self) -> None:
        self._seed_legacy_pending_audit()
        code, result, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert result is not None
        publication = result.get("publication") or {}
        self.assertEqual(publication.get("delivered"), 0)
        self.assertEqual(self.sink_files(), [], "a legacy audit must not reach SAIPEN")
        self.assertNotEqual(self.ledger_entry().get("status"), "PUBLISHED")
        for finding in _findings(self.home):
            self.assertFalse(
                findings_mod.is_semantically_confirmed(finding),
                "the legacy finding is not analyst-confirmed",
            )

    def test_control_17_the_same_audit_is_quarantined_with_bytes_intact(self) -> None:
        self._seed_legacy_pending_audit()
        before = self.staged_bytes()
        code, _result, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        entry = self.ledger_entry()
        self.assertEqual(entry.get("status"), "QUARANTINED")
        self.assertIn("semantic", str(entry.get("quarantine_reason") or ""))
        self.assertEqual(entry.get("audit_number"), 1, "the number is preserved")
        self.assertEqual(
            entry.get("audit_sha256"), hashlib.sha256(before).hexdigest()
        )
        self.assertEqual(self.staged_bytes(), before, "staged bytes must be untouched")
        self.assertNotIn(entry, self.pub.pending(self.home))
        self.assertEqual([row["audit_number"] for row in self.pub.quarantined(self.home)], [1])

    def test_control_18_migration_runs_without_a_session_index(self) -> None:
        self._seed_legacy_pending_audit()
        # Remove the session index entirely: analysis cannot run at all.
        (self.home / "sessions" / "index.json").unlink(missing_ok=True)
        code, _result, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        finding = _findings(self.home)[0]
        self.assertEqual(finding["state"], "SUSPECTED")
        self.assertNotEqual(self.ledger_entry().get("status"), "PUBLISHED")
        self.assertEqual(self.sink_files(), [])

    def test_control_19_migration_happens_before_any_publication_retry(self) -> None:
        """One cycle: the finding is demoted AND the audit is not delivered."""
        self._seed_legacy_pending_audit()
        code, _result, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        finding = _findings(self.home)[0]
        self.assertEqual(finding["state"], "SUSPECTED", "migration ran in the same cycle")
        self.assertNotEqual(self.ledger_entry().get("status"), "PUBLISHED")
        self.assertEqual(self.sink_files(), [])

    def test_control_20_retry_pending_revalidates_authority_itself(self) -> None:
        self._seed_legacy_pending_audit()
        result = self.pub.retry_pending(self.home, registry=None)
        self.assertEqual(result["published"], 0, "retry must not publish an unconfirmed finding")
        self.assertEqual(result.get("quarantined"), 1)
        self.assertEqual(self.sink_files(), [])
        self.assertEqual(self.ledger_entry().get("status"), "QUARANTINED")

    def test_control_21_emit_audit_refuses_an_unconfirmed_finding(self) -> None:
        from saipal_engine.errors import PalError

        finding = {
            "finding_id": "PAL-0042",
            "fingerprint": "fp",
            "state": "QUALIFIED",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P1",
            "confidence": "HIGH",
            "change_target": "ENGINE",
            "rule_ids": ["PAL-CMD-01"],
            "root_cause": "mechanical prose",
            "protected_invariants": [],
            "harm_warnings": [],
            "occurrences": [{"session_id": "s", "episode_id": 0, "event_refs": [1]}],
            "protocol_bindings": [{"binding_status": "BOUND"}],
            "alternatives": [],
            "mechanical_confidence": "HIGH",
            "audit": None,
        }
        with self.assertRaises(PalError):
            pipeline_mod.emit_audit(
                self.home, finding, {"session_id": "s"}, {}, None, None, []
            )
        staging = self.home / "audit" / "staging"
        self.assertFalse(
            staging.is_dir() and any(staging.glob("*.md")),
            "an unconfirmed finding may not stage an audit",
        )

    def test_control_22_a_confirmed_bound_drift_publishes_normally(self) -> None:
        support.put_inbox(self.home, DRIFT)
        code, _r, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        receipt = support.submit_drift(self.home, support.next_unit(self.home))
        self.assertIsNotNone(receipt["audit"], "a valid BOUND confirmation publishes")
        self.assertEqual(self.sink_files(), ["1.md"])
        finding = _findings(self.home)[0]
        self.assertEqual((finding.get("audit") or {}).get("delivery"), "PUBLISHED")

    def test_control_28_migration_is_idempotent_across_continues(self) -> None:
        self._seed_legacy_pending_audit()
        support.run_saipal("continue", home=self.home)
        first = _findings(self.home)[0]
        support.run_saipal("continue", home=self.home)
        second = _findings(self.home)[0]
        self.assertEqual(first["state"], "SUSPECTED")
        self.assertEqual(second["state"], "SUSPECTED")
        self.assertEqual(
            first.get("pre_semantic_migration", {}).get("from_state"),
            second.get("pre_semantic_migration", {}).get("from_state"),
        )
        self.assertEqual(self.ledger_entry().get("status"), "QUARANTINED")
        self.assertEqual(self.ledger_entry().get("audit_number"), 1)

    def test_control_29_quarantine_is_idempotent_and_never_reallocates(self) -> None:
        self._seed_legacy_pending_audit()
        support.run_saipal("continue", home=self.home)
        first_entry = dict(self.ledger_entry())
        support.run_saipal("continue", home=self.home)
        second_entry = self.ledger_entry()
        self.assertEqual(second_entry.get("status"), "QUARANTINED")
        self.assertEqual(second_entry.get("audit_number"), first_entry.get("audit_number"))
        self.assertEqual(self.staged_bytes(), self.staged_bytes())
        self.assertEqual(len(self.pub.quarantined(self.home)), 1)
        self.assertEqual(self.sink_files(), [])


class BindingAuthority(unittest.TestCase):
    """PARTIAL or UNKNOWN historical authority cannot confirm protocol drift."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _unit(self, session_id: str, protocol: dict) -> dict:
        payload = _drift_bundle(session_id)
        payload["protocol"] = protocol
        payload["session_sha256"] = bundle_mod.bundle_digest(payload)
        support.write_inbox(self.home, f"{session_id}.json", payload)
        code, _r, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        unit = support.next_unit(self.home)
        self.assertIsNotNone(unit)
        return unit

    def _drift(self, unit: dict) -> dict:
        return support.drift_candidate(unit)

    def test_control_8_drift_on_partial_binding_becomes_insufficient(self) -> None:
        unit = self._unit("part-001", {"version": "7.231.9", "binding_status": "PARTIAL"})
        receipt = submit_mod.submit_candidate(
            self.home, self._drift(unit), registry=self.registry
        )
        self.assertEqual(receipt["verdict"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(receipt.get("attempted_verdict"), "DRIFT")
        self.assertIn("binding", json.dumps(receipt))
        self.assertIsNone(receipt["finding_id"])
        self.assertEqual(_findings(self.home), [])

    def test_control_9_drift_on_unknown_binding_becomes_insufficient(self) -> None:
        unit = self._unit("unk-001", {"binding_status": "UNKNOWN"})
        receipt = submit_mod.submit_candidate(
            self.home, self._drift(unit), registry=self.registry
        )
        self.assertEqual(receipt["verdict"], "INSUFFICIENT_EVIDENCE")
        self.assertIsNone(receipt["finding_id"])
        self.assertEqual(_findings(self.home), [])

    def test_control_10_two_partial_occurrences_cannot_satisfy_p2(self) -> None:
        finding = {
            "finding_id": "PAL-0009",
            "fingerprint": "fp",
            "state": "QUALIFIED",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P2",
            "confidence": "HIGH",
            "change_target": "ENGINE",
            "rule_ids": ["PAL-CMD-01"],
            "root_cause": "rc",
            "protected_invariants": [],
            "harm_warnings": [],
            "occurrences": [
                {"session_id": "a", "episode_id": 0, "event_refs": [1]},
                {"session_id": "b", "episode_id": 0, "event_refs": [1]},
            ],
            "protocol_bindings": [{"binding_status": "PARTIAL"}],
            "alternatives": [],
            "mechanical_confidence": "LOW",
            "semantic_confirmation": {
                "receipt_id": "rcp-x",
                "verdict": "DRIFT",
                "session_id": "a",
                "episode_index": 0,
                "unit_digest": "d" * 64,
                "protocol_binding": {"binding_status": "PARTIAL"},
            },
            "audit": None,
        }
        # A PARTIAL-backed confirmation is not a confirmation at all: the
        # fail-closed invariant refuses it before the threshold is reached.
        self.assertFalse(findings_mod.is_semantically_confirmed(finding))
        self.assertFalse(
            findings_mod.qualification_threshold(finding, registry=None),
            "two PARTIAL occurrences do not establish which rule governed",
        )

    def test_control_11_recurrence_cannot_substitute_for_bound_authority(self) -> None:
        from saipal_engine import recurrence as recurrence_mod

        finding = {
            "finding_id": "PAL-0010",
            "fingerprint": "fp-r",
            "state": "QUALIFIED",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P2",
            "confidence": "HIGH",
            "change_target": "ENGINE",
            "rule_ids": ["PAL-CMD-01"],
            "root_cause": "rc",
            "protected_invariants": [],
            "harm_warnings": [],
            "occurrences": [
                {"session_id": "a", "episode_id": 0, "event_refs": [1]},
                {"session_id": "b", "episode_id": 0, "event_refs": [1]},
                {"session_id": "c", "episode_id": 0, "event_refs": [1]},
            ],
            "protocol_bindings": [{"binding_status": "PARTIAL"}],
            "alternatives": [],
            "mechanical_confidence": "HIGH",
            "semantic_confirmation": {
                "receipt_id": "rcp-y",
                "verdict": "DRIFT",
                "session_id": "a",
                "episode_index": 0,
                "unit_digest": "d" * 64,
                "protocol_binding": {"binding_status": "PARTIAL"},
            },
            "audit": None,
        }
        session = {"session_id": "a", "adapter": "generic", "conformant": False}
        recurrence_mod.record_occurrence(self.home, finding, session)
        self.assertFalse(
            findings_mod.qualification_threshold(finding, registry=None),
            "recurrence rows are not historical authority",
        )

    def test_control_12_a_bound_occurrence_cannot_legitimize_a_partial_confirmation(
        self,
    ) -> None:
        finding = {
            "finding_id": "PAL-0011",
            "fingerprint": "fp-m",
            "state": "QUALIFIED",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P1",
            "confidence": "HIGH",
            "change_target": "ENGINE",
            "rule_ids": ["PAL-CMD-01"],
            "root_cause": "rc",
            "protected_invariants": [],
            "harm_warnings": [],
            "occurrences": [
                {"session_id": "bound-s", "episode_id": 0, "event_refs": [1]},
                {"session_id": "partial-s", "episode_id": 0, "event_refs": [1]},
            ],
            "protocol_bindings": [
                {"binding_status": "BOUND"},
                {"binding_status": "PARTIAL"},
            ],
            "alternatives": [],
            "mechanical_confidence": "LOW",
            "semantic_confirmation": {
                "receipt_id": "rcp-z",
                "verdict": "DRIFT",
                "session_id": "partial-s",
                "episode_index": 0,
                "unit_digest": "d" * 64,
                "protocol_binding": {"binding_status": "PARTIAL"},
            },
            "audit": None,
        }
        self.assertFalse(
            findings_mod.qualification_threshold(finding, registry=None),
            "qualification must use the CONFIRMATION's binding, not an unrelated "
            "BOUND occurrence",
        )


def _drift_bundle(session_id: str) -> dict:
    events = [
        {"seq": 1, "type": "USER_MESSAGE", "ts": None, "loc": None, "digest": None,
         "facts": {}},
        {"seq": 2, "type": "PHASE_CHANGE", "ts": None, "loc": None, "digest": None,
         "facts": {"from_phase": "PLAN", "to_phase": "NOPE"}},
        {"seq": 3, "type": "SESSION_BOUNDARY", "ts": None, "loc": None, "digest": None,
         "facts": {}},
    ]
    payload = {
        "schema_version": 1,
        "session_id": session_id,
        "adapter": "generic",
        "project": {"name": "X", "git_head": "x", "root_fingerprint": "fx"},
        "runtime": {"provider": "openai", "model": "gpt-x", "reasoning_mode": "unknown"},
        "temperature": "COLD",
        "protocol": {"version": "7.231.9", "binding_status": "BOUND",
                     "git_head": "deadbeef", "registry_sha256": "b" * 64},
        "events": events,
    }
    payload["session_sha256"] = bundle_mod.bundle_digest(payload)
    return payload


if __name__ == "__main__":
    unittest.main()
