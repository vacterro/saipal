"""NEXT1 operational loop acceptance bar.

End-to-end CLI tests: configured sources dispatch through adapters into the
canonical inbox, historical binding gates HIGH confidence, the sink abstraction
keeps private bookkeeping local and defaults to STAGE_ONLY, disposition intake
is idempotent, and setup/doctor/trigger behave through the real CLI.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import bundle as bundle_mod
from saipal_engine import config as config_mod
from saipal_engine import dispatcher as dispatch_mod
from saipal_engine import enqueue as enqueue_mod
from saipal_engine.sink import AuditSink


def _drift_bundle(session_id: str = "n1-drift-001", protocol: dict | None = None) -> dict:
    payload = {
        "schema_version": 1,
        "session_id": session_id,
        "adapter": "generic",
        "project": {"name": "X", "git_head": "x", "root_fingerprint": "fx"},
        "runtime": {"provider": "openai", "model": "gpt-x", "reasoning_mode": "unknown"},
        "temperature": "COLD",
        "protocol": protocol or {
            "version": "7.231.9",
            "binding_status": "BOUND",
            "git_head": "deadbeef",
            "registry_sha256": "a" * 64,
        },
        "events": [
            {"seq": 1, "type": "PHASE_CHANGE", "facts": {"from_phase": "PLAN", "to_phase": "NOPE"}},
            {"seq": 2, "type": "SESSION_BOUNDARY", "facts": {}},
        ],
    }
    payload["session_sha256"] = bundle_mod.bundle_digest(payload)
    return payload


def _findings(home: Path) -> list[dict]:
    index = home / "findings" / "index.json"
    if not index.exists():
        return []
    return list(json.loads(index.read_text(encoding="utf-8"))["findings"])


class SourceDispatcher(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_generic_source_with_canonical_bundle_reaches_analysis(self) -> None:
        source_dir = self.tmp / "sources"
        source_dir.mkdir()
        bundle = _drift_bundle()
        bundle["session_id"] = "src-import-001"
        bundle["session_sha256"] = bundle_mod.bundle_digest(bundle)
        (source_dir / "src-import-001.json").write_text(
            json.dumps(bundle) + "\n", encoding="utf-8"
        )
        before = support.tree_digest(source_dir)
        support.write_sources(
            self.home,
            [{"id": "s1", "kind": "generic", "path": str(source_dir), "enabled": True}],
        )
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        self.assertEqual(len(payload["dispatch"]["imported"]), 1)
        self.assertEqual(payload["sessions_indexed"], 1)
        self.assertEqual(support.tree_digest(source_dir), before, "raw source was mutated")

    def test_second_run_is_idempotent(self) -> None:
        source_dir = self.tmp / "sources"
        source_dir.mkdir()
        bundle = _drift_bundle(session_id="src-idem-001")
        (source_dir / "src-idem-001.json").write_text(
            json.dumps(bundle) + "\n", encoding="utf-8"
        )
        support.write_sources(
            self.home,
            [{"id": "s1", "kind": "generic", "path": str(source_dir), "enabled": True}],
        )
        support.run_saipal_json("continue", home=self.home)
        _code, second, _err = support.run_saipal_json("continue", home=self.home)
        assert second is not None
        self.assertEqual(second["sessions_indexed"], 0, "second run must not duplicate a session")

    def test_known_cold_session_is_skipped_without_crash(self) -> None:
        """Red control: known_ids skip must not touch an unbound variable.

        A pre-existing regression built the inbox filename from `source_path`
        before it was assigned; a session that was already indexed and COLD
        crashed the whole cycle. This exercises the exact path.
        """
        source_dir = self.tmp / "sources"
        source_dir.mkdir()
        bundle = _drift_bundle(session_id="src-known-001")
        (source_dir / "src-known-001.json").write_text(
            json.dumps(bundle) + "\n", encoding="utf-8"
        )
        support.write_sources(
            self.home,
            [{"id": "s1", "kind": "generic", "path": str(source_dir), "enabled": True}],
        )
        code, first, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert first is not None
        self.assertEqual(first["sessions_indexed"], 1)

        code, second, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert second is not None
        self.assertEqual(second["sessions_indexed"], 0)
        self.assertEqual(
            len(second["dispatch"]["unchanged"]),
            1,
            "the known cold session must land in unchanged, not a crash",
        )

    def test_unknown_adapter_fails_closed(self) -> None:
        source_dir = self.tmp / "sources"
        source_dir.mkdir()
        support.write_sources(
            self.home,
            [{"id": "s1", "kind": "not-a-real-adapter", "path": str(source_dir), "enabled": True}],
        )
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        self.assertEqual(len(payload["dispatch"]["unsupported"]), 1)

    def test_disabled_source_untouched(self) -> None:
        source_dir = self.tmp / "sources"
        source_dir.mkdir()
        bundle = _drift_bundle(session_id="src-disabled-001")
        (source_dir / "src-disabled-001.json").write_text(
            json.dumps(bundle) + "\n", encoding="utf-8"
        )
        support.write_sources(
            self.home,
            [{"id": "s1", "kind": "generic", "path": str(source_dir), "enabled": False}],
        )
        _code, payload, _err = support.run_saipal_json("continue", home=self.home)
        assert payload is not None
        self.assertEqual(payload["sessions_indexed"], 0, "disabled source must not import")
        self.assertEqual(payload["dispatch"]["imported"], [])


class TermisaiAdapter(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_termisai_jsonl_normalizes_with_binding(self) -> None:
        source_dir = self.tmp / "termisai"
        source_dir.mkdir()
        # The release identity has to be the one the home's declared authority
        # actually published: a binding is proved against those bytes, and a
        # placeholder digest would (correctly) come out PARTIAL.
        lines = [
            {"type": "user", "seq": 1, "content": "hello"},
            {"type": "phase_change", "seq": 2, "protocol": {
                "version": support.AUTHORITY_VERSION,
                "registry_sha256": support.authority_digest(self.tmp),
            }, "content": "PLAN to VERIFY"},
            {"type": "session_boundary", "seq": 3, "closed": True, "content": "done"},
        ]
        (source_dir / "sess-term.jsonl").write_text(
            "\n".join(json.dumps(l) for l in lines) + "\n", encoding="utf-8"
        )
        support.write_sources(
            self.home,
            [{"id": "t1", "kind": "termisai", "path": str(source_dir), "enabled": True}],
        )
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        self.assertEqual(len(payload["dispatch"]["imported"]), 1)
        self.assertEqual(payload["sessions_indexed"], 1)
        canonical = json.loads(
            Path(payload["dispatch"]["imported"][0]["target"]).read_text(encoding="utf-8")
        )
        self.assertEqual(canonical["protocol"]["proof_level"], "RELEASE_REGISTRY")
        sessions = support.sessions_of(self.home)
        self.assertEqual(sessions[0]["temperature"], "COLD")
        self.assertEqual(sessions[0]["protocol"]["binding_status"], "BOUND")
        self.assertEqual(sessions[0]["protocol"]["proof_level"], "RELEASE_REGISTRY")


class HistoricalBindingGate(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_unknown_binding_cannot_produce_high_confidence(self) -> None:
        bundle = _drift_bundle(
            session_id="gate-unknown-001",
            protocol={"version": None, "binding_status": "UNKNOWN"},
        )
        support.write_inbox(self.home, "gate-unknown.json", bundle)
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        for finding in _findings(self.home):
            self.assertNotEqual(finding["confidence"], "HIGH")
        self.assertEqual(payload["audits_emitted"], 0)

    def test_old_session_against_new_rule_no_high_violation(self) -> None:
        bundle = _drift_bundle(
            session_id="gate-old-001",
            protocol={"version": "1.0.0", "binding_status": "PARTIAL"},
        )
        support.write_inbox(self.home, "gate-old.json", bundle)
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        for finding in _findings(self.home):
            self.assertNotEqual(finding["confidence"], "HIGH")


class SinkAbstraction(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        self.sink_root = self.tmp / "sink"
        (self.sink_root / "audit").mkdir(parents=True)
        (self.sink_root / "audit" / "MANIFEST.json").write_text(
            json.dumps({"name": "termisai-audit-sink", "schema_version": 1}) + "\n",
            encoding="utf-8",
        )
        self.sink = AuditSink(self.home, root=self.sink_root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _qualified_finding(self, fid: str = "PAL-SINK-1") -> dict:
        return {
            "finding_id": fid,
            "fingerprint": "f" + fid,
            "state": "QUALIFIED",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P1",
            "confidence": "HIGH",
            "change_target": "ENGINE",
            "rule_ids": ["COMMAND_ROUTE_DRIFT"],
            "root_cause": "route drifted",
            "protected_invariants": ["destructive_confirmation"],
            "occurrences": [{"session_id": "s-1", "episode_id": 0, "event_refs": [2]}],
            "protocol_bindings": [{"version": "7.231.9", "binding_status": "BOUND"}],
            "alternatives": [],
            "audit": None,
        }

    def test_preflight_requires_manifest(self) -> None:
        bare = self.tmp / "bare-sink"
        (bare / "audit").mkdir(parents=True)
        sink = AuditSink(self.home, root=bare)
        self.assertFalse(sink.preflight()["ok"])

    def test_publish_keeps_private_ledger_local(self) -> None:
        result = self.sink.publish(self._qualified_finding(), "# SAIPAL AUDIT\nmaintainer_verdict: PENDING\n")
        self.assertTrue((self.sink_root / "audit" / f"{result['audit_number']}.md").exists())
        self.assertTrue(self.sink.verify(result))
        # the external sink receives only the numbered audit, no bookkeeping
        external_files = {p.name for p in (self.sink_root / "audit").iterdir()}
        self.assertNotIn("entries.json", external_files)
        self.assertNotIn("ledger.json", external_files)
        # the private ledger stays inside the SAIPAL home
        self.assertTrue((self.home / "audit" / "entries.json").exists())

    def test_publish_is_exactly_once_per_finding(self) -> None:
        finding = self._qualified_finding()
        body = "# SAIPAL AUDIT\nmaintainer_verdict: PENDING\n"
        first = self.sink.publish(finding, body)
        second = self.sink.publish(finding, body)
        self.assertEqual(first["audit_number"], second["audit_number"])
        numbered = [p for p in (self.sink_root / "audit").iterdir() if p.suffix == ".md"]
        self.assertEqual(len(numbered), 1)

    def test_collision_never_overwrites(self) -> None:
        foreign = self.sink_root / "audit" / "5.md"
        foreign.write_text("another producer's audit", encoding="utf-8")
        finding = self._qualified_finding("PAL-SINK-2")
        result = self.sink.publish(finding, "# SAIPAL AUDIT\nmaintainer_verdict: PENDING\n")
        self.assertNotEqual(result["audit_number"], 5, "a foreign slot must never be reused")
        self.assertEqual(foreign.read_text(encoding="utf-8"), "another producer's audit")


class PublicationPolicy(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_default_is_stage_only(self) -> None:
        status, config, _ = config_mod.load_config(self.home)
        self.assertEqual(status, "ok")
        assert config is not None
        self.assertEqual(config["publication_mode"], "STAGE_ONLY")

    def test_publish_enabled_requires_shadow_review(self) -> None:
        with self.assertRaises(Exception):
            config_mod.save_config(
                self.home,
                {"schema_version": 1, "publication_mode": "PUBLISH_ENABLED", "shadow_reviewed": False, "sink": {"kind": "termisai-file", "root": str(self.tmp / "sink")}},
            )


class DispositionIntake(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        bundle = _drift_bundle(session_id="disp-001")
        support.write_inbox(self.home, "disp.json", bundle)
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        self.assertEqual(payload["audits_emitted"], 1)
        findings = _findings(self.home)
        emitted = [f for f in findings if f["state"] == "EMITTED" and f["audit"]]
        self.audit_number = emitted[0]["audit"]["audit_number"]

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_cli_disposition_import_is_idempotent(self) -> None:
        from saipal_engine import closedloop as cl

        receipt = {
            "dispositions": [
                {"audit_number": self.audit_number, "disposition": "CONFIRMED_PROTOCOL_DEFECT", "receipt_id": "SRC-1", "work_id": "T-1"},
            ]
        }
        path = self.tmp / "disp.json"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        code, payload, err = support.run_saipal_json("disposition", str(path), home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        self.assertEqual(payload["count"], 1)
        # import again -> idempotent
        code, payload, err = support.run_saipal_json("disposition", str(path), home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        self.assertEqual(payload["count"], 1)
        chain = cl.reconstruct_provenance(self.home, audit_number=self.audit_number)
        self.assertEqual(chain["disposition"], "CONFIRMED_PROTOCOL_DEFECT")


class OperatorSurface(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_setup_configures_and_doctor_reports(self) -> None:
        source_dir = self.tmp / "sources"
        source_dir.mkdir()
        code, payload, err = support.run_saipal_json(
            "setup", "--source", str(source_dir), "--kind", "generic", home=self.home
        )
        self.assertEqual(code, 0, err)
        assert payload is not None
        self.assertEqual(payload["source"], str(source_dir))
        sources = json.loads((self.home / "sources.json").read_text(encoding="utf-8"))
        self.assertEqual(len(sources["sources"]), 1)
        self.assertEqual(sources["sources"][0]["kind"], "generic")

        before = support.tree_digest(self.home)
        code, doctor, err = support.run_saipal_json("doctor", home=self.home)
        self.assertEqual(code, 0, err)
        assert doctor is not None
        self.assertEqual(doctor["command"], "doctor")
        self.assertEqual(doctor["publication_mode"], "STAGE_ONLY")
        self.assertEqual(support.tree_digest(self.home), before, "doctor mutated the home")

    def test_trigger_coalesces(self) -> None:
        code, first, err = support.run_saipal_json("trigger", home=self.home)
        self.assertEqual(code, 0, err)
        assert first is not None
        self.assertFalse(first["coalesced"])
        code, second, err = support.run_saipal_json("trigger", home=self.home)
        self.assertEqual(code, 0, err)
        assert second is not None
        self.assertTrue(second["coalesced"])
        code, cc, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert cc is not None
        code, third, err = support.run_saipal_json("trigger", home=self.home)
        self.assertEqual(code, 0, err)
        assert third is not None
        self.assertFalse(third["coalesced"], "a consumed trigger frees the next slot")


if __name__ == "__main__":
    unittest.main()
