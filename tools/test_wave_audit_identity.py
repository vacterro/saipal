"""T-049: audit metadata a maintainer can act on (PAL-AUDIT-03).

An audit whose "models" and "owner_documents" fields are blank is an audit nobody
can route. The first questions about drift are *which model, which provider,
which project, which rule, which document owns that rule* — and every one of them
was empty in the emitted body.

These tests pin the metadata, and the detector fix behind it: a detector knows the
symptom, so it must resolve real PAL rule ids from the law surface instead of
putting the drift-class name where a rule id belongs.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import audits as audits_mod
from saipal_engine import detectors as detectors_mod
from saipal_engine import law as law_mod
from saipal_engine.registry import load_registry, require_mapping, require_string_list

DRIFT = "agent-noncompliance-command-route.json"


class DetectorRuleIds(unittest.TestCase):
    """A detector cites law, not its own taxonomy label."""

    def setUp(self) -> None:
        self.registry = load_registry()

    def test_every_drift_class_resolves_to_real_rule_ids(self) -> None:
        owners = require_mapping(self.registry, "rule_owners")
        for drift_class in require_string_list(self.registry, "drift_taxonomy"):
            rules = detectors_mod._rule_ids(drift_class, self.registry)
            self.assertTrue(rules, f"{drift_class} resolved no rule")
            for rule in rules:
                self.assertIn(rule, owners, f"{drift_class} -> {rule}")

    def test_an_unknown_class_yields_no_fabricated_rule(self) -> None:
        """Red control: better an empty list than an invented rule id."""
        self.assertEqual(detectors_mod._rule_ids("NOT_A_CLASS", self.registry), [])

    def test_the_drift_class_name_is_never_used_as_a_rule_id(self) -> None:
        for drift_class in require_string_list(self.registry, "drift_taxonomy"):
            rules = detectors_mod._rule_ids(drift_class, self.registry)
            self.assertNotIn(drift_class, rules)

    def test_a_detector_candidate_carries_resolved_rules(self) -> None:
        episode = {"index": 0, "start_seq": 1, "end_seq": 3, "kind": "command"}
        bundle = {
            "events": [
                {
                    "seq": 1,
                    "type": "COMMAND",
                    "facts": {"canonical": "saipen teleport now"},
                }
            ]
        }
        candidate = detectors_mod.detect_command_route(
            episode, bundle, {"session_id": "s1"}, registry=self.registry
        )
        self.assertIsNotNone(candidate)
        self.assertEqual(
            candidate["rule_ids"],
            list(law_mod.resolve_law("COMMAND_ROUTE_DRIFT", registry=self.registry)["rule_ids"]),
        )


class AuditIdentityFields(unittest.TestCase):
    """Body fields, built from the index record with the bundle as fallback."""

    def setUp(self) -> None:
        self.registry = load_registry()

    def finding(self, **overrides) -> dict:
        finding = {
            "finding_id": "PAL-0001",
            "rule_ids": ["PAL-CMD-01", "PAL-CMD-02"],
            "root_cause": "the command routed outside the closed surface",
            "severity": "P2",
            "confidence": "MEDIUM",
            "change_target": "ENGINE",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "causal_key": "command outside rout surface",
            "occurrences": [{"session_id": "s1", "episode_id": 0, "event_refs": [1]}],
            "protocol_bindings": [{"binding_status": "BOUND"}],
            "protected_invariants": ["verify"],
            "harm_warnings": [],
            "disposition_class": "ENGINE_ENFORCEMENT_GAP",
            "analyst_reasoning": "the token is absent from the declared surface",
        }
        finding.update(overrides)
        return finding

    def record(self, **overrides) -> dict:
        record = {
            "session_id": "ses_abc",
            "generation": 2,
            "adapter": "opencode",
            "temperature": "COLD",
            "imported_at": "2026-01-01T00:00:00Z",
            "project": {"name": "SAIPAL", "root_fingerprint": "fp1", "git_head": "abc1234"},
            "runtime": {"provider": "openai", "model": "gpt-5", "agent": "build"},
        }
        record.update(overrides)
        return record

    def body(self, finding: dict | None = None, record: dict | None = None,
             bundle: dict | None = None) -> str:
        return audits_mod.build_audit_body(
            finding or self.finding(),
            record or self.record(),
            bundle if bundle is not None else {"adapter": "opencode", "protocol": {}},
            registry=self.registry,
        )

    def test_the_model_and_provider_are_named(self) -> None:
        body = self.body()
        self.assertIn("provider=openai", body)
        self.assertIn("model=gpt-5", body)
        self.assertIn("agent=build", body)

    def test_the_project_identity_is_named(self) -> None:
        body = self.body()
        self.assertIn("SAIPAL", body)
        self.assertIn("root=fp1", body)
        self.assertIn("git_head=abc1234", body)

    def test_the_session_identity_carries_generation_and_temperature(self) -> None:
        body = self.body()
        self.assertIn("ses_abc, gen=2, COLD", body)

    def test_the_owner_documents_are_resolved_from_the_registry(self) -> None:
        body = self.body()
        self.assertIn("saipal/COMMANDS.md", body)

    def test_an_unknown_rule_contributes_no_owner_document(self) -> None:
        body = self.body(self.finding(rule_ids=["PAL-NOT-99"]))
        self.assertIn("- owner_documents:\n", body)

    def test_the_analyst_reasoning_and_disposition_reach_the_body(self) -> None:
        body = self.body()
        self.assertIn("the token is absent from the declared surface", body)
        self.assertIn("ENGINE_ENFORCEMENT_GAP", body)

    def test_the_causal_key_reaches_the_recurrence_section(self) -> None:
        body = self.body()
        self.assertIn("command outside rout surface", body)

    def test_recurrence_names_the_observed_model_and_project(self) -> None:
        body = self.body()
        self.assertIn("gpt-5 (1 session(s) observed)", body)
        self.assertIn("SAIPAL (1 session(s) observed)", body)

    def test_bundle_runtime_is_the_fallback_when_the_record_has_none(self) -> None:
        body = self.body(
            record=self.record(runtime={}),
            bundle={"adapter": "opencode", "protocol": {},
                    "runtime": {"provider": "anthropic", "model": "claude-x"}},
        )
        self.assertIn("provider=anthropic", body)
        self.assertIn("model=claude-x", body)

    def test_a_session_with_no_runtime_anywhere_leaves_models_empty(self) -> None:
        body = self.body(
            record=self.record(runtime={}), bundle={"adapter": "generic", "protocol": {}}
        )
        self.assertIn("- models:\n", body)

    def test_the_body_still_passes_the_quality_gate(self) -> None:
        finding = self.finding()
        body = self.body(finding)
        self.assertTrue(audits_mod.passes_quality_gate(body, finding))

    def test_the_provisional_marker_reaches_the_session_line(self) -> None:
        body = self.body(record=self.record(episode_finality="PROVISIONAL"))
        self.assertIn("PROVISIONAL", body)


class EmittedAuditIsAttributable(unittest.TestCase):
    """Through the real pipeline: the staged file names its origin."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)
        support.submit_drift(self.home, support.next_unit(self.home))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def audit_text(self) -> str:
        staging = self.home / "audit" / "staging"
        files = sorted(staging.glob("*.md")) if staging.is_dir() else []
        self.assertTrue(files, "the drift fixture must emit an audit")
        return files[0].read_text(encoding="utf-8")

    def test_the_emitted_audit_names_the_model(self) -> None:
        self.assertIn("model=gpt-5", self.audit_text())

    def test_the_emitted_audit_names_real_rule_ids(self) -> None:
        text = self.audit_text()
        self.assertIn("PAL-CMD-01", text)
        self.assertNotIn("rule_ids: COMMAND_ROUTE_DRIFT", text)

    def test_the_emitted_audit_names_the_owner_document(self) -> None:
        self.assertIn("saipal/COMMANDS.md", self.audit_text())

    def test_the_emitted_audit_carries_a_causal_key(self) -> None:
        text = self.audit_text()
        self.assertIn("causal_key:", text)
        line = next(l for l in text.splitlines() if l.startswith("- causal_key:"))
        self.assertTrue(line.split(":", 1)[1].strip(), "causal_key must not be blank")


if __name__ == "__main__":
    unittest.main()
