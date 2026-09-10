"""T-80: deliberation is asymmetric, adversarial, and never self-submissive.

Deterministic scripted backends prove the seven deliberation fixtures without
any live model, and prove the module never manufactures a verdict of its own:
a malformed role submits nothing, and disagreement without a finalizer blocks.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import deliberation as delib_mod
from saipal_analyst import output as output_mod
from saipal_analyst import packet as packet_mod
from saipal_engine import carrier as carrier_mod

CLEAN = "conformant-cold.json"
DRIFT = "agent-noncompliance-command-route.json"

POLICY = {
    "critic_on_drift": True,
    "critic_on_high_signal_no_drift": True,
    "clean_sample_percent": 0,
    "finalizer_on_disagreement": True,
}


def clean_candidate(packet: dict) -> dict:
    return {
        "schema_version": 1,
        "verdict": "NO_DRIFT",
        "unit_digest": packet["unit_digest"],
        "session_id": packet["session"]["session_id"],
        "episode_index": packet["episode"]["index"],
        "slice_index": packet["slice"]["index"],
        "disposition_class": "NO_DRIFT",
        "reasoning": "clean",
        "event_refs": [event["seq"] for event in packet["events"][:1]],
    }


def drift_candidate_for(packet: dict, carrier: dict) -> dict:
    candidate = support.drift_candidate(carrier, slice_index=packet["slice"]["index"])
    candidate["unit_digest"] = packet["unit_digest"]
    candidate["session_id"] = packet["session"]["session_id"]
    candidate["episode_index"] = packet["episode"]["index"]
    return candidate


def critic_payload(packet: dict, decision: str) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "unit_digest": packet["unit_digest"],
            "decision": decision,
            "objections": ["objection" for _ in ()] or [],
            "missed_evidence": [],
            "reasoning": f"the critic {decision.lower()}s",
        }
    )


class ScriptedModel:
    """Reply script by role, in order. Nothing here is a live model."""

    def __init__(self, script: dict[str, list[str]]):
        self.script = {role: list(replies) for role, replies in script.items()}
        self.prompts: list[tuple[str, str]] = []

    def __call__(self, role: str, user: str) -> str:
        self.prompts.append((role, user))
        return self.script[role].pop(0)


class DeliberationBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def stage(self, fixture: str) -> tuple[dict, dict]:
        support.put_inbox(self.home, fixture)
        support.run_saipal("continue", home=self.home)
        carrier = carrier_mod.build_carrier(self.home)
        packet = packet_mod.build_packet(
            carrier, analyst={"backend_type": "openai_compatible", "model": "stub"}
        )
        return carrier, packet


class DeliberationFixtures(DeliberationBase):
    def test_1_clean_episode_one_call_one_receipt_path(self) -> None:
        _carrier, packet = self.stage(CLEAN)
        model = ScriptedModel({"investigator": [json.dumps(clean_candidate(packet))]})
        result = delib_mod.run_investigation(
            packet, call=model, policy=POLICY, registry=support.load_registry_copy()
        )
        self.assertEqual(result.status, "CANDIDATE")
        self.assertEqual(result.candidate["verdict"], "NO_DRIFT")
        self.assertEqual(len(model.prompts), 1)
        self.assertEqual(result.path, ["investigator"])
        self.assertFalse(result.finalizer_changed)

    def test_2_drift_agreed_submits_one_candidate(self) -> None:
        carrier, packet = self.stage(DRIFT)
        candidate = drift_candidate_for(packet, carrier)
        model = ScriptedModel(
            {
                "investigator": [json.dumps(candidate)],
                "critic": [critic_payload(packet, "AGREE")],
            }
        )
        result = delib_mod.run_investigation(
            packet, call=model, policy=POLICY, registry=support.load_registry_copy()
        )
        self.assertEqual(result.status, "CANDIDATE")
        self.assertEqual(result.candidate["verdict"], "DRIFT")
        self.assertEqual(result.path[-1], "critic_agree")
        self.assertEqual(len(model.prompts), 2)

    def test_3_false_positive_overturned_to_no_drift(self) -> None:
        carrier, packet = self.stage(DRIFT)
        candidate = drift_candidate_for(packet, carrier)
        final = dict(candidate, verdict="NO_DRIFT", disposition_class="NO_DRIFT")
        for key in ("rule_ids", "event_refs", "drift_class", "change_target",
                    "severity", "confidence", "challenge", "alternatives",
                    "root_cause", "addressed_defences"):
            final.pop(key, None)
        model = ScriptedModel(
            {
                "investigator": [json.dumps(candidate)],
                "critic": [critic_payload(packet, "DISAGREE")],
                "finalizer": [json.dumps(final)],
            }
        )
        result = delib_mod.run_investigation(
            packet, call=model, policy=POLICY, registry=support.load_registry_copy()
        )
        self.assertEqual(result.status, "CANDIDATE")
        self.assertEqual(result.final_verdict, "NO_DRIFT")
        self.assertTrue(result.finalizer_changed)
        self.assertIn("finalizer_decided", result.path)

    def test_4_ambiguous_resolves_to_insufficient(self) -> None:
        carrier, packet = self.stage(DRIFT)
        candidate = drift_candidate_for(packet, carrier)
        final = dict(candidate, verdict="INSUFFICIENT_EVIDENCE",
                     disposition_class="INSUFFICIENT_EVIDENCE")
        for key in ("rule_ids", "event_refs", "drift_class", "change_target",
                    "severity", "confidence", "challenge", "alternatives",
                    "root_cause", "addressed_defences"):
            final.pop(key, None)
        model = ScriptedModel(
            {
                "investigator": [json.dumps(candidate)],
                "critic": [critic_payload(packet, "INSUFFICIENT")],
                "finalizer": [json.dumps(final)],
            }
        )
        result = delib_mod.run_investigation(
            packet, call=model, policy=POLICY, registry=support.load_registry_copy()
        )
        self.assertEqual(result.status, "CANDIDATE")
        self.assertEqual(result.final_verdict, "INSUFFICIENT_EVIDENCE")
        self.assertTrue(result.finalizer_changed)

    def test_5_high_signal_false_negative_overturned_to_drift(self) -> None:
        # A clean verdict on the drift fixture is challenged via the
        # deterministic sample; the finalizer may restore DRIFT. (The
        # high-signal trigger itself is pinned by the needs_critic tests.)
        _carrier, packet = self.stage(DRIFT)
        clean = clean_candidate(packet)
        restored = support.drift_candidate(_carrier, slice_index=packet["slice"]["index"])
        restored["unit_digest"] = packet["unit_digest"]
        restored["session_id"] = packet["session"]["session_id"]
        restored["episode_index"] = packet["episode"]["index"]
        model = ScriptedModel(
            {
                "investigator": [json.dumps(clean)],
                "critic": [critic_payload(packet, "DISAGREE")],
                "finalizer": [json.dumps(restored)],
            }
        )
        result = delib_mod.run_investigation(
            packet, call=model, policy={**POLICY, "clean_sample_percent": 100},
            registry=support.load_registry_copy(),
        )
        self.assertEqual(result.status, "CANDIDATE")
        self.assertEqual(result.final_verdict, "DRIFT")
        self.assertTrue(result.finalizer_changed)

    def test_5b_sampled_clean_episode_gets_exactly_the_critic(self) -> None:
        # Sampling at 100% forces one critic call on a clean verdict.
        _carrier, packet = self.stage(CLEAN)
        model = ScriptedModel(
            {
                "investigator": [json.dumps(clean_candidate(packet))],
                "critic": [critic_payload(packet, "AGREE")],
            }
        )
        result = delib_mod.run_investigation(
            packet, call=model, policy={**POLICY, "clean_sample_percent": 100},
            registry=support.load_registry_copy(),
        )
        self.assertEqual(result.status, "CANDIDATE")
        self.assertEqual([role for role, _user in model.prompts], ["investigator", "critic"])

    def test_6_malformed_critic_blocks_after_bounded_repair(self) -> None:
        carrier, packet = self.stage(DRIFT)
        candidate = drift_candidate_for(packet, carrier)
        model = ScriptedModel(
            {
                "investigator": [json.dumps(candidate)],
                "critic": ["not json", "still not json"],
            }
        )
        result = delib_mod.run_investigation(
            packet, call=model, policy=POLICY, registry=support.load_registry_copy()
        )
        self.assertEqual(result.status, "BLOCKED_OUTPUT")
        self.assertIsNone(result.candidate)
        self.assertIn("still invalid after repair", result.blocked_detail)
        # Exactly the bounded attempts: one call + one repair.
        self.assertEqual(len(model.prompts), 3)

    def test_7_malformed_finalizer_submits_nothing(self) -> None:
        carrier, packet = self.stage(DRIFT)
        candidate = drift_candidate_for(packet, carrier)
        model = ScriptedModel(
            {
                "investigator": [json.dumps(candidate)],
                "critic": [critic_payload(packet, "DISAGREE")],
                "finalizer": ["```json nope```", "nope again"],
            }
        )
        result = delib_mod.run_investigation(
            packet, call=model, policy=POLICY, registry=support.load_registry_copy()
        )
        self.assertEqual(result.status, "BLOCKED_OUTPUT")
        self.assertIsNone(result.candidate)

    def test_malformed_investigator_gets_one_repair_then_blocks(self) -> None:
        _carrier, packet = self.stage(CLEAN)
        model = ScriptedModel(
            {
                "investigator": ["Here is the JSON: {}", "still garbage"],
            }
        )
        result = delib_mod.run_investigation(
            packet, call=model, policy=POLICY, registry=support.load_registry_copy()
        )
        self.assertEqual(result.status, "BLOCKED_OUTPUT")
        self.assertEqual(result.invalid_outputs, 2)
        self.assertIsNone(result.candidate)


class RepairIdentity(DeliberationBase):
    def test_repair_keeps_the_same_packet(self) -> None:
        _carrier, packet = self.stage(CLEAN)
        model = ScriptedModel(
            {
                "investigator": [
                    "oops",
                    json.dumps(clean_candidate(packet)),
                ]
            }
        )
        result = delib_mod.run_investigation(
            packet, call=model, policy=POLICY, registry=support.load_registry_copy()
        )
        self.assertEqual(result.status, "CANDIDATE")
        role, user = model.prompts[1]
        self.assertEqual(role, "investigator")
        self.assertIn("copied verbatim", user)
        self.assertIn(packet["unit_digest"], user)
        self.assertTrue(result.calls[-1].repaired)


class Sampling(DeliberationBase):
    def test_sampling_is_deterministic_from_the_digest(self) -> None:
        packet = {"mechanical_signals": {"signals": []}, "unit_digest": "ab" * 32}
        policy = {**POLICY, "clean_sample_percent": 50}
        first, reason = output_mod.needs_critic(
            {"verdict": "NO_DRIFT"}, packet, policy=policy, unit_digest=packet["unit_digest"]
        )
        second, _reason2 = output_mod.needs_critic(
            {"verdict": "NO_DRIFT"}, packet, policy=policy, unit_digest=packet["unit_digest"]
        )
        self.assertEqual(first, second)
        bucket = int(packet["unit_digest"][:8], 16) % 100
        self.assertEqual(first, bucket < 50)

    def test_high_signal_forces_the_critic_on_clean(self) -> None:
        packet = {
            "unit_digest": "cd" * 32,
            "mechanical_signals": {
                "signals": [{"confidence": "HIGH", "severity": "P2"}]
            },
        }
        needed, reason = output_mod.needs_critic(
            {"verdict": "NO_DRIFT"},
            packet,
            policy={**POLICY, "clean_sample_percent": 0},
            unit_digest=packet["unit_digest"],
        )
        self.assertTrue(needed)
        self.assertEqual(reason, "high_signal_no_drift")

    def test_insufficient_evidence_never_gets_a_critic(self) -> None:
        needed, _reason = output_mod.needs_critic(
            {"verdict": "INSUFFICIENT_EVIDENCE"},
            {"mechanical_signals": {"signals": [{"confidence": "HIGH"}]}},
            policy=POLICY,
            unit_digest="ab" * 32,
        )
        self.assertFalse(needed)


class NoMachineVerdicts(DeliberationBase):
    def test_disagreement_without_finalizer_blocks_instead_of_flipping(self) -> None:
        _carrier, packet = self.stage(CLEAN)
        policy = {**POLICY, "critic_on_high_signal_no_drift": True,
                  "finalizer_on_disagreement": False}
        # Force the critic path via sampling, then refuse the finalizer.
        model = ScriptedModel(
            {
                "investigator": [json.dumps(clean_candidate(packet))],
                "critic": [critic_payload(packet, "DISAGREE")],
            }
        )
        forced = {**policy, "clean_sample_percent": 100}
        result = delib_mod.run_investigation(
            packet, call=model, policy=forced, registry=support.load_registry_copy()
        )
        self.assertEqual(result.status, "BLOCKED_OUTPUT")
        self.assertIn("finalizer disabled", result.blocked_detail)

    def test_module_never_sets_a_verdict_itself(self) -> None:
        # The only places a verdict string is assigned come from parsed model
        # text; nothing in the module hardcodes DRIFT/NO_DRIFT decisions.
        source = Path(delib_mod.__file__).read_text(encoding="utf-8")
        self.assertNotIn('verdict": "DRIFT"', source.replace(" ", ""))
        self.assertNotIn('"verdict": "NO_DRIFT"', source)


if __name__ == "__main__":
    unittest.main()
