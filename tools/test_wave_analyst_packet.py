"""T-79 (packet half): the packet is the model's whole world, and it is bounded.

Structural proofs: the packet derives only from the canonical carrier, drops
everything a remote analyst must never hold, labels mechanical signals as
hints, and stays byte-stable for the same carrier. The prompts state the
authority contract; the delimiters are ergonomics, never the boundary.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import config as analyst_config
from saipal_analyst import output as output_mod
from saipal_analyst import packet as packet_mod
from saipal_analyst import prompts as prompts_mod
from saipal_engine import carrier as carrier_mod
from saipal_engine.errors import PalError

CLEAN = "conformant-cold.json"
HOSTILE = "hostile-transcript-injection.json"


class PacketBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def carrier_for(self, fixture: str) -> dict:
        support.put_inbox(self.home, fixture)
        support.run_saipal("continue", home=self.home)
        carrier = carrier_mod.build_carrier(self.home)
        if carrier.get("carrier") != "analyze-episodes":
            raise AssertionError(f"no analyzable unit for {fixture}: {carrier}")
        return carrier

    def packet_for(self, fixture: str, **analyst: object) -> dict:
        carrier = self.carrier_for(fixture)
        analyst_payload = {
            "backend_type": "openai_compatible",
            "model": "stub-model",
            **analyst,
        }
        return packet_mod.build_packet(carrier, analyst=analyst_payload)


class PacketShape(PacketBase):
    def test_packet_derives_from_carrier(self) -> None:
        packet = self.packet_for(CLEAN)
        self.assertEqual(packet_mod.packet_problems(packet), [])
        self.assertEqual(packet["packet_schema_version"], 1)
        self.assertTrue(packet_mod.packet_digest_matches(packet))

    def test_forbidden_carrier_content_is_dropped(self) -> None:
        carrier = self.carrier_for(CLEAN)
        self.assertIn("evidence_command", carrier)  # the manual surface has it...
        packet = self.packet_for(CLEAN)
        self.assertNotIn("evidence_command", packet)  # ...the packet never does
        rendered = json.dumps(packet)
        for marker in ("saipal evidence", "saipal submit", "saipal continue"):
            self.assertNotIn(marker, rendered)

    def test_packet_drops_paths_and_secrets(self) -> None:
        packet = self.packet_for(CLEAN)
        rendered = json.dumps(packet)
        self.assertNotIn(str(self.home), rendered)
        self.assertNotIn(".saipal", rendered)
        self.assertNotIn("SAIPAL_ANALYST_API_KEY", rendered)
        self.assertNotIn("sink", rendered)

    def test_mechanical_signals_are_labelled_hints(self) -> None:
        packet = self.packet_for("agent-noncompliance-command-route.json")
        signals = packet["mechanical_signals"]
        self.assertEqual(signals["label"], packet_mod.SIGNALS_LABEL)
        self.assertIn("NOT facts", signals["hint"])
        self.assertIn("no authority", signals["hint"])

    def test_identity_is_copiable_verbatim(self) -> None:
        packet = self.packet_for(CLEAN)
        self.assertTrue(packet["unit_digest"])
        self.assertTrue(packet["session"]["session_id"])
        self.assertIsInstance(packet["episode"]["index"], int)
        self.assertIn("index", packet["slice"])

    def test_binding_surface_is_copied_not_decided(self) -> None:
        packet = self.packet_for("agent-noncompliance-command-route.json")
        self.assertIn(packet["protocol"]["binding_status"], ("BOUND", "PARTIAL", "UNKNOWN"))

    def test_unknown_packet_field_refused(self) -> None:
        packet = self.packet_for(CLEAN)
        packet["evidence_command"] = "saipal evidence x 1"
        problems = packet_mod.packet_problems(packet)
        self.assertIn("unknown packet field 'evidence_command'", problems)

    def test_smuggled_forbidden_key_refused(self) -> None:
        packet = self.packet_for(CLEAN)
        packet["applicable_law"] = {"rules": [], "sink_root": "/maintainer"}
        problems = packet_mod.packet_problems(packet)
        self.assertIn("packet must not carry 'sink_root'", problems)

    def test_idle_carrier_refused(self) -> None:
        from saipal_engine.errors import PalError

        with self.assertRaises(PalError):
            packet_mod.build_packet(
                {"carrier": "idle", "session": None}, analyst={}
            )


class PacketStability(PacketBase):
    def test_same_carrier_same_digest(self) -> None:
        first = self.packet_for(CLEAN)
        carrier = carrier_mod.build_carrier(self.home)
        second = packet_mod.build_packet(
            carrier, analyst={"backend_type": "openai_compatible", "model": "stub-model"}
        )
        self.assertEqual(first["packet_digest"], second["packet_digest"])


class EgressGate(PacketBase):
    def test_remote_endpoint_refused_before_any_call(self) -> None:
        config = analyst_config.default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = "http://api.example.invalid/v1/chat/completions"
        with self.assertRaises(PalError) as caught:
            packet_mod.ensure_egress(config)
        self.assertIn("leave the machine", str(caught.exception))
        self.assertIn("api.example.invalid", str(caught.exception))
        self.assertIn("allow_remote_evidence", str(caught.exception))

    def test_remote_endpoint_allowed_only_with_flag(self) -> None:
        config = analyst_config.default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = "http://api.example.invalid/v1/chat/completions"
        config["egress"]["allow_remote_evidence"] = True
        packet_mod.ensure_egress(config)

    def test_loopback_needs_no_flag(self) -> None:
        config = analyst_config.default_analyst_config()
        packet_mod.ensure_egress(config)


class Prompts(unittest.TestCase):
    def test_every_system_prompt_states_the_authority_contract(self) -> None:
        for system in (
            prompts_mod.INVESTIGATOR_SYSTEM,
            prompts_mod.CRITIC_SYSTEM,
            prompts_mod.FINALIZER_SYSTEM,
        ):
            self.assertIn("zero authority", system)
            self.assertIn("no tools", system)
            self.assertIn("UNVERIFIED INVESTIGATION HINT", system)
            self.assertIn("system prompt", system.lower())

    def test_prompts_never_instruct_model_to_run_tools(self) -> None:
        for system in (
            prompts_mod.INVESTIGATOR_SYSTEM,
            prompts_mod.CRITIC_SYSTEM,
            prompts_mod.FINALIZER_SYSTEM,
        ):
            self.assertNotIn("run `saipal submit", system)
            self.assertNotIn("invoke saipal", system)

    def test_user_message_delimits_evidence(self) -> None:
        message = prompts_mod.packet_user_message({"unit_digest": "d" * 64})
        self.assertIn(prompts_mod.DELIMITER_BEGIN, message)
        self.assertIn(prompts_mod.DELIMITER_END, message)
        self.assertIn("UNTRUSTED EVIDENCE", message)

    def test_repair_message_preserves_packet_and_demands_identity(self) -> None:
        packet = {"unit_digest": "d" * 64, "session": {"session_id": "s"}}
        message = prompts_mod.repair_user_message(
            packet, "your bad reply", ["not valid JSON"]
        )
        self.assertIn("not valid JSON", message)
        self.assertIn("copied verbatim", message)
        self.assertIn(prompts_mod.DELIMITER_BEGIN, message)


class StrictParse(unittest.TestCase):
    def test_plain_object_parses(self) -> None:
        self.assertEqual(output_mod.parse_json_object('{"verdict": "NO_DRIFT"}'), {"verdict": "NO_DRIFT"})

    def test_fenced_json_refused(self) -> None:
        with self.assertRaises(output_mod.OutputRejected):
            output_mod.parse_json_object('```json\n{"a": 1}\n```')

    def test_prose_wrapped_json_refused(self) -> None:
        with self.assertRaises(output_mod.OutputRejected):
            output_mod.parse_json_object("Here is the JSON:\n{\"a\": 1}")
        with self.assertRaises(output_mod.OutputRejected):
            output_mod.parse_json_object('{"a": 1}\nHope that helps!')

    def test_oversized_reply_refused(self) -> None:
        with self.assertRaises(output_mod.OutputRejected):
            output_mod.parse_json_object('{"a": "' + "x" * 600000 + '"}')

    def test_array_root_refused(self) -> None:
        with self.assertRaises(output_mod.OutputRejected):
            output_mod.parse_json_object("[1, 2, 3]")


if __name__ == "__main__":
    unittest.main()
