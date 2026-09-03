"""Wave B: the canonical bundle contract (PAL-SESSION-01).

The transcript guard is the one that matters most: a bundle carrying raw
conversation text is not evidence, it is a second copy of the conversation.
"""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import bundle as bundle_mod
from saipal_engine.errors import PalError

VALID = "conformant-cold.json"


class BundleContract(unittest.TestCase):
    def setUp(self) -> None:
        self.bundle = support.load_fixture(VALID)

    # -- acceptance bar 1: generic bundles validate ------------------------ #

    def test_golden_fixture_is_valid(self) -> None:
        self.assertEqual(bundle_mod.validate_bundle(self.bundle), [])
        self.assertEqual(bundle_mod.validate_bundle(support.load_fixture("no-events.json")), [])

    def test_parse_returns_the_bundle(self) -> None:
        self.assertIs(bundle_mod.parse_bundle(self.bundle), self.bundle)

    def test_digest_is_stable_and_declared_value_matches(self) -> None:
        self.assertEqual(self.bundle["session_sha256"], bundle_mod.bundle_digest(self.bundle))

    def test_digest_ignores_the_digest_field_itself(self) -> None:
        """A bundle cannot contain its own digest; verify the recursion is cut."""
        with_digest = copy.deepcopy(self.bundle)
        without = copy.deepcopy(self.bundle)
        without["session_sha256"] = None
        self.assertEqual(
            bundle_mod.bundle_digest(with_digest), bundle_mod.bundle_digest(without)
        )

    def test_declared_digest_mismatch_is_rejected(self) -> None:
        problems = bundle_mod.validate_bundle(support.load_fixture("bad-digest.json"))
        self.assertTrue(any("does not match" in p for p in problems))

    def test_unsupported_schema_is_rejected(self) -> None:
        problems = bundle_mod.validate_bundle(support.load_fixture("unsupported-schema.json"))
        self.assertTrue(any("schema_version" in p for p in problems))

    def test_out_of_order_sequence_is_rejected(self) -> None:
        problems = bundle_mod.validate_bundle(support.load_fixture("out-of-order-seq.json"))
        self.assertTrue(any("does not increase" in p for p in problems))

    def test_missing_required_field_is_rejected(self) -> None:
        broken = copy.deepcopy(self.bundle)
        del broken["session_id"]
        self.assertTrue(any("session_id" in p for p in bundle_mod.validate_bundle(broken)))

    def test_unknown_top_level_field_is_rejected(self) -> None:
        broken = copy.deepcopy(self.bundle)
        broken["vibes"] = "suspicious"
        self.assertTrue(any("unknown field 'vibes'" in p for p in bundle_mod.validate_bundle(broken)))

    def test_unknown_adapter_is_rejected(self) -> None:
        broken = copy.deepcopy(self.bundle)
        broken["adapter"] = "gpt"
        self.assertTrue(any("adapter" in p for p in bundle_mod.validate_bundle(broken)))

    def test_bad_temperature_is_rejected(self) -> None:
        broken = copy.deepcopy(self.bundle)
        broken["temperature"] = "LUKEWARM"
        self.assertTrue(any("temperature" in p for p in bundle_mod.validate_bundle(broken)))

    def test_unknown_event_type_is_rejected(self) -> None:
        broken = copy.deepcopy(self.bundle)
        broken["events"][0]["type"] = "TELEPATHY"
        self.assertTrue(any("TELEPATHY" in p for p in bundle_mod.validate_bundle(broken)))

    def test_unknown_protocol_field_is_rejected(self) -> None:
        broken = copy.deepcopy(self.bundle)
        broken["protocol"]["horoscope"] = "mercury retrograde"
        self.assertTrue(any("horoscope" in p for p in bundle_mod.validate_bundle(broken)))

    def test_unknown_binding_proof_level_is_rejected(self) -> None:
        broken = copy.deepcopy(self.bundle)
        broken["protocol"]["proof_level"] = "TRUST_ME"
        self.assertTrue(any("proof_level" in p for p in bundle_mod.validate_bundle(broken)))

    # -- acceptance bar 9: no raw transcript ------------------------------- #

    def test_event_carrying_raw_content_is_rejected(self) -> None:
        problems = bundle_mod.validate_bundle(support.load_fixture("transcript-in-events.json"))
        self.assertTrue(any("forbidden raw-content field" in p for p in problems))

    def test_every_forbidden_key_is_refused(self) -> None:
        for key in ("content", "text", "body", "transcript", "raw", "message", "payload"):
            with self.subTest(key=key):
                broken = copy.deepcopy(self.bundle)
                broken["events"][0][key] = "nope"
                self.assertTrue(bundle_mod.validate_bundle(broken))

    def test_oversized_fact_string_is_rejected(self) -> None:
        broken = copy.deepcopy(self.bundle)
        broken["events"][0]["facts"]["essay"] = "x" * 5000
        self.assertTrue(any("budget" in p for p in bundle_mod.validate_bundle(broken)))

    def test_facts_must_be_an_object(self) -> None:
        broken = copy.deepcopy(self.bundle)
        broken["events"][0]["facts"] = "the whole conversation"
        self.assertTrue(
            any("facts must be an object" in p for p in bundle_mod.validate_bundle(broken))
        )

    def test_parse_raises_with_every_problem_listed(self) -> None:
        broken = copy.deepcopy(self.bundle)
        del broken["session_id"]
        broken["events"][0]["type"] = "NONSENSE"
        with self.assertRaises(PalError) as caught:
            bundle_mod.parse_bundle(broken)
        self.assertEqual(caught.exception.code, "BUNDLE_INVALID")
        self.assertIn("session_id", caught.exception.message)
        self.assertIn("NONSENSE", caught.exception.message)

    # -- event span helpers ------------------------------------------------ #

    def test_event_span_and_prefix_digest(self) -> None:
        self.assertEqual(bundle_mod.event_span(self.bundle), (1, 11))
        self.assertEqual(bundle_mod.event_span({"events": []}), (0, 0))
        first_two = bundle_mod.prefix_digest(self.bundle, 2)
        self.assertEqual(len(first_two), 64)
        self.assertNotEqual(first_two, bundle_mod.prefix_digest(self.bundle, 3))

    # -- red controls ------------------------------------------------------ #

    def test_red_control_transcript_guard_follows_the_registry(self) -> None:
        """Empty the guard's registry key and the refusal must disappear.

        If the refusal survived, the guard is hardcoded and this whole
        acceptance bar is theatre.
        """
        payload = support.load_fixture("transcript-in-events.json")
        before = bundle_mod.validate_bundle(payload)
        self.assertTrue(any("forbidden raw-content" in p for p in before))

        mutated = support.load_registry_copy()
        mutated["forbidden_event_keys"] = []
        after = bundle_mod.validate_bundle(payload, registry=mutated)
        self.assertFalse(
            any("forbidden raw-content" in p for p in after),
            "emptying the guard key must silence the guard",
        )

    def test_red_control_schema_gate_can_be_broken(self) -> None:
        mutated = support.load_registry_copy()
        mutated["bundle_schema_version"] = 99
        self.assertEqual(
            bundle_mod.validate_bundle(support.load_fixture("unsupported-schema.json"), registry=mutated),
            [],
        )


class BundleFiles(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_unreadable_file_is_inbox_unreadable(self) -> None:
        missing = self.tmp / "gone.json"
        with self.assertRaises(PalError) as caught:
            bundle_mod.load_bundle_file(missing)
        self.assertEqual(caught.exception.code, "INBOX_UNREADABLE")

    def test_non_json_file_is_bundle_invalid(self) -> None:
        target = self.tmp / "junk.json"
        target.write_text("{ not json", encoding="utf-8")
        with self.assertRaises(PalError) as caught:
            bundle_mod.load_bundle_file(target)
        self.assertEqual(caught.exception.code, "BUNDLE_INVALID")

    def test_valid_file_loads(self) -> None:
        target = self.tmp / "ok.json"
        target.write_bytes(support.fixture(VALID).read_bytes())
        payload = bundle_mod.load_bundle_file(target)
        self.assertEqual(payload["session_id"], "golden-cold-001")


if __name__ == "__main__":
    unittest.main()
