"""T-054: real evidence locators and windows for Claude / Codex / Gemini.

Only the OpenCode adapter could reopen raw evidence. Every other provider
normalized events with no locator at all, so `saipal evidence` was structurally
impossible for them: an audit could cite a session it could never quote.

Locator construction and window reading are now shared, so all three JSONL
providers behave identically — and the shared code is where the subtle mistakes
were: a chained conditional that bound the wrong way and produced `role: user`
for assistant events.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from saipal_engine import bundle as bundle_mod
from saipal_engine.adapters import ADAPTER_REGISTRY, read_evidence
from saipal_engine.adapters import claude, codex, gemini, locators
from saipal_engine.adapters.jsonl_evidence import MAX_ITEM_CHARS, jsonl_window
from saipal_engine.errors import PalError
from saipal_engine.paths import sha256_text
from saipal_engine.registry import load_registry, require_string_list

#: One session per provider, in each provider's own event vocabulary.
FIXTURES = {
    "claude": [
        {"seq": 1, "type": "user", "content": "please run the build", "ts": "2026-01-01T00:00:00Z"},
        {"seq": 2, "type": "assistant", "content": "running it now"},
        {"seq": 3, "type": "tool_call", "content": {"tool": "bash", "command": "make"}},
        {"seq": 4, "type": "tool_result", "content": {"ok": True}},
        {"seq": 5, "type": "session_boundary", "content": {"reason": "done"}},
    ],
    "codex": [
        {"seq": 1, "type": "user", "content": "cc"},
        {"seq": 2, "type": "command", "content": "saipal continue"},
        {"seq": 3, "type": "assistant", "content": "one cycle done"},
        {"seq": 4, "type": "tool_result", "content": {"ok": True}},
        {"seq": 5, "type": "session_boundary", "content": {"reason": "done"}},
    ],
    "gemini": [
        {"seq": 1, "type": "user_message", "content": "check the protocol"},
        {"seq": 2, "type": "assistant_message", "content": "checked"},
        {"seq": 3, "type": "tool_call", "content": {"tool": "read"}},
        {"seq": 4, "type": "phase_change", "content": {"from_phase": "PLAN", "to_phase": "BUILD"}},
        {"seq": 5, "type": "session_boundary", "content": {"reason": "done"}},
    ],
}

MODULES = {"claude": claude, "codex": codex, "gemini": gemini}


def _write_session(root: Path, provider: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{provider}-session-001.jsonl"
    path.write_text(
        "\n".join(json.dumps(row) for row in FIXTURES[provider]) + "\n", encoding="utf-8"
    )
    return path


class RoleMapping(unittest.TestCase):
    """The role a locator claims must be the role the event had."""

    def test_declared_roles_are_honoured(self) -> None:
        for role in ("user", "assistant", "tool", "unknown"):
            self.assertEqual(locators.role_of("whatever", {"role": role}), role)

    def test_an_invented_declared_role_is_ignored(self) -> None:
        self.assertEqual(locators.role_of("user", {"role": "operator"}), "user")

    def test_user_types_map_to_user(self) -> None:
        for kind in ("user", "user_message", "command"):
            self.assertEqual(locators.role_of(kind, {}), "user")

    def test_assistant_types_map_to_assistant(self) -> None:
        """Red control: the old inline conditional returned 'user' here."""
        for kind in ("assistant", "assistant_message"):
            self.assertEqual(locators.role_of(kind, {}), "assistant")

    def test_tool_types_map_to_tool(self) -> None:
        for kind in ("tool_call", "tool_result"):
            self.assertEqual(locators.role_of(kind, {}), "tool")

    def test_an_unmapped_type_is_unknown_not_guessed(self) -> None:
        self.assertEqual(locators.role_of("session_boundary", {}), "unknown")
        self.assertEqual(locators.role_of("", {}), "unknown")


class LocatorShape(unittest.TestCase):
    """Every locator field is registry-declared and within its length bound."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self.fields = set(require_string_list(self.registry, "evidence_locator_fields"))
        self.kinds = set(require_string_list(self.registry, "evidence_source_kinds"))
        self.roles = set(require_string_list(self.registry, "evidence_roles"))

    def test_every_jsonl_provider_is_a_registered_evidence_source(self) -> None:
        for provider in MODULES:
            self.assertIn(provider, self.kinds)

    def test_a_locator_carries_exactly_the_declared_fields(self) -> None:
        built = locators.locator(
            source_kind="claude", source_type="user", raw={"seq": 3},
            digest="a" * 64, default_seq=3,
        )
        self.assertEqual(set(built), self.fields)
        self.assertIn(built["role"], self.roles)

    def test_a_locator_falls_back_to_the_sequence_number(self) -> None:
        built = locators.locator(
            source_kind="codex", source_type="user", raw={"seq": 7},
            digest="b" * 64, default_seq=7,
        )
        self.assertEqual(built["source_part_id"], "7")
        self.assertEqual(built["source_message_id"], "7")

    def test_provider_ids_win_over_the_fallback(self) -> None:
        built = locators.locator(
            source_kind="gemini", source_type="assistant_message",
            raw={"seq": 2, "session_id": "ses_x", "message_id": "msg_y", "part_id": "part_z"},
            digest="c" * 64, default_seq=2,
        )
        self.assertEqual(built["source_session_id"], "ses_x")
        self.assertEqual(built["source_message_id"], "msg_y")
        self.assertEqual(built["source_part_id"], "part_z")


class NormalizedBundlesCarryLocators(unittest.TestCase):
    """Normalization must attach a locator to every admissible event."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_every_provider_bundle_validates(self) -> None:
        for provider, module in MODULES.items():
            with self.subTest(provider=provider):
                path = _write_session(self.tmp / provider, provider)
                bundle = module.normalize(str(path))
                self.assertEqual(bundle_mod.validate_bundle(bundle), [], provider)

    def test_every_event_carries_a_locator(self) -> None:
        for provider, module in MODULES.items():
            with self.subTest(provider=provider):
                path = _write_session(self.tmp / provider, provider)
                bundle = module.normalize(str(path))
                self.assertTrue(bundle["events"])
                for event in bundle["events"]:
                    self.assertIsInstance(event.get("evidence_ref"), dict, event)
                    self.assertEqual(event["evidence_ref"]["source_kind"], provider)

    def test_locator_digests_match_the_event_digest(self) -> None:
        """The digest is the anchor, so it must be the event's own digest."""
        for provider, module in MODULES.items():
            with self.subTest(provider=provider):
                path = _write_session(self.tmp / provider, provider)
                bundle = module.normalize(str(path))
                for event in bundle["events"]:
                    self.assertEqual(
                        event["evidence_ref"]["source_digest"], event["digest"]
                    )

    def test_assistant_events_are_labelled_assistant(self) -> None:
        for provider, module in MODULES.items():
            with self.subTest(provider=provider):
                path = _write_session(self.tmp / provider, provider)
                bundle = module.normalize(str(path))
                assistant = [
                    event for event in bundle["events"]
                    if event["type"] == "ASSISTANT_MESSAGE"
                ]
                self.assertTrue(assistant, provider)
                for event in assistant:
                    self.assertEqual(event["evidence_ref"]["role"], "assistant")


class EvidenceWindows(unittest.TestCase):
    """The window contains the cited event, bounded, and refuses when it cannot."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _bundle(self, provider: str) -> tuple[Path, dict]:
        path = _write_session(self.tmp / provider, provider)
        return path, MODULES[provider].normalize(str(path))

    def test_every_provider_has_an_evidence_reader(self) -> None:
        for provider in MODULES:
            module = ADAPTER_REGISTRY[provider]
            self.assertTrue(hasattr(module, "read_evidence"), provider)

    def test_a_window_is_anchored_on_the_cited_event(self) -> None:
        for provider in MODULES:
            with self.subTest(provider=provider):
                path, bundle = self._bundle(provider)
                event = bundle["events"][2]
                window = read_evidence(
                    provider, str(path), event["evidence_ref"],
                    before=1, after=1, registry=self.registry,
                )
                anchors = [item for item in window["items"] if item["is_anchor"]]
                self.assertEqual(len(anchors), 1, provider)
                self.assertEqual(window["provider"], provider)

    def test_a_window_carries_the_untrusted_warning(self) -> None:
        path, bundle = self._bundle("claude")
        window = read_evidence(
            "claude", str(path), bundle["events"][0]["evidence_ref"],
            before=0, after=0, registry=self.registry,
        )
        self.assertEqual(window["warning"], "UNTRUSTED EVIDENCE")

    def test_before_and_after_bound_the_window(self) -> None:
        path, bundle = self._bundle("codex")
        event = bundle["events"][2]
        narrow = read_evidence(
            "codex", str(path), event["evidence_ref"], before=0, after=0,
            registry=self.registry,
        )
        wide = read_evidence(
            "codex", str(path), event["evidence_ref"], before=2, after=2,
            registry=self.registry,
        )
        self.assertEqual(narrow["total_items"], 1)
        self.assertGreater(wide["total_items"], narrow["total_items"])

    def test_a_zero_width_window_is_exactly_the_anchor(self) -> None:
        path, bundle = self._bundle("gemini")
        event = bundle["events"][1]
        window = read_evidence(
            "gemini", str(path), event["evidence_ref"], before=0, after=0,
            registry=self.registry,
        )
        self.assertEqual(window["total_items"], 1)
        self.assertTrue(window["items"][0]["is_anchor"])

    def test_an_unresolvable_locator_is_refused(self) -> None:
        """Red control: a window that does not contain the event is worse than none."""
        path, _bundle = self._bundle("claude")
        with self.assertRaises(PalError) as raised:
            read_evidence(
                "claude", str(path),
                {"source_kind": "claude", "source_digest": "f" * 64, "source_part_id": "999"},
                before=1, after=1, registry=self.registry,
            )
        self.assertEqual(raised.exception.code, "EVIDENCE_NOT_FOUND")

    def test_an_absent_source_file_is_refused(self) -> None:
        with self.assertRaises(PalError) as raised:
            read_evidence(
                "codex", str(self.tmp / "gone.jsonl"),
                {"source_kind": "codex", "source_digest": "a" * 64},
                before=1, after=1, registry=self.registry,
            )
        self.assertEqual(raised.exception.code, "EVIDENCE_NOT_FOUND")

    def test_reading_a_window_writes_nothing(self) -> None:
        import hashlib

        path, bundle = self._bundle("claude")
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        read_evidence(
            "claude", str(path), bundle["events"][0]["evidence_ref"],
            before=2, after=2, registry=self.registry,
        )
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_an_enormous_line_is_clipped(self) -> None:
        path = self.tmp / "big.jsonl"
        payload = {"seq": 1, "type": "user", "content": "x" * (MAX_ITEM_CHARS * 3)}
        path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        window = jsonl_window(
            str(path),
            {"source_kind": "claude", "source_part_id": "1", "source_digest": ""},
            provider="claude",
        )
        item = window["items"][0]["payload"]
        self.assertTrue(item.get("truncated"))
        self.assertLessEqual(len(item["excerpt"]), MAX_ITEM_CHARS)

    def test_an_unparsable_line_is_reported_not_crashed(self) -> None:
        path = self.tmp / "mixed.jsonl"
        path.write_text(
            json.dumps({"seq": 1, "type": "user", "content": "hi"}) + "\n{ broken\n",
            encoding="utf-8",
        )
        window = jsonl_window(
            str(path),
            {"source_kind": "codex", "source_part_id": "1", "source_digest": ""},
            provider="codex", before=0, after=1,
        )
        self.assertEqual(window["total_items"], 2)
        self.assertIn("unparsed_line", window["items"][1]["payload"])

    def test_the_digest_resolves_the_anchor_when_part_ids_collide(self) -> None:
        """Two lines can share a seq after an edit; the digest disambiguates."""
        path = self.tmp / "collide.jsonl"
        first = {"seq": 1, "type": "user", "content": "original"}
        second = {"seq": 1, "type": "user", "content": "replacement"}
        path.write_text(
            json.dumps(first) + "\n" + json.dumps(second) + "\n", encoding="utf-8"
        )
        digest = sha256_text("replacement")
        window = jsonl_window(
            str(path),
            {"source_kind": "claude", "source_part_id": "1", "source_digest": digest},
            provider="claude", before=0, after=0,
        )
        self.assertEqual(window["items"][0]["payload"]["content"], "replacement")


class UnsupportedProvidersStayHonest(unittest.TestCase):
    """A provider with no reader refuses; it does not invent a window."""

    def setUp(self) -> None:
        self.registry = load_registry()

    def test_the_generic_adapter_has_no_evidence_reader(self) -> None:
        with self.assertRaises(PalError) as raised:
            read_evidence(
                "generic", "x", {"source_kind": "generic"},
                before=1, after=1, registry=self.registry,
            )
        self.assertEqual(raised.exception.code, "EVIDENCE_UNSUPPORTED")

    def test_an_unknown_adapter_is_refused(self) -> None:
        with self.assertRaises(PalError) as raised:
            read_evidence(
                "telepathy", "x", {}, before=1, after=1, registry=self.registry
            )
        self.assertEqual(raised.exception.code, "EVIDENCE_UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
