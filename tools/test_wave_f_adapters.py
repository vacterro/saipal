"""Wave F acceptance bar: provider adapters.

Tests generic/claude normalization, registry, and the transcript guard. The
guard is the most important thing here: a normalized bundle must not contain
the original conversation text, ever, in any field the auditor later quotes.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import bundle as bundle_mod
from saipal_engine.adapters import (
    ADAPTER_REGISTRY,
    claude,
    codex,
    gemini,
    generic,
    opencode,
    termisai,
)

COLD = "conformant-cold.json"
FORBIDDEN_CONTENT_KEYS = (
    "content", "text", "body", "transcript", "raw", "message", "payload",
)


class AdapterRegistry(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_generic_adapter_passthrough(self) -> None:
        self.assertEqual(generic.NAME, "generic")
        self.assertEqual(claude.NAME, "claude")
        self.assertEqual(codex.NAME, "codex")
        self.assertEqual(opencode.NAME, "opencode")
        self.assertEqual(termisai.NAME, "termisai")
        self.assertEqual(gemini.NAME, "gemini")
        for name, mod in (
            ("generic", generic),
            ("claude", claude),
            ("codex", codex),
            ("opencode", opencode),
            ("termisai", termisai),
            ("gemini", gemini),
        ):
            self.assertIn(name, ADAPTER_REGISTRY)
            self.assertIs(ADAPTER_REGISTRY[name], mod)

    def test_generic_normalize_validates(self) -> None:
        fixture = support.fixture(COLD)
        with tempfile.TemporaryDirectory() as tmp_dir:
            staged = Path(tmp_dir) / "conformant-cold.json"
            staged.write_bytes(fixture.read_bytes())
            result = generic.normalize(str(staged))

        self.assertIsInstance(result, dict)
        self.assertEqual(result["session_id"], "golden-cold-001")
        self.assertEqual(result["adapter"], "generic")
        # generic normalize is a passthrough of the canonical bundle, so it
        # also passes the validator unchanged.
        self.assertEqual(bundle_mod.validate_bundle(result), [])

    def _assert_valid_normalized(self, result: dict, adapter: str) -> None:
        self.assertEqual(result["adapter"], adapter)
        self.assertIn("events", result)
        seqs = [event["seq"] for event in result["events"]]
        self.assertEqual(seqs, sorted(seqs), "seqs must be strictly increasing")
        for index in range(1, len(seqs)):
            self.assertGreater(seqs[index], seqs[index - 1])
        for event in result["events"]:
            leaked = [k for k in FORBIDDEN_CONTENT_KEYS if k in event]
            self.assertEqual(
                leaked, [],
                f"event {event.get('seq')} leaks raw-content fields: {leaked}",
            )
        self.assertEqual(bundle_mod.validate_bundle(result), [])

    def test_codex_normalize_builds_a_valid_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sess-codex-001.jsonl"
            lines = [
                {"type": "user", "content": "hello"},
                {"type": "command", "content": "cc"},
                {"type": "tool_call", "content": "read",
                 "name": "read", "input": {"path": "x"}},
                {"type": "session_boundary", "content": "cut"},
            ]
            path.write_text(
                "\n".join(json.dumps(line) for line in lines) + "\n",
                encoding="utf-8",
            )
            result = codex.normalize(str(path))

        self.assertEqual(result["session_id"], "sess-codex-001")
        self.assertEqual(result["runtime"]["provider"], "openai")
        self.assertEqual(len(result["events"]), 4)
        self._assert_valid_normalized(result, "codex")

    def test_opencode_normalize_builds_a_valid_bundle(self) -> None:
        import sqlite3

        with tempfile.TemporaryDirectory() as tmp_dir:
            home = Path(tmp_dir) / "opencode"
            home.mkdir()
            db = home / "opencode.db"
            con = sqlite3.connect(str(db))
            cur = con.cursor()
            cur.executescript(
                """
                CREATE TABLE session (id TEXT PRIMARY KEY, project_id TEXT, workspace_id TEXT,
                    parent_id TEXT, slug TEXT, directory TEXT, path TEXT, title TEXT,
                    version TEXT, share_url TEXT, summary_additions INTEGER, summary_deletions INTEGER,
                    summary_files INTEGER, summary_diffs TEXT, metadata TEXT, cost REAL,
                    tokens_input INTEGER, tokens_output INTEGER, tokens_reasoning INTEGER,
                    tokens_cache_read INTEGER, tokens_cache_write INTEGER, revert TEXT,
                    permission TEXT, agent TEXT, model TEXT, time_created INTEGER, time_updated INTEGER,
                    time_compacting INTEGER, time_archived INTEGER);
                CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, time_created INTEGER,
                    time_updated INTEGER, data TEXT);
                CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, session_id TEXT,
                    time_created INTEGER, time_updated INTEGER, data TEXT);
                """
            )
            cur.execute(
                "INSERT INTO session(id, directory, title, version, agent, model, time_created, time_updated) "
                "VALUES ('ses-oc-001', 'V:/demo', 'demo', '1.18.25', 'build', ?, 1, 2)",
                (json.dumps({"id": "gpt-5", "providerID": "x"}),),
            )
            cur.execute(
                "INSERT INTO message(id, session_id, time_created, data) "
                "VALUES ('m1', 'ses-oc-001', 10, ?)",
                (json.dumps({"role": "user"}),),
            )
            for part_id, ts, data in (
                ("p1", 11, {"type": "text", "text": "hello"}),
                ("p2", 12, {"type": "tool", "tool": "bash",
                      "state": {"status": "completed", "input": {"command": "cc"}, "output": "ok"}}),
                ("p3", 13, {"type": "step-finish", "reason": "done"}),
            ):
                cur.execute(
                    "INSERT INTO part(id, message_id, session_id, time_created, data) "
                    "VALUES (?, 'm1', 'ses-oc-001', ?, ?)",
                    (part_id, ts, json.dumps(data)),
                )
            con.commit()
            con.close()

            candidates = opencode.discover(str(home))
            self.assertEqual(len(candidates), 1)
            result = opencode.normalize(candidates[0]["path"])

        self.assertEqual(result["session_id"], "ses-oc-001")
        self.assertEqual(result["runtime"]["model"], "gpt-5")
        self.assertEqual(result["temperature"], "COLD")
        self._assert_valid_normalized(result, "opencode")

    def test_codex_malformed_line_is_safe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sess-codex-bad.jsonl"
            path.write_text(
                "not json\n"
                + json.dumps({"type": "user", "content": "hello"})
                + "\n"
                "{broken\n",
                encoding="utf-8",
            )
            result = codex.normalize(str(path))

        self.assertEqual(len(result["events"]), 1)
        self.assertEqual(bundle_mod.validate_bundle(result), [])

    def test_termisai_normalize_builds_a_valid_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sess-termisai-001.jsonl"
            lines = [
                {"type": "user", "content": "hello"},
                {"type": "command", "content": "cc"},
                {"type": "session_boundary", "content": "cut"},
            ]
            path.write_text(
                "\n".join(json.dumps(line) for line in lines) + "\n",
                encoding="utf-8",
            )
            result = termisai.normalize(str(path))

        self.assertEqual(result["session_id"], "sess-termisai-001")
        self.assertEqual(result["runtime"]["provider"], "termisai")
        self.assertEqual(len(result["events"]), 3)
        self._assert_valid_normalized(result, "termisai")

    def test_gemini_normalize_builds_a_valid_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sess-gemini-001.jsonl"
            lines = [
                {"type": "user_message", "content": "hello", "model": "gemini-2.5"},
                {"type": "tool_call", "content": "read",
                 "name": "read", "input": {"path": "x"}},
                {"type": "assistant_message", "content": "ok"},
                {"type": "session_boundary", "content": "cut"},
            ]
            path.write_text(
                "\n".join(json.dumps(line) for line in lines) + "\n",
                encoding="utf-8",
            )
            result = gemini.normalize(str(path))

        self.assertEqual(result["session_id"], "sess-gemini-001")
        self.assertEqual(result["runtime"]["model"], "gemini-2.5")
        self.assertEqual(len(result["events"]), 4)
        self._assert_valid_normalized(result, "gemini")

    def test_claude_normalize_builds_a_valid_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sess-claude-001.jsonl"
            lines = [
                {"type": "user", "content": "hello"},
                {"type": "tool_call", "content": "read",
                 "name": "read", "input": {"path": "x"}},
                {"type": "assistant", "content": "ok"},
                {"type": "session_boundary", "content": "cut"},
            ]
            path.write_text(
                "\n".join(json.dumps(line) for line in lines) + "\n",
                encoding="utf-8",
            )
            result = claude.normalize(str(path))

        self.assertEqual(result["adapter"], "claude")
        self.assertEqual(result["session_id"], "sess-claude-001")
        self.assertIn("events", result)
        self.assertEqual(len(result["events"]), 4)

        seqs = [event["seq"] for event in result["events"]]
        self.assertEqual(seqs, sorted(seqs), "seqs must be strictly increasing")
        for index in range(1, len(seqs)):
            self.assertGreater(seqs[index], seqs[index - 1])

        for event in result["events"]:
            leaked = [k for k in FORBIDDEN_CONTENT_KEYS if k in event]
            self.assertEqual(
                leaked, [],
                f"event {event.get('seq')} leaks raw-content fields: {leaked}",
            )

        # the canonical form must validate as a real bundle
        self.assertEqual(bundle_mod.validate_bundle(result), [])

    def test_claude_malformed_line_is_safe(self) -> None:
        """Garbage lines are skipped; valid ones survive; the result is valid."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sess-malformed.jsonl"
            path.write_text(
                "this is not json at all\n"
                + json.dumps({"type": "user", "content": "hello"})
                + "\n"
                "{also broken\n"
                + json.dumps({"type": "assistant", "content": "world"})
                + "\n",
                encoding="utf-8",
            )
            result = claude.normalize(str(path))

        self.assertEqual(result["adapter"], "claude")
        # only the two valid lines survive
        self.assertEqual(len(result["events"]), 2)
        seqs = [event["seq"] for event in result["events"]]
        self.assertEqual(seqs, sorted(set(seqs)))
        self.assertEqual(bundle_mod.validate_bundle(result), [])

    def test_unknown_adapter_is_not_registered(self) -> None:
        self.assertNotIn("anthropic", ADAPTER_REGISTRY)
        self.assertNotIn("llm", ADAPTER_REGISTRY)
        self.assertNotIn("gpt", ADAPTER_REGISTRY)
        # the registered set is exactly what the spec says it is
        self.assertEqual(
            set(ADAPTER_REGISTRY.keys()),
            {"generic", "claude", "codex", "opencode", "termisai", "gemini"},
        )


if __name__ == "__main__":
    unittest.main()
