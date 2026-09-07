"""Wave A acceptance bar, exercised through the real CLI.

Every test here runs `python -B tools/saipal.py` in a subprocess, so the suite
proves the shipped entry point behaves, not just the library underneath it.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pal_test_support as support

TOOLS_DIR = support.TOOLS_DIR


class ContinueCycle(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = self.tmp / ".saipal"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # -- acceptance bar 1 and 2 ------------------------------------------- #

    def test_clean_continue_returns_idle(self) -> None:
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["phase"], "IDLE")
        self.assertTrue(payload["idle"])
        self.assertEqual(payload["sessions_indexed"], 0)
        self.assertEqual(payload["candidates"], 0)
        self.assertEqual(payload["audits_emitted"], 0)

    def test_clean_continue_materializes_the_home(self) -> None:
        support.run_saipal("continue", home=self.home)
        for name in ("STATE.json", "LOG.jsonl", "sources.json", "locks", "session_inbox"):
            self.assertTrue((self.home / name).exists(), f"{name} was not created")

    def test_second_run_creates_nothing(self) -> None:
        _code, first, _err = support.run_saipal_json("continue", home=self.home)
        assert first is not None
        self.assertTrue(first["created"]["created_files"])

        _code, second, _err = support.run_saipal_json("continue", home=self.home)
        assert second is not None
        self.assertEqual(second["created"]["created_dirs"], [])
        self.assertEqual(second["created"]["created_files"], [])

    def test_continue_materializes_a_missing_home_directory(self) -> None:
        nested = self.tmp / "deeper" / ".saipal"
        code, payload, err = support.run_saipal_json("continue", home=nested)
        self.assertEqual(code, 0, err)
        self.assertTrue((nested / "STATE.json").is_file())

    # -- acceptance bar 3: status and next are read-only ------------------- #

    def test_status_is_read_only(self) -> None:
        support.run_saipal("continue", home=self.home)
        before = support.tree_digest(self.home)
        code, _out, err = support.run_saipal("status", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(before, support.tree_digest(self.home), "status mutated the home")

    def test_next_is_read_only(self) -> None:
        support.run_saipal("continue", home=self.home)
        before = support.tree_digest(self.home)
        code, _out, err = support.run_saipal("next", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(before, support.tree_digest(self.home), "next mutated the home")

    def test_status_refuses_without_a_home(self) -> None:
        missing = self.tmp / "nothing-here"
        code, payload, _err = support.run_saipal_json("status", home=missing)
        self.assertEqual(code, 3)
        assert payload is not None
        self.assertEqual(payload["code"], "NO_HOME")
        self.assertFalse(missing.exists(), "a read-only command created a home")

    def test_next_refuses_without_a_home(self) -> None:
        missing = self.tmp / "nothing-here"
        code, payload, _err = support.run_saipal_json("next", home=missing)
        self.assertEqual(code, 3)
        assert payload is not None
        self.assertEqual(payload["code"], "NO_HOME")
        self.assertFalse(missing.exists())

    # -- acceptance bar 4: state survives restart -------------------------- #

    def test_state_survives_restart(self) -> None:
        support.run_saipal("continue", home=self.home)
        _code, first, _err = support.run_saipal_json("status", home=self.home)
        _code, second, _err = support.run_saipal_json("status", home=self.home)
        assert first is not None and second is not None
        self.assertEqual(first["phase"], second["phase"])
        self.assertEqual(first["last_checkpoint"], second["last_checkpoint"])
        self.assertGreater(second["log_events"], 0)

    # -- acceptance bar 5: malformed state is refused, not guessed --------- #

    def test_malformed_state_is_refused_and_preserved(self) -> None:
        support.run_saipal("continue", home=self.home)
        target = self.home / "STATE.json"
        garbage = b"/* half a thought */"
        target.write_bytes(garbage)

        code, payload, _err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 1)
        assert payload is not None
        self.assertEqual(payload["code"], "STATE_UNRECOVERABLE")
        self.assertEqual(target.read_bytes(), garbage, "the corrupt state was overwritten")

    def test_status_also_refuses_a_malformed_state(self) -> None:
        support.run_saipal("continue", home=self.home)
        (self.home / "STATE.json").write_text("nope", encoding="utf-8")
        code, payload, _err = support.run_saipal_json("status", home=self.home)
        self.assertEqual(code, 1)
        assert payload is not None
        self.assertEqual(payload["code"], "STATE_UNRECOVERABLE")

    def test_invalid_source_registry_is_refused(self) -> None:
        support.run_saipal("continue", home=self.home)
        (self.home / "sources.json").write_text('{"sources": "not a list"}', encoding="utf-8")
        code, payload, _err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 1)
        assert payload is not None
        self.assertEqual(payload["code"], "INVALID_SOURCE_REGISTRY")

    # -- acceptance bar 6: no external project mutation -------------------- #

    def test_continue_never_touches_an_analyzed_project(self) -> None:
        project = self.tmp / "analyzed"
        (project / ".saipen").mkdir(parents=True)
        (project / ".saipen" / "STATE.md").write_text("phase: BUILD\n", encoding="utf-8")
        (project / "app.py").write_text("print('hello')\n", encoding="utf-8")

        support.run_saipal("continue", home=self.home)
        support.write_sources(
            self.home,
            [{"id": "p1", "kind": "generic", "path": str(project), "enabled": True}],
        )
        before = support.tree_digest(project)

        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(
            support.tree_digest(project), before, "SAIPAL mutated the analyzed project"
        )
        assert payload is not None
        self.assertTrue(payload["discovered_sources"][0]["exists"])

    # -- acceptance bar 10: no session parsing, no audits ------------------ #

    def test_configured_source_is_ready_for_dispatch(self) -> None:
        source_dir = self.tmp / "sessions"
        source_dir.mkdir()
        support.run_saipal("continue", home=self.home)
        support.write_sources(
            self.home,
            [{"id": "s1", "kind": "generic", "path": str(source_dir), "enabled": True}],
        )

        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        self.assertEqual(len(payload["discovered_sources"]), 1)
        source = payload["discovered_sources"][0]
        self.assertEqual(source["status"], "READY")
        self.assertEqual(source["sessions"], 0)
        self.assertEqual(payload["sessions_indexed"], 0)
        self.assertEqual(payload["audits_emitted"], 0)

    def test_disabled_source_is_reported_disabled(self) -> None:
        source_dir = self.tmp / "sessions"
        source_dir.mkdir()
        support.run_saipal("continue", home=self.home)
        support.write_sources(
            self.home,
            [{"id": "s1", "kind": "generic", "path": str(source_dir), "enabled": False}],
        )
        _code, payload, _err = support.run_saipal_json("continue", home=self.home)
        assert payload is not None
        self.assertEqual(payload["discovered_sources"][0]["status"], "DISABLED")

    def test_no_audit_files_are_written(self) -> None:
        source_dir = self.tmp / "sessions"
        source_dir.mkdir()
        support.run_saipal("continue", home=self.home)
        support.write_sources(
            self.home,
            [{"id": "s1", "kind": "generic", "path": str(source_dir), "enabled": True}],
        )
        before = support.checkout_audit_entries()
        support.run_saipal("continue", home=self.home)
        self.assertFalse((self.home / "audit").exists())
        self.assertEqual(support.checkout_audit_entries(), before)

    # -- command surface --------------------------------------------------- #

    def test_unknown_command_exits_with_usage(self) -> None:
        code, payload, _err = support.run_saipal_json("scan", home=self.home)
        self.assertEqual(code, 2)
        assert payload is not None
        self.assertEqual(payload["code"], "UNKNOWN_COMMAND")

    def test_cc_alias_runs_continue(self) -> None:
        code, payload, err = support.run_saipal_json("cc", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        self.assertEqual(payload["command"], "continue")

    def test_bare_invocation_runs_continue(self) -> None:
        if str(TOOLS_DIR) not in sys.path:
            sys.path.insert(0, str(TOOLS_DIR))
        import contextlib
        import io

        import saipal

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            with mock.patch.dict(os.environ, {"SAIPAL_HOME": str(self.home)}):
                code = saipal.main([])
        self.assertEqual(code, 0)
        self.assertIn("phase: IDLE", buffer.getvalue())
        self.assertTrue((self.home / "STATE.json").is_file())

    def test_read_only_commands_take_no_arguments(self) -> None:
        support.run_saipal("continue", home=self.home)
        code, payload, _err = support.run_saipal_json("status", "extra", home=self.home)
        self.assertEqual(code, 2)
        assert payload is not None
        self.assertEqual(payload["code"], "USAGE")

    def test_unknown_option_exits_with_usage(self) -> None:
        code, payload, _err = support.run_saipal_json("--teleport", home=self.home)
        self.assertEqual(code, 2)
        assert payload is not None
        self.assertEqual(payload["code"], "USAGE")

    # -- usability: compact output ----------------------------------------- #

    def test_status_output_is_compact(self) -> None:
        support.run_saipal("continue", home=self.home)
        code, out, _err = support.run_saipal("status", home=self.home)
        self.assertEqual(code, 0)
        self.assertLess(len(out), 2000, "status dumped too much")
        for line in out.splitlines():
            self.assertLess(len(line), 220, f"line too long: {line!r}")

    def test_next_reports_a_carrier(self) -> None:
        source_dir = self.tmp / "sessions"
        source_dir.mkdir()
        support.run_saipal("continue", home=self.home)
        _code, payload, _err = support.run_saipal_json("next", home=self.home)
        assert payload is not None
        self.assertEqual(payload["carrier"], "idle")

        support.write_sources(
            self.home,
            [{"id": "s1", "kind": "generic", "path": str(source_dir), "enabled": True}],
        )
        _code, payload, _err = support.run_saipal_json("next", home=self.home)
        assert payload is not None
        self.assertEqual(payload["carrier"], "discover-sources")

    # -- red controls ------------------------------------------------------ #

    def test_red_control_digest_detects_a_real_change(self) -> None:
        """The read-only assertions above are worthless if the digest is blind."""
        support.run_saipal("continue", home=self.home)
        before = support.tree_digest(self.home)
        (self.home / "sneaky.txt").write_text("tamper", encoding="utf-8")
        self.assertNotEqual(before, support.tree_digest(self.home))

    def test_lock_is_released_after_a_cycle(self) -> None:
        support.run_saipal("continue", home=self.home)
        self.assertFalse((self.home / "locks" / "saipal.lock").exists())


class DrainLoop(unittest.TestCase):
    """`continue --drain` repeats bounded cycles until there is nothing left.

    The point of the flag is that an agent driving SAIPAL does not have to
    re-invoke `continue` until it guesses the backlog is gone: the loop stops on
    a real terminal condition and says which one it was.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _drain(self) -> dict:
        code, payload, err = support.run_saipal_json("continue", "--drain", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        return payload

    def test_an_empty_home_drains_in_one_cycle(self) -> None:
        payload = self._drain()
        self.assertTrue(payload["drain"])
        self.assertEqual(payload["drain_cycles"], 1)
        self.assertEqual(payload["drain_outcome"], "idle")
        self.assertFalse(payload["drain_blocked"])

    def test_a_backlog_is_drained_and_totals_are_summed(self) -> None:
        support.put_inbox(self.home, "conformant-cold.json", "no-finding-normal.json")
        payload = self._drain()
        self.assertEqual(payload["drain_outcome"], "idle")
        self.assertEqual(payload["sessions_indexed"], 2)
        self.assertEqual(payload["cycles"], payload["drain_cycles"])
        self.assertEqual(len(payload["cycle_results"]), payload["drain_cycles"])

    def test_a_conflicted_session_blocks_the_drain_instead_of_looping(self) -> None:
        """A CONFLICT is an operator task, so draining stops and says so."""
        support.put_inbox(self.home, "hot-partial.json")
        support.run_saipal("continue", home=self.home)
        support.clear_inbox(self.home)
        support.put_inbox(self.home, "hot-prefix-mutated.json")
        payload = self._drain()
        self.assertEqual(payload["drain_outcome"], "blocked")
        self.assertTrue(payload["drain_blocked"])
        self.assertIn("conflict", payload["drain_reason"])

    def test_drain_refuses_an_unknown_argument(self) -> None:
        code, payload, _err = support.run_saipal_json("continue", "--forever", home=self.home)
        self.assertEqual(code, 2)
        assert payload is not None
        self.assertEqual(payload["code"], "USAGE")

    def test_a_plain_continue_is_still_one_cycle(self) -> None:
        """Red control: the loop must be opt-in, never the default."""
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        self.assertNotIn("drain", payload)


if __name__ == "__main__":
    unittest.main()
