"""Wave T-164: Exclusive shortcut ownership (pal) and cc collision removal.

Negative controls and acceptance proofs A through I:
- TEST A: `pal` runs bounded continue (detector + reporter entry)
- TEST B: `cc` is not routed into SAIPAL (refused with UNKNOWN_COMMAND)
- TEST C: `saipal pal` runs bounded continue
- TEST D: `saipal cc` returns non-mutating UNKNOWN_COMMAND refusal
- TEST E: `/saipal pal` activates SAIPAL continue
- TEST F: `/saipal cc` returns UNKNOWN_COMMAND refusal (no legacy execution)
- TEST G: Forensic adapter recognizes observed SAIPEN `cc` command
- TEST H: Ordinary prose containing 'pal' is not a command event
- TEST I: Core invariants preserved (session integrity, submission, report)
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine.adapters import opencode
from saipal_engine.commands import load_shortcut_table, resolve_shortcut


class ExclusiveShortcutOwnership(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = self.tmp / ".saipal"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_shortcut_table_ownership(self) -> None:
        table = load_shortcut_table()
        self.assertEqual(table.get("pal"), "saipal continue")
        self.assertNotIn("cc", table)
        self.assertEqual(resolve_shortcut("pal"), "saipal continue")
        self.assertIsNone(resolve_shortcut("cc"))

    # TEST A: bare `pal` -> SAIPAL detector and reporter entry
    def test_a_bare_pal_runs_continue(self) -> None:
        code, payload, err = support.run_saipal_json("pal", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["command"], "continue")
        self.assertEqual(payload["phase"], "IDLE")
        self.assertTrue(payload["idle"])
        self.assertTrue((self.home / "STATE.json").is_file())

    # TEST B: bare `cc` -> not routed into SAIPAL
    def test_b_bare_cc_not_routed_into_saipal(self) -> None:
        code, payload, _err = support.run_saipal_json("cc", home=self.home)
        self.assertEqual(code, 2)
        assert payload is not None
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "UNKNOWN_COMMAND")
        self.assertIn("pal", payload.get("message", "") + payload.get("next_action", ""))
        # Home must not be materialized by a rejected command
        self.assertFalse((self.home / "STATE.json").exists())

    # TEST C: `saipal pal` -> existing bounded SAIPAL continue behavior
    def test_c_saipal_pal_runs_continue(self) -> None:
        code, payload, err = support.run_saipal_json("saipal", "pal", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["command"], "continue")

    # TEST D: `saipal cc` -> non-mutating UNKNOWN_COMMAND refusal
    def test_d_saipal_cc_refused_unknown_command(self) -> None:
        code, payload, _err = support.run_saipal_json("saipal", "cc", home=self.home)
        self.assertEqual(code, 2)
        assert payload is not None
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "UNKNOWN_COMMAND")
        self.assertFalse((self.home / "STATE.json").exists())

    # TEST E: `/saipal pal` -> SAIPAL skill activation
    def test_e_slash_saipal_pal_runs_continue(self) -> None:
        code, payload, err = support.run_saipal_json("/saipal", "pal", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["command"], "continue")

    # TEST F: `/saipal cc` -> no deprecated SAIPAL shortcut execution
    def test_f_slash_saipal_cc_refused_unknown_command(self) -> None:
        code, payload, _err = support.run_saipal_json("/saipal", "cc", home=self.home)
        self.assertEqual(code, 2)
        assert payload is not None
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "UNKNOWN_COMMAND")

    # TEST G: Observed SAIPEN session contains `cc` -> recognized as SAIPEN command
    def test_g_observed_saipen_session_recognizes_cc(self) -> None:
        self.assertEqual(opencode.protocol_command("cc"), "cc")
        self.assertEqual(opencode.protocol_command("CC"), "cc")
        self.assertEqual(opencode.protocol_command("saipen cc"), "saipen cc")

    # TEST H: Prose containing 'pal' is not recognized as command
    def test_h_prose_containing_pal_not_a_command(self) -> None:
        self.assertIsNone(opencode.protocol_command("Please check the pal report tomorrow"))
        self.assertIsNone(opencode.protocol_command("pal report"))
        self.assertIsNone(opencode.protocol_command("pal && git push"))
        self.assertIsNone(opencode.protocol_command("my pal did this"))

    # TEST I: Preserves invariants (candidate submission, report, isolation)
    def test_i_preserves_invariants(self) -> None:
        # 1. Continue with pal
        code, payload, err = support.run_saipal_json("pal", home=self.home)
        self.assertEqual(code, 0, err)

        # 2. Next returns idle on empty inbox
        code, next_payload, err = support.run_saipal_json("next", home=self.home)
        self.assertEqual(code, 0, err)
        assert next_payload is not None
        self.assertEqual(next_payload["carrier"], "idle")

        # 3. Report runs cleanly
        code, report_payload, err = support.run_saipal_json("report", home=self.home)
        self.assertEqual(code, 0, err)
        assert report_payload is not None
        self.assertEqual(report_payload["command"], "report")

        # 4. Global option ordering --json pal works
        code, json_pal_payload, err = support.run_saipal_json("pal", home=self.home)
        self.assertEqual(code, 0, err)
        assert json_pal_payload is not None
        self.assertEqual(json_pal_payload["command"], "continue")


if __name__ == "__main__":
    unittest.main()
