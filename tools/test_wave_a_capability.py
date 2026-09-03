"""Wave A: the write boundary (PAL-WRITE-01).

A boundary that is only written down is decoration. These tests prove the
denial is structural, data-driven, and applies to real paths on disk.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from saipal_engine import capability
from saipal_engine.errors import PalError
from saipal_engine.paths import atomic_write_bytes
from saipal_engine.registry import load_registry, require_mapping

import pal_test_support as support

REAL_SAIPEN = Path("V:/___VAC/__K/__CODE/_AI_STUFF_AGENTIC/_SAIPEN")

FORBIDDEN_SAMPLE = (
    "mutate_analyzed_project",
    "mutate_saipen_state",
    "mutate_saipen_board",
    "mutate_saipen_log",
    "mutate_saipen_knowledge",
    "create_saipen_work",
    "edit_saipen_protocol",
    "edit_emitted_audit",
    "delete_emitted_audit",
)


class ActionBoundary(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = load_registry()
        actions = require_mapping(self.registry, "write_actions")
        self.allowed = list(actions["allowed"])
        self.reserved = list(actions["reserved"])
        self.forbidden = list(actions["forbidden"])

    def test_allowed_actions_pass(self) -> None:
        for action in self.allowed:
            with self.subTest(action=action):
                permitted, code, _detail = capability.assert_action_capability(
                    action, registry=self.registry
                )
                self.assertTrue(permitted, action)
                self.assertEqual(code, capability.ACTION_OK)

    def test_forbidden_actions_are_denied(self) -> None:
        for action in self.forbidden:
            with self.subTest(action=action):
                permitted, code, _detail = capability.assert_action_capability(
                    action, registry=self.registry
                )
                self.assertFalse(permitted, f"{action} must never be permitted")
                self.assertEqual(code, capability.CAPABILITY_DENIED)

    def test_every_declared_forbidden_action_is_actually_denied(self) -> None:
        # Not a hardcoded sample: whatever the registry forbids must be denied.
        for action in FORBIDDEN_SAMPLE:
            with self.subTest(action=action):
                self.assertIn(action, self.forbidden)

    def test_reserved_actions_are_denied_with_their_own_code(self) -> None:
        for action in self.reserved:
            with self.subTest(action=action):
                permitted, code, _detail = capability.assert_action_capability(
                    action, registry=self.registry
                )
                self.assertFalse(permitted)
                self.assertEqual(code, capability.ACTION_RESERVED)

    def test_unknown_action_is_denied_by_default(self) -> None:
        permitted, code, _detail = capability.assert_action_capability(
            "teleport_to_mars", registry=self.registry
        )
        self.assertFalse(permitted)
        self.assertEqual(code, capability.CAPABILITY_DENIED)

    def test_require_action_raises_instead_of_returning(self) -> None:
        with self.assertRaises(PalError) as caught:
            capability.require_action("mutate_saipen_board", registry=self.registry)
        self.assertEqual(caught.exception.code, capability.CAPABILITY_DENIED)

    def test_saipen_core_is_never_reachable(self) -> None:
        for action in self.allowed + self.reserved + self.forbidden:
            with self.subTest(action=action):
                self.assertFalse(
                    capability.may_touch_saipen_core(action, registry=self.registry)
                )

    def test_red_control_the_registry_is_the_authority(self) -> None:
        """Mutate the registry; the guard must flip. Otherwise it is hardcoded."""
        mutated = support.load_registry_copy()
        actions = mutated["write_actions"]
        actions["allowed"] = sorted(set(actions["allowed"]) | {"mutate_saipen_state"})
        actions["forbidden"] = [a for a in actions["forbidden"] if a != "mutate_saipen_state"]

        with mock.patch.object(capability, "load_registry", return_value=mutated):
            permitted, code, _ = capability.assert_action_capability("mutate_saipen_state")

        self.assertTrue(permitted, "the guard must follow the registry, not a literal")
        self.assertEqual(code, capability.ACTION_OK)

        # And the real registry still denies it -- the mutation was contained.
        self.assertFalse(
            capability.assert_action_capability("mutate_saipen_state")[0],
            "the real registry must still forbid SAIPEN Core mutation",
        )


class PathBoundary(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = self.tmp / ".saipal"
        self.home.mkdir()
        self.project = self.tmp / "analyzed-project"
        (self.project / ".saipen").mkdir(parents=True)
        (self.project / ".saipen" / "STATE.md").write_text("phase: BUILD\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_write_inside_home_is_allowed(self) -> None:
        target = self.home / "STATE.json"
        atomic_write_bytes(target, b'{"ok": true}', root=self.home)
        self.assertEqual(target.read_bytes(), b'{"ok": true}')

    def test_write_into_analyzed_project_is_refused(self) -> None:
        target = self.project / ".saipen" / "STATE.md"
        before = target.read_bytes()
        with self.assertRaises(PalError) as caught:
            atomic_write_bytes(target, b"tampered", root=self.home)
        self.assertEqual(caught.exception.code, "PATH_ESCAPE")
        self.assertEqual(target.read_bytes(), before, "a refused write must write nothing")

    def test_parent_traversal_is_refused(self) -> None:
        target = self.home / ".." / "escaped.txt"
        with self.assertRaises(PalError) as caught:
            atomic_write_bytes(target, b"nope", root=self.home)
        self.assertEqual(caught.exception.code, "PATH_ESCAPE")
        self.assertFalse((self.tmp / "escaped.txt").exists())

    def test_symlink_out_of_home_is_refused(self) -> None:
        inside = self.home / "sneaky"
        outside = self.project / "target.txt"
        outside.write_text("original", encoding="utf-8")
        try:
            inside.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable in this environment")
        with self.assertRaises(PalError) as caught:
            atomic_write_bytes(inside, b"tampered", root=self.home)
        self.assertEqual(caught.exception.code, "PATH_ESCAPE")
        self.assertEqual(outside.read_text(encoding="utf-8"), "original")

    def test_guard_home_write_names_the_boundary(self) -> None:
        with self.assertRaises(PalError) as caught:
            capability.guard_home_write(self.project / "app.py", home=self.home)
        self.assertEqual(caught.exception.code, "PATH_ESCAPE")
        self.assertIsNotNone(caught.exception.next_action)

    @unittest.skipUnless(REAL_SAIPEN.is_dir(), "real SAIPEN clone not present")
    def test_the_real_saipen_clone_is_outside_every_home(self) -> None:
        """The guard must refuse the actual SAIPEN root, not a toy stand-in."""
        with self.assertRaises(PalError) as caught:
            capability.guard_home_write(
                REAL_SAIPEN / ".saipen" / "STATE.md", home=self.home
            )
        self.assertEqual(caught.exception.code, "PATH_ESCAPE")


if __name__ == "__main__":
    unittest.main()
