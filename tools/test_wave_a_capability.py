"""Wave A: the write boundary (PAL-WRITE-01).

A boundary that is only written down is decoration. These tests prove the
denial is structural, data-driven, and applies to real paths on disk.
"""

from __future__ import annotations

import contextlib
import os
import unittest
from pathlib import Path
from unittest import mock

from saipal_engine import capability
from saipal_engine import paths as paths_mod
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


class AtomicWriteFinalNodeBoundary(unittest.TestCase):
    """T-122 closure retry (SRC-005 W2-002): the SHARED atomic write
    primitive must judge the requested final node BEFORE resolution erases
    its identity. `Path.resolve()` flattens a final symlink, so the old
    post-resolve `is_symlink()` test checked the TARGET, not the node the
    caller named: a write through `root/link.txt` silently replaced
    `root/target.txt` and left the symlink alive. The contract
    "refuses a symlinked or non-regular final node" is now enforced with
    non-following primitives (lstat + the Windows reparse-attribute probe),
    including dangling symlinks regardless of where their target would land,
    and every refusal leaves all pre-existing bytes untouched and creates no
    symlink target as a side effect.
    """

    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.external_root = Path(tempfile.mkdtemp())
        self.addCleanup(self._tmp.cleanup)

    def _symlink(self, link: Path, target: Path) -> None:
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable in this environment")

    def test_absent_regular_destination_inside_root_succeeds(self) -> None:
        target = self.root / "fresh.txt"
        result = atomic_write_bytes(target, b"fresh", root=self.root)
        self.assertEqual(target.read_bytes(), b"fresh")
        self.assertFalse(result.is_symlink())

    def test_regular_file_inside_root_is_atomically_replaced(self) -> None:
        target = self.root / "state.json"
        target.write_bytes(b"{\"v\": 1}")
        atomic_write_bytes(target, b"{\"v\": 2}", root=self.root)
        self.assertEqual(target.read_bytes(), b"{\"v\": 2}")
        self.assertFalse(target.is_symlink(), "replacement must stay a regular file")

    def test_final_symlink_to_existing_file_outside_root_is_refused(self) -> None:
        outside = self.external_root / "outside.txt"
        outside.write_bytes(b"outside bytes")
        link = self.root / "link.txt"
        self._symlink(link, outside)
        with self.assertRaises(PalError) as caught:
            atomic_write_bytes(link, b"x", root=self.root)
        self.assertEqual(caught.exception.code, "PATH_ESCAPE")
        self.assertEqual(outside.read_bytes(), b"outside bytes", "external bytes untouched")
        self.assertTrue(link.is_symlink(), "the indirection itself must survive")

    def test_final_symlink_to_existing_file_inside_root_is_refused(self) -> None:
        target = self.root / "target.txt"
        target.write_bytes(b"old bytes")
        link = self.root / "link.txt"
        self._symlink(link, target)
        with self.assertRaises(PalError) as caught:
            atomic_write_bytes(link, b"new bytes", root=self.root)
        self.assertEqual(caught.exception.code, "PATH_ESCAPE")
        self.assertEqual(target.read_bytes(), b"old bytes", "target bytes preserved")
        self.assertTrue(link.is_symlink())

    def test_dangling_final_symlink_to_outside_root_is_refused(self) -> None:
        link = self.root / "dangle.txt"
        self._symlink(link, self.external_root / "never.txt")
        with self.assertRaises(PalError) as caught:
            atomic_write_bytes(link, b"x", root=self.root)
        self.assertEqual(caught.exception.code, "PATH_ESCAPE")
        self.assertFalse((self.external_root / "never.txt").exists(), "no target created")
        self.assertTrue(link.is_symlink())

    def test_dangling_final_symlink_to_inside_root_is_refused(self) -> None:
        link = self.root / "dangle.txt"
        self._symlink(link, self.root / "never.md")
        with self.assertRaises(PalError) as caught:
            atomic_write_bytes(link, b"x", root=self.root)
        self.assertEqual(caught.exception.code, "PATH_ESCAPE")
        self.assertFalse((self.root / "never.md").exists(), "no target created")
        self.assertTrue(link.is_symlink())

    @unittest.skipIf(os.name == "nt", "POSIX fifo control; the Windows junction control carries the reparse case")
    def test_non_regular_final_node_is_refused(self) -> None:
        import stat as stat_mod

        fifo = self.root / "pipe"
        os.mkfifo(str(fifo))
        with self.assertRaises(PalError) as caught:
            atomic_write_bytes(fifo, b"x", root=self.root)
        self.assertEqual(caught.exception.code, "PATH_ESCAPE")
        self.assertTrue(stat_mod.S_ISFIFO(os.lstat(str(fifo)).st_mode))

    def test_parent_directory_junction_outside_root_is_refused(self) -> None:
        """A parent directory swapped for a junction/reparse point to an
        external directory must not carry the write outside the root."""
        if os.name != "nt":
            self.skipTest("Windows junction control (POSIX dir-symlink variant below)")
        import _winapi  # junction creation on Windows

        outside_dir = self.external_root / "extdir"
        outside_dir.mkdir()
        junction = self.root / "audit"
        junction.rmdir() if junction.exists() else None
        _winapi.CreateJunction(str(outside_dir), str(junction))
        try:
            with self.assertRaises(PalError) as caught:
                atomic_write_bytes(junction / "f.md", b"x", root=self.root)
            self.assertEqual(caught.exception.code, "PATH_ESCAPE")
            self.assertFalse((outside_dir / "f.md").exists(), "no file through the junction")
        finally:
            with contextlib.suppress(OSError):
                junction.rmdir()

    def test_parent_directory_symlink_outside_root_is_refused(self) -> None:
        """POSIX variant of the parent-indirection refusal."""
        if os.name == "nt":
            self.skipTest("POSIX directory-symlink control")
        outside_dir = self.external_root / "extdir"
        outside_dir.mkdir()
        sub = self.root / "audit"
        self._symlink(sub, outside_dir)
        with self.assertRaises(PalError) as caught:
            atomic_write_bytes(sub / "f.md", b"x", root=self.root)
        self.assertEqual(caught.exception.code, "PATH_ESCAPE")
        self.assertFalse((outside_dir / "f.md").exists())

    def test_refusal_preserves_all_pre_existing_bytes(self) -> None:
        """A refused write must leave every pre-existing byte in the tree."""
        target = self.root / "target.txt"
        target.write_bytes(b"keep me")
        sibling = self.root / "sibling.txt"
        sibling.write_bytes(b"sibling")
        link = self.root / "link.txt"
        self._symlink(link, target)
        with self.assertRaises(PalError):
            atomic_write_bytes(link, b"overwrite", root=self.root)
        self.assertEqual(target.read_bytes(), b"keep me")
        self.assertEqual(sibling.read_bytes(), b"sibling")
        leftovers = [p.name for p in self.root.iterdir() if p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [], "a refused write must leave no temp artifacts")

    def test_reparse_detection_actually_sees_a_junction(self) -> None:
        """Windows acceptance: carries_reparse_attr must return True for a
        REAL junction, proving the WinAPI path executes and detects -- not a
        code path that silently returns False on a non-Windows platform."""
        if os.name != "nt":
            self.skipTest("Windows junction acceptance")
        import _winapi

        real_dir = self.root / "real"
        real_dir.mkdir()
        junction = self.root / "junc"
        _winapi.CreateJunction(str(real_dir), str(junction))
        try:
            self.assertTrue(
                paths_mod.carries_reparse_attr(junction),
                "a real junction must be detected via the reparse attribute",
            )
            self.assertFalse(
                paths_mod.carries_reparse_attr(real_dir),
                "a plain directory must not be flagged as a reparse point",
            )
        finally:
            with contextlib.suppress(OSError):
                junction.rmdir()


if __name__ == "__main__":
    unittest.main()
