"""CORE-001: one common writer fence over shared .saipal state.

Audit SRC-004 CORE-001 proved durable data loss: `submit_candidate` ran its
load_index -> save_index transaction with NO writer lock while a concurrent
HomeLock-protected `continue` imported a generation; the stale save erased
the intake. The repair is one reentrant WriterFence (file-fenced across
processes, depth-counted per thread inside one) taken by submit, intake,
rebind and analyst-setup, with paid model reasoning OUTSIDE it.

Controls here prove fence exclusivity DURING the submit transaction,
reentrancy, cross-thread exclusion, and a mutant red control that reproduces
the audited stale-save loss when the fence is bypassed.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from contextlib import nullcontext
from pathlib import Path

import pal_test_support as support
from saipal_engine import carrier as carrier_mod
from saipal_engine import sessions as sessions_mod
from saipal_engine import submit as submit_mod
from saipal_engine.errors import PalError
from saipal_engine.inbox import import_inbox
from saipal_engine.paths import (
    HomeLock,
    atomic_write_json,
    writer_fence,
)

CLEAN = "conformant-cold.json"


def _clean_candidate(packet: dict) -> dict:
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


class _FenceHarness(unittest.TestCase):
    """A home with the conformant session imported and one ready candidate."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        support.put_inbox(self.home, CLEAN)
        support.run_saipal("continue", home=self.home)
        self._candidate()
        support.clear_inbox(self.home)
        self._patch_save()

    def _patch_save(self):
        """Arm a controllable pause just before the index save lands."""
        self.entered = threading.Event()
        self.release = threading.Event()
        self.holder: dict = {"armed": False}
        real_save = sessions_mod.save_index
        outer = self

        def hooked(home, index, *, registry=None):
            if outer.holder.get("armed"):
                outer.entered.set()
                outer.release.wait(10)
            return real_save(home, index, registry=registry)

        self._original_save = real_save
        self.holder["hook"] = hooked
        sessions_mod.save_index = hooked
        self.addCleanup(self._unpatch_save)

    def _unpatch_save(self):
        sessions_mod.save_index = self._original_save

    def _candidate(self):
        packet = carrier_mod.build_carrier(self.home)
        self.session_id = packet["session"]["session_id"]
        self.candidate = _clean_candidate(packet)


class SubmitHoldsCommonWriterFence(_FenceHarness):
    def test_concurrent_home_writer_is_excluded_during_submit_transaction(self):
        self.holder["armed"] = True
        outcome: dict = {}

        def analyst():
            try:
                outcome["receipt"] = submit_mod.submit_candidate(self.home, self.candidate)
                outcome["error"] = None
            except Exception as exc:  # pragma: no cover - surfaced below
                outcome["error"] = exc

        worker = threading.Thread(target=analyst)
        worker.start()
        self.assertTrue(self.entered.wait(10), "submit never reached its index save")
        # A concurrent HomeLock writer (what `saipal continue` takes) must be
        # refused while the fenced submit transaction is in flight.
        intruder = HomeLock(self.home, ttl=30)
        outcome["intruder_acquired"] = intruder.acquire()
        if outcome["intruder_acquired"]:  # pragma: no cover - would be a defect
            intruder.release()
        self.release.set()
        worker.join(15)
        self.holder["armed"] = False

        self.assertFalse(outcome.get("intruder_acquired", True),
                         "a concurrent writer entered during the fenced submit")
        self.assertIsNone(outcome.get("error"))
        self.assertTrue(outcome["receipt"].get("receipt_id"))


class MutantBypassingFenceLosesIntake(_FenceHarness):
    """RED CONTROL: the audited loss, reproduced with the fence bypassed."""

    def test_audited_ordering_stale_save_after_intake_erases_generation(self):
        import saipal_engine.paths as paths_mod

        original_fence = paths_mod.writer_fence
        paths_mod.writer_fence = lambda home: nullcontext()
        self.holder["armed"] = True
        result: dict = {}

        def analyst():
            try:
                submit_mod.submit_candidate(self.home, self.candidate)
            except Exception as exc:
                result["error"] = exc

        worker = threading.Thread(target=analyst)
        worker.start()
        try:
            self.assertTrue(self.entered.wait(10))
            # The concurrent `continue` completes its intake of a DIFFERENT
            # new session while the submit transaction is suspended just
            # before its own save.
            support.put_inbox(self.home, "conformant-cold-other.json")
            report = import_inbox(self.home)
            result["intake_imported"] = len(report["imported"])
            self.release.set()
            worker.join(15)
        finally:
            paths_mod.writer_fence = original_fence
            self.holder["armed"] = False

        self.assertEqual(result.get("intake_imported"), 1)
        _status, index, _detail = sessions_mod.load_index(self.home)
        records = [r for r in index["sessions"] if r.get("session_id") == "golden-cold-002"]
        self.assertEqual(
            len(records), 0,
            "RED CONTROL EXPECTED THE LOSS: the unfenced stale save erased the "
            "concurrent intake generation (audit CORE-001 reproduction)",
        )


class FenceReentrancyAndThreads(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def test_nested_same_thread_acquisition_is_reentrant(self):
        with writer_fence(self.home):
            with writer_fence(self.home):
                pass  # no WRITER_BUSY deadlock

    def test_analyst_setup_is_reentrant_under_outer_fence(self):
        from saipal import cmd_analyst_setup
        from saipal_analyst import config as analyst_config

        config = analyst_config.default_analyst_config()
        config["backend"]["model"] = "stub-model"
        analyst_config.save_analyst_config(self.home, config)
        with writer_fence(self.home):
            exit_code, payload = cmd_analyst_setup(self.home, {}, ["--enable"])
        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["enabled"])

    def test_other_thread_must_not_reenter_the_owners_fence(self):
        acquired: dict = {}

        def contender():
            fence = writer_fence(self.home)
            acquired["inside"] = fence.acquire()

        with writer_fence(self.home):
            thread = threading.Thread(target=contender)
            thread.start()
            thread.join(10)
        self.assertFalse(acquired.get("inside", True),
                         "a second thread reentered the same fence without the file lock")
        # After the owner releases, the contender path is free again.
        fence = writer_fence(self.home)
        self.assertTrue(fence.acquire())
        fence.release()


class CanonicalRebindIsFenced(unittest.TestCase):
    """SRC-004 CORE-001 acceptance matrix, ROLE 15-19 (E/F/G shapes).

    ROLE 15/16 repro: `saipal rebind` (and every direct rebind() caller)
    previously ran with NO writer fence; a controlled probe showed
    cmd_rebind completing while another thread held the fence. The repair
    puts the fence INSIDE the canonical rebind() transaction, reentrantly,
    so supervisor, CLI, tests and future callers share one invariant.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        support.put_inbox(self.home, CLEAN)
        support.run_saipal("continue", home=self.home)
        support.clear_inbox(self.home)

    def test_e_direct_canonical_rebind_caller_cannot_bypass_fence(self):
        """ROLE 19-E: rebind() itself refuses while a foreign fence is held."""
        release = threading.Event()
        acquired = threading.Event()

        def holder():
            with writer_fence(self.home):
                acquired.set()
                release.wait(30)

        thread = threading.Thread(target=holder)
        thread.start()
        self.assertTrue(acquired.wait(10))
        try:
            with self.assertRaises(Exception) as caught:
                from saipal_engine.rebind import rebind as rebind_mod

                rebind_mod(self.home)
            self.assertIn("home lock", str(caught.exception))
        finally:
            release.set()
            thread.join(10)
        # After release the same call succeeds.
        from saipal_engine.rebind import rebind as rebind_mod

        report = rebind_mod(self.home)
        self.assertTrue(report["ok"])

    def test_c_cli_rebind_serializes_behind_a_foreign_fence(self):
        """ROLE 19-C: cmd_rebind cannot run inside another holder's fence."""
        from saipal import cmd_rebind

        release = threading.Event()
        acquired = threading.Event()

        def holder():
            with writer_fence(self.home):
                acquired.set()
                release.wait(30)

        thread = threading.Thread(target=holder)
        thread.start()
        self.assertTrue(acquired.wait(10))
        outcome = cmd_rebind(self.home, {}, [])
        release.set()
        thread.join(10)
        # The CLI surfaces the refusal (exit code or emitted refusal body).
        if isinstance(outcome, tuple):
            code, payload = outcome
            self.assertNotEqual(code, 0)
        else:
            self.assertNotEqual(outcome, 0)  # refusal, never a silent success

    def test_f_rebind_reenters_under_an_outer_fence(self):
        """ROLE 19-F: legitimate same-thread nesting stays reentrant."""
        from saipal import cmd_rebind

        with writer_fence(self.home):
            outcome = cmd_rebind(self.home, {}, [])
        code = outcome[0] if isinstance(outcome, tuple) else outcome
        self.assertEqual(code, 0)

    def test_rebind_dry_run_is_read_only_and_unfenced(self):
        """--dry-run stays a pure read: no fence, no write, no refusal."""
        from saipal_engine import sessions as sessions_mod
        from saipal_engine.rebind import rebind as rebind_mod

        release = threading.Event()
        acquired = threading.Event()

        def holder():
            with writer_fence(self.home):
                acquired.set()
                release.wait(30)

        thread = threading.Thread(target=holder)
        thread.start()
        self.assertTrue(acquired.wait(10))
        try:
            report = rebind_mod(self.home, dry_run=True)
            self.assertTrue(report["ok"])
            self.assertTrue(report["dry_run"])
        finally:
            release.set()
            thread.join(10)
        _s, index, _d = sessions_mod.load_index(self.home)
        self.assertTrue(index)  # home untouched, call returned normally


class ControlPlaneDispatchIsFenced(unittest.TestCase):
    """SRC-004 CORE-001 ROLE 18-D: authority/source control-plane writes
    serialize through the common writer fence at CLI dispatch."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def _authority_dir(self) -> Path:
        root = Path(self._tmp.name) / "authority"
        root.mkdir(exist_ok=True)
        return root

    def test_d_authority_enroll_refused_while_fence_held(self):
        from saipal import cmd_authority
        from saipal_engine.errors import PalError

        release = threading.Event()
        acquired = threading.Event()

        def holder():
            with writer_fence(self.home):
                acquired.set()
                release.wait(30)

        thread = threading.Thread(target=holder)
        thread.start()
        self.assertTrue(acquired.wait(10))
        try:
            with self.assertRaises(PalError) as caught:
                cmd_authority(
                    self.home, {}, ["enroll", "--release-root", str(self._authority_dir())]
                )
            self.assertEqual(str(caught.exception.code), "WRITER_BUSY")
        finally:
            release.set()
            thread.join(10)
        # After release the enrollment itself converges.
        code, payload = cmd_authority(
            self.home, {}, ["enroll", "--release-root", str(self._authority_dir())]
        )
        self.assertEqual(code, 0, payload)

    def test_sources_enroll_refused_while_fence_held(self):
        from saipal import cmd_sources
        from saipal_engine.errors import PalError

        source_dir = Path(self._tmp.name) / "srcstore"
        source_dir.mkdir(exist_ok=True)
        release = threading.Event()
        acquired = threading.Event()

        def holder():
            with writer_fence(self.home):
                acquired.set()
                release.wait(30)

        thread = threading.Thread(target=holder)
        thread.start()
        self.assertTrue(acquired.wait(10))
        try:
            with self.assertRaises(PalError) as caught:
                cmd_sources(
                    self.home, {}, ["enroll", "--kind", "generic", "--path", str(source_dir)]
                )
            self.assertEqual(str(caught.exception.code), "WRITER_BUSY")
        finally:
            release.set()
            thread.join(10)

    def test_authority_doctor_read_only_consistent_snapshot(self):
        """Read-only authority surfaces still return (fence permits same-thread)."""
        from saipal import cmd_authority

        with writer_fence(self.home):
            code, payload = cmd_authority(self.home, {}, ["doctor"])
        self.assertEqual(code, 0)


class ReadOnlySurfacesAreZeroWrite(unittest.TestCase):
    """ROLE 20260910 §9-A/B: read-only authority/source doctor+discover
    surfaces create ZERO durable home state and stay usable while a foreign
    writer holds the fence. A lock acquisition itself materializes locks/,
    so fencing a pure read was a contract violation."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def test_a_fresh_home_read_only_commands_create_zero_durable_state(self):
        from saipal import cmd_authority, cmd_sources

        for args in (["doctor"], ["discover"]):
            code, _payload = cmd_authority(self.home, {}, args)
            self.assertEqual(code, 0)
        for args in (["doctor"], ["discover"]):
            code, _payload = cmd_sources(self.home, {}, args)
            self.assertEqual(code, 0)
        # Zero durable home mutation: no locks/ node, byte-identical tree.
        self.assertFalse(
            (self.home / "locks").exists(),
            "a read-only command materialized locks/",
        )
        baseline = self._baseline_tree()
        for args in (["doctor"], ["discover"]):
            cmd_authority(self.home, {}, args)
            cmd_sources(self.home, {}, args)
        self.assertEqual(self._baseline_tree(), baseline)

    def _baseline_tree(self) -> dict:
        snapshot: dict[str, bytes] = {}
        for path in sorted(Path(self.home).rglob("*")):
            if path.is_file():
                snapshot[str(path.relative_to(self.home))] = path.read_bytes()
        return snapshot

    def test_b_read_only_surfaces_usable_under_foreign_fence(self):
        """All four read-only commands answer while a foreign thread holds the fence."""
        from saipal import cmd_authority, cmd_sources

        release = threading.Event()
        acquired = threading.Event()

        def holder():
            with writer_fence(self.home):
                acquired.set()
                release.wait(30)

        thread = threading.Thread(target=holder)
        thread.start()
        self.assertTrue(acquired.wait(10))
        try:
            for args in (["doctor"], ["discover"]):
                code, _payload = cmd_authority(self.home, {}, args)
                self.assertEqual(code, 0, args)
                code, _payload = cmd_sources(self.home, {}, args)
                self.assertEqual(code, 0, args)
        finally:
            release.set()
            thread.join(10)


class DirectCanonicalMutationsAreSelfFenced(unittest.TestCase):
    """ROLE 20260910 §9-C/D: the DIRECT library mutations -- authority.enroll,
    enroll_source, set_source_state, remove_source -- refuse WRITER_BUSY while
    a foreign thread holds the fence and leave ZERO durable mutation. The
    safety invariant belongs to the canonical function, not the CLI."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def _hold_fence_and_call(self, call):
        release = threading.Event()
        acquired = threading.Event()

        def holder():
            with writer_fence(self.home):
                acquired.set()
                release.wait(30)

        thread = threading.Thread(target=holder)
        thread.start()
        self.assertTrue(acquired.wait(10))
        try:
            call()
        finally:
            release.set()
            thread.join(10)

    def _authority_dir(self) -> Path:
        root = Path(self._tmp.name) / "authority"
        root.mkdir(exist_ok=True)
        return root

    def _tree_signature(self) -> list:
        return sorted(
            (str(p.relative_to(self.home)), p.stat().st_size)
            for p in Path(self.home).rglob("*")
            if p.is_file()
        )

    def test_c_direct_authority_enroll_refused_zero_authority_writes(self):
        from saipal_engine import authority as authority_mod
        from saipal_engine.errors import PalError

        before = self._tree_signature()

        def call():
            with self.assertRaises(PalError) as caught:
                authority_mod.enroll(self.home, "release_root", str(self._authority_dir()))
            self.assertEqual(str(caught.exception.code), "WRITER_BUSY")

        self._hold_fence_and_call(call)
        self.assertEqual(self._tree_signature(), before, "authority enrollment wrote under a foreign fence")

    def test_d_direct_enroll_source_refused_zero_source_writes(self):
        from saipal_engine.errors import PalError
        from saipal_engine.source_health import enroll_source

        source_dir = Path(self._tmp.name) / "srcstore"
        source_dir.mkdir(exist_ok=True)
        before = self._tree_signature()

        def call():
            with self.assertRaises(PalError) as caught:
                enroll_source(self.home, kind="generic", path=str(source_dir))
            self.assertEqual(str(caught.exception.code), "WRITER_BUSY")

        self._hold_fence_and_call(call)
        self.assertEqual(self._tree_signature(), before, "source enrollment wrote under a foreign fence")

    def test_d_direct_set_source_state_refused_zero_source_writes(self):
        from saipal_engine.errors import PalError
        from saipal_engine.source_health import enroll_source, set_source_state

        source_dir = Path(self._tmp.name) / "srcstore2"
        source_dir.mkdir(exist_ok=True)
        # Seed one source so a state flip has a real target.
        enroll_source(self.home, kind="generic", path=str(source_dir))
        from saipal_engine.source_health import load_sources

        _status, payload, _d = load_sources(self.home)
        source_id = payload["sources"][0]["id"]
        before = self._tree_signature()

        def call():
            with self.assertRaises(PalError) as caught:
                set_source_state(self.home, source_id, enabled=False)
            self.assertEqual(str(caught.exception.code), "WRITER_BUSY")

        self._hold_fence_and_call(call)
        self.assertEqual(self._tree_signature(), before, "set_source_state wrote under a foreign fence")

    def test_d_direct_remove_source_refused_zero_source_writes(self):
        from saipal_engine.errors import PalError
        from saipal_engine.source_health import enroll_source, remove_source

        source_dir = Path(self._tmp.name) / "srcstore3"
        source_dir.mkdir(exist_ok=True)
        enroll_source(self.home, kind="generic", path=str(source_dir))
        from saipal_engine.source_health import load_sources

        _status, payload, _d = load_sources(self.home)
        source_id = payload["sources"][0]["id"]
        before = self._tree_signature()

        def call():
            with self.assertRaises(PalError) as caught:
                remove_source(self.home, source_id)
            self.assertEqual(str(caught.exception.code), "WRITER_BUSY")

        self._hold_fence_and_call(call)
        self.assertEqual(self._tree_signature(), before, "remove_source wrote under a foreign fence")


class PhysicalHomeIdentitySplitBrain(unittest.TestCase):
    """SRC-010 CORE-001: a WriterFence binds the PHYSICAL home, not a pathname.

    Audit/5.md reproduced the split brain: `writer_fence(home)` was acquired,
    the whole physical home was renamed away, a fresh ordinary directory was
    created at the same lexical pathname, and a nested `writer_fence(home)`
    reentered by lexical key alone -- then `atomic_write_json` mutated the
    replacement while the only real lock stayed in the moved home. These are the
    required red controls A-E; every one must fail closed after substitution.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = self.tmp / ".saipal"
        self.home.mkdir()
        self.moved = self.tmp / "home.old"

    def _replace_root(self) -> None:
        """Rename the physical home away and create a real replacement."""
        os.rename(str(self.home), str(self.moved))
        self.home.mkdir()

    def _snapshot(self, root: Path) -> dict:
        return {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }

    # -- A: outer holder root replacement ---------------------------------- #

    def test_a_outer_holder_cannot_mutate_a_replacement_home(self) -> None:
        with writer_fence(self.home):
            self._replace_root()
            before = self._snapshot(self.home)
            with self.assertRaises(PalError):
                atomic_write_json(self.home / "STATE.json", {"x": 1}, root=self.home)
            self.assertEqual(
                self._snapshot(self.home),
                before,
                "the replacement home must stay byte-identical",
            )
            self.assertFalse((self.home / "STATE.json").exists())
            self.assertFalse((self.home / "locks" / "saipal.lock").exists())
            # The real lock is still the one bound to the moved physical home.
            self.assertTrue((self.moved / "locks" / "saipal.lock").exists())

    # -- B: same-thread reentrancy after substitution ---------------------- #

    def test_b_nested_fence_does_not_reenter_a_replacement_home(self) -> None:
        with writer_fence(self.home):
            self._replace_root()
            with self.assertRaises(PalError):
                nested = writer_fence(self.home)
                nested.acquire()
            # And no confined mutation through the nested attempt either.
            with self.assertRaises(PalError):
                atomic_write_json(self.home / "STATE.json", {"x": 1}, root=self.home)
            self.assertEqual(sorted(p.name for p in self.home.iterdir()), [])

    # -- C: second holder in the replacement home -------------------------- #

    def test_c_second_holder_may_own_the_replacement_but_not_the_original(self) -> None:
        with writer_fence(self.home):
            self._replace_root()
            outcome: dict = {}

            def second_holder():
                try:
                    with writer_fence(self.home):
                        atomic_write_json(
                            self.home / "STATE.json", {"owned": "second"}, root=self.home
                        )
                    outcome["ok"] = True
                except Exception as exc:  # noqa: BLE001
                    outcome["error"] = exc

            thread = threading.Thread(target=second_holder)
            thread.start()
            thread.join(15)
            self.assertIsNone(outcome.get("error"), outcome.get("error"))
            self.assertTrue(outcome.get("ok"))
            # The original holder is STILL unable to mutate the replacement it
            # does not own, so two writers never share one logical generation.
            with self.assertRaises(PalError):
                atomic_write_json(self.home / "OTHER.json", {"x": 1}, root=self.home)
            self.assertFalse((self.home / "OTHER.json").exists())

    # -- D: normal reentrancy is preserved --------------------------------- #

    def test_d_unchanged_home_reentrancy_still_works(self) -> None:
        with writer_fence(self.home):
            with writer_fence(self.home):
                nested = writer_fence(self.home)
                self.assertTrue(nested.acquire())
                nested.release()
                atomic_write_json(self.home / "STATE.json", {"x": 1}, root=self.home)
        self.assertTrue((self.home / "STATE.json").read_bytes())
        # Only one physical lock was ever needed, and it is released.
        self.assertFalse((self.home / "locks" / "saipal.lock").exists())

    # -- E: identity verified at the mutation boundary --------------------- #

    def test_e_identity_change_between_check_and_mutation_is_refused(self) -> None:
        with writer_fence(self.home):
            # A legitimate mutation before the swap proves the fence is usable.
            atomic_write_json(self.home / "STATE.json", {"x": 1}, root=self.home)
            # The swap happens AFTER acquisition, immediately before the write.
            self._replace_root()
            before = self._snapshot(self.home)
            with self.assertRaises(PalError):
                atomic_write_json(self.home / "STATE.json", {"x": 2}, root=self.home)
            self.assertEqual(self._snapshot(self.home), before)
            self.assertFalse((self.home / "STATE.json").exists())

    def test_unfenced_primitives_are_unaffected_by_the_identity_gate(self) -> None:
        atomic_write_json(self.home / "STATE.json", {"x": 1}, root=self.home)
        self.assertTrue((self.home / "STATE.json").exists())
        self.home.rename(self.moved)
        self.home.mkdir()
        # No fence is active for this thread, so a fresh path is ordinary work.
        atomic_write_json(self.home / "STATE.json", {"x": 2}, root=self.home)
        self.assertTrue((self.home / "STATE.json").exists())


if __name__ == "__main__":
    unittest.main()
