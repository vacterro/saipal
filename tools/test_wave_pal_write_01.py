"""PAL-WRITE-01 filesystem-confinement controls.

PAL-WRITE-01 says: SAIPAL may write only inside its own home. These tests pin
the load-bearing primitives at `saipal_engine.paths` that make that a PHYSICAL
boundary, not a check-then-write sequence:

- append-only log confinement (final symlink, parent redirection);
- fenced lock/lease confinement (redirected locks dir, symlinked lock node);
- the deterministic parent-swap TOCTOU against the shared atomic write;
- external sink delivery only through its validated boundary.

A refusal must leave every external byte byte-identical. Every control that
can also be evaluated as a pre-fix RED control is written so the assertion is
on the refusal itself, not on incidental state.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from saipal_engine.errors import PalError  # noqa: E402
from saipal_engine.log import append_event  # noqa: E402
from saipal_engine.paths import (  # noqa: E402
    FencedLockFile,
    atomic_write_bytes,
    atomic_write_json,
    confined_append_line,
    confined_create_exclusive,
    confined_mkdir,
    confined_replace,
    confined_unlink,
    home_paths,
)

ON_POSIX = os.name == "posix"


def _symlink_capability() -> str:
    """Why this host cannot create a file symlink, or "" when it can.

    Every symlink control in this module needs `os.symlink` to succeed before
    the confinement primitive is ever reached. On Windows that call needs
    SeCreateSymbolicLinkPrivilege (developer mode or elevation); without it the
    setup dies with WinError 1314 and the control reports an ERROR that says
    nothing about PAL-WRITE-01. A host that cannot create the indirection
    cannot measure it, so the control is SKIPPED, never weakened -- the same
    contract `PosixDescriptorLifetime` already uses off POSIX.

    Directory junctions are unaffected: `_indirect_dir` goes through `_winapi`,
    so the SRC-006 indirection controls still run on an unelevated host.
    """
    if os.name != "nt":
        return ""
    directory = Path(tempfile.mkdtemp(prefix="saipal-symlink-probe-"))
    try:
        target = directory / "target"
        target.write_bytes(b"probe")
        os.symlink(str(target), str(directory / "link"))
        return ""
    except OSError as exc:
        return f"this host cannot create a file symlink: {exc}"
    finally:
        shutil.rmtree(str(directory), ignore_errors=True)


SYMLINK_UNAVAILABLE = _symlink_capability()
skip_without_symlink = unittest.skipIf(
    bool(SYMLINK_UNAVAILABLE), SYMLINK_UNAVAILABLE or ""
)


def _home(tmp: Path) -> Path:
    home = tmp / ".saipal"
    home.mkdir(parents=True, exist_ok=True)
    (home / "locks").mkdir(exist_ok=True)
    return home


@skip_without_symlink
class LogAppendConfinement(unittest.TestCase):
    """PAL-WRITE-01 A: LOG.jsonl must not follow path indirection."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = _home(self.tmp)
        self.outside = self.tmp / "outside"
        self.outside.mkdir()
        self.outside_file = self.outside / "captured.log"
        self.outside_file.write_bytes(b"ORIGINAL\n")

    def test_final_symlink_to_external_file_is_refused(self) -> None:
        log = self.home / "LOG.jsonl"
        os.symlink(str(self.outside_file), str(log))
        with self.assertRaises(PalError):
            append_event(self.home, "tamper")
        self.assertEqual(self.outside_file.read_bytes(), b"ORIGINAL\n")

    def test_dangling_final_symlink_is_refused(self) -> None:
        log = self.home / "LOG.jsonl"
        os.symlink(str(self.outside / "nothere.log"), str(log))
        with self.assertRaises(PalError):
            append_event(self.home, "tamper")
        self.assertFalse((self.outside / "nothere.log").exists())

    def test_symlinked_home_root_is_refused(self) -> None:
        # The log's parent (the home) replaced by a symlink: the append must
        # be refused, never written through the indirection.
        real = self.tmp / "realhome"
        (real / "locks").mkdir(parents=True)
        link = self.tmp / "homelink"
        os.symlink(str(real), str(link))
        with self.assertRaises(PalError):
            append_event(link, "tamper")
        self.assertEqual(list((real / "LOG.jsonl").parent.glob("LOG*")), [])

    def test_log_parent_swapped_after_validation_never_writes_outside(
        self,
    ) -> None:
        # T-125 Defect F: the previous control swapped home/locks -- a
        # directory LOG.jsonl never traverses -- and treated the resulting
        # refusal as a confinement pass. That was conceptually invalid: a
        # redirected UNRELATED directory is not a reason for append_event to
        # fail. The honest race targets a component the log write ACTUALLY
        # uses: the home itself. The acceptable outcomes are (A) refusal with
        # zero external writes, or (B) the append stays bound to the
        # previously verified physical home inode. The FORBIDDEN outcome is
        # bytes appearing in the attacker-controlled replacement path.
        if not ON_POSIX:
            self.skipTest("dir_fd primitive is POSIX-only")
        replacement = self.tmp / "replacement_home"
        replacement.mkdir()
        real_open = os.open
        opened = {"count": 0}

        def swapping_open(path, flags, mode=0o666, **kwargs):
            # Runs at the exact moment confined_append_line opens its parent:
            # the home has passed validation as a real directory; swap it now.
            if opened["count"] == 0:
                opened["count"] += 1
                os.symlink(str(replacement), str(self.home))
            return real_open(path, flags, mode, **kwargs)

        import saipal_engine.paths as paths_module

        saved = paths_module.os.open
        paths_module.os.open = swapping_open  # type: ignore[misc]
        try:
            append_event(self.home, "tamper")
        except (PalError, OSError):
            pass  # outcome A: refusal
        finally:
            paths_module.os.open = saved  # type: ignore[misc]

        # The FORBIDDEN outcome: bytes in the attacker-controlled path.
        self.assertEqual(
            list(replacement.iterdir()),
            [],
            "the parent-swap race wrote into the replacement path",
        )

    def test_legitimate_append_still_works(self) -> None:
        append_event(self.home, "ok-one")
        append_event(self.home, "ok-two")
        lines = (self.home / "LOG.jsonl").read_bytes().decode().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[1])["seq"], 2)

    def test_append_to_existing_regular_log_preserves_it(self) -> None:
        (self.home / "LOG.jsonl").write_bytes(b'{"seq": 1}\n')
        append_event(self.home, "next")
        raw = (self.home / "LOG.jsonl").read_bytes()
        self.assertTrue(raw.startswith(b'{"seq": 1}\n'))
        self.assertEqual(json.loads(raw.splitlines()[1])["seq"], 2)


@skip_without_symlink
class LockConfinement(unittest.TestCase):
    """PAL-WRITE-01 B: lock and lease writes must not escape the home."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = _home(self.tmp)
        self.outside = self.tmp / "outside"
        self.outside.mkdir()

    def test_symlinked_locks_directory_is_refused(self) -> None:
        locks = self.home / "locks"
        locks.rmdir()
        os.symlink(str(self.outside), str(locks))
        lock = FencedLockFile(self.home / "locks" / "writer.lock")
        with self.assertRaises(PalError):
            lock.acquire()
        self.assertEqual(
            [p.name for p in self.outside.iterdir()],
            [],
            "a refused lock acquisition must not write outside the home",
        )

    def test_symlinked_lock_node_is_refused(self) -> None:
        victim = self.outside / "victim.lock"
        victim.write_bytes(b"")
        os.symlink(str(victim), str(self.home / "locks" / "writer.lock"))
        lock = FencedLockFile(self.home / "locks" / "writer.lock")
        with self.assertRaises(PalError):
            lock.acquire()
        self.assertEqual(victim.read_bytes(), b"")
        self.assertFalse(lock.held)

    def test_lease_sidecar_parent_redirection_is_refused(self) -> None:
        # The lock is acquired legitimately, THEN the locks directory is
        # swapped to an external symlink; a subsequent lease refresh must
        # refuse (delayed freshness), never write the sidecar outside.
        lock = FencedLockFile(self.home / "locks" / "writer.lock", confine_under=self.home)
        self.assertTrue(lock.acquire())
        victim_dir = self.outside / "leasesteal"
        victim_dir.mkdir()
        victim = victim_dir / ".writer.lock.lease"
        victim.write_bytes(b"KEEP\n")
        import shutil as _shutil

        _shutil.rmtree(str(self.home / "locks"))
        os.symlink(str(victim_dir), str(self.home / "locks"))
        self.assertFalse(
            lock.refresh(),
            "refresh on a redirected sidecar slot must not report success",
        )
        self.assertEqual(victim.read_bytes(), b"KEEP\n")
        self.assertEqual(
            [p.name for p in victim_dir.iterdir()], [victim.name]
        )

    def test_stale_takeover_does_not_rename_outside_home(self) -> None:
        # A stale lock whose node is a symlink: takeover must refuse, never
        # rename or delete the external target.
        victim = self.outside / "stale-target.lock"
        victim.write_bytes(b"PRECIOUS\n")
        node = self.home / "locks" / "writer.lock"
        os.symlink(str(victim), str(node))
        contender = FencedLockFile(node)
        with self.assertRaises(PalError):
            contender.acquire()
        self.assertEqual(victim.read_bytes(), b"PRECIOUS\n")

    def test_refusal_never_destroys_a_successors_lock(self) -> None:
        # A successor holds a real lock; a refused (redirected) acquisition
        # must leave it byte-identical and owned.
        successor = FencedLockFile(self.home / "locks" / "writer.lock")
        self.assertTrue(successor.acquire())
        before = (self.home / "locks" / "writer.lock").read_bytes()
        outsider = FencedLockFile(
            self.home / "locks" / ".." / ".." / ".." / ".." / "outside" / "evil.lock",
            confine_under=self.home,
        )
        with self.assertRaises(PalError):
            outsider.acquire()
        self.assertFalse((self.outside / "evil.lock").exists())
        self.assertEqual((self.home / "locks" / "writer.lock").read_bytes(), before)
        self.assertTrue(successor.owns_on_disk())
        successor.release()

    def test_legitimate_lock_still_works(self) -> None:
        lock = FencedLockFile(self.home / "locks" / "writer.lock")
        self.assertTrue(lock.acquire())
        self.assertTrue(lock.owns_on_disk())
        self.assertTrue(lock.refresh())
        lock.release()
        self.assertFalse((self.home / "locks" / "writer.lock").exists())


@skip_without_symlink
class AtomicWriteParentSwapRace(unittest.TestCase):
    """PAL-WRITE-01 C: the deterministic parent-swap TOCTOU control.

    The parent is a REAL directory when validation runs, then swapped to an
    external symlink before the temp-file open. Refusal with zero external
    bytes is the only acceptable outcome, and a static pre-existing symlink
    is already refused by W2-002/T-122 -- this is the RACE window.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = _home(self.tmp)
        self.outside = self.tmp / "outside"
        self.outside.mkdir()

    def test_parent_swapped_after_validation_is_refused(self) -> None:
        audit = self.home / "audit"
        audit.mkdir()
        original = self.outside / "victim.md"
        original.write_bytes(b"ORIGINAL\n")

        real_open = os.open
        opened = {"count": 0}

        def swapping_open(path, flags, mode=0o666, **kwargs):
            # Runs at the exact moment atomic_write_bytes opens its temp file:
            # the parent has passed validation as a real directory; swap it now.
            if str(path).endswith(".tmp") and opened["count"] == 0:
                opened["count"] += 1
                import shutil as _shutil

                _shutil.rmtree(str(audit))
                os.symlink(str(self.outside), str(audit))
            return real_open(path, flags, mode, **kwargs)

        # Patch os.open used by the module under test.
        import saipal_engine.paths as paths_module

        saved = paths_module.os.open
        paths_module.os.open = swapping_open  # type: ignore[misc]
        try:
            with self.assertRaises((PalError, OSError)):
                atomic_write_bytes(audit / "x.md", b"EVIL\n", root=self.home)
        finally:
            paths_module.os.open = saved  # type: ignore[misc]

        self.assertFalse(
            original.read_bytes() == b"EVIL\n",
            "the parent-swap race wrote outside the home",
        )
        self.assertEqual(original.read_bytes(), b"ORIGINAL\n")

    def test_static_symlinked_parent_still_refused(self) -> None:
        audit = self.home / "audit"
        audit.mkdir()
        import shutil as _shutil

        _shutil.rmtree(str(audit))
        os.symlink(str(self.outside), str(audit))
        with self.assertRaises(PalError):
            atomic_write_bytes(audit / "x.md", b"EVIL\n", root=self.home)
        self.assertEqual(list(self.outside.iterdir()), [])

    def test_atomic_write_semantics_survive(self) -> None:
        # TARGET B2 (T-125): `atomic_write_bytes` writes only into an
        # already-authorized EXISTING parent and never recreates one itself,
        # so the owner (here the test) materializes it through the confinement
        # primitive first.
        from saipal_engine.paths import confined_mkdir

        confined_mkdir(self.home, "audit")
        target = self.home / "audit" / "x.md"
        atomic_write_bytes(target, b"one\n", root=self.home)
        atomic_write_bytes(target, b"two\n", root=self.home)
        self.assertEqual(target.read_bytes(), b"two\n")
        self.assertEqual(
            [p.name for p in target.parent.iterdir()],
            ["x.md"],
            "temp files must be cleaned or replaced away",
        )


@skip_without_symlink
class SinkConfinement(unittest.TestCase):
    """PAL-WRITE-01 D: the external sink is reachable ONLY through its
    validated boundary, and private bookkeeping never leaves the home."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = _home(self.tmp)
        self.sink_root = self.tmp / "sink"
        (self.sink_root / "audit").mkdir(parents=True)
        (self.sink_root / "audit" / "MANIFEST.json").write_text(
            json.dumps({"kind": "saipen-audit-inbox", "schema_version": 1}),
            encoding="utf-8",
        )

    def _finding(self) -> dict:
        return {
            "finding_id": "PAL-9001",
            "drift_class": "PHASE_ILLEGALITY",
            "severity": "P3",
            "confidence": "HIGH",
        }

    def test_private_ledger_stays_inside_home(self) -> None:
        from saipal_engine.enqueue import enqueue_audit

        result = enqueue_audit(
            self.home,
            self._finding(),
            "body\n",
            maintainer_root=self.sink_root,
            private_ledger_home=self.home,
        )
        self.assertTrue((self.sink_root / "audit" / "1.md").is_file())
        # The private ledger lives in the HOME audit dir, never in the sink.
        home_ledger = self.home / "audit" / "entries.json"
        self.assertTrue(home_ledger.is_file())
        self.assertFalse((self.sink_root / "audit" / "entries.json").exists())
        self.assertEqual(result["audit_number"], 1)

    def test_verify_refuses_symlink_alias_in_sink(self) -> None:
        from saipal_engine.enqueue import enqueue_audit

        enqueue_audit(
            self.home,
            self._finding(),
            "body\n",
            maintainer_root=self.sink_root,
            private_ledger_home=self.home,
        )
        slot = self.sink_root / "audit" / "1.md"
        digest_before = slot.read_bytes()
        # Replace the slot with a symlink aliasing a DIFFERENT external file
        # that happens to hash correctly is out of scope; here we prove that a
        # symlink alias is refused outright rather than accepted on bytes.
        alias_target = self.outside_alias()
        os.symlink(str(alias_target), str(self.sink_root / "audit" / "alias.md"))
        from saipal_engine.enqueue import verify_audit

        self.assertFalse(verify_audit(self.sink_root / "audit" / "alias.md", "x"))
        self.assertEqual(slot.read_bytes(), digest_before)

    def outside_alias(self) -> Path:
        target = self.tmp / "elsewhere.md"
        target.write_bytes(b"body\n")
        return target


@skip_without_symlink
class LockParentSwapRace(unittest.TestCase):
    """T-125 Defect B: the deterministic lock parent-swap TOCTOU control.

    The locks directory is a REAL directory when the final confinement check
    runs, then swapped to an external symlink immediately before the O_EXCL
    open. The lock create, takeover rename and sidecar replace must all be
    bound to the verified physical parent, so the swap yields zero external
    bytes (refusal, or a lock still inside the home) -- never a lock (or a
    lease sidecar) inside the attacker's directory.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = _home(self.tmp)
        self.outside = self.tmp / "outside"
        self.outside.mkdir()

    def _swap_locks_before_open(self):
        locks = self.home / "locks"
        real_open = os.open
        state = {"count": 0}

        def swapping_open(path, flags, mode=0o666, **kwargs):
            # Runs at the exact moment the lock create reaches the O_EXCL
            # open: the parent has passed confinement; swap it now.
            if state["count"] == 0:
                state["count"] += 1
                import shutil as _shutil

                _shutil.rmtree(str(locks))
                os.symlink(str(self.outside), str(locks))
            return real_open(path, flags, mode, **kwargs)

        import saipal_engine.paths as paths_module

        saved = paths_module.os.open
        paths_module.os.open = swapping_open  # type: ignore[misc]
        self.addCleanup(setattr, paths_module, "os.open", saved)
        return state

    def test_create_after_parent_swap_creates_zero_external_bytes(self) -> None:
        lock = FencedLockFile(self.home / "locks" / "writer.lock", confine_under=self.home)
        self._swap_locks_before_open()
        try:
            acquired = lock.acquire()
        except (PalError, OSError):
            acquired = False
        # The forbidden outcome: a lock node in the attacker's directory.
        self.assertFalse(
            (self.outside / "writer.lock").exists(),
            "the parent-swap race created the lock outside the home",
        )
        self.assertEqual(
            [p.name for p in self.outside.iterdir()],
            [],
            "the parent-swap race left external bytes behind",
        )
        if acquired:
            lock.release()

    def test_lease_sidecar_after_parent_swap_creates_zero_external_bytes(self) -> None:
        lock = FencedLockFile(self.home / "locks" / "writer.lock", confine_under=self.home)
        self.assertTrue(lock.acquire())
        self.addCleanup(lambda: lock.release() if lock.held else None)
        side = self.outside / ".writer.lock.lease"
        side.write_bytes(b"KEEP\n")

        # Swap the locks directory right after the final confinement check,
        # before the sidecar temp create. On Windows the strongest-practical
        # chain probe runs on the temp path FIRST, so the swap must fire on
        # the LOCK create's os.open to be inside the race window; we instead
        # place the swap at the first os.replace (the sidecar rename).
        real_replace = os.replace
        state = {"count": 0}

        def swapping_replace(src, dst, **kwargs):
            if state["count"] == 0:
                state["count"] += 1
                import shutil as _shutil

                _shutil.rmtree(str(self.home / "locks"))
                os.symlink(str(self.outside), str(self.home / "locks"))
            return real_replace(src, dst, **kwargs)

        import saipal_engine.paths as paths_module

        saved = paths_module.os.replace
        paths_module.os.replace = swapping_replace  # type: ignore[misc]
        try:
            lock.refresh()
        finally:
            paths_module.os.replace = saved  # type: ignore[misc]
        self.assertEqual(side.read_bytes(), b"KEEP\n")
        self.assertEqual(
            [p.name for p in self.outside.iterdir()],
            [side.name],
            "the parent-swap race wrote lease records outside the home",
        )


@skip_without_symlink
class AuditInboxAncestorConfinement(unittest.TestCase):
    """T-125 Defect C: AuditInboxLock must prove the ANCESTORS of its lock
    directory, not just the already-descended lock directory itself."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.outside = self.tmp / "outside"
        (self.outside / "staging").mkdir(parents=True)

    def test_symlinked_audit_ancestor_is_refused(self) -> None:
        # home/audit -> outside: the local staging lock must refuse, never
        # materialize audit_inbox.lock inside the external tree.
        os.symlink(str(self.outside), str(self.home / "audit"))
        from saipal_engine.enqueue import enqueue_audit, AuditInboxLock

        lock = AuditInboxLock(
            self.home / "audit" / "staging", confine_under=self.home
        )
        with self.assertRaises(PalError):
            lock.acquire()
        self.assertFalse((self.outside / "staging" / "audit_inbox.lock").exists())

    def test_enqueue_through_symlinked_audit_ancestor_writes_nothing_outside(self) -> None:
        from saipal_engine.enqueue import enqueue_audit

        os.symlink(str(self.outside), str(self.home / "audit"))
        finding = {
            "finding_id": "PAL-9002",
            "drift_class": "PHASE_ILLEGALITY",
            "severity": "P3",
            "confidence": "HIGH",
        }
        with self.assertRaises((PalError, OSError)):
            enqueue_audit(self.home, finding, "body\n", private_ledger_home=self.home)
        self.assertEqual(
            [p.name for p in (self.outside / "staging").iterdir()],
            [],
            "the symlinked ancestor carried audit bytes outside the home",
        )

    def test_staging_directory_symlink_is_refused(self) -> None:
        from saipal_engine.enqueue import AuditInboxLock

        staging = self.home / "audit" / "staging"
        staging.mkdir(parents=True)
        staging.rmdir()
        os.symlink(str(self.outside / "staging"), str(staging))
        lock = AuditInboxLock(staging, confine_under=self.home)
        with self.assertRaises(PalError):
            lock.acquire()
        self.assertFalse((self.outside / "staging" / "audit_inbox.lock").exists())

    def test_external_sink_ancestor_symlink_is_refused(self) -> None:
        from saipal_engine.enqueue import enqueue_audit

        sink = self.tmp / "sink"
        (sink / "audit").mkdir(parents=True)
        (sink / "audit" / "MANIFEST.json").write_text(
            json.dumps({"kind": "saipen-audit-inbox", "schema_version": 1}),
            encoding="utf-8",
        )
        # The sink's audit dir itself is swapped for a symlink AFTER the
        # manifest check: the enqueue must refuse rather than write through
        # the indirection.
        victim = self.outside / "staging"
        import shutil as _shutil

        _shutil.rmtree(str(sink / "audit"))
        os.symlink(str(victim), str(sink / "audit"))
        finding = {
            "finding_id": "PAL-9003",
            "drift_class": "PHASE_ILLEGALITY",
            "severity": "P3",
            "confidence": "HIGH",
        }
        with self.assertRaises((PalError, OSError)):
            enqueue_audit(
                self.home, finding, "body\n",
                maintainer_root=sink, private_ledger_home=self.home,
            )
        self.assertFalse((victim / "1.md").exists())

    def test_audit_inbox_lock_final_node_symlink_is_refused(self) -> None:
        from saipal_engine.enqueue import AuditInboxLock

        staging = self.home / "audit" / "staging"
        staging.mkdir(parents=True)
        victim = self.outside / "victim.lock"
        victim.write_bytes(b"")
        os.symlink(str(victim), str(staging / "audit_inbox.lock"))
        lock = AuditInboxLock(staging, confine_under=self.home)
        with self.assertRaises(PalError):
            lock.acquire()
        self.assertEqual(victim.read_bytes(), b"")


@skip_without_symlink
class EnsureHomeRootEstablishment(unittest.TestCase):
    """T-125 Defect E: materializing a home behind an indirection root must
    produce ZERO external mutations -- not even directories -- before the
    refusal."""

    EXTERNAL_LAYOUT = (
        "cache", "evidence", "findings", "findings/candidates",
        "findings/emitted", "locks", "session_inbox", "sessions",
        "sessions/checkpoints",
    )

    def test_symlinked_home_root_creates_zero_external_directories(self) -> None:
        from saipal_engine.home import ensure_home

        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            outside = tmp / "outside"
            outside.mkdir()
            linked = tmp / "linked_home"
            os.symlink(str(outside), str(linked))
            with self.assertRaises(PalError):
                ensure_home(linked)
            self.assertEqual(
                sorted(p.relative_to(outside).as_posix() for p in outside.rglob("*")),
                [],
                "ensure_home mutated the external target before refusing",
            )

    def test_real_home_still_materializes_the_full_layout(self) -> None:
        from saipal_engine.home import ensure_home

        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            home = tmp / ".saipal"
            result = ensure_home(home)
            for name in self.EXTERNAL_LAYOUT:
                self.assertTrue(
                    (home / name).is_dir(), f"layout dir {name} missing"
                )
            self.assertIn("LOG.jsonl", result["created_files"])


class NestedAtomicWriteTargets(unittest.TestCase):
    """T-125 Defect A: atomic_write_bytes writes the EXACT requested node.

    The POSIX branch of the old _confined_parent stripped one component too
    many from a caller-supplied parent, so `audit/x.md` landed at `x.md`. The
    requested path must be the node written on every platform, at every
    nesting depth, including the audit/staging family that backs Wave E.
    """

    CASES = (
        "file.md",
        "a/file.md",
        "a/b/file.md",
        "audit/staging/N.md",
        "findings/candidates/X.json",
        "sessions/checkpoints/X.json",
    )

    def test_every_nesting_depth_lands_at_the_requested_node(self) -> None:
        for relative in self.CASES:
            with self.subTest(target=relative):
                with tempfile.TemporaryDirectory() as raw:
                    tmp = Path(raw)
                    home = tmp / ".saipal"
                    home.mkdir()
                    target = home / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    returned = atomic_write_bytes(target, b"X\n", root=home)
                    self.assertTrue(
                        target.exists(),
                        f"requested node {relative} was not written",
                    )
                    self.assertEqual(target.read_bytes(), b"X\n")
                    self.assertEqual(
                        Path(returned), Path(target),
                        "the primitive returned a different node than requested",
                    )
                    strays = [
                        p for p in home.rglob("*")
                        if p.is_file() and p != target
                    ]
                    self.assertEqual(
                        strays, [],
                        f"a stray node was written for {relative}: {strays}",
                    )


class AtomicWriteRequiresExistingParent(unittest.TestCase):
    """TARGET B2 (T-125): `atomic_write_bytes` writes only into an
    already-authorized EXISTING parent. It is NOT an implicit recursive mkdir:
    a missing parent is a refusal on every platform, and the caller that owns
    directory creation materializes through `confined_mkdir` first."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = self.tmp / ".saipal"
        self.home.mkdir()

    def test_missing_parent_is_refused_and_creates_nothing(self) -> None:
        with self.assertRaises(PalError):
            atomic_write_bytes(
                self.home / "missing" / "x.md", b"X\n", root=self.home
            )
        self.assertFalse((self.home / "missing").exists())
        self.assertEqual(sorted(p.name for p in self.home.iterdir()), [])

    def test_explicitly_materialized_parent_accepts_the_write(self) -> None:
        from saipal_engine.paths import confined_mkdir

        confined_mkdir(self.home, "missing")
        target = self.home / "missing" / "x.md"
        atomic_write_bytes(target, b"X\n", root=self.home)
        self.assertEqual(target.read_bytes(), b"X\n")


@skip_without_symlink
class WriterFenceBootstrap(unittest.TestCase):
    """TARGET A (T-125): the writer fence materializes ONLY the minimum
    surface required to take the first lock -- the home root and locks/ --
    through the confinement primitives, so a missing or minimally initialized
    home can run a fenced command while an indirection still refuses with zero
    external mutation."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.outside = self.tmp / "outside"
        self.outside.mkdir()

    def test_missing_home_bootstraps_root_and_locks(self) -> None:
        from saipal_engine.paths import HomeLock

        home = self.tmp / "brand" / "new" / ".saipal"
        self.assertFalse(home.exists())
        lock = HomeLock(home)
        self.assertTrue(lock.acquire())
        try:
            self.assertTrue((home / "locks").is_dir())
            self.assertTrue((home / "locks" / "saipal.lock").is_file())
        finally:
            lock.release()

    def test_missing_home_bootstraps_through_the_writer_fence(self) -> None:
        from saipal_engine.paths import writer_fence

        home = self.tmp / "fresh" / ".saipal"
        with writer_fence(home):
            self.assertTrue((home / "locks").is_dir())

    def test_minimal_home_without_locks_acquires_the_fence(self) -> None:
        from saipal_engine.paths import HomeLock

        home = self.tmp / ".saipal"
        home.mkdir()
        (home / "config.json").write_text("{}", encoding="utf-8")
        before = sorted(p.name for p in home.iterdir())
        lock = HomeLock(home)
        self.assertTrue(lock.acquire())
        lock.release()
        added = [n for n in sorted(p.name for p in home.iterdir()) if n not in before]
        self.assertEqual(added, ["locks"], "only the lock parent may appear")

    def test_symlinked_home_root_refuses_with_zero_external_mutation(self) -> None:
        from saipal_engine.paths import HomeLock

        linked = self.tmp / "linkedhome"
        os.symlink(str(self.outside), str(linked))
        lock = HomeLock(linked)
        with self.assertRaises(PalError):
            lock.acquire()
        self.assertEqual(
            sorted(p.name for p in self.outside.rglob("*")),
            [],
            "the writer fence mutated the redirected home root",
        )

    def test_symlinked_locks_directory_refuses_with_zero_external_mutation(
        self,
    ) -> None:
        from saipal_engine.paths import HomeLock

        home = self.tmp / ".saipal"
        home.mkdir()
        os.symlink(str(self.outside), str(home / "locks"))
        lock = HomeLock(home)
        with self.assertRaises(PalError):
            lock.acquire()
        self.assertEqual(
            sorted(p.name for p in self.outside.rglob("*")),
            [],
            "the writer fence mutated the redirected locks directory",
        )

    def test_lock_under_a_symlinked_home_creates_nothing_outside(self) -> None:
        # A bare lock (no confinement root) must not create its directory
        # through a symlinked home. A `mkdir(parents=True)` here would build
        # the whole chain outside and admit a lock there.
        linked = self.tmp / "linkedhome2"
        os.symlink(str(self.outside), str(linked))
        lock = FencedLockFile(linked / "locks" / "writer.lock")
        with self.assertRaises(PalError):
            lock.acquire()
        self.assertEqual(
            sorted(p.name for p in self.outside.rglob("*")),
            [],
            "a bare lock created its directory through a symlinked home",
        )

    def test_cli_continue_bootstraps_a_completely_missing_home(self) -> None:
        import saipal

        home = self.tmp / "cli" / ".saipal"
        self.assertFalse(home.exists())
        code = saipal.main(["--home", str(home), "continue"])
        self.assertEqual(code, 0)
        self.assertTrue((home / "locks").is_dir())
        self.assertTrue((home / "STATE.json").is_file())

    def test_cli_continue_on_a_minimal_existing_home(self) -> None:
        import saipal
        from saipal_engine.config import config_path, default_config

        home = self.tmp / "minimal" / ".saipal"
        home.mkdir(parents=True)
        config_path(home).write_text(
            json.dumps(default_config()), encoding="utf-8"
        )
        before = sorted(p.name for p in home.iterdir())
        self.assertEqual(before, ["config.json"])
        code = saipal.main(["--home", str(home), "continue"])
        self.assertEqual(code, 0)
        self.assertTrue((home / "locks").is_dir())


@skip_without_symlink
class EnsureHomeRootContract(unittest.TestCase):
    """TARGET B1 (T-125): a MISSING home root is a legitimate creation state,
    not PATH_ESCAPE; an EXISTING symlinked/junction/reparse root stays a
    refusal with zero external mutations."""

    LAYOUT = (
        "cache", "evidence", "findings", "findings/candidates",
        "findings/emitted", "locks", "session_inbox", "sessions",
        "sessions/checkpoints",
    )

    def test_missing_root_materializes_the_full_layout(self) -> None:
        from saipal_engine.home import ensure_home

        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "new" / ".saipal"
            self.assertFalse(home.exists())
            result = ensure_home(home)
            for name in self.LAYOUT:
                self.assertTrue((home / name).is_dir(), f"{name} missing")
            self.assertIn("LOG.jsonl", result["created_files"])

    def test_real_existing_root_is_idempotent(self) -> None:
        from saipal_engine.home import ensure_home

        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / ".saipal"
            first = ensure_home(home)
            second = ensure_home(home)
            self.assertTrue(first["created_files"])
            self.assertEqual(second["created_dirs"], [])
            self.assertEqual(second["created_files"], [])

    def test_symlinked_root_refuses_with_zero_external_mutation(self) -> None:
        from saipal_engine.home import ensure_home

        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            outside = tmp / "outside"
            outside.mkdir()
            linked = tmp / "linked"
            os.symlink(str(outside), str(linked))
            with self.assertRaises(PalError):
                ensure_home(linked)
            self.assertEqual(
                sorted(p.name for p in outside.rglob("*")),
                [],
                "ensure_home mutated the external target before refusing",
            )


@skip_without_symlink
class PrivateLedgerMaterialization(unittest.TestCase):
    """TARGET B2 (T-125, Wave E): when the private ledger home is separate
    from the publication sink, its `audit/` surface is securely materialized
    through the confinement primitive before any bookkeeping write, and a
    redirected one refuses with zero external bytes."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = _home(self.tmp)
        self.sink = self.tmp / "sink"
        (self.sink / "audit").mkdir(parents=True)
        (self.sink / "audit" / "MANIFEST.json").write_text(
            json.dumps({"kind": "saipen-audit-inbox", "schema_version": 1}),
            encoding="utf-8",
        )

    def _finding(self, finding_id: str = "PAL-9500") -> dict:
        return {
            "finding_id": finding_id,
            "drift_class": "PHASE_ILLEGALITY",
            "severity": "P3",
            "confidence": "HIGH",
        }

    def test_separate_private_ledger_audit_dir_is_materialized(self) -> None:
        from saipal_engine.enqueue import enqueue_audit

        private = self.tmp / "private"
        private.mkdir()
        self.assertFalse((private / "audit").exists())
        result = enqueue_audit(
            self.home, self._finding(), "body\n",
            maintainer_root=self.sink, private_ledger_home=private,
        )
        self.assertTrue((private / "audit").is_dir())
        self.assertTrue((private / "audit" / "entries.json").is_file())
        self.assertTrue((private / "audit" / "ledger.json").is_file())
        self.assertTrue((self.sink / "audit" / "1.md").is_file())
        self.assertEqual(result["audit_number"], 1)

    def test_redirected_private_ledger_audit_dir_refuses_with_zero_bytes(
        self,
    ) -> None:
        from saipal_engine.enqueue import enqueue_audit

        victim = self.tmp / "victim"
        victim.mkdir()
        private = self.tmp / "private"
        private.mkdir()
        os.symlink(str(victim), str(private / "audit"))
        with self.assertRaises(PalError):
            enqueue_audit(
                self.home, self._finding("PAL-9501"), "body\n",
                maintainer_root=self.sink, private_ledger_home=private,
            )
        self.assertEqual(
            sorted(p.name for p in victim.rglob("*")),
            [],
            "the redirected private ledger received bytes",
        )


@skip_without_symlink
class FinalLockNodeClassification(unittest.TestCase):
    """TARGET B4 (T-125): a known indirection at the FINAL lock node is an
    explicit confinement refusal (PATH_ESCAPE), never ordinary lock
    contention; a real competing lock still returns normal busy semantics,
    and an external target stays byte-identical."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = _home(self.tmp)
        self.outside = self.tmp / "outside"
        self.outside.mkdir()
        self.node = self.home / "locks" / "saipal.lock"

    def test_symlinked_final_lock_node_is_path_escape(self) -> None:
        victim = self.outside / "victim.lock"
        victim.write_bytes(b"PRECIOUS\n")
        os.symlink(str(victim), str(self.node))
        lock = FencedLockFile(self.node, confine_under=self.home)
        with self.assertRaises(PalError) as caught:
            lock.acquire()
        self.assertEqual(str(caught.exception.code), "PATH_ESCAPE")
        self.assertFalse(lock.held)
        self.assertEqual(victim.read_bytes(), b"PRECIOUS\n")

    def test_stale_symlinked_final_node_never_renames_or_deletes(
        self,
    ) -> None:
        victim = self.outside / "stale.lock"
        victim.write_bytes(b"KEEP\n")
        os.utime(str(victim), (0, 0))  # ancient: would be judged stale
        os.symlink(str(victim), str(self.node))
        lock = FencedLockFile(self.node, confine_under=self.home)
        with self.assertRaises(PalError):
            lock.acquire()
        self.assertEqual(victim.read_bytes(), b"KEEP\n")
        self.assertEqual(
            sorted(p.name for p in self.outside.iterdir()), ["stale.lock"]
        )

    def test_real_competing_lock_keeps_busy_semantics(self) -> None:
        holder = FencedLockFile(self.node, confine_under=self.home)
        self.assertTrue(holder.acquire())
        try:
            contender = FencedLockFile(self.node, confine_under=self.home)
            self.assertFalse(contender.acquire())
            self.assertFalse(contender.held)
            self.assertTrue(holder.owns_on_disk())
        finally:
            holder.release()


@skip_without_symlink
class DefaultHomeResolution(unittest.TestCase):
    """T-125 Target A: a missing discoverable home must NEVER be invented as a
    literal 'None' directory; mutating commands fall back to the tool-root
    home, whose writer fence supplies the safe bootstrap."""

    def test_missing_home_resolves_to_the_tool_root_home(self) -> None:
        import saipal
        from saipal_engine.paths import HOME_DIRNAME

        class _Options:
            home = None

        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as raw:
            os.chdir(raw)
            try:
                with mock.patch.dict(
                    os.environ, {"SAIPAL_HOME": ""}, clear=False
                ):
                    resolved = saipal._resolve_home(_Options(), "continue")
                    self.assertFalse(
                        (Path(raw) / "None").exists(),
                        "the bootstrap invented a 'None' home",
                    )
                self.assertEqual(resolved, saipal.resolve_tool_root() / HOME_DIRNAME)
            finally:
                os.chdir(cwd)

    def test_read_only_without_home_still_refuses(self) -> None:
        import saipal

        class _Options:
            home = None

        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as raw:
            os.chdir(raw)
            try:
                with mock.patch.dict(
                    os.environ, {"SAIPAL_HOME": ""}, clear=False
                ):
                    with self.assertRaises(PalError) as caught:
                        saipal._resolve_home(_Options(), "status")
                    self.assertEqual(str(caught.exception.code), "NO_HOME")
            finally:
                os.chdir(cwd)

    def test_cli_explicit_missing_home_bootstraps(self) -> None:
        import saipal

        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "new_home" / ".saipal"
            self.assertFalse(target.exists())
            code = saipal.main(["--home", str(target), "continue"])
            self.assertEqual(code, 0)
            self.assertTrue((target / "locks").is_dir())
            self.assertTrue((target / "STATE.json").is_file())

    def test_cli_ancestor_symlink_above_home_refuses(self) -> None:
        import saipal

        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            outside = tmp / "outside"
            outside.mkdir()
            link = tmp / "symlink_dir"
            os.symlink(str(outside), str(link), target_is_directory=True)
            target = link / ".saipal"
            with self.assertRaises(PalError) as caught:
                class _Opt:
                    home = str(target)
                saipal._resolve_home(_Opt(), "continue")
            self.assertEqual(str(caught.exception.code), "PATH_ESCAPE")
            self.assertEqual(list(outside.iterdir()), [])

    def test_cli_ancestor_symlink_two_levels_above_home_refuses(self) -> None:
        import saipal

        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            outside = tmp / "outside"
            outside.mkdir()
            link = tmp / "symlink_dir"
            os.symlink(str(outside), str(link), target_is_directory=True)
            target = link / "nested" / ".saipal"
            with self.assertRaises(PalError) as caught:
                class _Opt:
                    home = str(target)
                saipal._resolve_home(_Opt(), "continue")
            self.assertEqual(str(caught.exception.code), "PATH_ESCAPE")
            self.assertEqual(list(outside.iterdir()), [])


# --------------------------------------------------------------------------- #
# SRC-006 / T-127: the POSIX ownership, root-chain, trigger and stale-takeover
# controls. Every one of them is written as a RED control: it asserts on the
# confinement refusal (and on the untouched external bytes), so the pre-fix
# tree fails it rather than passing it by accident.
# --------------------------------------------------------------------------- #


def _fd_count() -> int | None:
    """Descriptors open in THIS process, or None without accounting.

    `/proc/self/fd` is the mechanism SRC-006 measured against; `/dev/fd` is
    the BSD/macOS spelling. No counting mechanism means no honest verdict, so
    the caller skips instead of guessing.
    """
    for candidate in ("/proc/self/fd", "/dev/fd"):
        directory = Path(candidate)
        if not directory.is_dir():
            continue
        try:
            return len(list(directory.iterdir()))
        except OSError:
            continue
    return None


def _indirect_dir(link: Path, target: Path) -> None:
    """Make `link` name `target` through an indirection, never directly.

    A directory junction on Windows (creatable without elevation) and a
    directory symlink on POSIX -- both are the exact indirection class
    PAL-WRITE-01 must refuse to traverse.
    """
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
        return
    os.symlink(str(target), str(link), target_is_directory=True)


def _remove_indirect(link: Path) -> None:
    """Remove an indirection WITHOUT recursing through it."""
    for remover in (os.rmdir, os.unlink):
        try:
            remover(str(link))
            return
        except OSError:
            continue


class PosixDescriptorLifetime(unittest.TestCase):
    """SRC-006 R001/R002: a confined primitive owns its descriptors.

    `_open_confined_parent` returns a NEW parent fd, and the root fd is the
    caller's too. Five callers closed only the root fd, so every POSIX call
    leaked exactly one descriptor until the process reached EMFILE and the
    full discovery run died with `OSError: [Errno 24] Too many open files`.

    The Windows fallback holds no descriptor at all (os.open cannot open a
    directory fd), so this contract is unmeasurable there: the control is
    SKIPPED, never weakened, off POSIX.
    """

    TOLERANCE = 4

    def setUp(self) -> None:
        if not ON_POSIX:
            self.skipTest("descriptor-relative primitives are POSIX-only")
        if _fd_count() is None:
            self.skipTest("no deterministic descriptor accounting on this host")
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = _home(self.tmp)

    def _delta(self, operation, count: int) -> int:
        before = _fd_count()
        for index in range(count):
            operation(index)
        after = _fd_count()
        return int(after) - int(before)

    def _assert_bounded(self, delta: int, what: str) -> None:
        self.assertLessEqual(
            delta,
            self.TOLERANCE,
            f"{what} grew the descriptor count by {delta} over 100 calls: "
            "an owned parent fd has no close path",
        )

    def test_atomic_write_bytes_owns_both_descriptors(self) -> None:
        delta = self._delta(
            lambda index: atomic_write_bytes(
                self.home / f"w{index}.json", b"x", root=self.home
            ),
            100,
        )
        self._assert_bounded(delta, "atomic_write_bytes")

    def test_confined_append_line_owns_both_descriptors(self) -> None:
        delta = self._delta(
            lambda index: confined_append_line(self.home, "LOG.jsonl", b"line"),
            100,
        )
        self._assert_bounded(delta, "confined_append_line")

    def test_confined_mkdir_owns_both_descriptors(self) -> None:
        delta = self._delta(
            lambda index: confined_mkdir(self.home, f"d{index}"), 100
        )
        self._assert_bounded(delta, "confined_mkdir")

    def test_confined_create_exclusive_and_unlink_own_both_descriptors(self) -> None:
        def cycle(index: int) -> None:
            confined_create_exclusive(self.home, f"locks/c{index}.lock", b"token")
            confined_unlink(self.home, f"locks/c{index}.lock")

        delta = self._delta(cycle, 100)
        self._assert_bounded(delta, "confined_create_exclusive+confined_unlink")

    def test_confined_replace_owns_both_descriptors(self) -> None:
        for index in range(100):
            atomic_write_bytes(self.home / f"s{index}", b"x", root=self.home)
        delta = self._delta(
            lambda index: confined_replace(self.home, f"s{index}", f"t{index}"), 100
        )
        self._assert_bounded(delta, "confined_replace")

    def test_a_thousand_confined_operations_stay_bounded(self) -> None:
        """SRC-006's resource-lifetime control: 1000 legitimate confined
        operations must not show linear growth, measured IMMEDIATELY after the
        calls return -- no garbage collection, no process exit."""
        before = _fd_count()
        for index in range(1000):
            step = index % 5
            if step == 0:
                atomic_write_bytes(self.home / f"bulk{index}.json", b"x", root=self.home)
            elif step == 1:
                confined_append_line(self.home, "LOG.jsonl", b"line")
            elif step == 2:
                confined_mkdir(self.home, f"bulkdir{index}")
            elif step == 3:
                confined_create_exclusive(self.home, f"locks/b{index}.lock", b"token")
                confined_unlink(self.home, f"locks/b{index}.lock")
            else:
                atomic_write_bytes(self.home / f"pre{index}", b"x", root=self.home)
                confined_replace(self.home, f"pre{index}", f"post{index}")
        after = _fd_count()
        self.assertLessEqual(
            int(after) - int(before),
            16,
            f"1000 confined operations left {int(after) - int(before)} extra "
            "descriptors open: every one of them is a leaked owned fd",
        )


class AppendEventAncestorIndirection(unittest.TestCase):
    """SRC-006 R003/R004: append_event is not an owner of home bootstrap.

    The measured pre-fix behaviour: `paths.root.mkdir(parents=True)` created
    `outside/nested/.saipal/` and then wrote `outside/nested/.saipal/LOG.jsonl`
    for `home = link/nested/.saipal` where `link` is an indirection, and an
    already-existing `outside/.saipal` accepted the append just as quietly.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.outside = self.tmp / "outside"
        self.outside.mkdir()
        self.link_path = self.tmp / "indirect"

    def _link(self, target: Path) -> Path:
        _indirect_dir(self.link_path, target)
        self.addCleanup(_remove_indirect, self.link_path)
        return self.link_path

    def test_missing_home_above_an_indirection_creates_nothing_external(self) -> None:
        link = self._link(self.outside)
        with self.assertRaises(PalError):
            append_event(link / "nested" / ".saipal", "probe")
        self.assertEqual(
            sorted(p.name for p in self.outside.iterdir()),
            [],
            "append_event must not materialize a home through an indirection",
        )

    def test_existing_external_home_above_an_indirection_is_refused(self) -> None:
        (self.outside / ".saipal").mkdir()
        link = self._link(self.outside)
        with self.assertRaises(PalError) as caught:
            append_event(link / ".saipal", "probe")
        self.assertEqual(str(caught.exception.code), "PATH_ESCAPE")
        self.assertFalse(
            (self.outside / ".saipal" / "LOG.jsonl").exists(),
            "an existing external home must not receive LOG.jsonl",
        )

    def test_indirection_installed_after_the_home_was_established_is_refused(
        self,
    ) -> None:
        real = self.tmp / "real_home"
        (real / ".saipal").mkdir(parents=True)
        append_event(real / ".saipal", "first")
        # Establish the home for real, then swap the lexical ancestor away.
        moved = self.tmp / "moved_home"
        os.rename(str(real), str(moved))
        self._link(self.outside)
        with self.assertRaises(PalError):
            append_event(real / ".saipal", "second")
        self.assertEqual(
            sorted(p.name for p in self.outside.iterdir()), [],
            "a post-establishment swap must not receive external bytes",
        )
        self.assertNotIn(
            "second",
            (moved / ".saipal" / "LOG.jsonl").read_text(encoding="utf-8"),
            "and must not be silently adopted by the moved physical home either",
        )


class TriggerLifecycleConfinement(unittest.TestCase):
    """SRC-006 R005: trigger claim/release go through the confined primitives.

    The writer fence serializes cycles; it does NOT freeze the lexical home
    pathname. The measured pre-fix behaviour, exactly as reproduced: rename the
    physical home away while the fence is held, replace the lexical home with
    an indirection, and raw `os.replace`/`os.unlink` renaming and deleting an
    EXTERNAL `trigger.json`/`trigger.claimed` as if it were home state.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = _home(self.tmp)
        self.outside = self.tmp / "outside"
        self.outside.mkdir()
        self.moved = self.tmp / "physical_home"

    def _swap_home_for_an_indirection(self) -> None:
        os.rename(str(self.home), str(self.moved))
        _indirect_dir(self.home, self.outside)
        self.addCleanup(_remove_indirect, self.home)

    def test_claim_cannot_rename_an_external_trigger(self) -> None:
        import saipal

        original = b'{"attacker": true}\n'
        (self.outside / "trigger.json").write_bytes(original)
        self._swap_home_for_an_indirection()
        with self.assertRaises(PalError):
            saipal._claim_trigger(self.home)
        self.assertEqual(
            (self.outside / "trigger.json").read_bytes(),
            original,
            "the external token must stay byte-identical",
        )
        self.assertFalse((self.outside / "trigger.claimed").exists())

    def test_release_cannot_delete_an_external_claim(self) -> None:
        import saipal

        original = b'{"claimed": true}\n'
        (self.outside / "trigger.claimed").write_bytes(original)
        self._swap_home_for_an_indirection()
        with self.assertRaises(PalError):
            saipal._release_trigger(self.home)
        self.assertEqual(
            (self.outside / "trigger.claimed").read_bytes(),
            original,
            "the external claim must not be deleted",
        )

    def test_a_legitimate_home_keeps_one_pending_and_one_claimed_trigger(self) -> None:
        """Semantics preserved: coalescing, one-cycle ownership, adoption."""
        import saipal

        paths = home_paths(self.home)
        paths.trigger.write_bytes(b'{"pending": 1}\n')
        self.assertTrue(saipal._claim_trigger(self.home))
        self.assertFalse(paths.trigger.exists(), "the claim consumed the token")
        self.assertTrue(paths.trigger_claim.exists())
        # A crash-left claim is adopted rather than deleted unexamined.
        self.assertTrue(saipal._claim_trigger(self.home))
        # A request arriving during the cycle survives it for the next one.
        paths.trigger.write_bytes(b'{"pending": 2}\n')
        saipal._release_trigger(self.home)
        self.assertTrue(paths.trigger.exists())
        self.assertFalse(paths.trigger_claim.exists())


class StaleTakeoverCleanupConfinement(unittest.TestCase):
    """SRC-006 R006: the contested claim stays bound to the parent that moved it.

    The measured pre-fix behaviour: `_take_over_if_stale` renamed the stale
    lock through `confined_replace` and then rebuilt
    `self.path.parent / claim.name` -- an UNBOUND absolute path -- to read and
    `_unlink_lock` it. Replacing the lexical locks parent with an indirection
    after the rename made both the verdict and the delete land on an external
    attacker file, while the truly moved claim stayed behind.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = _home(self.tmp)
        self.locks = self.home / "locks"
        self.outside = self.tmp / "outside"
        self.outside.mkdir()
        self.moved_locks = self.home / "locks_moved"
        self.lock_file = self.locks / "saipal.lock"
        self.judged = json.dumps(
            {"pid": 0, "host": "ghost", "created_at": 0, "owner": "old"}
        ).encode("utf-8")
        self.lock_file.write_bytes(self.judged)

    def _swap_locks_after_the_confined_rename(self, claim_name: list) -> None:
        """After the real rename, redirect the lexical locks dir externally."""
        import saipal_engine.paths as paths_module

        real_replace = paths_module.confined_replace
        swapped = {"done": False}

        def swapping_replace(root, source_relative, target_relative):
            result = real_replace(root, source_relative, target_relative)
            if not swapped["done"]:
                swapped["done"] = True
                claim_name.append(Path(target_relative).name)
                os.rename(str(self.locks), str(self.moved_locks))
                _indirect_dir(self.locks, self.outside)
                self.addCleanup(_remove_indirect, self.locks)
                (self.outside / Path(target_relative).name).write_bytes(self.judged)
            return result

        return mock.patch.object(paths_module, "confined_replace", swapping_replace)

    def test_external_contested_file_is_neither_judged_nor_deleted(self) -> None:
        claim_name: list = []
        lock = FencedLockFile(self.lock_file)
        with self._swap_locks_after_the_confined_rename(claim_name):
            with self.assertRaises(PalError):
                lock._take_over_if_stale()
        self.assertEqual(len(claim_name), 1, "the confined rename must have run")
        external = self.outside / claim_name[0]
        self.assertTrue(external.exists(), "the external file must survive")
        self.assertEqual(external.read_bytes(), self.judged)
        self.assertTrue(
            (self.moved_locks / claim_name[0]).exists(),
            "the claim the confined rename actually moved stays in the real "
            "physical directory",
        )
        self.assertFalse(
            lock.stale_taken_over,
            "a refused cleanup must not report a successful takeover",
        )

    def test_a_lost_takeover_never_touches_a_successor_lock(self) -> None:
        """Successor fencing survives the cleanup rewrite."""
        lock = FencedLockFile(self.lock_file)
        real_stale_now = lock._stale_now

        def racing_stale_now():
            verdict = real_stale_now()
            self.lock_file.write_bytes(
                json.dumps(
                    {"pid": os.getpid(), "host": "live", "owner": "successor"}
                ).encode("utf-8")
            )
            return verdict

        with mock.patch.object(lock, "_stale_now", racing_stale_now):
            self.assertFalse(lock._take_over_if_stale())
        self.assertEqual(
            json.loads(self.lock_file.read_text(encoding="utf-8"))["owner"],
            "successor",
            "a lost takeover must never overwrite a successor's live lock",
        )


if __name__ == "__main__":
    unittest.main()
