"""T-062 / audit W2-001: lock ownership fencing across all three lock types.

The defect was structural and identical in three places: an acquisition minted a
random `owner` token, wrote it to the lock file, and threw it away. `release()`
then unlinked whatever node happened to be at the path -- so a slow or stale
holder deleted its successor's live lock and two writers were admitted to the
same home, session or audit ledger.

`FencedLockFile` is now the only lock mechanism. These tests pin the properties
the audit's VERIFY list asks for, for every wrapper, plus the create/write window
the old code treated as debris.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import pal_test_support as support
from saipal_engine import enqueue as enqueue_mod
from saipal_engine import hardening as hard
from saipal_engine.paths import (
    LOCK_CREATE_GRACE_SECONDS,
    FencedLockFile,
    HomeLock,
)


def live_payload(owner: str) -> str:
    """A lock payload that is unambiguously alive on this host."""
    return json.dumps(
        {
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "created_at": time.time(),
            "owner": owner,
        }
    )


class LockCase(unittest.TestCase):
    """One case per lock type, so a fix that misses one wrapper still fails."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        (self.home / "locks").mkdir(parents=True, exist_ok=True)
        (self.home / "audit" / "staging").mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def home_lock(self) -> tuple[object, Path]:
        lock = HomeLock(self.home)
        return lock, self.home / "locks" / "saipal.lock"

    def session_lease(self) -> tuple[object, Path]:
        lease = hard.SessionLease(self.home, "sess-fence")
        return lease, lease.path

    def audit_lock(self) -> tuple[object, Path]:
        lock = enqueue_mod.AuditInboxLock(self.home / "audit" / "staging")
        return lock, lock.lock_path

    def each_lock(self):
        """`(label, factory)` for every lock type in the codebase."""
        return (
            ("HomeLock", self.home_lock),
            ("SessionLease", self.session_lease),
            ("AuditInboxLock", self.audit_lock),
        )


class EveryLockTypeIsFenced(LockCase):
    def test_a_stale_holder_release_never_deletes_a_successor(self) -> None:
        """The audit's exact reproduction, for all three implementations."""
        for label, factory in self.each_lock():
            with self.subTest(lock=label):
                holder, path = factory()
                self.assertTrue(holder.acquire(), label)
                path.write_text(live_payload("successor"), encoding="utf-8")
                holder.release()
                self.assertTrue(path.exists(), f"{label} deleted a live successor lock")
                self.assertEqual(
                    json.loads(path.read_text(encoding="utf-8"))["owner"], "successor"
                )
                self.assertFalse(holder.held, label)

    def test_a_holder_releases_its_own_lock(self) -> None:
        """The control for the test above: fencing must not break normal release."""
        for label, factory in self.each_lock():
            with self.subTest(lock=label):
                holder, path = factory()
                self.assertTrue(holder.acquire(), label)
                self.assertTrue(path.exists(), label)
                holder.release()
                self.assertFalse(path.exists(), f"{label} failed to release its own lock")

    def test_two_contenders_never_both_hold(self) -> None:
        for label, factory in self.each_lock():
            with self.subTest(lock=label):
                first, _path = factory()
                second, _same = factory()
                self.assertTrue(first.acquire(), label)
                try:
                    self.assertFalse(second.acquire(), label)
                    self.assertTrue(first.held, label)
                    self.assertFalse(second.held, label)
                finally:
                    first.release()

    def test_a_fresh_unpopulated_lock_is_never_stolen(self) -> None:
        """The create-before-payload window: O_EXCL then a moment of empty bytes."""
        for label, factory in self.each_lock():
            with self.subTest(lock=label):
                _unused, path = factory()
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"")
                contender, _same = factory()
                self.assertFalse(
                    contender.acquire(),
                    f"{label} stole a lock inside its create/write window",
                )
                self.assertTrue(path.exists(), f"{label} deleted a live acquisition")

    def test_a_dead_owner_is_still_recoverable(self) -> None:
        """Fencing must not cost crash recovery."""
        for label, factory in self.each_lock():
            with self.subTest(lock=label):
                _unused, path = factory()
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    json.dumps(
                        {
                            "pid": 999_999_999,
                            "host": socket.gethostname(),
                            "created_at": time.time() - 10_000,
                            "owner": "ghost",
                        }
                    ),
                    encoding="utf-8",
                )
                lock, _same = factory()
                self.assertTrue(lock.acquire(), f"{label} cannot recover a dead owner")
                lock.release()

    def test_aged_debris_is_recoverable_but_fresh_debris_is_not(self) -> None:
        for label, factory in self.each_lock():
            with self.subTest(lock=label):
                _unused, path = factory()
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{{{ not json", encoding="utf-8")

                fresh, _same = factory()
                self.assertFalse(fresh.acquire(), f"{label} stole fresh unreadable bytes")

                old = time.time() - LOCK_CREATE_GRACE_SECONDS - 60
                os.utime(path, (old, old))
                aged, _same2 = factory()
                self.assertTrue(aged.acquire(), f"{label} wedged on aged debris")
                aged.release()


class LeaseOwnership(LockCase):
    """SessionLease's own surface: refresh, expiry and re-targeting."""

    def test_refresh_keeps_the_same_owner(self) -> None:
        lease = hard.SessionLease(self.home, "sess-refresh")
        self.assertTrue(lease.acquire())
        try:
            token = lease.token
            self.assertTrue(lease.refresh(ttl=60))
            payload = json.loads(lease.path.read_text(encoding="utf-8"))
            self.assertEqual(lease.token, token)
            self.assertEqual(payload["owner"], token)
            self.assertEqual(payload["ttl"], 60)
        finally:
            lease.release()

    def test_refresh_after_a_takeover_is_refused(self) -> None:
        """Red control: a lease may not refresh its way back into ownership."""
        lease = hard.SessionLease(self.home, "sess-lost")
        self.assertTrue(lease.acquire())
        lease.path.write_text(live_payload("newer-cycle"), encoding="utf-8")
        self.assertFalse(lease.refresh())
        self.assertEqual(
            json.loads(lease.path.read_text(encoding="utf-8"))["owner"], "newer-cycle"
        )

    def test_an_absent_lease_reads_as_expired(self) -> None:
        lease = hard.SessionLease(self.home, "sess-absent")
        self.assertTrue(lease.is_expired())

    def test_a_held_lease_is_not_expired(self) -> None:
        lease = hard.SessionLease(self.home, "sess-live")
        self.assertTrue(lease.acquire())
        try:
            self.assertFalse(lease.is_expired())
        finally:
            lease.release()

    def test_re_targeting_a_held_lease_is_refused(self) -> None:
        """Otherwise the first lease file is abandoned with nobody able to release it."""
        lease = hard.SessionLease(self.home, "sess-one")
        self.assertTrue(lease.acquire())
        first_path = lease.path
        try:
            self.assertFalse(lease.acquire(home=self.home, session_id="sess-two"))
            self.assertTrue(first_path.exists())
        finally:
            lease.release()

    def test_two_sessions_do_not_share_a_lease(self) -> None:
        first = hard.SessionLease(self.home, "sess-A")
        second = hard.SessionLease(self.home, "sess-B")
        self.assertTrue(first.acquire())
        try:
            self.assertTrue(second.acquire(), "distinct sessions must not contend")
            second.release()
        finally:
            first.release()


class AuditEnqueueSurvivesFencing(LockCase):
    """The one external write must still work, and still release its lock."""

    def _finding(self, finding_id: str) -> dict:
        return {
            "finding_id": finding_id,
            "state": "QUALIFIED",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "rule_ids": ["PAL-CMD-01"],
        }

    def test_enqueue_releases_its_lock(self) -> None:
        enqueue_mod.enqueue_audit(self.home, self._finding("PAL-FENCE1"), "body one")
        self.assertFalse(
            (self.home / "audit" / "staging" / "audit_inbox.lock").exists(),
            "the audit inbox lock must not survive a successful enqueue",
        )

    def test_two_enqueues_take_distinct_slots(self) -> None:
        first = enqueue_mod.enqueue_audit(self.home, self._finding("PAL-FENCE2"), "b2")
        second = enqueue_mod.enqueue_audit(self.home, self._finding("PAL-FENCE3"), "b3")
        self.assertNotEqual(first["audit_number"], second["audit_number"])

    def test_an_enqueue_never_deletes_a_concurrent_publishers_lock(self) -> None:
        """Red control: the lock a retrying publisher took over must survive.

        The first publisher finishes and releases; a second publisher's lock is
        already in place by then. The release must leave it alone.
        """
        lock_path = self.home / "audit" / "staging" / "audit_inbox.lock"
        holder = enqueue_mod.AuditInboxLock(self.home / "audit" / "staging")
        self.assertTrue(holder.acquire())
        lock_path.write_text(live_payload("other-publisher"), encoding="utf-8")
        holder.release()
        self.assertTrue(lock_path.exists())
        self.assertEqual(
            json.loads(lock_path.read_text(encoding="utf-8"))["owner"], "other-publisher"
        )


class ReleaseSurvivesASharingWindow(LockCase):
    """A contender reading the lock must not strand it on release.

    Windows refuses to unlink a file another handle has open, and every contender
    opens the lock to judge it. A single best-effort unlink therefore failed
    intermittently and left a released lock on disk, which the next publisher read
    as live and waited out the TTL for -- observed as a ~1-in-4 flake in
    `test_wave_e_audit.test_lock_blocks_second_publisher`.
    """

    def test_release_retries_past_a_transient_unlink_failure(self) -> None:
        lock = FencedLockFile(self.home / "locks" / "saipal.lock")
        self.assertTrue(lock.acquire())
        real_unlink = os.unlink
        failures = {"left": 3}

        def flaky_unlink(target):
            if failures["left"] > 0:
                failures["left"] -= 1
                raise PermissionError(32, "The process cannot access the file")
            real_unlink(target)

        with mock.patch("saipal_engine.paths.os.unlink", flaky_unlink):
            lock.release()
        self.assertFalse(
            lock.path.exists(), "a transient sharing failure must not strand the lock"
        )
        self.assertEqual(lock.detail, "released")
        self.assertEqual(failures["left"], 0, "the retry loop must actually have retried")

    def test_a_permanently_undeletable_lock_is_reported_not_claimed_free(self) -> None:
        """Red control: never tell a caller the slot is free when it is not."""
        lock = FencedLockFile(self.home / "locks" / "saipal.lock")
        self.assertTrue(lock.acquire())

        def always_fails(_target):
            raise PermissionError(32, "The process cannot access the file")

        with mock.patch("saipal_engine.paths.os.unlink", always_fails):
            lock.release()
        self.assertTrue(lock.path.exists())
        self.assertIn("could not be removed", lock.detail)
        os.unlink(str(lock.path))

    def test_a_lock_held_open_for_reading_is_still_released(self) -> None:
        """The real shape of the flake, without mocking anything."""
        lock = FencedLockFile(self.home / "locks" / "saipal.lock")
        self.assertTrue(lock.acquire())
        handle = open(str(lock.path), "rb")
        try:
            lock.release()
        finally:
            handle.close()
        # On POSIX the unlink succeeds immediately; on Windows it succeeds once
        # the handle closes or is reported honestly. Either way the caller is not
        # told a stranded lock was released.
        if lock.path.exists():
            self.assertIn("could not be removed", lock.detail)
        else:
            self.assertEqual(lock.detail, "released")


    def test_a_takeover_that_loses_the_race_restores_what_it_moved(self) -> None:
        """Red control: the fenced takeover must not destroy a live lock.

        The node is judged stale, then replaced by a live one before the claim.
        The loser must put the live lock back rather than delete it.
        """
        locks = self.home / "locks"
        locks.mkdir(parents=True, exist_ok=True)
        lock_file = locks / "saipal.lock"
        lock_file.write_text(
            json.dumps({"pid": 0, "host": "ghost", "created_at": 0, "owner": "old"}),
            encoding="utf-8",
        )

        lock = FencedLockFile(lock_file)
        original = lock._stale_now

        def racing_stale_now():
            verdict = original()
            lock_file.write_text(live_payload("winner"), encoding="utf-8")
            return verdict

        with mock.patch.object(lock, "_stale_now", racing_stale_now):
            self.assertFalse(lock._take_over_if_stale())
        self.assertTrue(lock_file.exists(), "the live lock must survive")
        self.assertEqual(
            json.loads(lock_file.read_text(encoding="utf-8"))["owner"], "winner"
        )

    def test_a_lost_takeover_leaves_no_lock_named_debris(self) -> None:
        """The restore must not leave a second file that looks like a lock."""
        locks = self.home / "locks"
        locks.mkdir(parents=True, exist_ok=True)
        lock_file = locks / "saipal.lock"
        lock_file.write_text(
            json.dumps({"pid": 0, "host": "ghost", "created_at": 0, "owner": "old"}),
            encoding="utf-8",
        )
        lock = FencedLockFile(lock_file)
        original = lock._stale_now

        def racing_stale_now():
            verdict = original()
            lock_file.write_text(live_payload("winner"), encoding="utf-8")
            return verdict

        with mock.patch.object(lock, "_stale_now", racing_stale_now):
            lock._take_over_if_stale()
        self.assertEqual(
            sorted(p.name for p in locks.iterdir()),
            ["saipal.lock"],
            "a lost race must not leave contested residue behind",
        )


class SharedPrimitive(unittest.TestCase):
    """One mechanism, not three -- the wrappers must delegate, not duplicate."""

    def test_every_lock_type_uses_the_fenced_primitive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = support.make_home(Path(tmp))
            self.assertIsInstance(HomeLock(home)._lock, FencedLockFile)
            self.assertIsInstance(hard.SessionLease(home, "s")._lock, FencedLockFile)
            self.assertIsInstance(
                enqueue_mod.AuditInboxLock(Path(home) / "audit")._lock, FencedLockFile
            )

    def test_no_lock_module_reimplements_acquire(self) -> None:
        """Red control against the defect returning as a fourth copy."""
        engine = Path(__file__).resolve().parent / "saipal_engine"
        for name in ("hardening.py", "enqueue.py"):
            text = (engine / name).read_text(encoding="utf-8")
            self.assertNotIn(
                "O_EXCL", text, f"{name} must not open lock files itself; use FencedLockFile"
            )


if __name__ == "__main__":
    unittest.main()
