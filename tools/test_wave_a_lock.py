"""Wave A: one writer per home, with stale takeover instead of a permanent wedge.

T-062 adds the ownership half (audit W2-001): the filesystem node is not proof of
ownership, so a holder may delete only the lock it can still prove is its own.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path

from saipal_engine.errors import PalError
from saipal_engine.paths import (
    LOCK_CREATE_GRACE_SECONDS,
    FencedLockFile,
    HomeLock,
)

import pal_test_support as support


class HomeLockContract(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = support.make_home(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_acquire_then_release(self) -> None:
        lock = HomeLock(self.home)
        self.assertTrue(lock.acquire())
        self.assertTrue(lock.held)
        self.assertTrue(Path(lock.paths.lock).exists())
        lock.release()
        self.assertFalse(lock.held)
        self.assertFalse(Path(lock.paths.lock).exists())

    def test_second_writer_is_refused_while_held(self) -> None:
        first = HomeLock(self.home)
        self.assertTrue(first.acquire())
        second = HomeLock(self.home)
        try:
            self.assertFalse(second.acquire())
            self.assertIn("holds the home lock", second.detail)
        finally:
            first.release()

    def test_lock_is_reusable_after_release(self) -> None:
        first = HomeLock(self.home)
        first.acquire()
        first.release()
        second = HomeLock(self.home)
        self.assertTrue(second.acquire())
        second.release()

    def test_context_manager_refuses_with_writer_busy(self) -> None:
        first = HomeLock(self.home)
        self.assertTrue(first.acquire())
        try:
            with self.assertRaises(PalError) as caught:
                with HomeLock(self.home):
                    pass
            self.assertEqual(caught.exception.code, "WRITER_BUSY")
        finally:
            first.release()

    def test_context_manager_releases_on_exception(self) -> None:
        with self.assertRaises(RuntimeError):
            with HomeLock(self.home):
                raise RuntimeError("boom")
        self.assertFalse(Path(HomeLock(self.home).paths.lock).exists())

    def test_stale_lock_by_age_is_taken_over(self) -> None:
        locks = self.home / "locks"
        locks.mkdir(parents=True, exist_ok=True)
        payload = {
            "pid": 999999,
            "host": "ghost",
            "created_at": time.time() - 10_000,
            "owner": "x",
        }
        (locks / "saipal.lock").write_text(json.dumps(payload), encoding="utf-8")

        lock = HomeLock(self.home)
        self.assertTrue(lock.acquire())
        self.assertTrue(lock.stale_taken_over)
        lock.release()

    def test_lock_with_dead_pid_is_taken_over(self) -> None:
        locks = self.home / "locks"
        locks.mkdir(parents=True, exist_ok=True)
        payload = {"pid": 0, "host": "here", "created_at": time.time(), "owner": "x"}
        (locks / "saipal.lock").write_text(json.dumps(payload), encoding="utf-8")

        lock = HomeLock(self.home)
        self.assertTrue(lock.acquire())
        self.assertTrue(lock.stale_taken_over)
        lock.release()

    def test_live_lock_is_never_stolen(self) -> None:
        lock = HomeLock(self.home)
        self.assertTrue(lock.acquire())
        try:
            intruder = HomeLock(self.home)
            self.assertFalse(intruder.acquire())
            self.assertFalse(intruder.stale_taken_over)
        finally:
            lock.release()

    def test_release_without_acquire_is_harmless(self) -> None:
        lock = HomeLock(self.home)
        lock.release()
        lock.release()
        self.assertFalse(lock.held)

    def test_takeover_replaces_the_stale_payload(self) -> None:
        """After a takeover the lock must describe its new owner, not the ghost."""
        locks = self.home / "locks"
        locks.mkdir(parents=True, exist_ok=True)
        (locks / "saipal.lock").write_text(
            json.dumps(
                {"pid": 0, "host": "ghost", "created_at": time.time() - 10_000, "owner": "x"}
            ),
            encoding="utf-8",
        )

        lock = HomeLock(self.home)
        self.assertTrue(lock.acquire())
        try:
            payload = json.loads((locks / "saipal.lock").read_text(encoding="utf-8"))
            self.assertNotEqual(payload["owner"], "x")
            self.assertGreater(payload["pid"], 0)
        finally:
            lock.release()

    def test_an_aged_unreadable_lock_is_treated_as_stale(self) -> None:
        """A corrupt lock must not wedge the home forever -- once it is old.

        This test used to accept a FRESHLY written corrupt lock as stale, which
        codified the create-before-payload steal: `O_EXCL` creates the node
        before the payload, so every honest acquisition is briefly unreadable and
        was therefore briefly stealable (audit W2-001). Age is what separates
        debris from a live acquisition, so the fixture now ages the file and the
        fresh case has its own test below.
        """
        locks = self.home / "locks"
        locks.mkdir(parents=True, exist_ok=True)
        corrupt = locks / "saipal.lock"
        corrupt.write_text("not json", encoding="utf-8")
        old = time.time() - LOCK_CREATE_GRACE_SECONDS - 60
        os.utime(corrupt, (old, old))

        lock = HomeLock(self.home)
        self.assertTrue(lock.acquire(), "aged debris must not wedge the home forever")
        self.assertTrue(lock.stale_taken_over)
        lock.release()

    def test_a_freshly_created_unreadable_lock_is_not_stolen(self) -> None:
        """Red control: the create/write window of an honest acquisition.

        Another process has just created its lock node and has not written the
        payload yet. Reading it yields nothing, and calling that stale hands two
        writers the same home.
        """
        locks = self.home / "locks"
        locks.mkdir(parents=True, exist_ok=True)
        (locks / "saipal.lock").write_bytes(b"")

        lock = HomeLock(self.home)
        self.assertFalse(
            lock.acquire(), "a lock still inside its create window is not debris"
        )
        self.assertFalse(lock.stale_taken_over)
        self.assertTrue((locks / "saipal.lock").exists(), "nothing may be deleted")


class OwnershipFencing(unittest.TestCase):
    """A holder may only delete the lock it still owns (audit W2-001)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = support.make_home(Path(self._tmp.name))
        self.lock_file = self.home / "locks" / "saipal.lock"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _payload(self) -> dict:
        return json.loads(self.lock_file.read_text(encoding="utf-8"))

    def test_acquire_retains_the_owner_token_it_wrote(self) -> None:
        lock = HomeLock(self.home)
        self.assertTrue(lock.acquire())
        try:
            self.assertEqual(self._payload()["owner"], lock._lock.token)
        finally:
            lock.release()

    def test_two_acquisitions_never_share_a_token(self) -> None:
        first = HomeLock(self.home)
        self.assertTrue(first.acquire())
        token = first._lock.token
        first.release()
        second = HomeLock(self.home)
        self.assertTrue(second.acquire())
        try:
            self.assertNotEqual(second._lock.token, token)
        finally:
            second.release()

    def test_a_stale_holder_release_leaves_the_successor_lock_intact(self) -> None:
        """The audit's reproduction: A releases after B legitimately took over."""
        holder = HomeLock(self.home)
        self.assertTrue(holder.acquire())

        successor = json.dumps(
            {
                "pid": os.getpid(),
                "host": socket.gethostname(),
                "created_at": time.time(),
                "owner": "successor-token",
            }
        )
        self.lock_file.write_text(successor, encoding="utf-8")

        holder.release()
        self.assertTrue(
            self.lock_file.exists(), "a stale holder must not delete a live lock"
        )
        self.assertEqual(self._payload()["owner"], "successor-token")
        self.assertFalse(holder.held)
        self.assertIn("owned by another run", holder.detail)

    def test_a_released_holder_cannot_delete_the_successor_later(self) -> None:
        holder = HomeLock(self.home)
        self.assertTrue(holder.acquire())
        holder.release()
        successor = HomeLock(self.home)
        self.assertTrue(successor.acquire())
        try:
            holder.release()
            self.assertTrue(self.lock_file.exists())
            self.assertEqual(self._payload()["owner"], successor._lock.token)
        finally:
            successor.release()

    def test_an_unreadable_lock_is_left_in_place_by_release(self) -> None:
        """Our own torn write, or a successor mid-acquisition. Either way: leave it."""
        holder = HomeLock(self.home)
        self.assertTrue(holder.acquire())
        self.lock_file.write_bytes(b"")
        holder.release()
        self.assertTrue(self.lock_file.exists())
        self.assertIn("unreadable", holder.detail)

    def test_a_vanished_lock_release_is_not_an_error(self) -> None:
        holder = HomeLock(self.home)
        self.assertTrue(holder.acquire())
        self.lock_file.unlink()
        holder.release()
        self.assertFalse(holder.held)
        self.assertIn("already gone", holder.detail)

    def test_only_one_of_two_contenders_reports_ownership(self) -> None:
        first = FencedLockFile(self.lock_file)
        second = FencedLockFile(self.lock_file)
        self.assertTrue(first.acquire())
        try:
            self.assertFalse(second.acquire())
            self.assertTrue(first.owns_on_disk())
            self.assertFalse(second.owns_on_disk())
        finally:
            first.release()

    def test_refresh_preserves_the_owner_token(self) -> None:
        lock = FencedLockFile(self.lock_file)
        self.assertTrue(lock.acquire())
        try:
            token = lock.token
            self.assertTrue(lock.refresh(ttl=99))
            self.assertEqual(lock.token, token)
            payload = self._payload()
            self.assertEqual(payload["owner"], token)
            self.assertEqual(payload["ttl"], 99)
        finally:
            lock.release()

    def test_refresh_is_refused_once_ownership_changed(self) -> None:
        """Red control: refresh must not steal a lock back."""
        lock = FencedLockFile(self.lock_file)
        self.assertTrue(lock.acquire())
        self.lock_file.write_text(
            json.dumps(
                {
                    "pid": os.getpid(),
                    "host": socket.gethostname(),
                    "created_at": time.time(),
                    "owner": "somebody-else",
                }
            ),
            encoding="utf-8",
        )
        self.assertFalse(lock.refresh())
        self.assertEqual(self._payload()["owner"], "somebody-else")

    def test_a_dead_owner_is_recovered_before_the_ttl_expires(self) -> None:
        """PID before TTL: a crash must not wedge the home for the full TTL."""
        locks = self.home / "locks"
        locks.mkdir(parents=True, exist_ok=True)
        self.lock_file.write_text(
            json.dumps(
                {
                    "pid": 999_999_999,
                    "host": socket.gethostname(),
                    "created_at": time.time(),
                    "owner": "dead",
                }
            ),
            encoding="utf-8",
        )
        lock = HomeLock(self.home, ttl=10_000)
        self.assertTrue(lock.acquire(), "a dead owner is recoverable immediately")
        self.assertTrue(lock.stale_taken_over)
        lock.release()

    def test_a_foreign_host_lock_waits_for_the_ttl(self) -> None:
        """A pid from another machine says nothing about a local process."""
        locks = self.home / "locks"
        locks.mkdir(parents=True, exist_ok=True)
        self.lock_file.write_text(
            json.dumps(
                {
                    "pid": 999_999_999,
                    "host": "some-other-host",
                    "created_at": time.time(),
                    "owner": "remote",
                }
            ),
            encoding="utf-8",
        )
        lock = HomeLock(self.home, ttl=10_000)
        self.assertFalse(
            lock.acquire(), "a foreign live lock expires on TTL, not on a local pid probe"
        )
        self.assertEqual(self._payload()["owner"], "remote")


if __name__ == "__main__":
    unittest.main()
