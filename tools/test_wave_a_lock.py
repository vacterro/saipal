"""Wave A: one writer per home, with stale takeover instead of a permanent wedge."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from saipal_engine.errors import PalError
from saipal_engine.paths import HomeLock

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

    def test_unreadable_lock_is_treated_as_stale(self) -> None:
        locks = self.home / "locks"
        locks.mkdir(parents=True, exist_ok=True)
        (locks / "saipal.lock").write_text("not json", encoding="utf-8")

        lock = HomeLock(self.home)
        self.assertTrue(lock.acquire(), "a corrupt lock must not wedge the home forever")
        self.assertTrue(lock.stale_taken_over)
        lock.release()


if __name__ == "__main__":
    unittest.main()
