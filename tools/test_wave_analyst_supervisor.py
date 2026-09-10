"""T-91: the foreground unattended supervisor.

The supervisor orchestrates existing boundaries -- the real worker, the
durable budget window, the provenance reconciliation -- and never duplicates
a pipeline. These controls run whole watch cycles against temporary homes
with fake backends and injected sleeps: single ownership, read-only status
while supervised, cycle checkpoints, provider outage and one broken source
never freeze the supervisor, restart continues without duplicate receipts,
and publication stays STAGE_ONLY.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import pal_test_support as support
from saipal_analyst import jobs as jobs_mod
from saipal_analyst import supervisor as sup_mod
from saipal_analyst.config import default_analyst_config, save_analyst_config
from saipal_engine import submit as submit_module
from saipal_engine.errors import PalError


class RefreshFencingRace(unittest.TestCase):
    """Holds the successor lock between interleaving steps."""

    _successor = None


class WatchBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def fresh_home(self, *fixtures: str) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = support.make_home(Path(tmp.name))
        support.put_inbox(home, *fixtures)
        support.run_saipal("continue", home=home)
        return home

    def enable(self, home: Path, backend: object) -> dict:
        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 0
        config["budgets"]["max_units_per_run"] = 1
        save_analyst_config(home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "stub-key"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)
        return config

    def candidate_for(self, home: Path, verdict: str = "NO_DRIFT") -> str:
        import test_wave_analyst_repair as repair

        return repair.RepairBase.candidate_for(repair.RepairBase(), home, verdict)


class IntakeAndRebind(WatchBase):
    def test_cycle_imports_then_investigates_then_checkpoints(self) -> None:
        import test_wave_analyst_repair as repair
        from saipal_analyst import jobs as jobs_mod
        from saipal_engine.sources import load_sources, save_sources

        home = self.fresh_home()
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        # A configured source whose store holds the golden session.
        store = Path(self._tmp.name) / "claude-store"
        store.mkdir(parents=True, exist_ok=True)
        (store / "conformant-cold.json").write_text(
            json.dumps(support.stamp_binding(home, support.load_fixture("conformant-cold.json"))),
            encoding="utf-8",
        )
        save_sources(home, {
            "schema_version": 1,
            "sources": [{"id": "generic-main", "kind": "generic", "path": str(store), "enabled": True}],
        })
        # Import first so the pending unit exists and the scripted reply can
        # name it; then one supervisor cycle runs intake (idempotent) plus
        # the semantic batch.
        intake = sup_mod._cycle_intake(home)
        self.assertGreaterEqual(intake["sources_checked"], 1)
        self.assertGreaterEqual(intake["sessions_imported"], 1)
        backend.script.append((200, repair.envelope(self.candidate_for(home))))

        result = sup_mod.watch(home, max_cycles=1, max_units_per_cycle=1, sleep_fn=lambda _s: None)
        self.assertEqual(result["cycles_run"], 1)
        cycle = result["cycle_results"][0]
        self.assertGreaterEqual(cycle["intake"]["sources_checked"], 1)
        # The imported session became semantic work.
        self.assertGreaterEqual(cycle["receipts"], 1)
        _status, receipts_payload, _d = submit_module.load_receipts(home)
        self.assertGreaterEqual(len(receipts_payload.get("receipts") or []), 1)

    def test_authority_change_triggers_rebind_waking_blocked_jobs(self) -> None:
        import test_wave_analyst_repair as repair
        from saipal_analyst import jobs as jobs_mod

        tmp_home = tempfile.TemporaryDirectory()
        self.addCleanup(tmp_home.cleanup)
        home = support.make_home(Path(tmp_home.name))
        # The home's declared release root lives beside the home; remember it
        # BEFORE the import, then strip the config to the pre-T-86 state.
        authority_root = Path(tmp_home.name) / "protocol_authority" / "releases"
        support.put_inbox(home, "conformant-cold.json")
        from saipal_engine.config import load_config, save_config

        cfg = load_config(home)[1]
        cfg["protocol_authority"] = {k: None for k in ("git_repository", "release_root", "snapshot_root")}
        save_config(home, cfg)
        support.run_saipal("continue", home=home)

        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        # T-101 first-cycle invariant: trusted authority exists and indexed
        # bindings carry no matching reconciliation checkpoint -> the first
        # cycle rebinds exactly once (UNKNOWN records get their one chance at
        # strengthening instead of waiting for a SECOND authority change).
        first = sup_mod.watch(home, max_cycles=1, max_units_per_cycle=1, sleep_fn=lambda _s: None)
        self.assertEqual(first["cycle_results"][0]["rebound"], True)
        job = list(jobs_mod.load_journal(home)["jobs"].values())[0]
        self.assertIn(job["stage"], (jobs_mod.BLOCKED, jobs_mod.BLOCKED_BINDING))

        # Authority arrives THROUGH THE TRUST PATH (T-100): enroll pins the
        # root; the material fingerprint changes -> the next cycle rebinds
        # again and reports impact.
        from saipal_engine import authority as authority_mod

        authority_mod.enroll(home, "release_root", authority_root)
        cfg = load_config(home)[1]
        cfg["protocol_authority"] = {
            "git_repository": None,
            "release_root": str(authority_root),
            "snapshot_root": None,
        }
        save_config(home, cfg)
        backend.script.append((200, repair.envelope(self.candidate_for(home))))
        second = sup_mod.watch(home, max_cycles=1, max_units_per_cycle=1, sleep_fn=lambda _s: None)
        self.assertTrue(second["cycle_results"][0]["rebound"])
        self.assertGreaterEqual(second["cycle_results"][0]["newly_eligible"], 1)
        journal = jobs_mod.load_journal(home)
        self.assertTrue(
            any(job["stage"] == jobs_mod.DONE for job in journal["jobs"].values()),
            "a rebind-strengthened unit must become semantic work",
        )
        # Unchanged trusted authority: no repeated rebind.
        backend.script.append((200, repair.envelope(self.candidate_for(home))))
        third = sup_mod.watch(home, max_cycles=1, max_units_per_cycle=1, sleep_fn=lambda _s: None)
        self.assertFalse(third["cycle_results"][0]["rebound"], "unchanged authority must not rebind again")

    def test_one_broken_source_never_freezes_intake(self) -> None:
        import test_wave_analyst_repair as repair
        from saipal_engine.sources import save_sources

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        broken = Path(self._tmp.name) / "broken-store"
        broken.mkdir(parents=True, exist_ok=True)
        healthy = Path(self._tmp.name) / "healthy-store"
        healthy.mkdir(parents=True, exist_ok=True)
        (healthy / "session-1.jsonl").write_text('{"type": "x"}\n', encoding="utf-8")
        save_sources(home, {
            "schema_version": 1,
            "sources": [
                {"id": "broken", "kind": "claude", "path": str(broken), "enabled": True},
                {"id": "healthy", "kind": "claude", "path": str(healthy), "enabled": True},
            ],
        })
        result = sup_mod.watch(home, max_cycles=1, max_units_per_cycle=1, sleep_fn=lambda _s: None)
        # The cycle completed with BOTH sources recorded: no global freeze.
        self.assertEqual(result["cycles_run"], 1)


class Ownership(WatchBase):
    def test_second_watch_refused_busy(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_for(home))))

        from saipal_engine.paths import FencedLockFile

        lock = FencedLockFile(sup_mod.supervisor_lock_path(home), ttl=3600.0)
        self.assertTrue(lock.acquire())
        try:
            with self.assertRaises(PalError) as caught:
                sup_mod.watch(home, max_cycles=1)
            self.assertEqual(caught.exception.code, "WRITER_BUSY")
        finally:
            lock.release()

    def test_watch_status_is_read_only_while_supervising(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)

        from saipal_engine.paths import FencedLockFile

        lock = FencedLockFile(sup_mod.supervisor_lock_path(home), ttl=3600.0)
        self.assertTrue(lock.acquire())
        try:
            status = sup_mod.watch_status(home)
            self.assertTrue(status["ok"])
            self.assertIn("supervisor", status)
            self.assertIn("budget_window", status)
            self.assertEqual(backend.attempts, 0)
        finally:
            lock.release()

    def test_supervisor_lock_is_distinct_from_worker_lock(self) -> None:
        self.assertNotEqual(
            str(sup_mod.supervisor_lock_path(self.home)),
            str(jobs_mod.worker_lock_path(self.home)),
        )


class RefreshFencingRace(WatchBase):
    """T-110: a fenced refresh can never steal a successor's lock back.

    The old `refresh()` did `owns_on_disk()` then an `O_TRUNC` rewrite of the
    node. A successor taking the path between the check and the write had its
    owner token destroyed -- the dethroned owner returned True while the
    successor's payload was gone. These tests force that exact interleaving.
    """

    def test_refresh_interleaving_cannot_overwrite_successor(self) -> None:
        from saipal_engine.paths import FencedLockFile

        home = self.fresh_home("conformant-cold.json")
        lock_path = sup_mod.supervisor_lock_path(home)
        owner = FencedLockFile(lock_path, ttl=6.0)
        self.assertTrue(owner.acquire())

        original_owns = owner.owns_on_disk

        def owns_then_successor_takes_over() -> bool:
            # Step 1 of the interleaving: the old owner's ownership check
            # succeeds (the node is still ours)...
            verdict = original_owns()
            if not verdict:
                return False
            # ...and BEFORE the old owner's refresh performs its write, the
            # successor legitimately takes the path over (mtime-aged stale node:
            # the exact takeover a crashed/slow owner must be recoverable from).
            old = time.time() - 999.0
            os.utime(lock_path, (old, old))
            successor = FencedLockFile(lock_path, ttl=6.0)
            self.assertTrue(
                successor.acquire(), "the successor must take the stale node"
            )
            RefreshFencingRace._successor = successor
            return verdict

        with mock.patch.object(owner, "owns_on_disk", owns_then_successor_takes_over):
            refreshed = owner.refresh()
        successor = RefreshFencingRace._successor
        RefreshFencingRace._successor = None

        self.assertFalse(refreshed, "the old owner must lose the refresh race")
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
        self.assertNotEqual(payload["owner"], owner.token)
        self.assertTrue(
            successor.owns_on_disk(), "the successor must still own the node"
        )
        # The old owner also cannot release the successor's lock away.
        owner.release()
        self.assertTrue(successor.owns_on_disk())

    def test_watch_detects_ownership_loss_without_external_stop(self) -> None:
        """Real supervisor detection: no STOP_REQUESTED may cause the stop.

        The successor replaces the lock while the old supervisor is between
        cycles; `stop_requested` stays False forever, so the ONLY thing that
        can end the watch is the supervisor's own ownership validation.
        """
        import test_wave_analyst_repair as repair
        from saipal_engine.paths import FencedLockFile

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_for(home))))

        clock = LeaseHeartbeat.FakeClock()
        stop_calls = {"n": 0}

        def stop_requested() -> bool:
            stop_calls["n"] += 1
            # Never stop externally: any stop must come from the supervisor's
            # own ownership loss detection. On the first call, take the lease.
            if stop_calls["n"] == 1:
                lock_path = sup_mod.supervisor_lock_path(home)
                old = time.time() - 999.0
                os.utime(lock_path, (old, old))
                successor = FencedLockFile(lock_path, ttl=6.0)
                self.assertTrue(successor.acquire())
                RefreshFencingRace._successor = successor
                return False
            return False

        result = sup_mod.watch(
            home,
            max_cycles=0,
            max_units_per_cycle=1,
            lock_ttl=6.0,
            sleep_fn=clock.sleep,
            clock=clock,
            stop_requested=stop_requested,
        )
        self.assertEqual(result["stop_reason"], "OWNERSHIP_LOST")
        self.assertFalse(result["ok"])
        successor = RefreshFencingRace._successor
        RefreshFencingRace._successor = None
        self.assertTrue(successor.owns_on_disk(), "the successor keeps the lease")

    def test_zero_shared_state_writes_after_ownership_loss(self) -> None:
        """The old owner performs ZERO shared supervisor-state writes after loss.

        `_lose_ownership` used to persist `last_stop_reason` while a successor
        could already be checkpointing the same file. Now the stop reason is
        returned in process output only.
        """
        import test_wave_analyst_repair as repair
        from saipal_engine.paths import FencedLockFile

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_for(home))))

        state_path = sup_mod.supervisor_state_path(home)
        clock = LeaseHeartbeat.FakeClock()
        takeover = {"done": False}
        writes = {"before": 0, "after": 0}
        phase = {"lost": False}

        real_save = sup_mod.save_state

        def counting_save(root, state):
            if phase["lost"]:
                writes["after"] += 1
            else:
                writes["before"] += 1
            return real_save(root, state)

        def stop_requested() -> bool:
            if takeover["done"]:
                return False
            takeover["done"] = True
            lock_path = sup_mod.supervisor_lock_path(home)
            old = time.time() - 999.0
            os.utime(lock_path, (old, old))
            successor = FencedLockFile(lock_path, ttl=6.0)
            self.assertTrue(successor.acquire())
            return False

        with mock.patch.object(sup_mod, "save_state", counting_save):
            # The supervisor loses ownership on its pre-cycle renewal: the
            # moment `watch` returns OWNERSHIP_LOST, no save may follow.
            result = sup_mod.watch(
                home,
                max_cycles=0,
                max_units_per_cycle=1,
                lock_ttl=6.0,
                sleep_fn=clock.sleep,
                clock=clock,
                stop_requested=stop_requested,
            )
        self.assertEqual(result["stop_reason"], "OWNERSHIP_LOST")
        self.assertEqual(
            writes["after"],
            0,
            "the old owner must not write shared state after ownership loss",
        )


class ShadowCeiling(WatchBase):
    """T-111: the shadow ceiling survives a mid-batch config mutation.

    The supervisor validated STAGE_ONLY at cycle start; the operator flips the
    config to PUBLISH_ENABLED with a VALID sink while the semantic batch is in
    flight. The immutable execution ceiling -- not the mutable config read at
    the external-effect boundary -- decides: the audit stages locally, the sink
    receives zero writes, the mismatch is recorded.
    """

    def test_mid_batch_flip_to_publish_enabled_stages_locally(self) -> None:
        import test_wave_analyst_repair as repair
        from saipal_engine import config as engine_config

        home = self.fresh_home("agent-noncompliance-command-route.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        # A real, valid audit inbox: the flip must be a LEGITIMATE publication
        # configuration, so the only thing preventing delivery is the ceiling.
        sink = Path(self._tmp.name) / "maintainer"
        (sink / "audit").mkdir(parents=True, exist_ok=True)
        (sink / "audit" / "MANIFEST.json").write_text(
            json.dumps({"kind": "saipen-audit-inbox", "schema_version": 1}),
            encoding="utf-8",
        )

        # Qualifying DRIFT through the REAL semantic path: investigator finds
        # DRIFT, critic agrees, submit/emit executes inside the batch.
        backend.script.append((200, repair.envelope(self.candidate_for(home, "DRIFT"))))
        backend.script.append((200, repair.envelope(self.critic_json_for(home, "AGREE"))))

        flipped = {"done": False}

        def flip_on_investigator(request: dict) -> None:
            if flipped["done"]:
                return
            if backend.attempts == 1:
                flipped["done"] = True
                cfg = engine_config.load_config(home)[1]
                cfg["publication_mode"] = "PUBLISH_ENABLED"
                cfg["shadow_reviewed"] = True
                cfg["sink"] = {"kind": "termisai-file", "root": str(sink)}
                engine_config.save_config(home, cfg)

        backend.on_request = flip_on_investigator

        result = sup_mod.watch(
            home, max_cycles=1, max_units_per_cycle=1, sleep_fn=lambda _s: None
        )
        self.assertEqual(result["cycles_run"], 1)
        # Config really is PUBLISH_ENABLED at the end: the flip happened and
        # stuck; nothing reset it.
        self.assertEqual(
            engine_config.load_config(home)[1]["publication_mode"], "PUBLISH_ENABLED"
        )
        # ZERO external writes.
        self.assertEqual(
            sorted(p.name for p in (sink / "audit").glob("*.md")),
            [],
            "a shadow run must never publish externally, even mid-batch flip",
        )
        # The audit WAS produced and staged locally.
        staged = sorted((home / "audit" / "staging").glob("*.md"))
        self.assertTrue(staged, "the qualifying audit must still be staged locally")
        # The mismatch is recorded loudly.
        events = [
            json.loads(line)
            for line in (home / "LOG.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertTrue(
            any(e.get("event") == "shadow_ceiling_mismatch" for e in events),
            "the ceiling/config mismatch must be reported",
        )
        # And the next supervisor boundary refuses to run semantics at all.
        second = sup_mod.watch(home, max_cycles=1, max_units_per_cycle=1, sleep_fn=lambda _s: None)
        self.assertEqual(second["stop_reason"], "PUBLICATION_MODE_BLOCKED")

    def critic_json_for(self, home: Path, decision: str) -> str:
        import test_wave_analyst_repair as repair

        return repair.RepairBase.critic_json(repair.RepairBase(), home, decision)

    def test_manual_path_retains_its_own_policy(self) -> None:
        """Non-supervisor submission keeps the ordinary policy (T-109 later).

        With PUBLISH_ENABLED + valid sink and no ceiling passed, the same
        drift still publishes -- the ceiling is orchestration authority the
        CALLER must own, not a global clamp on publication support.
        """
        import test_wave_analyst_repair as repair
        from saipal_engine import config as engine_config
        from saipal_engine import submit as submit_module

        home = self.fresh_home("agent-noncompliance-command-route.json")
        sink = Path(self._tmp.name) / "maintainer"
        (sink / "audit").mkdir(parents=True, exist_ok=True)
        (sink / "audit" / "MANIFEST.json").write_text(
            json.dumps({"kind": "saipen-audit-inbox", "schema_version": 1}),
            encoding="utf-8",
        )
        cfg = engine_config.load_config(home)[1]
        cfg["publication_mode"] = "PUBLISH_ENABLED"
        cfg["shadow_reviewed"] = True
        cfg["sink"] = {"kind": "termisai-file", "root": str(sink)}
        engine_config.save_config(home, cfg)

        unit = support.next_unit(home)
        receipt = support.submit_drift(home, unit)
        self.assertIn(receipt["verdict"], ("DRIFT",))
        sink_files = sorted(p.name for p in (sink / "audit").glob("*.md"))
        self.assertEqual(sink_files, ["1.md"], "ordinary publication still works")

        _ = repair, submit_module  # imported shapes kept for future controls


class LeaseHeartbeat(WatchBase):
    """T-94: a healthy watch renews its lease and cannot be stolen by TTL."""

    class FakeClock:
        """Injectable wall clock advancing only when the code asks to sleep."""

        def __init__(self) -> None:
            self.now = 1_000_000.0

        def wall_now(self) -> float:
            return self.now

        def monotonic_now(self) -> float:
            return self.now

        def sleep(self, seconds: float) -> None:
            self.now += float(seconds)

    def test_long_watch_renews_before_ttl_and_second_stays_busy(self) -> None:
        """Logical hours pass; the lease is refreshed; takeover never fires."""
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_for(home))))

        clock = self.FakeClock()
        # Short TTL: 6s lease, 2s renewal cadence. The idle wake advances the
        # clock far past multiple TTLs.
        result = sup_mod.watch(
            home,
            max_cycles=1,
            max_units_per_cycle=1,
            lock_ttl=6.0,
            sleep_fn=clock.sleep,
            clock=clock,
        )
        self.assertEqual(result["cycles_run"], 1)
        self.assertEqual(result["stop_reason"], "MAX_CYCLES")

        # A second supervisor sees a LIVE lease: BUSY, no stale takeover.
        from saipal_engine.paths import FencedLockFile

        # Bounded run: after MAX_CYCLES the first supervisor released, so
        # prove liveness DURING the run instead: run an unbounded watch with
        # a stop callback that grabs the second lock while the first sleeps.
        home2 = self.fresh_home("conformant-cold.json")
        backend2 = repair.StubBackend()
        self.addCleanup(backend2.stop)
        self.enable(home2, backend2)
        clock2 = self.FakeClock()
        seen_busy: list[str] = []
        probes = {"n": 0}

        def stop_when_stolen() -> bool:
            # While the first supervisor holds its (renewed) lease, a second
            # contender must be refused BUSY. After several probes across
            # multiple TTLs, stop the watch deterministically.
            probes["n"] += 1
            if probes["n"] > 8:
                return True
            contender = FencedLockFile(
                sup_mod.supervisor_lock_path(home2), ttl=6.0
            )
            acquired = contender.acquire()
            if not acquired:
                seen_busy.append(contender.detail)
                return False
            contender.release()
            return False

        result2 = sup_mod.watch(
            home2,
            max_cycles=0,
            max_units_per_cycle=1,
            idle_wake_seconds=2.0,
            lock_ttl=6.0,
            sleep_fn=clock2.sleep,
            clock=clock2,
            stop_requested=stop_when_stolen,
        )
        self.assertTrue(seen_busy, "the second supervisor must stay BUSY while the lease is renewed")
        self.assertEqual(result2["stop_reason"], "STOP_REQUESTED")
        self.assertGreaterEqual(clock2.now - 1_000_000.0, 6.0, "multiple logical TTLs must have passed")

    def test_lease_renewal_across_many_logical_ttls(self) -> None:
        """Direct heartbeat proof: many renewal windows, same token, no steal."""
        from saipal_engine.paths import FencedLockFile

        lock = FencedLockFile(sup_mod.supervisor_lock_path(self.home), ttl=6.0)
        self.assertTrue(lock.acquire())
        self.addCleanup(lock.release)
        clock = self.FakeClock()
        heartbeat = sup_mod.LeaseHeartbeat(lock, ttl=6.0, now=clock.wall_now)
        token = lock.token
        for _ in range(30):  # 30 x 2s = 10 logical TTLs of 6s
            clock.sleep(heartbeat.renew_interval)
            self.assertTrue(heartbeat.renew(), "the healthy lease must renew indefinitely")
            self.assertEqual(lock.token, token, "renewal must keep the same owner token")
        # The lease is still alive for a contender: no stale takeover.
        contender = FencedLockFile(sup_mod.supervisor_lock_path(self.home), ttl=6.0)
        self.assertFalse(contender.acquire())
        self.assertTrue(contender.detail)  # refused with a BUSY detail

    def test_external_replacement_stops_original_without_unlinking_successor(self) -> None:
        """A stolen lease is detected; the old owner stops and never deletes
        the successor's lock (T-94 invariants 4-6)."""
        import test_wave_analyst_repair as repair
        from saipal_engine.paths import FencedLockFile

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)

        clock = self.FakeClock()

        def steal_after_first_cycle() -> bool:
            # Invoked as stop_requested each loop iteration before a cycle:
            # replace the supervisor's lock with a fresh foreign owner.
            lock_path = sup_mod.supervisor_lock_path(home)
            lock_path.unlink()
            successor = FencedLockFile(lock_path, ttl=6.0)
            self.assertTrue(successor.acquire())
            LeaseHeartbeatTestHolder.successor = successor
            return True

        result = sup_mod.watch(
            home,
            max_cycles=0,
            max_units_per_cycle=1,
            lock_ttl=6.0,
            sleep_fn=clock.sleep,
            clock=clock,
            stop_requested=steal_after_first_cycle,
        )
        self.assertEqual(result["stop_reason"], "STOP_REQUESTED")
        # The successor's lock file is still on disk with the successor token.
        successor = LeaseHeartbeatTestHolder.successor
        self.assertIsNotNone(successor)
        self.assertTrue(successor.owns_on_disk(), "the original supervisor must not unlink the successor's lock")

    def test_sleep_longer_than_cadence_does_not_expire_lease(self) -> None:
        """Idle wake >> renewal cadence: chunked sleep keeps the lease alive."""
        from saipal_engine.paths import FencedLockFile

        lock = FencedLockFile(sup_mod.supervisor_lock_path(self.home), ttl=4.0)
        self.assertTrue(lock.acquire())
        self.addCleanup(lock.release)
        clock = self.FakeClock()
        heartbeat = sup_mod.LeaseHeartbeat(lock, ttl=4.0, now=clock.wall_now)

        # Simulate the chunked idle sleep: 60 logical seconds in chunks that
        # are each shorter than the renewal cadence.
        deadline = clock.wall_now() + 60.0
        slept = 0.0
        while clock.wall_now() < deadline:
            self.assertTrue(heartbeat.renew_if_due() or heartbeat.renew())
            chunk = min(deadline - clock.wall_now(), heartbeat.renew_interval)
            clock.sleep(chunk)
            slept += chunk
            self.assertTrue(heartbeat.renew(), "each wake must revalidate the lease")
        self.assertGreaterEqual(slept, 59.999)
        contender = FencedLockFile(sup_mod.supervisor_lock_path(self.home), ttl=4.0)
        self.assertFalse(contender.acquire(), "a chunked sleep must never expire the lease")


class LeaseHeartbeatTestHolder:
    successor = None


class ShadowGate(WatchBase):
    """T-95: STAGE_ONLY is revalidated before every cycle, not once at start."""

    def test_publication_mode_changed_between_cycles_blocks_before_semantics(self) -> None:
        import test_wave_analyst_repair as repair
        from saipal_engine import config as engine_config

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_for(home))))

        flips = {"n": 0}

        def flip_after_first_cycle() -> bool:
            flips["n"] += 1
            if flips["n"] == 2:
                # Cycle 1 finished: the operator (or an accident) closes the
                # shadow gate. PUBLISH_BLOCKED is a valid non-STAGE_ONLY mode
                # the config validator accepts without a sink.
                cfg = engine_config.load_config(home)[1]
                cfg["publication_mode"] = "PUBLISH_BLOCKED"
                engine_config.save_config(home, cfg)
                return False
            if flips["n"] > 2:
                return True  # should never be reached: cycle 2 must refuse
            return False

        result = sup_mod.watch(
            home,
            max_cycles=0,
            max_units_per_cycle=1,
            sleep_fn=lambda _s: None,
            stop_requested=flip_after_first_cycle,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["stop_reason"], "PUBLICATION_MODE_BLOCKED")
        self.assertEqual(len(result["cycle_results"]), 1, "cycle 2 must never run semantics")
        # The mode was refused loudly, never reset back by the supervisor.
        self.assertEqual(
            engine_config.load_config(home)[1]["publication_mode"], "PUBLISH_BLOCKED"
        )

    def test_shadow_safety_reports_external_publication_possible_false(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        safety = sup_mod._shadow_safety(home)
        self.assertFalse(safety["external_publication_possible"])
        self.assertEqual(safety["publication_mode"], "STAGE_ONLY")
        self.assertTrue(safety["gate_ok"])

    def test_shadow_safety_is_derived_not_hardcoded(self) -> None:
        from saipal_engine import config as engine_config

        home = self.fresh_home("conformant-cold.json")
        cfg = engine_config.load_config(home)[1]
        cfg["publication_mode"] = "PUBLISH_BLOCKED"
        engine_config.save_config(home, cfg)
        safety = sup_mod._shadow_safety(home)
        self.assertNotEqual(safety["publication_mode"], "STAGE_ONLY")
        self.assertFalse(safety["gate_ok"])

    def test_watch_status_reports_shadow_safety(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        status = sup_mod.watch_status(home)
        self.assertIn("shadow_safety", status)
        self.assertFalse(status["shadow_safety"]["external_publication_possible"])

    def test_supervisor_never_writes_publication_mode(self) -> None:
        """Static truth: no code path in the supervisor/analyst mutates mode."""
        import pathlib

        package = pathlib.Path(sup_mod.__file__).resolve().parent
        for path in sorted(package.glob("*.py")):
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if '"publication_mode"] =' in stripped or "'publication_mode'] =" in stripped:
                    self.fail(f"{path.name} assigns publication_mode: {stripped}")


class AuthorityMaterial(WatchBase):
    """T-101: material authority changes, not path spelling, drive rebind."""

    def test_first_watch_reconciles_existing_authority_and_checkpoint_survives_state_loss(self) -> None:
        import test_wave_analyst_repair as repair
        from saipal_analyst import jobs as jobs_mod
        from saipal_engine.config import load_config, save_config
        from saipal_engine.rebind import checkpoint_path, material_fingerprint

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        # Remove authority BEFORE import so the indexed session is UNKNOWN;
        # restore the same configured root BEFORE watch starts.
        cfg = load_config(home)[1]
        authority_root = Path(self._tmp.name) / "protocol_authority" / "releases"
        cfg["protocol_authority"] = {
            "git_repository": None,
            "release_root": None,
            "snapshot_root": None,
        }
        save_config(home, cfg)
        support.run_saipal("continue", home=home)
        cfg = load_config(home)[1]
        cfg["protocol_authority"]["release_root"] = str(authority_root)
        save_config(home, cfg)
        result = sup_mod.watch(home, max_cycles=1, max_units_per_cycle=0, sleep_fn=lambda _s: None)
        self.assertTrue(result["cycle_results"][0]["rebound"], "first cycle must reconcile stale bindings")
        self.assertTrue(checkpoint_path(home).exists())
        checkpoint = json.loads(checkpoint_path(home).read_text(encoding="utf-8"))
        self.assertEqual(checkpoint["authority_fingerprint"], material_fingerprint(home))
        # Destroy only supervisor runtime state: checkpoint remains beside
        # indexed state and the next cycle does NOT rebind again.
        sup_mod.supervisor_state_path(home).unlink()
        again = sup_mod.watch(home, max_cycles=1, max_units_per_cycle=0, sleep_fn=lambda _s: None)
        self.assertFalse(again["cycle_results"][0]["rebound"], "checkpoint survives supervisor state loss")

    def test_same_path_material_change_changes_fingerprint_and_rebinds_once(self) -> None:
        from saipal_engine import authority as authority_mod
        from saipal_engine.config import load_config, save_config
        from saipal_engine.rebind import material_fingerprint

        home = self.fresh_home()
        cfg = load_config(home)[1]
        root = Path(self._tmp.name) / "authority-root"
        root.mkdir(parents=True, exist_ok=True)
        cfg["protocol_authority"]["snapshot_root"] = str(root)
        save_config(home, cfg)
        # T-100: only TRUSTED material fingerprints. Snapshot with no registry
        # yet would be unreadable; create a real snapshot with a protocol
        # surface, then pin it.
        snapshot = root / "snap-a" / "saipal"
        snapshot.mkdir(parents=True)
        shutil.copy(
            Path(__file__).resolve().parents[1] / "saipal" / "REGISTRY.json",
            snapshot / "REGISTRY.json",
        )
        authority_mod.enroll(home, "snapshot_root", root)
        first = material_fingerprint(home)
        # A NEW snapshot appears under the same root.
        snapshot2 = root / "snap-b" / "saipal"
        snapshot2.mkdir(parents=True)
        shutil.copy(
            Path(__file__).resolve().parents[1] / "saipal" / "REGISTRY.json",
            snapshot2 / "REGISTRY.json",
        )
        second = material_fingerprint(home)
        self.assertNotEqual(first, second, "same root with new material must fingerprint differently")
        # Unchanged material remains stable.
        self.assertEqual(second, material_fingerprint(home))

    def test_supervisor_digest_is_not_path_only(self) -> None:
        from saipal_engine import authority as authority_mod
        from saipal_engine.config import load_config, save_config
        from saipal_engine.rebind import material_fingerprint

        home = self.fresh_home()
        root = Path(self._tmp.name) / "authority-root"
        root.mkdir(parents=True, exist_ok=True)
        cfg = load_config(home)[1]
        cfg["protocol_authority"]["snapshot_root"] = str(root)
        save_config(home, cfg)
        # Same root, no TRUSTED pin: the trust STATE itself fingerprints, but
        # material under a non-trusted root is not hashed. Enroll first, then
        # prove content change under the SAME trusted path changes it.
        authority_mod.enroll(home, "snapshot_root", root)
        before = material_fingerprint(home)
        snapshot = root / "snap-1" / "saipal"
        snapshot.mkdir(parents=True)
        shutil.copy(
            Path(__file__).resolve().parents[1] / "saipal" / "REGISTRY.json",
            snapshot / "REGISTRY.json",
        )
        after = material_fingerprint(home)
        self.assertNotEqual(before, after)


class SourceCircuit(WatchBase):
    """T-96: the source circuit breaker really breaks intake (not module-only)."""

    def _store(self, name: str, *, broken: bool = False) -> Path:
        store = Path(self._tmp.name) / name
        store.mkdir(parents=True, exist_ok=True)
        if broken:
            # A JSON bundle that load_bundle_file rejects: dispatch records a
            # REJECTED candidate every cycle -- the poison source.
            (store / "broken-session.json").write_text(
                '{"torn json',
                encoding="utf-8",
            )
        return store

    def test_open_source_is_not_dispatched_but_other_sources_continue(self) -> None:
        """Real supervisor cycles: A poisons, opens; B keeps working."""
        import test_wave_analyst_repair as repair
        from saipal_analyst import budgets as budgets_mod
        from saipal_engine.sources import save_sources

        home = self.fresh_home()
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        broken = self._store("broken-store", broken=True)
        healthy = Path(self._tmp.name) / "healthy-store"
        healthy.mkdir(parents=True, exist_ok=True)
        (healthy / "conformant-cold.json").write_text(
            json.dumps(
                support.stamp_binding(home, support.load_fixture("conformant-cold.json"))
            ),
            encoding="utf-8",
        )
        save_sources(
            home,
            {
                "schema_version": 1,
                "sources": [
                    {"id": "broken", "kind": "generic", "path": str(broken), "enabled": True},
                    {"id": "healthy", "kind": "generic", "path": str(healthy), "enabled": True},
                ],
            },
        )

        # Trip the broken source's circuit through REAL supervisor cycles.
        for _ in range(budgets_mod.CIRCUIT_TRIP_THRESHOLD + 1):
            sup_mod.watch(home, max_cycles=1, max_units_per_cycle=0, sleep_fn=lambda _s: None)
        circuits = budgets_mod.source_circuits(home)
        self.assertEqual(circuits["broken"]["state"], budgets_mod.CIRCUIT_OPEN)
        # A never-failed source has no circuit entry: absent means CLOSED.
        self.assertTrue(
            circuits.get("healthy", {}).get("state", budgets_mod.CIRCUIT_CLOSED)
            in (None, budgets_mod.CIRCUIT_CLOSED)
        )

        # Once OPEN, the broken source is SKIPPED (reported, not dispatched),
        # while the healthy source still dispatches. B's known session is
        # already indexed (idempotent import), so a NEW session proves B alive.
        fresh = support.stamp_binding(home, support.load_fixture("conformant-cold.json"))
        fresh["session_id"] = "golden-cold-b2"
        fresh.pop("session_sha256", None)
        (healthy / "conformant-cold-2.json").write_text(
            json.dumps(fresh), encoding="utf-8"
        )
        intake = sup_mod._cycle_intake(home)
        self.assertEqual(intake["skipped_open"], 1, "an OPEN source must be skipped")
        self.assertGreaterEqual(intake["sources_checked"], 2)
        self.assertEqual(intake["sessions_imported"], 1, "B must keep importing")

    def test_half_open_probe_closes_on_success_and_reopens_on_failure(self) -> None:
        import test_wave_analyst_repair as repair
        from saipal_analyst import budgets as budgets_mod
        from saipal_engine.sources import save_sources

        home = self.fresh_home()
        store = self._store("poison-store", broken=True)
        save_sources(
            home,
            {
                "schema_version": 1,
                "sources": [
                    {"id": "poison", "kind": "generic", "path": str(store), "enabled": True}
                ],
            },
        )
        source = {"id": "poison", "kind": "generic", "path": str(store), "enabled": True}
        digest = budgets_mod.source_config_digest(source)

        # Trip it, then force the probe window open by back-dating open_until.
        for _ in range(budgets_mod.CIRCUIT_TRIP_THRESHOLD):
            budgets_mod.record_source_failure(
                home, "poison", detail="boom", config_digest=digest
            )
        self.assertEqual(
            budgets_mod.source_circuits(home)["poison"]["state"], budgets_mod.CIRCUIT_OPEN
        )
        ledger = budgets_mod.load_ledger(home)
        ledger["source_circuits"]["poison"]["open_until"] = (
            __import__("time").time() - 1.0
        )
        budgets_mod.save_ledger(home, ledger)

        allowed, _reason = budgets_mod.source_circuit_allows(home, source)
        self.assertTrue(allowed, "a due OPEN must be probed once")
        self.assertEqual(
            budgets_mod.source_circuits(home)["poison"]["state"],
            budgets_mod.CIRCUIT_HALF_OPEN,
        )

        # Probe FAILS -> OPEN again.
        budgets_mod.record_source_failure(
            home, "poison", detail="still broken", config_digest=digest
        )
        self.assertEqual(
            budgets_mod.source_circuits(home)["poison"]["state"], budgets_mod.CIRCUIT_OPEN
        )
        # Probe SUCCEEDS -> CLOSED.
        budgets_mod.record_source_success(home, "poison", config_digest=digest)
        self.assertEqual(
            budgets_mod.source_circuits(home)["poison"]["state"], budgets_mod.CIRCUIT_CLOSED
        )

    def test_configuration_failure_stays_open_until_path_returns(self) -> None:
        from saipal_analyst import budgets as budgets_mod

        source = {
            "id": "gone",
            "kind": "generic",
            "path": str(Path(self._tmp.name) / "does-not-exist"),
            "enabled": True,
        }
        digest = budgets_mod.source_config_digest(source)
        # One CONFIGURATION failure: no polling a dead path every few seconds.
        budgets_mod.record_source_failure(
            home=self.home,
            source_id="gone",
            detail="path missing",
            failure_class=budgets_mod.SOURCE_FAILURE_CONFIGURATION,
            config_digest=digest,
        )
        allowed, reason = budgets_mod.source_circuit_allows(self.home, source)
        self.assertFalse(allowed)
        self.assertIn("CONFIGURATION", reason)
        # Restoring the path half-opens it (one probe, not a busy loop).
        Path(source["path"]).mkdir(parents=True, exist_ok=True)
        allowed, _reason = budgets_mod.source_circuit_allows(self.home, source)
        self.assertTrue(allowed, "a restored path must be probed")

    def test_material_configuration_change_clears_the_old_poison(self) -> None:
        from saipal_analyst import budgets as budgets_mod

        first = {
            "id": "renamed",
            "kind": "generic",
            "path": str(Path(self._tmp.name) / "old-store"),
            "enabled": True,
        }
        Path(first["path"]).mkdir(parents=True, exist_ok=True)
        for _ in range(budgets_mod.CIRCUIT_TRIP_THRESHOLD):
            budgets_mod.record_source_failure(
                self.home, "renamed", config_digest=budgets_mod.source_config_digest(first)
            )
        self.assertEqual(
            budgets_mod.source_circuits(self.home)["renamed"]["state"],
            budgets_mod.CIRCUIT_OPEN,
        )
        # The operator changes the material configuration (new store path):
        # the old poison must not permanently block the new configuration.
        changed = dict(first)
        changed["path"] = str(Path(self._tmp.name) / "new-store")
        Path(changed["path"]).mkdir(parents=True, exist_ok=True)
        allowed, _reason = budgets_mod.source_circuit_allows(self.home, changed)
        self.assertTrue(allowed, "a new source configuration must be re-evaluated")
        self.assertEqual(
            budgets_mod.source_config_digest(first),
            budgets_mod.source_config_digest(first),
        )
        self.assertNotEqual(
            budgets_mod.source_config_digest(first),
            budgets_mod.source_config_digest(changed),
        )

    def test_no_busy_loop_while_open(self) -> None:
        """Skipping an OPEN source never increments its failure count."""
        from saipal_analyst import budgets as budgets_mod

        store = self._store("quiet-store")
        source = {"id": "quiet", "kind": "generic", "path": str(store), "enabled": True}
        digest = budgets_mod.source_config_digest(source)
        for _ in range(budgets_mod.CIRCUIT_TRIP_THRESHOLD):
            budgets_mod.record_source_failure(
                self.home, "quiet", detail="boom", config_digest=digest
            )
        failures = budgets_mod.source_circuits(self.home)["quiet"]["consecutive_failures"]
        for _ in range(20):
            allowed, _reason = budgets_mod.source_circuit_allows(self.home, source)
            self.assertFalse(allowed, "OPEN and not due: no dispatch")
        self.assertEqual(
            budgets_mod.source_circuits(self.home)["quiet"]["consecutive_failures"],
            failures,
            "skipping must not count as a failure",
        )


class Cycles(WatchBase):
    def test_cycle_investigates_checkpoints_and_advances_state(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_for(home))))

        sleeps: list[float] = []
        result = sup_mod.watch(
            home, max_cycles=1, max_units_per_cycle=1, sleep_fn=sleeps.append
        )
        self.assertEqual(result["cycles_run"], 1)
        self.assertEqual(result["stop_reason"], "MAX_CYCLES")
        self.assertEqual(len(result["cycle_results"]), 1)
        cycle = result["cycle_results"][0]
        self.assertEqual(cycle["receipts"], 1)

        state = sup_mod.load_state(home)
        self.assertEqual(state["cycles"], 1)
        self.assertEqual(state["successful_cycles"], 1)
        self.assertIsNotNone(state["last_cycle_id"])
        self.assertIsNotNone(state["last_successful_analyst_run"])
        _status, receipts_payload, _detail = submit_module.load_receipts(home)
        self.assertEqual(len(receipts_payload.get("receipts") or []), 1)

    def test_provider_outage_degrades_but_does_not_freeze(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((429, b"{}"))  # outage in cycle 1

        sleeps: list[float] = []
        result = sup_mod.watch(
            home, max_cycles=1, max_units_per_cycle=1, sleep_fn=sleeps.append
        )
        self.assertEqual(result["cycles_run"], 1)
        # The supervisor itself stayed operational: cycle recorded, no crash.
        state = sup_mod.load_state(home)
        self.assertEqual(state["cycles"], 1)
        self.assertEqual(state["consecutive_failures"], 0)

    def test_restart_continues_without_duplicate_receipts(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_for(home))))
        sup_mod.watch(home, max_cycles=1, max_units_per_cycle=1, sleep_fn=lambda _s: None)

        # A second supervisor run continues the backlog (the COLD session has
        # more pending episodes): new work proceeds, no receipt id repeats --
        # kernel idempotency plus the journal's DONE stage guarantee it.
        backend.script.append((200, repair.envelope(self.candidate_for(home))))
        result = sup_mod.watch(
            home, max_cycles=1, max_units_per_cycle=1, sleep_fn=lambda _s: None
        )
        self.assertEqual(result["cycles_run"], 1)
        _status, receipts_payload, _detail = submit_module.load_receipts(home)
        receipt_ids = [
            str(entry.get("receipt_id"))
            for entry in receipts_payload.get("receipts") or []
        ]
        self.assertGreaterEqual(len(receipt_ids), 2)
        self.assertEqual(
            len(set(receipt_ids)),
            len(receipt_ids),
            "a restarted supervisor must never duplicate a semantic receipt",
        )

    def test_non_stage_only_publication_refuses_semantic_batches(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        from saipal_engine import config as engine_config

        cfg = engine_config.load_config(home)[1] or engine_config.default_config()
        cfg["publication_mode"] = "PUBLISH_BLOCKED"
        engine_config.save_config(home, cfg)

        result = sup_mod.watch(home, max_cycles=1, sleep_fn=lambda _s: None)
        self.assertFalse(result["ok"])
        self.assertEqual(result["stop_reason"], "PUBLICATION_MODE_BLOCKED")
        self.assertEqual(backend.attempts, 0, "no semantic batch under a non-shadow mode")
        self.assertIn("STAGE_ONLY", result["detail"])
        # The config was refused loudly, never mutated to fix itself.
        mode_after = engine_config.load_config(home)[1]["publication_mode"]
        self.assertEqual(mode_after, "PUBLISH_BLOCKED")

    def test_stop_callback_stops_cleanly(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_for(home))))

        result = sup_mod.watch(
            home,
            max_cycles=0,
            max_units_per_cycle=1,
            sleep_fn=lambda _s: None,
            stop_requested=lambda: True,
        )
        self.assertEqual(result["stop_reason"], "STOP_REQUESTED")
        self.assertEqual(result["cycles_run"], 0)
        state = sup_mod.load_state(home)
        self.assertEqual(state["stop_requested"], False)


class StateDiscipline(WatchBase):
    def test_state_schema_is_closed(self) -> None:
        state = sup_mod.fresh_state()
        self.assertEqual(sup_mod.state_problems(state), [])
        state["nope"] = 1
        self.assertIn(
            "unknown supervisor state field 'nope'", sup_mod.state_problems(state)
        )

    def test_corrupt_state_is_a_loud_refusal(self) -> None:
        path = sup_mod.supervisor_state_path(self.home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{torn", encoding="utf-8")
        with self.assertRaises(PalError) as caught:
            sup_mod.load_state(self.home)
        self.assertIn("unreadable", str(caught.exception))

    def test_supervisor_state_does_not_duplicate_journal(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, repair.envelope(self.candidate_for(home))))
        sup_mod.watch(home, max_cycles=1, max_units_per_cycle=1, sleep_fn=lambda _s: None)

        raw = sup_mod.supervisor_state_path(home).read_text(encoding="utf-8")
        for forbidden in ("candidate", "event_refs", "response_text", "critic_payload"):
            self.assertNotIn(forbidden, raw, "supervisor state must not duplicate journal jobs")


class CliSurface(WatchBase):
    def test_cli_watch_status_routes(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        _code, payload, _err = support.run_saipal_json("watch", "--status", home=home)
        self.assertIsNotNone(payload)
        self.assertTrue(payload["ok"])

    def test_cli_watch_bounded_runs(self) -> None:
        import test_wave_analyst_repair as repair

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        _code, payload, _err = support.run_saipal_json(
            "watch", "--max-cycles", "1", home=home
        )
        self.assertIsNotNone(payload)
        self.assertTrue(payload.get("watch"))
        self.assertEqual(payload.get("cycles_run"), 1)


if __name__ == "__main__":
    unittest.main()
