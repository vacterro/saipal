"""T-135: `/goal cpall` — the durable autonomous convergence objective.

The contract under test is orchestration, not a bigger loop:

* the objective survives process death, restart and context exhaustion;
* a budget is a checkpoint boundary, never a goal boundary;
* a `CONFLICT` isolates ONE work item instead of freezing the universe;
* a backend outage is a durable `WAITING` with a retry, never a silent done;
* duplicate `/goal cpall` attaches, it does not start a second worker;
* cancellation is explicit and preserves every completed unit;
* `conflicts:` has exactly one canonical meaning on every surface.

Long-duration behaviour is proved by simulation, never by waiting: the virtual
clock, the injected work view and the injected slices make "seven days",
"thousands of slices" and "backend down for three hours" deterministic.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import cpall
from saipal_engine import carrier as carrier_mod
from saipal_engine import sessions as sessions_mod
from saipal_engine.registry import load_registry

HOT = "hot-partial.json"
HOT_MUTATED = "hot-prefix-mutated.json"


class VirtualClock:
    """Logical time: seven simulated days cost no real seconds."""

    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.t = float(start)
        self.slept = 0.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        seconds = max(0.0, float(seconds))
        self.slept += seconds
        self.sleeps.append(seconds)
        self.t += seconds

    def advance(self, seconds: float) -> None:
        self.t += float(seconds)


class Sim:
    """A synthetic, bounded work graph plus the two slice callables.

    Only the *work* is synthetic. Everything under test -- the durable
    objective, the state machine, conflict isolation, retry scheduling, report
    cadence, budget chaining, restart resume -- is the real supervisor.
    """

    def __init__(
        self,
        *,
        units: int = 0,
        conflicts: list[dict] | None = None,
        units_per_slice: int = 5,
        sessions: int = 1,
    ) -> None:
        self.discovered = int(units)
        self.completed = 0
        self.conflict_units = 0
        self.conflict_rows = list(conflicts or [])
        self.units_per_slice = int(units_per_slice)
        self.sessions_total = int(sessions)
        self.sessions_completed = 0
        self.mechanical_pending = 0
        self.intake_idle = True
        self.mechanical_calls = 0
        self.semantic_calls = 0
        self.view_calls = 0
        self.backend_available = True
        self.rate_limited_slices = 0
        self.failures: list[str] = []
        self.crash_after_submit = False
        self.new_units_added = 0
        self.accepted_receipts: list[str] = []

    # -- the durable work view -------------------------------------------- #

    def view(self, home: Path) -> dict:
        self.view_calls += 1
        eligible = max(
            0,
            self.discovered - self.completed - self.conflict_units,
        )
        return {
            "ok": True,
            "sessions_total": self.sessions_total,
            "sessions_completed": self.sessions_completed,
            "units_discovered": self.discovered,
            "units_completed": self.completed,
            "units_remaining": max(0, self.discovered - self.completed),
            "units_eligible_remaining": eligible,
            "units_conflict": self.conflict_units,
            "conflicts_current": len(self.conflict_rows),
            "conflicts_indexed": len(self.conflict_rows),
            "conflicts_superseded": 0,
            "conflict_rows": list(self.conflict_rows),
            "mechanical_pending": self.mechanical_pending,
            "staged_audits": self.mechanical_pending,
            "inbox_files": 0,
            "source_fingerprint": f"sim-{self.discovered}-{self.completed}",
        }

    # -- the two bounded slices -------------------------------------------- #

    def mechanical(self, home: Path) -> dict:
        self.mechanical_calls += 1
        new_sessions = self.import_once(home)
        idle = self.intake_idle and not new_sessions
        return {
            "ok": True,
            "idle": idle,
            "intake_idle": idle,
            "work_remaining": False,
            "budget_hit": False,
            "sessions_indexed": new_sessions,
            "sessions_analyzed": new_sessions,
            "events_analyzed": 0,
            "candidates": 0,
            "audits_emitted": 0,
            "next_action": "simulated mechanical cycle",
        }

    def import_once(self, home: Path) -> int:
        """Import anything staged under `_new_units`, once, like real intake."""
        marker = Path(home) / "_new_units"
        if not marker.is_file():
            return 0
        try:
            added = int(marker.read_text(encoding="utf-8").strip() or "0")
        except ValueError:
            added = 0
        marker.unlink()
        self.discovered += added
        self.new_units_added += added
        return 1 if added else 0

    def stage_new_units(self, home: Path, count: int) -> None:
        (Path(home) / "_new_units").write_text(str(int(count)), encoding="utf-8")

    def semantic(self, home: Path) -> dict:
        self.semantic_calls += 1
        if not self.backend_available:
            self.failures.append("connection refused by 127.0.0.1:11434")
            return {
                "ok": False,
                "stop_reason": "ERROR",
                "units": 0,
                "errors": [{"message": "connection refused by 127.0.0.1:11434"}],
                "backend": {"route": "local", "model": "qwen3.5:9b", "ok": False},
            }
        if self.rate_limited_slices > 0:
            self.rate_limited_slices -= 1
            self.failures.append("429 too many requests")
            return {
                "ok": True,
                "stop_reason": "RATE_LIMITED",
                "units": 0,
                "rate_limited": 1,
                "backend": {"route": "local", "model": "qwen3.5:9b", "ok": True},
            }
        remaining = max(0, self.discovered - self.completed - self.conflict_units)
        produced = min(self.units_per_slice, remaining)
        first = self.completed
        self.completed += produced
        for index in range(first + 1, self.completed + 1):
            self.accepted_receipts.append(f"unit-{index}")
        return {
            "ok": True,
            "stop_reason": "BUDGET" if produced else "IDLE",
            "jobs_completed": produced,
            "units": produced,
            "backend": {"route": "local", "model": "qwen3.5:9b", "ok": True},
        }


class CpallCase(unittest.TestCase):
    """Shared home/objective plumbing."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        self.registry = load_registry()
        self.settings = cpall.settings_from_registry(self.registry)

    def objective(self) -> dict:
        status, payload, detail = cpall.load_objective(self.home)
        assert status == "ok", detail
        return payload

    def run_cpall(self, sim: Sim, *, clock: VirtualClock | None = None,
                  max_slices: int = 0, settings: dict | None = None, **kwargs) -> dict:
        merged = dict(self.settings)
        merged.update(settings or {})
        return cpall.run(
            self.home,
            mechanical_slice=sim.mechanical,
            semantic_slice=sim.semantic,
            registry=self.registry,
            settings=merged,
            clock=clock or VirtualClock(),
            max_slices=max_slices,
            backlog_fn=sim.view,
            **kwargs,
        )


# --------------------------------------------------------------------------- #
# command routing
# --------------------------------------------------------------------------- #


class CommandRouting(unittest.TestCase):
    """`/goal cpall` is a real canonical command; nothing else moves."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def test_slash_goal_cpall_is_recognised(self) -> None:
        code, payload, err = support.run_saipal_json("/goal", "cpall", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["command"], "cpall")
        self.assertEqual(payload["state"], cpall.STATE_COMPLETED)
        self.assertTrue(payload["objective_id"].startswith("cpall-"))

    def test_the_two_spellings_are_the_same_command(self) -> None:
        """`/goal cpall`, `goal cpall` and `cpall` cannot drift apart."""
        code, payload, err = support.run_saipal_json("cpall", "--status", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertFalse(payload["cpall"]["exists"])

        support.run_saipal("goal", "cpall", home=self.home)
        code, payload, err = support.run_saipal_json("cpall", "--status", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertTrue(payload["cpall"]["exists"])

    def test_duplicate_invocation_is_idempotent(self) -> None:
        """A second `/goal cpall` attaches; it never starts a second worker."""
        support.run_saipal("cpall", home=self.home)
        first = json.loads(
            (self.home / cpall.CPALL_NAME).read_text(encoding="utf-8")
        )
        # A completed objective is terminal: a new invocation opens a NEW
        # objective rather than pretending the old one is still running.
        code, payload, err = support.run_saipal_json("cpall", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertNotEqual(payload["objective_id"], first["objective_id"])

        # A LIVE objective is never duplicated.
        live = cpall.fresh_objective(started_at=1_700_000_000.0)
        cpall.claim_ownership(live, now=1_700_000_000.0,
                              settings=cpall.settings_from_registry())
        live["owner"]["pid"] = os.getpid()
        (self.home / cpall.CPALL_NAME).write_text(
            json.dumps(live), encoding="utf-8"
        )
        status, objective, _detail = cpall.load_objective(self.home)
        self.assertEqual(status, "ok")
        attach = cpall.attach_or_start(self.home, registry=load_registry(),
                                       now=1_700_000_001.0)
        self.assertTrue(attach["attached"])
        self.assertTrue(attach["resumed"])
        self.assertEqual(attach["objective_id"], objective["objective_id"])
        self.assertIn("already active", attach["detail"])

    def test_existing_commands_keep_their_bounded_semantics(self) -> None:
        """`pal` and `continue --drain` are unchanged by cpall's arrival."""
        support.put_inbox(self.home, "conformant-cold.json")
        code, payload, err = support.run_saipal_json("pal", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["command"], "continue")
        self.assertNotIn("cpall", payload)

        code, payload, err = support.run_saipal_json("continue", "--drain", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertTrue(payload["drain"])
        self.assertIn(payload["drain_outcome"], ("idle", "blocked", "safety_valve"))
        # Drain is bounded to its own process and says nothing about a goal.
        self.assertNotIn("objective_id", payload)

    def test_unknown_goal_subcommand_is_a_usage_refusal(self) -> None:
        code, out, err = support.run_saipal("/goal", "everything", home=self.home)
        self.assertEqual(code, 2, out + err)
        self.assertIn("unknown goal", err)

    def test_cpall_status_is_read_only(self) -> None:
        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        support.run_saipal("cpall", home=self.home)
        before = support.tree_digest(self.home)
        code, payload, err = support.run_saipal_json("cpall", "--status", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(support.tree_digest(self.home), before,
                         "cpall --status mutated the home")
        self.assertEqual(
            payload["cpall"]["conflicts"]["current"],
            payload["backlog"]["conflicts_current"],
        )


# --------------------------------------------------------------------------- #
# convergence and budget chaining
# --------------------------------------------------------------------------- #


class Convergence(CpallCase):
    def test_a_hundred_units_converge_without_a_manual_continue(self) -> None:
        sim = Sim(units=100, units_per_slice=25)
        summary = self.run_cpall(sim)
        self.assertEqual(summary["state"], cpall.STATE_COMPLETED)
        self.assertEqual(sim.completed, 100)
        self.assertEqual(self.objective()["units_completed"], 100)
        self.assertEqual(self.objective()["units_eligible_remaining"], 0)
        self.assertGreater(sim.semantic_calls, 1, "cpall must chain slices")
        self.assertEqual(len(set(sim.accepted_receipts)), 100,
                         "no unit may be accepted twice")

    def test_a_budget_chains_instead_of_terminating_the_goal(self) -> None:
        """37 units at 5 per slice: seven full slices plus one partial."""
        sim = Sim(units=37, units_per_slice=5)
        summary = self.run_cpall(sim)
        self.assertEqual(summary["state"], cpall.STATE_COMPLETED)
        self.assertEqual(sim.completed, 37)
        # 8 semantic passes carry the units (7 full + 1 partial), plus the
        # closing pass that observes the empty backlog.
        self.assertGreaterEqual(sim.semantic_calls, 8)
        objective = self.objective()
        self.assertEqual(objective["semantic_units_completed"], 37)
        self.assertGreater(objective["slices"], 7,
                           "each bounded slice must be its own checkpoint")

    def test_a_process_slice_budget_leaves_the_objective_resumable(self) -> None:
        """`--slices N` bounds the PROCESS, never the objective."""
        sim = Sim(units=40, units_per_slice=5)
        summary = self.run_cpall(sim, max_slices=2)
        self.assertEqual(summary["stop_reason"], "SLICE_BUDGET")
        self.assertEqual(summary["state"], cpall.STATE_ACTIVE)
        self.assertEqual(sim.completed, 10, "two bounded slices ran")
        objective = self.objective()
        self.assertEqual(objective["state"], cpall.STATE_ACTIVE)
        self.assertEqual(objective["cursor"]["semantic_units"], 10)

        resumed = self.run_cpall(sim, max_slices=100)
        self.assertEqual(resumed["state"], cpall.STATE_COMPLETED)
        self.assertEqual(sim.completed, 40)
        self.assertGreaterEqual(self.objective()["slices"], 3,
                                "a resumed objective keeps its slice history")

    def test_a_stopped_run_releases_its_lease_to_the_next_process(self) -> None:
        """A process that stopped is not an owner: the next run resumes at once.

        The lease exists to stop two LIVE workers writing into one home. A
        bounded run that hit its slice budget has stopped, so keeping the lease
        would make the next invocation attach to a dead process and refuse to
        work until the TTL lapsed -- durable only on the TTL's clock.
        """
        sim = Sim(units=20, units_per_slice=5)
        self.run_cpall(sim, max_slices=2)
        objective = self.objective()
        self.assertEqual(objective["state"], cpall.STATE_ACTIVE)
        self.assertIsNone(objective["owner"], "a bounded run releases its lease")
        brief = cpall.recover(self.home, registry=self.registry)
        self.assertTrue(brief["resumable"])
        self.assertFalse(brief["stale_owner"])

        attach = cpall.attach_or_start(self.home, registry=self.registry)
        self.assertFalse(attach["resumed"], "no live owner exists to attach to")

        resumed = self.run_cpall(sim)
        self.assertEqual(resumed["state"], cpall.STATE_COMPLETED)
        self.assertEqual(sim.completed, 20)
        self.assertEqual(self.objective()["objective_id"], objective["objective_id"])

    def test_an_empty_home_completes_in_one_slice(self) -> None:
        sim = Sim(units=0)
        summary = self.run_cpall(sim)
        self.assertEqual(summary["state"], cpall.STATE_COMPLETED)
        self.assertEqual(summary["slices"], 1)

    def test_completion_is_explained(self) -> None:
        sim = Sim(units=3, units_per_slice=5)
        self.run_cpall(sim)
        objective = self.objective()
        self.assertIn("no eligible work remains", objective["state_reason"])
        reports = cpall.load_reports(self.home)
        self.assertEqual(reports[-1]["kind"], cpall.REPORT_FINAL)
        self.assertEqual(reports[-1]["state"], cpall.STATE_COMPLETED)


# --------------------------------------------------------------------------- #
# conflict isolation
# --------------------------------------------------------------------------- #


class ConflictIsolation(CpallCase):
    @staticmethod
    def conflict_row(session_id: str, *, material: str = "a" * 8) -> dict:
        row = carrier_mod.conflict_row({
            "session_id": session_id,
            "generation": 1,
            "conflict": {
                "source_ref": f"{session_id}#raw",
                "last_analyzed_seq": 2,
                "expected_prefix_sha256": material * 4,
                "observed_prefix_sha256": ("b" * 8) * 4,
                "detected_at": "2026-09-01T00:00:00Z",
            },
        })
        return row

    def test_one_conflict_does_not_freeze_unrelated_work(self) -> None:
        sim = Sim(units=51, units_per_slice=5,
                  conflicts=[self.conflict_row("session-a")])
        sim.conflict_units = 1
        summary = self.run_cpall(sim)
        self.assertEqual(sim.completed, 50, "session B's units must all converge")
        self.assertGreater(sim.semantic_calls, 5)
        # The conflict is isolated, persisted with its material identity, and it
        # is what the run finally blocks on -- not what stopped it early.
        objective = self.objective()
        self.assertEqual(objective["state"], cpall.STATE_OPERATOR_BLOCKED)
        self.assertEqual(objective["conflicts"]["current"], 1)
        isolated = objective["conflicts"]["isolated"]
        self.assertEqual(len(isolated), 1)
        self.assertEqual(isolated[0]["session_id"], "session-a")
        self.assertEqual(isolated[0]["state"], "OPERATOR_BLOCKED")
        self.assertEqual(isolated[0]["resolvable_by"], "operator")
        self.assertTrue(isolated[0]["conflict_material_sha256"])
        self.assertEqual(isolated[0]["first_seen_at"] is not None, True)
        self.assertIn("operator", objective["state_reason"])

    def test_a_conflict_resolved_between_slices_leaves_the_set(self) -> None:
        sim = Sim(units=10, units_per_slice=5,
                  conflicts=[self.conflict_row("session-a")])
        sim.conflict_units = 1

        original = sim.semantic

        def resolving(home: Path) -> dict:
            result = original(home)
            # New evidence arrives: the operator accepted the changed prefix.
            last_marker = Path(home) / "_resolved"
            if last_marker.is_file():
                sim.conflict_rows = []
                sim.conflict_units = 0
            last_marker.write_text("1", encoding="utf-8")
            return result

        sim.semantic = resolving  # type: ignore[assignment]
        summary = self.run_cpall(sim)
        self.assertEqual(summary["state"], cpall.STATE_COMPLETED)
        objective = self.objective()
        self.assertEqual(objective["conflicts"]["current"], 0)
        self.assertEqual(objective["conflicts"]["isolated"], [])

    def test_flagging_a_superseded_generation_is_not_a_second_work_item(self) -> None:
        """The 11-vs-12 defect: `current` is the population, `indexed` history."""
        index = {
            "schema_version": 1,
            "sessions": [
                {"session_id": "s1", "generation": 1, "status": "CONFLICT",
                 "conflict": {"source_ref": "s1#1"}},
                {"session_id": "s1", "generation": 2, "status": "IMPORTED",
                 "conflict": None},
                {"session_id": "s2", "generation": 1, "status": "CONFLICT",
                 "conflict": {"source_ref": "s2#1"}},
                {"session_id": "s3", "generation": 1, "status": "IMPORTED",
                 "conflict": None},
            ],
        }
        population = carrier_mod.conflict_population(index)
        self.assertEqual(population["current_total"], 1)
        self.assertEqual(population["indexed_total"], 2)
        self.assertEqual(population["superseded_total"], 1)
        self.assertEqual([row["session_id"] for row in population["current"]], ["s2"])


class ConflictCountRegression(CpallCase):
    """One canonical conflict count, and every surface agrees on it."""

    def _conflicted_home(self) -> None:
        support.put_inbox(self.home, HOT)
        support.run_saipal("continue", home=self.home)
        status, index, detail = sessions_mod.load_index(self.home)
        self.assertEqual(status, sessions_mod.STATUS_OK, detail)
        record = next(r for r in index["sessions"] if r["session_id"] == "golden-hot-001")
        record["last_analyzed_seq"] = 2
        sessions_mod.save_index(self.home, index)
        support.clear_inbox(self.home)
        support.put_inbox(self.home, HOT_MUTATED)
        support.run_saipal("continue", home=self.home)

    def test_status_next_report_and_doctor_agree(self) -> None:
        self._conflicted_home()
        code, status, err = support.run_saipal_json("status", home=self.home)
        self.assertEqual(code, 0, err)
        code, nxt, err = support.run_saipal_json("next", home=self.home)
        self.assertEqual(code, 0, err)
        code, report, err = support.run_saipal_json("report", home=self.home)
        self.assertEqual(code, 0, err)
        code, doctor, err = support.run_saipal_json("doctor", home=self.home)
        self.assertEqual(code, 0, err)

        canonical = status["sessions_conflict_current"]
        self.assertEqual(status["sessions_conflict"], canonical,
                         "the ambiguous field must BE the canonical population")
        self.assertEqual(nxt["sessions_conflict"], canonical)
        self.assertEqual(report["sessions_conflict"], canonical)
        self.assertEqual(doctor["conflict_triage"]["conflicts_current"], canonical)
        self.assertEqual(
            status["sessions_conflict_indexed"] - status["sessions_conflict_superseded"],
            canonical,
            "indexed minus superseded must equal the canonical population",
        )

    def test_a_superseded_conflict_generation_is_named_history(self) -> None:
        """A real home where an old generation conflicted and its successor did not."""
        support.put_inbox(self.home, HOT)
        support.run_saipal("continue", home=self.home)
        status, index, _detail = sessions_mod.load_index(self.home)
        record = next(r for r in index["sessions"] if r["session_id"] == "golden-hot-001")
        record["last_analyzed_seq"] = 2
        sessions_mod.save_index(self.home, index)
        support.clear_inbox(self.home)
        support.put_inbox(self.home, HOT_MUTATED)
        support.run_saipal("continue", home=self.home)

        # A clean successor generation supersedes the conflicted one.
        status, index, _detail = sessions_mod.load_index(self.home)
        conflicted = next(r for r in index["sessions"] if r["status"] == "CONFLICT")
        successor = dict(conflicted)
        successor["generation"] = int(conflicted.get("generation") or 1) + 1
        successor["status"] = "IMPORTED"
        successor["conflict"] = None
        index["sessions"].append(successor)
        sessions_mod.save_index(self.home, index)

        code, payload, err = support.run_saipal_json("status", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["sessions_conflict_current"], 0)
        self.assertEqual(payload["sessions_conflict_indexed"], 1)
        self.assertEqual(payload["sessions_conflict_superseded"], 1)
        self.assertEqual(payload["sessions_conflict"], 0)

    def test_cpall_records_the_same_population_as_status(self) -> None:
        self._conflicted_home()
        sim = Sim(units=5, units_per_slice=5)
        sim.conflict_units = 999  # the simulated view is not the conflict truth
        code, status, _err = support.run_saipal_json("status", home=self.home)
        merged = dict(self.settings)
        summary = cpall.run(
            self.home,
            mechanical_slice=sim.mechanical,
            semantic_slice=sim.semantic,
            registry=self.registry,
            settings=merged,
            clock=VirtualClock(),
            max_slices=1,
            backlog_fn=cpall.backlog,
        )
        objective = self.objective()
        self.assertEqual(objective["conflicts"]["current"],
                         status["sessions_conflict_current"])
        self.assertEqual(objective["conflicts"]["indexed_total"],
                         status["sessions_conflict_indexed"])
        self.assertEqual(summary["conflicts"]["current"],
                         status["sessions_conflict_current"])


# --------------------------------------------------------------------------- #
# backend outage, retry and rate limits
# --------------------------------------------------------------------------- #


class BackendOutage(CpallCase):
    def test_an_outage_waits_with_a_durable_retry_then_resumes(self) -> None:
        sim = Sim(units=20, units_per_slice=5)
        sim.backend_available = False
        clock = VirtualClock()

        def recover_after_an_hour() -> bool:
            if clock.now() - 1_700_000_000.0 >= 3600.0:
                sim.backend_available = True
            return False

        settings = dict(self.settings, retry_base_seconds=60.0, retry_max_seconds=900.0)
        summary = cpall.run(
            self.home,
            mechanical_slice=sim.mechanical,
            semantic_slice=sim.semantic,
            registry=self.registry,
            settings=settings,
            clock=clock,
            stop_requested=recover_after_an_hour,
            backlog_fn=sim.view,
        )
        self.assertEqual(summary["state"], cpall.STATE_COMPLETED)
        objective = self.objective()
        self.assertGreater(objective["failures"]["transient"], 0,
                           "transient failures are counted, never erased")
        self.assertGreater(objective["retry"]["attempts"], 0)
        self.assertEqual(objective["units_completed"], 20)
        self.assertGreaterEqual(clock.slept, 3600.0,
                                "the run must have waited out the outage")

    def test_waiting_never_degrades_into_done(self) -> None:
        sim = Sim(units=20, units_per_slice=5)
        sim.backend_available = False
        clock = VirtualClock()
        merged = dict(self.settings)
        summary = cpall.run(
            self.home,
            mechanical_slice=sim.mechanical,
            semantic_slice=sim.semantic,
            registry=self.registry,
            settings=merged,
            clock=clock,
            max_slices=3,
            backlog_fn=sim.view,
        )
        self.assertNotEqual(summary["state"], cpall.STATE_COMPLETED)
        self.assertIn(summary["state"], (cpall.STATE_ACTIVE, cpall.STATE_WAITING))
        objective = self.objective()
        self.assertEqual(objective["units_completed"], 0)
        self.assertEqual(
            objective["families"][cpall.FAMILY_SEMANTIC]["state"],
            cpall.FAMILY_WAITING,
        )
        self.assertIsNotNone(objective["retry"]["next_attempt_at"])

    def test_rate_limits_back_off_instead_of_spinning(self) -> None:
        sim = Sim(units=10, units_per_slice=5)
        sim.rate_limited_slices = 2
        clock = VirtualClock()
        summary = self.run_cpall(sim, clock=clock)
        self.assertEqual(summary["state"], cpall.STATE_COMPLETED)
        objective = self.objective()
        self.assertGreater(objective["failures"]["rate_limit"], 0)
        self.assertEqual(objective["units_completed"], 10)
        self.assertGreater(clock.slept, 0.0, "a rate limit must actually wait")

    def test_backoff_is_bounded(self) -> None:
        settings = {"retry_base_seconds": 30.0, "retry_max_seconds": 1800.0}
        delays = [cpall.retry_delay(n, settings) for n in range(0, 40)]
        self.assertEqual(delays[0], 30.0)
        self.assertEqual(delays[1], 60.0)
        self.assertEqual(max(delays), 1800.0)
        self.assertTrue(all(delay <= 1800.0 for delay in delays))

    def test_failure_classification_is_closed(self) -> None:
        self.assertEqual(cpall.classify_failure(reason="Connection refused"), "TRANSIENT")
        self.assertEqual(cpall.classify_failure(reason="429 too many requests"), "RATE_LIMIT")
        self.assertEqual(cpall.classify_failure(code="CONFIG_DISABLED"), "CONFIGURATION")
        self.assertEqual(cpall.classify_failure(code="PATH_ESCAPE"), "UNSAFE")
        self.assertEqual(cpall.classify_failure(code="SOMETHING_ELSE"), "PERMANENT")


# --------------------------------------------------------------------------- #
# ownership, crash recovery and context handoff
# --------------------------------------------------------------------------- #


class CrashRecovery(CpallCase):
    def test_a_stale_owner_lease_is_recovered_automatically(self) -> None:
        sim = Sim(units=10, units_per_slice=5)
        self.run_cpall(sim, max_slices=1)
        objective = self.objective()
        # Simulate a crash: the owner process is gone and its heartbeat is old.
        # A bounded run releases its lease on exit, so the crash is modelled
        # explicitly: a foreign host cannot be probed, so its TTL decides.
        objective["owner"] = {
            "owner_id": "cpall-dead",
            "pid": 999_999_999,
            "ttl_seconds": 3600,
        }
        objective["owner"]["host"] = "some-other-host"
        objective["owner"]["heartbeat_at"] = "2000-01-01T00:00:00Z"
        objective["state"] = cpall.STATE_ACTIVE
        cpall.save_objective(self.home, objective, registry=self.registry)

        summary = self.run_cpall(sim)
        self.assertEqual(summary["state"], cpall.STATE_COMPLETED)
        recovered = self.objective()
        self.assertGreaterEqual(recovered["failures"]["stale_owner_recoveries"], 1)
        self.assertNotEqual(
            (recovered.get("owner") or {}).get("owner_id"), "cpall-dead",
            "the crashed lease must never survive the takeover",
        )
        self.assertEqual(sim.completed, 10, "no unit is skipped by a takeover")

    def test_a_dead_owner_pid_on_this_host_is_recovered_immediately(self) -> None:
        """Machine evidence beats the clock when the evidence is OURS to take.

        The TTL covers what this host cannot decide -- a foreign host's lease, or
        a PID that still answers. When the lease belongs to this host and the
        process that took it is provably gone, waiting out the rest of the hour
        is not safety: it is a durable objective refusing to continue.
        """
        import time

        sim = Sim(units=10, units_per_slice=5)
        now = time.time()
        fresh = cpall.fresh_objective(started_at=now, settings=self.settings)
        cpall.claim_ownership(fresh, now=now, settings=self.settings)
        fresh["owner"]["pid"] = 999_999_999  # a PID that cannot be alive
        fresh["state"] = cpall.STATE_ACTIVE
        cpall.save_objective(self.home, fresh, registry=self.registry)

        brief = cpall.recover(self.home, registry=self.registry)
        self.assertTrue(brief["resumable"])
        self.assertTrue(brief["stale_owner"],
                        "a dead PID makes the lease stale now, not in an hour")

        summary = self.run_cpall(sim)
        self.assertEqual(summary["state"], cpall.STATE_COMPLETED)
        self.assertEqual(sim.completed, 10, "no unit is skipped by the takeover")
        self.assertGreaterEqual(
            self.objective()["failures"]["stale_owner_recoveries"], 1
        )

    def test_an_unreadable_objective_is_refused_not_rewritten(self) -> None:
        path = self.home / cpall.CPALL_NAME
        path.write_text("{not json", encoding="utf-8")
        code, out, err = support.run_saipal("cpall", home=self.home)
        self.assertEqual(code, 1, out + err)
        self.assertIn("STATE_UNRECOVERABLE", err)
        self.assertEqual(path.read_text(encoding="utf-8"), "{not json",
                         "the unreadable objective must be left exactly as found")
        self.assertIn("by hand", err)

    def test_an_objective_with_an_unknown_field_is_refused(self) -> None:
        objective = cpall.fresh_objective(started_at=1_700_000_000.0)
        objective["surprise"] = True
        (self.home / cpall.CPALL_NAME).write_text(json.dumps(objective), encoding="utf-8")
        status, payload, detail = cpall.load_objective(self.home)
        self.assertEqual(status, "unrecoverable")
        self.assertIn("unknown field", detail)
        self.assertIsNone(payload)

    def test_cold_recovery_needs_no_chat_history(self) -> None:
        sim = Sim(units=30, units_per_slice=5)
        self.run_cpall(sim, max_slices=2)
        brief = cpall.recover(self.home, registry=self.registry)
        self.assertTrue(brief["present"])
        self.assertTrue(brief["resumable"])
        self.assertIsNotNone(brief["next_action"])
        self.assertIsNotNone(brief["objective_id"])
        self.assertIsNotNone(brief["cursor"])

        # A brand new "process" (fresh settings object, fresh clock) continues
        # the SAME objective from repository state alone.
        resumed = self.run_cpall(sim)
        self.assertEqual(resumed["state"], cpall.STATE_COMPLETED)
        self.assertEqual(resumed["objective_id"], brief["objective_id"])
        self.assertEqual(sim.completed, 30)

    def test_context_exhaustion_handoffs_do_not_change_the_outcome(self) -> None:
        """Hand off after every single unit; the result must be identical."""
        reference = Sim(units=20, units_per_slice=5)
        self.run_cpall(reference)
        reference_total = reference.completed

        # Fresh home, hand off (new process) after every slice.
        with tempfile.TemporaryDirectory() as td:
            home = support.make_home(Path(td))
            sim = Sim(units=20, units_per_slice=5)
            for _ in range(60):
                summary = cpall.run(
                    home,
                    mechanical_slice=sim.mechanical,
                    semantic_slice=sim.semantic,
                    registry=self.registry,
                    settings=self.settings,
                    clock=VirtualClock(),
                    max_slices=1,
                    backlog_fn=sim.view,
                )
                if summary["state"] in cpall.TERMINAL_STATES:
                    break
            self.assertEqual(summary["state"], cpall.STATE_COMPLETED)
            self.assertEqual(sim.completed, reference_total)
            self.assertEqual(len(set(sim.accepted_receipts)), 20,
                             "handoffs must not duplicate accepted work")

    def test_ownership_lost_stops_instead_of_writing(self) -> None:
        """A dethroned owner stops; it never writes into a stolen home."""
        sim = Sim(units=20, units_per_slice=5)
        original = sim.semantic
        calls = {"n": 0}

        def steal(home: Path) -> dict:
            calls["n"] += 1
            result = original(home)
            if calls["n"] == 2:
                # Proof that the successor took the slot: `owns` now answers
                # False for this process, exactly as it would after a real
                # lease takeover.
                real_owns = cpall.owns
                cpall.owns = lambda objective, owner_id: False  # type: ignore[assignment]
                self.addCleanup(setattr, cpall, "owns", real_owns)
            return result

        sim.semantic = steal  # type: ignore[assignment]
        summary = self.run_cpall(sim)
        self.assertFalse(summary["ok"])
        self.assertEqual(summary["stop_reason"], "OWNERSHIP_LOST")
        self.assertIn("stolen home", summary["detail"])


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #


class Reporting(CpallCase):
    def test_start_periodic_and_final_reports_exist(self) -> None:
        sim = Sim(units=100, units_per_slice=1)
        clock = VirtualClock()
        sim.semantic = Reporting._advancing(sim, clock, seconds_per_slice=600)
        self.run_cpall(sim, clock=clock)
        reports = cpall.load_reports(self.home)
        kinds = [row["kind"] for row in reports]
        self.assertEqual(kinds[0], cpall.REPORT_START)
        self.assertEqual(kinds[-1], cpall.REPORT_FINAL)
        self.assertGreater(kinds.count(cpall.REPORT_PROGRESS), 5,
                           "a long run must report periodically")

    def test_cadence_is_durable_and_configurable(self) -> None:
        sim = Sim(units=200, units_per_slice=1)
        clock = VirtualClock()
        sim.semantic = self._advancing(sim, clock, seconds_per_slice=600)
        self.run_cpall(sim, clock=clock,
                       settings={"report_cadence_seconds": 1800.0})
        reports = cpall.load_reports(self.home)
        progress = [r for r in reports if r["kind"] == cpall.REPORT_PROGRESS]
        # 200 slices at ten simulated minutes each = ~33 hours of logical time,
        # so a 30-minute cadence produces ~66 reports -- far fewer than one per
        # slice, and never a silent gap.
        self.assertGreater(len(progress), 3)
        self.assertLess(len(progress), sim.semantic_calls,
                        "reports must not be spam")

    def test_a_restart_does_not_reset_report_history(self) -> None:
        sim = Sim(units=60, units_per_slice=5)
        clock = VirtualClock()
        sim.semantic = self._advancing(sim, clock, seconds_per_slice=1200)
        self.run_cpall(sim, clock=clock, max_slices=3)
        first = cpall.load_reports(self.home)
        self.assertGreaterEqual(len(first), 1)
        sim.semantic = self._advancing(sim, clock, seconds_per_slice=2400)
        self.run_cpall(sim, clock=clock, max_slices=3)
        second = cpall.load_reports(self.home)
        self.assertGreater(len(second), len(first))
        self.assertEqual(second[0]["objective_id"], first[0]["objective_id"])
        brief = cpall.recover(self.home, registry=self.registry)
        self.assertEqual(brief["objective_id"], first[0]["objective_id"])

    def test_a_report_never_carries_secrets_or_raw_evidence(self) -> None:
        sim = Sim(units=5, units_per_slice=5)
        self.run_cpall(sim)
        raw = (self.home / cpall.CPALL_REPORTS_NAME).read_text(encoding="utf-8")
        for forbidden in ("api_key", "Bearer ", "SAIPAL_ANALYST_API_KEY"):
            self.assertNotIn(forbidden, raw)

    def test_the_rendered_report_is_readable(self) -> None:
        sim = Sim(units=5, units_per_slice=5)
        self.run_cpall(sim)
        report = cpall.load_reports(self.home)[-1]
        text = cpall.render_report_text(report)
        for expected in ("CPALL", "Runtime:", "Semantic:", "Coverage:", "Next:"):
            self.assertIn(expected, text)

    def test_a_failed_delivery_does_not_corrupt_or_stop_the_run(self) -> None:
        sim = Sim(units=10, units_per_slice=5)
        original = cpall.confined_append_line

        def broken(*args, **kwargs):
            raise OSError("disk full")

        cpall.confined_append_line = broken  # type: ignore[assignment]
        try:
            summary = self.run_cpall(sim)
        finally:
            cpall.confined_append_line = original  # type: ignore[assignment]
        self.assertEqual(summary["state"], cpall.STATE_COMPLETED)
        objective = self.objective()
        self.assertGreater(objective["reports"]["delivery_failures"], 0)
        self.assertGreater(objective["units_completed"], 0,
                           "reporting debt never stops the objective")

    @staticmethod
    def _advancing(sim: Sim, clock: VirtualClock, *, seconds_per_slice: float):
        """A slice that also advances logical time, so cadence is exercised."""
        original = sim.semantic

        def wrapper(home: Path) -> dict:
            result = original(home)
            clock.advance(seconds_per_slice)
            return result

        return wrapper


# --------------------------------------------------------------------------- #
# new evidence and cancellation
# --------------------------------------------------------------------------- #


class NewEvidence(CpallCase):
    def test_new_work_is_imported_once_and_processed_before_completion(self) -> None:
        sim = Sim(units=10, units_per_slice=5)
        original = sim.semantic
        fires = {"n": 0}

        def staging(home: Path) -> dict:
            result = original(home)
            # New evidence lands mid-objective, from outside cpall.
            if fires["n"] == 0 and sim.completed >= 5:
                sim.stage_new_units(home, 12)
                fires["n"] = 1
            return result

        sim.semantic = staging  # type: ignore[assignment]
        summary = self.run_cpall(sim, settings={"rescan_every_slices": 2})
        self.assertEqual(summary["state"], cpall.STATE_COMPLETED)
        self.assertEqual(fires["n"], 1, "the new work must be staged")
        self.assertEqual(sim.new_units_added, 12, "and imported exactly once")
        self.assertEqual(sim.completed, 22, "discovered work is processed too")
        self.assertEqual(self.objective()["units_discovered"], 22)

    def test_discovery_happens_at_a_rescan_boundary(self) -> None:
        sim = Sim(units=40, units_per_slice=1)
        settings = dict(self.settings, rescan_every_slices=5)
        summary = self.run_cpall(sim, settings=settings)
        self.assertEqual(summary["state"], cpall.STATE_COMPLETED)
        # The mechanical pass is settled early and rescanned periodically, not
        # once per semantic carrier.
        self.assertLess(sim.mechanical_calls, sim.semantic_calls)

    def test_cpall_bookkeeping_never_becomes_work(self) -> None:
        """Reports and the objective itself must not feed the work graph."""
        sim = Sim(units=5, units_per_slice=5)
        summary = self.run_cpall(sim)
        self.assertEqual(summary["state"], cpall.STATE_COMPLETED)
        self.assertEqual(sim.discovered, 5)
        self.assertEqual(sim.new_units_added, 0)
        self.assertGreater(len(cpall.load_reports(self.home)), 0)


class Cancellation(CpallCase):
    def test_explicit_cancellation_is_terminal_and_preserves_evidence(self) -> None:
        sim = Sim(units=40, units_per_slice=5)
        self.run_cpall(sim, max_slices=2)
        completed_before = self.objective()["units_completed"]
        reports_before = len(cpall.load_reports(self.home))

        result = cpall.cancel(self.home, reason="operator changed priority",
                              registry=self.registry)
        self.assertEqual(result["state"], cpall.STATE_CANCELLED)
        objective = self.objective()
        self.assertEqual(objective["state"], cpall.STATE_CANCELLED)
        self.assertEqual(objective["cancelled_reason"], "operator changed priority")
        self.assertIsNone(objective["owner"], "cancellation releases ownership")
        self.assertIsNone(objective["retry"]["next_attempt_at"])
        self.assertEqual(objective["units_completed"], completed_before,
                         "completed work survives cancellation")
        self.assertGreaterEqual(len(cpall.load_reports(self.home)), reports_before)

        # No further work happens: a new invocation opens a NEW objective.
        summary = self.run_cpall(sim, max_slices=1)
        self.assertNotEqual(summary["objective_id"], objective["objective_id"])
        self.assertNotEqual(self.objective()["state"], cpall.STATE_CANCELLED)

    def test_slash_goal_stop_cancels(self) -> None:
        support.run_saipal("/goal", "cpall", home=self.home)
        live = cpall.fresh_objective(started_at=1_700_000_000.0)
        (self.home / cpall.CPALL_NAME).write_text(json.dumps(live), encoding="utf-8")
        code, payload, err = support.run_saipal_json("/goal", "stop", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["state"], cpall.STATE_CANCELLED)
        self.assertEqual(self.objective()["state"], cpall.STATE_CANCELLED)

    def test_cancelling_twice_is_idempotent(self) -> None:
        cpall.attach_or_start(self.home, registry=self.registry)
        cpall.cancel(self.home, reason="first", registry=self.registry)
        again = cpall.cancel(self.home, reason="second", registry=self.registry)
        self.assertTrue(again["already_cancelled"])
        self.assertEqual(self.objective()["cancelled_reason"], "first")


class SemanticWalls(CpallCase):
    """A semantic wall is classified and named, never smoothed into "ran"."""

    def test_a_binding_wall_is_not_mistaken_for_a_config_wall(self) -> None:
        self.assertFalse(
            cpall.names_unusable_configuration(
                "binding status is PARTIAL: no historical protocol authority to "
                "compare against"
            ),
            "'authority' must not read as 'AUTH'",
        )
        self.assertTrue(cpall.names_unusable_configuration(
            "backend circuit OPEN after AUTH; fix the configuration to half-open it"))
        self.assertTrue(cpall.names_unusable_configuration(
            "environment variable 'SAIPAL_ANALYST_API_KEY' is not set; no request "
            "was sent"))
        self.assertFalse(
            cpall.names_unusable_configuration("backend circuit OPEN until 1790589000"),
            "a time-boxed circuit is transient, not a configuration wall",
        )

    def test_an_unusable_configuration_blocks_instead_of_spinning(self) -> None:
        """An OPEN AUTH circuit is an operator action, not a retry target."""
        # Eligible work must remain, or durable coverage would answer "no
        # analyzable episode is pending" and mask a configuration wall.
        sim = Sim(units=10, units_per_slice=5)
        sim.semantic = lambda home: {  # type: ignore[assignment]
            "ok": True,
            "stop_reason": "BUDGET_EXHAUSTED",
            "units": 0,
            "detail": "global hourly budget: backend circuit OPEN after AUTH; "
                      "fix the configuration to half-open it",
        }
        summary = self.run_cpall(sim, max_slices=3)
        objective = self.objective()
        family = objective["families"][cpall.FAMILY_SEMANTIC]
        self.assertEqual(family["state"], cpall.FAMILY_BLOCKED)
        self.assertEqual(family["last_error_class"], cpall.FAILURE_CONFIGURATION)
        self.assertIn("fix the configuration", str(family["last_error"]))
        self.assertGreater(objective["failures"]["validation_failures"], 0)
        # Nothing independent is left, so the objective says so instead of
        # pretending a retry will outlast a configuration problem.
        self.assertEqual(objective["units_eligible_remaining"], 10)
        self.assertEqual(objective["units_completed"], 0)
        self.assertEqual(summary["state"], cpall.STATE_OPERATOR_BLOCKED)
        self.assertIn("semantic", objective["state_reason"])

    def test_a_blocked_family_does_not_freeze_the_other_family(self) -> None:
        """PAL-CPALL-03's rule, applied to a configuration wall as well.

        The whole point of isolating a wall is that the work which does NOT
        depend on it keeps converging. A blocked semantic family must leave the
        mechanical family running and the objective ACTIVE with the wall named --
        never OPERATOR_BLOCKED while independent work remains.
        """
        sim = Sim(units=20, units_per_slice=5)
        sim.intake_idle = False  # mechanical work genuinely remains
        sim.semantic = lambda home: {  # type: ignore[assignment]
            "ok": True,
            "stop_reason": "BUDGET_EXHAUSTED",
            "units": 0,
            "detail": "backend circuit OPEN after AUTH; fix the configuration "
                      "to half-open it",
        }
        summary = self.run_cpall(sim, max_slices=3)
        objective = self.objective()
        self.assertEqual(summary["state"], cpall.STATE_ACTIVE)
        self.assertIn("blocked: semantic", objective["state_reason"])
        self.assertEqual(
            objective["families"][cpall.FAMILY_MECHANICAL]["state"],
            cpall.FAMILY_ACTIVE,
        )
        self.assertEqual(
            objective["families"][cpall.FAMILY_SEMANTIC]["state"],
            cpall.FAMILY_BLOCKED,
        )
        self.assertEqual(sim.mechanical_calls, 3,
                         "the independent family kept working every slice")
        self.assertTrue(
            any(row.get("kind") == "FAMILY_BLOCKED:semantic"
                for row in objective["unresolved"]),
            "a wall that another family outlives is still operator-visible",
        )

    def test_a_cleared_wall_stops_being_reported_as_unresolved(self) -> None:
        """The wall is fixed; `unresolved` must not keep claiming it.

        A section that still says FAMILY_BLOCKED:semantic next to a family that is
        producing units teaches the reader to ignore it -- and the next real wall
        goes unnoticed.
        """
        sim = Sim(units=20, units_per_slice=5)
        sim.intake_idle = False
        calls = {"n": 0}
        real = sim.semantic

        def wall_then_work(home: Path) -> dict:
            calls["n"] += 1
            if calls["n"] <= 4:
                return {
                    "ok": True,
                    "stop_reason": "BUDGET_EXHAUSTED",
                    "units": 0,
                    "detail": "backend circuit OPEN after AUTH; fix the "
                              "configuration to half-open it",
                }
            return real(home)

        sim.semantic = wall_then_work  # type: ignore[assignment]
        self.run_cpall(sim, max_slices=8, settings={"max_units_per_slice": 3})
        objective = self.objective()
        family = objective["families"][cpall.FAMILY_SEMANTIC]
        self.assertIn(family["state"], (cpall.FAMILY_ACTIVE, cpall.FAMILY_DONE),
                      "a cleared wall leaves a producing or finished family, "
                      "never a blocked one")
        self.assertGreater(objective["units_completed"], 0)
        kinds = [row.get("kind") for row in objective["unresolved"]]
        self.assertNotIn("FAMILY_BLOCKED:semantic", kinds,
                         "a family that is working is not blocked")
        self.assertNotIn("SEMANTIC_NO_PROGRESS", kinds,
                         "the named no-progress condition is gone")

    def test_a_slice_that_judges_units_and_blocks_one_names_both(self) -> None:
        """A mixed slice is progress WITH a block, and it must say so.

        The worker no longer ends a slice on the first inadmissible unit: the
        other sessions still get judged. That makes `units > 0` and
        `jobs_blocked > 0` legal at once, and the objective must not drop the
        block on the floor -- nor back the family off work that is converging.
        """
        sim = Sim(units=20, units_per_slice=5)
        sim.intake_idle = False
        real = sim.semantic

        def mixed(home: Path) -> dict:
            result = real(home)
            result["jobs_blocked"] = 1
            result["detail"] = "blocked units are recorded in the journal"
            return result

        sim.semantic = mixed  # type: ignore[assignment]
        self.run_cpall(sim, max_slices=2)
        family = self.objective()["families"][cpall.FAMILY_SEMANTIC]
        self.assertIn("1 unit(s) blocked", family["reason"])
        self.assertEqual(family["state"], cpall.FAMILY_ACTIVE,
                         "a block never backs the family off converging work")

    def test_an_exhausted_eligible_set_blocks_the_family_instead_of_spinning(self) -> None:
        """The worker's own verdict on the backlog decides the family's state.

        `units_eligible` is a KERNEL count of episodes without receipts. When the
        worker reports that nothing in that set is eligible any more -- every
        remaining unit blocked on authority or model capability -- a family that
        stayed ACTIVE would slice forever over a backlog that cannot converge.
        The wall is an operator decision, so the family BLOCKS; the objective
        still answers OPERATOR_BLOCKED only once the other family is DONE.
        """
        # The kernel still counts 425 outstanding episodes (units_discovered);
        # the WORKER says none of them is eligible. That disagreement is the
        # whole point: the family must follow the worker.
        sim = Sim(units=425)
        sim.intake_idle = True
        sim.semantic = lambda home: {  # type: ignore[assignment]
            "ok": True,
            "stop_reason": "BLOCKED_BINDING",
            "units": 0,
            "jobs_blocked": 0,
            "jobs_blocked_binding": 425,
            "no_eligible_unit": True,
            "detail": "no eligible unit remains; blocked units are recorded in the journal",
        }

        summary = self.run_cpall(sim, max_slices=3)
        objective = self.objective()
        family = objective["families"][cpall.FAMILY_SEMANTIC]

        self.assertEqual(family["state"], cpall.FAMILY_BLOCKED)
        self.assertIn("425", family["reason"])
        self.assertIn("no eligible unit remains", family["reason"])
        self.assertEqual(
            objective["families"][cpall.FAMILY_MECHANICAL]["state"],
            cpall.FAMILY_DONE,
        )
        self.assertEqual(summary["state"], cpall.STATE_OPERATOR_BLOCKED,
                         "independent work is exhausted, so the wall is the answer")
        self.assertIn("semantic", objective["state_reason"])
        self.assertIn(
            "FAMILY_BLOCKED:semantic",
            [row.get("kind") for row in objective["unresolved"]],
        )

    def test_a_purely_binding_blocked_slice_blocks_the_family(self) -> None:
        """PAL-CPALL-05: unbound authority is a wall, not a spinning family.

        The exhausted-eligible control above carries one backend/output block.
        The other half of the same `no_eligible_unit` answer -- every blocked
        unit blocked on BINDING -- used to be unreachable: the earlier
        `BLOCKED_BINDING` branch returned ACTIVE/PERMANENT whenever
        `no_eligible_unit` was absent, and when it WAS present the backend branch
        claimed it first. Measured on the live home: `jobs_blocked: 1,
        jobs_blocked_binding: 0` took the backend branch, so a purely
        binding-blocked slice could only ever reach a family that slices forever
        over a backlog that cannot converge -- the silent spin PAL-CPALL-02
        forbids.
        """
        sim = Sim(units=421)
        sim.intake_idle = True
        sim.semantic = lambda home: {  # type: ignore[assignment]
            "ok": True,
            "stop_reason": "BLOCKED_BINDING",
            "units": 0,
            "jobs_blocked": 0,
            "jobs_blocked_binding": 421,
            "no_eligible_unit": True,
            "detail": "no eligible unit remains; blocked units are recorded in the journal",
        }

        summary = self.run_cpall(sim, max_slices=3)
        objective = self.objective()
        family = objective["families"][cpall.FAMILY_SEMANTIC]

        self.assertEqual(family["state"], cpall.FAMILY_BLOCKED)
        self.assertIn("binding", family["reason"])
        self.assertIn("421", family["reason"])
        # The canonical way back is named on the family itself, so the wall is
        # actionable from the same read the objective publishes.
        self.assertIn("authority enroll", family["reason"])
        self.assertIn("rebind", family["reason"])
        self.assertEqual(
            objective["families"][cpall.FAMILY_MECHANICAL]["state"],
            cpall.FAMILY_DONE,
        )
        self.assertEqual(summary["state"], cpall.STATE_OPERATOR_BLOCKED)
        self.assertIn("semantic", objective["state_reason"])

    def test_a_conflict_alone_does_not_unsettle_the_mechanical_family(self) -> None:
        """A conflict is an isolated operator item, never mechanical work.

        Measured on the real home: zero analysis debt, 11 CONFLICT sessions, and
        `idle: False` forever -- so an objective that trusted `idle` could never
        reach a terminal state at all. The cycle still reports `intake_idle:
        False` (a conflict is not nothing), but a cycle that imported nothing and
        owes no analysis IS settled, and the conflict is answered by
        `derive_state` -- here, on top of the semantic wall.
        """
        sim = Sim(units=425)

        def cycle(home: Path) -> dict:
            return {
                "ok": True,
                "idle": False,
                "intake_idle": False,
                "work_remaining": False,
                "budget_hit": False,
                "sessions_indexed": 0,
                "sessions_analyzed": 0,
                "events_analyzed": 0,
                "candidates": 0,
                "audits_emitted": 0,
                "intake": {"conflicted": 12, "conflicts": [{"session_id": "ses-x"}]},
                "next_action": "12 session(s) are in CONFLICT",
            }

        real_view = sim.view

        def view(home: Path) -> dict:
            result = real_view(home)
            result["conflicts_current"] = 12
            result["conflicts_indexed"] = 12
            result["conflict_rows"] = [{"session_id": "ses-x"}]
            return result

        sim.mechanical = cycle  # type: ignore[assignment]
        sim.view = view  # type: ignore[assignment]
        sim.semantic = lambda home: {  # type: ignore[assignment]
            "ok": True,
            "stop_reason": "IDLE",
            "units": 0,
            "no_analyzable_unit": True,
            "population_classes": {"TERMINAL": 425},
            "detail": "no analyzable episode is pending",
        }

        summary = self.run_cpall(sim, max_slices=3)
        objective = self.objective()

        self.assertEqual(
            objective["families"][cpall.FAMILY_MECHANICAL]["state"],
            cpall.FAMILY_DONE,
            "nothing was imported and no analysis is owed: the cycle is settled",
        )
        self.assertEqual(summary["state"], cpall.STATE_OPERATOR_BLOCKED)
        self.assertIn("semantic", objective["state_reason"])
        self.assertIn("12 isolated conflict(s)", objective["state_reason"],
                      "the operator resolves SESSIONS, not conflict units")

    def test_new_evidence_unsettles_the_mechanical_family_for_one_cycle(self) -> None:
        """The forgiveness is for conflicts only: an import is real work."""
        sim = Sim(units=5, units_per_slice=5)

        def cycle(home: Path) -> dict:
            return {
                "ok": True,
                "idle": False,
                "intake_idle": False,
                "work_remaining": False,
                "budget_hit": False,
                "sessions_indexed": 1,
                "sessions_analyzed": 1,
                "events_analyzed": 10,
                "candidates": 0,
                "audits_emitted": 0,
                "intake": {"conflicted": 0, "conflicts": []},
                "next_action": "1 session imported; analyse it",
            }

        sim.mechanical = cycle  # type: ignore[assignment]
        self.run_cpall(sim, max_slices=1)
        mechanical = self.objective()["families"][cpall.FAMILY_MECHANICAL]
        self.assertEqual(mechanical["state"], cpall.FAMILY_ACTIVE)
        self.assertFalse(mechanical["settled"])

    def test_an_idle_worker_over_a_nonempty_backlog_blocks_with_its_classes(self) -> None:
        """"nothing to do" and "nothing I may analyse" must not read the same.

        The worker's IDLE answer is authoritative about the ELIGIBLE set, while
        `units_eligible` is the kernel's count of units without a verdict. When
        the first is empty and the second is not, those units are blocked -- and
        the classes the worker excluded are what makes the wall actionable.
        """
        sim = Sim(units=425)
        sim.intake_idle = True
        sim.semantic = lambda home: {  # type: ignore[assignment]
            "ok": True,
            "stop_reason": "IDLE",
            "units": 0,
            "no_analyzable_unit": True,
            "population_classes": {
                "TERMINAL": 425,
                "PROVISIONAL_DISABLED": 130,
                "DONE": 37,
            },
            "detail": "no analyzable episode is pending",
        }

        summary = self.run_cpall(sim, max_slices=2)
        objective = self.objective()
        family = objective["families"][cpall.FAMILY_SEMANTIC]

        self.assertEqual(family["state"], cpall.FAMILY_BLOCKED)
        self.assertIn("425 unit(s) still lack a verdict", family["reason"])
        self.assertIn("425 terminal", family["reason"])
        self.assertIn("130 provisional disabled", family["reason"])
        self.assertEqual(summary["state"], cpall.STATE_OPERATOR_BLOCKED)
        self.assertIn(
            "FAMILY_BLOCKED:semantic",
            [row.get("kind") for row in objective["unresolved"]],
        )

    def test_a_refused_population_names_its_canonical_way_back(self) -> None:
        """T-136 / PAL-CPALL-04: the wall names the command, not just the count.

        A `BLOCKED` unit is a refusal, and a refusal now has a bounded path back
        (`analyst-requeue`). The objective's own family reason must say so: an
        operator reading a terminal state should not have to discover the tool.
        """
        sim = Sim(units=425)
        sim.intake_idle = True
        sim.semantic = lambda home: {  # type: ignore[assignment]
            "ok": True,
            "stop_reason": "IDLE",
            "units": 0,
            "no_analyzable_unit": True,
            "population_classes": {"BLOCKED": 8, "TERMINAL": 417},
            "detail": "no analyzable episode is pending",
        }

        self.run_cpall(sim, max_slices=2)
        family = self.objective()["families"][cpall.FAMILY_SEMANTIC]

        self.assertEqual(family["state"], cpall.FAMILY_BLOCKED)
        self.assertIn("8 refused unit(s) have a canonical way back", family["reason"])
        self.assertIn("analyst-requeue", family["reason"])

    def test_an_unknown_remote_outcome_is_named_as_nonreplayable(self) -> None:
        sim = Sim(units=1)
        sim.intake_idle = True
        sim.semantic = lambda home: {  # type: ignore[assignment]
            "ok": True,
            "stop_reason": "IDLE",
            "units": 0,
            "no_analyzable_unit": True,
            "population_classes": {"REMOTE_OUTCOME_UNKNOWN": 1},
            "detail": "no analyzable episode is pending",
        }

        self.run_cpall(sim, max_slices=2)
        family = self.objective()["families"][cpall.FAMILY_SEMANTIC]

        self.assertEqual(family["state"], cpall.FAMILY_BLOCKED)
        self.assertIn("REMOTE_OUTCOME_UNKNOWN", family["reason"])
        self.assertIn("must not be replayed automatically", family["reason"])

    def test_a_drained_backlog_still_completes_when_the_worker_is_idle(self) -> None:
        """The new wall must not steal completion from a genuinely empty queue."""
        sim = Sim(units=5, units_per_slice=5)
        sim.intake_idle = True

        summary = self.run_cpall(sim, max_slices=6)
        self.assertEqual(summary["state"], cpall.STATE_COMPLETED)

    def test_a_wall_that_is_not_the_whole_backlog_keeps_the_family_runnable(self) -> None:
        """Authority can improve: a blocked UNIT is not a blocked BACKLOG."""
        sim = Sim(units=20, units_per_slice=5)
        sim.intake_idle = False
        sim.semantic = lambda home: {  # type: ignore[assignment]
            "ok": True,
            "stop_reason": "BLOCKED",
            "units": 0,
            "jobs_blocked": 1,
            "detail": "backend or output failure blocked the unit",
        }

        self.run_cpall(sim, max_slices=2)
        family = self.objective()["families"][cpall.FAMILY_SEMANTIC]
        self.assertEqual(family["state"], cpall.FAMILY_ACTIVE)
        self.assertIn("blocked the unit", family["reason"])

    def test_a_zero_unit_slice_carries_the_workers_own_reason(self) -> None:
        """`why did it skip a unit?` must be answerable from the objective."""
        sim = Sim(units=10, units_per_slice=5)
        sim.semantic = lambda home: {  # type: ignore[assignment]
            "ok": True,
            "stop_reason": "IDLE",
            "units": 0,
            "detail": "no analyzable episode is pending",
        }
        self.run_cpall(sim, max_slices=1)
        reason = self.objective()["families"][cpall.FAMILY_SEMANTIC]["reason"]
        self.assertIn("no analyzable episode is pending", reason)
        self.assertIn("IDLE", reason)


# --------------------------------------------------------------------------- #
# long-duration soak
# --------------------------------------------------------------------------- #


class MultiDaySoak(CpallCase):
    """Seven simulated days, thousands of slices, crashes and a long outage."""

    def test_seven_simulated_days_converge_truthfully(self) -> None:
        units = 3_000
        sim = Sim(units=units, units_per_slice=5, sessions=40)
        clock = VirtualClock()
        settings = dict(
            self.settings,
            report_cadence_seconds=1800.0,
            retry_base_seconds=60.0,
            retry_max_seconds=900.0,
            rescan_every_slices=25,
        )

        start = clock.now()
        slices_per_process = 120
        processes = 0
        outage_over = start + 3600.0 * 3  # backend down for three simulated hours
        sim.backend_available = False
        sim.rate_limited_slices = 0
        rate_limit_until = 0.0

        previous_completed = 0
        objective = None
        for _ in range(12):
            processes += 1
            summary = cpall.run(
                self.home,
                mechanical_slice=sim.mechanical,
                semantic_slice=sim.semantic,
                registry=self.registry,
                settings=settings,
                clock=clock,
                max_slices=slices_per_process,
                backlog_fn=sim.view,
            )
            objective = self.objective()
            self.assertGreaterEqual(
                objective["units_completed"], previous_completed,
                "a restart must never lose or duplicate accepted units",
            )
            previous_completed = objective["units_completed"]
            if summary["state"] in cpall.TERMINAL_STATES:
                break
            # A process restart: the closure of one process is not the end of
            # the objective, so the objective is still resumable right now.
            self.assertTrue(cpall.recover(self.home, registry=self.registry)["resumable"])
            if clock.now() >= outage_over and not sim.backend_available:
                sim.backend_available = True
                # The backend does not come back clean: it answers with a
                # rate limit for the next simulated hour, so RATE_LIMIT
                # recovery is exercised too, not only a refused connection.
                sim.rate_limited_slices = 4
                rate_limit_until = clock.now() + 3600.0
            if sim.rate_limited_slices and clock.now() >= rate_limit_until:
                sim.rate_limited_slices = 0

        # Let the simulated outage end, then let it converge.
        sim.backend_available = True
        sim.rate_limited_slices = 0
        if summary["state"] not in cpall.TERMINAL_STATES:
            summary = cpall.run(
            self.home,
            mechanical_slice=sim.mechanical,
            semantic_slice=sim.semantic,
            registry=self.registry,
            settings=settings,
            clock=clock,
            max_slices=4000,
            backlog_fn=sim.view,
        )
        self.assertEqual(summary["state"], cpall.STATE_COMPLETED)
        self.assertEqual(sim.completed, units)
        self.assertGreater(processes, 1, "the soak must span several processes")
        self.assertEqual(len(set(sim.accepted_receipts)), units,
                         "no unit may be accepted twice across restarts")

        refreshed = self.objective()
        self.assertEqual(refreshed["objective_id"], objective["objective_id"])
        objective = refreshed
        self.assertGreater(objective["slices"], 100)
        self.assertLess(clock.now() - start, 7 * 86400.0,
                        "the soak must finish inside seven simulated days")
        self.assertEqual(objective["units_completed"], units)
        self.assertEqual(objective["units_eligible_remaining"], 0)
        self.assertGreater(objective["failures"]["transient"], 0)
        self.assertGreater(objective["failures"]["rate_limit"], 0)
        self.assertGreater(objective["runtime_seconds"], 0.0)
        reports = cpall.load_reports(self.home)
        self.assertEqual(reports[-1]["kind"], cpall.REPORT_FINAL)
        self.assertEqual(reports[-1]["state"], cpall.STATE_COMPLETED)

    def test_a_permanently_conflicted_session_does_not_block_the_rest(self) -> None:
        sim = Sim(units=540, units_per_slice=5, sessions=12)
        sim.conflict_units = 40
        sim.conflict_rows = [ConflictIsolation.conflict_row("session-stuck")]
        clock = VirtualClock()
        summary = self.run_cpall(sim, clock=clock,
                                settings={"rescan_every_slices": 20})
        self.assertEqual(sim.completed, 500)
        self.assertEqual(summary["state"], cpall.STATE_OPERATOR_BLOCKED)
        objective = self.objective()
        self.assertEqual(objective["conflicts"]["current"], 1)
        self.assertEqual(objective["units_conflict"], 40)
        self.assertEqual(
            objective["families"][cpall.FAMILY_SEMANTIC]["state"],
            cpall.FAMILY_DONE,
        )

    def test_no_hot_spin_when_a_worker_keeps_returning_nothing(self) -> None:
        """A worker that reports no work while coverage says otherwise backs off."""
        sim = Sim(units=100, units_per_slice=5)
        sim.semantic = lambda home: {  # type: ignore[assignment]
            "ok": True, "stop_reason": "IDLE", "units": 0,
        }
        clock = VirtualClock()
        summary = self.run_cpall(
            sim, clock=clock, max_slices=40,
            settings={"max_units_per_slice": 3, "retry_base_seconds": 30.0},
        )
        objective = self.objective()
        self.assertNotEqual(summary["state"], cpall.STATE_COMPLETED)
        self.assertEqual(
            objective["families"][cpall.FAMILY_SEMANTIC]["state"],
            cpall.FAMILY_WAITING,
        )
        self.assertTrue(
            any(row.get("kind") == "SEMANTIC_NO_PROGRESS"
                for row in objective["unresolved"]),
            "the discrepancy must be named, not averaged away",
        )
        self.assertGreater(clock.slept, 0.0)


    def test_a_binding_wall_is_named_and_counted_not_hidden(self) -> None:
        """A unit the analyst BLOCKED is a named wall, never a healthy slice.

        The analyst's own fail-closed refusal (a PARTIAL historical binding has
        no protocol authority to compare against) reaches cpall as a slice that
        completed nothing. It must not be reported as "the slice ran" with a
        zero failure ledger: the reason names the wall and the ledger counts it,
        while the family stays runnable because authority can improve.
        """
        sim = Sim(units=100, units_per_slice=5)
        calls = {"n": 0}

        def blocked(home: Path) -> dict:
            calls["n"] += 1
            return {
                "ok": True,
                "stop_reason": "BLOCKED_BINDING",
                "jobs_completed": 0,
                "units": 0,
                "detail": "binding status is PARTIAL: no historical protocol authority",
            }

        sim.semantic = blocked  # type: ignore[assignment]
        clock = VirtualClock()
        summary = self.run_cpall(
            sim, clock=clock, max_slices=2,
            settings={"max_units_per_slice": 3},
        )
        objective = self.objective()
        family = objective["families"][cpall.FAMILY_SEMANTIC]
        self.assertEqual(family["state"], cpall.FAMILY_ACTIVE)
        self.assertEqual(family["last_error_class"], cpall.FAILURE_PERMANENT)
        self.assertIn("binding", str(family["last_error"]))
        self.assertIn("PARTIAL", str(family["last_error"]))
        self.assertGreater(objective["failures"]["permanent"], 0)
        self.assertEqual(objective["units_completed"], 0)
        # The wall is not completion and not a hidden success.
        self.assertNotEqual(summary["state"], cpall.STATE_COMPLETED)
        self.assertEqual(summary["coverage"]["units_eligible_remaining"], 100)
        self.assertEqual(calls["n"], 2)
# --------------------------------------------------------------------------- #
# data integrity: at-least-once slicing, exactly-once accepted results
# --------------------------------------------------------------------------- #


class SubmissionIdempotency(CpallCase):
    """A crash after submission but before the cursor checkpoint replays safely."""

    def _one_confirmed_unit(self) -> dict:
        from saipal_engine import submit as submit_mod

        support.put_inbox(self.home, "hot-partial.json")
        support.run_saipal("continue", home=self.home)
        return submit_mod.load_receipts(self.home)[1] or {"receipts": []}

    def test_replaying_an_accepted_submission_does_not_double_it(self) -> None:
        from saipal_engine import submit as submit_mod

        payload = self._one_confirmed_unit()
        unit = support.next_unit(self.home)
        self.assertIsNotNone(unit, "the fixture must offer a semantic unit")

        support.submit_drift(self.home, unit)
        after_first = submit_mod.load_receipts(self.home)[1]
        count_first = len((after_first or {}).get("receipts") or [])
        self.assertGreaterEqual(count_first, 1)
        cursor_first = submit_mod.load_receipts(self.home)

        # The crash: the cursor checkpoint never happened, so the next worker
        # re-runs the same slice with the same unit.
        support.submit_drift(self.home, unit)
        after_replay = submit_mod.load_receipts(self.home)[1]
        count_replay = len((after_replay or {}).get("receipts") or [])
        self.assertEqual(count_replay, count_first,
                         "an accepted submission must be idempotent per unit")
        self.assertEqual(cursor_first[0], submit_mod.load_receipts(self.home)[0])
        del payload


# --------------------------------------------------------------------------- #
# fairness: a huge session must not starve a tiny one
# --------------------------------------------------------------------------- #


class TwoSessionSim:
    """Two sessions of very different size, served least-served-first.

    The fairness POLICY is carrier allocation's (`saipal_analyst.fairness`, owned
    and controlled there). What cpall owns is the consequence: it keeps slicing
    until BOTH are drained, and the tiny session must reach its last unit long
    before the huge one instead of waiting behind 1,300 units of backlog.
    """

    BIG = "session-big"
    SMALL = "session-small"

    def __init__(self, *, big: int = 1300, small: int = 10,
                 per_slice: int = 5) -> None:
        self.total = int(big) + int(small)
        self.pending = {self.BIG: int(big), self.SMALL: int(small)}
        self.served: list[str] = []
        self.finished_at: dict[str, int] = {}
        self.per_slice = int(per_slice)
        self.semantic_calls = 0

    def view(self, home: Path) -> dict:
        completed = len(self.served)
        return {
            "ok": True,
            "sessions_total": len(self.pending),
            "sessions_completed": len(self.finished_at),
            "units_discovered": self.total,
            "units_completed": completed,
            "units_remaining": self.total - completed,
            "units_eligible_remaining": self.total - completed,
            "units_conflict": 0,
            "conflicts_current": 0,
            "conflicts_indexed": 0,
            "conflicts_superseded": 0,
            "conflict_rows": [],
            "mechanical_pending": 0,
            "staged_audits": 0,
            "inbox_files": 0,
            "source_fingerprint": f"fair-{completed}",
        }

    def mechanical(self, home: Path) -> dict:
        return {
            "ok": True,
            "idle": True,
            "intake_idle": True,
            "work_remaining": False,
            "budget_hit": False,
            "sessions_indexed": 0,
            "sessions_analyzed": 0,
            "events_analyzed": 0,
            "candidates": 0,
            "audits_emitted": 0,
            "next_action": "simulated mechanical cycle",
        }

    def semantic(self, home: Path) -> dict:
        self.semantic_calls += 1
        pending = [name for name, left in self.pending.items() if left > 0]
        if not pending:
            return {
                "ok": True,
                "stop_reason": "IDLE",
                "jobs_completed": 0,
                "units": 0,
                "backend": {"route": "local", "model": "qwen3.5:9b", "ok": True},
            }
        counts = {name: self.served.count(name) for name in self.pending}
        chosen = min(pending, key=lambda name: (counts[name], name))
        take = min(self.per_slice, self.pending[chosen])
        self.pending[chosen] -= take
        self.served.extend([chosen] * take)
        if self.pending[chosen] == 0:
            self.finished_at[chosen] = len(self.served)
        return {
            "ok": True,
            "stop_reason": "BUDGET",
            "jobs_completed": take,
            "units": take,
            "backend": {"route": "local", "model": "qwen3.5:9b", "ok": True},
        }


class Fairness(CpallCase):
    """One huge session must not starve every other session forever."""

    def test_a_huge_session_does_not_starve_a_tiny_one(self) -> None:
        sim = TwoSessionSim(big=1300, small=10, per_slice=5)
        summary = self.run_cpall(sim, max_slices=400)

        self.assertEqual(summary["state"], cpall.STATE_COMPLETED)
        self.assertEqual({name: left for name, left in sim.pending.items()}, {
            TwoSessionSim.BIG: 0, TwoSessionSim.SMALL: 0,
        }, "cpall converges the whole live graph, not just the biggest session")
        small_done = sim.finished_at[TwoSessionSim.SMALL]
        big_done = sim.finished_at[TwoSessionSim.BIG]
        self.assertLess(
            small_done, big_done,
            "the tiny session finishes before the huge one is drained",
        )
        self.assertLessEqual(
            small_done, 4 * sim.per_slice,
            "10 units cost the tiny session four slices, not the whole run",
        )
        self.assertEqual(summary["coverage"]["sessions_completed"], 2)
        self.assertEqual(summary["coverage"]["units_completed"], sim.total)

    def test_the_objective_stays_active_while_the_huge_session_drains(self) -> None:
        sim = TwoSessionSim(big=200, small=10, per_slice=5)
        summary = self.run_cpall(sim, max_slices=8)

        self.assertEqual(summary["state"], cpall.STATE_ACTIVE,
                         "a slice budget is a checkpoint, not an outcome")
        self.assertEqual(sim.pending[TwoSessionSim.SMALL], 0,
                         "the tiny session drained inside those slices")
        self.assertGreater(sim.pending[TwoSessionSim.BIG], 0)

# --------------------------------------------------------------------------- #
# T-159: the OPERATOR_BLOCKED hint names only walls the objective actually hit
# --------------------------------------------------------------------------- #

class OperatorBlockedHintNamesOnlyRealWalls(CpallCase):
    """An objective blocked on binding does not stop being told to enable the
    analyst runtime. The hint is chosen by state alone, so it keeps offering a
    route the operator already acted on -- and stops naming the real one."""

    def hint(self, stop_reason: str | None) -> str:
        run = cpall.CpallRun(
            self.home,
            mechanical_slice=lambda home: {},
            semantic_slice=lambda home: {},
            registry=self.registry,
            settings=self.settings,
        )
        objective = cpall.fresh_objective(started_at=1_700_000_000.0)
        objective["state"] = cpall.STATE_OPERATOR_BLOCKED
        if stop_reason is not None:
            cpall._family(objective, cpall.FAMILY_SEMANTIC)["last_stop_reason"] = stop_reason
        return run._next_action(objective)

    def test_a_binding_wall_does_not_name_the_analyst_runtime(self) -> None:
        hint = self.hint("BLOCKED_BINDING")
        self.assertNotIn("analyst runtime", hint)
        self.assertNotIn("analyst configuration", hint)
        self.assertIn("isolated conflicts", hint)

    def test_an_output_wall_does_not_name_the_analyst_runtime(self) -> None:
        self.assertNotIn("analyst runtime", self.hint("BLOCKED"))

    def test_a_disabled_runtime_still_names_the_runtime(self) -> None:
        self.assertIn("enable the analyst runtime", self.hint("CONFIG_DISABLED"))

    def test_an_incomplete_configuration_names_the_configuration(self) -> None:
        self.assertIn("fix the analyst configuration", self.hint("CONFIGURATION_BLOCKED"))

    def test_a_successful_slice_records_no_runtime_route(self) -> None:
        self.assertNotIn("analyst runtime", self.hint("BUDGET"))

    def test_the_family_records_the_slice_stop_reason(self) -> None:
        sim = Sim(units=30, units_per_slice=5)

        def disabled(home: Path) -> dict:
            return {"ok": False, "stop_reason": "CONFIG_DISABLED", "units": 0,
                    "errors": [{"message": "analyst runtime is disabled"}]}

        sim.semantic = disabled
        self.run_cpall(sim, max_slices=2)
        objective = self.objective()
        self.assertEqual(
            cpall._family(objective, cpall.FAMILY_SEMANTIC)["last_stop_reason"],
            "CONFIG_DISABLED",
        )
