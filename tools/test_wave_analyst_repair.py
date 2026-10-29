"""T-84: real-worker fault injection -- the journal is the loop's spine.

Every case here drives the REAL worker (allocator + journal + fake HTTP
backend + deliberation + submit + crash/restart) as one system. No case is
satisfied by calling jobs.next_action() on a hand-built state alone: the
journal must describe what the real worker durably did.

Crash simulation: any uncaught exception that escapes `investigate` stands in
for process death. The worker lock is released by its own finally block, the
journal keeps the last durable stage, and the next `investigate` call is the
restart. That is exactly the crash contract the journal exists for.

Old invariants replaced on purpose (T-84, stronger):
- a recovered investigator candidate re-enters the critic policy; the old
  direct-submit expectation let recovered DRIFT bypass the mandatory critic;
- a transport failure is never an output-validation failure;
- repair attempts are durable per-role counters, not per-run locals.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import pal_test_support as support
from saipal_analyst import jobs as jobs_mod
from saipal_analyst import openai_compatible as transport_module
from saipal_analyst import output as output_module
from saipal_analyst import worker as worker_module
from saipal_analyst.config import default_analyst_config, save_analyst_config
from saipal_analyst.worker import WorkerClock, investigate
from saipal_engine.registry import load_registry, require_string_list
from saipal_engine import submit as submit_module


def _newest_digest(record: dict) -> str:
    from saipal_engine import carrier as carrier_mod

    return carrier_mod.unit_digest(record, record["episodes"][0], 0)


class CrashError(BaseException):
    """Process death. BaseException so no PalError handler may eat it."""


def carrier_id_order(index: dict) -> list:
    from saipal_engine import carrier as carrier_mod

    ordered = sorted(
        carrier_mod.freshest_records(index),
        key=lambda record: (
            str(record.get("updated_at") or record.get("imported_at") or ""),
        ),
        reverse=True,
    )
    return [record for record in ordered if record.get("status") == "IMPORTED"]


def envelope(text: str) -> bytes:
    return json.dumps(
        {
            "id": "stub-req-1",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
        }
    ).encode("utf-8")


class StubBackend:
    """One backend: a queue of (status, body) replies plus arrival counts."""

    def __init__(self) -> None:
        self.script: list[tuple[int, bytes]] = []
        self.requests: list[dict] = []
        self.on_request = None  # optional test hook: called with each request dict
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw.decode("utf-8")) if raw else None
                except (ValueError, UnicodeDecodeError):
                    body = raw
                server.requests.append({"body": body})
                if callable(server.on_request):
                    server.on_request(server.requests[-1])
                if server.script:
                    status, payload = server.script.pop(0)
                else:
                    status, payload = 500, b"{}"
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args: object) -> None:
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1/chat/completions"

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    @property
    def attempts(self) -> int:
        return len(self.requests)

    def system_of(self, index: int) -> str:
        body = self.requests[index]["body"]
        return str((body or {}).get("messages", [{}])[0].get("content", ""))

    def role_of(self, index: int) -> str:
        """Which worker role made request `index`.

        All three system prompts share the AUTHORITY_TEXT prefix, so roles are
        told apart by their distinguishing tokens: the critic prompt contains
        'critic', the finalizer prompt contains 'finalizer', the investigator
        prompt contains neither.
        """
        system = self.system_of(index).lower()
        if "finalizer" in system:
            return "finalizer"
        if "critic" in system:
            return "critic"
        return "investigator"

    def count_role(self, role: str) -> int:
        return sum(1 for index in range(self.attempts) if self.role_of(index) == role)


class FakeClock:
    """Injected time: wall, monotonic and sleep advance together."""

    def __init__(self) -> None:
        self.wall = 1_000_000.0
        self.mono = 0.0
        self.slept: list[float] = []

    def wall_now(self) -> float:
        return self.wall

    def monotonic_now(self) -> float:
        return self.mono

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.wall += seconds
        self.mono += seconds

    def advance(self, seconds: float) -> None:
        self.wall += seconds
        self.mono += seconds

    def as_worker_clock(self) -> WorkerClock:
        return WorkerClock(
            monotonic=self.monotonic_now, wall=self.wall_now, sleep=self.sleep
        )


class RepairBase(unittest.TestCase):
    def _two_session_home(self) -> tuple[Path, list[str]]:
        """Two bindable sessions, in the deterministic order the worker serves.

        Both sessions are least-served (0), so the fair rank is session id order.
        """
        home = self.fresh_home("conformant-cold.json", "conformant-cold-other.json")
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.sessions import load_index

        _status, index, _detail = load_index(home)
        order = [
            str(record.get("session_id"))
            for record in sorted(
                carrier_mod.freshest_records(index),
                key=lambda record: str(record.get("session_id")),
            )
        ]
        self.assertEqual(len(order), 2, "the fixture pair must yield two sessions")
        return home, order

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

    def enable(self, home: Path, backend: StubBackend, **budgets: object) -> dict:
        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 0
        budgets.setdefault("max_units_per_run", 1)
        for key, value in budgets.items():
            config["budgets"][key] = value
        save_analyst_config(home, config)
        import os

        os.environ["SAIPAL_ANALYST_API_KEY"] = "stub-key"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)
        return config

    def run_worker(self, home: Path, clock: FakeClock | None = None, **kw: object) -> dict:
        return investigate(
            home, clock=clock.as_worker_clock() if clock else None, **kw
        )

    def candidate_json(self, home: Path, verdict: str = "NO_DRIFT") -> str:
        return self.candidate_for(home, verdict)

    def candidate_for(self, home: Path, verdict: str = "NO_DRIFT", session_id: str | None = None) -> str:
        from saipal_engine import carrier as carrier_mod

        if session_id is None:
            packet = carrier_mod.build_carrier(home)
        else:
            from saipal_engine.sessions import load_index

            _status, index, _d = load_index(home)
            record = next(
                item for item in carrier_mod.freshest_records(index)
                if str(item.get("session_id")) == session_id
            )
            episode = record["episodes"][0]
            packet = carrier_mod.build_carrier(
                home, index=index, session_id=session_id,
                episode_index=int(episode["index"]), slice_index=0,
            )
        base = {
            "schema_version": 1,
            "verdict": verdict,
            "unit_digest": packet["unit_digest"],
            "session_id": packet["session"]["session_id"],
            "episode_index": packet["episode"]["index"],
            "slice_index": packet["slice"]["index"],
            "disposition_class": verdict,
            "reasoning": "clean",
            "event_refs": [event["seq"] for event in packet["events"][:1]],
        }
        if verdict == "DRIFT":
            base["disposition_class"] = "MODEL_NONCOMPLIANCE"
            base["root_cause"] = "model routed against the surface"
            base["rule_ids"] = ["PAL-CMD-01"]
            base["drift_class"] = "COMMAND_ROUTE_DRIFT"
            base["change_target"] = "ENGINE"
            base["confidence"] = "HIGH"
            base["severity"] = "P1"
            base["challenge"] = {
                "prosecutor": "surface forbids it",
                "defender": "alias maybe",
                "winner": "prosecutor",
                "loser_rejection": "verbatim token",
            }
            base["alternatives"] = ["shell alias"]
        return json.dumps(base)

    def critic_json(self, home: Path, decision: str) -> str:
        from saipal_engine import carrier as carrier_mod

        packet = carrier_mod.build_carrier(home)
        return json.dumps(
            {
                "schema_version": 1,
                "unit_digest": packet["unit_digest"],
                "decision": decision,
                "objections": [],
                "missed_evidence": [],
                "reasoning": "critic",
            }
        )

    def journal_job(self, home: Path) -> dict:
        journal = jobs_mod.load_journal(home)
        jobs = list((journal.get("jobs") or {}).values())
        self.assertEqual(len(jobs), 1, "expected exactly one analyst job")
        return jobs[0]

    def pending_job_ids(self, home: Path) -> list[str]:
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.registry import load_registry
        from saipal_engine.sessions import load_index

        _status, index, _detail = load_index(home)
        limit = int(carrier_mod._limits(load_registry())["max_events"])
        ids = []
        for record in carrier_mod.freshest_records(index):
            if record.get("status") != "IMPORTED":
                continue
            state = carrier_mod.semantic_state(record)
            if state["exhausted"]:
                continue
            episodes = record.get("episodes") or []
            start = state["next_episode_index"]
            if start >= len(episodes):
                continue
            episode = episodes[start]
            slices = carrier_mod.episode_slice_count(record, episode, limit)
            slice_at = min(state["next_slice_index"], slices - 1)
            digest = carrier_mod.unit_digest(record, episode, slice_at)
            ids.append(
                jobs_mod.unit_job_id(
                    str(record.get("session_id")), int(episode["index"]), slice_at, digest
                )
            )
        return ids


class CrashPoints(RepairBase):
    def test_1_crash_before_call_performs_one_call(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        job_id = self.pending_job_ids(home)[0]
        journal = jobs_mod.load_journal(home)
        record = list(journal["jobs"].values())
        self.assertEqual(record, [])
        # A previous run died before its first call: the job is READY.
        job = jobs_mod.new_job(
            session_id="ses",
            episode_index=0,
            slice_index=0,
            unit_digest="d" * 64,
            finality="FINAL",
            backend_type="openai_compatible",
            model="stub-model",
            run_id="prev",
        )
        job["job_id"] = job_id
        job["session_id"] = "ses"
        # Rebuild with the REAL identity so the allocator can match it.
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.sessions import load_index

        _status, index, _d = load_index(home)
        rec = carrier_mod.freshest_records(index)[0]
        episode = rec["episodes"][0]
        digest = carrier_mod.unit_digest(rec, episode, 0)
        real_id = jobs_mod.unit_job_id(str(rec["session_id"]), int(episode["index"]), 0, digest)
        job = jobs_mod.new_job(
            session_id=str(rec["session_id"]),
            episode_index=int(episode["index"]),
            slice_index=0,
            unit_digest=digest,
            finality="FINAL",
            backend_type="openai_compatible",
            model="stub-model",
            run_id="prev",
        )
        journal["jobs"] = {real_id: job}
        jobs_mod.save_journal(home, journal)

        backend.script.append((200, envelope(self.candidate_json(home))))
        summary = self.run_worker(home)
        self.assertEqual(backend.attempts, 1)
        self.assertEqual(summary["jobs_completed"], 1)

    def test_2_crash_during_call_becomes_ambiguous(self) -> None:
        """W2-005: crash during investigator call does NOT auto-retry.

        The safest default is no automatic paid replay. The job enters
        REMOTE_OUTCOME_UNKNOWN with a durable attempt_id and blocks,
        requiring explicit operator/configured policy for any re-attempt.
        """
        home = self.fresh_home("conformant-cold.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, envelope(self.candidate_json(home))))

        original = transport_module.call

        def dying_call(*args: object, **kwargs: object) -> object:
            result = original(*args, **kwargs)  # the HTTP attempt happened
            raise CrashError("process died with the response in the socket")

        with mock.patch.object(transport_module, "call", dying_call):
            with self.assertRaises(CrashError):
                self.run_worker(home)

        job = self.journal_job(home)
        # W2-005: crash during call persists attempt_id but no response
        self.assertEqual(job["stage"], jobs_mod.INVESTIGATOR_CALLING)
        self.assertIsNone(job["response_text"])
        self.assertIn("investigator", job.get("attempt_ids", {}))
        # next_action now returns "ambiguous" for a CALLING with an attempt_id
        self.assertEqual(jobs_mod.next_action(job), "ambiguous")

        # Restart: the job transitions to REMOTE_OUTCOME_UNKNOWN and blocks
        summary = self.run_worker(home)
        # No automatic completion; the ambiguous attempt is surfaced and blocked
        self.assertEqual(summary.get("jobs_completed", 0), 0)
        self.assertEqual(backend.attempts, 1)
        # The job is now in REMOTE_OUTCOME_UNKNOWN or BLOCKED
        job = self.journal_job(home)
        self.assertIn(job["stage"], (jobs_mod.REMOTE_OUTCOME_UNKNOWN, jobs_mod.BLOCKED))
        self.assertEqual(job.get("error_class"), "REMOTE_OUTCOME_UNKNOWN")

    def test_3_crash_after_response_persisted_reuses_it(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, envelope(self.candidate_json(home))))

        real_validate = output_module.validate_candidate

        def dying_validate(*args: object, **kwargs: object) -> object:
            raise CrashError("process died parsing the persisted response")

        with mock.patch.object(output_module, "validate_candidate", dying_validate):
            with self.assertRaises(CrashError):
                self.run_worker(home)

        job = self.journal_job(home)
        self.assertEqual(job["stage"], jobs_mod.INVESTIGATOR_RESPONSE)
        self.assertIsNotNone(job["response_text"])

        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1)
        self.assertEqual(backend.attempts, 1, "the persisted response must be reused")

    def test_4_crash_after_candidate_persisted_zero_new_investigator_calls(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, envelope(self.candidate_json(home))))

        def dying_needs_critic(*args: object, **kwargs: object) -> object:
            raise CrashError("process died after the candidate write")

        with mock.patch.object(output_module, "needs_critic", dying_needs_critic):
            with self.assertRaises(CrashError):
                self.run_worker(home)

        job = self.journal_job(home)
        self.assertEqual(job["stage"], jobs_mod.CANDIDATE_READY)

        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1)
        self.assertEqual(backend.attempts, 1)

    def test_5_recovered_drift_cannot_submit_without_critic(self) -> None:
        home = self.fresh_home("agent-noncompliance-command-route.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, envelope(self.candidate_json(home, "DRIFT"))))
        backend.script.append((200, envelope(self.critic_json(home, "AGREE"))))

        def dying_needs_critic(*args: object, **kwargs: object) -> object:
            raise CrashError("crash between candidate and critic")

        with mock.patch.object(output_module, "needs_critic", dying_needs_critic):
            with self.assertRaises(CrashError):
                self.run_worker(home)

        job = self.journal_job(home)
        self.assertEqual(job["stage"], jobs_mod.CANDIDATE_READY)
        self.assertIsNone(job["critic_payload"])

        summary = self.run_worker(home)  # restart
        self.assertEqual(summary["jobs_completed"], 1)
        self.assertEqual(backend.count_role("investigator"), 1)
        self.assertEqual(backend.count_role("critic"), 1)
        self.assertEqual(
            backend.role_of(1),
            "critic",
            "the restart's first NEW call must be the critic, not a re-investigation",
        )
        self.assertEqual(summary["receipts"][0]["verdict"], "DRIFT")

    def test_6_recovered_sampled_no_drift_still_invokes_critic(self) -> None:
        home = self.fresh_home("agent-noncompliance-command-route.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        # Deterministic sampling: every NO_DRIFT unit is sampled for a critic.
        # Recovery must re-run the SAME policy, so the persisted NO_DRIFT
        # cannot skip its critic after the restart.
        self.enable(home, backend, max_units_per_run=1)
        import os

        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 100
        config["budgets"]["max_wall_seconds"] = int(config["budgets"]["max_wall_seconds"])
        save_analyst_config(home, config)
        backend.script.append((200, envelope(self.candidate_json(home, "NO_DRIFT"))))
        backend.script.append((200, envelope(self.critic_json(home, "AGREE"))))

        def dying_needs_critic(*args: object, **kwargs: object) -> object:
            raise CrashError("crash before the policy decision")

        with mock.patch.object(output_module, "needs_critic", dying_needs_critic):
            with self.assertRaises(CrashError):
                self.run_worker(home)

        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1)
        self.assertGreaterEqual(backend.attempts, 2)
        self.assertEqual(
            backend.role_of(1),
            "critic",
            "the critic policy must survive the restart",
        )

    def test_7_critic_response_survives_crash_without_second_critic(self) -> None:
        home = self.fresh_home("agent-noncompliance-command-route.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, envelope(self.candidate_json(home, "DRIFT"))))
        backend.script.append((200, envelope(self.critic_json(home, "AGREE"))))

        def dying_parse_critic(*args: object, **kwargs: object) -> object:
            raise CrashError("crash between the critic write and its parse")

        with mock.patch.object(output_module, "parse_critic", dying_parse_critic):
            with self.assertRaises(CrashError):
                self.run_worker(home)

        job = self.journal_job(home)
        self.assertEqual(job["stage"], jobs_mod.CRITIC_CALLING)
        self.assertIsNotNone(job["critic_response_text"])
        self.assertIsNone(job["critic_payload"])

        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1)
        self.assertEqual(
            backend.count_role("critic"), 1, "the persisted critic must never be paid twice"
        )
        job = self.journal_job(home)
        self.assertEqual(job["stage"], jobs_mod.DONE)

    def test_8_finalizer_response_survives_crash_without_second_finalizer(self) -> None:
        home = self.fresh_home("agent-noncompliance-command-route.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, envelope(self.candidate_json(home, "DRIFT"))))
        backend.script.append((200, envelope(self.critic_json(home, "DISAGREE"))))
        backend.script.append((200, envelope(self.candidate_json(home, "NO_DRIFT"))))

        real_validate = output_module.validate_candidate
        calls = {"n": 0}

        def second_call_dies(*args: object, **kwargs: object) -> object:
            calls["n"] += 1
            if calls["n"] == 2:
                raise CrashError("crash between the finalizer write and its parse")
            return real_validate(*args, **kwargs)

        with mock.patch.object(output_module, "validate_candidate", second_call_dies):
            with self.assertRaises(CrashError):
                self.run_worker(home)

        job = self.journal_job(home)
        self.assertEqual(job["stage"], jobs_mod.FINALIZER_CALLING)
        self.assertIsNotNone(job["finalizer_response_text"])

        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1)
        self.assertEqual(backend.count_role("finalizer"), 1)

    def test_9_crash_before_submit_resubmits_from_final_ready(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, envelope(self.candidate_json(home))))

        real_stage = worker_module._stage

        def dying_stage(root, journal, job, to_state, **fields: object) -> None:
            if to_state == jobs_mod.SUBMITTING:
                raise CrashError("crash between FINAL_READY and the submit write")
            return real_stage(root, journal, job, to_state, **fields)

        with mock.patch.object(worker_module, "_stage", dying_stage):
            with self.assertRaises(CrashError):
                self.run_worker(home)

        job = self.journal_job(home)
        self.assertEqual(job["stage"], jobs_mod.FINAL_READY)

        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1)
        self.assertEqual(backend.attempts, 1)

    def test_10_crash_after_kernel_commit_converges_to_one_receipt(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, envelope(self.candidate_json(home))))
        backend.script.append((200, envelope(self.candidate_json(home))))

        real_submit = submit_module.submit_candidate

        def commit_then_die(*args: object, **kwargs: object) -> object:
            receipt = real_submit(*args, **kwargs)  # the kernel committed
            raise CrashError("process died before the DONE write")

        with mock.patch.object(submit_module, "submit_candidate", commit_then_die):
            with self.assertRaises(CrashError):
                self.run_worker(home)

        job = self.journal_job(home)
        self.assertEqual(job["stage"], jobs_mod.SUBMITTING)

        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1)
        job = self.journal_job(home)
        self.assertEqual(job["stage"], jobs_mod.DONE)
        self.assertIsNotNone(job["receipt_id"])
        # The restart's submission must be the SAME candidate and converge to
        # the SAME receipt: kernel idempotency, no duplicate semantic effect.
        _status, receipts_payload, _detail = submit_module.load_receipts(home)
        self.assertIsNotNone(receipts_payload)
        self.assertEqual(len(receipts_payload.get("receipts") or []), 1)


class TransportFailures(RepairBase):
    def _scripted_home(self) -> tuple[Path, StubBackend]:
        home = self.fresh_home("conformant-cold.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        return home, backend

    def test_11_429_then_success_retries_in_budget(self) -> None:
        home, backend = self._scripted_home()
        self.enable(home, backend, max_units_per_run=1)
        clock = FakeClock()
        backend.script.append((429, b'{"error": "slow down"}'))
        backend.script.append((200, envelope(self.candidate_json(home))))

        summary = self.run_worker(home, clock)
        self.assertEqual(backend.attempts, 2)
        self.assertEqual(summary["model_calls"], 2)
        self.assertEqual(summary["rate_limited"], 1)
        self.assertEqual(summary["jobs_completed"], 1)
        self.assertEqual(len(summary["receipts"]), 1)

    def test_12_503_then_success_converges(self) -> None:
        home, backend = self._scripted_home()
        self.enable(home, backend)
        clock = FakeClock()
        backend.script.append((503, b"{}"))
        backend.script.append((200, envelope(self.candidate_json(home))))

        summary = self.run_worker(home, clock)
        self.assertEqual(summary["jobs_completed"], 1)
        self.assertEqual(backend.attempts, 2)
        self.assertEqual(len(summary["receipts"]), 1)

    def test_13_timeout_then_success_retries(self) -> None:
        home, backend = self._scripted_home()
        self.enable(home, backend)
        clock = FakeClock()
        backend.script.append((200, envelope(self.candidate_json(home))))

        original = transport_module.call

        def timeout_first(*args: object, **kwargs: object) -> object:
            timeout_first.calls += 1
            if timeout_first.calls == 1:
                from saipal_analyst.backend import RETRYABLE, ModelReply

                return ModelReply(
                    ok=False,
                    failure_class=RETRYABLE,
                    detail="request to model endpoint timed out",
                    latency_seconds=1.0,
                    timed_out=True,
                )
            return original(*args, **kwargs)

        timeout_first.calls = 0
        with mock.patch.object(transport_module, "call", timeout_first):
            summary = self.run_worker(home, clock)

        self.assertEqual(summary["jobs_completed"], 1)
        self.assertEqual(summary["timeouts"], 1)
        self.assertEqual(len(summary["receipts"]), 1)

    def test_14_401_blocks_with_one_request_and_no_retry(self) -> None:
        home, backend = self._scripted_home()
        self.enable(home, backend)
        backend.script.append((401, b'{"error": "nope"}'))

        summary = self.run_worker(home)
        self.assertEqual(backend.attempts, 1)
        self.assertEqual(summary["model_calls"], 1)
        self.assertEqual(summary["stop_reason"], "BLOCKED")
        job = self.journal_job(home)
        self.assertEqual(job["stage"], jobs_mod.BLOCKED)
        self.assertEqual(job["error_class"], "BACKEND_AUTH")

    def test_15_missing_key_makes_zero_requests(self) -> None:
        """Fail closed where the credential matters: a REMOTE endpoint.

        The credential requirement is an egress requirement. A loopback endpoint
        has no remote party to authenticate to, so an unset key is inert there and
        the call proceeds header-less (test_wave_analyst_backend and
        test_wave_analyst_config carry that control). The refusal this test guards
        is the egress one: remote party, no credential -- zero requests.
        """
        home, backend = self._scripted_home()
        config = self.enable(home, backend)
        config["backend"]["endpoint"] = "https://analyst.invalid/v1/chat/completions"
        config["egress"]["allow_remote_evidence"] = True
        save_analyst_config(home, config)
        import os

        os.environ.pop("SAIPAL_ANALYST_API_KEY", None)
        summary = self.run_worker(home)
        self.assertEqual(backend.attempts, 0)
        self.assertEqual(summary["stop_reason"], "BLOCKED")
        job = self.journal_job(home)
        self.assertEqual(job["error_class"], "BACKEND_AUTH")


class RetryWaiting(RepairBase):
    def test_16_retry_waits_until_due_with_zero_calls_before(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        clock = FakeClock()
        backend.script.append((429, b"{}"))
        backend.script.append((200, envelope(self.candidate_json(home))))

        first = self.run_worker(home, clock)
        # First run: the retryable failure persists RETRY_WAIT, then the
        # same run sleeps (injected clock: free) to its own due time and
        # retries -- one run converges through the backlog within budget.
        self.assertEqual(first["jobs_completed"], 1)
        self.assertEqual(backend.attempts, 2)
        self.assertGreater(len(clock.slept), 0, "the bounded wait must be slept, not spun")

        # A future RETRY_WAIT with the due time still ahead makes zero calls
        # before it is due: the allocator reports the future wait truthfully
        # and the worker stops without hammering the backend.
        clock2 = FakeClock()
        home2 = self.fresh_home("conformant-cold.json")
        backend2 = StubBackend()
        self.addCleanup(backend2.stop)
        self.enable(home2, backend2)
        # An already-waiting job whose due time is in the future.
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.registry import load_registry
        from saipal_engine.sessions import load_index as _load_index

        _status, index, _d = _load_index(home2)
        rec = carrier_mod.freshest_records(index)[0]
        digest = carrier_mod.unit_digest(rec, rec["episodes"][0], 0)
        job = jobs_mod.new_job(
            session_id=str(rec["session_id"]),
            episode_index=int(rec["episodes"][0]["index"]),
            slice_index=0,
            unit_digest=digest,
            finality="FINAL",
            backend_type="openai_compatible",
            model="stub-model",
            run_id="run-future",
        )
        job["transport_attempts"] = 1
        job["stage"] = jobs_mod.RETRY_WAIT
        job["next_retry_at"] = clock2.wall_now() + 3600
        journal = jobs_mod.load_journal(home2)
        journal["jobs"][job["job_id"]] = job
        jobs_mod.save_journal(home2, journal)
        backend2.script.append((200, envelope(
            json.dumps(
                {
                    "schema_version": 1,
                    "verdict": "NO_DRIFT",
                    "unit_digest": digest,
                    "session_id": str(rec["session_id"]),
                    "episode_index": int(rec["episodes"][0]["index"]),
                    "slice_index": 0,
                    "disposition_class": "NO_DRIFT",
                    "reasoning": "clean",
                    "event_refs": [rec["episodes"][0]["start_seq"]],
                }
            )
        )))
        summary_future = investigate(home2, clock=clock2.as_worker_clock())
        self.assertEqual(summary_future["stop_reason"], "RETRY_WAIT")
        self.assertEqual(backend2.attempts, 0, "no calling before the retry is due")
        self.assertEqual(clock2.slept, [])
        backend2.stop()

    def test_17_retry_due_resumes(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        clock = FakeClock()
        backend.script.append((429, b"{}"))
        backend.script.append((200, envelope(self.candidate_json(home))))

        summary = self.run_worker(home, clock)
        self.assertEqual(summary["jobs_completed"], 1)
        self.assertEqual(backend.attempts, 2)
        self.assertEqual(summary["model_calls"], 2)

    def test_16b_future_retry_deferred_while_other_work_runs(self) -> None:
        home = self.fresh_home("conformant-cold.json", "no-finding-normal.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.sessions import load_index as _load_index

        _status, index, _d = _load_index(home)
        ordered = carrier_id_order(index)
        newest, oldest = ordered[0], ordered[-1]
        # Attach the retrying unit to the FRESHEST record, so scanning finds
        # the RETRY_WAIT first and must keep scanning instead of stopping.
        newest_digest = carrier_mod.unit_digest(newest, newest["episodes"][0], 0)
        newest_id = jobs_mod.unit_job_id(
            str(newest["session_id"]), int(newest["episodes"][0]["index"]), 0, newest_digest
        )
        journal = jobs_mod.load_journal(home)
        job = jobs_mod.new_job(
            session_id=str(newest["session_id"]),
            episode_index=int(newest["episodes"][0]["index"]),
            slice_index=0,
            unit_digest=newest_digest,
            finality="FINAL",
            backend_type="openai_compatible",
            model="stub-model",
            run_id="run-wait",
        )
        job["stage"] = jobs_mod.RETRY_WAIT
        job["transport_attempts"] = 1
        job["next_retry_at"] = FakeClock().wall_now() + 3600
        journal["jobs"][newest_id] = job
        jobs_mod.save_journal(home, journal)

        clock = FakeClock()
        backend.script.append(
            (200, envelope(self.candidate_for(home, "NO_DRIFT", str(oldest["session_id"]))))
        )
        summary = self.run_worker(home, clock)
        self.assertEqual(summary["jobs_completed"], 1, "eligible work must run while one job waits")
        self.assertEqual(backend.attempts, 1)
        journal = jobs_mod.load_journal(home)
        self.assertEqual(journal["jobs"][newest_id]["stage"], jobs_mod.RETRY_WAIT)


class Accounting(RepairBase):
    def test_18_one_request_is_one_model_call(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, envelope(self.candidate_json(home))))

        summary = self.run_worker(home)
        self.assertEqual(backend.attempts, 1)
        self.assertEqual(summary["model_calls"], 1)

    def test_19_three_roles_are_three_model_calls(self) -> None:
        home = self.fresh_home("agent-noncompliance-command-route.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, envelope(self.candidate_json(home, "DRIFT"))))
        backend.script.append((200, envelope(self.critic_json(home, "DISAGREE"))))
        backend.script.append((200, envelope(self.candidate_json(home, "NO_DRIFT"))))

        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1)
        self.assertEqual(summary["model_calls"], 3)
        self.assertEqual(summary["investigator_calls"], 1)
        self.assertEqual(summary["critic_calls"], 1)
        self.assertEqual(summary["finalizer_calls"], 1)

    def test_20_mid_deliberation_budget_stop_resumes_exact_stage(self) -> None:
        home = self.fresh_home("agent-noncompliance-command-route.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend, max_model_calls_per_run=1)
        backend.script.append((200, envelope(self.candidate_json(home, "DRIFT"))))
        backend.script.append((200, envelope(self.critic_json(home, "AGREE"))))
        backend.script.append((200, envelope(self.candidate_json(home, "DRIFT"))))

        stopped = self.run_worker(home)
        self.assertEqual(stopped["stop_reason"], "BUDGET_EXHAUSTED")
        job = self.journal_job(home)
        self.assertEqual(job["stage"], jobs_mod.CRITIC_CALLING)

        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 0
        config["budgets"]["max_model_calls_per_run"] = 5
        config["budgets"]["max_units_per_run"] = 1
        save_analyst_config(home, config)

        resumed = self.run_worker(home)
        self.assertEqual(resumed["jobs_completed"], 1)
        self.assertEqual(
            backend.count_role("investigator"), 1,
            "the restart must resume with the critic, not re-investigate"
        )
        self.assertEqual(backend.count_role("critic"), 1)


class Scheduling(RepairBase):
    def test_21_newest_unknown_does_not_starve_older_bound(self) -> None:
        home = self.fresh_home("conformant-cold.json", "unknown-protocol.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, envelope(self.candidate_json(home))))

        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1, "the BOUND unit must be processed")
        journal = jobs_mod.load_journal(home)
        stages = {job["stage"] for job in journal["jobs"].values()}
        self.assertIn(jobs_mod.BLOCKED_BINDING, stages, "the UNKNOWN unit must be recorded")
        self.assertIn(jobs_mod.DONE, stages)

    def test_22_hot_provisional_does_not_starve_cold_final(self) -> None:
        home = self.fresh_home("conformant-cold.json", "hot-extended.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, envelope(self.candidate_json(home))))

        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1)
        journal = jobs_mod.load_journal(home)
        done_jobs = [job for job in journal["jobs"].values() if job["stage"] == jobs_mod.DONE]
        self.assertEqual(len(done_jobs), 1)
        self.assertNotEqual(
            done_jobs[0]["finality"],
            "PROVISIONAL",
            "provisional work must not be selected while disabled",
        )

    def test_23_blocked_binding_reactivates_when_authority_binds(self) -> None:
        home = self.fresh_home("unknown-protocol.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)

        blocked = self.run_worker(home)
        self.assertEqual(blocked["stop_reason"], "BLOCKED")
        self.assertEqual(backend.attempts, 0)
        job = self.journal_job(home)
        self.assertEqual(job["stage"], jobs_mod.BLOCKED_BINDING)
        job_id = job["job_id"]

        # Authority arrives: the session record's binding proof is recomputed
        # in place (the T-87 rebind outcome). Evidence identity -- and therefore
        # the job id -- is unchanged.
        from saipal_engine.paths import home_paths

        index_path = home_paths(home).sessions_index
        index = json.loads(index_path.read_text(encoding="utf-8"))
        for record in index.get("sessions", []):
            protocol = record.get("protocol")
            if isinstance(protocol, dict):
                protocol["binding_status"] = "BOUND"
                protocol["proof_level"] = "RELEASE_REGISTRY"
        index_path.write_text(json.dumps(index), encoding="utf-8")

        backend.script.append((200, envelope(self.candidate_json(home))))
        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1, "reactivation must process the job")
        self.assertEqual(backend.attempts, 1)
        journal = jobs_mod.load_journal(home)
        reactivated = journal["jobs"].get(job_id)
        self.assertIsNotNone(reactivated)
        self.assertEqual(reactivated["stage"], jobs_mod.DONE)

    def test_24_one_permanently_blocked_job_does_not_freeze_work(self) -> None:
        home = self.fresh_home("conformant-cold.json", "agent-noncompliance-command-route.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        from saipal_engine.sessions import load_index as _load_index

        _status, index, _d = _load_index(home)
        ordered = carrier_id_order(index)
        newest, oldest = ordered[0], ordered[-1]
        ids = self.pending_job_ids(home)
        self.assertEqual(len(ids), 2)
        journal = jobs_mod.load_journal(home)
        blocked_job = jobs_mod.new_job(
            session_id=str(newest["session_id"]),
            episode_index=int(newest["episodes"][0]["index"]),
            slice_index=0,
            unit_digest=_newest_digest(newest),
            finality="FINAL",
            backend_type="openai_compatible",
            model="stub-model",
            run_id="operator",
        )
        blocked_job["job_id"] = ids[0]
        blocked_job["stage"] = jobs_mod.BLOCKED
        blocked_job["error_class"] = "OPERATOR_BLOCK"
        journal["jobs"][ids[0]] = blocked_job
        jobs_mod.save_journal(home, journal)

        # The healthy session's unit is the one that must run.
        backend.script.append(
            (200, envelope(self.candidate_for(home, "NO_DRIFT", str(oldest["session_id"]))))
        )
        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1, "the healthy job must still run")
        self.assertEqual(backend.attempts, 1)
        journal = jobs_mod.load_journal(home)
        self.assertEqual(journal["jobs"][ids[0]]["stage"], jobs_mod.BLOCKED)


class RepairBudget(RepairBase):
    def test_repair_prompt_recovers_candidate_missing_required_reasoning(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        valid = json.loads(self.candidate_json(home))
        invalid = dict(valid)
        invalid.pop("reasoning")
        invalid.pop("slice_index")
        invalid["unit_digest"] = (
            ("0" if valid["unit_digest"][0] != "0" else "1")
            + valid["unit_digest"][1:]
        )
        invalid["disposition_class"] = "COMPLIANT"
        invalid["confidence"] = "HIGH"
        invalid["severity"] = None
        invalid["mitigations"] = []
        invalid["turn_digest"] = "invented"
        backend.script.append((200, envelope(json.dumps(invalid))))
        backend.script.append((200, envelope(json.dumps(valid))))

        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1)
        self.assertEqual(backend.attempts, 2)
        repair_prompt = backend.requests[1]["body"]["messages"][1]["content"]
        required_fields = require_string_list(
            load_registry(), "candidate_required_fields"
        )

        self.assertIn(
            ", ".join(f'"{field}"' for field in required_fields), repair_prompt
        )
        self.assertIn("Repair the complete candidate", repair_prompt)
        self.assertIn("keep reasoning a non-empty string", repair_prompt)
        self.assertIn("Preserve valid evidence-based content", repair_prompt)
        self.assertIn("REJECTED MODEL OUTPUT", repair_prompt)
        self.assertIn("Exact top-level fields:", repair_prompt)
        self.assertIn(
            "missing_evidence, protected_invariants, and addressed_defences are arrays of strings",
            repair_prompt,
        )
        self.assertIn("disposition_class must be one of:", repair_prompt)
        self.assertIn("If the packet contains slice_index", repair_prompt)
        self.assertIn("EXACT IDENTITY VALUES", repair_prompt)
        self.assertIn(f'"unit_digest": "{valid["unit_digest"]}"', repair_prompt)
        self.assertIn("For NO_DRIFT and INSUFFICIENT_EVIDENCE", repair_prompt)
        self.assertIn("Do not use mitigations or turn_digest", repair_prompt)

    def test_25_malformed_repair_429_recovers_after_retry(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        clock = FakeClock()
        good = self.candidate_json(home)
        backend.script.append((200, envelope("{not json")))  # investigator: malformed
        # repair call: transport failure
        backend.script.append((429, b"{}"))
        backend.script.append((200, envelope(good)))  # retried repair: valid

        summary = self.run_worker(home, clock)
        # The 429'd repair persists RETRY_WAIT under the bounded backoff; the
        # same run waits to the due time (injected clock: free) and retries.
        self.assertEqual(summary["jobs_completed"], 1)
        self.assertEqual(backend.attempts, 3)
        self.assertEqual(summary["model_calls"], 3)
        self.assertEqual(summary["rate_limited"], 1)
        job = self.journal_job(home)
        self.assertEqual(job["stage"], jobs_mod.DONE)
        self.assertEqual(
            job["investigator_repairs"], 1, "the durable semantic repair was consumed once"
        )
        self.assertEqual(
            job["transport_attempts"], 1, "the transport retry of the repair is a transport fact"
        )

    def test_26_repair_budget_survives_restart(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        backend.script.append((200, envelope("{still not json")))  # investigator
        backend.script.append((200, envelope("{repair also broken")))  # repair

        first = self.run_worker(home)
        self.assertEqual(first["stop_reason"], "BLOCKED")
        job = self.journal_job(home)
        self.assertEqual(job["investigator_repairs"], 1)
        self.assertEqual(backend.attempts, 2)

        # Restart: the job is terminal, the spent repair budget is not reset,
        # and no further model call is made.
        second = self.run_worker(home)
        self.assertEqual(backend.attempts, 2)
        self.assertEqual(second["jobs_completed"], 0)
        job = self.journal_job(home)
        self.assertEqual(job["stage"], jobs_mod.BLOCKED)
        self.assertEqual(job["investigator_repairs"], 1)


class BlockedTriage(RepairBase):
    """`blocked_triage`: which class of session is unanalyzable, and the ACTIONS.

    A blocked population is an operator decision only if the operator can see the
    classes and what each one costs. Two of the three classes have a canonical
    command; the third does not, and saying so is the honest answer.
    """

    def _triage(self, home: Path) -> dict:
        from saipal_analyst.doctor import blocked_triage

        return blocked_triage(home)

    def _group(self, triage: dict, klass: str) -> dict:
        rows = [row for row in triage["groups"] if row["class"] == klass]
        self.assertTrue(rows, f"expected a {klass} group in {triage['groups']}")
        return rows[0]

    def test_a_binding_wall_names_the_authority_command(self) -> None:
        home = self.fresh_home("unknown-protocol.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)

        self.run_worker(home)
        triage = self._triage(home)

        group = self._group(triage, "BLOCKED_BINDING")
        self.assertGreaterEqual(group["count"], 1)
        self.assertIn("coverage", group["command"])
        self.assertIn("rebind", group["then"])
        self.assertTrue(group["recoverable"])
        self.assertEqual(triage["runnable"], 0)
        self.assertIn("coverage", triage["next_action"])
        self.assertNotIn("BLOCKED_BINDING", triage["no_canonical_action"])

    def test_an_output_wall_names_the_canonical_requeue(self) -> None:
        """T-136: the refusal class now HAS a path back, and the triage says so.

        Before the requeue contract existed this class was the honest gap: the
        triage named it under `no_canonical_action`. It is now actionable, so
        the same read-only surface must report the command AND whether the
        command would actually do anything right now.
        """
        home, _order = self._two_session_home()
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend, max_units_per_run=3)
        for _ in range(2):
            backend.script.append((200, envelope("{not json")))
            backend.script.append((200, envelope("{repair broken")))

        self.run_worker(home)
        triage = self._triage(home)

        group = self._group(triage, "BLOCKED_OUTPUT")
        self.assertEqual(group["count"], 2)
        self.assertIn("analyst-requeue", group["command"])
        self.assertTrue(group["recoverable"])
        self.assertIn("does not repair the model", group["caveat"])
        self.assertEqual(group["requeue_ready"], 2)
        self.assertEqual(group["requeue_refused"], 0)
        self.assertEqual(triage["no_canonical_action"], [])
        self.assertIn("analyst-requeue", triage["next_action"])
        self.assertEqual(triage["blocked_total"], 2)

    def test_a_drained_home_reports_nothing_to_unblock(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend, max_units_per_run=1)
        # The candidate must answer the unit actually served, and the session is
        # drained one episode at a time: build it per request, from the carrier
        # the worker sent.
        backend.on_request = lambda request: backend.script.append(
            (200, envelope(self.candidate_for(home, "NO_DRIFT")))
        )
        for _ in range(12):
            if self.run_worker(home)["stop_reason"] == "IDLE":
                break

        triage = self._triage(home)
        self.assertEqual(triage["blocked_total"], 0)
        self.assertEqual(triage["groups"], [])
        self.assertEqual(triage["no_canonical_action"], [])
        self.assertEqual(triage["runnable"], 0)
        self.assertIn("nothing to unblock", triage["next_action"])

    def test_the_binding_wall_says_which_units_an_enrollment_can_move(self) -> None:
        """PAL-CPALL-04: name WHICH decision makes a refused unit eligible.

        The wall published one command for the whole BLOCKED_BINDING class, but
        the command only moves a unit whose session carries an artifact an
        authority root can actually check -- a full commit id, a registry
        digest or a tree fingerprint. A version claim with no digest, or no
        claim at all, has nothing to verify: measured on the real home, 418 of
        425 blocked units were evidence-absent, so running the recommended
        command on them was the one action that cannot work.
        """
        for fixture, movable in (
            ("version-only-protocol.json", False),
            ("unknown-protocol.json", False),
        ):
            with self.subTest(fixture=fixture):
                home = self.fresh_home(fixture)
                backend = StubBackend()
                self.addCleanup(backend.stop)
                self.enable(home, backend)
                self.run_worker(home)

                group = self._group(self._triage(home), "BLOCKED_BINDING")
                evidence = group["binding_evidence"]
                self.assertEqual(
                    evidence["authority_verifiable"] + evidence["evidence_absent"],
                    group["count"],
                    "the split must partition the class, not restate it",
                )
                if movable:
                    self.assertEqual(evidence["authority_verifiable"], group["count"])
                else:
                    self.assertEqual(evidence["evidence_absent"], group["count"])
                self.assertIn("binding_evidence", group["caveat"])

    def test_a_verifiable_claim_counts_as_enrol_movable(self) -> None:
        """The complement: a full commit id IS something a root can check."""
        home = self.fresh_home("unverifiable-commit.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)
        self.run_worker(home)

        group = self._group(self._triage(home), "BLOCKED_BINDING")
        evidence = group["binding_evidence"]
        self.assertEqual(evidence["authority_verifiable"], group["count"])
        self.assertEqual(evidence["evidence_absent"], 0)

    def test_the_read_only_command_exposes_the_triage(self) -> None:
        home = self.fresh_home("unknown-protocol.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend)

        code, payload, err = support.run_saipal_json("analyst-doctor", home=home)
        self.assertEqual(code, 0, err)
        blocked = payload.get("blocked") or {}
        self.assertIn("groups", blocked)
        self.assertIn("next_action", blocked)
        self.assertEqual(blocked["population"], 1)

    # -- T-158 ---------------------------------------------------------------
    # The provisional class is decided BEFORE the terminal-job check and before
    # the binding guard, so `--with-provisional` RECLASSIFIES its members
    # instead of releasing them. Publishing that flag for the whole class was
    # the T-145 dead end wearing a different label: the named command runs,
    # admits nothing, and reads like progress. Measured on the real home,
    # 246 of 246 reclassified (196 TERMINAL, 50 BLOCKED_BINDING) and the
    # command served zero.

    def test_the_provisional_split_partitions_the_class(self) -> None:
        from saipal_analyst.doctor import _provisional_admission

        split = {"TERMINAL": 196, "BLOCKED_BINDING": 50}
        out = _provisional_admission(split)

        self.assertEqual(out["provisional_admission"], 0)
        self.assertEqual(out["not_admitted"], split)
        self.assertEqual(
            out["provisional_admission"] + sum(split.values()),
            246,
            "the split must partition the class, not restate it",
        )

    def test_an_unadmittable_class_names_no_command(self) -> None:
        from saipal_analyst.doctor import _provisional_admission

        out = _provisional_admission({"TERMINAL": 3})
        self.assertIsNone(out["command"])
        self.assertFalse(out["recoverable"])
        self.assertIn("3 TERMINAL", out["caveat"])

    def test_an_admittable_class_keeps_its_command_and_counts_the_rest(self) -> None:
        from saipal_analyst.doctor import _provisional_admission

        out = _provisional_admission({"RUNNABLE_PROVISIONAL": 4, "TERMINAL": 6})
        self.assertEqual(out["provisional_admission"], 4)
        self.assertNotIn("command", out, "an admitted half keeps the table's command")
        self.assertIn("admits 4 of these unit(s)", out["caveat"])
        self.assertIn("6 TERMINAL", out["caveat"])

    def test_a_refused_provisional_unit_is_not_admitted_by_the_flag(self) -> None:
        """The human surface must not print a command the flag cannot run.

        Every split the allocator can produce for this class is refused except
        the one half a `--with-provisional` run actually serves, so the class
        has no canonical action whenever the split is not that half.
        """
        import saipal

        for split in (
            {"TERMINAL": 1},
            {"BLOCKED_BINDING": 2},
            {"TERMINAL": 196, "BLOCKED_BINDING": 50},
            {"REMOTE_OUTCOME_UNKNOWN": 5},
        ):
            with self.subTest(split=split):
                from saipal_analyst.doctor import _provisional_admission

                group = dict(_provisional_admission(split))
                group.update({"class": "PROVISIONAL_DISABLED", "count": sum(split.values())})
                text = saipal.render_human({
                    "analyst_doctor": True,
                    "config_present": True,
                    "enabled": True,
                    "backend_type": "openai_compatible",
                    "model": "stub",
                    "endpoint": "http://127.0.0.1:1/v1",
                    "endpoint_local": True,
                    "api_key_env": "K",
                    "api_key_env_present": False,
                    "journal_present": True,
                    "worker_active": False,
                    "semantic": {},
                    "config_problems": [],
                    "blocked": {
                        "population": sum(split.values()),
                        "runnable": 0,
                        "blocked_total": sum(split.values()),
                        "groups": [group],
                        "no_canonical_action": ["PROVISIONAL_DISABLED"],
                        "next_action": "nothing canonical remains to run",
                    },
                })
                self.assertIn("no command moves these units", text)
                self.assertIn("--with-provisional admits 0:", text)
                self.assertNotIn("investigate --with-provisional --max-units", text)

    def test_the_split_counts_the_class_members_and_nobody_else(self) -> None:
        """The split qualifies THIS class, so it may not restate the home.

        Counting every record's post-flag class made the rendered detail sum to
        the whole home (738) while the group header read 246, which reads as a
        partition of the class and is not one.
        """
        from saipal_analyst import doctor as doctor_mod
        from saipal_analyst import worker as worker_mod

        home = self.fresh_home("unknown-protocol.json")
        seen: list[tuple[bool, str]] = []

        real = worker_mod._classify_unit

        def fake(record, event_limit, journal, provisional, now, *a, **kw):
            # Only the flag-OFF view decides membership; the flag-ON view decides
            # where a member lands. Every record is a member and every member
            # reclassifies, so a split that counted the whole home twice would
            # still look plausible here and sum to twice the class.
            seen.append((bool(provisional), "TERMINAL"))
            return "TERMINAL" if provisional else "PROVISIONAL_DISABLED"

        worker_mod._classify_unit = fake
        self.addCleanup(setattr, worker_mod, "_classify_unit", real)

        triage = doctor_mod.blocked_triage(home)
        group = self._group(triage, "PROVISIONAL_DISABLED")

        self.assertEqual(group["count"], triage["population"])
        self.assertEqual(
            group["provisional_admission"] + sum(group["not_admitted"].values()),
            group["count"],
            "the split must partition the class it qualifies",
        )
        self.assertEqual(group["not_admitted"], {"TERMINAL": triage["population"]})
        self.assertEqual(
            [flag for flag, _ in seen],
            [False, True] * triage["population"],
            "the flag-ON pass runs once per member and no more",
        )


class BlockedUnitIsolation(RepairBase):
    """One inadmissible unit must not consume another session's turn.

    A blocked unit is a property of THAT unit, exactly as a CONFLICT is a
    property of one session. Ending the slice on the first block made one bad
    model response cost every other eligible session its place -- the same
    global freeze PAL-CPALL-03 forbids between families, observed on the real
    home: 18,364 pending episodes and a 9B model that answers some units with
    invalid JSON.
    """

    def test_a_blocked_unit_does_not_end_a_slice_that_has_other_sessions(self) -> None:
        home, order = self._two_session_home()
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend, max_units_per_run=2)

        # The serve order is the scheduler's decision, not this test's: the reply
        # is built per REQUEST from the carrier the worker actually sent, so the
        # first session it serves is the one whose model output is inadmissible
        # (investigator AND its repair) and every other session gets a valid one.
        state: dict = {"first": None}

        def answer_from_request(request: dict) -> None:
            user = str((request.get("body") or {}).get("messages", [{}])[-1].get("content", ""))
            marker = user.find('"session_id": "')
            session = ""
            if marker >= 0:
                session = user[marker + len('"session_id": "'):].split('"', 1)[0]
            if state["first"] is None:
                state["first"] = session
            if session == state["first"]:
                backend.script.append((200, envelope("{still not json")))
            else:
                backend.script.append(
                    (200, envelope(self.candidate_for(home, "NO_DRIFT", session)))
                )

        backend.on_request = answer_from_request

        summary = self.run_worker(home)

        self.assertEqual(summary["jobs_blocked"], 1,
                         "the inadmissible unit is blocked and counted")
        self.assertEqual(summary["jobs_completed"], 1,
                         "the OTHER session was still judged in the same run")
        self.assertEqual(summary["units"], 2)
        self.assertEqual(summary["stop_reason"], "BUDGET_EXHAUSTED",
                         "a run that judged a unit stops on its budget, not as BLOCKED")
        self.assertIn(state["first"], order)
        self.assertEqual(
            [row["session_id"] for row in summary["receipts"]],
            [session for session in order if session != state["first"]],
        )

        journal = jobs_mod.load_journal(home)
        stages = {
            str(job["session_id"]): job["stage"]
            for job in (journal.get("jobs") or {}).values()
        }
        self.assertEqual(stages[state["first"]], jobs_mod.BLOCKED)
        self.assertEqual(len(stages), 2, "both sessions were attempted in one run")
        self.assertEqual(
            sorted(stages.values()), sorted([jobs_mod.BLOCKED, jobs_mod.DONE])
        )

    def test_the_slice_still_names_the_wall_when_only_blocks_were_left(self) -> None:
        home, order = self._two_session_home()
        backend = StubBackend()
        self.addCleanup(backend.stop)
        # Budget ABOVE the blocked population, so the allocator is consulted once
        # more and answers for itself that nothing eligible is left.
        self.enable(home, backend, max_units_per_run=3)

        for _ in range(2):
            backend.script.append((200, envelope("{not json")))
            backend.script.append((200, envelope("{repair broken")))

        summary = self.run_worker(home)

        self.assertEqual(summary["jobs_completed"], 0)
        self.assertEqual(summary["jobs_blocked"], 2)
        self.assertEqual(summary["stop_reason"], "BLOCKED",
                         "an unproductive run says BLOCKED, never a healthy stop")
        self.assertIn("blocked", str(summary["detail"]).lower())
        self.assertTrue(summary["no_eligible_unit"],
                        "the allocator exhausted the eligible set and said so in a "
                        "structured field, not only in prose")

    def test_an_idle_allocator_reports_its_population_classes(self) -> None:
        """"no analyzable episode is pending" must be countable, not just prose."""
        home = self.fresh_home("conformant-cold.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend, max_units_per_run=1)
        backend.script.append((200, envelope(self.candidate_for(home, "NO_DRIFT"))))

        # Every answer carries the population classes ...
        first = self.run_worker(home)
        self.assertEqual(first["jobs_completed"], 1)
        self.assertEqual(first["population_size"], 1)
        self.assertIn("RUNNABLE_FINAL", first["population_classes"])

        # ... and once the session is judged out, the empty answer is structured
        # too: nothing is runnable, nothing was blocked, the queue is really empty.
        idle = None
        for _ in range(12):
            result = self.run_worker(home)
            if result["stop_reason"] == "IDLE":
                idle = result
                break
        self.assertIsNotNone(idle, "the fixture must drain within the run budget")
        self.assertEqual(idle["jobs_completed"], 0)
        self.assertTrue(idle["no_analyzable_unit"])
        self.assertNotIn("no_eligible_unit", idle,
                         "no unit was blocked here: the queue really is empty")
        classes = idle["population_classes"]
        self.assertEqual(sum(int(count) for count in classes.values()), idle["population_size"])
        self.assertFalse(
            [name for name in classes if name.startswith("RUNNABLE")],
            "an idle allocator reports no runnable class",
        )
        self.assertIn("TERMINAL", classes)

    def test_a_slice_that_judged_a_unit_is_not_reported_as_exhausted(self) -> None:
        home, _order = self._two_session_home()
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend, max_units_per_run=1)
        backend.script.append(
            (200, envelope(self.candidate_for(home, "NO_DRIFT")))
        )

        summary = self.run_worker(home)
        self.assertEqual(summary["jobs_completed"], 1)
        self.assertNotIn("no_eligible_unit", summary,
                         "work remained after a judged unit: not an exhausted set")


class MidDeliberationBudgetBoundaries(RepairBase):
    """T-108 ROLE 25: every paid-stage boundary, proved per role.

    The budget is preventive and per-CALL. When the final available attempt
    is consumed by one role, the NEXT paid stage must not start: the durable
    stage reached so far is kept and the later role resumes on the next
    allowed run. No aggregate "HTTP attempts" hand-waving -- each control
    names the exact per-role call counts.
    """

    def _reconfigure(self, home: Path, backend: StubBackend, calls: int) -> None:
        from saipal_analyst.config import default_analyst_config, save_analyst_config

        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 0
        config["budgets"]["max_model_calls_per_run"] = calls
        config["budgets"]["max_units_per_run"] = 1
        save_analyst_config(home, config)

    def test_a_investigator_consumes_final_call_before_critic(self) -> None:
        """ROLE 25-A: investigator spends the last attempt; critic stays at 0."""
        home = self.fresh_home("agent-noncompliance-command-route.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend, max_model_calls_per_run=1)
        backend.script.append((200, envelope(self.candidate_json(home, "DRIFT"))))
        backend.script.append((200, envelope(self.critic_json(home, "AGREE"))))

        stopped = self.run_worker(home)
        self.assertEqual(stopped["stop_reason"], "BUDGET_EXHAUSTED")
        job = self.journal_job(home)
        # The investigator response is durable; the critic never ran.
        self.assertEqual(job["stage"], jobs_mod.CRITIC_CALLING)
        self.assertEqual(backend.count_role("investigator"), 1)
        self.assertEqual(backend.count_role("critic"), 0)
        self.assertEqual(backend.count_role("finalizer"), 0)
        self.assertIsNone(job.get("receipt_id"), "no receipt before deliberation ends")

        # Next allowed run: investigator additional = 0, critic resumes.
        self._reconfigure(home, backend, calls=4)
        resumed = self.run_worker(home)
        self.assertEqual(backend.count_role("investigator"), 1)
        self.assertEqual(backend.count_role("critic"), 1)
        self.assertEqual(resumed["jobs_completed"], 1)
        job = self.journal_job(home)
        self.assertTrue(job.get("receipt_id"))

    def test_b_budget_stops_before_finalizer(self) -> None:
        """ROLE 25-B: disagreement, but no attempt left for the finalizer."""
        home = self.fresh_home("agent-noncompliance-command-route.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend, max_model_calls_per_run=2)
        backend.script.append((200, envelope(self.candidate_json(home, "DRIFT"))))
        backend.script.append((200, envelope(self.critic_json(home, "DISAGREE"))))
        backend.script.append((200, envelope(self.candidate_json(home, "DRIFT"))))

        stopped = self.run_worker(home)
        self.assertEqual(stopped["stop_reason"], "BUDGET_EXHAUSTED")
        job = self.journal_job(home)
        self.assertEqual(job["stage"], jobs_mod.FINALIZER_CALLING)
        self.assertEqual(backend.count_role("finalizer"), 0)
        self.assertIsNone(job.get("receipt_id"))

        # Resume: investigator and critic additional = 0, finalizer runs.
        self._reconfigure(home, backend, calls=5)
        resumed = self.run_worker(home)
        self.assertEqual(backend.count_role("investigator"), 1)
        self.assertEqual(backend.count_role("critic"), 1)
        self.assertEqual(backend.count_role("finalizer"), 1)
        self.assertEqual(resumed["jobs_completed"], 1)

    def test_c_budget_stops_before_output_repair(self) -> None:
        """ROLE 25-C: a malformed paid response is deferred, never re-bought."""
        home = self.fresh_home("conformant-cold.json")
        backend = StubBackend()
        self.addCleanup(backend.stop)
        self.enable(home, backend, max_model_calls_per_run=1)
        backend.script.append((200, envelope("{malformed paid response")))
        backend.script.append((200, envelope(self.candidate_json(home))))

        stopped = self.run_worker(home)
        self.assertEqual(stopped["stop_reason"], "BUDGET_EXHAUSTED")
        job = self.journal_job(home)
        # The ORIGINAL malformed response stays durable; the repair is deferred.
        self.assertEqual(job["stage"], jobs_mod.INVESTIGATOR_RESPONSE)
        self.assertEqual(job["response_text"], "{malformed paid response")
        self.assertEqual(backend.attempts, 1)
        self.assertEqual(job["investigator_repairs"], 0)

        # Resume: the original call is not repeated -- only the repair is paid.
        self._reconfigure(home, backend, calls=4)
        resumed = self.run_worker(home)
        self.assertEqual(backend.attempts, 2, "one repair call, never a replay")
        self.assertEqual(job["investigator_repairs"], 0)  # journal re-read below
        job = self.journal_job(home)
        self.assertEqual(job["investigator_repairs"], 1)
        self.assertEqual(resumed["jobs_completed"], 1)


if __name__ == "__main__":
    unittest.main()
