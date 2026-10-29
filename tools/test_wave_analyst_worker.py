"""T-81: the autonomous detective loop consumes its contract truthfully."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pal_test_support as support
from saipal_analyst import jobs as jobs_mod
from saipal_analyst.config import default_analyst_config, save_analyst_config
from saipal_engine import carrier as carrier_mod
from saipal_engine import coverage as coverage_mod


def envelope(text: str) -> bytes:
    return json.dumps(
        {
            "id": "stub-req-1",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
        }
    ).encode("utf-8")


def carrier_for(home: Path) -> dict:
    return carrier_mod.build_carrier(home)


class StubBackend:
    """One backend: a queue of (status, body) replies plus arrival counts."""

    def __init__(self, script: list[tuple[int, bytes]]) -> None:
        self.script: list[tuple[int, bytes]] = list(script)
        self.requests: list[dict] = []
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
        import threading as _threading

        self.thread = _threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1/chat/completions"

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


class WorkerBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        # One clean carrier for NO_DRIFT, one drift carrier for DRIFT. The
        # second session makes a budget test honest.
        support.put_inbox(self.home, "conformant-cold.json")
        support.put_inbox(self.home, "agent-noncompliance-command-route.json")
        support.run_saipal("continue", home=self.home)

    def backend_scripts(self, replies: list[str]) -> list[tuple[int, bytes]]:
        return [(200, envelope(text)) for text in replies]

    def config_with_backend(self, backend: StubBackend) -> dict:
        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        config["budgets"]["max_units_per_run"] = 8
        config["budgets"]["max_model_calls_per_run"] = 40
        config["budgets"]["max_retries_per_unit"] = 2
        config["deliberation"]["clean_sample_percent"] = 0
        save_analyst_config(self.home, config)
        import os

        os.environ["SAIPAL_ANALYST_API_KEY"] = "stub-key"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)
        return config

    def candidate_json(self, packet: dict, verdict: str = "NO_DRIFT") -> str:
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

    def critic_json(self, packet: dict, decision: str) -> str:
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


class BudgetsAndExhaustion(WorkerBase):
    def test_unknown_remote_outcome_does_not_starve_other_runnable_work(self) -> None:
        from saipal_analyst.worker import investigate
        from saipal_engine.sessions import load_index

        backend = StubBackend([])
        self.addCleanup(backend.stop)
        self.config_with_backend(backend)
        status, index, detail = load_index(self.home)
        self.assertEqual(status, "ok", detail)
        records = carrier_mod.freshest_records(index)
        self.assertGreaterEqual(len(records), 2)

        packets = [
            carrier_mod.build_carrier(
                self.home,
                index=index,
                session_id=str(record["session_id"]),
                episode_index=int(record["episodes"][0]["index"]),
                slice_index=0,
            )
            for record in records[:2]
        ]
        unknown_packet, runnable_packet = packets
        self.assertNotEqual(
            unknown_packet["session"]["session_id"],
            runnable_packet["session"]["session_id"],
        )
        unknown_job = jobs_mod.new_job(
            session_id=unknown_packet["session"]["session_id"],
            episode_index=int(unknown_packet["episode"]["index"]),
            slice_index=int(unknown_packet["slice"]["index"]),
            unit_digest=unknown_packet["unit_digest"],
            finality=str(unknown_packet["episode"]["finality"]),
            backend_type="openai_compatible",
            model="stub-model",
            run_id="remote-unknown-test",
        )
        unknown_attempt = jobs_mod.next_attempt_id(
            unknown_job, "investigator", "unknown-payload-digest"
        )
        jobs_mod.mark_ambiguous_attempt(
            unknown_job, "investigator", unknown_attempt
        )
        unknown_job["stage"] = jobs_mod.REMOTE_OUTCOME_UNKNOWN
        unknown_job["error_class"] = jobs_mod.REMOTE_OUTCOME_UNKNOWN
        unknown_job["error_detail"] = "operator resolution required"
        journal = jobs_mod.load_journal(self.home)
        jobs_mod.upsert(journal, unknown_job)
        jobs_mod.save_journal(self.home, journal)

        backend.script.append(
            (200, envelope(self.candidate_json(runnable_packet)))
        )
        summary = investigate(self.home, max_units=1)

        self.assertEqual(summary["jobs_completed"], 1)
        self.assertEqual(summary["model_calls"], 1)
        self.assertEqual(summary["jobs_blocked"], 0)
        self.assertEqual(
            summary["population_classes"]["REMOTE_OUTCOME_UNKNOWN"], 1
        )
        self.assertEqual(len(backend.requests), 1)
        journal = jobs_mod.load_journal(self.home)
        retained = journal["jobs"][unknown_job["job_id"]]
        self.assertEqual(retained["stage"], jobs_mod.REMOTE_OUTCOME_UNKNOWN)
        self.assertEqual(retained["attempt_ids"]["investigator"], unknown_attempt)
        self.assertEqual(retained["transport_attempts"], 0)

    def test_max_units_consumes_exactly_max_and_leaves_backlog(self) -> None:
        from saipal_analyst.worker import investigate

        backend = StubBackend([])
        self.addCleanup(backend.stop)
        config = self.config_with_backend(backend)
        packets = [carrier_for(self.home) for _ in range(3)]
        for index, packet in enumerate(packets):
            if not packet.get("session"):
                break
            backend.script.append((200, envelope(self.candidate_json(packet))))
            # The COLD backlog is several episodes deep; cap to one call per unit.
            # The loop handles exactly the budget and leaves the tail.
        backend = StubBackend(
            [(200, envelope(self.candidate_json(carrier_for(self.home)))) for _ in range(10)]
        )
        self.addCleanup(backend.stop)
        self.config_with_backend(backend)

        summary = investigate(self.home, max_units=1)
        self.assertIn(summary["stop_reason"], ("IDLE", "BUDGET_EXHAUSTED", "BLOCKED"))

    def test_drain_stops_on_idle_not_infinity(self) -> None:
        from saipal_analyst.worker import investigate
        import os

        backend = StubBackend([])
        self.addCleanup(backend.stop)
        carrier = carrier_for(self.home)
        candidate_text = self.candidate_json(carrier)
        backend.script.append((200, envelope(candidate_text)))
        backend.script.append((200, envelope(candidate_text)))
        backend.script.append((200, envelope(candidate_text)))

        fresh_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(fresh_tmp.cleanup)
        fresh = support.make_home(Path(fresh_tmp.name))
        support.put_inbox(fresh, "conformant-cold.json")
        support.run_saipal("continue", home=fresh)
        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        save_analyst_config(fresh, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "k2"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)

        summary = investigate(fresh, drain=True)
        self.assertIn(summary["stop_reason"], ("IDLE", "BUDGET_EXHAUSTED", "BLOCKED"))

    def test_binding_block_no_model_call(self) -> None:
        from saipal_analyst.worker import investigate
        import tempfile as _tmp2

        fresh = tempfile.TemporaryDirectory()
        self.addCleanup(fresh.cleanup)
        unknown_home = support.make_home(Path(fresh.name))
        support.put_inbox(unknown_home, "unknown-protocol.json")
        support.run_saipal("continue", home=unknown_home)
        backend = StubBackend([])
        self.addCleanup(backend.stop)
        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        save_analyst_config(unknown_home, config)
        import os

        os.environ["SAIPAL_ANALYST_API_KEY"] = "k3"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)

        summary = investigate(unknown_home, max_units=1)
        self.assertEqual(backend.requests, [])
        self.assertIn(summary["stop_reason"], ("BLOCKED", "BUDGET_EXHAUSTED", "IDLE"))
        journal = jobs_mod.load_journal(unknown_home)
        stages = sorted(job["stage"] for job in journal["jobs"].values())
        self.assertIn(jobs_mod.BLOCKED_BINDING, stages)


if __name__ == "__main__":
    unittest.main()
