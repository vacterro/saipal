"""T-77: the text-only backend behaves like a boring, honest HTTP client.

A local stub server plays the provider, so the canonical suite never touches an
external endpoint and never spends a token. Every failure class the worker will
rely on is proven here against a real socket, not a mock.
"""

from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pal_test_support as support
from saipal_analyst import config as analyst_config
from saipal_analyst import openai_compatible as backend_mod
from saipal_analyst.backend import AUTH, LIMIT, OK, PERMANENT, RETRYABLE, UsageLedger


def envelope(text: str, *, usage: dict | None = None, request_id: str | None = None) -> bytes:
    payload = {
        "id": request_id or "chatcmpl-1",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text}}],
    }
    if usage:
        payload["usage"] = usage
    return (json.dumps(payload) + "\n").encode("utf-8")


class StubServer:
    """One-shot scriptable endpoint: a status code plus a body per request."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.script: list[tuple[int, bytes, float]] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                server.requests.append(
                    {
                        "headers": dict(self.headers.items()),
                        "body": json.loads(body.decode("utf-8")) if body else None,
                    }
                )
                status, raw, delay = server.script.pop(0) if server.script else (200, envelope("{}"), 0.0)
                if delay:
                    time.sleep(delay)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("x-request-id", "stub-req-1")
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args: object) -> None:  # silence the suite
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


class BackendBase(unittest.TestCase):
    def setUp(self) -> None:
        self.server = StubServer()
        self.addCleanup(self.server.stop)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        self.config = analyst_config.default_analyst_config()
        self.config["enabled"] = True
        self.config["backend"]["endpoint"] = self.server.endpoint()
        self.config["backend"]["model"] = "stub-model"
        # Deterministic key presence: every stub call is authorized unless a
        # test explicitly removes the variable to prove the refusal.
        import os

        os.environ["SAIPAL_ANALYST_API_KEY"] = "stub-key-value"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)

    def call(self, config: dict | None = None, **kwargs: object) -> object:
        return backend_mod.call(
            config or self.config,
            system="system contract",
            user="analysis packet",
            timeout=kwargs.pop("timeout", None),
            **kwargs,
        )


class HappyPath(BackendBase):
    def test_success_parses_text_usage_and_request_id(self) -> None:
        self.server.script = [
            (
                200,
                envelope('{"verdict": "NO_DRIFT"}', usage={"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}),
                0.0,
            )
        ]
        reply = self.call()
        self.assertTrue(reply.ok)
        self.assertEqual(reply.text, '{"verdict": "NO_DRIFT"}')
        self.assertEqual(reply.failure_class, OK)
        self.assertEqual(reply.http_status, 200)
        self.assertEqual(reply.request_id, "stub-req-1")
        self.assertEqual(reply.usage["total_tokens"], 18)
        self.assertGreater(reply.latency_seconds, 0.0)

    def test_request_is_text_only_and_keyed(self) -> None:
        self.server.script = [(200, envelope("{}"), 0.0)]
        self.call()
        request = self.server.requests[0]
        body = request["body"]
        self.assertEqual(body["model"], "stub-model")
        self.assertEqual(body["messages"][0]["role"], "system")
        self.assertEqual(body["messages"][1]["role"], "user")
        # The transport must never offer the model a tool surface.
        for forbidden in ("tools", "functions", "tool_choice", "function_call"):
            self.assertNotIn(forbidden, body)
        self.assertEqual(request["headers"].get("Authorization"), "Bearer stub-key-value")

    def test_usage_ledger_counts_only_reported_calls(self) -> None:
        ledger = UsageLedger()
        ledger.absorb({"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15})
        ledger.absorb(None)
        ledger.absorb({"completion_tokens": 3})
        snapshot = ledger.snapshot()
        self.assertEqual(snapshot["calls"], 0)
        self.assertEqual(snapshot["usage_reported_calls"], 2)
        self.assertEqual(snapshot["input_tokens"], 10)
        self.assertEqual(snapshot["output_tokens"], 8)
        self.assertEqual(snapshot["total_tokens"], 15)
        ledger.calls = 3
        self.assertEqual(ledger.snapshot()["calls"], 3)


class StatusClasses(BackendBase):
    def probe(self, status: int) -> object:
        self.server.script = [(status, envelope("{}"), 0.0)]
        return self.call()

    def test_400_is_permanent(self) -> None:
        self.assertEqual(self.probe(400).failure_class, PERMANENT)

    def test_auth_failures_classified(self) -> None:
        for status in (401, 403):
            with self.subTest(status=status):
                self.assertEqual(self.probe(status).failure_class, AUTH)

    def test_retryable_status_classes(self) -> None:
        for status in (408, 429, 500, 502, 503):
            with self.subTest(status=status):
                self.assertEqual(self.probe(status).failure_class, RETRYABLE)

    def test_missing_key_never_sends_a_request(self) -> None:
        import os

        os.environ.pop("SAIPAL_ANALYST_API_KEY", None)
        reply = self.call()
        self.assertFalse(reply.ok)
        self.assertEqual(reply.failure_class, AUTH)
        self.assertIn("SAIPAL_ANALYST_API_KEY", reply.detail)
        self.assertEqual(self.server.requests, [])


class EnvelopeFailures(BackendBase):
    def test_invalid_json_envelope_is_retryable(self) -> None:
        self.server.script = [(200, b"not json at all\n", 0.0)]
        reply = self.call()
        self.assertFalse(reply.ok)
        self.assertEqual(reply.failure_class, RETRYABLE)

    def test_envelope_without_content_is_retryable(self) -> None:
        self.server.script = [(200, b'{"choices": []}\n', 0.0)]
        self.assertEqual(self.call().failure_class, RETRYABLE)

    def test_non_text_content_is_retryable(self) -> None:
        self.server.script = [(200, b'{"choices": [{"message": {"content": 42}}]}\n', 0.0)]
        self.assertEqual(self.call().failure_class, RETRYABLE)

    def test_oversized_response_is_never_parsed(self) -> None:
        self.config["backend"]["max_response_bytes"] = 64
        self.server.script = [(200, envelope("x" * 4096), 0.0)]
        reply = self.call()
        self.assertFalse(reply.ok)
        self.assertEqual(reply.failure_class, LIMIT)
        self.assertIn("exceeded", reply.detail)


class TimeoutAndConnection(BackendBase):
    def test_timeout_is_retryable(self) -> None:
        self.config["backend"]["timeout_seconds"] = 1
        self.server.script = [(200, envelope("{}"), 2.5)]
        started = time.monotonic()
        reply = self.call()
        self.assertFalse(reply.ok)
        self.assertEqual(reply.failure_class, RETRYABLE)
        self.assertLess(time.monotonic() - started, 4.0)

    def test_refused_connection_is_retryable(self) -> None:
        dead = analyst_config.default_analyst_config()
        dead["enabled"] = True
        dead["backend"]["endpoint"] = "http://127.0.0.1:1/v1/chat/completions"
        dead["backend"]["model"] = "stub-model"
        import os

        os.environ["SAIPAL_ANALYST_API_KEY"] = "k"
        try:
            reply = self.call(dead, timeout=2.0)
        finally:
            os.environ.pop("SAIPAL_ANALYST_API_KEY", None)
        self.assertFalse(reply.ok)
        self.assertEqual(reply.failure_class, RETRYABLE)


if __name__ == "__main__":
    unittest.main()
