"""The one text-only backend of this milestone: OpenAI-compatible chat.

Rules baked in, none overridable by the model or the payload:
- the endpoint is taken verbatim from config (never guessed, never joined);
- the request NEVER carries tools, functions or tool_choice -- the model has
  no tools, so the transport must not pretend otherwise;
- the response is read under a hard byte cap and never parsed beyond it;
- every outcome is classified (OK/RETRYABLE/PERMANENT/AUTH/LIMIT); retries are
  the worker's decision, never the transport's.
"""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request

from .backend import AUTH, LIMIT, OK, PERMANENT, RETRYABLE, ModelReply
from .config import credential_verdict

_REQUEST_TIMEOUT = 120.0
_CHUNK = 8192


def build_payload(config: dict, *, system: str, user: str) -> dict:
    """The chat payload. Deliberately tool-free."""
    backend = config.get("backend") or {}
    return {
        "model": str(backend.get("model") or ""),
        "temperature": backend.get("temperature", 0.1),
        "stream": False,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }


def _headers(config: dict) -> tuple[dict, str | None]:
    backend = config.get("backend") or {}
    api_key_env = backend.get("api_key_env")
    value = os.environ.get(api_key_env or "")
    headers = {"Content-Type": "application/json"}
    if value:
        headers["Authorization"] = f"Bearer {value}"
    return headers, value


def call(
    config: dict,
    *,
    system: str,
    user: str,
    timeout: float | None = None,
) -> ModelReply:
    """One chat completion call. Classifies; never retries; never logs secrets."""
    backend = config.get("backend") or {}
    endpoint = str(backend.get("endpoint") or "")
    byte_cap = int(backend.get("max_response_bytes") or 131072)
    started = time.perf_counter()

    headers, _key = _headers(config)
    credential_ok, credential_detail = credential_verdict(config)
    if not credential_ok:
        # Fail closed BEFORE a socket exists: with no configured credential there
        # is no authorized remote party to send evidence to. A loopback endpoint
        # is the documented exception -- it has no remote party at all, so an
        # unset key is inert there and the call proceeds header-less.
        return ModelReply(
            ok=False,
            failure_class=AUTH,
            detail=credential_detail,
            latency_seconds=time.perf_counter() - started,
        )

    payload = json.dumps(build_payload(config, system=system, user=user)).encode("utf-8")
    request = urllib.request.Request(
        endpoint, data=payload, headers=headers, method="POST"
    )

    try:
        with urllib.request.urlopen(
            request, timeout=float(timeout or backend.get("timeout_seconds") or _REQUEST_TIMEOUT)
        ) as response:
            status = int(response.status or 0)
            request_id = response.headers.get("x-request-id") or response.headers.get(
                "request-id"
            )
            raw = _read_capped(response, byte_cap)
    except urllib.error.HTTPError as exc:
        return ModelReply(
            ok=False,
            failure_class=_classify_status(exc.code),
            detail=f"HTTP {exc.code} from model endpoint",
            http_status=int(exc.code),
            latency_seconds=time.perf_counter() - started,
        )
    except urllib.error.URLError as exc:
        reason = exc.reason
        timed_out = isinstance(reason, socket.timeout) or (
            isinstance(reason, OSError) and isinstance(reason.__class__, type)
            and "timed out" in str(reason).lower()
        )
        return ModelReply(
            ok=False,
            failure_class=RETRYABLE,
            detail=(
                "request to model endpoint timed out"
                if timed_out
                else f"connection to model endpoint failed: {reason}"
            ),
            latency_seconds=time.perf_counter() - started,
            timed_out=timed_out,
        )
    except socket.timeout as exc:
        return ModelReply(
            ok=False,
            failure_class=RETRYABLE,
            detail="request to model endpoint timed out",
            latency_seconds=time.perf_counter() - started,
            timed_out=True,
        )
    except OSError as exc:
        # socket.timeout is an OSError subclass: a read that outlived the
        # timeout lands here, and it is as retryable as any reset.
        timed_out = "timed out" in str(exc).lower()
        return ModelReply(
            ok=False,
            failure_class=RETRYABLE,
            detail=(
                "request to model endpoint timed out"
                if timed_out
                else f"connection to model endpoint failed: {exc}"
            ),
            latency_seconds=time.perf_counter() - started,
            timed_out=timed_out,
        )

    latency = time.perf_counter() - started
    if len(raw) > byte_cap:
        return ModelReply(
            ok=False,
            failure_class=LIMIT,
            detail=f"response exceeded {byte_cap} bytes and was not parsed",
            http_status=status,
            request_id=request_id,
            latency_seconds=latency,
        )

    try:
        envelope = json.loads(raw.decode("utf-8"))
        content = envelope["choices"][0]["message"]["content"]
        usage = envelope.get("usage") if isinstance(envelope.get("usage"), dict) else None
    except (ValueError, KeyError, IndexError, TypeError, UnicodeDecodeError):
        return ModelReply(
            ok=False,
            failure_class=RETRYABLE,
            detail="model endpoint returned an unusable response envelope",
            http_status=status,
            request_id=request_id,
            latency_seconds=latency,
        )

    if not isinstance(content, str):
        return ModelReply(
            ok=False,
            failure_class=RETRYABLE,
            detail="model response content is not text",
            http_status=status,
            request_id=request_id,
            latency_seconds=latency,
        )

    return ModelReply(
        ok=True,
        text=content,
        failure_class=OK,
        http_status=status,
        request_id=request_id,
        usage=usage,
        latency_seconds=latency,
        byte_count=len(raw),
    )


def _read_capped(response, cap: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            # Keep draining is pointless: the reply is oversized by policy.
            return b"\0" * (cap + 1)
        chunks.append(chunk)
    return b"".join(chunks)


def _classify_status(status: int) -> str:
    if 200 <= status < 300:
        return OK
    if status in (401, 403):
        return AUTH
    if status == 400:
        return PERMANENT
    if status in (408, 409, 429) or 500 <= status <= 599:
        return RETRYABLE
    return RETRYABLE
