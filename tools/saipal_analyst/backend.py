"""Transport-neutral failure classes for model backends.

The backend NEVER retries: classification only. Retry policy is owned by the
worker budget, because a retry policy buried inside a transport is a policy
nobody can audit.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: The reply carried content and the call is a success.
OK = "OK"
#: Transient: timeouts, 408, 429, 5xx, connection resets, unusable envelopes.
RETRYABLE = "RETRYABLE"
#: The request itself is wrong and will fail identically forever.
PERMANENT = "PERMANENT"
#: Authentication/configuration: missing key, 401, 403.
AUTH = "AUTH"
#: Response exceeded the configured byte cap: never parsed, never retried.
LIMIT = "LIMIT"


@dataclass(frozen=True)
class ModelReply:
    """One model call outcome. Never contains the API key or the endpoint URL."""

    ok: bool
    text: str = ""
    failure_class: str = ""
    detail: str = ""
    http_status: int | None = None
    request_id: str | None = None
    usage: dict | None = None
    latency_seconds: float = 0.0
    byte_count: int = 0
    timed_out: bool = False

    @property
    def retryable(self) -> bool:
        return self.failure_class == RETRYABLE


class BackendFailure(Exception):
    """A provider/transport outcome that is NOT a malformed model output.

    Carrier for the truthful facts a retry policy and telemetry need. No
    secret values ride along: detail strings are transport facts only.
    """

    def __init__(self, reply: ModelReply) -> None:
        self.reply = reply
        super().__init__(
            f"backend {reply.failure_class}"
            + (f" HTTP {reply.http_status}" if reply.http_status else "")
            + f": {reply.detail}"
        )

    @property
    def failure_class(self) -> str:
        return self.reply.failure_class

    @property
    def retryable(self) -> bool:
        return self.reply.failure_class == RETRYABLE


@dataclass
class UsageLedger:
    """Usage truth for one run. Correctness never depends on these existing."""

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    reported: int = 0

    def absorb(self, usage: dict | None) -> None:
        if not isinstance(usage, dict):
            return
        self.reported += 1
        self.input_tokens += _int_or_zero(usage.get("prompt_tokens") or usage.get("input_tokens"))
        self.output_tokens += _int_or_zero(
            usage.get("completion_tokens") or usage.get("output_tokens")
        )
        self.total_tokens += _int_or_zero(usage.get("total_tokens"))

    @staticmethod
    def usage_delta(usage: dict | None) -> tuple[int, int]:
        """THE authoritative per-call token normalization (audit W2-002).

        Returns (input_tokens, output_tokens) for ONE reply. Run summaries and
        the durable budget window must interpret provider usage identically,
        so both consume this helper; the run ledger stays cumulative via
        `absorb`, while durable accounting charges only this delta.
        """
        if not isinstance(usage, dict):
            return (0, 0)
        return (
            _int_or_zero(usage.get("prompt_tokens") or usage.get("input_tokens")),
            _int_or_zero(usage.get("completion_tokens") or usage.get("output_tokens")),
        )

    def snapshot(self) -> dict:
        return {
            "calls": self.calls,
            "usage_reported_calls": self.reported,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
        }


def _int_or_zero(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0
