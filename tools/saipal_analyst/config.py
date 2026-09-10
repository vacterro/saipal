"""Analyst runtime configuration: `.saipal/analyst.json` (Layer B owned).

The config is closed and fail-closed: an unknown field, an unknown backend, a
missing budget or a dangerous implicit default is a validation failure, never a
fallback. API secrets are referenced only by environment-variable NAME; a
secret VALUE is never accepted, stored, logged or telemetried.

The default state is disabled: installing or upgrading SAIPAL must never
silently start sending session evidence to a model endpoint.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

from saipal_engine.errors import PalError
from saipal_engine.paths import atomic_write_json, home_paths, read_json

ANALYST_CONFIG_NAME = "analyst.json"
ANALYST_SCHEMA_VERSION = 1

BACKEND_TYPES = ("openai_compatible",)

TOP_FIELDS = (
    "schema_version",
    "enabled",
    "backend",
    "egress",
    "budgets",
    "deliberation",
)
BACKEND_FIELDS = (
    "type",
    "endpoint",
    "model",
    "api_key_env",
    "timeout_seconds",
    "max_response_bytes",
    "temperature",
)
EGRESS_FIELDS = ("allow_remote_evidence",)
BUDGET_FIELDS = (
    "max_units_per_run",
    "max_model_calls_per_run",
    "max_wall_seconds",
    "max_retries_per_unit",
    # Durable cross-run windows (optional; absent means unbounded here, the
    # per-run budgets still bound every invocation).
    "max_model_attempts_per_hour",
    "max_semantic_units_per_hour",
)
DELIBERATION_FIELDS = (
    "critic_on_drift",
    "critic_on_high_signal_no_drift",
    "clean_sample_percent",
    "finalizer_on_disagreement",
)

ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
DEFAULT_API_KEY_ENV = "SAIPAL_ANALYST_API_KEY"


def default_analyst_config() -> dict:
    """The shipped default: present, fully specified, and OFF."""
    return {
        "schema_version": ANALYST_SCHEMA_VERSION,
        "enabled": False,
        "backend": {
            "type": "openai_compatible",
            "endpoint": "http://127.0.0.1:8080/v1/chat/completions",
            "model": "",
            "api_key_env": DEFAULT_API_KEY_ENV,
            "timeout_seconds": 120,
            "max_response_bytes": 131072,
            "temperature": 0.1,
        },
        "egress": {"allow_remote_evidence": False},
        "budgets": {
            "max_units_per_run": 25,
            "max_model_calls_per_run": 50,
            "max_wall_seconds": 1800,
            "max_retries_per_unit": 2,
        },
        "deliberation": {
            "critic_on_drift": True,
            "critic_on_high_signal_no_drift": True,
            "clean_sample_percent": 5,
            "finalizer_on_disagreement": True,
        },
    }


def analyst_config_path(home: Path | str) -> Path:
    return home_paths(home).root / ANALYST_CONFIG_NAME


def _closed_object(
    payload: dict, name: str, fields: tuple[str, ...], problems: list[str]
) -> None:
    value = payload.get(name)
    if not isinstance(value, dict):
        problems.append(f"{name} must be an object")
        return
    for key in sorted(set(value) - set(fields)):
        problems.append(f"{name} has unknown field {key!r}")


def _positive_int(
    container: dict, name: str, key: str, problems: list[str], *, maximum: int | None = None
) -> None:
    value = container.get(key) if isinstance(container, dict) else None
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        problems.append(f"{name}.{key} must be a positive integer")
    elif maximum is not None and value > maximum:
        problems.append(f"{name}.{key} must not exceed {maximum}")


def validate_analyst_config(payload: object) -> list[str]:
    """Every reason this analyst config is unusable, or an empty list."""
    if not isinstance(payload, dict):
        return ["analyst config root is not an object"]
    problems: list[str] = []
    if payload.get("schema_version") != ANALYST_SCHEMA_VERSION:
        problems.append(f"schema_version must be {ANALYST_SCHEMA_VERSION}")
    for key in sorted(set(payload) - set(TOP_FIELDS)):
        problems.append(f"unknown analyst config field {key!r}")
    if not isinstance(payload.get("enabled"), bool):
        problems.append("enabled must be a boolean")

    backend = payload.get("backend")
    if not isinstance(backend, dict):
        problems.append("backend must be an object")
        return problems
    _closed_object(payload, "backend", BACKEND_FIELDS, problems)
    if backend.get("type") not in BACKEND_TYPES:
        problems.append(
            f"backend.type {backend.get('type')!r} outside {list(BACKEND_TYPES)}"
        )
    endpoint = backend.get("endpoint")
    if not isinstance(endpoint, str) or not _valid_http_url(endpoint):
        problems.append("backend.endpoint must be an absolute http(s) URL")
    model = backend.get("model")
    # An inert (disabled) config may name no model; an enabled one may not.
    if not isinstance(model, str) or (payload.get("enabled") and not model.strip()):
        problems.append("backend.model must be a non-empty string")
    api_key_env = backend.get("api_key_env")
    if not isinstance(api_key_env, str) or not ENV_NAME_RE.match(api_key_env or ""):
        problems.append("backend.api_key_env must be an environment variable NAME")
    _positive_int(backend, "backend", "timeout_seconds", problems, maximum=3600)
    _positive_int(backend, "backend", "max_response_bytes", problems, maximum=1024 * 1024)
    temperature = backend.get("temperature")
    if (
        not isinstance(temperature, (int, float))
        or isinstance(temperature, bool)
        or not 0.0 <= float(temperature) <= 2.0
    ):
        problems.append("backend.temperature must be a number between 0 and 2")

    _closed_object(payload, "egress", EGRESS_FIELDS, problems)
    egress = payload.get("egress")
    if isinstance(egress, dict) and not isinstance(
        egress.get("allow_remote_evidence"), bool
    ):
        problems.append("egress.allow_remote_evidence must be a boolean")

    _closed_object(payload, "budgets", BUDGET_FIELDS, problems)
    budgets = payload.get("budgets")
    if isinstance(budgets, dict):
        for key in BUDGET_FIELDS:
            if budgets.get(key) is None:
                # Optional durable cross-run windows stay optional.
                if key in ("max_model_attempts_per_hour", "max_semantic_units_per_hour"):
                    continue
            if key == "max_wall_seconds":
                # Seconds may legitimately be fractional; the wall budget is a
                # duration, not a count.
                value = budgets.get(key)
                if (
                    not isinstance(value, (int, float))
                    or isinstance(value, bool)
                    or value <= 0
                ):
                    problems.append("budgets.max_wall_seconds must be a positive number")
            else:
                _positive_int(budgets, "budgets", key, problems)

    _closed_object(payload, "deliberation", DELIBERATION_FIELDS, problems)
    deliberation = payload.get("deliberation")
    if isinstance(deliberation, dict):
        for key in ("critic_on_drift", "critic_on_high_signal_no_drift", "finalizer_on_disagreement"):
            if not isinstance(deliberation.get(key), bool):
                problems.append(f"deliberation.{key} must be a boolean")
        percent = deliberation.get("clean_sample_percent")
        if (
            not isinstance(percent, int)
            or isinstance(percent, bool)
            or not 0 <= percent <= 100
        ):
            problems.append("deliberation.clean_sample_percent must be an integer 0..100")
    return problems


def _valid_http_url(endpoint: str) -> bool:
    parts = urlsplit(endpoint)
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def endpoint_host(endpoint: str) -> str | None:
    """The host component of an endpoint URL, or None when it is not one."""
    try:
        parts = urlsplit(endpoint)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    host = parts.hostname
    return host.lower() if host else None


def endpoint_is_local(endpoint: str) -> bool:
    """True only for loopback: `localhost`, 127.0.0.0/8 or ::1.

    Deliberately conservative. A LAN name or private address is NOT trusted
    local; sending session evidence there is egress and needs the explicit flag.
    """
    host = endpoint_host(endpoint)
    if host is None:
        return False
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback


def load_analyst_config(home: Path | str) -> tuple[str, dict | None, str]:
    """`(status, config, detail)` with status absent|ok|unrecoverable."""
    path = analyst_config_path(home)
    if not path.exists():
        return "absent", None, ""
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return "unrecoverable", None, f"analyst.json is unreadable: {exc}"
    problems = validate_analyst_config(payload)
    if problems:
        return "unrecoverable", None, "; ".join(problems)
    return "ok", payload, ""


def save_analyst_config(home: Path | str, payload: dict) -> dict:
    """Validate, then atomically persist the analyst config. Zero writes on refusal."""
    problems = validate_analyst_config(payload)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "refusing invalid analyst config: " + "; ".join(problems),
            next_action="fix .saipal/analyst.json; nothing was written",
        )
    path = analyst_config_path(home)
    atomic_write_json(path, payload, root=home_paths(home).root)
    return payload


def egress_verdict(config: dict) -> tuple[bool, str]:
    """May session evidence be sent to the configured endpoint?

    Local loopback endpoints are always allowed. Anything else needs the
    operator's explicit `egress.allow_remote_evidence = true`; the refusal
    names the endpoint and the flag so the decision stays the operator's.
    """
    endpoint = str((config.get("backend") or {}).get("endpoint") or "")
    if endpoint_is_local(endpoint):
        return True, ""
    allowed = bool((config.get("egress") or {}).get("allow_remote_evidence"))
    if allowed:
        return True, ""
    return False, (
        "evidence would leave the machine: endpoint "
        f"{endpoint!r} is not a loopback address; set "
        "egress.allow_remote_evidence=true in .saipal/analyst.json to permit it"
    )
