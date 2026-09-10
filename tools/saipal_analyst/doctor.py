"""`saipal analyst-doctor` -- read-only diagnosis of the analyst runtime.

The doctor never mutates the home, never makes a network call, never spends
tokens and never prints or stores the API key VALUE. It reports the presence of
the environment variable named by the config, which is a fact about the
operator's machine, not a credential.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from saipal_engine.paths import home_paths
from saipal_engine.registry import load_registry
from saipal_engine.sessions import STATUS_UNRECOVERABLE, load_index
from saipal_engine import coverage as coverage_mod

from .config import (
    ANALYST_CONFIG_NAME,
    analyst_config_path,
    endpoint_is_local,
    egress_verdict,
    load_analyst_config,
)


def doctor_report(home: Path | str, *, registry: dict | None = None) -> dict:
    """A truthful, read-only snapshot of analyst readiness."""
    data = registry if registry is not None else load_registry()
    root = Path(home)
    report: dict = {
        "analyst_doctor": True,
        "config_file": ANALYST_CONFIG_NAME,
        "config_present": False,
        "config_valid": False,
        "config_problems": [],
        "enabled": False,
        "backend_type": None,
        "endpoint": None,
        "endpoint_local": None,
        "remote_evidence_allowed": None,
        "egress_ok": None,
        "api_key_env": None,
        "api_key_env_present": None,
        "model": None,
        "budgets": None,
        "journal_present": False,
        "worker_lock_present": False,
        "worker_active": False,
        "semantic": {},
        "ok": False,
    }

    status, config, detail = load_analyst_config(root)
    if status == "absent":
        report["config_problems"] = [f"{ANALYST_CONFIG_NAME} is absent"]
        return report
    if status == "unrecoverable":
        report["config_present"] = True
        report["config_problems"] = [detail]
        return report

    report["config_present"] = True
    report["config_valid"] = True
    report["enabled"] = bool(config.get("enabled"))
    backend = config.get("backend") or {}
    report["backend_type"] = backend.get("type")
    endpoint = backend.get("endpoint")
    report["endpoint"] = endpoint
    report["endpoint_local"] = endpoint_is_local(endpoint) if endpoint else None
    egress_allowed, egress_detail = egress_verdict(config)
    report["egress_ok"] = egress_allowed
    if not egress_allowed:
        report["config_problems"].append(egress_detail)
    report["remote_evidence_allowed"] = bool(
        (config.get("egress") or {}).get("allow_remote_evidence")
    )
    api_key_env = backend.get("api_key_env")
    report["api_key_env"] = api_key_env
    report["api_key_env_present"] = bool(api_key_env and os.environ.get(api_key_env))
    report["model"] = backend.get("model")
    report["budgets"] = config.get("budgets")

    if report["enabled"]:
        if not report["api_key_env_present"]:
            report["config_problems"].append(
                f"environment variable {api_key_env!r} is not set"
            )
        if not report["egress_ok"]:
            pass  # already reported with endpoint and flag
        if not report["model"]:
            report["config_problems"].append("backend.model is not configured")

    analyst_dir = home_paths(root).root / "analyst"
    journal = analyst_dir / "jobs.json"
    report["journal_present"] = journal.is_file()
    lock = home_paths(root).locks / "analyst-worker.lock"
    report["worker_lock_present"] = lock.is_file()
    report["worker_active"] = _lock_holder_alive(lock)

    report["semantic"] = _semantic_snapshot(root, data)
    report["ok"] = not report["config_problems"]
    return report


def _lock_holder_alive(lock: Path) -> bool:
    """Is there a live worker holding the lock? Read-only: never acquires."""
    if not lock.is_file():
        return False
    try:
        from saipal_engine.paths import _pid_alive

        payload = json.loads(lock.read_text(encoding="utf-8"))
        pid = int(payload.get("pid") or 0)
        return pid > 0 and _pid_alive(pid)
    except (ValueError, OSError, TypeError):
        return True  # unparseable lock: treat as held, never break it silently


def _semantic_snapshot(root: Path, registry: dict) -> dict:
    """Pending counts from the canonical index. Read-only."""
    status, index, _detail = load_index(root, registry=registry)
    snapshot: dict = {}
    if status == STATUS_UNRECOVERABLE or index is None:
        snapshot["index"] = "unavailable"
        return snapshot
    totals = coverage_mod.coverage(root, index, registry=registry)
    snapshot["episodes_total"] = totals["episodes_total"]
    snapshot["episodes_pending"] = totals["episodes_pending"]
    snapshot["slices_pending"] = totals["slices_pending"]
    snapshot["receipts_total"] = totals["receipts_total"]
    return snapshot
