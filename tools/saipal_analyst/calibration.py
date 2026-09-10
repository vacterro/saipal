"""Bounded shadow calibration: T-83.

The harness reuses the ONE repaired autonomous worker -- never a second
semantic pipeline. It selects a deterministic, reproducible sample of pending
semantic units across available dimensions (session, project, adapter,
finality, mechanical-signal presence), runs them through the real worker
against a bounded budget, and reports observed verdict distribution plus, for
labelled golden units only, measured accuracy. The two are never merged:
unlabelled historical output is never called accuracy.

Configuration discipline: calibration runs only when the analyst is enabled,
a backend model is configured, the API key environment variable is present
when one is referenced, egress policy is satisfied, publication stays
STAGE_ONLY, and an explicit unit budget is given. Any missing prerequisite is
CONFIGURATION_BLOCKED with zero mutation and zero model calls.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from saipal_engine import carrier as carrier_mod
from saipal_engine.errors import PalError
from saipal_engine.registry import load_registry
from saipal_engine.sessions import STATUS_UNRECOVERABLE, load_index

from . import backend as backend_mod
from . import jobs as jobs_mod
from .config import egress_verdict, load_analyst_config, endpoint_is_local
from .worker import WorkerClock, investigate

CALIBRATION_SCHEMA_VERSION = 1


def configuration_gate(home: Path | str, sample_units: int | None) -> tuple[bool, str]:
    """Every prerequisite, checked with zero writes and zero calls."""
    if sample_units is None or int(sample_units) <= 0:
        return False, "an explicit positive unit budget is required; omission never means drain"
    status, config, detail = load_analyst_config(home)
    if status == "absent":
        return False, "analyst is not configured"
    if status == "unrecoverable":
        return False, f"analyst config is unusable: {detail}"
    if not config.get("enabled"):
        return False, "analyst is disabled"
    backend = config.get("backend") or {}
    if not backend.get("model"):
        return False, "backend.model is not configured"
    api_key_env = backend.get("api_key_env")
    if api_key_env and not endpoint_is_local(str(backend.get("endpoint") or "")):
        import os

        if not os.environ.get(api_key_env):
            return False, f"API key environment variable {api_key_env!r} is not set"
    allowed, egress_detail = egress_verdict(config)
    if not allowed:
        return False, egress_detail
    from saipal_engine.config import load_config as load_publication_config

    _pub_status, publication, pub_detail = load_publication_config(home)
    if not isinstance(publication, dict):
        return False, f"config.json is unusable: {pub_detail}"
    if str(publication.get("publication_mode") or "") != "STAGE_ONLY":
        return False, (
            f"publication_mode is {publication.get('publication_mode')!r}; "
            "calibration runs only under STAGE_ONLY"
        )
    return True, ""


def select_sample(home: Path | str, sample_units: int, seed: str = "calibration") -> dict:
    """A deterministic, reproducible sample across available dimensions.

    Pure: no model call, no write. Units are ordered by a digest-based
    bucket over (seed, session, episode, slice), so the same seed and backlog
    reproduce the same sample; ties break on identity. FINAL+BOUND units are
    preferred for measured comparisons; PROVISIONAL units are eligible only
    as explicitly marked observations.
    """
    registry = load_registry()
    event_limit = int(carrier_mod._limits(registry)["max_events"])
    index_status, index, index_detail = load_index(home)
    if index_status == STATUS_UNRECOVERABLE:
        raise PalError("VALIDATION_FAILED", f"session index is unusable: {index_detail}")

    candidates: list[dict] = []
    for record in carrier_mod.freshest_records(index):
        if record.get("status") != "IMPORTED":
            continue
        episodes = record.get("episodes") or []
        state = carrier_mod.semantic_state(record)
        if state["exhausted"] or state["next_episode_index"] >= len(episodes):
            continue
        episode = episodes[state["next_episode_index"]]
        slices = carrier_mod.episode_slice_count(record, episode, event_limit)
        slice_at = min(state["next_slice_index"], slices - 1)
        if (
            carrier_mod.episode_finality(record, episode) == "PROVISIONAL"
            and state["tail_reviewed_digest"]
            and state["tail_reviewed_digest"]
            == carrier_mod.tail_digest(record, episode, slice_at)
        ):
            continue
        session_id = str(record.get("session_id") or "")
        digest = carrier_mod.unit_digest(record, episode, slice_at)
        job_id = jobs_mod.unit_job_id(session_id, int(episode["index"]), slice_at, digest)
        protocol = record.get("protocol") or {}
        project = (record.get("project") or {}).get("name") if isinstance(record.get("project"), dict) else None
        candidates.append(
            {
                "job_id": job_id,
                "session_id": session_id,
                "episode_index": int(episode["index"]),
                "slice_index": slice_at,
                "unit_digest": digest,
                "finality": carrier_mod.episode_finality(record, episode),
                "binding_status": protocol.get("binding_status", "UNKNOWN"),
                "project": project or "",
                "adapter": str(record.get("adapter") or ""),
            }
        )

    def bucket(entry: dict) -> tuple:
        material = f"{seed}|{entry['session_id']}|{entry['episode_index']}|{entry['slice_index']}"
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
        # FINAL+BOUND first (measured-comparison preference), then bucket.
        measured = 0 if (entry["finality"] == "FINAL" and entry["binding_status"] == "BOUND") else 1
        return (measured, digest, entry["unit_digest"])

    candidates.sort(key=bucket)
    sample = candidates[: int(sample_units)]
    sample_digest = hashlib.sha256(
        "\n".join(
            f"{entry['job_id']}|{entry['unit_digest']}" for entry in sample
        ).encode("utf-8")
    ).hexdigest()
    return {
        "sample": sample,
        "sample_digest": sample_digest,
        "eligible_total": len(candidates),
    }


def run_calibration(
    home: Path | str,
    *,
    sample_units: int,
    seed: str = "calibration",
    clock: WorkerClock | None = None,
) -> dict:
    """Run the bounded sample through the real worker; report the metrics."""
    report: dict = {"calibration": True, "schema_version": CALIBRATION_SCHEMA_VERSION}

    gate_ok, gate_detail = configuration_gate(home, sample_units)
    if not gate_ok:
        report["ok"] = False
        report["code"] = "CONFIGURATION_BLOCKED"
        report["reason"] = gate_detail
        return report

    selection = select_sample(home, sample_units, seed=seed)
    report.update(
        {
            "ok": True,
            "sample_digest": selection["sample_digest"],
            "requested_units": int(sample_units),
            "eligible_units": selection["eligible_total"],
            "selected_units": len(selection["sample"]),
        }
    )

    summary = investigate(
        home,
        max_units=len(selection["sample"]),
        clock=clock,
        restrict_job_ids={entry["job_id"] for entry in selection["sample"]},
    )

    report["analyzed_units"] = summary["units"]
    report["binding_blocked_units"] = summary["jobs_blocked_binding"]
    report["analyst_blocked_units"] = summary["jobs_blocked"]
    report["stop_reason"] = summary["stop_reason"]
    report["model_calls"] = summary["model_calls"]
    report["rate_limited"] = summary["rate_limited"]
    report["timeouts"] = summary["timeouts"]
    report["repair_calls"] = summary["repair_calls"]
    report["submit_successes"] = summary["submit_successes"]

    # Verdict distribution: OBSERVED, never accuracy (units are unlabelled
    # historical sessions).
    distribution = {"NO_DRIFT": 0, "INSUFFICIENT_EVIDENCE": 0, "DRIFT": 0}
    for receipt in summary["receipts"]:
        verdict = str(receipt.get("verdict") or "")
        if verdict in distribution:
            distribution[verdict] += 1
    report["verdict_distribution"] = distribution

    latencies = sorted(summary.get("unit_latencies") or [])
    report["latency"] = {
        "p50_seconds": _percentile(latencies, 50),
        "p95_seconds": _percentile(latencies, 95),
        "samples": len(latencies),
    }
    report["usage"] = {
        "available": bool(summary.get("usage_available")),
        "input_tokens": summary.get("input_tokens", 0),
        "output_tokens": summary.get("output_tokens", 0),
        "total_tokens": summary.get("total_tokens", 0),
    }

    # Golden accuracy ONLY where a labelled verdict exists; never merged with
    # the unlabelled distribution above. No labelled evidence: the block says
    # so instead of disappearing (absence would read as zero-cost omission).
    golden = golden_accuracy(home, summary["receipts"])
    report["golden"] = golden if golden is not None else {"labelled_units": 0}
    return report


def golden_accuracy(home: Path | str, receipts: list[dict]) -> dict | None:
    """Measured accuracy over labelled golden units only.

    A golden label lives in the session record's project marker; units
    without one are unlabelled history and contribute nothing here. With no
    labelled evidence the report says so instead of fabricating a rate.
    """
    labels = load_golden_labels(home)
    if not labels:
        return None
    counts = {"true_positive": 0, "true_negative": 0, "false_positive": 0, "false_negative": 0}
    matched = 0
    for receipt in receipts:
        session_id = str(receipt.get("session_id") or "")
        label = labels.get(session_id)
        if label is None:
            continue
        matched += 1
        verdict = receipt.get("verdict")
        if label == "drift":
            counts["true_positive" if verdict == "DRIFT" else "false_negative"] += 1
        else:
            counts["true_negative" if verdict == "NO_DRIFT" else "false_positive"] += 1
    if matched == 0:
        return None
    golden: dict = {"labelled_units": matched, **counts}
    drift_total = counts["true_positive"] + counts["false_positive"]
    clean_total = counts["true_negative"] + counts["false_negative"]
    if drift_total:
        golden["precision"] = counts["true_positive"] / drift_total
    if counts["true_positive"] + counts["false_negative"]:
        golden["recall"] = counts["true_positive"] / (
            counts["true_positive"] + counts["false_negative"]
        )
    if drift_total + clean_total:
        golden["accuracy"] = (
            counts["true_positive"] + counts["true_negative"]
        ) / (drift_total + clean_total)
    return golden


def load_golden_labels(home: Path | str) -> dict[str, str]:
    """Session-level golden labels from `.saipal/analyst/golden.json`."""
    from saipal_engine.paths import read_json

    path = jobs_mod.journal_dir(home) / "golden.json"
    if not path.exists():
        return {}
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError):
        return {}
    labels = payload.get("labels") if isinstance(payload, dict) else None
    if not isinstance(labels, dict):
        return {}
    return {
        str(session): str(label).lower()
        for session, label in labels.items()
        if str(label).lower() in ("drift", "clean")
    }


def _percentile(values: list[float], percent: int) -> float | None:
    if not values:
        return None
    index = min(len(values) - 1, max(0, round((percent / 100) * (len(values) - 1))))
    return values[index]
