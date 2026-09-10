"""Durable analyst execution provenance: `.saipal/analyst/provenance.json`.

Layer-B observational truth, keyed by committed semantic receipt. The kernel
receipt remains forensic truth; this ledger answers a different question --
WHICH analyst run, backend, model and deliberation path produced it. It never
holds API keys, endpoints, environments or transcript copies.

The write boundary is `record_provenance`, called after a successful submit.
A crash between the receipt commit and this write is recoverable: the journal
job still names the receipt, so `reconcile_provenance` rebuilds the link
without a model call and without duplicating the semantic effect. A receipt
without its provenance link surfaces as a discrepancy until repaired.
"""

from __future__ import annotations

from pathlib import Path

from saipal_engine.errors import PalError
from saipal_engine.paths import atomic_write_json, home_paths, read_json

from . import jobs as jobs_mod

PROVENANCE_SCHEMA_VERSION = 1
PROVENANCE_NAME = "provenance.json"

PROVENANCE_FIELDS = (
    "receipt_id",
    "job_id",
    "run_id",
    "backend_type",
    "model",
    "runtime_version",
    "investigator_digest",
    "critic_digest",
    "finalizer_digest",
    "repairs",
    "deliberation_path",
    "transport_attempts",
    "submit_attempts",
    "completed_at",
)


def provenance_path(home: Path | str) -> Path:
    return jobs_mod.journal_dir(home) / PROVENANCE_NAME


def fresh_ledger() -> dict:
    return {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "updated_at": "",
        "records": {},
    }


def load_ledger(home: Path | str) -> dict:
    path = provenance_path(home)
    if not path.exists():
        return fresh_ledger()
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise PalError(
            "VALIDATION_FAILED",
            f"analyst provenance ledger is unreadable: {exc}",
            next_action="repair or remove .saipal/analyst/provenance.json by hand",
        ) from None
    problems = ledger_problems(payload)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "analyst provenance ledger is invalid: " + "; ".join(problems[:5]),
        )
    return payload


def save_ledger(home: Path | str, ledger: dict) -> Path:
    problems = ledger_problems(ledger)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "refusing invalid analyst provenance ledger: " + "; ".join(problems[:5]),
        )
    return atomic_write_json(
        provenance_path(home), ledger, root=home_paths(home).root
    )


def ledger_problems(payload: object) -> list[str]:
    if not isinstance(payload, dict):
        return ["provenance root is not an object"]
    if payload.get("schema_version") != PROVENANCE_SCHEMA_VERSION:
        return [f"schema_version must be {PROVENANCE_SCHEMA_VERSION}"]
    for key in sorted(set(payload) - {"schema_version", "updated_at", "records"}):
        return [f"unknown provenance field {key!r}"]
    records = payload.get("records")
    if not isinstance(records, dict):
        return ["records must be an object"]
    problems: list[str] = []
    for receipt_id, record in sorted(records.items()):
        if not isinstance(receipt_id, str) or not receipt_id:
            problems.append("provenance receipt key must be a non-empty string")
            continue
        if not isinstance(record, dict):
            problems.append(f"provenance record {receipt_id} is not an object")
            continue
        for key in sorted(set(record) - set(PROVENANCE_FIELDS)):
            problems.append(f"provenance record {receipt_id} has unknown field {key!r}")
        if record.get("receipt_id") != receipt_id:
            problems.append(f"provenance record {receipt_id} disagrees with its key")
    return problems


def record_problems(record: object) -> list[str]:
    """Every reason one provenance record is unusable, or an empty list."""
    if not isinstance(record, dict):
        return ["provenance record is not an object"]
    problems: list[str] = []
    for key in sorted(set(record) - set(PROVENANCE_FIELDS)):
        problems.append(f"provenance record has unknown field {key!r}")
    receipt_id = record.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id:
        problems.append("provenance record missing receipt_id")
    return problems


def record_provenance(home: Path | str, record: dict) -> dict:
    """Persist one receipt-linked provenance record. Idempotent per receipt.

    Telemetry is observational truth, never authority: a provenance write
    failure must be visible and recoverable, and it never invalidates the
    semantic receipt it describes.
    """
    problems = record_problems(record)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "refusing provenance record: " + "; ".join(problems[:5]),
        )
    ledger = load_ledger(home)
    ledger.setdefault("records", {})[str(record["receipt_id"])] = record
    from time import gmtime, strftime

    ledger["updated_at"] = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
    save_ledger(home, ledger)
    return record


def reconcile_provenance(home: Path | str) -> dict:
    """Rebuild provenance links the durable journal still proves.

    The recovery path for `receipt committed -> provenance write crashed`:
    every DONE job that names a receipt missing from the ledger is repaired
    from journal facts alone. No model call, no duplicate receipt, no journal
    mutation.
    """
    journal = jobs_mod.load_journal(home)
    ledger = load_ledger(home)
    records = ledger.setdefault("records", {})
    repaired: list[dict] = []
    for job in (journal.get("jobs") or {}).values():
        if job.get("stage") != jobs_mod.DONE:
            continue
        receipt_id = job.get("receipt_id")
        if not receipt_id or receipt_id in records:
            continue
        record = provenance_from_job(job)
        records[str(receipt_id)] = record
        repaired.append(record)
    if repaired:
        from time import gmtime, strftime

        ledger["updated_at"] = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
        save_ledger(home, ledger)
    return {
        "reconciled": len(repaired),
        "receipts_with_provenance": len(records),
        "missing": missing_links(journal, ledger),
    }


def provenance_from_job(job: dict) -> dict:
    """The provenance record a DONE journal job proves, no model call."""
    return {
        "receipt_id": str(job.get("receipt_id") or ""),
        "job_id": str(job.get("job_id") or ""),
        "run_id": str(job.get("run_id") or ""),
        "backend_type": str(job.get("backend_type") or ""),
        "model": str(job.get("model") or ""),
        "runtime_version": 1,
        "investigator_digest": job.get("response_digest"),
        "critic_digest": job.get("critic_digest"),
        "finalizer_digest": job.get("finalizer_digest"),
        "repairs": int(job.get("repairs") or 0),
        "deliberation_path": _deliberation_path(job),
        "transport_attempts": int(job.get("transport_attempts") or 0),
        "submit_attempts": int(job.get("submit_attempts") or 0),
        "completed_at": str(job.get("updated_at") or ""),
    }


def _deliberation_path(job: dict) -> list[str]:
    """The durable deliberation route this job took."""
    path = ["investigator"]
    if job.get("critic_payload") is not None or job.get("critic_response_text"):
        path.append("critic")
    if job.get("finalizer_response_text") or job.get("finalizer_digest"):
        path.append("finalizer")
    return path


def missing_links(journal: dict, ledger: dict) -> list[dict]:
    """DONE receipts whose provenance link is absent -- a loud discrepancy."""
    records = ledger.get("records") or {}
    missing = []
    for job in (journal.get("jobs") or {}).values():
        if job.get("stage") != jobs_mod.DONE:
            continue
        receipt_id = job.get("receipt_id")
        if receipt_id and receipt_id not in records:
            missing.append({"receipt_id": receipt_id, "job_id": job.get("job_id")})
    return missing
