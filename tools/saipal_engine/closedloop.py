"""Closed-loop SAIPEN integration (Wave G).

Link SAIPAL findings to the SAIPEN maintainer lifecycle: finding -> audit ->
source receipt -> work -> disposition. The linkage ledger is durable and
survives a cold restart. Disposition import is read-only -- SAIPEN owns the
decision and SAIPAL never edits its own history.
"""

from __future__ import annotations

import json
from pathlib import Path

from .capability import require_action
from .errors import PalError
from .paths import atomic_write_json, home_paths, read_json, utc_now_iso

LINKS_NAME = "closed_loop_links.json"

DISPOSITIONS = frozenset(
    {
        "CONFIRMED_PROTOCOL_DEFECT",
        "ENGINE_FIX",
        "ADAPTER_FIX",
        "HARNESS_FIX",
        "TEST_ONLY",
        "DOCUMENTATION_ONLY",
        "MODEL_GUIDANCE",
        "NO_CHANGE",
        "REJECTED_FINDING",
        "NOT_APPLICABLE",
        "DUPLICATE",
        "SUPERSEDED",
    }
)


def empty_links() -> dict:
    return {"schema_version": 1, "links": []}


def load_links(home: Path | str) -> tuple[str, dict | None, str]:
    paths = home_paths(home)
    path = paths.root / LINKS_NAME
    if not path.exists():
        return "absent", None, ""
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return "unrecoverable", None, f"closed-loop links are unreadable: {exc}"
    if not isinstance(payload, dict) or not isinstance(payload.get("links"), list):
        return "unrecoverable", None, "closed-loop links root is malformed"
    return "ok", payload, ""


def save_links(home: Path | str, links: dict) -> dict:
    require_action("write_own_index")
    paths = home_paths(home)
    atomic_write_json(paths.root / LINKS_NAME, links, root=paths.root)
    return links


def link_finding_audit(home: Path | str, finding_id: str, audit_result: dict) -> dict:
    """Durably link a finding to its enqueued audit. Called once at emission.

    W2-002 (SRC-011): the linkage is an IDEMPOTENT effect keyed by stable audit
    identity (`audit_number`). Repeating the exact same link (same finding and
    audit_sha256) returns the stored row and writes nothing, so a crash after
    the link committed but before the surrounding finding/receipt commit cannot
    append the same link twice. A DIFFERENT identity for an already-bound audit
    number is a conflict and fails closed -- one audit, one finding -- rather
    than overwriting or accumulating a second contradictory row.
    """
    require_action("write_own_index")
    status, links, detail = load_links(home)
    if status == "unrecoverable":
        raise PalError(
            "VALIDATION_FAILED", detail,
            next_action="repair or remove .saipal/closed_loop_links.json by hand",
        )
    if links is None:
        links = empty_links()

    audit_number = int(audit_result.get("audit_number", 0))
    audit_sha256 = str(audit_result.get("audit_sha256", ""))
    for entry in links["links"]:
        if int(entry.get("audit_number", 0)) != audit_number:
            continue
        if (
            entry.get("finding_id") == finding_id
            and str(entry.get("audit_sha256") or "") == audit_sha256
        ):
            return entry
        raise PalError(
            "VALIDATION_FAILED",
            f"audit {audit_number} is already linked to finding "
            f"{entry.get('finding_id')!r}; refusing a conflicting link to "
            f"{finding_id!r}",
            next_action="one audit links to one finding; do not re-link it",
        )

    link = {
        "finding_id": finding_id,
        "audit_number": audit_number,
        "audit_path": audit_result.get("audit_path", ""),
        "audit_sha256": audit_sha256,
        "receipt_id": None,
        "work_id": None,
        "disposition": None,
        "fix_version": None,
        "closed_at": None,
    }
    links["links"].append(link)
    save_links(home, links)
    return link


def import_maintainer_disposition(
    home: Path | str,
    *,
    audit_number: int,
    disposition: str,
    receipt_id: str | None = None,
    work_id: str | None = None,
    fix_version: str | None = None,
) -> dict:
    """Import a maintainer verdict for a prior SAIPAL audit.

    Three checks: the audit exists, the disposition is a known enum value, and
    a rejected audit is recorded as calibration rather than deleted. The new
    link state's audit file is never modified.

    Revisions are APPEND-ONLY. A maintainer who changes their mind is itself
    calibration evidence -- "rejected, then confirmed after a second look" and
    "confirmed" teach an analyst different things -- so the superseded verdict
    moves into `history` instead of being overwritten (audit W2-002). Re-importing
    the SAME verdict is idempotent and records no history entry.
    """
    require_action("write_own_index")
    if disposition not in DISPOSITIONS:
        raise PalError(
            "VALIDATION_FAILED",
            f"disposition {disposition!r} is not a closed-loop value",
            next_action="use one of: " + ", ".join(sorted(DISPOSITIONS)),
        )

    status, links, detail = load_links(home)
    if status == "unrecoverable":
        raise PalError("VALIDATION_FAILED", detail)
    if links is None:
        links = empty_links()

    link = None
    for entry in links["links"]:
        if int(entry.get("audit_number", 0)) == audit_number:
            link = entry
            break
    if link is None:
        raise PalError(
            "VALIDATION_FAILED",
            f"no audit with number {audit_number} is linked",
            next_action="run `saipal continue` to build the link ledger first",
        )

    proposed = {
        "disposition": disposition,
        "fix_version": fix_version,
        "receipt_id": receipt_id if receipt_id is not None else link.get("receipt_id"),
        "work_id": work_id if work_id is not None else link.get("work_id"),
    }
    unchanged = link.get("disposition") is not None and all(
        link.get(field) == value for field, value in proposed.items()
    )
    if unchanged:
        return link

    if link.get("disposition") is not None:
        history = link.get("history")
        link["history"] = list(history) if isinstance(history, list) else []
        link["history"].append(
            {
                "disposition": link.get("disposition"),
                "fix_version": link.get("fix_version"),
                "receipt_id": link.get("receipt_id"),
                "work_id": link.get("work_id"),
                "closed_at": link.get("closed_at"),
                "superseded_at": utc_now_iso(),
            }
        )

    link["disposition"] = disposition
    link["fix_version"] = fix_version
    link["closed_at"] = utc_now_iso()
    if receipt_id is not None:
        link["receipt_id"] = receipt_id
    if work_id is not None:
        link["work_id"] = work_id
    save_links(home, links)
    return link


def import_disposition_file(home: Path | str, path: Path | str) -> list[dict]:
    """Import a disposition file ALL-OR-NOTHING (audit SRC-004 W2-006).

    The per-row commit made a failed batch destructive: row 1 committed, row 2
    refused, and the operator could not tell that part of the verdict set had
    already taken effect. Now the whole file is validated against ONE ledger
    snapshot first; any invalid row leaves `closed_loop_links.json`
    byte-identical. Re-importing an already-committed identical verdict stays
    idempotent, and conflicting duplicate rows for one audit are refused rather
    than last-write-wins.
    """
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise PalError("VALIDATION_FAILED", f"disposition file is unreadable: {exc}") from exc
    rows = payload if isinstance(payload, list) else payload.get("dispositions") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise PalError("VALIDATION_FAILED", "disposition file must contain dispositions array")

    # ONE authoritative snapshot behind both validation and the single save.
    status, links, detail = load_links(home)
    if status == "unrecoverable":
        raise PalError("VALIDATION_FAILED", detail)
    if links is None:
        links = empty_links()
    by_audit = {}
    for entry in links["links"]:
        by_audit[int(entry.get("audit_number", 0))] = entry

    # Validate EVERY row against the snapshot before the first mutation.
    plan: list[dict] = []
    decisions: dict[int, dict] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("audit_number"), int) or not isinstance(row.get("disposition"), str):
            raise PalError("VALIDATION_FAILED", "each disposition requires audit_number and disposition")
        audit_number = row["audit_number"]
        proposed = {
            "disposition": row["disposition"],
            "fix_version": row.get("fix_version"),
            "receipt_id": row.get("receipt_id"),
            "work_id": row.get("work_id"),
        }
        if row["disposition"] not in DISPOSITIONS:
            raise PalError(
                "VALIDATION_FAILED",
                f"disposition {row['disposition']!r} is not a closed-loop value",
                next_action="use one of: " + ", ".join(sorted(DISPOSITIONS)),
            )
        previous = decisions.get(audit_number)
        if previous is not None and any(previous.get(k) != v for k, v in proposed.items() if k != "fix_version" or v is not None):
            raise PalError(
                "VALIDATION_FAILED",
                f"contradictory duplicate rows for audit {audit_number} in one batch",
                next_action="one audit, one decision per file; split conflicting verdicts into revisions",
            )
        if audit_number not in by_audit:
            raise PalError(
                "VALIDATION_FAILED",
                f"no audit with number {audit_number} is linked",
                next_action="run `saipal continue` to build the link ledger first",
            )
        decisions[audit_number] = proposed
        plan.append({"audit_number": audit_number, "proposed": proposed, "link": by_audit[audit_number]})

    # Apply in memory, then ONE atomic save. Byte-identical ledger on any
    # earlier refusal is guaranteed because nothing was written before here.
    imported = []
    for item in plan:
        link = item["link"]
        proposed = item["proposed"]
        merged = {
            "disposition": proposed["disposition"],
            "fix_version": proposed["fix_version"],
            "receipt_id": proposed["receipt_id"] if proposed["receipt_id"] is not None else link.get("receipt_id"),
            "work_id": proposed["work_id"] if proposed["work_id"] is not None else link.get("work_id"),
        }
        unchanged = link.get("disposition") is not None and all(
            link.get(field) == value for field, value in merged.items()
        )
        if unchanged:
            imported.append(link)
            continue
        if link.get("disposition") is not None:
            history = link.get("history")
            link["history"] = list(history) if isinstance(history, list) else []
            link["history"].append(
                {
                    "disposition": link.get("disposition"),
                    "fix_version": link.get("fix_version"),
                    "receipt_id": link.get("receipt_id"),
                    "work_id": link.get("work_id"),
                    "closed_at": link.get("closed_at"),
                    "superseded_at": utc_now_iso(),
                }
            )
        link["disposition"] = merged["disposition"]
        link["fix_version"] = merged["fix_version"]
        link["closed_at"] = utc_now_iso()
        if merged["receipt_id"] is not None:
            link["receipt_id"] = merged["receipt_id"]
        if merged["work_id"] is not None:
            link["work_id"] = merged["work_id"]
        imported.append(link)
    save_links(home, links)
    return imported


def calibrate_finding(
    home: Path | str,
    finding: dict,
    *,
    links_payload: dict | None = None,
) -> dict:
    """Historical calibration signal for a finding or candidate.

    Computes maintainer verdict history for this finding's fingerprint and
    drift class: how many were confirmed, how many rejected, and whether the
    maintainer previously closed this exact root cause as a known non-issue.
    """
    if links_payload is None:
        status, payload, _ = load_links(home)
        links = payload.get("links", []) if status == "ok" and payload else []
    else:
        links = links_payload.get("links", [])

    fid = finding.get("finding_id")
    drift_class = finding.get("drift_class")

    confirmed = 0
    rejected = 0
    superseded = 0
    total = 0
    latest_fix_version = None

    for link in links:
        disp = link.get("disposition")
        if not disp:
            continue
        # Direct finding ID match
        if fid and link.get("finding_id") == fid:
            total += 1
            if disp in ("CONFIRMED_PROTOCOL_DEFECT", "ENGINE_FIX", "ADAPTER_FIX", "HARNESS_FIX"):
                confirmed += 1
            elif disp in ("REJECTED_FINDING", "NOT_APPLICABLE", "NO_CHANGE"):
                rejected += 1
            elif disp in ("SUPERSEDED", "DUPLICATE"):
                superseded += 1
            if link.get("fix_version"):
                latest_fix_version = link.get("fix_version")

    return {
        "finding_id": fid,
        "drift_class": drift_class,
        "total_dispositions": total,
        "confirmed": confirmed,
        "rejected": rejected,
        "superseded": superseded,
        "latest_fix_version": latest_fix_version,
        "has_prior_rejection": rejected > 0,
        "confidence_adjustment": "DOWNGRADE_LOW" if (rejected > 0 and confirmed == 0) else "NONE",
    }


def reconstruct_provenance(home: Path | str, *, audit_number: int) -> dict:
    """Cold-start-safe traceback: audit_number -> finding -> audit -> links."""
    status, links, detail = load_links(home)
    if status == "unrecoverable":
        raise PalError("VALIDATION_FAILED", detail)

    chain: dict = {"audit_number": audit_number, "links": []}
    if links is None:
        return chain
    for entry in links["links"]:
        if int(entry.get("audit_number", 0)) == audit_number:
            chain["audit_path"] = entry.get("audit_path")
            chain["audit_sha256"] = entry.get("audit_sha256")
            chain["finding_id"] = entry.get("finding_id")
            chain["receipt_id"] = entry.get("receipt_id")
            chain["work_id"] = entry.get("work_id")
            chain["disposition"] = entry.get("disposition")
            chain["fix_version"] = entry.get("fix_version")
            chain["closed_at"] = entry.get("closed_at")
            chain["links"] = [entry]
            break
    return chain

