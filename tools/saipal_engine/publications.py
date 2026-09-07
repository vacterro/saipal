"""Pending external publication: local staging is not delivery (audit CORE-007).

`PUBLISH_ENABLED` means a configured maintainer sink receives the numbered audit.
When that sink is unavailable the audit still stages locally -- correct, a finding
is never lost to an outage -- but the finding used to advance to `EMITTED`
regardless, so the outage permanently lost delivery: nothing recorded that the
sink had never seen it, and no later cycle tried again.

This ledger is that record. It holds the audit number and body digest of every
staged audit a sink has not confirmed, so the next cycle republishes exactly that
audit rather than allocating a new one.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .capability import require_action
from .errors import PalError
from .paths import atomic_write_json, home_paths, read_json, utc_now_iso

SCHEMA_VERSION = 1

STATUS_ABSENT = "absent"
STATUS_OK = "ok"
STATUS_UNRECOVERABLE = "unrecoverable"

#: A staged audit no sink has confirmed.
PENDING = "PENDING"
#: A sink write that was verified at the target.
PUBLISHED = "PUBLISHED"
#: Held from delivery: the audit predates the semantic authority boundary, so
#: its finding carries no valid semantic DRIFT confirmation. The bytes, the
#: digest, the number and the history are preserved; only delivery is refused.
QUARANTINED = "QUARANTINED"

QUARANTINE_REASON = (
    "this audit predates the semantic authority boundary: its finding carries "
    "no valid semantic DRIFT confirmation tied to a BOUND historical protocol "
    "authority, so it is held from delivery pending semantic review "
    "(PAL-ARCH-01)"
)


def empty_ledger() -> dict:
    return {"schema_version": SCHEMA_VERSION, "publications": []}


def load_publications(home: Path | str) -> tuple[str, dict | None, str]:
    """`(status, ledger, detail)`.

    Corruption is NOT absence. An unreadable ledger refuses mutation and keeps its
    bytes: overwriting it would silently drop the record of every undelivered
    audit, which is the same class of failure this module exists to prevent.
    """
    path = home_paths(home).publications
    if not path.exists():
        return STATUS_ABSENT, None, ""
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return STATUS_UNRECOVERABLE, None, f"publication ledger is unreadable: {exc}"
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != SCHEMA_VERSION
        or not isinstance(payload.get("publications"), list)
    ):
        return STATUS_UNRECOVERABLE, None, "publication ledger is malformed"
    return STATUS_OK, payload, ""


def save_publications(home: Path | str, ledger: dict, *, registry: dict | None = None) -> dict:
    require_action("write_own_index", registry=registry)
    paths = home_paths(home)
    atomic_write_json(paths.publications, ledger, root=paths.root)
    return ledger


def _key(entry: dict) -> tuple[int, str]:
    return (int(entry.get("audit_number") or 0), str(entry.get("audit_sha256") or ""))


def record_pending(
    home: Path | str,
    *,
    finding_id: str,
    audit_number: int,
    audit_path: str,
    audit_sha256: str,
    reason: str,
    registry: dict | None = None,
) -> dict:
    """Note that this exact audit is staged but undelivered. Idempotent."""
    status, ledger, detail = load_publications(home)
    if status == STATUS_UNRECOVERABLE:
        from .errors import PalError

        raise PalError("VALIDATION_FAILED", detail)
    if ledger is None:
        ledger = empty_ledger()

    entry = {
        "finding_id": str(finding_id),
        "audit_number": int(audit_number),
        "audit_path": str(audit_path),
        "audit_sha256": str(audit_sha256),
        "status": PENDING,
        "reason": str(reason),
        "attempts": 1,
        "first_failed_at": utc_now_iso(),
        "last_attempt_at": utc_now_iso(),
    }
    for existing in ledger["publications"]:
        if _key(existing) == _key(entry):
            existing["status"] = PENDING
            existing["reason"] = entry["reason"]
            existing["attempts"] = int(existing.get("attempts") or 0) + 1
            existing["last_attempt_at"] = entry["last_attempt_at"]
            save_publications(home, ledger, registry=registry)
            return existing
    ledger["publications"].append(entry)
    save_publications(home, ledger, registry=registry)
    return entry


def mark_published(
    home: Path | str,
    *,
    audit_number: int,
    audit_sha256: str,
    registry: dict | None = None,
) -> dict | None:
    """Record that the sink confirmed this audit. Returns the entry, or None."""
    status, ledger, detail = load_publications(home)
    if status != STATUS_OK or ledger is None:
        return None
    for entry in ledger["publications"]:
        if _key(entry) == (int(audit_number), str(audit_sha256)):
            entry["status"] = PUBLISHED
            entry["published_at"] = utc_now_iso()
            entry.pop("reason", None)
            save_publications(home, ledger, registry=registry)
            return entry
    return None


def pending(home: Path | str) -> list[dict]:
    """Every staged audit still awaiting delivery, oldest first.

    Quarantined audits are deliberately absent: a quarantine is not a retryable
    state, and returning it here would let the next cycle deliver what the
    authority boundary held back.
    """
    status, ledger, _detail = load_publications(home)
    if status != STATUS_OK or ledger is None:
        return []
    return [
        entry
        for entry in ledger["publications"]
        if isinstance(entry, dict) and entry.get("status") == PENDING
    ]


def quarantined(home: Path | str) -> list[dict]:
    """Every audit held from delivery by the authority boundary."""
    status, ledger, _detail = load_publications(home)
    if status != STATUS_OK or ledger is None:
        return []
    return [
        entry
        for entry in ledger["publications"]
        if isinstance(entry, dict) and entry.get("status") == QUARANTINED
    ]


def _referenced_finding(home: Path, finding_id: object) -> dict | None:
    from . import findings as findings_mod
    from .paths import read_json

    path = home_paths(home).findings_index
    if not path.exists():
        return None
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    for finding in payload.get("findings") or []:
        if isinstance(finding, dict) and finding.get("finding_id") == finding_id:
            return finding
    return None


def publication_problems(
    home: Path | str, finding: dict | None, entry: dict
) -> list[str]:
    """Every reason this pending entry may NOT be delivered right now.

    A ledger entry is historical transport state, never authority to publish.
    The referenced finding must still exist, still carry a semantic DRIFT
    confirmation judged against a BOUND historical authority, still name this
    exact audit slot, and the staged bytes must still hash to what was staged.
    """
    from . import findings as findings_mod
    from .paths import sha256_file

    problems: list[str] = []
    if finding is None:
        problems.append("the referenced finding no longer exists")
        return problems
    if not findings_mod.is_semantically_confirmed(finding):
        problems.append(
            "the finding carries no valid semantic DRIFT confirmation "
            "(no external audit without a semantic verdict; PAL-ARCH-01)"
        )
    confirmation = finding.get("semantic_confirmation") or {}
    binding = confirmation.get("protocol_binding") or {}
    if str(binding.get("binding_status") or "UNKNOWN") != "BOUND":
        problems.append(
            "the semantic confirmation is not backed by a BOUND historical "
            "protocol authority"
        )
    audit = finding.get("audit") or {}
    if not isinstance(audit, dict) or not audit:
        problems.append("the finding records no staged audit")
    elif int(audit.get("audit_number") or -1) != int(entry.get("audit_number") or -2):
        problems.append("the staged audit identity does not match the ledger entry")
    staged = Path(home) / str(entry.get("audit_path") or "")
    if not staged.is_file():
        problems.append("the staged audit file is missing")
    elif sha256_file(staged) != str(entry.get("audit_sha256") or ""):
        problems.append("the staged audit digest no longer matches the ledger entry")
    return problems


def quarantine_unconfirmed(home: Path | str, *, registry: dict | None = None) -> list[dict]:
    """Hold every pending audit whose finding lacks publish authority.

    Idempotent: an already-quarantined entry is left exactly as it is, and a
    PUBLISHED entry is never touched (history is not rewritten). Returns the
    entries quarantined by THIS call.
    """
    status, ledger, detail = load_publications(home)
    if status == STATUS_UNRECOVERABLE:
        raise PalError("VALIDATION_FAILED", detail)
    if ledger is None:
        return []
    newly: list[dict] = []
    for entry in ledger["publications"]:
        if not isinstance(entry, dict) or entry.get("status") != PENDING:
            continue
        finding = _referenced_finding(home, entry.get("finding_id"))
        problems = publication_problems(home, finding, entry)
        if not problems:
            continue
        entry["status"] = QUARANTINED
        entry["quarantine_reason"] = QUARANTINE_REASON
        entry["quarantine_problems"] = problems
        entry["quarantined_at"] = utc_now_iso()
        newly.append(entry)
    if newly:
        save_publications(home, ledger, registry=registry)
    return newly


def retry_pending(home: Path | str, *, registry: dict | None = None) -> dict[str, Any]:
    """Republish every pending audit through the configured sink.

    Runs before ordinary cycle work, so a restored sink receives the backlog
    before anything new is produced. Reuses the staged body and its audit number:
    a retry that allocated a fresh number would publish the same finding twice.

    Every entry is REVALIDATED before the sink is touched: the referenced
    finding must still exist, still carry a semantic DRIFT confirmation tied to
    a BOUND historical authority, and the staged bytes must still verify. A
    failed check quarantines the entry (bytes preserved, never delivered) and
    names the reason. A ledger entry is transport history, not authority to
    publish -- so this function is safe even if it is ever called before the
    cycle's own migration step.
    """
    from . import audits as audits_mod  # noqa: F401  (kept for parity/imports)
    from .errors import PalError
    from .sink import configured_sink

    outstanding = pending(home)
    result = {
        "attempted": len(outstanding), "published": 0, "still_pending": 0,
        "quarantined": 0, "failures": [],
    }
    if not outstanding:
        return result

    # Authority BEFORE transport: an entry that fails revalidation is
    # quarantined whether or not any sink is configured, so calling this
    # function never depends on delivery being possible. ONE ledger load
    # backs both the revalidation and the mutation, so a quarantined entry
    # cannot be silently re-saved from a stale second copy.
    status, ledger, _detail = load_publications(home)
    if status != STATUS_OK or ledger is None:
        result["still_pending"] = len(outstanding)
        result["failures"].append({"reason": "publication ledger is unreadable"})
        return result
    root = Path(home)
    ledger_dirty = False
    still: list[dict] = []
    for entry in [e for e in ledger["publications"]
                  if isinstance(e, dict) and e.get("status") == PENDING]:
        finding = _referenced_finding(root, entry.get("finding_id"))
        problems = publication_problems(root, finding, entry)
        if problems:
            entry["status"] = QUARANTINED
            entry["quarantine_reason"] = QUARANTINE_REASON
            entry["quarantine_problems"] = problems
            entry["quarantined_at"] = utc_now_iso()
            ledger_dirty = True
            result["quarantined"] += 1
            result["failures"].append(
                {
                    "audit_number": entry.get("audit_number"),
                    "reason": "; ".join(problems),
                }
            )
            continue
        still.append(entry)
    if ledger_dirty:
        save_publications(home, ledger, registry=registry)
    outstanding = still
    result["attempted"] = len(outstanding)
    if not outstanding:
        return result

    sink_status, sink, sink_detail = configured_sink(home)
    if sink_status != "ok" or sink is None:
        result["still_pending"] = len(outstanding)
        result["failures"].append({"reason": sink_detail or "no sink configured"})
        return result

    for entry in outstanding:
        staged = root / str(entry.get("audit_path") or "")
        try:
            body = staged.read_text(encoding="utf-8")
        except OSError as exc:
            result["still_pending"] += 1
            result["failures"].append(
                {"audit_number": entry.get("audit_number"), "reason": f"staged audit unreadable: {exc}"}
            )
            continue
        finding_stub = {"finding_id": entry.get("finding_id")}
        try:
            # Reuse the number the audit was staged as: a fresh one would deliver
            # the same finding to the maintainer under a second identity.
            published = sink.publish(
                finding_stub, body, reserve_number=int(entry.get("audit_number") or 0)
            )
            if not sink.verify(published):
                raise PalError("SINK_UNAVAILABLE", "sink write did not verify")
        except (OSError, PalError) as exc:
            result["still_pending"] += 1
            result["failures"].append(
                {"audit_number": entry.get("audit_number"), "reason": str(exc)}
            )
            continue
        mark_published(
            home,
            audit_number=int(entry.get("audit_number") or 0),
            audit_sha256=str(entry.get("audit_sha256") or ""),
            registry=registry,
        )
        result["published"] += 1
    return result
