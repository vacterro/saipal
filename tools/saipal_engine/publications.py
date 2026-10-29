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
    finding_id: str | None = None,
) -> dict | None:
    """Record that the sink confirmed this audit. Returns the entry, or None.

    W2-007 (SRC-004): the publication ledger is the AUTHORITATIVE delivery
    truth. This also reconciles the finding's duplicated
    `audit.delivery` cache to PUBLISHED so a consumer reading the finding
    (rather than the ledger) cannot see a false outage forever. The
    reconciliation is best-effort-then-idempotent: `delivery_status` re-derives
    from the ledger on every read, so a crash between the sink write and this
    cache update still converges on the next cold start.
    """
    status, ledger, detail = load_publications(home)
    if status != STATUS_OK or ledger is None:
        return None
    matched = None
    for entry in ledger["publications"]:
        if _key(entry) == (int(audit_number), str(audit_sha256)):
            entry["status"] = PUBLISHED
            entry["published_at"] = utc_now_iso()
            entry.pop("reason", None)
            matched = entry
            break
    if matched is not None:
        save_publications(home, ledger, registry=registry)
        _reconcile_finding_delivery(
            home, matched.get("finding_id"), registry=registry
        )
    return matched


def delivery_status(home: Path | str, finding: dict) -> str:
    """W2-007: authoritative delivery state for a finding's staged audit.

    The publication ledger wins for the COMPLETE supported state set
    (PENDING, PUBLISHED, QUARANTINED): a matching `(audit_number,
    audit_sha256)` ledger row is the delivery truth even when the finding's own
    `audit.delivery` cache is stale in either direction -- so a PENDING ledger
    entry overrides a stale PUBLISHED finding cache just as a PUBLISHED entry
    overrides a stale PENDING one. The finding cache is consulted only when no
    matching authoritative ledger row exists. A matching row carrying an
    unsupported status is a malformed ledger and fails closed rather than
    letting a stale cache claim delivery.
    """
    audit = finding.get("audit") or {}
    number = audit.get("audit_number")
    sha = audit.get("audit_sha256")
    if number is None or sha is None:
        return str(audit.get("delivery") or PENDING)
    status, ledger, detail = load_publications(home)
    if status == STATUS_UNRECOVERABLE:
        raise PalError("VALIDATION_FAILED", detail)
    if status == STATUS_OK and ledger is not None:
        expected_key = (int(number or 0), str(sha))
        for entry in ledger["publications"]:
            if not isinstance(entry, dict) or _key(entry) != expected_key:
                continue
            delivery = entry.get("status")
            if delivery in (PENDING, PUBLISHED, QUARANTINED):
                return str(delivery)
            raise PalError(
                "VALIDATION_FAILED",
                f"publication ledger has unsupported delivery status {delivery!r}",
            )
    return str(audit.get("delivery") or PENDING)


def _reconcile_finding_delivery(
    home: Path, finding_id: object, *, registry: dict | None = None
) -> None:
    """Converge one finding's `audit.delivery` cache to the ledger truth.

    Idempotent and silent: a missing findings index or missing finding is not an
    error (the ledger is still authoritative), and a crash here is repaired by
    the next `delivery_status` read or the next retry reconciliation.
    """
    from . import findings as findings_mod
    from .paths import read_json

    if finding_id is None:
        return
    path = home_paths(home).findings_index
    if not path.exists():
        return
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError):
        return
    if not isinstance(payload, dict):
        return
    dirty = False
    for finding in payload.get("findings") or []:
        if not isinstance(finding, dict) or finding.get("finding_id") != finding_id:
            continue
        audit = finding.get("audit")
        if isinstance(audit, dict) and audit.get("delivery") != PUBLISHED:
            audit["delivery"] = PUBLISHED
            dirty = True
    if dirty:
        try:
            findings_mod.save_index(home, payload, registry=registry)
        except Exception:
            # The ledger stays authoritative; the next cold-start read
            # re-derives the truth and the cache converges then.
            pass


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


def _findings_map(home: Path) -> dict[str, dict]:
    """The findings index as `finding_id -> finding`, parsed ONCE per transaction.

    PERF-005 (SRC-011): `_referenced_finding` reparsed the complete findings
    index for every pending entry, so a quarantine/retry pass cost
    O(pending_count x findings_history) full parses. Callers preload this map
    once and reuse it; `_referenced_finding` keeps its standalone behavior for
    single lookups.
    """
    from .paths import read_json

    path = home_paths(home).findings_index
    if not path.exists():
        return {}
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {
        str(finding.get("finding_id")): finding
        for finding in payload.get("findings") or []
        if isinstance(finding, dict) and finding.get("finding_id") is not None
    }


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
    findings_by_id = _findings_map(Path(home))
    newly: list[dict] = []
    for entry in ledger["publications"]:
        if not isinstance(entry, dict) or entry.get("status") != PENDING:
            continue
        finding = findings_by_id.get(str(entry.get("finding_id")))
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

    result = {
        "attempted": 0, "published": 0, "still_pending": 0,
        "quarantined": 0, "failures": [],
    }

    # PERF-005 (SRC-011): ONE publication-ledger load backs both the revalidation
    # and the mutation (the previous `pending(home)` call loaded the same ledger
    # again before this one), and the findings index is parsed ONCE into an
    # id->finding map instead of once per pending entry.
    status, ledger, _detail = load_publications(home)
    if status != STATUS_OK or ledger is None:
        result["failures"].append({"reason": "publication ledger is unreadable"})
        return result
    root = Path(home)
    findings_by_id = _findings_map(root)
    ledger_dirty = False
    still: list[dict] = []
    for entry in [e for e in ledger["publications"]
                  if isinstance(e, dict) and e.get("status") == PENDING]:
        finding = findings_by_id.get(str(entry.get("finding_id")))
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
        # The publication gate is revalidated at THIS external-effect boundary too:
        # a readiness proof that was valid at setup time may no longer match the
        # reviewed sink identity or software fingerprint (post-setup mutation,
        # reviewed sink substitution, or authored-code change). A closed gate does
        # NOT quarantine -- the audit is still a valid local staging; it simply
        # stays pending until a fresh, matching review is minted.
        try:
            from . import readiness as _readiness

            _readiness.check_publish_gate(home, sink)
        except Exception as exc:  # noqa: BLE001 - any gate failure keeps the audit pending
            code = getattr(exc, "code", "") or type(exc).__name__
            if code != "PUBLICATION_GATE_CLOSED":
                raise
            result["still_pending"] += 1
            result["failures"].append(
                {
                    "audit_number": entry.get("audit_number"),
                    "reason": f"publication gate closed: {getattr(exc, 'message', str(exc))}",
                }
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
            finding_id=str(entry.get("finding_id") or "") or None,
            registry=registry,
        )
        result["published"] += 1
    return result
