"""Recurrence / regression intelligence (Wave H)."""

from __future__ import annotations

import copy
import re
from pathlib import Path

from .capability import require_action
from .errors import PalError
from .paths import atomic_write_json, home_paths, read_json

SCHEMA_VERSION = 1

TELEMETRY_KEYS = (
    "sessions_analyzed", "events_analyzed", "bytes_loaded",
    "rule_bytes_loaded", "findings_created", "findings_rejected",
    "audits_emitted", "avg_context_per_episode",
)

_VERSION = re.compile(r"\d+")

#: Recurrence ledger schema. v1 anchored rows on the finding's WHOLE
#: occurrence set (T-74 defect); v2 anchors every row on exactly ONE evidence
#: occurrence and carries the legacy-anchor migration status (T-104/T-75).
SCHEMA_VERSION = 2
ANCHOR_GENERATION = "v2"


def _anchor_generation() -> str:
    return ANCHOR_GENERATION


def _vt(value) -> tuple:
    return tuple(int(part) for part in _VERSION.findall(str(value or "")))


def _project(session: dict) -> str:
    project = session.get("project")
    if isinstance(project, dict):
        for key in ("id", "name", "slug", "repo"):
            value = project.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return "unknown"


def _provider(session: dict) -> str:
    runtime = session.get("runtime")
    if isinstance(runtime, dict):
        value = runtime.get("provider")
        if isinstance(value, str) and value.strip():
            return value.strip()
    parts = str(session.get("adapter") or "").split(":")
    if len(parts) > 1 and parts[1].strip():
        return parts[1].strip()
    head = parts[0].strip().lower() if parts else ""
    return head or "unknown"


def _refs(occurrence: dict) -> str:
    out = []
    for ref in occurrence.get("event_refs") or []:
        try:
            out.append(int(ref))
        except (TypeError, ValueError):
            out.append(str(ref))
    return ",".join(str(ref) for ref in sorted(out, key=str))


def _occurrence_anchor(occurrence: dict) -> str | None:
    """The closed evidence identity of ONE occurrence (T-104).

    One immutable evidence occurrence == one anchor == one ledger row
    identity. The tuple is (session, episode, exact event refs) scoped by the
    finding's fingerprint: finding prose, severity, confidence, the mutable
    occurrence ARRAY around it and the recurrence count are all excluded, so
    a finding that GROWS never changes the identity of the occurrence it
    already stood on. `None` for a synthetic or evidence-less finding.
    """
    if not isinstance(occurrence, dict):
        return None
    episode = occurrence.get("episode_id")
    refs = _refs(occurrence)
    if episode is None and not refs:
        return None
    return f"{episode}:{refs}"


def _session_occurrences(session: dict, finding: dict) -> list[dict]:
    """This finding's occurrences that stand on THIS session's evidence."""
    session_id = session.get("session_id")
    return [
        row
        for row in finding.get("occurrences") or []
        if isinstance(row, dict)
        and row.get("session_id") == session_id
        and _occurrence_anchor(row) is not None
    ]


def _evidence_anchor(session: dict, finding: dict) -> list[str]:
    """Backwards-compatible view: every per-occurrence anchor in one list.

    T-104 narrowed the ROW anchor to a single occurrence (`_occurrence_anchor`);
    callers that want the whole session's evidence set read this. An empty
    list means no anchor is claimed and the historical write semantics stand.
    """
    return sorted(
        token
        for token in (_occurrence_anchor(row) for row in _session_occurrences(session, finding))
        if token is not None
    )


def _occurrence(
    session: dict,
    finding: dict,
    *,
    conformant: bool,
    occurrence_id: str = "",
    evidence_anchor: str | None = None,
    anchor_generation: str | None = None,
) -> dict:
    adapter = str(session.get("adapter") or "")
    model = adapter.split(":", 1)[0].strip().lower() or "unknown"
    entry = {
        "session_id": session.get("session_id"),
        "adapter": adapter,
        "provider": _provider(session),
        "model_family": model,
        "project": _project(session),
        "protocol_version": ((session.get("protocol") or {}).get("version") or "").strip(),
        "drift_class": str(finding.get("drift_class") or "UNKNOWN"),
        "confidence": finding.get("confidence") or "LOW",
        "severity": finding.get("severity") or "P3",
        "conformant": conformant,
        "imported_at": session.get("imported_at") or "",
    }
    # An identity for the WRITE, not for the session: a retry after a crash must
    # be recognizable as the same occurrence rather than counted twice (audit
    # W2-002). Absent means an unkeyed caller, which stays append-only.
    if occurrence_id:
        entry["occurrence_id"] = str(occurrence_id)
    # T-104 (ROLE 16): an identity for the EVIDENCE, closed per ONE occurrence.
    # One immutable evidence occurrence == one anchor == one row identity.
    if evidence_anchor:
        entry["evidence_anchor"] = str(evidence_anchor)
        if anchor_generation:
            entry["anchor_generation"] = str(anchor_generation)
    return entry


def empty_recurrence() -> dict:
    return {"schema_version": SCHEMA_VERSION, "by_finding": {}, "by_rule": {}}


def _findings_occurrence_map(paths) -> dict[str, dict[str, list[str]]]:
    """fingerprint -> session_id -> [per-occurrence anchor tokens], tolerant.

    The migration's defensible-match source (T-104/T-75): a legacy row without
    an anchor can only be backfilled when the finding index names exactly ONE
    evidence occurrence for that session. Anything else stays unanchored and
    flagged -- an anchor is never fabricated.
    """
    if not paths.findings_index.exists():
        return {}
    try:
        payload = read_json(paths.findings_index)
    except (OSError, ValueError, UnicodeDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    out: dict[str, dict[str, list[str]]] = {}
    for rec in payload.get("findings") or []:
        if not isinstance(rec, dict):
            continue
        fp = str(rec.get("fingerprint") or "")
        if not fp:
            continue
        bucket = out.setdefault(fp, {})
        for occ in rec.get("occurrences") or []:
            if not isinstance(occ, dict):
                continue
            sid = str(occ.get("session_id") or "")
            token = _occurrence_anchor(occ)
            if not sid or token is None:
                continue
            tokens = bucket.setdefault(sid, [])
            if token not in tokens:
                tokens.append(token)
    return out


def migrate_recurrence(home: Path | str, *, registry=None) -> dict:
    """One-shot v1 -> v2 ledger migration (T-104/T-75). Deterministic.

    v1 anchored rows on the finding's WHOLE occurrence set, so a grown finding
    changed the anchor of rows it already stood on (T-74), and pre-anchor rows
    carry none at all (T-75). This pass, run once before any new write:

    - a v1 row whose anchor names exactly ONE occurrence -> backfilled to the
      per-occurrence scalar anchor;
    - a v1 row whose anchor names SEVERAL -> preserved verbatim, flagged
      AMBIGUOUS -- the row stood on more than one occurrence and the exact one
      it represents is not recoverable, so nothing is guessed;
    - a v1 row with NO anchor -> backfilled only when the finding index names
      exactly ONE evidence occurrence for that session; several -> AMBIGUOUS;
      none -> preserved, flagged UNRESOLVED.

    Atomic (whole-ledger write), restart-safe (a crash leaves the v1 file, the
    next run derives the same v2), idempotent (v2 short-circuits). History is
    never deleted. A PRESENT corrupt ledger refuses with zero writes (ROLE 7):
    migration never replaces history it cannot read.
    """
    paths = home_paths(home)
    if paths.recurrence.exists() and recurrence_status(home) == RECURRENCE_INVALID:
        raise PalError(
            "VALIDATION_FAILED",
            f"{paths.recurrence.name} is corrupt; migration refuses to "
            "replace or touch it -- the original bytes stay untouched",
            next_action="inspect or restore the file manually",
        )
    data = load_recurrence(home)
    if data.get("schema_version") == SCHEMA_VERSION:
        return {"migrated": False, "backfilled": 0, "ambiguous": 0, "unresolved": 0}
    evidence = _findings_occurrence_map(paths)
    stats = {"backfilled": 0, "ambiguous": 0, "unresolved": 0}
    for entry in data.get("by_finding", {}).values():
        if not isinstance(entry, dict):
            continue
        fp = str(entry.get("fingerprint") or "")
        per_session = evidence.get(fp) or {}
        for row in entry.get("occurrences") or []:
            if not isinstance(row, dict):
                continue
            if isinstance(row.get("evidence_anchor"), str):
                continue  # already per-occurrence
            if row.get("anchor_status"):
                continue  # already migrated-and-flagged
            legacy = row.get("evidence_anchor")
            if isinstance(legacy, list):
                tokens = sorted({str(t) for t in legacy if t})
                if len(tokens) == 1:
                    row["evidence_anchor"] = tokens[0]
                    row["anchor_status"] = "MIGRATED"
                    stats["backfilled"] += 1
                elif len(tokens) > 1:
                    row["legacy_anchor"] = tokens
                    row.pop("evidence_anchor", None)
                    row["anchor_status"] = "AMBIGUOUS"
                    stats["ambiguous"] += 1
                else:
                    row["anchor_status"] = "UNRESOLVED"
                    stats["unresolved"] += 1
                continue
            # Pre-anchor row: only an exact single evidence match backfills.
            sid = str(row.get("session_id") or "")
            tokens = sorted(set(per_session.get(sid) or []))
            if len(tokens) == 1:
                row["evidence_anchor"] = tokens[0]
                row["anchor_status"] = "MIGRATED"
                stats["backfilled"] += 1
            elif len(tokens) > 1:
                row["anchor_status"] = "AMBIGUOUS"
                stats["ambiguous"] += 1
            else:
                row["anchor_status"] = "UNRESOLVED"
                stats["unresolved"] += 1
    data["schema_version"] = SCHEMA_VERSION
    save_recurrence(home, data, registry=registry)
    return {"migrated": True, **stats}


def _ensure_migrated(home, *, registry=None) -> None:
    """Operational migration runs before ANY new recurrence write (ROLE 19)."""
    migrate_recurrence(home, registry=registry)


def _valid(data) -> bool:
    """Structural validation, hardened beyond the shallow v2 check (ROLE 11).

    Mutation assumes every by_finding VALUE is an entry dict with a list of
    occurrence dicts, and every by_rule VALUE is a counter dict. A payload that
    violates those shapes would crash or corrupt on the next write, so it is
    refused at load time instead of silently reclassified or written over.
    """
    if not (
        isinstance(data, dict)
        and data.get("schema_version") in (1, SCHEMA_VERSION)
        and isinstance(data.get("by_finding"), dict)
        and isinstance(data.get("by_rule"), dict)
    ):
        return False
    for entry in data.get("by_finding").values():
        if not isinstance(entry, dict) or not isinstance(entry.get("occurrences"), list):
            return False
        for row in entry["occurrences"]:
            if not isinstance(row, dict):
                return False
    for counter in data.get("by_rule").values():
        if not isinstance(counter, dict) or not isinstance(
            counter.get("total"), int
        ) or isinstance(counter.get("total"), bool):
            return False
        if not isinstance(counter.get("drift"), int) or isinstance(counter.get("drift"), bool):
            return False
    return True


#: Recurrence read states (ROLE 5): ABSENT legitimately means a fresh empty
#: ledger; VALID means v1/v2 loaded; INVALID means the file EXISTS but cannot
#: be parsed or validated -- which must never be read as an empty ledger.
RECURRENCE_ABSENT = "ABSENT"
RECURRENCE_VALID = "VALID"
RECURRENCE_INVALID = "INVALID"


def recurrence_status(home: Path | str) -> str:
    """Read-only corruption probe (ROLE 8): zero writes, no repair."""
    paths = home_paths(home)
    if not paths.recurrence.exists():
        return RECURRENCE_ABSENT
    try:
        payload = read_json(paths.recurrence)
    except (OSError, ValueError, UnicodeDecodeError):
        return RECURRENCE_INVALID
    return RECURRENCE_VALID if _valid(payload) else RECURRENCE_INVALID


def load_recurrence(home: Path | str) -> dict:
    """Fail-closed load (ROLE 6).

    ABSENT -> a fresh empty ledger (a legitimate bootstrap). A PRESENT file
    that is unreadable or structurally invalid raises instead of silently
    reclassifying history as empty: the next write would otherwise replace the
    whole ledger. Nothing here renames, truncates, repairs or guesses -- the
    corrupt bytes stay untouched for the operator.
    """
    paths = home_paths(home)
    if not paths.recurrence.exists():
        return empty_recurrence()
    try:
        payload = read_json(paths.recurrence)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise PalError(
            "VALIDATION_FAILED",
            f"{paths.recurrence.name} exists but cannot be read as JSON "
            f"({exc.__class__.__name__}); historical recurrence state was "
            "left untouched",
            next_action="inspect or restore the file manually; no write "
            "touches it until it parses",
        ) from exc
    if not _valid(payload):
        raise PalError(
            "VALIDATION_FAILED",
            f"{paths.recurrence.name} exists but is not a valid recurrence "
            f"ledger (schema_version="
            f"{payload.get('schema_version')!r} when parsed as JSON); "
            "historical recurrence state was left untouched",
            next_action="inspect or restore the file manually; no write "
            "touches it until it validates",
        )
    return payload


def require_recurrence_healthy(home: Path | str) -> None:
    """Mutating-startup gate (ROLE 9): refuse BEFORE new effects.

    A present-but-corrupt ledger fails closed here so watch/investigate/
    continue never spend semantic or model work and only then discover the
    ledger cannot be written to without destroying it.
    """
    status = recurrence_status(home)
    if status == RECURRENCE_VALID:
        return
    if status == RECURRENCE_INVALID:
        raise PalError(
            "VALIDATION_FAILED",
            f"{home_paths(home).recurrence.name} is corrupt; refusing to "
            "start mutating work that would need the recurrence ledger",
            next_action="inspect or restore the file manually; read-only "
            "surfaces may still report recurrence_status INVALID",
        )


def save_recurrence(home: Path | str, data: dict, *, registry=None) -> dict:
    require_action("write_own_index", registry=registry)
    if not _valid(data):
        raise PalError(
            "VALIDATION_FAILED", "refusing to write an invalid recurrence",
            next_action="the existing recurrence was left untouched",
        )
    paths = home_paths(home)
    atomic_write_json(paths.recurrence, data, root=paths.root)
    return data


def _bump_occurrence(
    data: dict, finding: dict, session: dict, *, conformant: bool, occurrence_id: str = ""
) -> bool:
    """Record every unrecorded evidence occurrence of one session (T-104).

    Identity is PER OCCURRENCE: `(session_id, episode, event_refs)` under the
    finding's fingerprint. A row is written at most once under either identity
    it carries -- the write key (a crashed-then-retried submission, W2-002) or
    the per-occurrence anchor. The same occurrence observed first by
    mechanical triage and later confirmed semantically converges to ONE row;
    a finding that GROWS between the writes leaves the earlier row's identity
    untouched (T-74) and adds only genuinely new evidence; a legacy row with
    no anchor converges onto the anchored row that names its evidence (T-75).
    Returns True when anything was written.
    """
    fingerprint = str(finding.get("fingerprint") or finding.get("finding_id")
                      or finding.get("drift_class") or "UNKNOWN")
    entry = data["by_finding"].setdefault(fingerprint, {
        "finding_id": finding.get("finding_id") or "",
        "fingerprint": fingerprint,
        "causal_key": finding.get("causal_key") or "",
        "drift_class": str(finding.get("drift_class") or "UNKNOWN"),
        "severity": finding.get("severity") or "P3",
        "confidence": finding.get("confidence") or "LOW",
        "last_fix_version": finding.get("last_fix_version") or "",
        "occurrences": [],
    })
    # An entry created before causal keys existed, or by the negative-evidence
    # path, gains its key the first time a real finding supplies one.
    if not entry.get("causal_key") and finding.get("causal_key"):
        entry["causal_key"] = finding["causal_key"]
    # Snapshot the identity of the rows as they exist before this write, so a
    # caller passing a ledger entry back in cannot claim anchors off its own
    # mutable occurrence array.
    recorded_anchors = {
        (existing.get("session_id"), str(existing.get("evidence_anchor") or ""))
        for existing in entry["occurrences"]
        if isinstance(existing, dict)
    }
    session_id = session.get("session_id")
    pending = _session_occurrences(session, finding)
    if occurrence_id and any(
        str(existing.get("occurrence_id") or "") == str(occurrence_id)
        for existing in entry["occurrences"]
    ):
        # Exact write-key retry (W2-002): converged, nothing new.
        return False
    changed = False
    added_rows = 0
    if not pending:
        # No evidence claimed: the historical append-only semantics stand
        # (synthetic findings, negative evidence, ledger entries passed back).
        entry["occurrences"].append(
            _occurrence(
                session,
                finding,
                conformant=conformant,
                occurrence_id=occurrence_id,
            )
        )
        for rule in finding.get("rule_ids") or []:
            bucket = data["by_rule"].setdefault(str(rule), {"total": 0, "drift": 0})
            bucket["total"] += 1
            if not conformant:
                bucket["drift"] += 1
        return True
    for occurrence in pending:
        anchor = _occurrence_anchor(occurrence)
        if anchor is None:
            continue
        if (session_id, anchor) in recorded_anchors:
            continue  # this exact evidence is already a row: converged
        entry["occurrences"].append(
            _occurrence(
                session,
                finding,
                conformant=conformant,
                occurrence_id=occurrence_id,
                evidence_anchor=anchor,
                anchor_generation=_anchor_generation(),
            )
        )
        recorded_anchors.add((session_id, anchor))
        changed = True
        added_rows += 1
    if changed:
        # One rule bump per recorded ROW: two real occurrences are two counts.
        for _ in range(added_rows):
            for rule in finding.get("rule_ids") or []:
                bucket = data["by_rule"].setdefault(str(rule), {"total": 0, "drift": 0})
                bucket["total"] += 1
                if not conformant:
                    bucket["drift"] += 1
    return changed


def record_occurrence(home, finding, session, *, occurrence_id: str = "", registry=None) -> dict:
    if not isinstance(finding, dict) or not isinstance(session, dict):
        raise PalError("VALIDATION_FAILED", "finding and session must be objects")
    _ensure_migrated(home, registry=registry)
    data = load_recurrence(home)
    changed = _bump_occurrence(
        data,
        finding,
        session,
        conformant=bool(session.get("conformant", True)),
        occurrence_id=occurrence_id,
    )
    if not changed:
        return data
    return save_recurrence(home, data, registry=registry)


def record_negative(home, session, *, occurrence_id: str = "", registry=None) -> dict:
    if not isinstance(session, dict):
        raise PalError("VALIDATION_FAILED", "session must be an object")
    _ensure_migrated(home, registry=registry)
    data = load_recurrence(home)
    changed = _bump_occurrence(
        data, {"drift_class": "CONFORMANT", "severity": "P3", "confidence": "HIGH"},
        session, conformant=True, occurrence_id=occurrence_id,
    )
    if not changed:
        return data
    return save_recurrence(home, data, registry=registry)


def record_batch(
    home,
    session,
    findings: list[dict],
    *,
    occurrence_id: str = "",
    registry=None,
) -> dict:
    """Record every occurrence of one session in ONE ledger transaction.

    The per-finding API loaded, validated, serialized and atomically replaced the
    whole ledger once per finding: the audit measured 25.8x the cost of a single
    batched save on a 5,000-occurrence ledger, growing as
    O(new_findings x ledger_size) (PERF-005). An empty batch writes nothing, and a
    batch whose every occurrence was already keyed-recorded writes nothing either.
    """
    if not isinstance(session, dict):
        raise PalError("VALIDATION_FAILED", "session must be an object")
    rows = [finding for finding in (findings or []) if isinstance(finding, dict)]
    if not rows:
        _ensure_migrated(home, registry=registry)
        return load_recurrence(home)
    _ensure_migrated(home, registry=registry)
    data = load_recurrence(home)
    changed = False
    for finding in rows:
        if _bump_occurrence(
            data,
            finding,
            session,
            conformant=bool(session.get("conformant", True)),
            occurrence_id=occurrence_id,
        ):
            changed = True
    if not changed:
        return data
    return save_recurrence(home, data, registry=registry)


class RecurrenceBatch:
    """One recurrence ledger transaction for a batch of mechanical occurrences.

    PERF-001 (SRC-011): `record_negative`/`record_occurrence` each pay an
    `_ensure_migrated` (status + load) plus another `load_recurrence`, i.e. three
    full reads per call on an already-current v2 ledger, and one full
    serialization per changed row. A bounded analysis pass calls the mechanical
    negative path once per clean session, so that cost repeats per session even
    though all sessions belong to one analysis transaction. This context loads
    and migrates ONCE, applies every occurrence to the in-memory snapshot, and
    persists ONCE at a deterministic boundary.

    Durability: the caller commits this at the same boundary as the session
    index, so a restart cannot claim analysis progress whose recurrence write was
    discarded. A corrupt ledger still fails closed at `__enter__` (the
    `_ensure_migrated` gate). Public `record_negative`/`record_batch` are
    unchanged for independent callers.
    """

    def __init__(self, home: Path | str, *, registry: dict | None = None):
        self._home = home
        self._registry = registry
        self._data: dict | None = None
        self._changed = False

    def __enter__(self) -> "RecurrenceBatch":
        _ensure_migrated(self._home, registry=self._registry)
        self._data = load_recurrence(self._home)
        return self

    def record_occurrence(
        self, finding, session, *, occurrence_id: str = ""
    ) -> dict:
        if not isinstance(finding, dict) or not isinstance(session, dict):
            raise PalError("VALIDATION_FAILED", "finding and session must be objects")
        assert self._data is not None
        if _bump_occurrence(
            self._data,
            finding,
            session,
            conformant=bool(session.get("conformant", True)),
            occurrence_id=occurrence_id,
        ):
            self._changed = True
        return self._data

    def record_negative(self, session, *, occurrence_id: str = "") -> dict:
        if not isinstance(session, dict):
            raise PalError("VALIDATION_FAILED", "session must be an object")
        assert self._data is not None
        if _bump_occurrence(
            self._data,
            {"drift_class": "CONFORMANT", "severity": "P3", "confidence": "HIGH"},
            session,
            conformant=True,
            occurrence_id=occurrence_id,
        ):
            self._changed = True
        return self._data

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is None and self._changed and self._data is not None:
            save_recurrence(self._home, self._data, registry=self._registry)
        return False


def _breakdown(data: dict, drift_class: str, dimension: str, label: str) -> list[dict]:
    counts: dict[str, dict] = {}
    for finding in data.get("by_finding", {}).values():
        if finding.get("drift_class") != drift_class:
            continue
        for occurrence in finding.get("occurrences", []):
            key = str(occurrence.get(dimension) or "unknown")
            slot = counts.setdefault(key, {"drift": 0, "total": 0})
            slot["total"] += 1
            if not occurrence.get("conformant", True):
                slot["drift"] += 1
    rows = [
        {label: k, "drift": v["drift"], "total": v["total"],
         "rate": v["drift"] / v["total"] if v["total"] else 0.0}
        for k, v in counts.items()
    ]
    return sorted(rows, key=lambda r: (-r["drift"], -r["total"], r[label]))


def cross_model_recurrence(data: dict, drift_class: str) -> list[dict]:
    return _breakdown(data, drift_class, "model_family", "model")


def cross_project_recurrence(data: dict, drift_class: str) -> list[dict]:
    return _breakdown(data, drift_class, "project", "project")


def _summary(occurrences: list[dict]) -> dict:
    sessions = {o.get("session_id") for o in occurrences}
    drift_sessions = {o.get("session_id") for o in occurrences
                      if not o.get("conformant", True)}
    return {
        "occurrences": len(occurrences),
        "sessions": len(sessions),
        "rate": len(drift_sessions) / len(sessions) if sessions else 0.0,
    }


def before_after_analysis(data: dict, drift_class: str, fix_version: str) -> dict:
    fix = _vt(fix_version)
    before, after = [], []
    for finding in data.get("by_finding", {}).values():
        if finding.get("drift_class") != drift_class:
            continue
        for occurrence in finding.get("occurrences", []):
            version = _vt(occurrence.get("protocol_version"))
            target = before if version and fix and version < fix else after
            target.append(occurrence)
    return {"before": _summary(before), "after": _summary(after)}


def detect_regression(data, fingerprint, new_session, *, registry=None) -> dict | None:
    finding = data.get("by_finding", {}).get(fingerprint) if isinstance(data, dict) else None
    if not isinstance(finding, dict):
        return None
    last_fix = finding.get("last_fix_version")
    version = ((new_session.get("protocol") or {}).get("version") or "").strip()
    if not last_fix or not version or _vt(version) < _vt(last_fix):
        return None
    return {
        "regression": True,
        "original_finding_id": finding.get("finding_id") or "",
        "last_fix_version": last_fix,
        "occurrence": _occurrence(new_session, finding, conformant=False),
    }


#: What a spread means for the fix surface. One model drifting where others
#: comply is evidence about that model; the same drift across models under one
#: protocol version is evidence about the protocol or its enforcement.
SPREAD_SINGLE = "SINGLE_MODEL"
SPREAD_CROSS_MODEL = "CROSS_MODEL"
SPREAD_CROSS_PROJECT = "CROSS_PROJECT"
SPREAD_CROSS_BOTH = "CROSS_MODEL_AND_PROJECT"
SPREAD_UNKNOWN = "UNKNOWN"


def spread(data: dict, drift_class: str) -> dict:
    """How widely one drift class has actually been observed.

    The judgement this supports is PAL-FINDING-02's: an isolated model failure
    normally points at enforcement, guidance or a conformance test, NOT at
    rewriting the protocol. Reporting the spread lets the analyst make that call
    from evidence instead of from the single session in front of it.
    """
    models = {row["model"]: row for row in cross_model_recurrence(data, drift_class)}
    projects = {row["project"]: row for row in cross_project_recurrence(data, drift_class)}
    drifting_models = sorted(name for name, row in models.items() if row["drift"] > 0)
    clean_models = sorted(name for name, row in models.items() if row["drift"] == 0)
    drifting_projects = sorted(name for name, row in projects.items() if row["drift"] > 0)

    if not drifting_models and not drifting_projects:
        classification = SPREAD_UNKNOWN
    elif len(drifting_models) > 1 and len(drifting_projects) > 1:
        classification = SPREAD_CROSS_BOTH
    elif len(drifting_models) > 1:
        classification = SPREAD_CROSS_MODEL
    elif len(drifting_projects) > 1:
        classification = SPREAD_CROSS_PROJECT
    else:
        classification = SPREAD_SINGLE

    return {
        "drift_class": drift_class,
        "classification": classification,
        "drifting_models": drifting_models,
        "clean_models": clean_models,
        "drifting_projects": drifting_projects,
        "occurrences": sum(row["drift"] for row in models.values()),
        "isolated_to_one_model": classification == SPREAD_SINGLE and len(drifting_models) == 1,
        "contradicted_by_a_clean_model": bool(
            classification == SPREAD_SINGLE and clean_models
        ),
        "guidance": _spread_guidance(classification, clean_models),
    }


def _spread_guidance(classification: str, clean_models: list) -> str:
    if classification in (SPREAD_CROSS_MODEL, SPREAD_CROSS_BOTH):
        return (
            "the same drift appears under more than one model, so the protocol or its "
            "executable enforcement is the likelier surface than any single model"
        )
    if classification == SPREAD_CROSS_PROJECT:
        return (
            "one model drifts across several projects, so the surface is that model's "
            "guidance or the engine's enforcement rather than one project's setup"
        )
    if classification == SPREAD_SINGLE and clean_models:
        return (
            "another model complied under the same rule, so this is model "
            "noncompliance: prefer enforcement, guidance or a conformance test over "
            "changing the protocol"
        )
    if classification == SPREAD_SINGLE:
        return (
            "observed under one model only, with no comparison available; treat "
            "protocol change as unproven"
        )
    return "no drift occurrences recorded for this class"


def update_telemetry(home, telemetry, *, registry=None) -> dict:
    if not isinstance(telemetry, dict):
        raise PalError("VALIDATION_FAILED", "telemetry must be an object")
    require_action("write_own_index", registry=registry)
    paths = home_paths(home)
    current: dict = {}
    if paths.telemetry.exists():
        try:
            loaded = read_json(paths.telemetry)
            if isinstance(loaded, dict):
                current = loaded
        except (OSError, ValueError, UnicodeDecodeError):
            current = {}
    merged = copy.deepcopy(current)
    merged.setdefault("schema_version", SCHEMA_VERSION)
    for key in TELEMETRY_KEYS:
        if key in telemetry:
            merged[key] = telemetry[key]
    atomic_write_json(paths.telemetry, merged, root=paths.root)
    return merged
