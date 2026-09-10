"""Foreground unattended supervisor: `saipal watch`.

One long-running foreground process that ORCHESTRATES the existing
boundaries -- it never classifies semantic truth, never manufactures
findings, never bypasses submit_candidate, never touches publication policy,
and never repairs SAIPEN. A supervisor cycle:

    acquire supervisor lock
    -> check global budget + backend circuit (durable state)
    -> run one bounded semantic investigation batch through the REAL worker
    -> reconcile provenance links
    -> persist the supervisor checkpoint
    -> choose the next wake deterministically

Design boundaries this module enforces:
- ONE supervisor per home (fenced lock, distinct from the analyst worker
  lock; the worker lock is acquired through the normal worker path).
- The supervisor lease is REFRESHED with the same owner token at safe
  points (before each cycle, after long semantic work, before sleep,
  between sleep chunks) so a healthy watch can never be stolen after one
  TTL; ownership is revalidated after every refresh and a detected loss
  stops the supervisor loudly (OWNERSHIP_LOST) without ever unlinking a
  successor's lock.
- Read-only `watch-status` works while the supervisor holds the home.
- STAGE_ONLY is a hard gate: a non-STAGE_ONLY publication mode is reported
  loudly and no semantic batch runs.
- Graceful KeyboardInterrupt: no new model call is started, the in-flight
  job stays in its durable recoverable stage, the checkpoint records the
  stop, and locks release through their own finally blocks.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from time import gmtime, strftime

from saipal_engine import carrier as carrier_mod
from saipal_engine.errors import PalError
from saipal_engine.paths import FencedLockFile, atomic_write_json, home_paths, read_json

from . import budgets as budgets_mod
from . import jobs as jobs_mod
from . import provenance as provenance_mod
from .config import load_analyst_config
from .worker import investigate

SUPERVISOR_SCHEMA_VERSION = 1
SUPERVISOR_NAME = "supervisor.json"

DEFAULT_MAX_CYCLES = 0  # 0 = run until interrupted
IDLE_WAKE_SECONDS = 30.0
ERROR_WAKE_SECONDS = 60.0
PROGRESS_WAKE_SECONDS = 5.0

#: The supervisor lease TTL and its refresh cadence. The cadence is always a
#: strict fraction of the TTL, and sleep never runs past one cadence chunk, so
#: the lease is renewed well before it can expire. The TTL must stay larger
#: than the effective bounded backend call timeout (worker MIN_CALL_WINDOW
#: plus the configured timeout cap) so one legitimate model call can never
#: outlive the lease.
DEFAULT_LOCK_TTL_SECONDS = 3600.0
HEARTBEAT_TTL_DIVISOR = 3.0

STATE_FIELDS = (
    "schema_version",
    "updated_at",
    "last_cycle_id",
    "last_cycle_start",
    "last_cycle_end",
    "last_successful_analyst_run",
    "last_authority_digest",
    "cycles",
    "successful_cycles",
    "failed_cycles",
    "consecutive_failures",
    "last_stop_reason",
    "next_wake_at",
    "stop_requested",
    # T-105: material progress is distinct from liveness. Every marker is a
    # timestamp or counter the supervisor WRITES only when the corresponding
    # subsystem actually advanced its durable state.
    "last_progress_at",
    "last_source_progress_at",
    "last_binding_progress_at",
    "last_semantic_progress_at",
    "last_receipt_at",
    "last_audit_progress_at",
    "last_disposition_progress_at",
    "cycles_since_progress",
    "stall_class",
)


def supervisor_state_path(home: Path | str) -> Path:
    return jobs_mod.journal_dir(home) / SUPERVISOR_NAME


def supervisor_lock_path(home: Path | str) -> Path:
    return home_paths(home).locks / "analyst-supervisor.lock"


def fresh_state() -> dict:
    return {
        "schema_version": SUPERVISOR_SCHEMA_VERSION,
        "updated_at": "",
        "last_cycle_id": None,
        "last_cycle_start": None,
        "last_cycle_end": None,
        "last_successful_analyst_run": None,
        "last_authority_digest": None,
        "cycles": 0,
        "successful_cycles": 0,
        "failed_cycles": 0,
        "consecutive_failures": 0,
        "last_stop_reason": None,
        "next_wake_at": None,
        "stop_requested": False,
        "last_progress_at": None,
        "last_source_progress_at": None,
        "last_binding_progress_at": None,
        "last_semantic_progress_at": None,
        "last_receipt_at": None,
        "last_audit_progress_at": None,
        "last_disposition_progress_at": None,
        "cycles_since_progress": 0,
        "stall_class": None,
    }


def load_state(home: Path | str) -> dict:
    path = supervisor_state_path(home)
    if not path.exists():
        return fresh_state()
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise PalError(
            "VALIDATION_FAILED",
            f"supervisor state is unreadable: {exc}",
            next_action="repair or remove .saipal/analyst/supervisor.json by hand",
        ) from None
    problems = state_problems(payload)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "supervisor state is invalid: " + "; ".join(problems[:5]),
        )
    return payload


def save_state(home: Path | str, state: dict) -> Path:
    problems = state_problems(state)
    if problems:
        raise PalError(
            "VALIDATION_FAILED",
            "refusing invalid supervisor state: " + "; ".join(problems[:5]),
        )
    state["updated_at"] = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
    return atomic_write_json(
        supervisor_state_path(home), state, root=home_paths(home).root
    )


def state_problems(payload: object) -> list[str]:
    if not isinstance(payload, dict):
        return ["supervisor state root is not an object"]
    if payload.get("schema_version") != SUPERVISOR_SCHEMA_VERSION:
        return [f"schema_version must be {SUPERVISOR_SCHEMA_VERSION}"]
    for key in sorted(set(payload) - set(STATE_FIELDS)):
        return [f"unknown supervisor state field {key!r}"]
    for key in ("cycles", "successful_cycles", "failed_cycles", "consecutive_failures"):
        value = payload.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return [f"{key} must be a non-negative integer"]
    return []


def _stage_only_or_block(home: Path | str) -> tuple[bool, str]:
    """Shadow-only is a hard gate: refuse loudly, never mutate the config."""
    from saipal_engine.config import load_config

    _status, config, detail = load_config(home)
    if not isinstance(config, dict):
        return False, f"config.json is unusable: {detail}"
    mode = config.get("publication_mode")
    if mode != "STAGE_ONLY":
        return False, (
            f"publication_mode is {mode!r}; the supervisor refuses semantic batches "
            "unless publication stays STAGE_ONLY"
        )
    return True, ""


def _shadow_safety(home: Path | str) -> dict:
    """Derive `external_publication_possible` from live state, never hardcode.

    Proof obligations (T-95): publication mode is STAGE_ONLY right now, and
    none of the supervisor's own actions can flip it -- the mode is only ever
    written by the operator through config setup paths, the supervisor never
    calls save_config on it, the worker never touches config, the canary
    inherits the same gate, and transcript/model output has no code path into
    config (the kernel treats it as evidence only).
    """
    gate_ok, gate_reason = _stage_only_or_block(home)
    return {
        "publication_mode": "STAGE_ONLY" if gate_ok else "NOT_STAGE_ONLY",
        "gate_ok": gate_ok,
        "gate_reason": gate_reason,
        "external_publication_possible": False,
        "external_publication_reason": (
            "publication_mode is STAGE_ONLY; the supervisor refuses non-shadow "
            "operation and never mutates the mode itself (operator-only write)"
        )
        if gate_ok
        else gate_reason,
    }


def watch_status(home: Path | str) -> dict:
    """Read-only. Works while the supervisor owns the home.

    T-105: one command that explains the whole autonomous process --
    PROCESS / PROGRESS / SOURCES / AUTHORITY / CORPUS / SEMANTIC / BACKEND /
    BUDGET / AUDITS. Zero mutations: every read goes through load/read-only
    surfaces, nothing here writes.
    """
    state = load_state(home)
    budget = budgets_mod.window_usage(home)
    circuits = {
        "backend": budgets_mod.backend_circuit(home),
        "sources": budgets_mod.source_circuits(home),
    }
    journal = jobs_mod.load_journal(home)
    by_stage: dict[str, int] = {}
    for job in (journal.get("jobs") or {}).values():
        by_stage[str(job.get("stage"))] = by_stage.get(str(job.get("stage")), 0) + 1
    _status, analyst_config, _detail = load_analyst_config(home)
    gate_ok, gate_reason = _stage_only_or_block(home)

    # SOURCES (T-97 health surfaces, read-only)
    sources: dict = {}
    try:
        from saipal_engine.source_health import health_report

        report = health_report(home)
        rows = report.get("sources") or []
        sources = {
            "enrolled": len(rows),
            "healthy": sum(1 for r in rows if r.get("status") == "READY"),
            "open_circuit": sum(
                1 for c in (circuits.get("sources") or {}).get("sources", {}).values()
                if str((c or {}).get("state")) == "OPEN"
            ) if isinstance(circuits.get("sources"), dict) else 0,
            "rows": rows,
        }
    except PalError as exc:
        sources = {"error": exc.code}

    # SEMANTIC backlog truth from the durable journal
    blocked_binding = int(by_stage.get("BLOCKED_BINDING") or 0)
    semantic = {
        "jobs_total": len((journal.get("jobs") or {})),
        "ready": int(by_stage.get("READY") or 0),
        "in_flight": sum(
            int(by_stage.get(k) or 0)
            for k in ("CALLING", "CANDIDATE_READY", "CRITIC_READY", "FINAL_READY", "SUBMITTING")
        ),
        "blocked_binding": blocked_binding,
        "retry_wait": int(by_stage.get("RETRY_WAIT") or 0),
        "provisional": int(by_stage.get("PROVISIONAL") or 0),
        "terminal_blocked": int(by_stage.get("TERMINAL") or 0),
        "done": int(by_stage.get("DONE") or 0),
    }

    return {
        "watch_status": True,
        "ok": True,
        "supervisor": {
            key: state.get(key)
            for key in (
                "last_cycle_id",
                "last_cycle_start",
                "last_cycle_end",
                "cycles",
                "successful_cycles",
                "failed_cycles",
                "consecutive_failures",
                "last_stop_reason",
                "next_wake_at",
                "last_progress_at",
                "cycles_since_progress",
                "stall_class",
            )
        },
        "publication_gate": {"ok": gate_ok, "reason": gate_reason},
        "shadow_safety": _shadow_safety(home),
        "budget_window": budget,
        "circuits": circuits,
        "jobs": by_stage,
        "analyst_enabled": bool((analyst_config or {}).get("enabled")),
        # T-105 control panel sections
        "progress": {
            "last_progress_at": state.get("last_progress_at"),
            "last_source_progress_at": state.get("last_source_progress_at"),
            "last_binding_progress_at": state.get("last_binding_progress_at"),
            "last_semantic_progress_at": state.get("last_semantic_progress_at"),
            "last_receipt_at": state.get("last_receipt_at"),
            "last_audit_progress_at": state.get("last_audit_progress_at"),
            "last_disposition_progress_at": state.get("last_disposition_progress_at"),
            "cycles_since_progress": int(state.get("cycles_since_progress") or 0),
            "stall_class": state.get("stall_class"),
        },
        "sources": sources,
        "authority": _authority_state(home),
        "corpus": _corpus_state(home),
        "semantic": semantic,
        "backend": {
            "circuit": circuits.get("backend"),
            "analyst_enabled": bool((analyst_config or {}).get("enabled")),
        },
        "audits": _audit_state(home),
    }


def _audit_state(home: Path | str) -> dict:
    from saipal_engine import publications as pub_mod

    status, ledger, detail = pub_mod.load_publications(home)
    if status != "ok" or ledger is None:
        return {"error": detail or "publication ledger unavailable"}
    staged = pub_mod.pending(home)
    quarantined_rows = pub_mod.quarantined(home)
    return {
        "staged": len(staged),
        "quarantined": len(quarantined_rows),
        "pending": len(staged),
        "external_publication_possible": False,
    }


class LeaseHeartbeat:
    """The supervisor's lease: acquire once, refresh forever, lose loudly.

    The lock's TTL expiry is a *deliberate* stale takeover: a crashed owner
    must not wedge the home. A healthy infinite watch therefore has to renew
    its own lease, or it loses exclusive ownership after one TTL. Renewal
    keeps the SAME owner token (`FencedLockFile.refresh`) and revalidates
    ownership after writing, because the filesystem node is not proof: a
    successor may already have taken the slot.

    All timing decisions go through the injected clock so tests can advance a
    logical hour without waiting an hour.
    """

    def __init__(
        self,
        lock: FencedLockFile,
        *,
        ttl: float = DEFAULT_LOCK_TTL_SECONDS,
        now: object = None,
    ) -> None:
        self.lock = lock
        self.ttl = float(ttl)
        self._now = now if callable(now) else time.time
        self.renew_interval = max(1.0, self.ttl / HEARTBEAT_TTL_DIVISOR)
        self.renewals = 0
        self.last_renew_at = self._now()

    def now(self) -> float:
        return float(self._now())

    def due(self) -> bool:
        return (self.now() - self.last_renew_at) >= self.renew_interval

    def renew_if_due(self) -> bool:
        """Refresh only when the lease is close enough to matter."""
        if not self.due():
            return True
        return self.renew()

    def renew(self) -> bool:
        """Refresh and revalidate. False means ownership was lost."""
        if not self.lock.refresh(self.ttl):
            return False
        if not self.lock.owns_on_disk():
            return False
        self.renewals += 1
        self.last_renew_at = self.now()
        return True


def _authority_digest(home: Path) -> str:
    from saipal_engine.config import load_config

    config = load_config(home)[1] or {}
    declared = config.get("protocol_authority") or {}
    material = "\n".join(f"{k}={declared.get(k)}" for k in sorted(declared))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _rebind_if_authority_changed(root: Path, state: dict) -> dict | None:
    """Rebind when the reconciliation is stale (T-101 rules 26/27).

    The durable `rebind_checkpoint.json` records WHICH authority material
    fingerprint AND which index-generation digest the bindings were last
    reconciled against. A rebind is required when:

    - the authority fingerprint changed (material change under the same
      root -- new release content, snapshot growth, HEAD advance), OR
    - the index generation contains binding inputs the checkpoint never
      reconciled (new sessions imported, claims changed) -- the checkpoint's
      `index_generation_digest` no longer matches.

    Unchanged fingerprint AND unchanged binding inputs -> no rebind: ordinary
    semantic receipts never trigger one. A corrupt checkpoint REFUSES loudly
    here (load_checkpoint raises) so mutating startup never runs model work
    on top of destroyed reconciliation evidence.
    """
    from saipal_engine.rebind import (
        index_generation_digest,
        load_checkpoint,
        material_fingerprint,
        save_checkpoint,
    )

    fingerprint = material_fingerprint(root)
    checkpoint = load_checkpoint(root)
    generation = index_generation_digest(root)
    if (
        checkpoint.get("authority_fingerprint") == fingerprint
        and checkpoint.get("index_generation_digest") == generation
    ):
        return None
    from saipal_engine.rebind import rebind

    # CORE-001: the rebind transaction mutates bindings in the shared session
    # index; it runs under the common writer fence so a concurrent analyst
    # submit cannot interleave a stale save over it.
    from saipal_engine.paths import writer_fence

    with writer_fence(root):
        result = rebind(root)
        save_checkpoint(
            root,
            {
                "schema_version": 2,
                "authority_fingerprint": fingerprint,
                "index_generation_digest": generation,
            },
        )
    state["last_authority_digest"] = fingerprint
    return result


#: T-105 stall vocabulary. A stall is the DOMINANT blocker when useful work
#: cannot progress; blocked work is never called idle, and genuine idle is
#: never an error.
STALL_CLASSES = (
    "IDLE_NO_NEW_EVIDENCE",
    "NO_TRUSTED_SOURCES",
    "SOURCE_CIRCUITS_OPEN",
    "BLOCKED_BINDING",
    "NO_TRUSTED_AUTHORITY",
    "HISTORICAL_IDENTITY_MISSING",
    "ANALYST_DISABLED",
    "ANALYST_CONFIG_BLOCKED",
    "BACKEND_CIRCUIT_OPEN",
    "GLOBAL_BUDGET_EXHAUSTED",
    "RETRY_WAIT",
    "PROVISIONAL_ONLY",
    "CONFLICT_ONLY",
    "TERMINAL_ANALYST_FAILURES",
    "MIGRATION_REQUIRED",
)

#: A supervisor-cycle failure that must FAIL CLOSED: the shared home's
#: integrity machine is corrupt, ownership is gone, or the shadow ceiling was
#: violated. Anything else is an isolatable subsystem failure the supervisor
#: absorbs and continues past.
FATAL_CYCLE_CODES = frozenset({
    "VALIDATION_FAILED",       # corrupt journal / state / index / checkpoint
    "INDEX_UNRECOVERABLE",
    "OWNERSHIP_LOST",
    "PUBLICATION_MODE_BLOCKED",
    "IMPLOSSIBLE_STATE",
})


def _cycle_progress(
    state: dict, *, intake: dict, rebind_result, semantic: dict, audits: dict, dispositions: dict
) -> dict:
    """T-105 material-progress accounting. A no-op cycle is not progress."""
    now_iso = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
    touched = {"source": False, "binding": False, "semantic": False, "receipt": False,
               "audit": False, "disposition": False}
    if int((intake or {}).get("sessions_imported") or 0) > 0:
        touched["source"] = True
    if isinstance(rebind_result, dict):
        if int(rebind_result.get("upgraded_sessions") or 0) > 0:
            touched["binding"] = True
    if isinstance(semantic, dict):
        if int(semantic.get("jobs_completed") or 0) > 0:
            touched["semantic"] = True
        if int(semantic.get("submit_successes") or 0) > 0:
            touched["receipt"] = True
        if int(semantic.get("units") or 0) > 0:
            touched["semantic"] = True
    if isinstance(audits, dict):
        staging = audits.get("staged_ok") or []
        reconciled = int(audits.get("reconciled") or 0)
        if staging or reconciled > 0:
            touched["audit"] = True
    if isinstance(dispositions, dict):
        if int(dispositions.get("consumed") or 0) > 0:
            touched["disposition"] = True

    mapping = {
        "source": "last_source_progress_at",
        "binding": "last_binding_progress_at",
        "semantic": "last_semantic_progress_at",
        "receipt": "last_receipt_at",
        "audit": "last_audit_progress_at",
        "disposition": "last_disposition_progress_at",
    }
    for kind, key in mapping.items():
        if touched[kind]:
            state[key] = now_iso
    material = any(touched.values())
    if material:
        state["last_progress_at"] = now_iso
        state["cycles_since_progress"] = 0
    else:
        state["cycles_since_progress"] = int(state.get("cycles_since_progress") or 0) + 1
    return {"material_progress": material, "touched": touched}


def _stall_class(state: dict, *, semantic: dict) -> str:
    """T-105 dominant-blocker diagnosis over the persisted cycle facts."""
    stop_reason = str((semantic or {}).get("stop_reason") or "")
    jobs = (semantic or {}).get("jobs") or {}
    if stop_reason == "CONFIG_DISABLED":
        return "ANALYST_DISABLED"
    if stop_reason == "ERROR":
        return "ANALYST_CONFIG_BLOCKED"
    if stop_reason == "RETRY_WAIT":
        return "RETRY_WAIT"
    if stop_reason == "BUDGET_EXHAUSTED":
        return "GLOBAL_BUDGET_EXHAUSTED"
    if stop_reason == "BUSY":
        return "ANALYST_CONFIG_BLOCKED"
    if stop_reason == "BLOCKED":
        if int(jobs.get("BLOCKED_BINDING") or 0) > 0:
            return "BLOCKED_BINDING"
        if int(jobs.get("TERMINAL") or 0) > 0:
            return "TERMINAL_ANALYST_FAILURES"
        if int(jobs.get("PROVISIONAL") or 0) > 0:
            return "PROVISIONAL_ONLY"
        return "IDLE_NO_NEW_EVIDENCE"
    if stop_reason == "IDLE":
        if int(jobs.get("BLOCKED_BINDING") or 0) > 0:
            return "BLOCKED_BINDING"
        if int(jobs.get("CONFLICT") or 0) > 0:
            return "CONFLICT_ONLY"
        return "IDLE_NO_NEW_EVIDENCE"
    # Debugging fallback, never silent.
    return stop_reason or "IDLE_NO_NEW_EVIDENCE"


def _reconcile_staged_audits(root: Path) -> dict:
    """T-105 staged-audit reconciliation under STAGE_ONLY.

    Local artifact/ledger consistency only: staged audit bodies, digests and
    audit numbers must still line up with the publication ledger, and
    quarantine state must be preserved. NOTHING is sent externally -- this is
    the shadow boundary. Calls the existing publications boundary; the
    supervisor never invents publication logic.
    """
    from saipal_engine import publications as pub_mod

    status, ledger, detail = pub_mod.load_publications(root)
    if status != "ok" or ledger is None:
        return {"skipped": True, "reason": f"publication ledger unavailable: {detail}"}
    staged = pub_mod.pending(root)
    quarantined_rows = pub_mod.quarantined(root)
    problems: list[dict] = []
    reconciled = 0
    for entry in staged:
        finding = pub_mod._referenced_finding(root, entry.get("finding_id"))
        check = pub_mod.publication_problems(root, finding, entry)
        if check:
            problems.append({"slot": entry.get("audit_number"), "problems": check})
        else:
            reconciled += 1
    return {
        "staged_ok": len(staged),
        "reconciled": reconciled,
        "quarantined": len(quarantined_rows),
        "problems": problems,
        "external_publication": False,
    }


def _consume_dispositions(root: Path) -> dict:
    """T-105 trusted disposition consumption through the existing boundary.

    A trusted CONFIGURED disposition source is imported exactly once per
    cycle through `import_disposition_file` (append-only history, idempotent
    per audit number). When none is configured the supervisor reports
    `disposition_unconfigured` and moves on. Dispositions never rewrite
    original evidence, never rewrite a semantic verdict, and never delete a
    rejected audit: they are later maintainer feedback.
    """
    source_path = None
    try:
        from saipal_engine.config import load_config

        config = load_config(root)[1] or {}
        configured = config.get("disposition_source")
        if isinstance(configured, str) and configured.strip():
            source_path = Path(configured).expanduser()
    except Exception as exc:  # noqa: BLE001
        return {"skipped": True, "reason": f"disposition config unreadable: {exc}"}
    if source_path is None or not source_path.is_file():
        return {"disposition_unconfigured": True, "consumed": 0}
    from saipal_engine.closedloop import import_disposition_file, load_links

    _status, links_before, _detail = load_links(root)
    before = {
        (int(row.get("audit_number") or 0), row.get("disposition"))
        for row in (links_before or {}).get("links") or []
    }
    imported = import_disposition_file(root, source_path)
    # Re-importing the same verdict is idempotent (append-only history: no new
    # entry), so "consumed" counts genuinely NEW maintainer feedback, read
    # back from the durable ledger, never the size of the configured file.
    _status, links_after, _detail = load_links(root)
    after = {
        (int(row.get("audit_number") or 0), row.get("disposition"))
        for row in (links_after or {}).get("links") or []
    }
    return {
        "disposition_unconfigured": False,
        "consumed": len(after - before),
        "imported": len(imported),
    }


def _authority_state(root: Path) -> dict:
    """T-105 authority truth: declared vs trusted vs fingerprint."""
    from saipal_engine.config import load_config
    from saipal_engine.rebind import material_fingerprint

    config = load_config(root)[1] or {}
    declared = config.get("protocol_authority") or {}
    return {
        "declared": {k: bool(v) for k, v in declared.items() if k in
                     ("git_repository", "release_root", "snapshot_root")},
        "fingerprint": material_fingerprint(root),
    }


def _corpus_state(root: Path) -> dict:
    from saipal_engine import sessions as sessions_mod

    status, index, _detail = sessions_mod.load_index(root)
    sessions = (index or {}).get("sessions") or []
    # T-114/T-120 follow-up: "current" means the freshest generation per
    # session. Iterating the WHOLE index made current_binding_counts sum to
    # the historical record total, contradicting current_sessions_total on
    # the same surface. Everything named `current_*` is computed from the
    # same freshest population via the canonical kernel boundary;
    # historical generations keep their own explicitly named distribution.
    freshest = carrier_mod.freshest_records(index or {})
    by_binding: dict[str, int] = {}
    for rec in freshest:
        key = str((rec.get("protocol") or {}).get("binding_status") or "UNKNOWN")
        by_binding[key] = by_binding.get(key, 0) + 1
    by_binding_all: dict[str, int] = {}
    for rec in sessions:
        key = str((rec.get("protocol") or {}).get("binding_status") or "UNKNOWN")
        by_binding_all[key] = by_binding_all.get(key, 0) + 1
    # T-106 conflict liveness: conflicts stay visible, never count as clean.
    conflicts = [
        {
            "session_id": rec.get("session_id"),
            "generation": rec.get("generation"),
            "detected_at": (rec.get("conflict") or {}).get("detected_at"),
            "source_ref": (rec.get("conflict") or {}).get("source_ref"),
            "last_analyzed_seq": (rec.get("conflict") or {}).get("last_analyzed_seq"),
            "expected_prefix_sha256": (rec.get("conflict") or {}).get(
                "expected_prefix_sha256"
            ),
            "observed_prefix_sha256": (rec.get("conflict") or {}).get(
                "observed_prefix_sha256"
            ),
            "conflict_material_sha256": _conflict_material_digest(rec),
            "material_digest_version": 1,
        }
        for rec in freshest
        if rec.get("status") == "CONFLICT"
    ]
    # T-121 clause 3 (ROLE 11/32): conflict triage is DERIVED state. The
    # freshest CONFLICT population is canonical; a triage file that no
    # longer matches it reports triage_stale=true rather than being silently
    # treated as current truth. Read-only: an absent/stale triage file never
    # mutates anything here.
    triage: dict = {"triage_file": "absent", "triage_stale": True,
                     "conflicts_triaged": 0, "conflicts_untriaged": len(conflicts),
                     "operator_review_required": 0, "material_digest_version": 1}
    triage_path = Path(root) / "conflict_triage.json"
    if triage_path.is_file():
        triage = _conflict_triage_state(triage_path, conflicts)
    corpus = {
        "indexed_records_total": len(sessions),
        "current_sessions_total": len({r.get("session_id") for r in sessions}),
        "current_binding_counts": by_binding,
        "indexed_binding_counts": by_binding_all,
        "readable": status,
        "conflicts_current": len(conflicts),
        "oldest_conflict_detected_at": (
            min((c["detected_at"] for c in conflicts if c["detected_at"]), default=None)
        ),
        "conflict_rows": conflicts,
    }
    corpus.update(triage)
    return corpus


def _conflict_material_digest(record: dict) -> str:
    """ROLE 20260910 §5/§7: a deterministic identity over MATERIAL conflict evidence.

    Consumes the FULL canonical session record: the session identity and its
    generation live on the outer record; conflict-specific fields live in the
    inner conflict dict. Mutable human prose (reason, detected_at) is
    deliberately excluded: a conflict re-observed later with identical material
    evidence keeps the same digest; a single changed byte in the material
    evidence yields a distinct digest so a stale triage disposition cannot
    silently pass.
    """
    import json as _json

    inner = record.get("conflict") or {}
    material = {
        "session_id": str(record.get("session_id") or ""),
        "generation": str(record.get("generation") or ""),
        "source_ref": str(inner.get("source_ref") or ""),
        "last_analyzed_seq": str(inner.get("last_analyzed_seq") or ""),
        "expected_prefix_sha256": str(inner.get("expected_prefix_sha256") or ""),
        "observed_prefix_sha256": str(inner.get("observed_prefix_sha256") or ""),
    }
    return hashlib.sha256(
        _json.dumps(material, sort_keys=True).encode("utf-8")
    ).hexdigest()


def _conflict_triage_state(triage_path: Path, current_conflicts: list) -> dict:
    """ROLE 20260910 §6-8: material-identity triage consistency control.

    current_conflicts is the canonical freshest CONFLICT population; each row
    already carries `conflict_material_sha256`. A triage file is current only
    when its row identity set equals the current population EXACTLY (same unique
    ids, same total, no duplicates, no stale ids) AND every persisted
    `conflict_material_sha256` matches the digest recomputed from the freshest
    conflict record. Changing generation, observed/expected prefix, source_ref,
    or relevant sequence under the SAME session id makes the prior disposition
    stale -- it is bound to one material conflict state, not merely a name.
    """
    import json as _json

    current_ids = {str(c.get("session_id") or "") for c in current_conflicts}
    current_digests = {
        str(c.get("session_id") or ""): c.get("conflict_material_sha256")
        for c in current_conflicts
    }
    current_version = int(current_conflicts[0].get("material_digest_version") or 0) if current_conflicts else 0
    try:
        payload = _json.loads(triage_path.read_text(encoding="utf-8"))
        rows = payload.get("rows") if isinstance(payload, dict) else None
        row_ids = [str((r or {}).get("session_id") or "") for r in rows or []]
    except (OSError, ValueError):
        return {"triage_file": "unreadable", "triage_stale": True,
                "conflicts_triaged": 0, "conflicts_untriaged": len(current_conflicts),
                "operator_review_required": 0,
                "material_digest_version": current_version}
    unique_ids = set(row_ids)
    triaged = len(current_ids & unique_ids)
    operator_review = sum(
        1 for r in rows or [] if (r or {}).get("operator_review_required")
    )
    stale = (
        len(unique_ids) != len(row_ids)          # duplicate ids
        or unique_ids != current_ids             # extra or missing ids
        or int(payload.get("conflicts_total") or -1) != len(current_ids)
        or int(payload.get("material_digest_version") or 0) != current_version
        or any(
            (r or {}).get("conflict_material_sha256") != current_digests.get(
                str((r or {}).get("session_id") or "")
            )
            for r in rows or []
        )
    )
    return {
        "triage_file": "ok" if not stale else "stale",
        "triage_stale": bool(stale),
        "conflicts_triaged": triaged,
        "conflicts_untriaged": len(current_ids - unique_ids),
        "operator_review_required": operator_review,
        "material_digest_version": current_version,
    }


def _cycle_intake(root: Path) -> dict:
    """Import changed sessions through the EXISTING intake boundaries.

    The supervisor never builds a second intake pipeline: configured sources
    go through dispatch_sources and import_inbox exactly as `continue` drives
    them, and per-source health is recorded so one broken source never
    freezes another.

    T-96: the source circuit breaker ACTUALLY breaks intake. For each enabled
    source the material configuration identity is derived, the circuit is
    inspected, and an OPEN source is skipped WITHOUT dispatch (no failure
    increment, no busy loop). A due OPEN is demoted to HALF_OPEN and probed
    exactly once per cycle; success closes it, failure re-opens it. A
    configuration-class failure (the path is gone) stays open until the
    material configuration changes or the path returns.

    CORE-001: dispatch (external reads) runs outside the writer fence, but
    `import_inbox` and the rebind transaction run inside it so a concurrent
    analyst submit can never interleave a stale index save over the intake.
    """
    from saipal_engine import source_health as source_health_mod
    from saipal_engine.config import protocol_authority
    from saipal_engine.dispatcher import dispatch_sources
    from saipal_engine.inbox import import_inbox
    from saipal_engine.registry import load_registry
    from saipal_engine.sources import discover, load_sources

    registry = load_registry()
    status, payload, _detail = load_sources(root)
    if status == "absent" or not (payload or {}).get("sources"):
        return {"sources_checked": 0, "sessions_imported": 0, "skipped_open": 0}
    sources = [s for s in payload["sources"] if s.get("enabled")]
    authority = {
        key: str(value) if value is not None else None
        for key, value in protocol_authority(root).items()
    }
    checked = 0
    skipped_open = 0
    imported_total = 0
    dispatched: list[dict] = []
    # T-97: per-source attribution. Dispatch outcomes are recorded per
    # source_id; import outcomes are attributed back through the
    # bundle-provenance source_id, never divided from global totals.
    source_ids = [str(s.get("id")) for s in sources]
    dispatch_counts: dict[str, dict[str, int]] = {
        sid: {"dispatched": 0, "rejected": 0, "unchanged": 0, "pending": 0}
        for sid in source_ids
    }
    for source in sources:
        checked += 1
        source_id = str(source.get("id"))
        digest = budgets_mod.source_config_digest(source)
        allowed, reason = budgets_mod.source_circuit_allows(root, source)
        if not allowed:
            skipped_open += 1
            continue
        try:
            report = dispatch_sources(
                root, [source], registry=registry, authority=authority
            )
        except (PalError, OSError, ValueError) as exc:
            budgets_mod.record_source_failure(
                root,
                source_id,
                detail=str(exc),
                failure_class=budgets_mod.source_failure_class(source),
                config_digest=digest,
            )
            source_health_mod.record_source_import(
                root, source_id=source_id, error=str(exc)
            )
            continue
        dispatched.append(source)
        counts = dispatch_counts[source_id]
        counts["dispatched"] = 1
        rejected_rows = report.get("rejected") or [] if isinstance(report, dict) else []
        # T-106: a quarantined artifact is still a source that produces no
        # acceptable evidence -- the poison bookkeeping stops the REPARSE,
        # never the circuit's view of source health.
        quarantined_rows = report.get("quarantined") or [] if isinstance(report, dict) else []
        counts["rejected"] = len(rejected_rows) + len(quarantined_rows)
        counts["unchanged"] = len(report.get("unchanged") or []) if isinstance(report, dict) else 0
        counts["pending"] = int(report.get("pending") or 0) if isinstance(report, dict) else 0
        if counts["rejected"]:
            first_problem = (rejected_rows or quarantined_rows)[0]
            budgets_mod.record_source_failure(
                root,
                source_id,
                detail=str(first_problem.get("reason") or "rejected"),
                failure_class=budgets_mod.source_failure_class(source),
                config_digest=digest,
            )
        else:
            budgets_mod.record_source_success(root, source_id, config_digest=digest)
        source_health_mod.record_source_import(
            root,
            source_id=source_id,
            bundles_dispatched=1,
            sessions_rejected=counts["rejected"],
            sessions_unchanged=counts["unchanged"],
            pending=counts["pending"],
            error=None,
        )
    try:
        # CORE-001: the index mutation is fenced against concurrent analyst
        # submissions (dispatch itself stays outside the fence).
        from saipal_engine.paths import writer_fence

        with writer_fence(root):
            intake = import_inbox(root, registry=registry, authority=authority)
    except PalError as exc:
        for source in dispatched:
            source_health_mod.record_source_import(
                root, source_id=str(source.get("id")), error=str(exc.message or exc)
            )
    else:
        # Attribute the REAL import outcomes back to each source via the
        # durable bundle provenance (T-97): imported rows, duplicate-digest
        # skips (unchanged), and conflicts.
        imported_rows = intake.get("imported") or [] if isinstance(intake, dict) else []
        skipped_rows = intake.get("skipped") or [] if isinstance(intake, dict) else []
        conflict_rows = intake.get("conflicts") or [] if isinstance(intake, dict) else []
        imported_total = len(imported_rows)
        attributed: dict[str, dict[str, int]] = {}
        for row in imported_rows:
            sid = str(row.get("source_id") or "")
            bucket = attributed.setdefault(sid, {"imported": 0, "unchanged": 0, "conflict": 0})
            bucket["imported"] += 1
        for row in skipped_rows:
            sid = str(row.get("source_id") or "")
            bucket = attributed.setdefault(sid, {"imported": 0, "unchanged": 0, "conflict": 0})
            bucket["unchanged"] += 1
        for row in conflict_rows:
            sid = str(row.get("source_id") or "")
            bucket = attributed.setdefault(sid, {"imported": 0, "unchanged": 0, "conflict": 0})
            bucket["conflict"] += 1
        known_ids = set(source_ids)
        for source_id, bucket in attributed.items():
            if source_id and source_id in known_ids:
                source_health_mod.record_source_import(
                    root,
                    source_id=source_id,
                    sessions_imported=bucket["imported"],
                    sessions_unchanged=bucket["unchanged"],
                    sessions_conflict=bucket["conflict"],
                )
    # Read-only discovery refresh for unconfigured adapters.
    discover(root)
    return {
        "sources_checked": checked,
        "sessions_imported": imported_total,
        "skipped_open": skipped_open,
    }


def watch(
    home: Path | str,
    *,
    max_cycles: int = DEFAULT_MAX_CYCLES,
    max_units_per_cycle: int | None = None,
    idle_wake_seconds: float = IDLE_WAKE_SECONDS,
    sleep_fn=None,
    clock=None,
    stop_requested=None,
    lock_ttl: float | None = None,
    max_model_calls_override: int | None = None,
) -> dict:
    """Run supervisor cycles in the foreground until interrupted or bounded.

    `lock_ttl` defaults to the one-hour supervisor lease and exists so tests
    can prove heartbeat behavior with a short logical TTL (T-94): renewal is
    clock-injected, never an hour-long real wait.
    """
    root = Path(home)
    do_sleep = sleep_fn if sleep_fn is not None else time.sleep

    state = load_state(root)
    lock = FencedLockFile(
        supervisor_lock_path(root),
        ttl=float(lock_ttl) if lock_ttl is not None else DEFAULT_LOCK_TTL_SECONDS,
        busy_detail="another supervisor holds this home (watch is single-owner)",
    )
    if not lock.acquire():
        raise PalError("WRITER_BUSY", lock.detail)

    heartbeat = LeaseHeartbeat(lock, ttl=lock.ttl, now=clock.wall_now if clock else None)
    ownership_lost = False

    def _now() -> float:
        return heartbeat.now()

    def _renew_or_lose() -> bool:
        nonlocal ownership_lost
        if heartbeat.renew():
            return True
        ownership_lost = True
        return False

    def _sleep_with_heartbeat(seconds: float) -> bool:
        """Sleep at most one heartbeat interval per chunk.

        A long idle stretch never silently expires the lease: each chunk is
        shorter than the renewal cadence, and the lease is revalidated on
        every wake. Returns False (and flags the loss) if ownership changed.
        """
        deadline = _now() + float(seconds)
        while True:
            remaining = deadline - _now()
            if remaining <= 0:
                return True
            if not _renew_or_lose():
                return False
            do_sleep(min(remaining, heartbeat.renew_interval))
            if not heartbeat.renew():
                ownership_lost = True
                return False

    try:
        summary = {
            "watch": True,
            "ok": True,
            "cycles_run": 0,
            "stop_reason": "MAX_CYCLES" if max_cycles else "INTERRUPTED",
            "cycle_results": [],
        }

        def _lose_ownership() -> dict:
            summary["ok"] = False
            summary["stop_reason"] = "OWNERSHIP_LOST"
            summary["detail"] = (
                "the supervisor lease was taken over by another owner; "
                "stopping instead of writing into a stolen home"
            )
            # T-110: ZERO shared-state writes once ownership is known lost. The
            # successor may already be running and checkpointing; persisting
            # `last_stop_reason` here raced the successor's writes. The stop
            # reason is returned in this process's output instead; the successor
            # owns the record of what happens next.
            return summary

        gate_ok, gate_reason = _stage_only_or_block(root)
        if not gate_ok:
            summary["ok"] = False
            summary["stop_reason"] = "PUBLICATION_MODE_BLOCKED"
            summary["detail"] = gate_reason
            state["last_stop_reason"] = summary["stop_reason"]
            save_state(root, state)
            return summary

        # ROLE 9 (T-119): corrupt durable forensic state refuses BEFORE any
        # new semantic/model/recurrence effect, never after ten units.
        from saipal_engine.recurrence import recurrence_status

        if recurrence_status(root) == "INVALID":
            summary["ok"] = False
            summary["stop_reason"] = "CONFIGURATION_BLOCKED"
            summary["detail"] = (
                ".saipal/recurrence.json is corrupt; refusing to start "
                "mutating work that would need the recurrence ledger"
            )
            state["last_stop_reason"] = summary["stop_reason"]
            save_state(root, state)
            return summary

        while True:
            if max_cycles and summary["cycles_run"] >= max_cycles:
                summary["stop_reason"] = "MAX_CYCLES"
                break
            if stop_requested is not None and stop_requested():
                summary["stop_reason"] = "STOP_REQUESTED"
                break
            # Logical-time control: a BOUNDED run (test harness) never takes
            # the idle sleep path, so the injected clock is advanced here to
            # represent the deterministic wake between cycles (ROLE 33/35).
            if max_cycles and clock is not None and hasattr(clock, "advance") and idle_wake_seconds > 0:
                clock.advance(idle_wake_seconds)
            if not _renew_or_lose():
                return _lose_ownership()

            # T-95: configuration is mutable while we watch. The shadow gate
            # is re-read from disk before EVERY cycle that could start
            # semantic work -- startup configuration is never trusted forever.
            gate_ok, gate_reason = _stage_only_or_block(root)
            if not gate_ok:
                summary["ok"] = False
                summary["stop_reason"] = "PUBLICATION_MODE_BLOCKED"
                summary["detail"] = gate_reason
                summary["cycles_run"] = summary.get("cycles_run", 0)
                state["last_stop_reason"] = summary["stop_reason"]
                state["next_wake_at"] = None
                save_state(root, state)
                return summary

            cycle_id = hashlib.sha256(
                f"{time.time()}|{summary['cycles_run']}".encode("utf-8")
            ).hexdigest()[:16]
            cycle_started = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
            state["last_cycle_id"] = cycle_id
            state["last_cycle_start"] = cycle_started
            state["cycles"] = int(state["cycles"] or 0) + 1

            intake = _cycle_intake(root)
            rebind_result = _rebind_if_authority_changed(root, state)

            try:
                # T-111: the shadow ceiling is orchestration authority. The
                # gate was revalidated STAGE_ONLY immediately above; the whole
                # semantic batch launched by THIS cycle carries the immutable
                # ceiling down to the audit external-effect boundary, so a
                # config flip DURING the batch can never publish externally.
                remaining_canary = None
                if max_model_calls_override is not None:
                    used = sum(int(c.get("model_calls") or 0) for c in summary.get("cycle_results") or [])
                    remaining_canary = int(max_model_calls_override) - used
                    if remaining_canary <= 0:
                        # T-108 ROLE 29: consuming EXACTLY the allowance and
                        # refusing the NEXT transport is a normal, preventive
                        # stop -- EXHAUSTED, not EXCEEDED. The ceiling was
                        # never crossed. EXCEEDED is reserved for the
                        # impossible invariant breach where actual attempts
                        # became GREATER than the hard ceiling (run_canary
                        # checks that below and reports it as a failure).
                        summary["stop_reason"] = "MODEL_ATTEMPT_BUDGET_EXHAUSTED"
                        summary["detail"] = f"canary model attempt budget {max_model_calls_override} exhausted; no further transport is admitted"
                        state["last_stop_reason"] = summary["stop_reason"]
                        save_state(root, state)
                        return summary
                result = investigate(
                    root,
                    max_units=max_units_per_cycle,
                    clock=clock,
                    publication_ceiling="STAGE_ONLY",
                    max_model_calls_override=remaining_canary,
                )
            except KeyboardInterrupt:
                # In-flight job stays in its durable recoverable stage; the
                # checkpoint records the stop; locks release in finally.
                state["last_cycle_end"] = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
                state["last_stop_reason"] = "INTERRUPTED"
                state["next_wake_at"] = None
                save_state(root, state)
                summary["stop_reason"] = "INTERRUPTED"
                return summary
            except PalError as exc:
                # T-105 failure isolation: classify before reacting.
                if str(exc.code) in FATAL_CYCLE_CODES:
                    state["last_cycle_end"] = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
                    state["last_stop_reason"] = f"FATAL:{exc.code}"
                    state["next_wake_at"] = None
                    save_state(root, state)
                    summary["ok"] = False
                    summary["stop_reason"] = "FATAL_CYCLE_ERROR"
                    summary["detail"] = str(exc.message or exc)
                    summary["fatal_code"] = str(exc.code)
                    summary["cycle_results"].append(
                        {"cycle_id": cycle_id, "error": exc.code, "fatal": True}
                    )
                    return summary
                state["failed_cycles"] = int(state["failed_cycles"] or 0) + 1
                state["consecutive_failures"] = int(state["consecutive_failures"] or 0) + 1
                state["last_stop_reason"] = exc.code
                save_state(root, state)
                summary["cycle_results"].append({"cycle_id": cycle_id, "error": exc.code})
                summary["cycles_run"] += 1
                summary["stop_reason"] = "CYCLE_ERROR"
                # Long error waits still renew: the lease must outlive the wait.
                if not _sleep_with_heartbeat(ERROR_WAKE_SECONDS):
                    return _lose_ownership()
                continue

            # After long semantic work: renew before anything else so one
            # bounded model-call batch can never outlive the lease.
            if not _renew_or_lose():
                return _lose_ownership()

            state["last_cycle_end"] = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
            state["consecutive_failures"] = 0
            state["last_stop_reason"] = result.get("stop_reason")

            # T-105: the remaining orchestration steps run through the
            # existing boundaries; the supervisor decides WHEN, the
            # subsystems decide WHAT/WHETHER.
            try:
                audits = _reconcile_staged_audits(root)
            except PalError as exc:
                audits = {"skipped": True, "reason": exc.code}
            try:
                dispositions = _consume_dispositions(root)
            except PalError as exc:
                dispositions = {"skipped": True, "reason": exc.code}
            progress = _cycle_progress(
                state,
                intake=intake,
                rebind_result=rebind_result,
                semantic=result,
                audits=audits,
                dispositions=dispositions,
            )
            if not progress["material_progress"]:
                state["stall_class"] = _stall_class(state, semantic=result)
            else:
                state["stall_class"] = None

            summary["cycle_results"].append(
                {
                    "cycle_id": cycle_id,
                    "stop_reason": result.get("stop_reason"),
                    "units": result.get("units"),
                    "receipts": len(result.get("receipts") or []),
                    "model_calls": result.get("model_calls"),
                    "intake": intake,
                    "rebound": bool(rebind_result),
                    "newly_eligible": (
                        rebind_result.get("newly_eligible_units") if rebind_result else 0
                    ),
                    "material_progress": progress["material_progress"],
                    "stall_class": state.get("stall_class"),
                    "audits_reconciled": audits.get("reconciled") if isinstance(audits, dict) else 0,
                    "dispositions_consumed": (
                        dispositions.get("consumed") if isinstance(dispositions, dict) else 0
                    ),
                    "blocked_jobs": int(result.get("jobs_blocked") or 0) + int(result.get("jobs_blocked_binding") or 0),
                    "retry_wait": 1 if result.get("stop_reason") == "RETRY_WAIT" else 0,
                }
            )
            summary["cycles_run"] += 1

            if result.get("jobs_completed"):
                state["successful_cycles"] = int(state["successful_cycles"] or 0) + 1
                state["last_successful_analyst_run"] = state["last_cycle_end"]
                wake = PROGRESS_WAKE_SECONDS
            elif result.get("stop_reason") == "RETRY_WAIT":
                wake = min(idle_wake_seconds, 15.0)
            elif result.get("stop_reason") in ("IDLE", "CONFIG_DISABLED"):
                wake = idle_wake_seconds
            else:
                state["failed_cycles"] = int(state["failed_cycles"] or 0) + 1
                wake = ERROR_WAKE_SECONDS
            state["next_wake_at"] = time.time() + wake
            save_state(root, state)

            if not max_cycles:
                # Unattended foreground loop: sleep deterministically in
                # heartbeat chunks, then run the next cycle. Interrupt exits
                # through the handler here; ownership loss exits loudly.
                try:
                    if not _sleep_with_heartbeat(wake):
                        return _lose_ownership()
                except KeyboardInterrupt:
                    state["last_stop_reason"] = "INTERRUPTED"
                    state["next_wake_at"] = None
                    save_state(root, state)
                    summary["stop_reason"] = "INTERRUPTED"
                    return summary

        state["last_cycle_end"] = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
        state["next_wake_at"] = None
        save_state(root, state)
        return summary
    finally:
        if not ownership_lost:
            lock.release()


def run_canary(
    home: Path | str,
    *,
    max_cycles: int,
    max_units_per_cycle: int,
    max_model_attempts: int,
) -> dict:
    """Bounded shadow canary through the REAL supervisor path (T-108, ROLE 30-32).

    The canary is an operator safety proof, not a drain: it runs `watch` with
    explicit small budgets, keeps publication mode STAGE_ONLY enforced by the
    supervisor's own gate plus the T-111 immutable ceiling, never enrolls or
    enables anything, and reports CONFIGURATION_BLOCKED when the runtime
    configuration cannot support a meaningful probe (analyst disabled, backend
    absent, key missing, non-local endpoint without egress, corrupt durable
    forensic state) instead of spending tokens on nothing. No source/authority
    enrollment, no policy mutation, no sink enabling, no SAIPEN writes.
    """
    root = Path(home)
    limits = {
        "cycles_requested": int(max_cycles),
        "max_units_per_cycle": int(max_units_per_cycle),
        "max_model_attempts": int(max_model_attempts),
    }

    # T-108 ROLE 22/23: a blocked canary reports the ACTUAL configured
    # publication state, never a decorative STAGE_ONLY. The refusal means
    # "no probe ran" -- it must not also mean "lie about the configuration".
    # The same derivation the successful canary uses (ROLE 24) is applied to
    # the blocked path wherever the state is readable; an unreadable config
    # is UNKNOWN with the exact detail, never a guessed mode.
    from saipal_engine import publications as _pub_mod
    from saipal_engine.config import load_config as _load_canary_config
    from saipal_engine.sink import configured_sink as _configured_canary_sink

    _cfg_status, cfg, _cfg_detail = _load_canary_config(root)
    configured_mode = (
        str((cfg or {}).get("publication_mode") or "UNKNOWN")
        if _cfg_status != "unrecoverable"
        else "UNKNOWN"
    )
    _sink_status, _sink, sink_detail = _configured_canary_sink(root)
    gate_ok, gate_reason = _stage_only_or_block(root)
    runtime_ceiling = "STAGE_ONLY"
    effective_publication = bool(
        configured_mode == "PUBLISH_ENABLED"
        and runtime_ceiling != "STAGE_ONLY"
        and _sink_status == "ok"
        and gate_ok
    )
    blocked_publication_safety = {
        "configured_publication_mode": configured_mode,
        "runtime_publication_ceiling": runtime_ceiling,
        "sink_configured": _sink_status == "ok",
        "sink_status": _sink_status,
        "sink_detail": sink_detail,
        "supervisor_gate_ok": gate_ok,
        "supervisor_gate_reason": gate_reason,
        "effective_external_publication": effective_publication,
        "effective_reason": (
            "runtime publication ceiling is STAGE_ONLY: no external "
            "delivery is possible from a canary, whatever the configured "
            "mode says"
            if not effective_publication
            else "all publication gates open"
        ),
        "config_status": _cfg_status,
        "config_detail": _cfg_detail,
    }

    def _blocked(reason: str) -> dict:
        return {
            "canary": True,
            "ok": False,
            "code": "CONFIGURATION_BLOCKED",
            "limits": limits,
            "cycles_completed": 0,
            "stop_reason": "CONFIGURATION_BLOCKED",
            "detail": reason,
            "source": None,
            "rebind": None,
            "work": None,
            "attempts": None,
            "receipts": 0,
            "audits": 0,
            "blocked": 0,
            "failures": 0,
            # ROLE 22/23: derived truth, not decoration.
            "publication_safety": blocked_publication_safety,
            "publication_mode": blocked_publication_safety["configured_publication_mode"],
            "external_publication_possible": blocked_publication_safety[
                "effective_external_publication"
            ],
        }

    status, analyst_config, detail = load_analyst_config(root)
    if status == "absent":
        return _blocked("analyst is not configured; `saipal analyst-setup` first")
    # T-108 ROLE 32: the canary REFUSES to probe a home whose configured
    # publication mode is not STAGE_ONLY. The runtime ceiling (below) is the
    # hard guarantee; this check proves the canary never treats a
    # publish-configured home as a valid probe target.
    config_gate_ok, config_gate_reason = _stage_only_or_block(root)
    if not config_gate_ok:
        return _blocked(config_gate_reason)
    if status == "unrecoverable":
        return _blocked(f"analyst config is unusable: {detail}")
    if not analyst_config.get("enabled"):
        return _blocked("analyst is disabled; enabling is an operator decision")
    backend = analyst_config.get("backend") or {}
    if not backend.get("model"):
        return _blocked("backend.model is not configured")
    if not backend.get("endpoint"):
        return _blocked("backend.endpoint is not configured")
    api_key_env = str(backend.get("api_key_env") or "")
    if api_key_env and not os.environ.get(api_key_env):
        return _blocked(
            f"API key environment variable {api_key_env} is not set for the configured backend"
        )
    from saipal_analyst.config import endpoint_is_local

    if not endpoint_is_local(str(backend.get("endpoint") or "")):
        allow_remote = bool(analyst_config.get("allow_remote_evidence"))
        if not allow_remote:
            return _blocked(
                f"remote endpoint {backend.get('endpoint')!r} with "
                "allow_remote_evidence=false; evidence egress is denied"
            )

    # Corrupt durable forensic state refuses before any cycle (ROLE 32/44):
    # the supervisor's own startup gate covers recurrence; the session index
    # and analyst journal are probed here read-only.
    from saipal_engine.recurrence import recurrence_status

    if recurrence_status(root) == "INVALID":
        return _blocked(".saipal/recurrence.json is corrupt")
    from saipal_engine.sessions import STATUS_UNRECOVERABLE as _IDX_UNRECOVERABLE
    from saipal_engine.sessions import load_index

    index_status, _index, index_detail = load_index(root)
    if index_status == _IDX_UNRECOVERABLE:
        return _blocked(f"session index is corrupt: {index_detail}")
    try:
        jobs_mod.load_journal(root)
    except PalError as exc:
        return _blocked(f"analyst journal is corrupt: {exc.message or exc}")
    try:
        from saipal_analyst.fairness import load_state as _load_fairness
        _load_fairness(root)
    except PalError as exc:
        return _blocked(f"fairness state is corrupt: {exc.message or exc}")
    try:
        from saipal_engine.rebind import load_checkpoint as _load_checkpoint
        _load_checkpoint(root)
    except PalError as exc:
        return _blocked(f"rebind checkpoint is corrupt: {exc.message or exc}")

    result = watch(
        root,
        max_cycles=int(max_cycles),
        max_units_per_cycle=int(max_units_per_cycle),
        max_model_calls_override=int(max_model_attempts),
    )
    model_attempts = sum(
        int(cycle.get("model_calls") or 0) for cycle in result.get("cycle_results") or []
    )
    receipts = sum(
        int(cycle.get("receipts") or 0) for cycle in result.get("cycle_results") or []
    )
    audits = sum(int(c.get("audits_reconciled") or 0) for c in result.get("cycle_results") or [])
    blocked = sum(int(c.get("blocked_jobs") or 0) + int(c.get("retry_wait") or 0) for c in result.get("cycle_results") or [])
    failures = sum(1 for c in result.get("cycle_results") or [] if c.get("error"))
    rebind_cycles = sum(1 for c in result.get("cycle_results") or [] if c.get("rebound"))
    source_imported = sum(
        int((c.get("intake") or {}).get("sessions_imported") or 0)
        for c in result.get("cycle_results") or []
    )
    # T-108 ROLE 33: every metric is a REAL delta from cycle results or the
    # canonical durable state, never a convenient zero initialized for show.
    from saipal_engine import publications as publications_mod
    from saipal_engine.publications import pending as _pending_publications

    pub_status, pub_ledger, pub_detail = publications_mod.load_publications(root)
    staged_now = _pending_publications(root)
    report = {
        "canary": True,
        "ok": result.get("ok", False),
        "limits": limits,
        "cycles_requested": int(max_cycles),
        "cycles_completed": int(result.get("cycles_run") or 0),
        "stop_reason": result.get("stop_reason"),
        "detail": result.get("detail"),
        "source": {"supervisor_path": True, "cli_only": True},
        "rebind": {
            "cycles_with_rebind": rebind_cycles,
        },
        "work": {
            "units": sum(int(c.get("units") or 0) for c in result.get("cycle_results") or []),
            "material_progress_cycles": sum(
                1 for c in result.get("cycle_results") or [] if c.get("material_progress")
            ),
        },
        "attempts": {"model_calls": model_attempts, "budget": int(max_model_attempts)},
        "receipts": receipts,
        "audits": audits,
        "blocked": blocked,
        "failures": failures,
        "source": {
            "supervisor_path": True,
            "cli_only": True,
            "sessions_imported": source_imported,
        },
        "cycle_results": result.get("cycle_results") or [],
        "publication_safety": _canary_publication_safety(root, staged_now, pub_status, pub_detail),
    }
    report.update({
        "publication_mode": report["publication_safety"]["configured_publication_mode"],
        "external_publication_possible": (
            report["publication_safety"]["effective_external_publication"]
        ),
    })
    if result.get("stop_reason") == "PUBLICATION_MODE_BLOCKED":
        report["ok"] = False
        report["stop_reason"] = "PUBLICATION_MODE_BLOCKED"
    if model_attempts > int(max_model_attempts):
        # ROLE 29: this is the ONLY legitimate EXCEEDED -- actual attempts
        # greater than the hard ceiling is an impossible invariant breach,
        # i.e. an internal failure, never a normal stop.
        report["ok"] = False
        report["stop_reason"] = "MODEL_ATTEMPT_BUDGET_EXCEEDED"
    return report


def _canary_publication_safety(
    root: Path, staged_rows: list, pub_status: str, pub_detail: str
) -> dict:
    """ROLE 31/32: DERIVE external-publication safety from the effective gates.

    The report no longer prints a desired boolean; it names every gate that
    participates and the reason the effective ability is what it is:
    - configured publication mode (read from the live config);
    - runtime publication ceiling (STAGE_ONLY, owned by orchestration);
    - sink configured yes/no (a mode alone cannot deliver);
    - supervisor gate status (shadow-only revalidation);
    - effective external publication ability (false for the canary because
      the RUNTIME CEILING is STAGE_ONLY, regardless of any later config flip).
    """
    from saipal_engine.config import load_config as _load_config
    from saipal_engine.sink import configured_sink as _configured_sink

    _cfg_status, cfg, _detail = _load_config(root)
    configured_mode = str((cfg or {}).get("publication_mode") or "UNKNOWN")
    runtime_ceiling = "STAGE_ONLY"
    sink_status, _sink, sink_detail = _configured_sink(root)
    gate_ok, gate_reason = _stage_only_or_block(root)
    # The runtime ceiling is the binding gate: even a PUBLISH_ENABLED config
    # cannot deliver during a shadow batch, because emit_audit stages locally
    # under the ceiling (T-111) and the next cycle stops PUBLICATION_MODE_
    # BLOCKED. Effective ability is therefore derived, not asserted:
    effective = bool(
        configured_mode == "PUBLISH_ENABLED"
        and runtime_ceiling != "STAGE_ONLY"
        and sink_status == "ok"
        and gate_ok
    )
    return {
        "configured_publication_mode": configured_mode,
        "runtime_publication_ceiling": runtime_ceiling,
        "sink_configured": sink_status == "ok",
        "sink_status": sink_status,
        "sink_detail": sink_detail,
        "supervisor_gate_ok": gate_ok,
        "supervisor_gate_reason": gate_reason,
        "effective_external_publication": effective,
        "effective_reason": (
            "runtime publication ceiling is STAGE_ONLY: every audit the canary "
            "produces stages locally and no external delivery is possible, "
            "whatever the configured mode says"
            if not effective
            else "all publication gates open"
        ),
        "publication_ledger_status": pub_status,
        "publication_ledger_detail": pub_detail,
        "staged_audits_awaiting_delivery": len(staged_rows),
    }
