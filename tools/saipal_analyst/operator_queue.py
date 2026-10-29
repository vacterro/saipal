"""The canonical operator queue: one owner decision per blocked session.

`OPERATOR_BLOCKED` is a safe place to stop and a useless place to stop *at*. The
state says a human is needed; it does not say which human decision, about which
session, with what evidence, unlocks what, or -- the part that actually misled
the last report -- how much. Three analyzers each answer a different question
about the same corpus:

* `analyst-doctor` counts UNITS by the class the allocator refused them in, and
  already splits binding-blocked units into authority-verifiable vs
  evidence-absent (PAL-CPALL-04);
* `coverage` counts SESSIONS by binding reason, and calls 354 of them
  "recoverable" because the REASON is in principle fixable by enrolling a root;
* `cpall` counts CONFLICT SESSIONS.

Those three numbers are not variants of one truth; they are three questions, and
merging them is what produced a report implying a large unlock while the
measurable one was nine sessions. This module partitions the freshest-generation
session population into EXACTLY ONE owner decision per session -- exhaustive and
mutually exclusive by construction, so the groups always re-sum to the
population -- and computes each decision's unlock effect with the allocator's own
classifier rather than by assertion.

Two rules this module exists to keep:

* it never invents a number. Where a downstream effect cannot be computed it
  says `UNKNOWN` and says why;
* it never authorizes. Every entry names its legal actions AND the actions that
  must stay manual, and a candidate authority root is reported `CANDIDATE_ONLY`
  because discovery is not trust.

Read-only: it classifies, it does not decide, and it enrolls nothing.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from saipal_engine.paths import home_paths
from saipal_engine.registry import load_registry
from saipal_engine.sessions import STATUS_UNRECOVERABLE, load_index
from saipal_engine import carrier as carrier_mod

OPERATOR_QUEUE_SCHEMA_VERSION = 1
OPERATOR_QUEUE_NAME = "operator_queue.json"

#: The closed vocabulary of owner decisions. Every session in the population
#: lands in exactly one of these, so `sum(group.sessions) == population` is a
#: structural invariant of `build()`, not a hope about the numbers.
DECISION_AGENT_ACTIONABLE = "AGENT_ACTIONABLE"
DECISION_COMPLETE = "COMPLETE"
DECISION_RELEASE_ROOT = "RELEASE_ROOT_REQUIRED"
DECISION_IDENTITY_UNRECOVERABLE = "IDENTITY_UNRECOVERABLE_OR_EXTERNAL_AUTHORITY_REQUIRED"
DECISION_CONFLICT = "CONFLICT_DECISION_REQUIRED"
DECISION_REMOTE_OUTCOME = "REMOTE_OUTCOME_CONFIRMATION_REQUIRED"
DECISION_PROVISIONAL_POLICY = "PROVISIONAL_POLICY_REQUIRED"
DECISION_TERMINAL_REVIEW = "TERMINAL_JOB_REVIEW_REQUIRED"
DECISION_BLOCKED_OUTPUT = "BLOCKED_OUTPUT_REQUEUE_REQUIRED"
DECISION_WAITING_RETRY = "WAITING_RETRY_SCHEDULED"

#: Groups that are NOT operator work: either finished, or agent-actionable
#: right now. Kept explicit so the boundary report can answer "is automated work
#: complete?" without inferring it from the absence of a block.
NON_OPERATOR_DECISIONS = (DECISION_AGENT_ACTIONABLE, DECISION_COMPLETE)

#: Fixed presentation order for the decisions that carry no computable
#: leverage. A group whose unlock is UNKNOWN must still land somewhere stable,
#: because an operator reading two packets on the same corpus has to see the
#: same list.
_ZERO_LEVERAGE_ORDER = {
    DECISION_CONFLICT: 0,
    DECISION_REMOTE_OUTCOME: 1,
    DECISION_PROVISIONAL_POLICY: 2,
    DECISION_TERMINAL_REVIEW: 3,
    DECISION_BLOCKED_OUTPUT: 4,
    DECISION_WAITING_RETRY: 5,
    DECISION_IDENTITY_UNRECOVERABLE: 6,
}

#: What each decision MEANS, what evidence it rests on, and what is missing.
#: `forbidden` is load-bearing: it is the list of things an agent must never do
#: to make the group disappear, written next to the command that does not help.
_DECISION_META: dict[str, dict[str, Any]] = {
    DECISION_AGENT_ACTIONABLE: {
        "meaning": "the allocator classified this session runnable under current policy",
        "missing": "nothing; run the analyst worker",
        "legal_actions": ["python -B tools/saipal.py goal cpall"],
        "forbidden": [
            "do not hand a runnable unit to the operator queue -- it is not operator work"
        ],
    },
    DECISION_COMPLETE: {
        "meaning": "the session's semantic backlog is exhausted; this is finished history",
        "missing": "nothing",
        "legal_actions": [],
        "forbidden": [
            "do not re-open a complete session; replaying it spends a paid attempt for no verdict"
        ],
    },
    DECISION_RELEASE_ROOT: {
        "meaning": (
            "the session carries a commit, registry digest or tree fingerprint that an "
            "enrolled authority root can actually check, so enrolling a root changes its "
            "verdict"
        ),
        "missing": "an operator-supplied authority root path that exists on this machine",
        "legal_actions": [
            "python -B tools/saipal.py operator-queue  # read candidates, then choose",
            "python -B tools/saipal.py authority enroll --release-root PATH",
            "python -B tools/saipal.py rebind --dry-run",
        ],
        "forbidden": [
            "do NOT create, guess or auto-enroll a release root: enrollment is the one trust "
            "action in this protocol and a self-generated root would manufacture the very "
            "evidence the binding check exists to verify independently",
            "do NOT enroll a path discovery merely suggested -- CANDIDATE_ONLY is not trust",
        ],
    },
    DECISION_IDENTITY_UNRECOVERABLE: {
        "meaning": (
            "the session carries no artifact any authority root can check -- only a bare "
            "version string, or no protocol claim at all"
        ),
        "missing": (
            "evidence that does not exist in this corpus, or an external authority that "
            "publishes the historical bytes"
        ),
        "legal_actions": [
            "python -B tools/saipal.py coverage  # representative sessions per reason"
        ],
        "forbidden": [
            "do NOT re-run the slice: re-running is the one action that provably cannot change "
            "this verdict, and PAL-CPALL-04 names it as the dead end",
            "do NOT synthesize a protocol claim to make a session bindable",
        ],
    },
    DECISION_CONFLICT: {
        "meaning": (
            "an already-analyzed prefix changed under a stable watermark; the material "
            "evidence differs from what was judged"
        ),
        "missing": (
            "an operator decision about which prefix is authoritative for this session: the "
            "observed prefix, or the prefix that was judged and has since been mutated"
        ),
        "legal_actions": [
            "python -B tools/saipal.py evidence <SESSION_ID>  # read the two prefixes",
            "python -B tools/saipal.py sessions  # confirm which generations were judged",
            "OPERATOR DECISION, then: correct the source so the prefix stops mutating and "
            "re-import the session as a new generation; the frozen generation and its "
            "material digest are preserved either way",
        ],
        "forbidden": [
            "do NOT auto-resolve a conflict: a mutated already-analyzed prefix is a "
            "forensic event, and picking a winner silently would rewrite judged history",
            "do NOT re-import to clear the watermark; that discards the evidence of the change",
            "do NOT merge several conflicts into one decision -- they are separately "
            "addressable sessions even when their material digests match",
        ],
    },
    DECISION_REMOTE_OUTCOME: {
        "meaning": (
            "a paid remote attempt was made and its outcome is unknown; the journal cannot "
            "tell a delivered call from a dropped one"
        ),
        "missing": (
            "an external fact: whether the recorded attempt id produced a receipt on the "
            "remote side"
        ),
        "legal_actions": [
            "python -B tools/saipal.py operator-queue  # attempt ids per unit",
        ],
        "forbidden": [
            "do NOT replay the attempt to find out: W2-005 forbids re-entering a "
            "REMOTE_OUTCOME_UNKNOWN unit, and a replay risks a duplicate paid effect",
            "do NOT mark the outcome known without external evidence",
        ],
    },
    DECISION_PROVISIONAL_POLICY: {
        "meaning": (
            "the only pending work is a HOT provisional episode and provisional "
            "investigation is off"
        ),
        "missing": "an operator decision on whether provisional episodes may be investigated",
        "legal_actions": [
            "python -B tools/saipal.py investigate --with-provisional --max-units N",
        ],
        "forbidden": [
            "do NOT enable provisional investigation silently -- it changes what counts as "
            "evidence for every future slice, not just this group",
        ],
    },
    DECISION_TERMINAL_REVIEW: {
        "meaning": (
            "the session's cursor unit was journaled TERMINAL on a refusal stage other "
            "than binding; the session is out of eligible work but not resolved"
        ),
        "missing": (
            "a decision on the refused unit: requeue for one fresh attempt under changed "
            "material, or accept the refusal"
        ),
        "legal_actions": [
            "python -B tools/saipal.py analyst-requeue --dry-run",
        ],
        "forbidden": [
            "do NOT treat TERMINAL as complete history: TERMINAL means the refusal was "
            "terminal, not that the work was judged",
        ],
    },
    DECISION_BLOCKED_OUTPUT: {
        "meaning": (
            "the attempt was refused and journaled: the candidate contract rejected the "
            "model's output, or the transport retry budget ran out"
        ),
        "missing": (
            "changed analyst material (endpoint/model/budgets digest) or an explicit --force"
        ),
        "legal_actions": [
            "python -B tools/saipal.py analyst-requeue --reason 'why now'",
        ],
        "forbidden": [
            "do NOT requeue under an UNCHANGED config: a repeat refusal is the answer, and "
            "PAL-CPALL-04 bounds the allowance at max_requeues_per_unit",
            "do NOT edit the journal by hand; a command with a contract is the path",
        ],
    },
    DECISION_WAITING_RETRY: {
        "meaning": "a retry is scheduled and not yet due; this is not operator work",
        "missing": "nothing; the clock decides",
        "legal_actions": ["python -B tools/saipal.py analyst-status"],
        "forbidden": ["do not force a retry before it is due"],
    },
}


def operator_queue_path(home: Path | str) -> Path:
    """Where the persisted packet lives. Never created by a read."""
    return home_paths(home).root / OPERATOR_QUEUE_NAME


def _cursor_job(record: dict, journal: dict, event_limit: int) -> dict | None:
    """The journal job for the session's CURRENT unit, or None.

    `TERMINAL` is a property of a JOB, not of a session, so recovering which job
    refused the unit is the only way to say whether that terminal entry is
    finished history or outstanding work.
    """
    from saipal_analyst import jobs as jobs_mod

    state = carrier_mod.semantic_state(record)
    episodes = list(record.get("episodes") or [])
    if not episodes or state["exhausted"]:
        return None
    start = int(state["next_episode_index"])
    if start >= len(episodes):
        return None
    episode = episodes[start]
    slices = carrier_mod.episode_slice_count(record, episode, event_limit)
    slice_at = min(int(state["next_slice_index"]), slices - 1)
    digest = carrier_mod.unit_digest(record, episode, slice_at)
    job_id = jobs_mod.unit_job_id(str(record.get("session_id") or ""), int(episode["index"]), slice_at, digest)
    return jobs_mod.find_job(journal, job_id)


def _released_by_binding(record: dict, journal: dict, event_limit: int, wall_now: float) -> str | None:
    """What the allocator would classify this session as IF binding sufficed.

    The hypothetical is applied to a shallow copy whose only changed field is
    `binding_status`, then handed to the allocator's OWN classifier. The answer
    is therefore computed by the same code that decides eligibility today, not
    by a second implementation of eligibility that could drift from it.
    """
    from saipal_analyst import worker as worker_mod

    probe = dict(record)
    protocol = dict(probe.get("protocol") or {})
    protocol["binding_status"] = "BOUND"
    probe["protocol"] = protocol
    # provisional=True so a unit whose only other gate is the provisional flag
    # counts as released; the caller reports the class it was released FROM.
    return worker_mod._classify_unit(probe, event_limit, journal, True, wall_now)


def _unlock_for(decision: str, session_ids: list[str]) -> dict[str, Any]:
    """The unlock effect of one decision, computed or explicitly UNKNOWN."""
    if decision == DECISION_RELEASE_ROOT:
        return {
            "status": "COUNTED",
            "sessions_released": len(session_ids),
            "note": (
                "each released session's cursor unit re-enters the eligible set and then "
                "drains to that session's own completion; the release is a class flip, not "
                "a one-unit grant"
            ),
        }
    if decision == DECISION_CONFLICT:
        return {
            "status": "COUNTED",
            "sessions_released": len(session_ids),
            "note": "each resolved session resumes from its frozen watermark",
        }
    if decision == DECISION_REMOTE_OUTCOME:
        return {
            "status": "UNKNOWN",
            "sessions_released": None,
            "note": (
                "the downstream effect depends on an EXTERNAL fact -- whether the recorded "
                "attempt id produced a receipt remotely. It is not computable from this "
                "corpus, and is not guessed here"
            ),
        }
    if decision == DECISION_PROVISIONAL_POLICY:
        return {
            "status": "PARTIAL",
            "sessions_released": None,
            "note": (
                "reclassification under the flag is computed per session in "
                "provisional_admission; a session that reclassifies to another blocker is "
                "NOT released by it"
            ),
        }
    if decision in (DECISION_BLOCKED_OUTPUT, DECISION_TERMINAL_REVIEW):
        return {
            "status": "COUNTED",
            "sessions_released": len(session_ids),
            "note": "one fresh attempt each, bounded by budgets.max_requeues_per_unit",
        }
    if decision == DECISION_IDENTITY_UNRECOVERABLE:
        return {
            "status": "UNREACHABLE",
            "sessions_released": 0,
            "note": (
                "no authority root and no policy flag changes this verdict: the evidence "
                "the check needs is absent from the corpus, not merely unenrolled"
            ),
        }
    if decision == DECISION_COMPLETE:
        return {
            "status": "NOT_APPLICABLE",
            "sessions_released": 0,
            "note": "finished history; no decision applies and none is outstanding",
        }
    return {
        "status": "NOT_APPLICABLE",
        "sessions_released": 0,
        "note": "no decision is outstanding for this group",
    }


def build(home: Path | str, *, registry: dict | None = None) -> dict[str, Any]:
    """Partition the freshest-generation corpus into one decision per session.

    Read-only and model-free: it reuses the allocator's own classifier, so the
    packet cannot disagree with the worker about what is runnable.
    """
    from time import time

    from saipal_analyst import doctor as doctor_mod
    from saipal_analyst import jobs as jobs_mod
    from saipal_analyst import worker as worker_mod
    from saipal_engine import authority as authority_mod
    from saipal_engine import cpall as cpall_mod

    root = Path(home)
    data = registry if registry is not None else load_registry()
    wall_now = time()

    packet: dict[str, Any] = {
        "operator_queue": True,
        "schema_version": OPERATOR_QUEUE_SCHEMA_VERSION,
        "home": str(root),
        "decisions": [],
        "boundary": {},
        "authority": {},
        "ok": False,
    }

    status, index, detail = load_index(root, registry=data)
    if status == STATUS_UNRECOVERABLE or index is None:
        packet["reason"] = f"session index unreadable: {detail}"
        return packet

    records = list(carrier_mod.freshest_records(index))
    journal = jobs_mod.load_journal(root)
    event_limit = int(carrier_mod._limits(data)["max_events"])

    buckets: dict[str, list[str]] = {key: [] for key in _DECISION_META}
    provenance: dict[str, list[str]] = {key: [] for key in _DECISION_META}
    released_by_binding = 0
    provisional_admission: dict[str, int] = {}
    # PAL-CPALL-04 measures the binding wall in JOBS; this packet partitions in
    # SESSIONS. Both are true and they are not the same number, so both are
    # reported: a session can carry a checkable artifact and still be gated on
    # something else first.
    verifiable_binding_sessions: list[str] = []
    verifiable_binding_also_provisional: list[str] = []

    for record in records:
        session_id = str(record.get("session_id") or "")
        if not session_id:
            continue
        klass = worker_mod._classify_unit(record, event_limit, journal, False, wall_now)
        cursor = _cursor_job(record, journal, event_limit)
        cursor_stage = str((cursor or {}).get("stage") or "")
        if cursor_stage == jobs_mod.BLOCKED_BINDING and doctor_mod._authority_verifiable(
            record.get("protocol")
        ):
            verifiable_binding_sessions.append(session_id)
            if klass == "PROVISIONAL_DISABLED":
                verifiable_binding_also_provisional.append(session_id)

        if klass in ("RUNNABLE_FINAL", "RUNNABLE_PROVISIONAL"):
            decision = DECISION_AGENT_ACTIONABLE
        elif klass == "DONE":
            decision = DECISION_COMPLETE
        elif klass == "STALE":
            # A non-IMPORTED record is stale to the allocator; in this corpus the
            # stale population IS the conflict population. Naming the conflict
            # is what stops the same 11 sessions being reported once as analyst
            # STALE work and again as cpall conflict work.
            decision = DECISION_CONFLICT
        elif klass == "REMOTE_OUTCOME_UNKNOWN":
            decision = DECISION_REMOTE_OUTCOME
        elif klass == "PROVISIONAL_DISABLED":
            decision = DECISION_PROVISIONAL_POLICY
            with_flag = worker_mod._classify_unit(record, event_limit, journal, True, wall_now)
            provisional_admission[with_flag] = provisional_admission.get(with_flag, 0) + 1
        elif klass == "BLOCKED_BINDING":
            decision = _binding_decision(record, doctor_mod)
        elif klass == "TERMINAL":
            if cursor_stage == jobs_mod.BLOCKED_BINDING:
                decision = _binding_decision(record, doctor_mod)
            elif cursor_stage == jobs_mod.BLOCKED:
                decision = DECISION_BLOCKED_OUTPUT
            else:
                decision = DECISION_TERMINAL_REVIEW
            provenance[decision].append(f"{session_id}@{cursor_stage or 'no-job'}")
        elif klass == "WAITING_RETRY":
            decision = DECISION_WAITING_RETRY
        else:
            decision = DECISION_TERMINAL_REVIEW

        buckets[decision].append(session_id)

        # Leverage is measured on the decisions whose effect this corpus can
        # compute: a release-root enrollment and a provisional flag are both
        # re-runnable through the allocator without mutating anything.
        if decision == DECISION_RELEASE_ROOT:
            if _released_by_binding(record, journal, event_limit, wall_now) in (
                "RUNNABLE_FINAL",
                "RUNNABLE_PROVISIONAL",
            ):
                released_by_binding += 1

    for decision, session_ids in buckets.items():
        if not session_ids:
            continue
        ordered = sorted(set(session_ids))
        meta = _DECISION_META[decision]
        entry: dict[str, Any] = {
            "decision": decision,
            "sessions": len(ordered),
            "session_ids": ordered,
            "meaning": meta["meaning"],
            "missing": meta["missing"],
            "legal_actions": list(meta["legal_actions"]),
            "forbidden_actions": list(meta["forbidden"]),
            "operator_decision_required": decision not in NON_OPERATOR_DECISIONS,
            "unlock": _unlock_for(decision, ordered),
        }
        if decision == DECISION_PROVISIONAL_POLICY:
            entry["provisional_admission"] = dict(sorted(provisional_admission.items()))
            also = sorted(set(verifiable_binding_also_provisional) & set(ordered))
            if also:
                entry["binding_verifiable_but_also_gated_here"] = {
                    "sessions": len(also),
                    "session_ids": also,
                    "note": (
                        "these carry a checkable authority artifact, so enrolling a root "
                        "clears ONE of their two gates -- they still need the provisional "
                        "policy decision. Counting them as release-root work would "
                        "overstate what one enrollment buys"
                    ),
                }
        if decision == DECISION_TERMINAL_REVIEW and provenance[decision]:
            entry["cursor_job_stages"] = sorted(provenance[decision])
        if decision == DECISION_REMOTE_OUTCOME:
            entry["attempt_ids"] = _remote_attempt_ids(journal)
        if decision == DECISION_CONFLICT:
            entry["conflict_evidence"] = _conflict_evidence(cpall_mod, root, data, ordered)
        if decision == DECISION_RELEASE_ROOT:
            entry["authority_verifiable_sessions"] = released_by_binding
            entry["binding_evidence_disambiguation"] = {
                "verifiable_binding_jobs": len(verifiable_binding_sessions),
                "sessions_released_by_enrollment_alone": released_by_binding,
                "also_gated_on_provisional": len(set(verifiable_binding_also_provisional)),
                "note": (
                    "analyst-doctor counts the first row in JOBS (PAL-CPALL-04's split); this "
                    "packet counts sessions and gates. The two rows differ whenever a "
                    "verifiable session is blocked by a gate the allocator tests BEFORE the "
                    "journal lookup -- the provisional check does exactly that. Neither "
                    "number is wrong; they answer different questions, and the difference is "
                    "the honest measure of how much one enrollment actually buys"
                ),
            }
        packet["decisions"].append(entry)

    _rank(packet["decisions"])

    population = len(records)
    assigned = sum(int(entry["sessions"]) for entry in packet["decisions"])
    agent_runnable = _sessions_in(packet, DECISION_AGENT_ACTIONABLE)
    complete = _sessions_in(packet, DECISION_COMPLETE)
    operator_sessions = sum(
        int(entry["sessions"])
        for entry in packet["decisions"]
        if entry["operator_decision_required"]
    )
    unreachable = _sessions_in(packet, DECISION_IDENTITY_UNRECOVERABLE)
    unsafe = _sessions_in(packet, DECISION_REMOTE_OUTCOME)

    packet["boundary"] = {
        "population_sessions": population,
        "assigned_sessions": assigned,
        "unassigned_sessions": population - assigned,
        "auto_drain_complete": agent_runnable == 0,
        "agent_runnable_remaining": agent_runnable,
        "corpus_fully_resolved": operator_sessions == 0 and complete == population,
        "operator_work_remaining_sessions": operator_sessions,
        "complete_history_sessions": complete,
        "permanently_unverifiable_sessions": unreachable,
        "unsafe_to_replay_sessions": unsafe,
        "state": "AUTO_DRAIN_COMPLETE" if agent_runnable == 0 else "DRAINING",
        "reading": (
            "auto_drain_complete answers only whether an AGENT could still move something. "
            "corpus_fully_resolved is a separate question and is answered False whenever "
            "any operator decision remains, however little leverage it carries."
        ),
    }
    packet["authority"] = _authority_section(authority_mod, root)
    packet["corpus_digest"] = _corpus_digest(packet)
    packet["ok"] = assigned == population
    return packet


def _binding_decision(record: dict, doctor_mod: Any) -> str:
    """Split the binding wall on the artifact, not on the count.

    This is PAL-CPALL-04's split applied per session. `coverage` calls a session
    recoverable because the REASON is fixable in principle; only a session that
    carries a checkable artifact is actually released by enrolling a root.
    """
    protocol = record.get("protocol")
    if doctor_mod._authority_verifiable(protocol):
        return DECISION_RELEASE_ROOT
    return DECISION_IDENTITY_UNRECOVERABLE


def _remote_attempt_ids(journal: dict) -> list[dict[str, Any]]:
    """The paid attempts whose remote outcome is unconfirmed.

    Named so the operator can ask the REMOTE system about these exact ids; that
    is the whole reconciliation action, and it must not be a replay.
    """
    out: list[dict[str, Any]] = []
    for job in (journal.get("jobs") or {}).values():
        if str(job.get("stage")) != "REMOTE_OUTCOME_UNKNOWN":
            continue
        attempts = job.get("attempt_ids")
        out.append(
            {
                "job_id": job.get("job_id"),
                "session_id": job.get("session_id"),
                "episode_index": job.get("episode_index"),
                "created_at": job.get("created_at"),
                "attempt_ids": sorted(
                    (attempts or {}).items()
                ) and {role: value for role, value in sorted((attempts or {}).items())},
                "ambiguous_attempt_ids": sorted(
                    str(item.get("attempt_id"))
                    for item in (job.get("ambiguous_attempt_ids") or [])
                    if item.get("attempt_id")
                ),
                "error_detail": job.get("error_detail"),
            }
        )
    out.sort(key=lambda item: str(item.get("job_id") or ""))
    return out


def _conflict_evidence(
    cpall_mod: Any, root: Path, data: dict, session_ids: list[str]
) -> list[dict[str, Any]]:
    """Exact conflict identity + material evidence, from the live index.

    Batch presentation never merges identities: each conflict keeps its own
    session id and material digest even when several are mechanically identical,
    because resolving one is not resolving the others.
    """
    _status, _objective, _state = cpall_mod.load_objective(root)
    _st, index, _d = load_index(root, registry=data)
    rows: list[dict[str, Any]] = []
    if index is None:
        return rows
    by_session = {
        str(record.get("session_id") or ""): record
        for record in carrier_mod.freshest_records(index)
    }
    for session_id in sorted(session_ids):
        record = by_session.get(session_id)
        if record is None:
            continue
        rows.append(
            {
                "session_id": session_id,
                "generation": record.get("generation"),
                "status": record.get("status"),
                "last_analyzed_seq": record.get("last_analyzed_seq"),
                "conflict_material_sha256": carrier_mod.conflict_material_digest(record),
                "conflict": record.get("conflict"),
                # PAL-CPALL-04: a refusal has a canonical way back, and "an
                # operator decision makes them eligible again" is not one --
                # it never says WHICH decision. So the resolver is named on the
                # evidence itself, next to the material it applies to.
                "resolvable_by": "operator",
                "resolution_inputs": (
                    "expected_prefix_sha256 vs observed_prefix_sha256 over the "
                    "already-analyzed prefix: the operator decides which prefix is "
                    "the session's real history, then re-imports or accepts the "
                    "isolated generation"
                ),
                "auto_resolution": False,
            }
        )
    return rows


def _authority_section(authority_mod: Any, root: Path) -> dict[str, Any]:
    """Candidate authority roots, reported as CANDIDATE_ONLY. Never enrolled.

    `discover` is read-only and already refuses to trust anything. This section
    only restates that refusal in the operator packet, so the one command the
    operator is most likely to reach for cannot be mistaken for a suggestion the
    protocol already approved.
    """
    try:
        report = authority_mod.discover(root)
    except Exception as exc:  # pragma: no cover - discovery is defensive already
        return {"ok": False, "reason": f"authority discovery failed: {exc}"}
    candidates = []
    for candidate in report.get("candidates") or []:
        candidates.append(
            {
                "kind": candidate.get("kind"),
                "path": candidate.get("path"),
                "exists": candidate.get("exists"),
                "is_git_repo": candidate.get("is_git_repo"),
                "registry_present": candidate.get("registry_present"),
                "confidence": candidate.get("confidence"),
                "reason": candidate.get("reason"),
                "disposition": "CANDIDATE_ONLY",
            }
        )
    return {
        "ok": bool(report.get("ok")),
        "enrolled": report.get("currently_enrolled"),
        "pinned": report.get("pinned"),
        "candidates": candidates,
        "policy": (
            "discovery never trusts and this packet never enrolls: a candidate is a path "
            "to evaluate, not an approval. A candidate whose exists/registry_present is "
            "false is not a root at all and enrolling it would be fabricated authority"
        ),
    }


def _rank(decisions: list[dict[str, Any]]) -> None:
    """Highest-leverage first; UNKNOWN and UNREACHABLE sink to a stable tail.

    The point is that the action which releases the most sessions is the first
    line an operator reads. Ties break on a fixed per-decision order rather than
    on dict order, so an unchanged corpus always prints an unchanged list.
    """
    def rank(entry: dict[str, Any]) -> int:
        """0 = releases sessions, 1 = does not."""
        unlock = entry.get("unlock") or {}
        released = unlock.get("sessions_released")
        if str(unlock.get("status")) == "COUNTED" and isinstance(released, int) and released > 0:
            return 0
        return 1

    def sort_key(entry: dict[str, Any]) -> tuple:
        if rank(entry) == 0:
            released = int((entry.get("unlock") or {}).get("sessions_released") or 0)
            return (0, -released, _ZERO_LEVERAGE_ORDER.get(str(entry.get("decision")), 99))
        return (1, 0, _ZERO_LEVERAGE_ORDER.get(str(entry.get("decision")), 99))

    decisions.sort(key=sort_key)


def _sessions_in(packet: dict[str, Any], decision: str) -> int:
    for entry in packet.get("decisions") or []:
        if entry.get("decision") == decision:
            return int(entry.get("sessions") or 0)
    return 0


def _corpus_digest(packet: dict[str, Any]) -> str:
    """Identity of the corpus the packet describes.

    Determinism control: an unchanged corpus must produce an unchanged digest,
    so an operator (or SAIMAIL) can tell a real state change from a re-render.
    Built from sorted identities and counts only -- never from a clock, a
    hostname or a pid, all of which would make it churn for no reason.
    """
    material = json.dumps(
        {
            "schema_version": packet.get("schema_version"),
            "decisions": [
                {
                    "decision": entry.get("decision"),
                    "sessions": entry.get("sessions"),
                    "session_ids": entry.get("session_ids"),
                }
                for entry in packet.get("decisions") or []
            ],
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def render_text(packet: dict[str, Any]) -> str:
    """Concise operator rendering. Same facts, same order as the JSON."""
    if not packet.get("ok") and packet.get("reason"):
        return f"operator-queue: {packet['reason']}"
    boundary = packet.get("boundary") or {}
    lines = [
        f"operator-queue: {packet.get('home')}",
        f"population: {boundary.get('population_sessions')} session(s); "
        f"assigned {boundary.get('assigned_sessions')}; "
        f"unassigned {boundary.get('unassigned_sessions')}",
        f"boundary: {boundary.get('state')} "
        f"(auto_drain_complete={boundary.get('auto_drain_complete')}, "
        f"agent_runnable={boundary.get('agent_runnable_remaining')}, "
        f"fully_resolved={boundary.get('corpus_fully_resolved')})",
        f"operator work: {boundary.get('operator_work_remaining_sessions')} session(s); "
        f"permanently unverifiable {boundary.get('permanently_unverifiable_sessions')}; "
        f"unsafe to replay {boundary.get('unsafe_to_replay_sessions')}",
        "decisions (highest unlock first):",
    ]
    for entry in packet.get("decisions") or []:
        unlock = entry.get("unlock") or {}
        released = unlock.get("sessions_released")
        effect = (
            f"releases {released}" if isinstance(released, int)
            else str(unlock.get("status"))
        )
        lines.append(
            f"  [{entry.get('decision')}] {entry.get('sessions')} session(s) -- {effect}"
        )
        if entry.get("operator_decision_required"):
            lines.append(f"      missing: {entry.get('missing')}")
            for action in entry.get("legal_actions") or []:
                lines.append(f"      do: {action}")
        for action in entry.get("forbidden_actions") or []:
            lines.append(f"      never: {action}")
    authority = packet.get("authority") or {}
    for candidate in authority.get("candidates") or []:
        lines.append(
            f"  authority candidate [{candidate.get('disposition')}]: "
            f"{candidate.get('kind')} {candidate.get('path')} "
            f"(exists={candidate.get('exists')}, "
            f"registry_present={candidate.get('registry_present')})"
        )
    lines.append(f"corpus digest: {packet.get('corpus_digest')}")
    return "\n".join(lines)


def write_packet(home: Path | str, packet: dict[str, Any]) -> Path:
    """Persist the packet beside the objective it describes.

    The caller owns the fence; this only writes the file atomically so a reader
    never sees a half-rendered queue.
    """
    path = operator_queue_path(home)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(packet, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)
    return path