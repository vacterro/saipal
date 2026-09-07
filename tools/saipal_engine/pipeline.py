"""Analysis pipeline: session -> episodes -> detectors -> signals.

Orchestrates the bounded mechanical pass (Layer A) for one `continue` cycle.
The pipeline is triage-only (PAL-ARCH-01): detector output becomes a durable
SIGNAL that prioritizes the semantic carrier's work -- it never becomes a
finding, never advances a finding lifecycle, and never emits an audit. Only
the semantic submission boundary (`submit.py`) can open the finding
lifecycle, because only the analyst may decide that protocol drift is real.

Deterministic, stdlib-only, and it never touches an analyzed project or SAIPEN
Core except through the constrained audit enqueue (kept for the submission
boundary's use).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from . import audits as audits_mod
from . import bundle as bundle_mod
from . import detectors as detectors_mod
from . import enqueue as enqueue_mod
from . import findings as findings_mod
from . import hardening as hardening_mod
from . import historical as historical_mod
from . import law as law_mod
from . import publications as publications_mod
from . import recurrence as recurrence_mod
from . import config as config_mod
from .sink import configured_sink
from . import sessions as sessions_mod
from .analyst import analyze_episode
from .capability import require_action
from .errors import PalError
from .paths import atomic_write_json, home_paths
from .registry import load_registry

ANALYSIS_BUDGET = hardening_mod.Budget()


class HistoricalRuleReader:
    """Bounded, cached historical rule retrieval for one analysis cycle.

    The operator's `protocol_authority` roots are the only paths consulted; a
    session's binding fields select an identity inside them. One resolution per
    (binding identity, rule set) per cycle, because the same session yields the
    same surface however many findings it produces.
    """

    def __init__(self, authority: dict, *, registry: dict | None = None):
        self._authority = authority or {}
        self._registry = registry
        self._cache: dict[tuple, dict] = {}

    @property
    def configured(self) -> bool:
        return any(self._authority.get(key) for key in config_mod.AUTHORITY_KEYS)

    def read(self, protocol: dict | None, rule_ids: list[str]) -> dict | None:
        ids = tuple(dict.fromkeys(str(rid) for rid in (rule_ids or []) if rid))
        if not ids:
            return None
        evidence = protocol if isinstance(protocol, dict) else {}
        key = (
            str(evidence.get("git_head") or ""),
            str(evidence.get("version") or ""),
            str(evidence.get("registry_sha256") or ""),
            str(evidence.get("tree_fingerprint") or ""),
            ids,
        )
        if key in self._cache:
            return self._cache[key]
        try:
            resolution = historical_mod.read_historical_rules(
                evidence,
                ids,
                git_repository=self._authority.get("git_repository"),
                release_root=self._authority.get("release_root"),
                snapshot_root=self._authority.get("snapshot_root"),
                registry=self._registry,
            )
        except (OSError, ValueError) as exc:
            resolution = {
                "schema_version": 1,
                "status": "UNAVAILABLE",
                "source": "UNKNOWN",
                "identity": None,
                "rule_ids": list(ids),
                "rules": [],
                "attempts": [{"source": "UNKNOWN", "reason": str(exc)}],
            }
        compact = historical_mod.compact_rule_surface(resolution)
        self._cache[key] = compact
        return compact


def _candidates_for_session(
    record: dict,
    bundle: dict,
    episodes: list[dict],
    registry: dict,
    historical: HistoricalRuleReader | None,
    index: detectors_mod.EventIndex | None = None,
) -> list[dict]:
    out: list[dict] = []
    for episode in episodes:
        refined = analyze_episode(
            episode, bundle, record, None, registry=registry, index=index
        )
        for candidate in refined:
            if historical is not None and historical.configured:
                candidate["historical_rule_surface"] = historical.read(
                    record.get("protocol"),
                    candidate.get("rule_ids") or [],
                )
        out.extend(refined)
    return out


def _finding_shape(candidate: dict, record: dict, historical: dict | None = None) -> dict:
    """Normalize an analyst-refined candidate into a finding-shape candidate."""
    drift_class = candidate.get("drift_class", "UNKNOWN")
    law_info = _applicable(drift_class, record.get("protocol"), registry=None)
    binding = record.get("protocol") or {}
    confidence = candidate.get(
        "confidence_proposal",
        candidate.get("confidence", "LOW"),
    )
    if law_info["violation_claimable"] is False:
        confidence = "LOW" if confidence != "LOW" else confidence

    # T-053: calibration feedback -- if the finding carries a downgrade note from prior maintainer rejection
    if candidate.get("confidence_adjustment") == "DOWNGRADE_LOW":
        confidence = "LOW"

    severity = _severity(drift_class)
    change_target = candidate.get(
        "likely_change_target", candidate.get("change_target", "UNKNOWN")
    )
    if confidence not in ("HIGH", "MEDIUM", "LOW"):
        confidence = "LOW"
    return {
        "detector": candidate.get("detector", ""),
        "session_id": record.get("session_id", ""),
        "episode_id": candidate.get("episode_id", -1),
        "episode_index": candidate.get("episode_index", candidate.get("episode_id", -1)),
        "rule_ids": list(candidate.get("rule_ids") or []),
        "drift_class": candidate.get("drift_class", "UNKNOWN"),
        "severity": severity,
        "confidence": confidence,
        "change_target": change_target,
        "root_cause": candidate.get(
            "root_cause", candidate.get("root_cause_hypothesis", "")
        ),
        "alternatives": list(
            candidate.get("alternatives", candidate.get("alternative_explanations", []))
        ),
        "missing_evidence": list(candidate.get("missing_evidence") or []),
        "protocol_bindings": [binding],
        "protected_invariants": list(candidate.get("protected_invariants") or []),
        "event_refs": list(candidate.get("event_refs") or []),
        "expected": candidate.get("expected", {}),
        "observed": candidate.get("observed", {}),
        "mechanical_confidence": candidate.get("mechanical_confidence", "LOW"),
        "contrary_evidence_found": bool(candidate.get("contrary_evidence_found")),
        "contrary_evidence": list(candidate.get("contrary_evidence") or []),
        "root_cause_hypothesis": candidate.get("root_cause_hypothesis", ""),
        "historical_rule_surface": historical,
    }


def _severity(drift_class: str) -> str:
    high = {
        "EVIDENCE_FABRICATION",
        "DESTRUCTIVE_GATE_DRIFT",
        "RECOVERY_ORDER_DRIFT",
        "SOURCE_CLOSURE_FALSE_GREEN",
        "HUSH_SAFETY_SUPPRESSION",
    }
    if drift_class in high:
        return "P1"
    return "P3"


def _applicable(drift_class: str, protocol: dict | None, registry: dict | None = None) -> dict:
    try:
        law = law_mod.resolve_law(drift_class, registry=registry)
        rule_ids = law.get("rule_ids", [])
    except PalError:
        law = {"rule_ids": [], "owner_documents": [], "drift_class": drift_class, "expected_behavior": ""}
        rule_ids = []
    binding_status = (protocol or {}).get("binding_status")
    applicability = sessions_mod.historical_applicability(protocol, binding_status=binding_status)
    return {
        "applicable_law": law,
        "violation_claimable": bool(rule_ids) and applicability["violation_claimable"],
        "reason": "unknown or unbound protocol" if not applicability["violation_claimable"] else "",
        "current_protocol_protection": "UNKNOWN",
    }


def advance_to_qualified(index: dict, finding: dict) -> None:
    """OBSERVED -> BOUND -> CHALLENGED -> QUALIFIED with the challenge + do-no-harm gates.

    T-030: the do-no-harm gate (PAL-DONOHARM-01) must run before QUALIFIED so
    every destructive/core-facing candidate carries ``harm_warnings`` (empty
    or explicit). A finding cannot reach QUALIFIED until this gate has run.

    T-045: the gate now also BLOCKS. A finding that reaches a protected
    invariant without declaring it, from a disposition that does not blame the
    protocol, goes to BLOCKED instead of QUALIFIED -- a warning nobody has to
    act on is not a gate.

    PAL-ARCH-01: this path exists for the SEMANTIC submission boundary only.
    A finding without a semantic confirmation cannot leave SUSPECTED, and
    `qualification_threshold` refuses unconfirmed findings, so the lifecycle
    gates cannot be reached from the mechanical pass.
    """
    findings_mod.advance_lifecycle(finding, "BOUND", registry=None)
    findings_mod.prosecutor_defender_pass(finding, None, None)
    findings_mod.advance_lifecycle(finding, "CHALLENGED", registry=None)
    harm_warnings = findings_mod.do_no_harm_gate(finding)
    finding["harm_warnings"] = harm_warnings
    blocks = findings_mod.harm_blocks(finding)
    if blocks:
        finding["harm_blocks"] = blocks
        findings_mod.advance_lifecycle(finding, "BLOCKED", registry=None)
        return
    if not finding.get("protected_invariants"):
        finding["protected_invariants"] = list(findings_mod.PROTECTED)
    findings_mod.advance_lifecycle(finding, "QUALIFIED", registry=None)


def _signal_shape(candidate: dict, record: dict, historical: dict | None) -> dict:
    """A mechanical detector candidate in its durable signal shape.

    A signal is an investigation hint for the semantic carrier: it names where
    to look (session, episode, events), what the detector saw, how confident
    the mechanism is, and which rules would be violated IF the suspicion held.
    It carries no finding id and no lifecycle state, because it never becomes
    a finding on its own (PAL-ARCH-01).
    """
    drift_class = candidate.get("drift_class", "UNKNOWN")
    confidence = candidate.get(
        "confidence_proposal",
        candidate.get("confidence", "LOW"),
    )
    if confidence not in ("HIGH", "MEDIUM", "LOW"):
        confidence = "LOW"
    return {
        "signal_id": candidate.get("signal_id"),
        "detector": candidate.get("detector", ""),
        "session_id": record.get("session_id", ""),
        "episode_index": candidate.get("episode_index", candidate.get("episode_id", -1)),
        "rule_ids": list(candidate.get("rule_ids") or []),
        "drift_class": drift_class,
        "mechanical_confidence": candidate.get("mechanical_confidence", "LOW"),
        "confidence_proposal": confidence,
        "root_cause_hypothesis": candidate.get("root_cause_hypothesis", ""),
        "alternative_explanations": list(
            candidate.get("alternative_explanations", candidate.get("alternatives", []))
        ),
        "missing_evidence": list(candidate.get("missing_evidence") or []),
        "event_refs": list(candidate.get("event_refs") or []),
        "expected": candidate.get("expected", {}),
        "observed": candidate.get("observed", {}),
        "contrary_evidence_found": bool(candidate.get("contrary_evidence_found")),
        "contrary_evidence": list(candidate.get("contrary_evidence") or []),
        "protocol_binding": record.get("protocol") or {},
        "historical_rule_surface": historical,
    }


def _record_signal(home: Path, signal: dict, *, registry: dict | None) -> dict:
    """Persist one signal into the deduplicating signal ledger. Returns the row.

    Identity is the evidence the signal stands on (session, episode, detector,
    class, event refs) hashed into a stable id, so re-analysis of the same
    episode rewrites its row instead of accumulating copies; a NEW occurrence
    of the same mechanism elsewhere is a new row. The ledger is the semantic
    carrier's prioritization input and the durable record that mechanical
    triage ran -- it is never a finding.
    """
    paths = home_paths(home)
    signals_path = paths.root / "signals.json"
    payload = _load_signals(signals_path)
    key = str(signal.get("signal_id") or "")
    existing = next((row for row in payload["signals"] if row.get("signal_id") == key), None)
    row = dict(signal)
    row["signal_id"] = key
    row["occurrences"] = int((existing or {}).get("occurrences") or 0) + 1
    row["last_seen_at"] = _now_iso()
    if existing is None:
        row["first_seen_at"] = row["last_seen_at"]
        payload["signals"].append(row)
    else:
        existing.update(row)
    try:
        require_action("write_own_index", registry=registry)
        atomic_write_json(signals_path, payload, root=paths.root)
    except (OSError, PalError):
        # The signal ledger is an optimization over the session record, not
        # evidence: a home that cannot hold it still analyzed its sessions.
        pass
    return row


def _load_signals(signals_path: Path) -> dict:
    from .paths import read_json

    if not signals_path.exists():
        return {"schema_version": 1, "signals": []}
    try:
        payload = read_json(signals_path)
    except (OSError, ValueError, UnicodeDecodeError):
        return {"schema_version": 1, "signals": []}
    if not isinstance(payload, dict) or not isinstance(payload.get("signals"), list):
        return {"schema_version": 1, "signals": []}
    return payload


def _now_iso() -> str:
    from .paths import utc_now_iso

    return utc_now_iso()


def analyze_sessions(
    home: Path,
    index: dict,
    *,
    registry: dict | None = None,
    budget: hardening_mod.Budget | None = None,
) -> dict[str, Any]:
    """Run one bounded MECHANICAL TRIAGE pass over unanalyzed sessions.

    Triage-only (PAL-ARCH-01): detector candidates become signals in the
    signal ledger -- investigation hints for the semantic carrier, with the
    protocol binding and historical rule surface attached. No finding is
    created, no lifecycle advances, no audit is emitted here; those are the
    semantic submission boundary's. The findings index is only MIGRATED when
    a legacy index holds pre-boundary mechanical findings.

    Returns counts for the cycle report. Sessions whose episodes are
    exhausted are marked analyzed so a later cycle skips them.
    """
    data = registry if registry is not None else load_registry()
    budget = budget or ANALYSIS_BUDGET
    paths = home_paths(home)

    # NOTE (PAL-ARCH-01): legacy finding migration does NOT live here. It is an
    # authority/schema migration that must run at the start of every mutating
    # cycle -- before publication retry, before analysis, even when no session
    # index exists. `_continue_cycle` owns it.

    telemetry = hardening_mod.load_telemetry(home)
    started = time.monotonic()
    audits_emitted: list[dict] = []
    budget_hit = False
    signals_total = 0
    events_analyzed = 0
    sessions_analyzed = 0
    signals: list[dict] = []

    config_status, config, config_detail = config_mod.load_config(home)
    if config_status == "unrecoverable":
        raise PalError("VALIDATION_FAILED", config_detail)
    historical = HistoricalRuleReader(
        config_mod.protocol_authority(home, config), registry=data
    )

    for record in index.get("sessions", []):
        if sessions_analyzed >= int(budget.max_sessions):
            break
        # A tripped budget ends the CYCLE, not just the session: entering a later
        # session would count it, rewrite its analysis block from a budget that
        # was already spent, and claim work that never happened (audit CORE-003).
        if budget_hit:
            break
        if not record.get("episodes"):
            continue
        if record.get("analysis", {}).get("episodes_exhausted"):
            continue

        source_ref = record.get("source_ref", "")
        lease = hardening_mod.SessionLease(home, record.get("session_id", ""))
        if not lease.acquire():
            continue
        # Everything below holds the lease, so it lives in `with`: the
        # missing-bundle path used to `continue` without releasing and blocked
        # its own session until stale recovery (audit CORE-004).
        with lease:
            bundle_path = paths.session_inbox / Path(source_ref).name
            if not bundle_path.exists():
                continue
            try:
                bundle = bundle_mod.load_bundle_file(bundle_path, registry=data)
            except PalError:
                continue

            episodes = list(record.get("episodes") or [])
            # One event index per SESSION, shared by every episode and detector:
            # the span lookups are then bisects into one ordered list instead of
            # a full-bundle scan per detector per episode (PERF-001).
            view = detectors_mod.EventIndex(bundle)
            # Resume from the persisted cursor. Reading it is what makes the
            # checkpoint mean anything: a write-only cursor made every
            # budget-limited cycle reprocess episode 0 forever.
            cursor = _resume_cursor(record, len(episodes))
            analyzed_up_to = int(record.get("analysis", {}).get("analyzed_up_to_seq") or 0)
            session_signals = 0
            for position in range(cursor, len(episodes)):
                episode = episodes[position]
                span = _span_size(episode, bundle)
                if _budget_exhausted(budget, events_analyzed, started, span):
                    budget_hit = True
                    break
                candidates = _candidates_for_session(
                    record, bundle, [episode], data, historical, view
                )
                # Charge the span for EVERY analyzed episode, before the
                # candidate branches: a conformant session is work, and a pass
                # that costs nothing cannot be bounded.
                events_analyzed += span
                telemetry = hardening_mod.increment(telemetry, "events_analyzed", span)
                analyzed_up_to = max(analyzed_up_to, int(episode.get("end_seq", 0)))
                cursor = position + 1

                # Layer A is triage: a detector candidate is a SIGNAL for the
                # semantic carrier. It is recorded durably so `next` can
                # prioritize it, and it never becomes a finding (PAL-ARCH-01).
                for candidate in candidates:
                    if _candidate_rejected(candidate):
                        continue
                    signal = _signal_shape(
                        candidate, record, candidate.get("historical_rule_surface")
                    )
                    signal["signal_id"] = _signal_id(signal)
                    recorded = _record_signal(home, signal, registry=data)
                    signals_total += 1
                    session_signals += 1
                    if len(signals) < int(getattr(budget, "max_candidates", 100)):
                        signals.append(
                            {
                                "signal_id": recorded.get("signal_id"),
                                "session_id": recorded.get("session_id"),
                                "episode_index": recorded.get("episode_index"),
                                "drift_class": recorded.get("drift_class"),
                                "mechanical_confidence": recorded.get(
                                    "mechanical_confidence"
                                ),
                                "rule_ids": recorded.get("rule_ids"),
                                "event_refs": recorded.get("event_refs"),
                            }
                        )

                if signals_total >= int(budget.max_candidates):
                    budget_hit = True
                    break

            sessions_analyzed += 1
            telemetry = hardening_mod.increment(telemetry, "sessions_analyzed")
            exhausted = cursor >= len(episodes)
            record["analysis"] = {
                # Exhaustion is this record's own cursor reaching its own end.
                "episodes_exhausted": exhausted,
                "last_analyzed_at": None,
                "analyzed_up_to_seq": analyzed_up_to,
                "next_episode_index": cursor,
            }
            record["last_analyzed_seq"] = max(
                int(record.get("last_analyzed_seq", 0)), analyzed_up_to
            )
            # keep the watermark prefix digest in step with the watermark, so a
            # later append-only growth continues instead of a false CONFLICT.
            if analyzed_up_to > 0:
                record["prefix_sha256"] = bundle_mod.prefix_digest(bundle, analyzed_up_to)
            # Mechanical exhaustion is NOT semantic completion (PAL-ARCH-01):
            # a triaged session still owes every episode to the analyst, and
            # the negative-evidence receipt below records only that the
            # mechanical pass found nothing worth signaling.
            _record_recurrence(
                home, record, exhausted=exhausted and session_signals == 0, registry=data
            )

    # Nothing analyzed means nothing to persist. Rewriting an 11 MB session
    # index and telemetry after a no-work pass was pure amplification: `status`
    # and every idle cycle paid for it (PERF-004). The findings index is not
    # rewritten here at all: this pass never touches it beyond migration.
    if sessions_analyzed:
        sessions_mod.save_index(home, index, registry=data)
        hardening_mod.save_telemetry(home, telemetry)

    return {
        "sessions_analyzed": sessions_analyzed,
        "events_analyzed": events_analyzed,
        "signals_total": signals_total,
        "signals": signals,
        "findings_created": 0,
        "findings_rejected": 0,
        "audits_emitted": audits_emitted,
        "candidates_total": signals_total,
    }


def _signal_id(signal: dict) -> str:
    from .paths import sha256_text

    parts = (
        str(signal.get("session_id") or ""),
        str(signal.get("episode_index")),
        str(signal.get("detector") or ""),
        str(signal.get("drift_class") or ""),
        ",".join(str(r) for r in (signal.get("event_refs") or [])),
    )
    return "sig-" + sha256_text("\x00".join(parts))[:32]


def _candidate_rejected(candidate: dict) -> bool:
    """A signal contradicted by its own contrary-evidence pass is dropped."""
    return bool(candidate.get("contrary_evidence_found")) and candidate.get(
        "severity", "P3"
    ) == "P3"


def _record_recurrence(
    home: Path,
    record: dict,
    *,
    exhausted: bool = True,
    registry: dict | None,
) -> None:
    """Record mechanical-triage completion for the recurrence ledger.

    This is NOT a semantic verdict: it says the deterministic pass ran to the
    end of the episode cursor and found nothing worth signaling. It must never
    be read as evidence that a session was semantically examined (PAL-ARCH-01);
    the semantic receipts own that. A session that ran out of budget mid-way is
    not negative evidence: "no signal yet" and "no signal in this session" are
    different claims, and recording the first as the second would let a bounded
    cycle vote clean on evidence it never read.
    """
    try:
        if not exhausted:
            return
        recurrence_mod.record_negative(home, record, registry=registry)
    except (OSError, ValueError, UnicodeDecodeError, PalError) as exc:
        from . import log as log_mod

        log_mod.append_event(
            home,
            "recurrence_record_failure",
            data={
                "session_id": record.get("session_id", ""),
                "reason": str(exc),
            },
            registry=registry,
        )


def _span_size(episode: dict, bundle: dict) -> int:
    return max(0, int(episode.get("end_seq", 0)) - int(episode.get("start_seq", 0)) + 1)


def _resume_cursor(record: dict, episode_count: int) -> int:
    """Where this record's next analysis pass starts.

    The persisted cursor is trusted but clamped: a value past the end would skip
    the tail silently, and a negative or malformed one would restart work already
    charged. Both are index conditions, not reasons to abandon the record.
    """
    try:
        cursor = int((record.get("analysis") or {}).get("next_episode_index") or 0)
    except (TypeError, ValueError):
        cursor = 0
    return max(0, min(cursor, episode_count))


def _budget_exhausted(
    budget: hardening_mod.Budget, events_analyzed: int, started: float, span: int
) -> bool:
    """Is there room for one more episode of `span` events?

    Time is a hard stop. Events are a soft ceiling in exactly one case: when
    nothing has been analyzed yet this cycle, an episode larger than the whole
    budget is analyzed anyway. Refusing it would starve that episode forever --
    every later cycle would make the same refusal -- and a session that can never
    progress is worse than a cycle that overshoots once (audit CORE-003).
    """
    if time.monotonic() - started >= float(getattr(budget, "time_limit_seconds", 3600)):
        return True
    limit = int(budget.max_events)
    if events_analyzed == 0:
        return False
    return events_analyzed + span > limit


def emit_audit(
    home: Path,
    finding: dict,
    record: dict,
    bundle: dict,
    paths: Any,
    registry: dict,
    audits_emitted: list[dict],
) -> None:
    """Turn a qualified finding into a numbered audit — the external boundary.

    Fail-closed by construction (PAL-ARCH-01): a finding without a semantic
    DRIFT confirmation tied to a BOUND historical authority cannot stage or
    publish here, whatever its caller believes. External-effect boundaries
    defend their own invariants; they do not trust them to the caller.
    """
    if not findings_mod.is_semantically_confirmed(finding):
        raise PalError(
            "SEMANTIC_CONFIRMATION_REQUIRED",
            "refusing to stage or publish an audit for a finding without a "
            "semantic DRIFT confirmation tied to a BOUND historical protocol "
            "authority (PAL-ARCH-01)",
            next_action="submit a semantic DRIFT verdict for the finding's "
                        "evidence unit; nothing was written",
        )
    body = audits_mod.build_audit_body(finding, record, bundle, registry=registry)
    if not audits_mod.passes_quality_gate(body, finding):
        return
    config_status, config, config_detail = config_mod.load_config(home)
    if config_status == "unrecoverable":
        raise PalError("VALIDATION_FAILED", config_detail)
    mode = (config or {}).get("publication_mode", "STAGE_ONLY")
    delivery = None
    if mode == "PUBLISH_ENABLED":
        try:
            sink_status, sink, sink_detail = configured_sink(home)
            if sink_status != "ok" or sink is None:
                raise PalError("SINK_UNAVAILABLE", sink_detail, next_action="keep audit staged and retry")
            result = sink.publish(finding, body)
            if not sink.verify(result):
                raise PalError("SINK_UNAVAILABLE", "sink write did not verify")
            delivery = publications_mod.PUBLISHED
        except (OSError, PalError) as exc:
            # The audit is never lost to an outage: it stages locally. But local
            # staging is NOT delivery, so the failure is recorded as a durable
            # retryable publication instead of being forgotten the moment the
            # finding reads EMITTED (audit CORE-007).
            result = enqueue_mod.enqueue_audit(home, finding, body, registry=registry, maintainer_root=None)
            delivery = publications_mod.PENDING
            publications_mod.record_pending(
                home,
                finding_id=str(finding.get("finding_id") or ""),
                audit_number=int(result["audit_number"]),
                audit_path=str(result["audit_path"]),
                audit_sha256=str(result["audit_sha256"]),
                reason=str(exc),
                registry=registry,
            )
            from . import log as log_mod
            log_mod.append_event(home, "sink_publish_failure", data={"finding_id": finding.get("finding_id", ""), "reason": str(exc)}, registry=registry)
    else:
        result = enqueue_mod.enqueue_audit(home, finding, body, registry=registry, maintainer_root=None)
    finding["audit"] = {
        "audit_number": result["audit_number"],
        "audit_path": result["audit_path"],
        "audit_sha256": result["audit_sha256"],
        "operation_id": result["operation_id"],
    }
    if delivery is not None:
        # EMITTED means locally staged. Whether the maintainer sink has the file
        # is a separate fact, and a reader must be able to tell them apart.
        finding["audit"]["delivery"] = delivery
    findings_mod.advance_lifecycle(finding, "EMITTED", registry=registry)
    audits_emitted.append(result)

    try:
        from . import closedloop as closedloop_mod

        closedloop_mod.link_finding_audit(home, finding.get("finding_id", ""), result)
    except (OSError, ValueError, UnicodeDecodeError, PalError) as exc:
        from . import log as log_mod

        log_mod.append_event(
            home,
            "closed_loop_link_failure",
            data={
                "finding_id": finding.get("finding_id", ""),
                "audit_number": result.get("audit_number"),
                "audit_path": result.get("audit_path"),
                "reason": str(exc),
            },
            registry=registry,
        )


def candidate_count(home: Path, *, registry: dict | None = None) -> int:
    data = registry if registry is not None else load_registry()
    status, index, _detail = findings_mod.load_index(home, registry=data)
    if status != "ok" or index is None:
        return 0
    return len(index.get("findings") or [])


def findings_report(home: Path, *, registry: dict | None = None) -> list[dict]:
    data = registry if registry is not None else load_registry()
    status, index, _detail = findings_mod.load_index(home, registry=data)
    if status != "ok" or index is None:
        return []
    return [
        {
            "finding_id": r.get("finding_id"),
            "state": r.get("state"),
            "drift_class": r.get("drift_class"),
            "severity": r.get("severity"),
            "confidence": r.get("confidence"),
            "change_target": r.get("change_target"),
            "occurrences": len(r.get("occurrences") or []),
        }
        for r in index.get("findings") or []
    ]
