from __future__ import annotations

from .capability import require_action
from .errors import PalError
from .paths import atomic_write_json, home_paths, read_json
from .registry import load_registry, require_string_list
from . import causal as causal_mod

FINDINGS_INDEX_NAME = "findings/index.json"
#: SUSPECTED is the pre-semantic floor of the lifecycle (PAL-ARCH-01): the
#: state a mechanical detector signal reaches and the state a legacy
#: mechanical-only finding is demoted to. A finding cannot leave SUSPECTED
#: forward without a semantic DRIFT confirmation tied to its evidence.
LIFECYCLE_ORDER = ("SUSPECTED", "OBSERVED", "BOUND", "CHALLENGED", "QUALIFIED", "EMITTED")
TERMINAL = frozenset({"REJECTED", "MERGED", "BLOCKED", "STALE", "EMITTED"})
#: Compatibility alias. The authority is REGISTRY.json `protected_invariants`;
#: this tuple is what a caller with no registry in hand still gets.
PROTECTED = ("destructive_confirmation", "recovery_precedence", "source_closure",
              "verify", "review", "provenance", "cold_continuation")
CORE_PROTOCOL = "CORE_PROTOCOL"
REQUIRED = ("finding_id", "fingerprint", "state", "drift_class", "severity", "confidence",
            "change_target", "rule_ids", "root_cause", "protected_invariants",
            "harm_warnings",
            "occurrences", "protocol_bindings", "alternatives", "mechanical_confidence", "audit")
LIST_FIELDS = ("rule_ids", "protected_invariants", "occurrences", "protocol_bindings", "alternatives")
ENUM_KEYS = ("finding_lifecycle", "drift_taxonomy", "severity_enum", "confidence_enum", "change_target_enum")
ENUM_FIELDS = ("state", "drift_class", "severity", "confidence", "change_target")


def empty_index() -> dict:
    return {"schema_version": 1, "findings": []}


#: The fields a semantic DRIFT confirmation must carry, and what a forged or
#: partial one is checked against. This is the authority boundary made data:
#: only `submit_candidate` writes it, and only after re-deriving the evidence
#: unit from the kernel's own index.
CONFIRMATION_FIELDS = ("receipt_id", "verdict", "session_id", "episode_index", "unit_digest")


def is_semantic_confirmation_tied(
    confirmation: object, session_id: str, episode_index: int, unit_digest: str
) -> bool:
    """Does this confirmation stand on exactly this evidence unit?

    The tie is structural: verdict DRIFT, the named session and episode, and a
    unit digest that is not empty and not a mismatch. A missing or malformed
    field is a different confirmation, not a weaker one.
    """
    if not isinstance(confirmation, dict):
        return False
    for field in CONFIRMATION_FIELDS:
        value = confirmation.get(field)
        if value is None or value == "" or not str(value).strip():
            return False
    if str(confirmation.get("verdict")) != "DRIFT":
        return False
    return (
        str(confirmation.get("session_id")) == str(session_id)
        and int(confirmation.get("episode_index", -1)) == int(episode_index)
        and str(confirmation.get("unit_digest")) == str(unit_digest)
        and bool(str(confirmation.get("unit_digest")).strip())
    )


def _int_or(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _confirmation_binding(confirmation: dict) -> str:
    """The historical authority a confirmation was judged against."""
    binding = confirmation.get("protocol_binding")
    if not isinstance(binding, dict):
        return "UNKNOWN"
    return str(binding.get("binding_status") or "UNKNOWN")


def is_semantically_confirmed(finding: dict) -> bool:
    """Does this finding carry a semantic confirmation tied to its evidence?

    Mechanical confidence, recurrence, severity, protocol binding and lifecycle
    state are all irrelevant here by construction: only the confirmation block
    is consulted, because only it is written by the semantic submission
    boundary (PAL-ANALYSIS-05). A finding without one is a suspicion. The
    confirmation must name a session+episode that is one of this finding's own
    occurrences — so a confirmation of some other unit cannot confirm this one
    — and it must have been judged against a BOUND historical protocol
    authority: a drift claim without a verifiable governing protocol is not a
    drift claim (PAL-ARCH-01).
    """
    confirmation = finding.get("semantic_confirmation")
    if not isinstance(confirmation, dict):
        return False
    if str(confirmation.get("verdict") or "") != "DRIFT":
        return False
    for field in CONFIRMATION_FIELDS:
        value = confirmation.get(field)
        if value is None or value == "" or not str(value).strip():
            return False
    if _confirmation_binding(confirmation) != "BOUND":
        return False
    occurrences = finding.get("occurrences") or []
    if not occurrences:
        return False
    for occurrence in occurrences:
        if str(occurrence.get("session_id") or "") == str(confirmation.get("session_id")) and (
            _int_or(occurrence.get("episode_id"), -1)
            == _int_or(confirmation.get("episode_index"), -2)
        ):
            return True
    return False


def migrate_index(home, *, registry=None) -> dict:
    """Demote every mechanical-only finding to SUSPECTED. Deterministic, idempotent.

    Findings that reached QUALIFIED/EMITTED through the old mechanical pipeline
    carry no semantic confirmation, so under the authority boundary they must
    never qualify externally until a real semantic review occurs. They are not
    deleted: every field, occurrence and audit reference is preserved, the
    original state is recorded on the finding, and the state becomes SUSPECTED --
    the pre-semantic floor of the lifecycle.
    """
    status, index, detail = load_index(home, registry=registry)
    if status == "unrecoverable":
        raise PalError("VALIDATION_FAILED", detail)
    if index is None:
        return {"migrated": 0, "already_migrated": 0, "total": 0}
    migrated = 0
    already = 0
    for finding in index.get("findings") or []:
        if finding.get("state") == "SUSPECTED":
            already += 1
            continue
        if is_semantically_confirmed(finding):
            continue
        finding["pre_semantic_migration"] = {
            "from_state": finding.get("state"),
            "reason": "mechanical-only finding predates the semantic authority "
                      "boundary; requires a semantic DRIFT confirmation before it "
                      "may qualify externally (PAL-ARCH-01)",
        }
        finding["state"] = "SUSPECTED"
        migrated += 1
    if migrated:
        save_index(home, index, registry=registry)
    return {"migrated": migrated, "already_migrated": already, "total": len(index.get("findings") or [])}


def _enums(registry):
    d = registry if registry is not None else load_registry()
    return tuple(frozenset(require_string_list(d, k)) for k in ENUM_KEYS)


def validate_index(payload, *, registry=None):
    life, drift, sev, conf, tgt = _enums(registry)
    if not isinstance(payload, dict):
        return ["findings index root is not an object"]
    p = []
    if payload.get("schema_version") != 1:
        p.append(f"schema_version {payload.get('schema_version')!r} != 1")
    if not isinstance(payload.get("findings"), list):
        return p + ["findings must be an array"]
    seen_i, seen_f = set(), set()
    for i, r in enumerate(payload["findings"]):
        w = f"findings[{i}]"
        if not isinstance(r, dict):
            p.append(f"{w} is not an object"); continue
        for f in REQUIRED:
            if f not in r: p.append(f"{w} missing {f!r}")
        fid, fp = r.get("finding_id"), r.get("fingerprint")
        if isinstance(fid, str) and fid in seen_i:
            p.append(f"{w} duplicate finding_id {fid!r}")
        if isinstance(fid, str):
            seen_i.add(fid)
        if isinstance(fp, str) and fp in seen_f:
            p.append(f"{w} duplicate fingerprint {fp!r}")
        if isinstance(fp, str):
            seen_f.add(fp)
        for fld, allowed in zip(ENUM_FIELDS, (life, drift, sev, conf, tgt)):
            v = r.get(fld)
            if v not in allowed: p.append(f"{w}.{fld} {v!r} outside {sorted(allowed)}")
        for lf in LIST_FIELDS:
            if not isinstance(r.get(lf), list): p.append(f"{w}.{lf} must be an array")
        a = r.get("audit")
        if a is not None and not isinstance(a, dict): p.append(f"{w}.audit must be an object or null")
        h = r.get("historical_rule_surface")
        if h is not None and not isinstance(h, dict):
            p.append(f"{w}.historical_rule_surface must be an object or null")
    return p


def load_index(home, *, registry=None):
    p = home_paths(home)
    if not p.findings_index.exists():
        return "absent", None, ""
    try:
        payload = read_json(p.findings_index)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return "unrecoverable", None, f"findings index is unreadable: {exc}"
    probs = validate_index(payload, registry=registry)
    return ("unrecoverable", None, "; ".join(probs)) if probs else ("ok", payload, "")


def save_index(home, index, *, registry=None):
    require_action("write_own_index", registry=registry)
    probs = validate_index(index, registry=registry)
    if probs:
        raise PalError("VALIDATION_FAILED",
                       "refusing to write an invalid findings index: " + "; ".join(probs),
                       next_action="the existing index was left untouched")
    p = home_paths(home)
    atomic_write_json(p.findings_index, index, root=p.root)
    return index


def _causal(c):
    """Deprecated: the raw-prose causal slice. Kept only so an old index that was
    written with it can still be read; identity now comes from `causal.py`."""
    rc = c.get("root_cause")
    if isinstance(rc, str) and rc.strip():
        return rc.strip().lower()[:120]
    obs = c.get("observed") or {}
    if isinstance(obs, dict):
        s = obs.get("summary") or obs.get("raw") or ""
        if isinstance(s, str): return s.strip().lower()[:120]
    return ""

def fingerprint_of(candidate):
    """Identity by normalized causal mechanism (PAL-ROOTCAUSE-01).

    Wording must not decide identity: two analysts describing one defect
    differently are describing one defect. `causal.fingerprint` normalizes the
    description before hashing it.
    """
    from . import causal

    return causal.fingerprint(candidate)


def next_finding_id(index):
    hi = 0
    for r in index.get("findings", []):
        fid = r.get("finding_id", "")
        if isinstance(fid, str) and fid.startswith("PAL-") and fid[4:].isdigit():
            hi = max(hi, int(fid[4:]))
    return f"PAL-{hi + 1:04d}"


def _occ(candidate, session_record):
    return {"session_id": session_record.get("session_id"),
            "episode_id": candidate.get("episode_id"),
            "event_refs": candidate.get("event_refs", [])}


def _occ_key(o):
    return (o.get("session_id"), o.get("episode_id"), str(o.get("event_refs") or ""))


def _attach_analyst_work(candidate: dict, rec: dict) -> None:
    """Record the analyst's judgment on a finding it confirmed.

    The analyst does not mint a second finding for an episode the mechanical
    pass already raised; its verdict, challenge and disposition are work
    product that belongs ON that finding (PAL-ANALYSIS-05). A confirmation
    judged against final evidence also releases any PROVISIONAL hold, exactly
    as a fingerprint merge would.
    """
    for optional in ("challenge", "disposition_class", "analyst_reasoning",
                     "episode_finality", "recurrence_spread"):
        value = candidate.get(optional)
        if value:
            rec[optional] = value
    if candidate.get("episode_finality") == "FINAL":
        rec["episode_finality"] = "FINAL"
        rec.pop("provisional_hold", None)


def _occurrence_matches(rec: dict, occ: dict) -> bool:
    """Does this finding stand on the same session episode this candidate cites?

    Session and episode ids must agree, and event references must overlap when
    both sides name events: a candidate citing the episode alone must not merge
    into a finding about a different event inside it.
    """
    cand_refs = {int(r) for r in (occ.get("event_refs") or [])}
    for row in rec.get("occurrences") or []:
        if row.get("session_id") != occ.get("session_id"):
            continue
        if row.get("episode_id") != occ.get("episode_id"):
            continue
        row_refs = {int(r) for r in (row.get("event_refs") or [])}
        if not cand_refs or not row_refs or cand_refs & row_refs:
            return True
    return False


def find_or_create(index, candidate, session_record):
    target = fingerprint_of(candidate)
    occ = _occ(candidate, session_record)
    # A mechanical candidate is a SIGNAL: it may merge onto an existing finding
    # as a supporting occurrence, but it can never create a finding -- only a
    # semantic DRIFT submission can open the finding lifecycle (PAL-ARCH-01).
    for rec in index.get("findings", []):
        if rec.get("fingerprint") == target:
            keys = {_occ_key(o) for o in rec.get("occurrences", [])}
            if _occ_key(occ) not in keys:
                rec.setdefault("occurrences", []).append(occ)
            cand_m = candidate.get("mechanical_confidence")
            if cand_m in ("HIGH", "MEDIUM", "LOW"):
                existing_m = rec.get("mechanical_confidence")
                rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
                # Mechanical proof is cumulative: a merge that would weaken it
                # (an analyst confirmation always carries LOW) must not erase
                # the detector's HIGH.
                if rank[cand_m] >= rank.get(existing_m, -1):
                    rec["mechanical_confidence"] = cand_m
            surface = candidate.get("historical_rule_surface")
            if rec.get("historical_rule_surface") is None and surface is not None:
                rec["historical_rule_surface"] = surface
            elif (
                isinstance(surface, dict)
                and surface.get("status") == "RESOLVED"
                and (rec.get("historical_rule_surface") or {}).get("status") != "RESOLVED"
            ):
                rec["historical_rule_surface"] = surface
            _attach_analyst_work(candidate, rec)
            # Only a confirmation tied to this evidence unit AND judged against
            # a BOUND historical authority lifts a finding out of SUSPECTED: a
            # mechanical merge is a signal, not a verdict. A confirmed re-merge
            # folds an open finding back to OBSERVED so the submission boundary
            # re-runs the gates on the new disposition.
            confirmation = candidate.get("semantic_confirmation")
            if (
                is_semantic_confirmation_tied(
                    confirmation,
                    occ.get("session_id"),
                    _int_or(occ.get("episode_id"), -1),
                    str((confirmation or {}).get("unit_digest") or ""),
                )
                and _confirmation_binding(confirmation or {}) == "BOUND"
            ):
                rec["semantic_confirmation"] = confirmation
                if rec.get("state") in ("SUSPECTED", "BOUND", "CHALLENGED", "QUALIFIED"):
                    rec["state"] = "OBSERVED"
            return rec

    # An analyst confirmation is a merge, never a re-raise. The deterministic
    # pass runs before the analyst, so the episode being judged usually already
    # stands on a mechanical finding (the carrier's `open_candidates` says so).
    # The fingerprints will not agree -- template prose and analyst prose are
    # different descriptions of one mechanism -- so identity falls back to the
    # shared anchor: same session, same episode, same drift class, same event.
    # Without this fallback every confirmation minted a second finding for the
    # same event (PAL-ANALYSIS-01: "the analyst does not re-raise them").
    if str(candidate.get("detector") or "") == "analyst":
        for rec in index.get("findings", []):
            if str(rec.get("drift_class") or "") != str(candidate.get("drift_class") or ""):
                continue
            if not _occurrence_matches(rec, occ):
                continue
            _attach_analyst_work(candidate, rec)
            # The confirmation is tied to the evidence unit it judged and
            # recorded on the finding it stood on: this is the write that
            # makes `is_semantically_confirmed` true. Only a BOUND-backed
            # confirmation counts as one.
            confirmation = candidate.get("semantic_confirmation")
            if (
                is_semantic_confirmation_tied(
                    confirmation,
                    occ.get("session_id"),
                    _int_or(occ.get("episode_id"), -1),
                    str((confirmation or {}).get("unit_digest") or ""),
                )
                and _confirmation_binding(confirmation or {}) == "BOUND"
            ):
                rec["semantic_confirmation"] = confirmation
            if rec.get("state") in TERMINAL:
                # The finding already left the pipeline (an audit was emitted, a
                # block or a rejection was recorded): record the confirmation,
                # never re-emit and never re-advance.
                return rec
            keys = {_occ_key(o) for o in rec.get("occurrences", [])}
            if _occ_key(occ) not in keys:
                rec.setdefault("occurrences", []).append(occ)
            # Fold back to OBSERVED so the submission boundary re-runs the
            # gates (do-no-harm, qualification) on the analyst's disposition.
            rec["state"] = "OBSERVED"
            rec.pop("harm_blocks", None)
            return rec
    if str(candidate.get("detector") or "") != "analyst":
        # A mechanical candidate names no finding of its own: it is a signal
        # for the semantic carrier, not a finding (PAL-ARCH-01).
        return None
    finding = {"finding_id": next_finding_id(index), "fingerprint": target, "state": "OBSERVED",
               "causal_key": causal_mod.causal_key(candidate),
               "drift_class": candidate.get("drift_class"), "severity": candidate.get("severity", "P3"),
               "confidence": candidate.get("confidence", "LOW"),
               "change_target": candidate.get("change_target", "UNKNOWN"),
               "rule_ids": list(candidate.get("rule_ids") or []),
               "root_cause": candidate.get("root_cause") or "",
               "protected_invariants": list(candidate.get("protected_invariants") or []),
               "harm_warnings": list(candidate.get("harm_warnings") or []),
               "occurrences": [occ],
               "protocol_bindings": list(candidate.get("protocol_bindings") or []),
               "alternatives": list(candidate.get("alternatives") or []),
               "mechanical_confidence": candidate.get("mechanical_confidence", "LOW"),
               "historical_rule_surface": candidate.get("historical_rule_surface"),
               "audit": None}
    # An analyst-submitted candidate arrives with its own challenge, disposition
    # and reasoning. Those are the analyst's work product, so they are recorded
    # on the finding rather than regenerated from a template. The semantic
    # confirmation travels with it: this is the only path that creates a
    # confirmed finding (PAL-ARCH-01).
    for optional in ("challenge", "disposition_class", "analyst_reasoning",
                     "episode_finality", "recurrence_spread",
                     "semantic_confirmation"):
        if candidate.get(optional):
            finding[optional] = candidate[optional]
    index.setdefault("findings", []).append(finding)
    return finding


def advance_lifecycle(finding, target, *, registry=None):
    """Move a finding one step forward through the lifecycle.

    Leaving SUSPECTED for a post-semantic state requires the semantic
    confirmation invariant: SUSPECTED is where mechanical signals and demoted
    legacy findings live, and only a semantic DRIFT confirmation may carry a
    finding out of it (PAL-ARCH-01).
    """
    life, *_ = _enums(registry)
    if target not in life:
        raise PalError("VALIDATION_FAILED", f"unknown lifecycle state {target!r}")
    c = finding.get("state")
    if c == target:
        return
    if target in TERMINAL:
        finding["state"] = target; return
    try:
        ci, ti = LIFECYCLE_ORDER.index(c), LIFECYCLE_ORDER.index(target)
    except ValueError as e:
        raise PalError("VALIDATION_FAILED", f"lifecycle {c!r}/{target!r} not ordered") from e
    if ti < ci:
        raise PalError("VALIDATION_FAILED",
                       f"lifecycle cannot go backward from {c!r} to {target!r}",
                       next_action="use REJECTED/MERGED/BLOCKED/STALE to leave the pipeline")
    if c == "SUSPECTED" and not is_semantically_confirmed(finding):
        raise PalError(
            "VALIDATION_FAILED",
            "a finding without semantic confirmation cannot leave SUSPECTED",
            next_action="submit a semantic DRIFT verdict for its evidence unit",
        )
    finding["state"] = target


def prosecutor_defender_pass(finding, bundle, session_record):
    if finding.get("severity") not in ("P0", "P1") and finding.get("change_target") != CORE_PROTOCOL:
        return finding
    if isinstance(finding.get("challenge"), dict) and finding["challenge"].get("decided"):
        # A real analyst challenge already argued both passes. Overwriting it
        # with the mechanical template would discard the actual reasoning and
        # replace it with an assertion that the template always wins.
        return finding
    finding["challenge"] = {
        "pass_a": f"observed {finding.get('drift_class')!r} violates {finding.get('rule_ids')}: "
                  f"{finding.get('root_cause')}; bundle evidence matches.",
        "pass_b": f"{finding.get('drift_class')!r} may be adapter noise, missing owner doc, "
                  "override or env failure; protocol has not necessarily drifted.",
        "decided": "pass_a",
        "loser_rejection": "pass_b rejected: CORE_PROTOCOL/P0-P1 carries executable evidence "
                          "an alternative cannot neutralize.",
        "session_id": session_record.get("session_id") if isinstance(session_record, dict) else None,
        "bundle_sha256": bundle.get("bundle_sha256") if isinstance(bundle, dict) else None,
    }
    return finding


def do_no_harm_gate(finding, *, registry=None):
    """Warnings the maintainer must see (PAL-DONOHARM-01).

    Delegates the structural question to `donoharm.assess`: which protected
    invariants does the proposed change surface actually govern? The blocking
    half of that assessment is applied by the lifecycle, not here, so this
    function keeps its historical shape -- a list of warnings.
    """
    from . import donoharm

    return donoharm.assess(finding, registry=registry)["warnings"]


def harm_blocks(finding, *, registry=None):
    """Reasons this finding must NOT qualify: a protected invariant, undeclared,
    from a disposition that does not even blame the protocol."""
    from . import donoharm

    return donoharm.assess(finding, registry=registry)["blocks"]


def qualification_threshold(finding, *, registry=None):
    """Can this finding qualify for an external audit?

    The semantic-confirmation invariant comes first and is absolute: no
    semantic DRIFT confirmation tied to this finding's evidence, no
    qualification -- whatever the mechanical confidence, severity, recurrence,
    binding or current lifecycle state (PAL-ARCH-01). The binding that counts
    is the one the CONFIRMATION was judged against, kernel-derived at
    submission: an unrelated BOUND occurrence cannot legitimize a confirmation
    made against a PARTIAL unit, and several weak bindings do not establish
    which protocol rule governed the evidence.
    """
    if not is_semantically_confirmed(finding):
        return False
    state = finding.get("state")
    if state not in ("CHALLENGED", "QUALIFIED"):
        return False
    if state == "CHALLENGED" and finding.get("challenge") is None:
        return False
    if finding.get("audit") is not None or finding.get("confidence") != "HIGH":
        return False
    confirmation = finding.get("semantic_confirmation") or {}
    bind_status = _confirmation_binding(confirmation)
    if bind_status != "BOUND":
        return False
    sev = finding.get("severity")
    if sev in ("P0", "P1") or finding.get("change_target") == CORE_PROTOCOL:
        return True
    if sev == "P2":
        return len(finding.get("occurrences") or []) >= 2
    # Route C: a confirmed finding with mechanical proof behind it qualifies
    # even at P3 -- the semantic verdict owns the truth, the mechanical proof
    # only sharpens it. Absent that proof, a LOW one-off stays internal.
    return finding.get("mechanical_confidence") == "HIGH"


def _rank(state):
    try:
        return LIFECYCLE_ORDER.index(state)
    except ValueError:
        return -1


def merge_candidates(index, candidates, session_record):
    """Fold candidates into the findings index.

    A mechanical candidate is recorded as a signal and never produces a row
    here: `find_or_create` returns None for it, because only a semantic DRIFT
    submission may create a finding (PAL-ARCH-01). An analyst confirmation
    either merges onto the finding it stood on or creates that finding.
    """
    before = {r.get("fingerprint"): r.get("state") for r in index.get("findings", [])}
    out = []
    for cand in candidates:
        if not isinstance(cand, dict):
            continue
        finding = find_or_create(index, cand, session_record)
        if finding is None:
            continue
        fp, after = finding.get("fingerprint"), finding.get("state")
        if before.get(fp) is None:
            if after == "OBSERVED":
                out.append(finding)
        elif _rank(after) > _rank(before[fp]):
            out.append(finding)
        elif str(cand.get("detector") or "") == "analyst":
            # An analyst confirmation is answered with the finding it stood on:
            # a fold-back of an open finding (regressed to OBSERVED so the gates
            # re-run on the analyst's disposition) or a terminal finding that
            # already left the pipeline. Either way the receipt must name the
            # finding; the caller re-advances open findings and leaves terminal
            # ones be.
            out.append(finding)
        before[fp] = after
    return out