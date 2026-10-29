"""`saipal analyst-doctor` -- read-only diagnosis of the analyst runtime.

The doctor never mutates the home, never makes a network call, never spends
tokens and never prints or stores the API key VALUE. It reports the presence of
the environment variable named by the config, which is a fact about the
operator's machine, not a credential.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from saipal_engine.paths import home_paths
from saipal_engine.registry import load_registry
from saipal_engine.sessions import STATUS_UNRECOVERABLE, load_index
from saipal_engine import coverage as coverage_mod

from .config import (
    ANALYST_CONFIG_NAME,
    analyst_config_path,
    credential_verdict,
    endpoint_is_local,
    egress_verdict,
    load_analyst_config,
)


def doctor_report(home: Path | str, *, registry: dict | None = None) -> dict:
    """A truthful, read-only snapshot of analyst readiness."""
    data = registry if registry is not None else load_registry()
    root = Path(home)
    report: dict = {
        "analyst_doctor": True,
        "config_file": ANALYST_CONFIG_NAME,
        "config_present": False,
        "config_valid": False,
        "config_problems": [],
        "enabled": False,
        "backend_type": None,
        "endpoint": None,
        "endpoint_local": None,
        "remote_evidence_allowed": None,
        "egress_ok": None,
        "api_key_env": None,
        "api_key_env_present": None,
        "model": None,
        "budgets": None,
        "journal_present": False,
        "worker_lock_present": False,
        "worker_active": False,
        "semantic": {},
        "ok": False,
    }

    status, config, detail = load_analyst_config(root)
    if status == "absent":
        report["config_problems"] = [f"{ANALYST_CONFIG_NAME} is absent"]
        return report
    if status == "unrecoverable":
        report["config_present"] = True
        report["config_problems"] = [detail]
        return report

    report["config_present"] = True
    report["config_valid"] = True
    report["enabled"] = bool(config.get("enabled"))
    backend = config.get("backend") or {}
    report["backend_type"] = backend.get("type")
    endpoint = backend.get("endpoint")
    report["endpoint"] = endpoint
    report["endpoint_local"] = endpoint_is_local(endpoint) if endpoint else None
    egress_allowed, egress_detail = egress_verdict(config)
    report["egress_ok"] = egress_allowed
    if not egress_allowed:
        report["config_problems"].append(egress_detail)
    report["remote_evidence_allowed"] = bool(
        (config.get("egress") or {}).get("allow_remote_evidence")
    )
    api_key_env = backend.get("api_key_env")
    report["api_key_env"] = api_key_env
    report["api_key_env_present"] = bool(api_key_env and os.environ.get(api_key_env))
    report["model"] = backend.get("model")
    report["budgets"] = config.get("budgets")

    credential_ok, credential_detail = credential_verdict(config)
    if report["enabled"]:
        if not credential_ok:
            # Only a backend that must SEND its credential is broken without it.
            # On a loopback endpoint the requirement is inert, and flagging it
            # would report a healthy local analyst as unusable -- the same
            # disagreement that once left a keyless local model unable to run.
            report["config_problems"].append(credential_detail)
        if not report["egress_ok"]:
            pass  # already reported with endpoint and flag
        if not report["model"]:
            report["config_problems"].append("backend.model is not configured")

    analyst_dir = home_paths(root).root / "analyst"
    journal = analyst_dir / "jobs.json"
    report["journal_present"] = journal.is_file()
    lock = home_paths(root).locks / "analyst-worker.lock"
    report["worker_lock_present"] = lock.is_file()
    report["worker_active"] = _lock_holder_alive(lock)

    report["semantic"] = _semantic_snapshot(root, data)
    report["blocked"] = blocked_triage(root, registry=data)
    report["ok"] = not report["config_problems"]
    return report


def _lock_holder_alive(lock: Path) -> bool:
    """Is there a live worker holding the lock? Read-only: never acquires."""
    if not lock.is_file():
        return False
    try:
        from saipal_engine.paths import _pid_alive

        payload = json.loads(lock.read_text(encoding="utf-8"))
        pid = int(payload.get("pid") or 0)
        return pid > 0 and _pid_alive(pid)
    except (ValueError, OSError, TypeError):
        return True  # unparseable lock: treat as held, never break it silently


def _semantic_snapshot(root: Path, registry: dict) -> dict:
    """Pending counts from the canonical index. Read-only."""
    status, index, _detail = load_index(root, registry=registry)
    snapshot: dict = {}
    if status == STATUS_UNRECOVERABLE or index is None:
        snapshot["index"] = "unavailable"
        return snapshot
    totals = coverage_mod.coverage(root, index, registry=registry)
    snapshot["episodes_total"] = totals["episodes_total"]
    snapshot["episodes_pending"] = totals["episodes_pending"]
    snapshot["slices_pending"] = totals["slices_pending"]
    snapshot["receipts_total"] = totals["receipts_total"]
    return snapshot


#: What each analyst-side wall MEANS and the cheapest CANONICAL action for it.
#: `command` is a command that exists in this protocol, or None when none does --
#: naming that gap is the point. Journal surgery is not an action: the rebind
#: contract exists precisely so a blocked unit is woken by evidence, never by hand.
BLOCKED_ACTIONS: dict[str, dict] = {
    "BLOCKED_BINDING": {
        "meaning": (
            "historical protocol binding is insufficient (UNKNOWN/PARTIAL): there "
            "is no rule authority to compare the session's behaviour against"
        ),
        "action": "plan the blockers, then enrol authority and rebind",
        "command": "python -B tools/saipal.py coverage",
        "then": (
            "python -B tools/saipal.py authority enroll --release-root PATH; "
            "python -B tools/saipal.py rebind --dry-run"
        ),
        "recoverable": True,
        "caveat": (
            "enrolling a release root verifies a version claim only through a "
            "registry digest, and a git root only through a full commit id. Read "
            "binding_evidence before running it: authority_verifiable units move "
            "under an enrollment, and evidence_absent units carry only a bare "
            "version string or no protocol claim at all, so no authority root can "
            "ever change their verdict -- re-running the slice is the one action "
            "that cannot work"
        ),
    },
    "PROVISIONAL_DISABLED": {
        "meaning": (
            "the only pending work is a HOT provisional episode, and provisional "
            "investigation is off"
        ),
        "action": "investigate with provisional work enabled -- still bounded",
        "command": (
            "python -B tools/saipal.py investigate --with-provisional --max-units N"
        ),
        "then": None,
        "recoverable": True,
    },
    "BLOCKED_OUTPUT": {
        "meaning": (
            "the unit's attempt was REFUSED and journaled: the candidate contract "
            "rejected the model's output (invalid JSON, or fields the schema does "
            "not own), the transport retry budget ran out, or the backend errored "
            "in a way no retry inside the run could settle"
        ),
        "action": "requeue the refused unit for ONE fresh attempt",
        "command": "python -B tools/saipal.py analyst-requeue --dry-run",
        "then": "python -B tools/saipal.py analyst-requeue --reason 'why now'",
        "recoverable": True,
        "caveat": (
            "a requeue does not repair the model. It is admitted only when the "
            "analyst config (endpoint/model/budgets) changed since the last "
            "attempt, or with an explicit --force, and it is budgeted by "
            "budgets.max_requeues_per_unit"
        ),
    },
}


def _authority_verifiable(protocol: object) -> bool:
    """Can enrolling an authority root PROVE anything about this session?

    PAL-CPALL-04's rule: a refusal must name WHICH decision makes the unit
    eligible again, and re-running the slice is the one action that cannot
    work. `authority enroll --release-root` verifies a version claim by
    digest; a version WITHOUT a digest, a proof level with nothing under it,
    or no protocol claim at all has no artifact for any authority root to
    check -- so for those sessions the recommended command is a dead end and
    saying so is the honest answer.
    """
    from saipal_engine import sessions as sessions_mod

    if not isinstance(protocol, dict):
        return False
    if str(protocol.get("git_head") or "").strip():
        return True
    if sessions_mod._SHA256.fullmatch(str(protocol.get("registry_sha256") or "")):
        return True
    if sessions_mod._SHA256.fullmatch(str(protocol.get("tree_fingerprint") or "")):
        return True
    return False


def _binding_evidence_split(journal: dict, records: list) -> dict:
    """Which half of BLOCKED_BINDING an authority enrollment can actually move."""
    # A refused job carries no protocol block of its own, so each is classified
    # through its session's record in the index.
    by_session = {str(r.get("session_id") or ""): r for r in records}
    verifiable = 0
    evidence_absent = 0
    for job in (journal.get("jobs") or {}).values():
        if str(job.get("stage")) != "BLOCKED_BINDING":
            continue
        record = by_session.get(str(job.get("session_id") or ""))
        protocol = (record or {}).get("protocol")
        if _authority_verifiable(protocol):
            verifiable += 1
        else:
            evidence_absent += 1
    return {
        "authority_verifiable": verifiable,
        "evidence_absent": evidence_absent,
        "note": (
            "authority_verifiable sessions carry a commit, registry digest or "
            "tree fingerprint an enrolled authority root can actually check; "
            "evidence_absent sessions carry only a version string or no claim "
            "at all, so enrolling a root cannot change their verdict"
        ),
    }


def _provisional_admission(split: dict[str, int]) -> dict[str, object]:
    """T-158: how much of PROVISIONAL_DISABLED `--with-provisional` can serve.

    The allocator decides this class BEFORE the terminal-job check and before the
    binding guard, so switching the flag on reclassifies its members rather than
    releasing them. Publishing the flag for a population none of it can serve is
    the dead end T-145 removed for BLOCKED_BINDING: the command runs, admits
    nothing, and reads like progress.
    """
    admitted = int(split.get("RUNNABLE_PROVISIONAL", 0))
    elsewhere = {
        klass: int(count)
        for klass, count in sorted(split.items())
        if klass != "RUNNABLE_PROVISIONAL"
    }
    out: dict[str, object] = {
        "provisional_admission": admitted,
        "not_admitted": elsewhere,
    }
    detail = ", ".join(f"{count} {klass}" for klass, count in elsewhere.items())
    if admitted:
        out["caveat"] = (
            f"--with-provisional admits {admitted} of these unit(s); the other "
            f"{sum(elsewhere.values())} reclassify once the flag is on "
            f"({detail or 'none'}) and are NOT moved by it"
        )
        return out
    out.update(
        {
            "command": None,
            "then": None,
            "action": "no command moves these units",
            "recoverable": False,
            "caveat": (
                "enabling provisional investigation does not admit this population: "
                f"with the flag on every unit reclassifies ({detail or 'none'}). They "
                "are held by a terminal journal job or by insufficient binding, and "
                "no provisional setting changes either"
            ),
        }
    )
    return out


def blocked_triage(home: Path | str, *, registry: dict | None = None) -> dict:
    """Read-only: which class of session the analyst cannot analyse, and why.

    The ALLOCATOR's own classifier decides the classes -- the same function
    `investigate` calls. `investigate` runs it with a provisional flag this
    triage does not, so a class whose recovery command IS that flag is
    re-classified under it here (T-158): the count alone is not a route, and
    naming a route for a population none of it can serve is what this second
    pass exists to prevent. Model-free, write-free, no network.

    The kernel's `episodes_pending` counts episodes without a receipt; it does not
    say whether any of them is ANALYZABLE. On a home whose semantic side looks
    stuck, those are two very different numbers, and this is the second one.
    """
    from time import time

    from saipal_engine import carrier as carrier_mod

    from . import jobs as jobs_mod
    from . import worker as worker_mod

    root = Path(home)
    data = registry if registry is not None else load_registry()
    triage: dict = {
        "population": 0,
        "runnable": 0,
        "blocked_total": 0,
        "groups": [],
        "no_canonical_action": [],
        "next_action": None,
    }
    status, index, _detail = load_index(root, registry=data)
    if status == STATUS_UNRECOVERABLE or index is None:
        triage["index"] = "unavailable"
        return triage

    journal = jobs_mod.load_journal(root)
    records = list(carrier_mod.freshest_records(index))
    event_limit = int(carrier_mod._limits(data)["max_events"])
    now = time()
    classes: dict[str, int] = {}
    provisional_split: dict[str, int] = {}
    for record in records:
        klass = worker_mod._classify_unit(record, event_limit, journal, False, now)
        classes[klass] = classes.get(klass, 0) + 1
        # T-158: the class is DECIDED before the binding guard, so the only
        # honest question about a unit in it is what the command the doctor
        # names for it actually classifies as once the flag is on. Counting
        # that here is the difference between a class and a caveat. Only the
        # class's OWN members are counted: the split partitions the class it
        # qualifies, not the whole home.
        if klass == "PROVISIONAL_DISABLED":
            with_flag = worker_mod._classify_unit(record, event_limit, journal, True, now)
            provisional_split[with_flag] = provisional_split.get(with_flag, 0) + 1

    stages: dict[str, int] = {}
    for job in (journal.get("jobs") or {}).values():
        stage = str(job.get("stage"))
        stages[stage] = stages.get(stage, 0) + 1

    triage["population"] = len(records)
    triage["runnable"] = classes.get("RUNNABLE_FINAL", 0) + classes.get(
        "RUNNABLE_PROVISIONAL", 0
    )
    triage["classes"] = dict(sorted(classes.items(), key=lambda item: (-item[1], item[0])))

    # The two halves of the binding wall are disjoint by construction: a session
    # whose cursor unit already holds a terminal journal job classifies TERMINAL,
    # not BLOCKED_BINDING. So refused units plus not-yet-attempted unbound
    # sessions is the whole population, never a double count.
    counts = {
        "BLOCKED_BINDING": int(stages.get("BLOCKED_BINDING", 0))
        + int(classes.get("BLOCKED_BINDING", 0)),
        "PROVISIONAL_DISABLED": int(classes.get("PROVISIONAL_DISABLED", 0)),
        "BLOCKED_OUTPUT": int(stages.get("BLOCKED", 0)),
    }
    groups = []
    for klass, meta in BLOCKED_ACTIONS.items():
        count = counts.get(klass, 0)
        if count <= 0:
            continue
        group = {"class": klass, "count": count}
        group.update(meta)
        if klass == "BLOCKED_BINDING":
            group["binding_evidence"] = _binding_evidence_split(journal, records)
        if klass == "PROVISIONAL_DISABLED":
            group.update(_provisional_admission(provisional_split))
        groups.append(group)
    # T-136: the refused class now HAS a canonical path back, so the triage
    # reports whether that path is actually open right now (an unchanged config
    # or a spent allowance refuses it) instead of leaving the operator to guess.
    if any(group["class"] == "BLOCKED_OUTPUT" for group in groups):
        from . import requeue as requeue_mod

        state = requeue_mod.requeue_status(root, registry=data, journal=journal)
        for group in groups:
            if group["class"] != "BLOCKED_OUTPUT":
                continue
            group["requeue_ready"] = state["requeue_ready"]
            group["requeue_refused"] = state["requeue_refused"]
            group["max_requeues_per_unit"] = state["max_requeues_per_unit"]
            # The label names the STAGE; the classes say what actually happened.
            # A single class name over 8 refusals would be a claim the journal
            # does not support (measured: 4 candidate refusals, 3 exhausted
            # transport retries, 1 historical credential refusal).
            group["refusal_classes"] = state["blocked_by_class"]
    groups.sort(key=lambda group: (-int(group["count"]), str(group["class"])))
    triage["groups"] = groups
    triage["blocked_total"] = sum(int(group["count"]) for group in groups)
    triage["no_canonical_action"] = [
        group["class"] for group in groups if not group.get("command")
    ]
    actionable = [group for group in groups if group.get("command")]
    if actionable:
        biggest = actionable[0]
        triage["next_action"] = (
            f"{biggest['count']} {biggest['class']} unit(s): {biggest['command']}"
        )
    elif groups:
        triage["next_action"] = (
            "nothing canonical remains to run: "
            + ", ".join(triage["no_canonical_action"])
        )
    elif triage["runnable"]:
        triage["next_action"] = "runnable work exists; run the analyst worker"
    else:
        triage["next_action"] = "no blocked population: nothing to unblock"
    return triage
