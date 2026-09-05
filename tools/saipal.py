#!/usr/bin/env python
"""saipal -- the forensic protocol observer CLI.

Operator surface: `continue` (alias `cc`), read-only inspection, setup,
disposition intake and triggering.

Exit codes: 0 success, 1 refused, 2 usage, 3 no SAIPAL home.

Read-only commands must not dirty the checkout merely by importing their
implementation, so bytecode writing is disabled before the engine is imported.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import json  # noqa: E402
import os  # noqa: E402

from saipal_engine.commands import (  # noqa: E402
    Options,
    available_commands,
    parse_args,
    refusal_payload,
    usage_text,
)
from saipal_engine.errors import PalError  # noqa: E402
from saipal_engine.home import ensure_home  # noqa: E402
from saipal_engine.inbox import import_inbox  # noqa: E402
from saipal_engine.dispatcher import dispatch_sources  # noqa: E402
from saipal_engine.config import load_config, save_config, default_config  # noqa: E402
from saipal_engine.sink import configured_sink  # noqa: E402
from saipal_engine.closedloop import import_disposition_file  # noqa: E402
from saipal_engine.log import append_event, log_stats  # noqa: E402
from saipal_engine.sessions import (  # noqa: E402
    STATUS_UNRECOVERABLE as INDEX_UNRECOVERABLE,
)
from saipal_engine.sessions import load_index  # noqa: E402
from saipal_engine.paths import (  # noqa: E402
    HOME_DIRNAME,
    HomeLock,
    home_paths,
    resolve_home,
    resolve_tool_root,
    sha256_text,
    utc_now_iso,
)
from saipal_engine.registry import load_registry, require_string_list  # noqa: E402
from saipal_engine.sources import (  # noqa: E402
    SOURCES_UNRECOVERABLE,
    discover,
    load_sources,
)
from saipal_engine.state import (  # noqa: E402
    STATE_ABSENT,
    STATE_UNRECOVERABLE,
    fresh_state,
    load_state,
    save_state,
)

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
EXIT_NO_HOME = 3

READ_ONLY_COMMANDS = ("status", "next", "doctor", "report")
READ_ONLY_WITH_ARGS = ("sessions", "evidence")


def version_text() -> str:
    version_file = resolve_tool_root() / "VERSION"
    try:
        return version_file.read_text(encoding="utf-8").strip()
    except OSError:
        return "0.0.0-unknown"


# --------------------------------------------------------------------------- #
# continue
# --------------------------------------------------------------------------- #


def _claim_trigger(home: Path) -> bool:
    """Take ownership of the pending run request, if there is one.

    The token is renamed rather than read: a rename is atomic, so two cycles
    cannot both claim one trigger, and a trigger written after this instant stays
    pending for the next cycle. A claim left by a crashed cycle is adopted here
    rather than deleted unexamined -- the request was acknowledged, so it is owed
    a run (audit CORE-010).
    """
    paths = home_paths(home)
    if paths.trigger_claim.exists():
        return True
    if not paths.trigger.exists():
        return False
    try:
        os.replace(str(paths.trigger), str(paths.trigger_claim))
    except OSError:
        # Another cycle claimed it first, or the token vanished. Either way this
        # cycle owns nothing and must not delete anything.
        return paths.trigger_claim.exists()
    return True


def _release_trigger(home: Path) -> None:
    """Consume only the claim this cycle owns."""
    claim = home_paths(home).trigger_claim
    if claim.exists():
        try:
            os.unlink(str(claim))
        except OSError:
            pass


def _continue_cycle(home: Path, registry: dict) -> tuple[int, dict]:
    """One bounded analysis cycle — extracted for --drain reuse."""
    status, state, detail = load_state(home, registry=registry)
    if status == STATE_UNRECOVERABLE:
        raise PalError(
            "STATE_UNRECOVERABLE",
            f"STATE.json is unusable: {detail}",
            next_action=(
                "repair or remove .saipal/STATE.json by hand; SAIPAL will not "
                "overwrite it"
            ),
        )

    created = ensure_home(home, registry=registry)

    # Claim the trigger present RIGHT NOW, before any work. A request arriving
    # later in this cycle must survive it: deleting whatever trigger.json exists
    # at the end of the cycle acknowledged a trigger and then discarded it
    # without ever running for it (audit CORE-010).
    trigger_claimed = _claim_trigger(home)

    index_status, session_index, index_detail = load_index(home, registry=registry)
    if index_status == INDEX_UNRECOVERABLE:
        raise PalError(
            "VALIDATION_FAILED",
            f"session index is unusable: {index_detail}",
            next_action="repair or remove .saipal/sessions/index.json by hand",
        )

    source_status, source_payload, source_detail = load_sources(home)
    if source_status == SOURCES_UNRECOVERABLE:
        raise PalError("INVALID_SOURCE_REGISTRY", source_detail)
    configured = source_payload.get("sources", []) if source_payload else []
    if not configured and home == resolve_tool_root() / HOME_DIRNAME:
        from saipal_engine.sources import auto_sources
        configured = auto_sources()
    # Load protocol authority for binding verification during intake.
    authority: dict = {}
    config_status, config, config_detail = load_config(home)
    if config_status != "unrecoverable" and config:
        from saipal_engine.config import protocol_authority
        authority = {k: str(v) if v is not None else None for k, v in protocol_authority(home, config).items()}

    dispatch = dispatch_sources(home, configured, registry=registry, index=session_index, authority=authority)
    sources = discover(home, auto=home == resolve_tool_root() / HOME_DIRNAME)
    enabled = [source for source in sources if source["enabled"]]
    intake = import_inbox(home, registry=registry, authority=authority)

    index_status, session_index, index_detail = load_index(home, registry=registry)
    if index_status == INDEX_UNRECOVERABLE:
        raise PalError(
            "VALIDATION_FAILED",
            f"session index is unusable: {index_detail}",
            next_action="repair or remove .saipal/sessions/index.json by hand",
        )

    from saipal_engine.pipeline import analyze_sessions
    from saipal_engine.publications import retry_pending

    # A restored sink receives the backlog BEFORE anything new is produced:
    # an undelivered audit is older evidence than whatever this cycle finds.
    republished = retry_pending(home, registry=registry)

    analysis = {"sessions_analyzed": 0, "events_analyzed": 0,
                "findings_created": 0, "findings_rejected": 0,
                "audits_emitted": [], "candidates_total": 0}
    if session_index is not None:
        analysis = analyze_sessions(home, session_index, registry=registry)

    candidates = int(analysis["findings_created"])
    audits_emitted = len(analysis["audits_emitted"])

    if state is None:
        state = fresh_state(registry=registry)

    state["phase"] = "IDLE"
    state["queue"] = {
        "hot": intake["hot"],
        "recent": sum(
            1 for entry in intake["imported"] if entry.get("outcome") == "new-generation"
        ),
        "cold": intake["cold"],
        "candidates": candidates,
    }
    state["last_checkpoint"] = utc_now_iso()
    state["next_action"] = _continue_next_action(intake, enabled, analysis)

    # Only the claim this cycle owns is consumed. A trigger written while the
    # cycle ran is still sitting in trigger.json, pending for the next one.
    _release_trigger(home)

    append_event(
        home, "cycle", data={
            "phase": state["phase"], "sources": len(enabled),
            "imported": intake["new_sessions"], "skipped": len(intake["skipped"]),
            "rejected": len(intake["rejected"]),
            "conflicts": len(intake["conflicts"]),
            "sessions_analyzed": analysis["sessions_analyzed"],
            "events_analyzed": analysis["events_analyzed"],
            "candidates": candidates,
            "findings_rejected": analysis["findings_rejected"],
            "audits_emitted": audits_emitted, "created": created,
            "trigger_claimed": trigger_claimed,
            "republished": republished["published"],
        }, registry=registry,
    )
    save_state(home, state, registry=registry)

    return EXIT_OK, {
        "ok": True, "command": "continue", "home": str(home),
        "phase": state["phase"],
        "idle": not intake["imported"] and not intake["conflicts"],
        "created": created, "discovered_sources": sources, "intake": intake,
        "dispatch": dispatch, "sessions_indexed": intake["new_sessions"],
        "sessions_analyzed": analysis["sessions_analyzed"],
        "events_analyzed": analysis["events_analyzed"],
        "candidates": candidates,
        "findings_rejected": analysis["findings_rejected"],
        "audits_emitted": audits_emitted,
        "trigger_claimed": trigger_claimed,
        "publication_retry": republished,
        "next_action": state["next_action"],
    }


def cmd_continue(home: Path, registry: dict, args: list[str] | None = None) -> tuple[int, dict]:
    """One bounded analysis cycle, or drain loop when --drain is set.

    Without --drain runs one cycle (same as before). With --drain repeats
    bounded cycles until clean idle, blocked, or the safety valve hits.
    """
    drain = bool(args) and "--drain" in args
    unknown = [a for a in (args or []) if a not in ("--drain",)]
    if unknown:
        raise PalError("USAGE", f"continue takes no arguments or --drain; surplus: {' '.join(unknown)}")

    if not drain:
        return _continue_cycle(home, registry)

    from saipal_engine.hardening import SafetyValve, check_safety_valves
    import time

    valve = SafetyValve()
    started = time.monotonic()
    cycles = 0
    total = {
        "sessions_indexed": 0, "sessions_analyzed": 0, "events_analyzed": 0,
        "candidates": 0, "findings_rejected": 0, "audits_emitted": 0,
        "cycles": 0, "conflicts": 0,
    }
    cycle_results: list[dict] = []
    blocked = False

    while True:
        cycles += 1
        _exit, result = _continue_cycle(home, registry)
        if _exit != EXIT_OK:
            return _exit, result
        cycle_results.append(result)
        total["sessions_indexed"] += result.get("sessions_indexed", 0)
        total["sessions_analyzed"] += result.get("sessions_analyzed", 0)
        total["events_analyzed"] += result.get("events_analyzed", 0)
        total["candidates"] += result.get("candidates", 0)
        total["findings_rejected"] += result.get("findings_rejected", 0)
        total["audits_emitted"] += result.get("audits_emitted", 0)
        total["cycles"] = cycles
        total["conflicts"] += len(result.get("intake", {}).get("conflicts", []))

        elapsed = time.monotonic() - started
        valve_ok, valve_reason = check_safety_valves(
            valve, cycles, elapsed, result.get("audits_emitted", 0)
        )
        if not valve_ok:
            total["drain_outcome"] = "safety_valve"
            total["drain_reason"] = valve_reason
            break

        idle = result.get("idle", False)
        has_conflicts = len(result.get("intake", {}).get("conflicts", [])) > 0
        productive = any(
            result.get(k, 0) > 0
            for k in ("sessions_indexed", "sessions_analyzed", "candidates", "audits_emitted")
        )
        if idle or has_conflicts:
            total["drain_outcome"] = "idle" if idle else "blocked"
            total["drain_reason"] = (
                "backlog drained" if idle else "conflict requires operator resolution"
            )
            blocked = has_conflicts
            break
        if not productive:
            total["drain_outcome"] = "idle"
            total["drain_reason"] = "no remaining work"
            break

    total["drain"] = True
    total["drain_cycles"] = cycles
    total["drain_elapsed_s"] = round(elapsed, 1)
    total["drain_blocked"] = blocked
    total["cycle_results"] = cycle_results
    return EXIT_OK, total


def _continue_next_action(intake: dict, enabled: list, analysis: dict | None = None) -> str:
    """The next action is a sentence a human can act on, not a status code."""
    analysis = analysis or {}
    if analysis.get("audits_emitted"):
        return (
            f"{len(analysis['audits_emitted'])} qualified audit(s) emitted; "
            "run `saipal status` for details"
        )
    if analysis.get("findings_created"):
        return (
            f"{int(analysis['findings_created'])} candidate finding(s) created; "
            "run `saipal status` for details"
        )
    if intake["conflicts"]:
        return (
            f"{len(intake['conflicts'])} session(s) are in CONFLICT: an already-"
            "analyzed prefix changed; inspect .saipal/sessions/index.json"
        )
    if intake["rejected"]:
        return (
            f"{len(intake['rejected'])} inbox bundle(s) were rejected; see "
            "`saipal continue --json` for the reason on each"
        )
    if intake["imported"]:
        return "sessions indexed and analyzed; no drift found in this cycle"
    if not enabled:
        return (
            "no session sources configured and the inbox is empty; add a source "
            "to .saipal/sources.json or drop a canonical bundle into "
            ".saipal/session_inbox/"
        )
    return "no new evidence and no unfinished candidates"


# --------------------------------------------------------------------------- #
# setup -- explicit one-time configuration
# --------------------------------------------------------------------------- #


def _read_sources(home: Path) -> dict:
    from saipal_engine.sources import empty_sources, load_sources

    status, payload, _detail = load_sources(home)
    if status == SOURCES_UNRECOVERABLE:
        raise PalError("INVALID_SOURCE_REGISTRY", "sources.json is unusable")
    return payload if payload else empty_sources()


#: Operator flags that declare historical protocol authority roots. The keys
#: they map to are owned by `config.AUTHORITY_KEYS`; a session's binding fields
#: select an identity inside these roots and never name a path themselves.
_AUTHORITY_FLAGS = {
    "--protocol-git": "git_repository",
    "--protocol-releases": "release_root",
    "--protocol-snapshots": "snapshot_root",
}


def cmd_setup(home: Path, registry: dict, args: list[str]) -> tuple[int, dict]:
    """Explicit one-time configuration: sources, sink, publication mode."""
    from saipal_engine.sources import save_sources
    from saipal_engine.state import load_state, save_state, fresh_state
    from saipal_engine.config import save_config

    source_root: str | None = None
    source_kind: str | None = None
    sink_root: str | None = None
    mode: str | None = None
    maintainer_root: str | None = None
    shadow_reviewed: bool | None = None
    authority: dict[str, str] = {}

    index = 0
    while index < len(args):
        token = args[index]
        if token == "--shadow-reviewed":
            shadow_reviewed = True
            index += 1
            continue
        if token == "--no-shadow-reviewed":
            shadow_reviewed = False
            index += 1
            continue
        if token == "--source" and index + 1 < len(args):
            source_root = args[index + 1]
            index += 2
            continue
        if token == "--kind" and index + 1 < len(args):
            source_kind = args[index + 1]
            index += 2
            continue
        if token == "--sink" and index + 1 < len(args):
            sink_root = args[index + 1]
            index += 2
            continue
        if token == "--mode" and index + 1 < len(args):
            mode = args[index + 1]
            index += 2
            continue
        if token == "--maintainer" and index + 1 < len(args):
            maintainer_root = args[index + 1]
            index += 2
            continue
        if token in _AUTHORITY_FLAGS and index + 1 < len(args):
            authority[_AUTHORITY_FLAGS[token]] = args[index + 1]
            index += 2
            continue
        raise PalError("USAGE", f"unknown setup option {token!r}")

    if not any(
        (source_root, source_kind, sink_root, mode, maintainer_root, authority)
    ) and shadow_reviewed is None:
        raise PalError(
            "USAGE",
            "setup needs at least one of --source/--kind/--sink/--mode/--maintainer/"
            "--shadow-reviewed/--protocol-git/--protocol-releases/--protocol-snapshots",
        )

    sources = _read_sources(home)
    if source_root is not None or source_kind is not None:
        kind = source_kind or "generic"
        if source_root is None:
            raise PalError("USAGE", "--source is required when configuring a source")
        sources["sources"] = [
            s for s in sources.get("sources", []) if s.get("path") != source_root
        ]
        sources["sources"].append(
            {"id": f"src{len(sources['sources']) + 1}", "kind": kind, "path": source_root, "enabled": True}
        )
        save_sources(home, sources)

    if mode is not None:
        from saipal_engine.config import PUBLICATION_MODES

        if mode not in PUBLICATION_MODES:
            raise PalError("USAGE", f"mode must be one of {', '.join(PUBLICATION_MODES)}")

    # Config is one transaction. Applying mode, sink and authority as three
    # separate saves made PUBLISH_ENABLED unreachable: the mode was validated
    # before the sink root it requires existed, so `--mode PUBLISH_ENABLED
    # --sink PATH` always failed on its own first step.
    if mode is not None or sink_root is not None or authority or shadow_reviewed is not None:
        from saipal_engine.config import AUTHORITY_KEYS

        config_status, config, detail = load_config(home)
        if config_status == "unrecoverable":
            raise PalError("VALIDATION_FAILED", detail)
        config = dict(config or default_config())
        if mode is not None:
            config["publication_mode"] = mode
        if shadow_reviewed is not None:
            config["shadow_reviewed"] = shadow_reviewed
        if sink_root is not None:
            root = Path(sink_root).expanduser()
            if not root.is_dir():
                raise PalError("USAGE", f"sink root {sink_root!r} is not an existing directory")
            config.setdefault("sink", {"kind": "termisai-file", "root": None})
            config["sink"] = dict(config["sink"])
            config["sink"]["root"] = str(root)
        if authority:
            declared = dict(config.get("protocol_authority") or {})
            for key in AUTHORITY_KEYS:
                declared.setdefault(key, None)
            for key, value in authority.items():
                root = Path(value).expanduser()
                if not root.is_dir():
                    raise PalError(
                        "USAGE",
                        f"protocol authority {key} {value!r} is not an existing directory",
                    )
                declared[key] = str(root)
            config["protocol_authority"] = declared
        save_config(home, config)

    if maintainer_root is not None:
        from saipal_engine.state import load_state

        status, state, detail = load_state(home, registry=registry)
        if status == STATE_UNRECOVERABLE:
            raise PalError("STATE_UNRECOVERABLE", detail)
        state = state or fresh_state(registry=registry)
        state["maintainer_root"] = maintainer_root
        save_state(home, state, registry=registry)

    return EXIT_OK, {
        "ok": True,
        "command": "setup",
        "home": str(home),
        "mode": mode,
        "source": source_root,
        "sink": sink_root,
        "maintainer_root": maintainer_root,
        "shadow_reviewed": shadow_reviewed,
        "protocol_authority": authority or None,
        "next_action": "saipal doctor",
    }


# --------------------------------------------------------------------------- #
# doctor -- read-only diagnosis
# --------------------------------------------------------------------------- #


def cmd_doctor(home: Path, registry: dict) -> tuple[int, dict]:
    from saipal_engine.hardening import load_telemetry
    from saipal_engine.closedloop import load_links
    from saipal_engine.sessions import load_index as load_session_index
    from saipal_engine.sink import configured_sink

    config_status, config, detail = load_config(home)
    sources_status, sources_payload, sources_detail = load_sources(home)
    index_status, session_index, index_detail = load_session_index(home, registry=registry)
    links_status, links_payload, links_detail = load_links(home)
    sink_status, sink, sink_detail = configured_sink(home)

    telemetry = load_telemetry(home)
    staged = 0
    staging_dir = home_paths(home).audit_staging
    if staging_dir.is_dir():
        staged = sum(1 for p in staging_dir.iterdir() if p.suffix == ".md")

    mode = (config or {}).get("publication_mode", "STAGE_ONLY") if config_status != "unrecoverable" else "UNKNOWN"
    authority: dict[str, str | None] = {}
    if config_status != "unrecoverable":
        from saipal_engine.config import protocol_authority

        for key, value in protocol_authority(home, config).items():
            authority[key] = str(value) if value is not None else None
    result = {
        "ok": True,
        "command": "doctor",
        "home": str(home),
        "home_exists": home.exists(),
        "sources_status": sources_status,
        "sources_detail": sources_detail,
        "sources_count": len((sources_payload or {}).get("sources", [])) if sources_payload else 0,
        "adapter_available": True,
        "config_status": config_status,
        "config_detail": detail,
        "publication_mode": mode,
        "protocol_authority": authority,
        "protocol_authority_configured": any(authority.values()),
        "sink_status": sink_status,
        "sink_detail": sink_detail,
        "index_status": index_status,
        "index_detail": index_detail,
        "sessions_indexed": len((session_index or {}).get("sessions", [])) if session_index else 0,
        "links_status": links_status,
        "links_detail": links_detail,
        "staged_audits": staged,
        "telemetry": telemetry,
    }
    return EXIT_OK, result


# --------------------------------------------------------------------------- #
# disposition -- closed-loop intake
# --------------------------------------------------------------------------- #


def cmd_submit(home: Path, registry: dict, args: list[str]) -> tuple[int, dict]:
    """Absorb one analyst candidate from a JSON file, or `-` for stdin."""
    from saipal_engine.submit import submit_candidate

    if not args or args[0].startswith("--"):
        raise PalError(
            "USAGE",
            "submit needs a candidate JSON file path, or - for stdin",
        )
    source = args[0]
    if len(args) > 1:
        raise PalError("USAGE", "submit takes exactly one argument")
    try:
        raw = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise PalError("VALIDATION_FAILED", f"candidate file is unreadable: {exc}") from exc
    try:
        candidate = json.loads(raw)
    except ValueError as exc:
        raise PalError("VALIDATION_FAILED", f"candidate is not valid JSON: {exc}") from exc

    receipt = submit_candidate(home, candidate, registry=registry)
    return EXIT_OK, {
        "ok": True,
        "command": "submit",
        "home": str(home),
        "source": source,
        **receipt,
        "next_action": "saipal --json next",
    }


def cmd_disposition(home: Path, registry: dict, args: list[str]) -> tuple[int, dict]:
    from saipal_engine.closedloop import import_disposition_file

    if not args or args[0] in ("--json", "--help"):
        raise PalError("USAGE", "disposition needs a JSON file path")
    imported = import_disposition_file(home, args[0])
    return EXIT_OK, {
        "ok": True,
        "command": "disposition",
        "file": args[0],
        "imported": imported,
        "count": len(imported),
    }


# --------------------------------------------------------------------------- #
# trigger -- unattended coalescing entry point
# --------------------------------------------------------------------------- #


def cmd_trigger(home: Path, registry: dict) -> tuple[int, dict]:
    """Register one pending run; multiple rapid triggers coalesce into one.

    Coalescing is against the PENDING token only. A cycle in flight has already
    renamed its own token away, so a trigger arriving now is a request for the
    NEXT cycle and must be recorded rather than absorbed into a run that will
    never see it (audit CORE-010).
    """
    from saipal_engine.paths import atomic_write_json

    paths = home_paths(home)
    if paths.trigger.exists():
        return EXIT_OK, {
            "ok": True,
            "command": "trigger",
            "coalesced": True,
            "message": "a run is already pending; this trigger was coalesced",
        }
    atomic_write_json(paths.trigger, {"pending": True}, root=paths.root)
    return EXIT_OK, {"ok": True, "command": "trigger", "coalesced": False, "message": "run scheduled"}


# --------------------------------------------------------------------------- #
# status / next -- strictly read-only
# --------------------------------------------------------------------------- #


def _load_read_only(home: Path, registry: dict) -> dict:
    status, state, detail = load_state(home, registry=registry)
    if status == STATE_UNRECOVERABLE:
        raise PalError(
            "STATE_UNRECOVERABLE",
            f"STATE.json is unusable: {detail}",
            next_action="repair or remove .saipal/STATE.json by hand",
        )
    if status == STATE_ABSENT:
        raise PalError(
            "NO_HOME",
            "no STATE.json in this home; nothing to report",
            next_action="saipal continue",
        )

    sources_status, payload, sources_detail = load_sources(home)
    if sources_status == SOURCES_UNRECOVERABLE:
        raise PalError(
            "INVALID_SOURCE_REGISTRY",
            sources_detail,
            next_action="repair .saipal/sources.json by hand",
        )

    index_status, index, index_detail = load_index(home, registry=registry)
    if index_status == INDEX_UNRECOVERABLE:
        raise PalError(
            "VALIDATION_FAILED",
            f"session index is unusable: {index_detail}",
            next_action="repair .saipal/sessions/index.json by hand",
        )

    records = index["sessions"] if index else []
    # Two scalars, streamed: `read_events` decoded and retained the lifetime log
    # to answer them (PERF-006).
    log_events, malformed = log_stats(home)
    paths = home_paths(home)
    assert state is not None
    return {
        "ok": True,
        "_session_index": index,
        "home": str(paths.root),
        "phase": state["phase"],
        "current_session": state["current_session"],
        "current_episode": state["current_episode"],
        "current_candidate": state["current_candidate"],
        "queue": state["queue"],
        "maintainer_root": state["maintainer_root"],
        "next_action": state["next_action"],
        "last_checkpoint": state["last_checkpoint"],
        "sources": len(payload["sources"]) if payload else 0,
        "sessions": len(records),
        "sessions_hot": sum(1 for r in records if r["temperature"] == "HOT"),
        "sessions_cold": sum(1 for r in records if r["temperature"] == "COLD"),
        "sessions_conflict": sum(1 for r in records if r["status"] == "CONFLICT"),
        "events_indexed": sum(int(r["event_count"]) for r in records),
        "episodes": sum(len(r["episodes"]) for r in records),
        "log_events": log_events,
        "malformed_log_lines": malformed,
    }


def cmd_status(home: Path, registry: dict) -> tuple[int, dict]:
    from saipal_engine.coverage import coverage

    result = _load_read_only(home, registry)
    result["command"] = "status"

    # Semantic progress is reported from receipts, not from the watermark flag:
    # a cursor that ran off the end and a session that was actually judged look
    # identical to `exhausted`, and only one of them is real work. The index the
    # read-only load already parsed is reused: loading an 11 MB index twice for
    # one command was measurable on its own (PERF-004).
    index = result.pop("_session_index", None)
    result["semantic"] = coverage(home, index, registry=registry)
    return EXIT_OK, result


# --------------------------------------------------------------------------- #
# report -- the drift report, strictly read-only
# --------------------------------------------------------------------------- #


#: A report headline the operator can act on without reading the body.
VERDICT_NO_EVIDENCE = "NO_EVIDENCE"
VERDICT_NOT_EXAMINED = "NOT_EXAMINED"
VERDICT_NO_DRIFT_SO_FAR = "NO_DRIFT_SO_FAR"
VERDICT_DRIFT_SUSPECTED = "DRIFT_SUSPECTED"
VERDICT_DRIFT_REPORTED = "DRIFT_REPORTED"


def _owner_documents(rule_ids: list, registry: dict) -> list[str]:
    owners = registry.get("rule_owners") or {}
    out: list[str] = []
    for rule in rule_ids or []:
        document = owners.get(str(rule))
        if document and document not in out:
            out.append(str(document))
    return out


def _attribution(finding: dict, records: list[dict]) -> dict:
    """Which model, provider and project produced the occurrences of a finding.

    A maintainer routes a drift report by asking who drifted, so the report
    answers it from the session index rather than making the reader join two
    JSON files by hand (PAL-AUDIT-03).
    """
    wanted = {
        str(occurrence.get("session_id") or "")
        for occurrence in finding.get("occurrences") or []
    }
    models: list[str] = []
    providers: list[str] = []
    projects: list[str] = []
    for record in records:
        if str(record.get("session_id") or "") not in wanted:
            continue
        runtime = record.get("runtime") or {}
        project = record.get("project") or {}
        for value, bucket in (
            (runtime.get("model"), models),
            (runtime.get("provider"), providers),
            (project.get("name"), projects),
        ):
            text = str(value or "").strip()
            if text and text not in bucket:
                bucket.append(text)
    return {
        "sessions": sorted(session for session in wanted if session),
        "models": models,
        "providers": providers,
        "projects": projects,
    }


def _reported_finding(finding: dict, records: list[dict], registry: dict) -> dict:
    rule_ids = list(finding.get("rule_ids") or [])
    spread = finding.get("recurrence_spread") or {}
    return {
        "finding_id": finding.get("finding_id"),
        "state": finding.get("state"),
        "drift_class": finding.get("drift_class"),
        "disposition_class": finding.get("disposition_class"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "change_target": finding.get("change_target"),
        "rule_ids": rule_ids,
        "owner_documents": _owner_documents(rule_ids, registry),
        "causal_key": finding.get("causal_key"),
        "root_cause": finding.get("root_cause"),
        "occurrences": len(finding.get("occurrences") or []),
        "attribution": _attribution(finding, records),
        "recurrence": spread.get("classification"),
        "recurrence_guidance": spread.get("guidance"),
        "harm_warnings": list(finding.get("harm_warnings") or []),
        "harm_blocks": list(finding.get("harm_blocks") or []),
        "provisional_hold": finding.get("provisional_hold"),
        "episode_finality": finding.get("episode_finality"),
        "audit": finding.get("audit"),
    }


def _verdict(reported: list[dict], coverage: dict, sessions: int) -> str:
    """The headline, derived from findings AND coverage -- never from silence.

    "No drift" is only meaningful beside how much was actually judged: a report
    that says clean while every episode is still pending is reporting its own
    idleness. So an unexamined home says so instead. A paged episode counts as
    examined once any slice of it has a final verdict -- partial work is still
    work, and the slice counts beside the verdict say how much.
    """
    if not sessions:
        return VERDICT_NO_EVIDENCE
    if any(row["state"] == "EMITTED" or row["audit"] for row in reported):
        return VERDICT_DRIFT_REPORTED
    if reported:
        return VERDICT_DRIFT_SUSPECTED
    if int(coverage.get("slices_final") or 0) == 0:
        return VERDICT_NOT_EXAMINED
    return VERDICT_NO_DRIFT_SO_FAR


def _report_next_action(verdict: str, coverage: dict, counts: dict) -> str:
    """What to do about this report, which is not always "read the audits".

    A next action that says "hand the audit(s) to the maintainer" when nothing was
    emitted is worse than no advice: it invites the reader to look for a file that
    does not exist.

    The remainder is counted in SLICES as well as episodes: a paged episode with
    two of five slices judged is neither pending nor final, so an episode-only
    remainder would quietly stop pointing at the work that is left.
    """
    pending = int(coverage.get("episodes_pending") or 0)
    slices_left = int(coverage.get("slices_pending") or 0)
    if verdict == VERDICT_DRIFT_REPORTED:
        return "hand the emitted audit(s) to the SAIPEN Core maintainer"
    if verdict == VERDICT_DRIFT_SUSPECTED:
        return (
            f"{counts.get('total', 0)} internal finding(s) did not qualify for an "
            "audit; read them before deciding"
        )
    if pending:
        return f"saipal continue -- {pending} episode(s) are still unexamined"
    if slices_left:
        return f"saipal continue -- {slices_left} episode slice(s) are still unexamined"
    return "saipal continue"


def cmd_report(home: Path, registry: dict) -> tuple[int, dict]:
    """The drift report: what was found, against which rule, and how much was judged."""
    from saipal_engine.coverage import coverage as coverage_of
    from saipal_engine.findings import load_index as load_findings

    base = _load_read_only(home, registry)
    # Reuse the index the read-only load already parsed (PERF-004).
    index = base.pop("_session_index", None)
    records = list((index or {}).get("sessions") or [])
    coverage = coverage_of(home, index, registry=registry)

    findings_status, findings_index, findings_detail = load_findings(home, registry=registry)
    if findings_status == "unrecoverable":
        raise PalError(
            "VALIDATION_FAILED",
            f"findings index is unusable: {findings_detail}",
            next_action="repair or remove .saipal/findings/index.json by hand",
        )
    findings = list((findings_index or {}).get("findings") or [])
    reported = [_reported_finding(finding, records, registry) for finding in findings]

    staged: list[str] = []
    staging = home_paths(home).audit_staging
    if staging.is_dir():
        staged = sorted(path.name for path in staging.iterdir() if path.suffix == ".md")

    counts = {
        "total": len(reported),
        "emitted": sum(1 for row in reported if row["state"] == "EMITTED"),
        "qualified": sum(1 for row in reported if row["state"] == "QUALIFIED"),
        "blocked": sum(1 for row in reported if row["state"] == "BLOCKED"),
        "held_provisional": sum(1 for row in reported if row["provisional_hold"]),
        "internal": sum(
            1 for row in reported if row["state"] not in ("EMITTED", "QUALIFIED")
        ),
    }
    verdict = _verdict(reported, coverage, base["sessions"])
    return EXIT_OK, {
        "ok": True,
        "command": "report",
        "home": base["home"],
        "verdict": verdict,
        "sessions": base["sessions"],
        "sessions_conflict": base["sessions_conflict"],
        "coverage": coverage,
        "counts": counts,
        "findings": reported,
        "staged_audits": staged,
        "next_action": _report_next_action(verdict, coverage, counts),
    }


def cmd_next(home: Path, registry: dict) -> tuple[int, dict]:
    result = _load_read_only(home, registry)
    session_index = result.pop("_session_index", None)
    (
        idle,
        resume_session,
        advance_candidate,
        resolve_conflict,
        analyze_episodes,
        discover_sources,
    ) = require_string_list(registry, "next_carriers")

    # The analysis carrier (PAL-ANALYSIS-01) is built first, because only it can
    # answer whether indexed sessions actually contain pending analysis work.
    # Building it is read-only, so `next` keeps its PAL-CMD-02 contract. The
    # already-parsed index is handed over rather than re-read (PERF-004).
    unit = None
    if result["sessions"]:
        from saipal_engine.carrier import build_carrier

        unit = build_carrier(home, registry=registry, index=session_index)

    carrier = idle
    if result["current_session"]:
        carrier = resume_session
    elif result["current_candidate"]:
        carrier = advance_candidate
    elif unit is not None and unit["carrier"] == analyze_episodes:
        # Pending analysis outranks a frozen conflict: a CONFLICT is an operator
        # task that never resolves itself, so letting it win would starve the
        # analyst loop forever on one mutated session.
        carrier = analyze_episodes
    elif result["sessions_conflict"]:
        carrier = resolve_conflict
    elif result["sources"]:
        carrier = discover_sources

    summary = {
        "ok": True,
        "command": "next",
        "carrier": carrier,
        "home": result["home"],
        "phase": result["phase"],
        "sources": result["sources"],
        "sessions": result["sessions"],
        "sessions_conflict": result["sessions_conflict"],
        "next_action": "saipal continue",
    }
    notes = {
        resolve_conflict: (
            "a session's already-analyzed prefix changed; SAIPAL will not "
            "continue over mutated evidence"
        ),
        discover_sources: (
            "sources are configured; continue dispatches them through registered adapters"
        ),
    }
    if carrier in notes:
        summary["note"] = notes[carrier]

    if carrier == analyze_episodes and unit is not None:
        summary["analysis_carrier"] = unit
        summary["note"] = (
            f"episode {unit['episode']['index']} of session "
            f"{unit['session']['session_id']} is the next analysis unit"
        )
        if result["sessions_conflict"]:
            summary["note"] += (
                f"; {result['sessions_conflict']} session(s) also await conflict "
                "resolution by the operator"
            )
    return EXIT_OK, summary


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #


def render_human(result: dict) -> str:
    if result.get("command") == "status":
        keys = (
            "phase",
            "current_session",
            "current_episode",
            "current_candidate",
            "queue",
            "maintainer_root",
            "next_action",
            "last_checkpoint",
            "sources",
            "sessions",
            "events_indexed",
            "episodes",
            "log_events",
        )
        lines = [f"{key}: {result[key]}" for key in keys]
        semantic = result.get("semantic") or {}
        if semantic:
            lines.append(
                "semantic: "
                f"{semantic['episodes_final']}/{semantic['episodes_total']} episodes judged, "
                f"{semantic['episodes_provisional']} provisional, "
                f"{semantic['episodes_pending']} pending, "
                f"{semantic['sessions_truly_exhausted']} session(s) complete"
            )
            # A long episode is judged slice by slice, so the slice line is the
            # honest unit of progress: 1 of 5 slices judged is not a judged episode.
            lines.append(
                "slices: "
                f"{semantic.get('slices_final', 0)}/{semantic.get('slices_total', 0)} judged, "
                f"{semantic.get('slices_pending', 0)} pending"
            )
            if semantic.get("cursor_claims_more_than_receipts"):
                lines.append(
                    "semantic_discrepancy: "
                    f"{len(semantic['cursor_claims_more_than_receipts'])} session(s) claim "
                    "exhaustion without a receipt for every episode"
                )
        lines.append(f"home: {result['home']}")
        return "\n".join(lines)

    if result.get("command") == "report":
        coverage = result.get("coverage") or {}
        counts = result.get("counts") or {}
        lines = [
            f"verdict: {result['verdict']}",
            f"sessions: {result['sessions']} "
            f"(conflict: {result['sessions_conflict']})",
            f"judged: {coverage.get('episodes_final', 0)}/{coverage.get('episodes_total', 0)} "
            f"episodes, {coverage.get('episodes_provisional', 0)} provisional, "
            f"{coverage.get('episodes_pending', 0)} pending",
            f"slices: {coverage.get('slices_final', 0)}/{coverage.get('slices_total', 0)} "
            f"judged, {coverage.get('slices_pending', 0)} pending",
            f"findings: {counts.get('total', 0)} "
            f"(emitted {counts.get('emitted', 0)}, qualified {counts.get('qualified', 0)}, "
            f"blocked {counts.get('blocked', 0)}, held {counts.get('held_provisional', 0)})",
        ]
        if coverage.get("cursor_claims_more_than_receipts"):
            lines.append(
                "coverage_discrepancy: "
                f"{len(coverage['cursor_claims_more_than_receipts'])} session(s) claim "
                "exhaustion without a receipt for every episode"
            )
        for row in result.get("findings") or []:
            attribution = row.get("attribution") or {}
            audit = row.get("audit") or {}
            lines.append(
                f"  {row['finding_id']} [{row['state']}] {row['drift_class']} "
                f"{row['severity']}/{row['confidence']} -> {row['change_target']}"
            )
            lines.append(
                f"    rules: {row['rule_ids']} owners: {row['owner_documents']}"
            )
            lines.append(
                f"    who: models={attribution.get('models') or '-'} "
                f"projects={attribution.get('projects') or '-'} "
                f"occurrences={row['occurrences']} spread={row.get('recurrence') or '-'}"
            )
            if row.get("root_cause"):
                lines.append(f"    root_cause: {row['root_cause']}")
            if audit.get("audit_number"):
                lines.append(
                    f"    audit: {audit['audit_number']} at {audit.get('audit_path', '-')}"
                )
            if row.get("provisional_hold"):
                lines.append(f"    held: {row['provisional_hold']}")
            for warning in row.get("harm_warnings") or []:
                lines.append(f"    do-not-weaken: {warning}")
            for block in row.get("harm_blocks") or []:
                lines.append(f"    blocked: {block}")
        if result.get("staged_audits"):
            lines.append(f"staged_audits: {', '.join(result['staged_audits'])}")
        lines.append(f"next_action: {result['next_action']}")
        lines.append(f"home: {result['home']}")
        return "\n".join(lines)

    if result.get("command") == "next":
        lines = [
            f"carrier: {result['carrier']}",
            f"phase: {result['phase']}",
            f"sources: {result['sources']}",
            f"sessions: {result['sessions']}",
        ]
        unit = result.get("analysis_carrier")
        if unit:
            session = unit["session"]
            episode = unit["episode"]
            window = unit.get("slice") or {}
            law = unit.get("applicable_law") or {}
            surface = unit.get("historical_rule_surface") or {}
            defences = [entry.get("code") for entry in unit.get("defence_surface") or []]
            spread = (unit.get("recurrence") or {}).get("spread") or {}
            lines += [
                f"unit_digest: {unit.get('unit_digest', '-')}",
                f"session: {session['session_id']} [{session['adapter']}] "
                f"{session['temperature']} {session['event_count']} ev",
                f"episode: {episode['index']} {episode['kind']} "
                f"seq {episode['start_seq']}-{episode['end_seq']} "
                f"({episode['event_count']} ev"
                + (", truncated" if episode.get("events_truncated") else "")
                + f") {episode.get('finality', 'FINAL')}",
                # A paged episode is judged slice by slice, so which slice this is
                # decides what the analyst may cite and when the episode closes.
                f"slice: {window.get('index', 0) + 1}/{window.get('count', 1)} "
                f"seq {window.get('start_seq', '-')}-{window.get('end_seq', '-')} "
                f"of {window.get('span_event_count', episode['event_count'])} ev"
                + ("" if window.get("final_slice", True) else ", more remain"),
                f"binding: {unit['protocol']['binding_status']} / "
                f"{unit['protocol']['proof_level']} "
                f"claimable={unit['protocol']['violation_claimable']}",
                f"law: {law.get('drift_class', '-')} {law.get('rule_ids', [])}",
                f"historical_rules: {surface.get('status', 'not configured')}",
                f"signals: {len(unit.get('signals') or [])}",
                # A DRIFT claim must answer every raised mitigation by name
                # (PAL-ANALYSIS-02), so the codes belong in the compact view too.
                f"defence_surface: {defences or '-'}",
                f"recurrence: {spread.get('classification', '-')} "
                f"({spread.get('occurrences', 0)} occurrence(s))",
                f"open_candidates: {len(unit.get('open_candidates') or [])}",
                f"evidence: {unit['evidence_command']}",
            ]
        lines.append(f"next_action: {result['next_action']}")
        if result.get("note"):
            lines.append(f"note: {result['note']}")
        return "\n".join(lines)

    if result.get("command") == "evidence":
        lines = [
            "=== UNTRUSTED EVIDENCE ===",
            f"window: {result['evidence_window_id']}",
            f"session: {result['session_id']}",
            f"provider: {result['provider']}",
            f"project: {(result.get('project') or {}).get('name') or '-'}",
            f"model: {result.get('model') or '-'}",
        ]
        for item in result["items"]:
            lines.append(json.dumps(item, sort_keys=True, ensure_ascii=False))
        lines.append("=== END UNTRUSTED EVIDENCE ===")
        return "\n".join(lines)

    if result.get("command") == "doctor":
        lines = [
            f"home: {result['home']}",
            f"home_exists: {result['home_exists']}",
            f"sources: {result['sources_count']} ({result['sources_status']})",
            f"config: {result['config_status']}",
            f"publication_mode: {result['publication_mode']}",
            f"sink: {result['sink_status']}",
            f"index: {result['index_status']}",
            f"sessions: {result['sessions_indexed']}",
            f"staged_audits: {result['staged_audits']}",
            f"adapter: {'available' if result['adapter_available'] else 'missing'}",
            "protocol_authority: "
            + (
                ", ".join(
                    f"{key}={value}"
                    for key, value in sorted((result.get("protocol_authority") or {}).items())
                    if value
                )
                or "none configured"
            ),
        ]
        if result.get("sink_detail"):
            lines.append(f"sink_detail: {result['sink_detail']}")
        if result.get("config_detail"):
            lines.append(f"config_detail: {result['config_detail']}")
        return "\n".join(lines)

    if result.get("command") == "setup":
        lines = [
            f"home: {result['home']}",
            f"mode: {result.get('mode', '-')}",
            f"source: {result.get('source', '-')}",
            f"sink: {result.get('sink', '-')}",
            f"maintainer_root: {result.get('maintainer_root', '-')}",
            f"shadow_reviewed: {result.get('shadow_reviewed') if result.get('shadow_reviewed') is not None else '-'}",
            "protocol_authority: "
            + (
                ", ".join(
                    f"{key}={value}"
                    for key, value in sorted((result.get("protocol_authority") or {}).items())
                )
                or "-"
            ),
            f"next_action: {result.get('next_action', 'saipal doctor')}",
        ]
        return "\n".join(lines)

    if result.get("command") == "submit":
        lines = [
            f"receipt: {result['receipt_id']}"
            + (" [duplicate]" if result.get("duplicate") else ""),
            f"verdict: {result['verdict']} ({result.get('finality', 'FINAL')})",
            f"session: {result['session_id']} episode {result['episode_index']} "
            f"slice {int(result.get('slice_index', 0)) + 1}/{result.get('slice_count', 1)}",
            f"finding: {result.get('finding_id') or '-'}",
            f"audit: {(result.get('audit') or {}).get('audit_number', '-')}",
        ]
        semantic = result.get("semantic") or {}
        if semantic:
            lines.append(
                f"semantic: next_episode={semantic.get('next_episode_index')} "
                f"next_slice={semantic.get('next_slice_index')} "
                f"exhausted={semantic.get('exhausted')} "
                f"submitted={semantic.get('submitted')} "
                f"no_drift={semantic.get('no_drift')}"
            )
        lines.append(f"next_action: {result['next_action']}")
        return "\n".join(lines)

    if result.get("command") == "sessions":
        lines = [
            f"home: {result['home']}",
            f"total: {result['total']}",
            f"shown: {len(result['sessions'])}",
            f"next_action: {result['next_action']}",
        ]
        for entry in result["sessions"]:
            lines.append(
                f"  {entry['updated_at'] or '-'} | {entry['temperature']:4s} "
                f"| {entry['status']:8s} | {str(entry['event_count']):>4} ev "
                f"| analyzed {entry['last_analyzed_seq']}"
                f"{' [exhausted]' if entry['exhausted'] else ''} "
                f"| {entry['adapter']} | {entry['session_id']}"
                f"{' | ' + str(entry['project'])[:40] if entry['project'] else ''}"
            )
        return "\n".join(lines)

    intake = result["intake"]
    lines = [
        f"phase: {result['phase']}",
        f"sources: {len(result['discovered_sources'])}",
        f"dispatched: {len(result.get('dispatch', {}).get('imported', []))}",
        f"imported: {intake['new_sessions']}",
        f"skipped: {len(intake['skipped'])}",
        f"rejected: {len(intake['rejected'])}",
        f"conflicts: {len(intake['conflicts'])}",
        f"sessions_total: {intake['sessions_total']}",
        f"candidates: {result['candidates']}",
        f"audits_emitted: {result['audits_emitted']}",
    ]
    for source in result["discovered_sources"]:
        lines.append(f"  source {source['id']} [{source['kind']}] {source['status']}")
    for entry in intake["imported"]:
        lines.append(
            f"  session {entry['session_id']} gen {entry['generation']} "
            f"[{entry.get('outcome', 'imported')}] {entry.get('events', 0)} events"
        )
    for entry in intake["rejected"]:
        lines.append(f"  rejected {entry['source_ref']} [{entry['code']}]")
    for entry in intake["conflicts"]:
        lines.append(f"  conflict {entry['session_id']}: {entry['reason']}")
    lines.append(f"next_action: {result['next_action']}")
    return "\n".join(lines)


def emit(result: dict, *, as_json: bool) -> int:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(render_human(result))
    return EXIT_OK


def emit_refusal(error: PalError, *, as_json: bool, exit_code: int) -> int:
    payload = refusal_payload(error)
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(
            f"refused [{error.code}]: {error.message}",
            file=sys.stderr,
        )
        if error.next_action:
            print(f"next: {error.next_action}", file=sys.stderr)
    return exit_code


def cmd_sessions(home: Path, registry: dict, args: list[str]) -> tuple[int, dict]:
    """List known sessions, freshest first (read-only)."""
    limit = 25
    if args:
        try:
            limit = int(args[0])
        except ValueError:
            raise PalError("USAGE", f"limit must be an integer, got {args[0]!r}")

    from saipal_engine.sessions import load_index as load_session_index

    status, index, detail = load_session_index(home, registry=registry)
    if status == INDEX_UNRECOVERABLE:
        raise PalError("VALIDATION_FAILED", detail)

    records = (index or {}).get("sessions") or []
    ordered = sorted(
        records, key=lambda r: (r.get("updated_at") or r.get("imported_at") or ""), reverse=True
    )
    sessions = []
    for record in ordered[:limit]:
        analysis = record.get("analysis") or {}
        sessions.append(
            {
                "session_id": record.get("session_id"),
                "adapter": record.get("adapter"),
                "temperature": record.get("temperature"),
                "status": record.get("status"),
                "event_count": record.get("event_count"),
                "last_analyzed_seq": record.get("last_analyzed_seq"),
                "exhausted": bool(analysis.get("episodes_exhausted")),
                "updated_at": record.get("updated_at"),
                "project": ((record.get("project") or {}).get("name") or ""),
            }
        )
    return EXIT_OK, {
        "ok": True,
        "command": "sessions",
        "home": str(home),
        "total": len(records),
        "limit": limit,
        "sessions": sessions,
        "next_action": "saipal continue",
    }


def cmd_evidence(home: Path, registry: dict, args: list[str]) -> tuple[int, dict]:
    """Resolve an indexed event locator into one bounded provider window."""
    if len(args) < 2:
        raise PalError(
            "USAGE",
            "evidence needs SESSION EVENT [--before N] [--after N]",
        )
    session_id = args[0]
    try:
        event_seq = int(args[1])
    except ValueError as exc:
        raise PalError("USAGE", f"event must be an integer, got {args[1]!r}") from exc
    limits = registry["evidence_window_limits"]
    before = int(limits["default_before"])
    after = int(limits["default_after"])
    index = 2
    while index < len(args):
        flag = args[index]
        if flag not in ("--before", "--after") or index + 1 >= len(args):
            raise PalError("USAGE", f"invalid evidence option {flag!r}")
        try:
            value = int(args[index + 1])
        except ValueError as exc:
            raise PalError("USAGE", f"{flag} needs an integer") from exc
        if value < 0:
            raise PalError("USAGE", f"{flag} must not be negative")
        if flag == "--before":
            before = value
        else:
            after = value
        index += 2

    status, session_index, detail = load_index(home, registry=registry)
    if status == INDEX_UNRECOVERABLE:
        raise PalError("VALIDATION_FAILED", detail)
    from saipal_engine.sessions import find_session
    record = find_session(session_index or {"sessions": []}, session_id)
    if record is None:
        raise PalError("EVIDENCE_NOT_FOUND", f"session {session_id!r} is not indexed")
    entry = next(
        (item for item in record.get("evidence_refs", []) if item.get("seq") == event_seq),
        None,
    )
    if entry is None:
        raise PalError("EVIDENCE_NOT_FOUND", f"event {event_seq} has no evidence locator")
    source_ref = record.get("provider_source_ref")
    if not isinstance(source_ref, str) or not source_ref:
        raise PalError("EVIDENCE_UNSUPPORTED", "session has no provider source authority")
    source_status, source_payload, source_detail = load_sources(home)
    if source_status == SOURCES_UNRECOVERABLE:
        raise PalError("INVALID_SOURCE_REGISTRY", source_detail)
    configured = (source_payload or {}).get("sources") or []
    if not configured and home == resolve_tool_root() / HOME_DIRNAME:
        from saipal_engine.sources import auto_sources
        configured = auto_sources()
    provider_home = Path(source_ref.rpartition("#")[0]).resolve()
    allowed_roots = {
        Path(str(source.get("path") or "")).expanduser().resolve()
        for source in configured
        if source.get("enabled") and source.get("kind") == record.get("adapter")
    }
    if provider_home not in allowed_roots:
        raise PalError(
            "EVIDENCE_UNSUPPORTED",
            "provider source is outside configured/discovered adapter authority",
        )
    from saipal_engine.adapters import read_evidence
    envelope = read_evidence(
        str(record["adapter"]), source_ref, entry["evidence_ref"],
        before=before, after=after, registry=registry,
    )
    envelope["command"] = "evidence"
    envelope["anchor"]["event_seq"] = event_seq
    digest_payload = {
        key: value for key, value in envelope.items()
        if key not in ("command", "window_digest", "evidence_window_id")
    }
    stable = json.dumps(
        digest_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    envelope["window_digest"] = sha256_text(stable)
    envelope["evidence_window_id"] = "evw-" + envelope["window_digest"][:24]
    return EXIT_OK, envelope


# --------------------------------------------------------------------------- #
# dispatch
# --------------------------------------------------------------------------- #


def _resolve_home(options: Options, command: str) -> Path:
    home, _reason = resolve_home(explicit=options.home)
    if home is not None:
        return Path(home)
    if command in READ_ONLY_COMMANDS or command in READ_ONLY_WITH_ARGS:
        raise PalError(
            "NO_HOME",
            f"no {HOME_DIRNAME}/ found; read-only commands never create one",
            next_action="saipal continue",
        )
    return resolve_tool_root() / HOME_DIRNAME


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    try:
        options = parse_args(raw)
    except PalError as exc:
        # Parsing failed, so there are no parsed options to consult; the raw
        # argv is all that can tell us whether the caller wanted JSON.
        return emit_refusal(exc, as_json="--json" in raw, exit_code=EXIT_USAGE)

    if options.show_version:
        print(version_text())
        return EXIT_OK
    if options.show_help:
        print(usage_text())
        return EXIT_OK

    command = options.rest[0] if options.rest else "continue"
    args = options.rest[1:]

    try:
        registry = load_registry()
    except ValueError as exc:
        return emit_refusal(
            PalError("VALIDATION_FAILED", str(exc)),
            as_json=options.as_json,
            exit_code=EXIT_REFUSED,
        )

    if command not in available_commands(registry):
        return emit_refusal(
            PalError(
                "UNKNOWN_COMMAND",
                f"unknown command {command!r}",
                next_action="saipal --help",
            ),
            as_json=options.as_json,
            exit_code=EXIT_USAGE,
        )

    if args and command in READ_ONLY_COMMANDS:
        return emit_refusal(
            PalError("USAGE", f"{command} takes no arguments"),
            as_json=options.as_json,
            exit_code=EXIT_USAGE,
        )
    if command == "sessions" and len(args) > 1:
        return emit_refusal(
            PalError("USAGE", f"{command} takes at most one argument (limit)"),
            as_json=options.as_json,
            exit_code=EXIT_USAGE,
        )

    try:
        home = _resolve_home(options, command)
    except PalError as exc:
        return emit_refusal(exc, as_json=options.as_json, exit_code=EXIT_NO_HOME)

    try:
        if command == "continue":
            with HomeLock(home):
                exit_code, result = cmd_continue(home, registry, args)
        elif command == "status":
            exit_code, result = cmd_status(home, registry)
        elif command == "doctor":
            exit_code, result = cmd_doctor(home, registry)
        elif command == "report":
            exit_code, result = cmd_report(home, registry)
        elif command == "setup":
            with HomeLock(home):
                exit_code, result = cmd_setup(home, registry, args)
        elif command == "submit":
            with HomeLock(home):
                exit_code, result = cmd_submit(home, registry, args)
        elif command == "disposition":
            with HomeLock(home):
                exit_code, result = cmd_disposition(home, registry, args)
        elif command == "trigger":
            exit_code, result = cmd_trigger(home, registry)
        elif command == "sessions":
            exit_code, result = cmd_sessions(home, registry, args)
        elif command == "evidence":
            exit_code, result = cmd_evidence(home, registry, args)
        else:
            exit_code, result = cmd_next(home, registry)
    except PalError as exc:
        # The documented exit contract is code-driven, not call-site driven: a
        # USAGE refusal raised inside a subcommand is still a usage error, and a
        # caller scripting `saipal` must not have to know which layer raised it.
        if exc.code == "NO_HOME":
            code = EXIT_NO_HOME
        elif exc.code == "USAGE":
            code = EXIT_USAGE
        else:
            code = EXIT_REFUSED
        return emit_refusal(exc, as_json=options.as_json, exit_code=code)

    return emit(result, as_json=options.as_json) if exit_code == EXIT_OK else exit_code


def _smoke() -> None:
    """`python tools/saipal.py` with no arguments runs one cycle and exits."""
    sys.exit(main())


if __name__ == "__main__":
    _smoke()
