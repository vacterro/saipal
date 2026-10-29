#!/usr/bin/env python
"""SAIPAL validator -- the drift gate between protocol, registry and runtime.

It checks the things that rot quietly: a rule that ended up owned by two
documents, an enum value that exists in JSON but nowhere in prose, a document
that outgrew its budget, an error code the runtime invented.

Exit 0 means every check passed.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from saipal_engine.registry import (  # noqa: E402
    load_registry,
    require_mapping,
    require_string_list,
)

MANIFEST_PATH = _ROOT / "saipal" / "MANIFEST.json"
PROTOCOL_DIR = _ROOT / "saipal"
ENGINE_DIR = _HERE / "saipal_engine"

OWNER_RE = re.compile(r"<!--\s*OWNER:\s*([^\s>]+)\s*-->")
RULES_RE = re.compile(r"<!--\s*RULES:\s*([^>]*?)-->")
ENUMS_RE = re.compile(r"<!--\s*ENUMS:\s*([^>]*?)-->")
# Only literals that actually become a refusal code are interesting. Scanning
# every uppercase string would flag `IDLE` and `SAIPAL_HOME` as error codes.
ERROR_RAISE_RE = re.compile(r"PalError\(\s*[\"']([A-Z][A-Z0-9_]{2,})[\"']")
ERROR_COMPARE_RE = re.compile(r"code\s*==\s*[\"']([A-Z][A-Z0-9_]{2,})[\"']")
RULE_FAMILY_RE = re.compile(r"^(PAL(?:-[A-Z]+)+)-\d+$")

# Wave A owns exactly these rule families. A later wave that adds a family
# extends this list in the same commit that adds the rules -- that is the price
# of a guard that can actually fail.
EXPECTED_RULE_FAMILIES = (
    "PAL-BOOT",
    "PAL-ROLE",
    "PAL-WRITE",
    "PAL-BINDING",
    "PAL-EVIDENCE",
    "PAL-ROOTCAUSE",
    "PAL-NOEDIT",
    "PAL-DONOHARM",
    "PAL-OWNERSHIP",
    "PAL-CMD",
    "PAL-SESSION",
    "PAL-FINDING",
    "PAL-AUDIT",
    "PAL-ARCH",
    "PAL-SKILL",
    "PAL-INDEX",
    "PAL-ANALYSIS",
    # T-135: the durable autonomous convergence objective owns its own rules and
    # its own document, rather than adding prose to COMMANDS.md that nothing
    # can enforce.
    "PAL-CPALL",
)

# Modules owned by waves that have not landed yet. A guard that never
# changes is a decoration, so this list shrinks as waves land. The wave guard
# is therefore an `--option` in `check_wave_guards`, not a hard error.
WAVE_FORBIDDEN_MODULES: tuple[str, ...] = ()


class Report:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.checks = 0

    def check(self, condition: bool, name: str, detail: str = "") -> bool:
        self.checks += 1
        if condition:
            print(f"  ok   {name}")
            return True
        self.failures.append(f"{name}: {detail}")
        print(f"  FAIL {name}: {detail}")
        return False

    @property
    def ok(self) -> bool:
        return not self.failures


def _protocols() -> list[Path]:
    return sorted(PROTOCOL_DIR.glob("*.md"))


def _owner_of(path: Path) -> str | None:
    match = OWNER_RE.search(path.read_text(encoding="utf-8"))
    return match.group(1) if match else None


def _rules_of(path: Path) -> list[str]:
    match = RULES_RE.search(path.read_text(encoding="utf-8"))
    if not match:
        return []
    return [item.strip() for item in match.group(1).split(",") if item.strip()]


def _enums_of(path: Path) -> dict[str, list[str]]:
    match = ENUMS_RE.search(path.read_text(encoding="utf-8"))
    if not match:
        return {}
    declared: dict[str, list[str]] = {}
    for chunk in match.group(1).split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        key, values = chunk.split("=", 1)
        declared[key.strip()] = [v.strip() for v in values.split(",") if v.strip()]
    return declared


def check_manifest(report: Report) -> dict:
    print("[manifest]")
    try:
        manifest = _load_json(MANIFEST_PATH)
    except (OSError, ValueError) as exc:
        report.check(False, "manifest loads", str(exc))
        return {}

    report.check(
        manifest.get("kind") == "saipal-runtime-manifest"
        and manifest.get("schema_version") == 1,
        "manifest identity",
        f"unexpected kind/schema in {MANIFEST_PATH}",
    )

    for entry in manifest.get("files", []):
        target = _ROOT / entry["src"]
        exists = target.is_file()
        if entry.get("required", True):
            report.check(exists, f"manifest file {entry['src']}", "missing")
        elif not exists:
            print(f"  skip {entry['src']} (optional, absent)")

    for module in manifest.get("engine_modules", []):
        report.check(
            (ENGINE_DIR.parent / module).is_file(),
            f"engine module {module}",
            "missing",
        )

    for name in manifest.get("managed_dirs", []):
        report.check(
            (_ROOT / name).is_dir(), f"managed dir {name}", "missing or not a directory"
        )
    return manifest


def check_registry(report: Report) -> dict:
    print("[registry]")
    try:
        registry = load_registry(PROTOCOL_DIR)
    except ValueError as exc:
        report.check(False, "registry loads", str(exc))
        return {}

    for key in (
        "rule_owners",
        "enum_owners",
        "shortcuts",
        "commands",
        "write_actions",
        "analyst_actions",
        "state",
        "home_layout",
        "doc_budgets",
        "error_codes",
        "bundle_schema_version",
        "bundle_required_fields",
        "bundle_optional_fields",
        "event_fields",
        "event_types",
        "forbidden_event_keys",
        "protocol_binding_fields",
        "binding_proof_levels",
        "historical_rule_limits",
        "evidence_budgets",
    ):
        report.check(key in registry, f"registry key {key}", "missing")

    if "event_fields" in registry:
        overlap = set(registry["event_fields"]) & set(registry.get("forbidden_event_keys", []))
        report.check(
            not overlap,
            "event fields and forbidden raw-content keys do not overlap",
            f"{sorted(overlap)}",
        )

    if "evidence_budgets" in registry:
        budgets = registry["evidence_budgets"]
        report.check(
            int(budgets.get("max_excerpt_chars", 0)) > 0,
            "excerpt budget is positive",
            "a zero budget would reject every event",
        )

    if "write_actions" in registry:
        actions = registry["write_actions"]
        allowed = set(actions.get("allowed", []))
        reserved = set(actions.get("reserved", []))
        forbidden = set(actions.get("forbidden", []))
        report.check(
            not (allowed & reserved) and not (allowed & forbidden) and not (reserved & forbidden),
            "write action sets are disjoint",
            "an action appears in more than one set",
        )
        report.check(
            bool(allowed) and bool(forbidden),
            "write action sets are non-empty",
            "an empty allowed/forbidden set makes the boundary meaningless",
        )

    if "analyst_actions" in registry and "write_actions" in registry:
        analyst = require_mapping(registry, "analyst_actions")
        analyst_allowed = set(require_string_list(analyst, "allowed"))
        analyst_forbidden = set(require_string_list(analyst, "forbidden"))
        kernel_allowed = set(require_string_list(registry["write_actions"], "allowed"))
        report.check(
            bool(analyst_allowed) and not (analyst_allowed & analyst_forbidden),
            "analyst action sets are non-empty and disjoint",
            "analyst capability namespace overlaps or is empty",
        )
        report.check(
            "submit_candidate" in analyst_allowed
            and "enqueue_audit" in analyst_forbidden
            and "enqueue_audit" not in analyst_allowed,
            "analyst submission is separate from kernel audit enqueue",
            "Layer B must submit candidates and must never enqueue audits directly",
        )
        report.check(
            not (analyst_allowed & kernel_allowed),
            "analyst has zero direct kernel write actions",
            f"overlap={sorted(analyst_allowed & kernel_allowed)}",
        )

    if "home_layout" in registry:
        for name in require_string_list(registry, "home_layout"):
            report.check(
                name and ".." not in Path(name).parts and not Path(name).is_absolute(),
                f"home_layout entry {name!r}",
                "empty, absolute or escaping",
            )
    return registry


def check_rule_ownership(report: Report, registry: dict) -> None:
    print("[rule ownership]")
    owners = require_mapping(registry, "rule_owners")

    declared: dict[str, str] = {}
    duplicates: list[str] = []
    for path in _protocols():
        relative = path.relative_to(_ROOT).as_posix()
        owner = _owner_of(path)
        if not report.check(owner is not None, f"{relative} declares an owner", "no OWNER marker"):
            continue
        if not report.check(
            owner == relative, f"{relative} owner marker matches its path", f"marker says {owner}"
        ):
            continue
        rules = _rules_of(path)
        if not report.check(bool(rules), f"{relative} declares rules", "no RULES marker"):
            continue
        for rule in rules:
            if rule in declared:
                duplicates.append(f"{rule} in {relative} and {declared[rule]}")
            declared[rule] = relative

    report.check(not duplicates, "no rule is declared by two documents", "; ".join(duplicates))
    report.check(
        set(declared) == set(owners),
        "declared rules match registry rule_owners",
        f"only-in-docs={sorted(set(declared) - set(owners))} "
        f"only-in-registry={sorted(set(owners) - set(declared))}",
    )
    mismatched = [
        f"{rule}: docs say {doc}, registry says {owners.get(rule)}"
        for rule, doc in declared.items()
        if owners.get(rule) != doc
    ]
    report.check(
        not mismatched,
        "registry ownership agrees with the documents",
        "; ".join(mismatched),
    )

    unparsed = sorted(rule for rule in owners if not RULE_FAMILY_RE.match(rule))
    report.check(
        not unparsed,
        "every rule id has the form PAL-<FAMILY>-<NN>",
        f"{unparsed}",
    )

    families = {
        match.group(1) for match in (RULE_FAMILY_RE.match(rule) for rule in owners) if match
    }
    unexpected = sorted(families - set(EXPECTED_RULE_FAMILIES))
    report.check(
        not unexpected,
        "no undeclared rule family appeared",
        f"{unexpected}; if a wave added these, extend EXPECTED_RULE_FAMILIES here",
    )


def check_enum_parity(report: Report, registry: dict) -> None:
    print("[enum parity]")
    enum_owners = require_mapping(registry, "enum_owners")

    seen: dict[str, str] = {}
    collisions: list[str] = []
    for path in _protocols():
        relative = path.relative_to(_ROOT).as_posix()
        for key, values in _enums_of(path).items():
            if key in seen:
                collisions.append(f"{key} declared in {relative} and {seen[key]}")
            seen[key] = relative

            if key not in enum_owners:
                report.check(False, f"enum key {key} is known to the registry", "undeclared key")
                continue
            expected = set(require_string_list(registry, key))
            actual = set(values)
            report.check(
                expected == actual,
                f"enum {key} matches {relative}",
                f"only-in-registry={sorted(expected - actual)} "
                f"only-in-doc={sorted(actual - expected)}",
            )

    report.check(not collisions, "no enum key is declared by two documents", "; ".join(collisions))
    missing = sorted(set(enum_owners) - set(seen))
    report.check(not missing, "every registry enum is declared by its owner", f"{missing}")

    for key, owner in enum_owners.items():
        report.check(
            owner in {p.relative_to(_ROOT).as_posix() for p in _protocols()},
            f"enum owner {owner} exists",
            "owner document is missing",
        )


def check_command_parity(report: Report, registry: dict) -> None:
    print("[command parity]")
    commands = require_mapping(registry, "commands")
    saipal_commands = require_string_list(commands, "saipal")
    shortcuts = require_mapping(registry, "shortcuts")

    report.check(bool(saipal_commands), "command list is non-empty", "empty")
    report.check(bool(shortcuts), "shortcut table is non-empty", "empty")

    commands_doc = PROTOCOL_DIR / "COMMANDS.md"
    text = commands_doc.read_text(encoding="utf-8") if commands_doc.is_file() else ""

    for command in saipal_commands:
        report.check(
            bool(re.search(rf"\b{re.escape(command)}\b", text)),
            f"command {command!r} is documented in COMMANDS.md",
            "prose does not mention it",
        )
    for alias, expansion in shortcuts.items():
        parts = expansion.split()
        report.check(
            len(parts) >= 2 and parts[0] == "saipal",
            f"alias {alias!r} expands to a saipal command",
            f"expansion is {expansion!r}",
        )
        report.check(
            bool(re.search(rf"\b{re.escape(alias)}\b", text)),
            f"alias {alias!r} is documented in COMMANDS.md",
            "prose does not mention it",
        )

    carriers = set(require_string_list(registry, "next_carriers"))
    tree = ast.parse((_HERE / "saipal.py").read_text(encoding="utf-8"))
    cmd_next = next(
        (node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "cmd_next"),
        None,
    )
    literals = {
        node.value
        for node in ast.walk(cmd_next) if cmd_next is not None
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    report.check(
        not (carriers & literals),
        "cmd_next has no raw carrier value literals",
        f"raw runtime carriers={sorted(carriers & literals)}",
    )


def check_budgets(report: Report, registry: dict) -> None:
    print("[document budgets]")
    budgets = require_mapping(registry, "doc_budgets")
    for relative, limit in sorted(budgets.items()):
        path = _ROOT / relative
        if not path.is_file():
            report.check(False, f"budgeted doc {relative} exists", "missing")
            continue
        lines = len(path.read_text(encoding="utf-8").splitlines())
        report.check(
            lines <= int(limit),
            f"{relative} within budget",
            f"{lines} lines exceeds the {limit}-line budget",
        )


def check_error_codes(report: Report, registry: dict) -> None:
    print("[error codes]")
    known = set(require_string_list(registry, "error_codes"))
    sources = [_HERE / "saipal.py", _HERE / "validate.py", *_sorted_engine_sources()]

    used: set[str] = set()
    for path in sources:
        text = path.read_text(encoding="utf-8")
        used.update(ERROR_RAISE_RE.findall(text))
        used.update(ERROR_COMPARE_RE.findall(text))

    unknown = sorted(used - known)
    report.check(
        not unknown,
        "every uppercase literal the runtime raises is a registry error code",
        f"{unknown}; add them to REGISTRY.json error_codes or stop raising them",
    )
    report.check(
        bool(known),
        "registry declares error codes",
        "empty error_codes set",
    )


def check_wave_guards(report: Report, registry: dict) -> None:
    print("[wave guards]")
    for name in WAVE_FORBIDDEN_MODULES:
        report.check(
            not (ENGINE_DIR / name).exists(),
            f"no {name} yet",
            "that module belongs to a later wave; update this guard when it lands",
        )

    deferred = require_mapping(registry, "deferred_semantics")
    report.check(
        bool(deferred),
        "deferred semantics name who owns each unimplemented contract",
        "a declared-but-unimplemented contract must say who implements it",
    )
    for wave, rules in deferred.items():
        entry = rules if isinstance(rules, dict) else {"rules": rules}
        for rule in entry.get("rules", []):
            report.check(
                rule in require_mapping(registry, "rule_owners"),
                f"{wave} deferred rule {rule} exists",
                "deferred rule is not in rule_owners",
            )
        introduced = entry.get("introduced_in")
        report.check(
            isinstance(introduced, str) and bool(_VERSION_DIGITS.search(introduced)),
            f"{wave} declares a comparable introduced_in version",
            "a deferred contract needs a real version, or the no-hindsight "
            "gate silently compares against nothing (T-027)",
        )


#: A version a version-comparison can actually use: it holds digits.
_VERSION_DIGITS = re.compile(r"\d")

#: Status claims that were true of an earlier wave and are false now. The
#: validator cannot judge prose in general, so it rejects exactly the phrases
#: that have shipped as lies -- each one was live in a loaded protocol document
#: while the runtime it described was fully implemented (T-026).
STALE_STATUS_MARKERS: tuple[str, ...] = (
    "wave a status",
    "wave b status",
    "wave c status",
    "wave d status",
    "wave e status",
    "implementation owner: wave",
    "no constrained enqueue api exists yet",
    "is reserved for wave",
    "belongs to wave",
    "no candidate, finding or classifier exists",
    "no detector runs",
    "no audit is emitted",
    "deferred surface",
    "generic` in v1",
)

STALE_RUNTIME_MARKERS: tuple[str, ...] = (
    "owned by wave",
    "belongs to wave",
    "wave has not defined",
)


def check_status_freshness(report: Report) -> None:
    """A loaded protocol document may not claim the runtime is unbuilt.

    `saipal/*.md` is what an agent reads to decide what exists. A stale
    "Wave B status: no detector runs" there is worse than silence: it tells a
    conformant reader to skip a surface that is live. Historical checkpoints
    outside `saipal/` are explicitly exempt -- they are archaeology, and
    labelling them is the point.
    """
    print("[status freshness]")
    for path in _protocols():
        lowered = path.read_text(encoding="utf-8").lower()
        found = [marker for marker in STALE_STATUS_MARKERS if marker in lowered]
        report.check(
            not found,
            f"{path.name} carries no stale wave-status claim",
            f"stale status claim(s): {', '.join(found)}",
        )

    runtime_paths = [_HERE / "saipal.py", *_sorted_engine_sources()]
    for path in runtime_paths:
        lowered = path.read_text(encoding="utf-8").lower()
        found = [marker for marker in STALE_RUNTIME_MARKERS if marker in lowered]
        report.check(
            not found,
            f"{path.relative_to(_ROOT).as_posix()} carries no stale wave-status string",
            f"stale runtime status claim(s): {', '.join(found)}",
        )


def check_verification_truth(report: Report) -> None:
    """T-120: test/validator counts have exactly one sourced truth.

    Test counts are not collectibles: a number copied into several documents
    rots independently in each (README once claimed 970 while the real suite
    had grown past it, and founding checkpoints carried 225/241 as if current).
    The contract: `WAVE_I_CHECKPOINT.md` owns the **Current verification truth**
    block, stamped with a `checkpoint_id`; every other document either carries
    NO unittest/validator count or names the checkpoint id it repeats.
    """
    print("[verification truth]")
    checkpoint_path = _ROOT / "WAVE_I_CHECKPOINT.md"
    if not checkpoint_path.is_file():
        report.check(False, "checkpoint owns the verification truth", "WAVE_I_CHECKPOINT.md is missing")
        return
    checkpoint_text = checkpoint_path.read_text(encoding="utf-8")
    has_truth_block = "## Current verification truth" in checkpoint_text
    has_id = bool(re.search(r"checkpoint_id:\s*\S+", checkpoint_text))
    has_counts = bool(
        re.search(r"unittest_cases:\s*\d+", checkpoint_text)
        and re.search(r"validator_checks:\s*\d+", checkpoint_text)
    )
    report.check(
        has_truth_block and has_id and has_counts,
        "WAVE_I_CHECKPOINT.md carries the checkpointed verification truth",
        "needs a 'Current verification truth' block with checkpoint_id + counts",
    )
    checkpoint_id = ""
    match = re.search(r"checkpoint_id:\s*(\S+)", checkpoint_text)
    if match:
        checkpoint_id = match.group(1)

    import unittest

    discovered_cases = (
        unittest.TestLoader()
        .discover(str(_ROOT / "tools"), pattern="test_*.py")
        .countTestCases()
    )
    cases_match = re.search(r"unittest_cases:\s*(\d+)", checkpoint_text)
    recorded_cases = int(cases_match.group(1)) if cases_match else None
    report.check(
        recorded_cases == discovered_cases,
        f"WAVE_I_CHECKPOINT.md unittest_cases matches discovery ({discovered_cases})",
        f"checkpoint claims {recorded_cases}, discovery found {discovered_cases}",
    )

    has_win_decl = bool(re.search(r"Windows.*:\s*(?:EXECUTED|VERIFIED)", checkpoint_text, re.I))
    has_posix_decl = bool(re.search(r"POSIX:\s*(?:NOT EXECUTED|UNVERIFIED|EXECUTED|VERIFIED)", checkpoint_text, re.I))
    report.check(
        has_win_decl and has_posix_decl,
        "WAVE_I_CHECKPOINT.md declares explicit platform executions for Windows and POSIX",
        "missing explicit platform_executions declaration for Windows or POSIX",
    )
    if "POSIX: NOT EXECUTED" in checkpoint_text or "POSIX: UNVERIFIED" in checkpoint_text:
        report.check(
            "POSIX fully race-closed" not in checkpoint_text,
            "WAVE_I_CHECKPOINT.md does not claim 'POSIX fully race-closed' when unexecuted",
            "falsely claims 'POSIX fully race-closed' when POSIX was not executed",
        )

    # Any other repo document that quotes suite counts must name the same
    # checkpoint identity. Audits under docs/audits/ are exempt: they are
    # dated external artifacts, archaeology by definition.
    counted = re.compile(r"(\d[\d,]*)\s*(unittest cases|unit tests|validator checks)", re.I)
    for path in sorted(_ROOT.glob("*.md")) + sorted((_ROOT / "saipal").glob("*.md")):
        if path.name == "WAVE_I_CHECKPOINT.md":
            continue
        text = path.read_text(encoding="utf-8")
        if path.name == "README.md":
            # README may repeat counts only WITH the checkpoint identity line.
            for occurrence in counted.finditer(text):
                report.check(
                    checkpoint_id and checkpoint_id in text,
                    f"{path.name} count carries the checkpoint identity",
                    f"count {occurrence.group(0)!r} without checkpoint_id {checkpoint_id!r}",
                )
            report.check(
                "Current verification truth" in text
                or counted.search(text) is None,
                f"{path.name} points at the canonical verification truth",
                "carries a count with no source",
            )
        else:
            hits = [occurrence.group(0) for occurrence in counted.finditer(text)]
            stale = [
                hit for hit in hits
                if not (checkpoint_id and checkpoint_id in text)
            ]
            report.check(
                not stale,
                f"{path.name} carries no unsourced verification counts",
                f"counts without the {checkpoint_id!r} identity: {', '.join(stale)}",
            )


# --------------------------------------------------------------------------- #
# closure chain (SRC-006 / the T-125 gap)
# --------------------------------------------------------------------------- #
#
# The defect class this section ends, measured on this project's own memory:
# T-125 reached `## DONE` with `closure_mode`, `owner`, `claim_time` and
# mechanized events -- everything the field-based lifecycle repair looks at --
# while its LOG carried NO canonical finish record at all. The phase chain
# stopped at VERIFY; REVIEW and SHIP were never entered. Nothing caught it:
#
#   * `[saio]` flags structural-marker TEXT without an `[op: ...]` slot, and the
#     hand-written records that closed it carried a plain `DEC:`/`RUN:` text;
#   * the SAIOPS `[gate-closure]` check inspects EXISTING finish events, so a
#     closure with no finish event has nothing to inspect;
#   * the lifecycle repair planner reads BOARD FIELDS, which were present.
#
# So the missing control is about the CHAIN, not the fields: a `## DONE` record
# of the generation the closure contract governs must carry its own canonical
# closure chain -- a `ticket finished via SAIOPS -- completion (from SHIP)`
# record -- or an explicit, append-only attestation saying it did not.
#
# SCOPE is the protocol's own frontier, never a new invention: the lowest
# ticket number on BOARD that carries `closure_mode` is the point from which
# the closure contract was observable, and anything below it is LEGACY and
# exempt (its grammar did not exist yet). When no record carries
# `closure_mode` at all, the fallback is the operation layer's own marker: a
# ticket that never appears on an `[op: ...]` event predates it.
#
# REPAIR (decided here, and the reason this check has a second legal shape): a
# closure gap is repaired by an APPEND-ONLY ATTESTATION, never by synthesizing
# the missing gate. It must name the ticket, state the chain that was actually
# reached, and declare the record historical evidence rather than gate proof.
# A current-generation gap whose consequences are material additionally owes a
# corrective successor (T-125's is T-127, bound to source receipt SRC-006).
# SAIOPS' own `recover --attest-legacy-done` route covers LEGACY-generation
# records only, so this attestation is written under the documented OPS
# fallback and records why. No phase event, no `closure_mode` and no historical
# LOG line is ever created or rewritten to close a gap: an attestation that
# manufactured gate proof would be the very laundering it exists to prevent.
#
# WHY THE TWO EXISTING MECHANISMS CANNOT SEE IT, stated as the code states it:
#
#   * the skill's `[gate-closure]` check (T-602) regexes FINISH EVENTS that
#     exist and fails a non-SHIP one after its self-establishing boundary. A
#     record with NO finish event hands it an empty set to inspect, so absence
#     is invisible to it -- the complement of this check, not a duplicate;
#   * the skill's lifecycle repair planner (reconcile.py) judges FIELDS: it
#     reopens a `## DONE` row only when it carries no `closure_mode`, no
#     `owner`, no `claim_time` and no verification evidence. T-125 carries all
#     four, so it is skipped before its history is ever read. Fields present is
#     not a chain, and that difference is this section's whole subject.
#
# The repair record's CONTRACT, enforced below rather than trusted: anchored
# `DEC` text beginning `closure-chain-gap attested for`, naming the gap it
# answers, carrying the disclaimer `not gate proof`, and naming only Work that
# exists on BOARD (so a gap is docked to a real corrective successor instead of
# to prose). It is written in the engine's own attested-DEC shape, which is why
# `saipen validate` and the `[saio]` provenance rule both keep passing over it.

#: The canonical finish record the operation layer writes. Because
#: `finish_ticket` REFUSES every non-SHIP closure, the phase this names IS the
#: gate proof, and its absence is the gap.
CLOSURE_FINISH_MARKER = "ticket finished via SAIOPS"
CLOSURE_SHIP_EDGE = "(from SHIP)"

#: The machine prefix of the append-only repair record.
CLOSURE_ATTESTATION_PREFIX = "closure-chain-gap attested for"

#: A repair record must DISCLAIM gate authority IN ITS OWN TEXT. An attestation
#: that reads like a completion is the laundering this route exists to prevent,
#: so the disclaimer is part of the record's contract rather than its prose, and
#: the audit fails a record that omits it.
CLOSURE_ATTESTATION_DISCLAIMER = "not gate proof"

_LOG_EVENT_RE = re.compile(r"^\s*-\s+\S+\s+\S+\s+\[E-(\d+)\](?P<rest>.*)$")
_LOG_TICKET_RE = re.compile(r"\[(T-\d+)\]")
_LOG_OP_RE = re.compile(r"\[op:\s*([^\]]+)\]")
_LOG_LEAD_SLOT_RE = re.compile(r"\s*\[[^\]]*\]")
_LOG_TAXONOMY_RE = re.compile(r"\s*([A-Z]{3,8}):\s?(?P<text>.*)$", re.S)
_BOARD_DONE_ROW_RE = re.compile(r"^-\s*\[([ x/])\]\s+(T-\d+)(?P<fields>.*)$")
_CLOSURE_MODE_RE = re.compile(r"\bclosure_mode\s*:\s*\S+")
_LOG_TRANSITION_RE = re.compile(r"\btransition to ([A-Z][A-Z0-9_]*)")
_LOG_PHASE_EDGE_RE = re.compile(r"\(from ([A-Z][A-Z0-9_]*)\)")
_LOG_ANY_TICKET_RE = re.compile(r"\bT-\d+\b")


def _log_records(log_text: str) -> list[dict]:
    """Parse the append-only LOG into `{event, ticket, op_id, taxonomy, text}`.

    Deliberately structural-only: an unparseable line is skipped rather than
    guessed at, because this audit must never manufacture a chain out of prose.
    """
    records: list[dict] = []
    for raw in log_text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _LOG_EVENT_RE.match(line)
        if not match:
            continue
        rest = match.group("rest")
        ticket = _LOG_TICKET_RE.search(rest)
        op = _LOG_OP_RE.search(rest)
        body = rest
        while True:
            slot = _LOG_LEAD_SLOT_RE.match(body)
            if not slot:
                break
            body = body[slot.end() :]
        taxonomy = _LOG_TAXONOMY_RE.match(body)
        records.append(
            {
                "event": int(match.group(1)),
                "ticket": ticket.group(1) if ticket else None,
                "op_id": op.group(1) if op else None,
                "taxonomy": taxonomy.group(1) if taxonomy else None,
                "text": (taxonomy.group("text") if taxonomy else body).strip(),
            }
        )
    return records


def _board_rows(board_text: str, section_name: str | None = None) -> list[tuple[str, str]]:
    """`(ticket, row_fields)` for every BOARD row under one section.

    `section_name=None` means every section: a repair record may name Work that
    is not itself closed, and a reference is checked against the whole BOARD.
    """
    rows: list[tuple[str, str]] = []
    section = None
    for line in board_text.splitlines():
        if line.startswith("## "):
            section = line.strip()
            continue
        match = _BOARD_DONE_ROW_RE.match(line)
        if match and (section_name is None or section == section_name):
            rows.append((match.group(2), match.group(3)))
    return rows


def closure_chain_report(board_text: str, log_text: str) -> dict:
    """Audit every `## DONE` record of the governed generation for its chain.

    Returns `{frontier, judged, closed, unattested, attested, stale, legacy,
    rows, events}`:

    * `judged` -- DONE records at/above the closure-contract frontier;
    * `closed` -- judged records with a canonical `(from SHIP)` finish record;
    * `unattested` -- judged records with NO closure chain and no attestation
      (the defect class, and the only state this audit must fail);
    * `attested` -- `{ticket: {event, declares_historical_evidence, names}}`
      for gaps whose append-only repair record exists;
    * `stale` -- repair records answering no gap: a record that is not governed
      here, or one that has since closed properly (drift);
    * `undeclared` -- repair records that do not disclaim gate authority;
    * `phantom_refs` -- tickets a repair record names that are on no BOARD row;
    * `chains` -- `{ticket: [PHASE, ...]}`, the phase chain the LOG proves;
    * `legacy` -- records below the frontier, exempt and counted, never ignored.
    """
    records = _log_records(log_text)
    rows = _board_rows(board_text, "## DONE")
    board_ids = {ticket for ticket, _fields in _board_rows(board_text)}

    modes = [ticket for ticket, fields in rows if _CLOSURE_MODE_RE.search(fields)]
    frontier = min((int(ticket[2:]) for ticket in modes), default=None)
    mechanized = {
        record["ticket"]
        for record in records
        if record["ticket"] and record["op_id"]
    }

    def governed(ticket: str) -> bool:
        if not (ticket.startswith("T-") and ticket[2:].isdigit()):
            return False
        if frontier is not None:
            return int(ticket[2:]) >= frontier
        # No record carries closure_mode: the operation layer's own marker is
        # the boundary, and anything it never touched is LEGACY.
        return ticket in mechanized

    def note_phase(ticket: str, phase: str) -> None:
        phases = chains.setdefault(ticket, [])
        if phase not in phases:
            phases.append(phase)

    #: The phase chain the LOG actually proves, per ticket: a recorded
    #: transition, or the phase a canonical finish record closed FROM. This is
    #: what makes the failure detail say where the chain STOPPED rather than
    #: only that it did.
    chains: dict[str, list[str]] = {}

    #: ticket -> (has_a_finish_record, has_a_SHIP_finish_record). A finish
    #: record from any OTHER phase is not a chain either: it is the recorded
    #: skipped-gate closure this audit exists to surface. Anchored on the `DEC`
    #: taxonomy because authority belongs to the record type that carries it --
    #: a `RUN` reporting a completion is not one.
    finished: dict[str, list[bool]] = {}
    for record in records:
        ticket = record["ticket"]
        if not ticket:
            continue
        transition = _LOG_TRANSITION_RE.search(record["text"])
        if transition:
            note_phase(ticket, transition.group(1))
        if record["taxonomy"] != "DEC":
            continue
        text = record["text"]
        if not text.startswith(CLOSURE_FINISH_MARKER):
            continue
        entry = finished.setdefault(ticket, [True, False])
        entry[0] = True
        edge = _LOG_PHASE_EDGE_RE.search(text)
        if edge:
            note_phase(ticket, edge.group(1))
        if CLOSURE_SHIP_EDGE in text:
            entry[1] = True

    attestations: dict[str, dict] = {}
    for record in records:
        text = record["text"]
        if record["taxonomy"] != "DEC":
            continue
        if not text.startswith(CLOSURE_ATTESTATION_PREFIX):
            continue
        named = set(_LOG_ANY_TICKET_RE.findall(text))
        subject = record["ticket"]
        if subject is None and named:
            subject = sorted(named, key=lambda ticket: int(ticket[2:]))[0]
        if subject is None:
            continue
        named.discard(subject)
        attestations[subject] = {
            "event": record["event"],
            "declares_historical_evidence": CLOSURE_ATTESTATION_DISCLAIMER in text,
            "names": sorted(named, key=lambda ticket: int(ticket[2:])),
        }

    judged, closed, unattested, attest, legacy = [], [], [], {}, []
    for ticket, _fields in rows:
        if not governed(ticket):
            legacy.append(ticket)
            continue
        judged.append(ticket)
        _has_finish, has_ship = finished.get(ticket, [False, False])
        if has_ship:
            closed.append(ticket)
            continue
        if ticket in attestations:
            attest[ticket] = attestations[ticket]
        else:
            unattested.append(ticket)

    #: A repair record that answers NO gap is drift, in either direction: it
    #: names a record this audit does not govern, or a record that has since
    #: closed properly. Both are stale, and neither may be silently ignored.
    stale = sorted(
        t
        for t in attestations
        if t not in judged or finished.get(t, [False, False])[1]
    )
    undeclared = sorted(
        t for t, record in attestations.items() if not record["declares_historical_evidence"]
    )
    phantom_refs = sorted(
        {
            named
            for record in attestations.values()
            for named in record["names"]
            if named not in board_ids
        },
        key=lambda ticket: int(ticket[2:]),
    )
    return {
        "frontier": frontier,
        "judged": judged,
        "closed": closed,
        "unattested": unattested,
        "attested": attest,
        "stale": stale,
        "undeclared": undeclared,
        "phantom_refs": phantom_refs,
        "chains": chains,
        "legacy": legacy,
        "rows": [ticket for ticket, _fields in rows],
        "events": len(records),
    }


def check_closure_chain(report: Report) -> None:
    """A `## DONE` record owes its own closure chain -- or an honest attestation.

    Applied to THIS checkout's project memory when it is present (`.saipen/` is
    local state and is not part of a clean clone, so there is nothing to audit
    there and the section says so instead of passing silently).
    """
    print("[closure chain]")
    board_path = _ROOT / ".saipen" / "BOARD.md"
    log_path = _ROOT / ".saipen" / "LOG.md"
    if not (board_path.is_file() and log_path.is_file()):
        report.check(
            True,
            "no .saipen project memory in this checkout (closure-chain audit not applicable)",
            "",
        )
        return
    audit = closure_chain_report(
        board_path.read_text(encoding="utf-8"),
        log_path.read_text(encoding="utf-8"),
    )
    report.check(
        not audit["unattested"],
        "every current-generation ## DONE record carries its own closure chain",
        "closed with no SHIP finish record and no attestation: "
        + ", ".join(
            f"{ticket} (phase chain: "
            + (" > ".join(audit["chains"].get(ticket) or ()) or "no transition recorded")
            + ")"
            for ticket in audit["unattested"]
        )
        + " (repair with an append-only `"
        + CLOSURE_ATTESTATION_PREFIX
        + f"` record that says it is {CLOSURE_ATTESTATION_DISCLAIMER}, or reopen "
        "it -- never by synthesizing the missing gate)",
    )
    accounted = len(audit["judged"]) + len(audit["legacy"])
    report.check(
        accounted == len(audit["rows"]),
        "the closure-chain audit accounts for every ## DONE record",
        f"{accounted} of {len(audit['rows'])} rows classified",
    )
    report.check(
        not audit["stale"],
        "every closure-chain attestation answers a real gap",
        "attestation names a record with no closure gap (drift to clean): "
        + ", ".join(audit["stale"]),
    )
    report.check(
        not audit["undeclared"],
        "every closure-chain attestation disclaims gate authority",
        f"repair record does not say it is {CLOSURE_ATTESTATION_DISCLAIMER}: "
        + ", ".join(audit["undeclared"]),
    )
    report.check(
        not audit["phantom_refs"],
        "every ticket a closure-chain attestation names exists on BOARD",
        "repair record names Work that is on no BOARD row: "
        + ", ".join(audit["phantom_refs"]),
    )
    if audit["attested"]:
        print(
            "  note attested closure-chain gaps (historical evidence, never "
            "gate proof): "
            + ", ".join(
                f"{ticket} (E-{record['event']})"
                + (f" -> corrective successor {', '.join(record['names'])}" if record["names"] else "")
                for ticket, record in sorted(audit["attested"].items())
            )
        )


def check_law_coverage(report: Report, registry: dict) -> None:
    """Every drift class the taxonomy declares resolves to a real owner.

    A class with no law entry raises `UNKNOWN_DRIFT_CLASS`, which the pipeline
    swallows into `rule_ids: []` -- a finding with no rule behind it, from a
    class the taxonomy promised to cover (T-028).
    """
    print("[law coverage]")
    from saipal_engine import law as law_mod

    surface = law_mod.load_law_surface(registry=registry)
    taxonomy = require_string_list(registry, "drift_taxonomy")
    missing = [name for name in taxonomy if name not in surface]
    report.check(
        not missing,
        "every drift class has a law entry",
        f"no law entry for: {', '.join(missing)}",
    )
    owners = require_mapping(registry, "rule_owners")
    orphan_rules: list[str] = []
    for drift_class, entry in surface.items():
        for rule in entry.get("rule_ids", []):
            if rule not in owners:
                orphan_rules.append(f"{drift_class}:{rule}")
    report.check(
        not orphan_rules,
        "every law rule id has an owner document",
        f"rule without an owner: {', '.join(orphan_rules)}",
    )


def _sorted_engine_sources() -> list[Path]:
    return sorted(ENGINE_DIR.glob("*.py"))


def _load_json(path: Path) -> dict:
    import json

    return dict(json.loads(path.read_text(encoding="utf-8-sig")))


def main(argv: list[str] | None = None) -> int:
    quiet = "--quiet" in (argv or [])
    report = Report()

    manifest = check_manifest(report)
    registry = check_registry(report)

    if registry:
        check_rule_ownership(report, registry)
        check_enum_parity(report, registry)
        check_command_parity(report, registry)
        check_budgets(report, registry)
        check_error_codes(report, registry)
        check_wave_guards(report, registry)
        check_law_coverage(report, registry)
        check_status_freshness(report)
        check_verification_truth(report)
    else:
        report.check(False, "registry-driven checks ran", "registry did not load")

    check_closure_chain(report)

    if quiet:
        return 0 if report.ok else 1

    print()
    if report.ok:
        print(f"SAIPAL is conformant: {report.checks} checks passed.")
        return 0
    print(f"SAIPAL is NOT conformant: {len(report.failures)} of {report.checks} checks failed.")
    for failure in report.failures:
        print(f"  - {failure}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
