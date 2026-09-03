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
    else:
        report.check(False, "registry-driven checks ran", "registry did not load")

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
