"""Command surface, aliases and argv parsing (PAL-CMD-01).

Aliases live in REGISTRY.json, never in prose. A shortcut resolves to a
canonical command before dispatch; a shortcut is a command, not a greeting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import PalError
from .registry import load_registry, require_mapping, require_string_list

PROGRAM = "saipal"


def load_shortcut_table(protocol_dir: str | None = None) -> dict[str, str]:
    """`{"cc": "saipal continue"}`. A missing registry folds to an empty table."""
    try:
        registry = load_registry(protocol_dir)
    except ValueError:
        return {}
    try:
        return {str(k): str(v) for k, v in require_mapping(registry, "shortcuts").items()}
    except ValueError:
        return {}


def resolve_shortcut(
    token: str, *, table: dict[str, str] | None = None
) -> str | None:
    table = load_shortcut_table() if table is None else table
    return table.get(str(token).strip())


def available_commands(registry: dict | None = None) -> tuple[str, ...]:
    data = registry if registry is not None else load_registry()
    commands = require_mapping(data, "commands")
    return require_string_list(commands, PROGRAM)


@dataclass
class Options:
    """Global flags, consumed before any command dispatch."""

    as_json: bool = False
    home: str | None = None
    show_help: bool = False
    show_version: bool = False
    rest: list[str] = field(default_factory=list)


def parse_args(argv: list[str]) -> Options:
    """Split global flags from the command. Raises `PalError(USAGE)` on garbage.

    Global flags (`--json`, `--home`, `--help`, `--version`) are consumed before
    the command word. Everything from the first positional onward is the command
    and its own arguments, passed through verbatim so subcommands like `setup`
    can own their options.
    """
    options = Options()
    positional: list[str] = []
    index = 0
    total = len(argv)

    while index < total:
        token = argv[index]
        if positional:
            positional.append(token)
            index += 1
            continue
        if token == "--":
            positional.extend(argv[index + 1 :])
            break
        if token == "--json":
            options.as_json = True
        elif token == "--home":
            if index + 1 >= total:
                raise PalError("USAGE", "--home requires a path")
            options.home = argv[index + 1]
            index += 1
        elif token.startswith("--home="):
            options.home = token.split("=", 1)[1]
        elif token in ("-h", "--help"):
            options.show_help = True
        elif token in ("--version", "-V"):
            options.show_version = True
        elif token.startswith("-") and token != "-":
            raise PalError("USAGE", f"unknown option {token!r}")
        else:
            positional.append(token)
        index += 1

    if positional and resolve_shortcut(positional[0]):
        expansion = resolve_shortcut(positional[0]) or ""
        parts = [part for part in expansion.split() if part]
        if parts and parts[0] == PROGRAM:
            parts = parts[1:]
        positional = parts + positional[1:]

    options.rest = positional
    return options


def command_of(argv: list[str]) -> tuple[str | None, list[str]]:
    """`(command, args)` after alias resolution."""
    options = parse_args(argv)
    if not options.rest:
        return None, []
    return options.rest[0], options.rest[1:]


def usage_text(registry: dict | None = None) -> str:
    commands = ", ".join(available_commands(registry))
    aliases = ", ".join(sorted(load_shortcut_table()))
    return (
        f"usage: {PROGRAM} [--json] [--home PATH] <command>\n"
        f"commands: {commands}\n"
        f"aliases: {aliases}\n"
        f"bare `{PROGRAM}` means `{PROGRAM} continue`\n"
    )


def refusal_payload(error: PalError) -> dict[str, Any]:
    return {
        "ok": False,
        "code": error.code,
        "message": error.message,
        "next_action": error.next_action,
    }
