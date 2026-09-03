"""Configured external evidence sources."""

from __future__ import annotations

from pathlib import Path

from .capability import require_action
from .errors import PalError
from .paths import atomic_write_json, home_paths, read_json
from .adapters import ADAPTER_REGISTRY

SOURCES_OK = "ok"
SOURCES_ABSENT = "absent"
SOURCES_UNRECOVERABLE = "unrecoverable"

SOURCE_DISABLED = "DISABLED"


def empty_sources() -> dict:
    return {"schema_version": 1, "sources": []}


def validate_sources(payload: object) -> list[str]:
    """Every reason the registry is unusable, or an empty list."""
    if not isinstance(payload, dict):
        return ["sources root is not an object"]

    problems: list[str] = []
    if payload.get("schema_version") != 1:
        problems.append(
            f"schema_version {payload.get('schema_version')!r} != 1"
        )

    sources = payload.get("sources")
    if not isinstance(sources, list):
        return problems + ["sources must be an array"]

    seen: set[str] = set()
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            problems.append(f"sources[{index}] is not an object")
            continue
        for field in ("id", "kind", "path"):
            value = source.get(field)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"sources[{index}].{field} must be a non-empty string")
        if not isinstance(source.get("enabled"), bool):
            problems.append(f"sources[{index}].enabled must be a boolean")
        identifier = source.get("id")
        if isinstance(identifier, str):
            if identifier in seen:
                problems.append(f"duplicate source id {identifier!r}")
            seen.add(identifier)
    return problems


def load_sources(home: Path | str) -> tuple[str, dict | None, str]:
    """`(status, payload, detail)` where status is ok / absent / unrecoverable."""
    paths = home_paths(home)
    if not paths.sources.exists():
        return SOURCES_ABSENT, None, ""

    try:
        payload = read_json(paths.sources)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return SOURCES_UNRECOVERABLE, None, f"sources.json is unreadable: {exc}"

    problems = validate_sources(payload)
    if problems:
        return SOURCES_UNRECOVERABLE, None, "; ".join(problems)
    return SOURCES_OK, payload, ""


def save_sources(home: Path | str, payload: dict) -> dict:
    require_action("write_own_index")
    problems = validate_sources(payload)
    if problems:
        raise PalError(
            "INVALID_SOURCE_REGISTRY",
            "refusing to write an invalid source registry: " + "; ".join(problems),
            next_action="the existing sources.json was left untouched",
        )
    paths = home_paths(home)
    atomic_write_json(paths.sources, payload, root=paths.root)
    return payload


def discover(home: Path | str, *, auto: bool = False) -> list[dict]:
    """Report configured sources without normalizing any of them.

    Existence of the source path is an observable fact SAIPAL may record;
    provider adapters own deeper source parsing.

    With `auto=True` and no configured sources, known agent session homes
    (opencode) are reported as auto-discovered candidates. The caller decides
    whether that is appropriate; `continue` enables it only for the default
    tool-root home so isolated deployments never reach live agent stores.
    """
    status, payload, _detail = load_sources(home)
    if status == SOURCES_UNRECOVERABLE:
        raise PalError(
            "INVALID_SOURCE_REGISTRY",
            "sources.json is unusable; refusing to guess which sources exist",
            next_action="repair sources.json by hand, then run `saipal continue`",
        )
    if status == SOURCES_ABSENT or not payload:
        return auto_sources() if auto else []

    found: list[dict] = []
    for source in payload["sources"]:
        enabled = bool(source["enabled"])
        path = Path(source["path"]).expanduser()
        kind = source["kind"]
        if not enabled:
            status = SOURCE_DISABLED
        elif kind not in ADAPTER_REGISTRY:
            status = "UNSUPPORTED_ADAPTER"
        elif not path.exists():
            status = "UNAVAILABLE"
        else:
            status = "READY"
        found.append(
            {
                "id": source["id"],
                "kind": kind,
                "path": str(path),
                "enabled": enabled,
                "exists": path.exists(),
                "status": status,
                "sessions": 0,
            }
        )
    if not found and auto:
        found.extend(auto_sources())
    return found


def auto_sources() -> list[dict]:
    """Auto-discover known agent session homes when nothing is configured.

    Read-only discovery: the opencode data home is located on disk and reported
    as a candidate source; the caller (continue) may dispatch it, but this
    function never writes `sources.json`.
    """
    out: list[dict] = []
    try:
        from .adapters.opencode import find_home as find_opencode_home

        home = find_opencode_home()
        if home is not None:
            out.append(
                {
                    "id": "opencode-auto",
                    "kind": "opencode",
                    "path": str(home),
                    "enabled": True,
                    "exists": True,
                    "status": "READY",
                    "sessions": 0,
                    "auto": True,
                }
            )
    except (OSError, ValueError, ImportError):
        pass
    return out
