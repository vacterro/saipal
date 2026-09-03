from __future__ import annotations

import json
from pathlib import Path

from .capability import require_action
from .errors import PalError
from .paths import atomic_write_json, home_paths, read_json

CONFIG_NAME = "config.json"
PUBLICATION_MODES = ("STAGE_ONLY", "PUBLISH_ENABLED", "PUBLISH_BLOCKED")

#: Roots the operator declares as historical protocol authority. A session's
#: own binding fields select an identity *inside* one of these roots; they never
#: name a filesystem path themselves (PAL-SESSION-03).
AUTHORITY_KEYS = ("git_repository", "release_root", "snapshot_root")


def default_config() -> dict:
    return {
        "schema_version": 1,
        "publication_mode": "STAGE_ONLY",
        "shadow_reviewed": False,
        "sink": {"kind": "termisai-file", "root": None},
        "protocol_authority": {key: None for key in AUTHORITY_KEYS},
    }


def config_path(home: Path | str) -> Path:
    return home_paths(home).root / CONFIG_NAME


def validate_config(payload: object) -> list[str]:
    if not isinstance(payload, dict):
        return ["config root is not an object"]
    problems: list[str] = []
    if payload.get("schema_version") != 1:
        problems.append("schema_version must be 1")
    mode = payload.get("publication_mode")
    if mode not in PUBLICATION_MODES:
        problems.append(f"publication_mode {mode!r} is invalid")
    if not isinstance(payload.get("shadow_reviewed"), bool):
        problems.append("shadow_reviewed must be boolean")
    sink = payload.get("sink")
    if not isinstance(sink, dict) or sink.get("kind") != "termisai-file":
        problems.append("sink.kind must be termisai-file")
    elif sink.get("root") is not None and not isinstance(sink.get("root"), str):
        problems.append("sink.root must be a string or null")
    if mode == "PUBLISH_ENABLED":
        if not payload.get("shadow_reviewed"):
            problems.append("PUBLISH_ENABLED requires shadow_reviewed")
        if not isinstance(sink, dict) or not isinstance(sink.get("root"), str) or not sink["root"].strip():
            problems.append("PUBLISH_ENABLED requires configured sink.root")
    authority = payload.get("protocol_authority")
    if authority is not None:
        if not isinstance(authority, dict):
            problems.append("protocol_authority must be an object or absent")
        else:
            for key in sorted(set(authority) - set(AUTHORITY_KEYS)):
                problems.append(f"protocol_authority has unknown key {key!r}")
            for key in AUTHORITY_KEYS:
                value = authority.get(key)
                if value is not None and not isinstance(value, str):
                    problems.append(f"protocol_authority.{key} must be a string or null")
    return problems


def load_config(home: Path | str) -> tuple[str, dict | None, str]:
    path = config_path(home)
    if not path.exists():
        return "absent", default_config(), ""
    try:
        payload = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return "unrecoverable", None, f"config.json is unreadable: {exc}"
    problems = validate_config(payload)
    if problems:
        return "unrecoverable", None, "; ".join(problems)
    return "ok", payload, ""


def save_config(home: Path | str, payload: dict) -> dict:
    require_action("write_own_index")
    problems = validate_config(payload)
    if problems:
        raise PalError("VALIDATION_FAILED", "refusing invalid config: " + "; ".join(problems))
    path = config_path(home)
    atomic_write_json(path, payload, root=home_paths(home).root)
    return payload


def configured_sink_root(home: Path | str, config: dict | None = None) -> Path | None:
    data = config
    if data is None:
        status, data, detail = load_config(home)
        if status == "unrecoverable":
            raise PalError("VALIDATION_FAILED", detail)
    if not isinstance(data, dict):
        return None
    root = ((data.get("sink") or {}).get("root"))
    return Path(root).expanduser() if isinstance(root, str) and root.strip() else None


def protocol_authority(
    home: Path | str, config: dict | None = None
) -> dict[str, Path | None]:
    """The operator-declared historical protocol authority roots.

    An unset or absent root is `None`, which the historical reader reports as
    `authority not configured` instead of guessing a path. A configured root
    that does not exist stays as declared: the reader refuses it per attempt and
    names the reason, which is more useful than silently dropping it here.
    """
    data = config
    if data is None:
        status, data, detail = load_config(home)
        if status == "unrecoverable":
            raise PalError("VALIDATION_FAILED", detail)
    declared = (data or {}).get("protocol_authority")
    declared = declared if isinstance(declared, dict) else {}
    resolved: dict[str, Path | None] = {}
    for key in AUTHORITY_KEYS:
        value = declared.get(key)
        resolved[key] = (
            Path(value).expanduser() if isinstance(value, str) and value.strip() else None
        )
    return resolved
