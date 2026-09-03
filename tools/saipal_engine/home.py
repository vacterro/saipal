"""Materializing the runtime home.

The home layout is declared in REGISTRY.json `home_layout` and owned here, so
there is exactly one place that decides which directories exist.
"""

from __future__ import annotations

from pathlib import Path

from .capability import require_action
from .paths import atomic_write_bytes, atomic_write_json, home_paths
from .registry import load_registry, require_string_list
from .sources import empty_sources
from .config import default_config, config_path
from .state import STATE_ABSENT, fresh_state, load_state, save_state


def layout_dirs(registry: dict | None = None) -> tuple[str, ...]:
    data = registry if registry is not None else load_registry()
    return require_string_list(data, "home_layout")


def missing_dirs(home: Path | str, *, registry: dict | None = None) -> list[str]:
    root = Path(home)
    return [name for name in layout_dirs(registry) if not (root / name).is_dir()]


def ensure_home(home: Path | str, *, registry: dict | None = None) -> dict:
    """Create the home and its declared layout. Idempotent.

    Returns what it created, so a caller can log a real first-run event instead
    of a decorative one.
    """
    require_action("write_own_index", registry=registry)
    data = registry if registry is not None else load_registry()

    paths = home_paths(home)
    created_dirs: list[str] = []
    created_files: list[str] = []

    paths.root.mkdir(parents=True, exist_ok=True)
    paths.locks.mkdir(parents=True, exist_ok=True)
    for name in layout_dirs(data):
        target = paths.root / name
        if not target.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            created_dirs.append(name)

    if not paths.log.exists():
        require_action("write_own_log", registry=data)
        atomic_write_bytes(paths.log, b"", root=paths.root)
        created_files.append("LOG.jsonl")

    if not paths.sources.exists():
        atomic_write_json(paths.sources, empty_sources(), root=paths.root)
        created_files.append("sources.json")
    if not config_path(paths.root).exists():
        atomic_write_json(config_path(paths.root), default_config(), root=paths.root)
        created_files.append("config.json")

    status, _state, _detail = load_state(paths.root, registry=data)
    if status == STATE_ABSENT:
        save_state(paths.root, fresh_state(registry=data), registry=data)
        created_files.append("STATE.json")

    return {"created_dirs": created_dirs, "created_files": created_files}
