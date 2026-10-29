"""Materializing the runtime home.

The home layout is declared in REGISTRY.json `home_layout` and owned here, so
there is exactly one place that decides which directories exist.

PAL-WRITE-01 (T-125, Defect E): home materialization itself has a safe
root-establishment contract. The previous implementation did
`paths.root.mkdir(parents=True, exist_ok=True)` and then created every child
directory through the path -- so when the requested home was a symlink or
junction to an external directory, ALL of those child directories were
created OUTSIDE the intended root before the later guarded file write
finally refused. A refusal must produce ZERO external mutations:

  1. the requested root is refused outright if it exists as a
     symlink/junction/reparse point (never followed, never descended);
  2. the physical root is established through `confined_mkdir` (POSIX: the
     parent is held as a verified directory fd; Windows: the chain is
     reparse-verified before the mkdir);
  3. every declared child directory is created through `confined_mkdir`,
     never through a raw re-resolved path.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .capability import require_action
from .errors import PalError
from .paths import (
    carries_reparse_attr,
    confined_mkdir,
    home_paths,
    atomic_write_bytes,
    atomic_write_json,
    _open_confined_dir,
)
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


def _root_is_real_directory(root: Path) -> bool:
    """Classify the requested home root WITHOUT following it.

    TARGET B1 (T-125): a MISSING root is a legitimate creation state for
    `ensure_home`, NOT PATH_ESCAPE -- the previous implementation opened the
    root as a directory fd before it existed, and `_open_confined_dir`
    reported the absence as a refusal, so a fresh `ensure_home(new_home)`
    could never establish its own root. This returns False for an absent
    root and raises PATH_ESCAPE for an existing symlink/junction/reparse
    root or a non-directory root, so a refused home receives no child at all.
    """
    try:
        st = os.lstat(str(root))
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise PalError(
            "PATH_ESCAPE",
            f"home {str(root)!r} cannot be stated: {exc}",
            next_action="SAIPAL writes only inside its own home",
        ) from exc
    if stat.S_ISLNK(st.st_mode) or carries_reparse_attr(root):
        raise PalError(
            "PATH_ESCAPE",
            f"home {str(root)!r} is a symlink/junction/reparse point; "
            "refusing to materialize through it",
            next_action="SAIPAL writes only inside its own home",
        )
    if not stat.S_ISDIR(st.st_mode):
        raise PalError(
            "PATH_ESCAPE",
            f"home {str(root)!r} exists and is not a directory",
            next_action="SAIPAL writes only inside its own home",
        )
    return True


def ensure_home(home: Path | str, *, registry: dict | None = None) -> dict:
    """Create the home and its declared layout. Idempotent.

    Returns what it created, so a caller can log a real first-run event instead
    of a decorative one.

    T-125 Defect E: a symlinked/junction home root is refused BEFORE any
    child directory is created, so the failure leaves the external target
    byte-identical and directory-empty.
    """
    require_action("write_own_index", registry=registry)
    data = registry if registry is not None else load_registry()

    paths = home_paths(home)
    created_dirs: list[str] = []
    created_files: list[str] = []

    # (1) Root establishment contract (TARGET B1). A MISSING root is a
    # legitimate creation state -- NOT PATH_ESCAPE -- and is established by
    # `confined_mkdir` below; an EXISTING root is refused outright here when
    # it is a symlink/junction/reparse point or is not a directory, BEFORE a
    # single child directory is created. A bound fd re-proves the physical
    # node where the platform has directory fds.
    if _root_is_real_directory(paths.root):
        root_fd = None
        try:
            root_fd = _open_confined_dir(paths.root)
        except OSError:
            # Windows has no directory fds; the classification above is the
            # authoritative refusal there.
            pass
        finally:
            if root_fd is not None:
                os.close(root_fd)

    # (2) The root itself is materialized through the confinement primitive.
    confined_mkdir(paths.root, ".")

    # (3) Every child directory goes through the same primitive: the parent
    # chain is verified immediately before each mkdir, so an indirection
    # root or an indirection ancestor cannot receive the directories.
    confined_mkdir(paths.root, paths.locks.name)
    for name in layout_dirs(data):
        if not (paths.root / name).is_dir():
            _confined_mkdir_tree(paths.root, name)
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


def _confined_mkdir_tree(root: Path, relative: str) -> None:
    """Create every level of `relative` under `root` through confined_mkdir."""
    parts = [p for p in Path(relative).parts if p not in (".", "")]
    current: Path = Path(".")
    for part in parts:
        current = Path(part) if current == Path(".") else current / part
        confined_mkdir(root, current)
