from __future__ import annotations

from pathlib import Path
from typing import Any

from saipal_engine import bundle as bundle_mod
from saipal_engine.paths import sha256_file

NAME = "generic"

CANONICAL_SUFFIX = ".json"


def discover(source_path: str) -> list[dict]:
    root = Path(source_path)
    if not root.is_dir():
        return []
    return [
        {"path": str(p), "name": p.name, "size": p.stat().st_size}
        for p in sorted(root.iterdir())
        if p.is_file() and p.suffix == CANONICAL_SUFFIX and not p.name.startswith(".")
    ]


def identity(file_path: str) -> str:
    return sha256_file(file_path)


def stable_watermark(file_path: str) -> int:
    bundle = bundle_mod.load_bundle_file(file_path)
    events = bundle_mod.events_of(bundle)
    if not events:
        return 0
    return max(int(event["seq"]) for event in events)


def normalize(file_path: str) -> dict:
    return bundle_mod.load_bundle_file(file_path)


def protocol_binding(file_path: str) -> dict:
    bundle = bundle_mod.load_bundle_file(file_path)
    protocol = bundle.get("protocol")
    if isinstance(protocol, dict):
        return protocol
    return {"binding_status": "UNKNOWN"}
