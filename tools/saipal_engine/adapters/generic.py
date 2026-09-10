from __future__ import annotations

from pathlib import Path
from typing import Any

from saipal_engine import bundle as bundle_mod
from saipal_engine.paths import sha256_file

NAME = "generic"

CANONICAL_SUFFIX = ".json"

#: T-103 watermark capability contract. `stable_watermark` here is the max
#: event seq -- it detects APPENDS only. The provider store is an ordinary
#: file SAIPAL does not control, so an existing event can be rewritten in
#: place without moving max(seq). This probe is an APPEND hint, never a
#: mutation-safe change token, and it may never independently suppress
#: forensic normalization.
WATERMARK_CAPABILITY = "APPEND_ONLY_HINT"


def discover(source_path: str) -> list[dict]:
    root = Path(source_path)
    if not root.is_dir():
        return []
    return [
        {
            "path": str(p),
            "name": p.name,
            "size": p.stat().st_size,
            # The canonical bundle's session id is authoritative at normalize
            # time, but the file stem is the honest per-candidate handle every
            # other adapter carries (T-97 provenance; opencode does the same).
            "session_id": p.stem,
        }
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
