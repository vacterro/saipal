from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import bundle as bundle_mod
from .adapters import ADAPTER_REGISTRY
from .errors import PalError
from .paths import atomic_write_bytes, home_paths, sha256_text
from .sessions import binding_proof_of


def dispatch_sources(
    home: Path | str,
    sources: list[dict],
    *,
    registry: dict,
    index: dict | None = None,
    max_per_source: int = 50,
    authority: dict | None = None,
) -> dict[str, Any]:
    paths = home_paths(home)
    known_ids: set[str] = set()
    if index is not None:
        for rec in index.get("sessions") or []:
            sid = rec.get("session_id")
            if isinstance(sid, str):
                known_ids.add(sid)

    report = {
        "imported": [], "unchanged": [], "deferred_hot_tail": [],
        "rejected": [], "conflict": [], "unsupported": [],
        "pending": 0, "processed": 0,
    }
    for source in sources:
        if not source.get("enabled"):
            continue
        adapter_name = str(source.get("kind", ""))
        adapter = ADAPTER_REGISTRY.get(adapter_name)
        if adapter is None:
            report["unsupported"].append({"id": source.get("id"), "reason": "unknown adapter"})
            continue
        try:
            candidates = adapter.discover(source["path"])
        except Exception as exc:
            report["rejected"].append({"id": source.get("id"), "reason": str(exc)})
            continue
        count = 0
        for candidate in candidates:
            if count >= max_per_source:
                report["pending"] += 1
                continue
            session_id = candidate.get("session_id") or ""
            source_ref = str(candidate["path"])
            inbox_name = f"{adapter_name}-{session_id}-{sha256_text(source_ref)[:12]}.json"
            if session_id in known_ids:
                try:
                    existing_bundle = bundle_mod.load_bundle_file(
                        paths.session_inbox / inbox_name,
                        registry=registry
                    )
                    if existing_bundle.get("temperature") == "COLD":
                        report["unchanged"].append({"source": str(session_id), "reason": "already indexed, cold"})
                        count += 1
                        continue
                except (OSError, ValueError, PalError):
                    pass
            try:
                source_path = source_ref
                bundle = adapter.normalize(str(source_path))
                if not bundle.get("raw_source_ref"):
                    bundle["raw_source_ref"] = str(source_path)
                if not bundle.get("raw_source_sha256"):
                    bundle["raw_source_sha256"] = adapter.identity(str(source_path))
                protocol = bundle.get("protocol")
                if not isinstance(protocol, dict):
                    protocol = adapter.protocol_binding(str(source_path))
                    bundle["protocol"] = protocol
                proof = binding_proof_of(protocol, authority=authority, registry=registry)
                protocol["binding_status"] = proof["binding_status"]
                protocol["proof_level"] = proof["proof_level"]
                bundle_sha = bundle_mod.bundle_digest(bundle)
                bundle["session_sha256"] = bundle_sha
                bundle_mod.parse_bundle(bundle, registry=registry)
                sid = bundle["session_id"]
                target = paths.session_inbox / inbox_name
                if target.exists():
                    existing = bundle_mod.load_bundle_file(target, registry=registry)
                    if existing.get("session_sha256") == bundle.get("session_sha256"):
                        report["unchanged"].append({"source": str(source_path), "target": str(target), "session_id": sid})
                        count += 1
                        continue
                atomic_write_bytes(target, _json_bytes(bundle), root=paths.root)
                report["imported"].append({"source": str(source_path), "target": str(target), "session_id": sid})
                count += 1
            except (OSError, ValueError, UnicodeDecodeError, PalError) as exc:
                report["rejected"].append({"id": candidate.get("session_id") or source.get("id"), "reason": str(exc)})
        report["processed"] += count
    return report


def _json_bytes(payload: dict) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
