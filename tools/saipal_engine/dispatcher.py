from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import bundle as bundle_mod
from .adapters import ADAPTER_REGISTRY, watermark_capability
from .errors import PalError
from .paths import atomic_write_bytes, confined_mkdir, home_paths, sha256_text
from .sessions import STATUS_ABSENT, STATUS_OK, binding_proof_of, find_session, load_index


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
    # TARGET B2 (T-125): the staging directory is materialized EXPLICITLY by
    # its owner (this dispatcher). `atomic_write_bytes` writes only into an
    # already-authorized existing parent and never recreates missing parents;
    # an indirection refuses with zero external mutation.
    confined_mkdir(paths.root, paths.session_inbox.name)
    if index is None:
        # T-103: conflict surfacing (ROLE 12) needs the accepted session
        # state. Callers that already hold the index pass it in; every other
        # caller gets one read of a small durable JSON.
        status, loaded, _detail = load_index(paths.root, registry=registry)
        if status in (STATUS_ABSENT, STATUS_OK) and loaded is not None:
            index = loaded
    known_ids: set[str] = set()
    if index is not None:
        for rec in index.get("sessions") or []:
            sid = rec.get("session_id")
            if isinstance(sid, str):
                known_ids.add(sid)

    report = {
        "imported": [], "unchanged": [], "deferred_hot_tail": [],
        "rejected": [], "conflict": [], "unsupported": [],
        "unchanged_hot": [], "quarantined": [],
        "pending": 0, "processed": 0,
    }
    for source in sources:
        if not source.get("enabled"):
            continue
        source_id = str(source.get("id") or "")
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
        capability = watermark_capability(adapter)
        count = 0
        for candidate in candidates:
            if count >= max_per_source:
                report["pending"] += 1
                continue
            session_id = candidate.get("session_id") or ""
            source_ref = str(candidate["path"])
            inbox_name = f"{adapter_name}-{session_id}-{sha256_text(source_ref)[:12]}.json"
            staged_path = paths.session_inbox / inbox_name
            if session_id in known_ids and _unchanged_cold(
                adapter, source_ref, staged_path, registry
            ):
                report["unchanged"].append(
                    {"source": str(session_id), "reason": "already indexed, cold", "source_id": source_id}
                )
                count += 1
                continue
            # T-103: HOT candidates skip normalization only when a probe the
            # adapter DECLARES mutation-safe is unchanged, or when the
            # provider's raw bytes still hash to what the last staged,
            # accepted artifact recorded. An append-only hint on its own
            # suppresses nothing (ROLE 2/3/6/8): historical rewrites that
            # keep max(seq) still normalize and still reach the inbox prefix
            # check.
            hot_unchanged, observed_watermark, reason = _unchanged_hot(
                adapter, source_ref, staged_path, registry, capability=capability
            )
            if hot_unchanged:
                record = find_session(index, session_id) if index is not None else None
                if record is not None and record.get("status") == "CONFLICT":
                    # ROLE 12: skipping re-normalization of an exact,
                    # conflicted artifact is allowed -- calling it ordinary
                    # clean is not. The conflict stays surfaced.
                    report["conflict"].append({
                        "source": str(session_id),
                        "source_id": source_id,
                        "status": "CONFLICT",
                        "reason": "existing conflict stands; unchanged artifact not re-normalized",
                        "watermark": observed_watermark,
                    })
                else:
                    report["unchanged_hot"].append({
                        "source": str(session_id),
                        "source_id": source_id,
                        "watermark": observed_watermark,
                        "reason": reason,
                    })
                count += 1
                continue
            try:
                source_path = source_ref
                raw_identity = adapter.identity(str(source_path))
                # T-106: an artifact identity already quarantined skips the
                # reparse while its bytes stay unchanged. A changed identity
                # (released below) or no quarantine record normalizes.
                from . import poison as poison_mod

                poisoned = poison_mod.quarantine_state(
                    paths.root,
                    source_id=source_id,
                    session_id=str(session_id),
                    raw_source_sha256=raw_identity,
                )
                if poisoned.get("quarantined"):
                    report["quarantined"].append({
                        "source": str(session_id),
                        "source_id": source_id,
                        "reason": "unchanged artifact quarantined (poison); not reparsed",
                        "rejection_class": poisoned.get("rejection_class"),
                    })
                    count += 1
                    continue
                bundle = adapter.normalize(str(source_path))
                if not bundle.get("raw_source_ref"):
                    bundle["raw_source_ref"] = str(source_path)
                if not bundle.get("raw_source_sha256"):
                    bundle["raw_source_sha256"] = raw_identity
                # T-97: the SOURCE identity is durable provenance, not a
                # filename guess. Every staged bundle carries the configured
                # source id so import outcomes attribute back to the source.
                bundle["source_id"] = source_id
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
                target = staged_path
                if target.exists():
                    existing = bundle_mod.load_bundle_file(target, registry=registry)
                    if existing.get("session_sha256") == bundle.get("session_sha256"):
                        report["unchanged"].append({"source": str(source_path), "target": str(target), "session_id": sid, "source_id": source_id})
                        count += 1
                        continue
                # T-103 (ROLE 10): the staged bundle carries the OBSERVED
                # provider watermark, named for what it is. It is advisory
                # operational metadata beside the evidence, excluded from the
                # bundle digest, and it never stands in for the accepted
                # state -- acceptance is the inbox import's decision, and the
                # skip path must additionally prove the raw bytes unchanged.
                try:
                    observed = int(adapter.stable_watermark(str(source_path)))
                    if observed > 0:
                        bundle["observed_watermark"] = observed
                except Exception:
                    pass
                atomic_write_bytes(target, _json_bytes(bundle), root=paths.root)
                # The artifact normalized and staged: any earlier quarantine
                # verdict for this identity no longer describes it.
                from . import poison as poison_mod

                poison_mod.release_changed_artifact(
                    paths.root,
                    source_id=source_id,
                    session_id=str(sid),
                    raw_source_sha256=str(bundle.get("raw_source_sha256") or ""),
                    registry=registry,
                )
                report["imported"].append({"source": str(source_path), "target": str(target), "session_id": sid, "source_id": source_id})
                count += 1
            except (OSError, ValueError, UnicodeDecodeError, PalError) as exc:
                from . import poison as poison_mod

                try:
                    poison_mod.record_rejected_artifact(
                        paths.root,
                        source_id=source_id,
                        session_id=str(candidate.get("session_id") or ""),
                        raw_source_sha256=str(adapter.identity(source_ref) or ""),
                        rejection_class=type(exc).__name__,
                        reason=str(exc),
                        registry=registry,
                    )
                except Exception:
                    pass  # quarantine bookkeeping must never mask the rejection
                report["rejected"].append({"id": candidate.get("session_id") or source.get("id"), "reason": str(exc), "source_id": source_id})
        report["processed"] += count
    return report


def _unchanged_cold(adapter, source_ref: str, staged: Path, registry: dict) -> bool:
    """May this known COLD candidate be skipped without normalizing it?

    Only when the raw source still hashes to what the staged bundle recorded.
    A known session id was previously treated as proof that the artifact had not
    changed, so a COLD session rewritten in place was suppressed before intake
    could ever see it -- exactly the digest decision `PAL-SESSION-02` reserves for
    the generation logic (audit W2-003).

    `adapter.identity()` is the cheap content identity the fast path is allowed to
    trust: it hashes the raw source rather than parsing it. When it cannot be
    computed, the honest answer is to normalize, not to guess.
    """
    try:
        existing = bundle_mod.load_bundle_file(staged, registry=registry)
    except (OSError, ValueError, PalError):
        return False
    if existing.get("temperature") != "COLD":
        return False
    recorded = str(existing.get("raw_source_sha256") or "")
    if not recorded:
        return False
    try:
        current = str(adapter.identity(source_ref) or "")
    except Exception:
        return False
    return bool(current) and current == recorded


def _unchanged_hot(
    adapter, source_ref: str, staged: Path, registry: dict, *, capability: dict
) -> tuple[bool, int | None, str]:
    """May this known HOT candidate be skipped without normalizing it? (T-103)

    A cheap probe may suppress normalization ONLY when it is demonstrably
    change-sensitive for every source mutation relevant to forensic identity
    (ROLE 3). Presence of `adapter.stable_watermark` is not such a probe: every
    shipped watermark is max(seq) or a row count, so it detects appends and
    silently misses historical rewrites (ROLE 2/5/6).

    Decision ladder, failing open toward extra normalization:

    1. no staged artifact / not HOT            -> normalize
    2. no accepted watermark checkpoint        -> normalize
    3. probe missing or malformed              -> normalize
    4. probe advanced past the checkpoint      -> normalize
    5. capability is MUTATION_SAFE_CHANGE_TOKEN
       and the probe matches the checkpoint    -> skip (probe alone is proof)
    6. otherwise the probe matched only as an
       APPEND hint: skip only when the raw
       source still hashes to the identity the
       staged artifact recorded                -> skip, else normalize

    The checkpoint compared against is the durable staged artifact: it is the
    observed provider state at the last normalization, and the identity check
    ties it to the provider bytes NOW (ROLE 10). Returns
    `(unchanged, observed_watermark, reason)`.
    """
    try:
        existing = bundle_mod.load_bundle_file(staged, registry=registry)
    except (OSError, ValueError, PalError):
        return False, None, "no staged artifact"
    if existing.get("temperature") != "HOT":
        return False, None, "not hot"
    # ROLE 10: `observed_watermark` is the staged bundle's own name; the
    # legacy `watermark` key stays readable so older staged artifacts do not
    # silently lose their checkpoint.
    recorded = existing.get("observed_watermark", existing.get("watermark"))
    if not isinstance(recorded, int) or isinstance(recorded, bool) or recorded <= 0:
        return False, None, "no accepted watermark checkpoint"
    try:
        watermark = adapter.stable_watermark(source_ref)
    except Exception:
        return False, None, "probe unavailable"
    if not isinstance(watermark, int) or isinstance(watermark, bool) or watermark <= 0:
        return False, None, "probe invalid"
    if watermark != recorded:
        return False, watermark, "watermark advanced"
    if capability.get("mutation_safe"):
        return True, watermark, "mutation-safe change token unchanged"
    # Append hint only: the probe says nothing about historical mutation.
    recorded_raw = str(existing.get("raw_source_sha256") or "")
    if not recorded_raw:
        return False, watermark, "no raw identity to compare"
    try:
        current = str(adapter.identity(source_ref) or "")
    except Exception:
        return False, watermark, "identity unavailable"
    if not current or current != recorded_raw:
        return False, watermark, "raw identity changed"
    return True, watermark, "raw identity proven unchanged"


def _json_bytes(payload: dict) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
