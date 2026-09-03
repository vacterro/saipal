"""Read historical protocol rule surfaces without checkout or mutation.

The caller supplies authority roots. Session/transcript fields select identities
inside those roots; they never select an arbitrary filesystem path.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Callable

from .paths import sha256_bytes
from .registry import REGISTRY_KIND, SCHEMA_VERSION, load_registry, require_mapping

_FULL_GIT_OBJECT_ID = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_SAFE_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$")
_RULE_ID = re.compile(r"^PAL-[A-Z][A-Z0-9]*-[0-9]{2}$")
_RULE_HEADING = re.compile(r"^(#{2,6})\s+(PAL-[A-Z][A-Z0-9]*-[0-9]{2})\b")

Reader = Callable[[str], bytes]


def _limits(registry: dict | None) -> dict[str, int]:
    data = registry if registry is not None else load_registry()
    raw = require_mapping(data, "historical_rule_limits")
    return {key: int(value) for key, value in raw.items()}


def _safe_owner_path(value: object) -> str:
    text = str(value or "")
    path = PurePosixPath(text)
    if (
        not text
        or path.is_absolute()
        or "\\" in text
        or ".." in path.parts
        or not text.startswith("saipal/")
    ):
        raise ValueError("historical registry contains an unsafe rule-owner path")
    return path.as_posix()


def _registry_from_bytes(raw: bytes) -> dict:
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("historical registry is not valid UTF-8 JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("historical registry root is not an object")
    if data.get("kind") != REGISTRY_KIND or data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("historical registry identity/schema is unsupported")
    owners = data.get("rule_owners")
    if not isinstance(owners, dict):
        raise ValueError("historical registry has no rule_owners object")
    return data


def _directory_reader(root: Path) -> Reader:
    authority = root.resolve()

    def read(relative: str) -> bytes:
        target = (authority / Path(*PurePosixPath(relative).parts)).resolve()
        if authority not in target.parents:
            raise ValueError("historical rule path escapes configured authority")
        if not target.is_file():
            raise ValueError("historical rule file is absent")
        return target.read_bytes()

    return read


def _git_reader(repository: Path, commit: str) -> Reader:
    repo = repository.resolve()
    if not repo.is_dir():
        raise ValueError("configured Git protocol authority is absent")
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"

    probe = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", f"{commit}^{{commit}}"],
        capture_output=True,
        timeout=10,
        env=env,
        check=False,
    )
    if probe.returncode != 0:
        raise ValueError("git commit was not found by configured protocol authority")

    def read(relative: str) -> bytes:
        completed = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "blob", f"{commit}:{relative}"],
            capture_output=True,
            timeout=10,
            env=env,
            check=False,
        )
        if completed.returncode != 0:
            raise ValueError("historical rule file is absent at the exact commit")
        return completed.stdout

    return read


def _surface(reader: Reader, rule_ids: tuple[str, ...], limits: dict[str, int]) -> dict:
    registry_raw = reader("saipal/REGISTRY.json")
    registry = _registry_from_bytes(registry_raw)
    owners = registry["rule_owners"]
    documents: dict[str, bytes] = {}
    rules: list[dict] = []
    for rule_id in rule_ids:
        owner = _safe_owner_path(owners.get(rule_id))
        if owner not in documents:
            documents[owner] = reader(owner)
        raw = documents[owner]
        if len(raw) > limits["max_rule_document_bytes"]:
            raise ValueError("historical rule document exceeds the configured bound")
        text = raw.decode("utf-8-sig")
        section = _rule_section(text, rule_id)
        if len(section) > limits["max_rule_text_chars"]:
            raise ValueError("historical rule section exceeds the configured bound")
        rules.append(
            {
                "rule_id": rule_id,
                "owner": owner,
                "document_sha256": sha256_bytes(raw),
                "text": section,
            }
        )
    return {
        "registry_sha256": sha256_bytes(registry_raw),
        "registry": registry,
        "rules": rules,
    }


def _rule_section(document: str, rule_id: str) -> str:
    lines = document.splitlines()
    start = -1
    level = 0
    for index, line in enumerate(lines):
        match = _RULE_HEADING.match(line)
        if match and match.group(2) == rule_id:
            start = index
            level = len(match.group(1))
            break
    if start < 0:
        raise ValueError("historical owner document does not contain the requested rule")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        heading = re.match(r"^(#{1,6})\s+", lines[index])
        if heading and len(heading.group(1)) <= level:
            end = index
            break
    return "\n".join(lines[start:end]).strip() + "\n"


def protocol_tree_fingerprint(
    artifact_root: Path | str,
    *,
    registry: dict | None = None,
    reader: Reader | None = None,
) -> str:
    """Digest the historical registry and every rule-owner document."""
    limits = _limits(registry)
    if reader is None:
        reader = _directory_reader(Path(artifact_root))
    registry_raw = reader("saipal/REGISTRY.json")
    historical_registry = _registry_from_bytes(registry_raw)
    owner_paths = sorted({_safe_owner_path(value) for value in historical_registry["rule_owners"].values()})
    if len(owner_paths) > limits["max_surface_documents"]:
        raise ValueError("historical protocol surface has too many owner documents")
    entries = {"saipal/REGISTRY.json": registry_raw}
    total = len(registry_raw)
    for owner in owner_paths:
        raw = reader(owner)
        total += len(raw)
        if total > limits["max_surface_bytes"]:
            raise ValueError("historical protocol surface exceeds the configured byte bound")
        entries[owner] = raw
    digest = hashlib.sha256()
    for relative in sorted(entries):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(entries[relative]).digest())
        digest.update(b"\n")
    return digest.hexdigest()


def read_historical_rules(
    protocol: dict | None,
    rule_ids: list[str] | tuple[str, ...],
    *,
    git_repository: Path | str | None = None,
    release_root: Path | str | None = None,
    snapshot_root: Path | str | None = None,
    registry: dict | None = None,
) -> dict:
    """Resolve bounded rule text from configured historical authorities."""
    limits = _limits(registry)
    requested = tuple(dict.fromkeys(rule_ids))
    if not requested or len(requested) > limits["max_rule_ids"]:
        raise ValueError("historical rule request is empty or exceeds the configured bound")
    if any(not _RULE_ID.fullmatch(rule_id) for rule_id in requested):
        raise ValueError("historical rule request contains an invalid rule id")

    evidence = protocol if isinstance(protocol, dict) else {}
    attempts: list[dict[str, str]] = []

    git_head = str(evidence.get("git_head") or "").strip().lower()
    if git_head:
        if not _FULL_GIT_OBJECT_ID.fullmatch(git_head):
            attempts.append({"source": "EXACT_COMMIT", "reason": "invalid full commit identity"})
        elif git_repository is None:
            attempts.append({"source": "EXACT_COMMIT", "reason": "authority not configured"})
        else:
            try:
                surface = _surface(_git_reader(Path(git_repository), git_head), requested, limits)
                expected = str(evidence.get("registry_sha256") or "").strip().lower()
                if expected and expected != surface["registry_sha256"]:
                    raise ValueError("captured registry digest conflicts with exact commit")
                return _resolved("EXACT_COMMIT", git_head, requested, surface)
            except (OSError, subprocess.SubprocessError, ValueError) as exc:
                attempts.append({"source": "EXACT_COMMIT", "reason": str(exc)})

    version = str(evidence.get("version") or "").strip()
    registry_digest = str(evidence.get("registry_sha256") or "").strip().lower()
    if version and registry_digest:
        if not _SAFE_VERSION.fullmatch(version) or not _SHA256.fullmatch(registry_digest):
            attempts.append({"source": "RELEASE_REGISTRY", "reason": "invalid release identity"})
        elif release_root is None:
            attempts.append({"source": "RELEASE_REGISTRY", "reason": "authority not configured"})
        else:
            try:
                root = Path(release_root) / version
                surface = _surface(_directory_reader(root), requested, limits)
                if registry_digest != surface["registry_sha256"]:
                    raise ValueError("release registry digest mismatch")
                return _resolved("RELEASE_REGISTRY", version, requested, surface)
            except (OSError, UnicodeDecodeError, ValueError) as exc:
                attempts.append({"source": "RELEASE_REGISTRY", "reason": str(exc)})

    fingerprint = str(evidence.get("tree_fingerprint") or "").strip().lower()
    if fingerprint:
        if not _SHA256.fullmatch(fingerprint):
            attempts.append({"source": "CAPTURED_FINGERPRINT", "reason": "invalid snapshot identity"})
        elif snapshot_root is None:
            attempts.append({"source": "CAPTURED_FINGERPRINT", "reason": "authority not configured"})
        else:
            try:
                root = Path(snapshot_root) / fingerprint
                actual = protocol_tree_fingerprint(root, registry=registry)
                if actual != fingerprint:
                    raise ValueError("captured protocol fingerprint mismatch")
                surface = _surface(_directory_reader(root), requested, limits)
                return _resolved("CAPTURED_FINGERPRINT", fingerprint, requested, surface)
            except (OSError, UnicodeDecodeError, ValueError) as exc:
                attempts.append({"source": "CAPTURED_FINGERPRINT", "reason": str(exc)})

    return {
        "schema_version": 1,
        "status": "UNAVAILABLE",
        "source": "UNKNOWN",
        "identity": None,
        "rule_ids": list(requested),
        "rules": [],
        "attempts": attempts,
    }


def _resolved(source: str, identity: str, requested: tuple[str, ...], surface: dict) -> dict:
    return {
        "schema_version": 1,
        "status": "RESOLVED",
        "source": source,
        "identity": identity,
        "rule_ids": list(requested),
        "registry_sha256": surface["registry_sha256"],
        "rules": surface["rules"],
        "attempts": [],
    }


def compact_rule_surface(resolution: dict) -> dict:
    """The audit-safe projection of a resolution: digests, never rule text.

    A finding index is an index, not a copy of the protocol. The full historical
    text is up to `max_rule_text_chars` per rule, so what travels with a finding
    is the identity plus per-rule digests an operator can re-fetch from the same
    authority.
    """
    rules = resolution.get("rules") or []
    return {
        "status": resolution.get("status", "UNAVAILABLE"),
        "source": resolution.get("source", "UNKNOWN"),
        "identity": resolution.get("identity"),
        "registry_sha256": resolution.get("registry_sha256"),
        "rules": [
            {
                "rule_id": rule.get("rule_id"),
                "owner": rule.get("owner"),
                "document_sha256": rule.get("document_sha256"),
                "text_sha256": sha256_bytes(str(rule.get("text") or "").encode("utf-8")),
                "text_chars": len(str(rule.get("text") or "")),
            }
            for rule in rules
        ],
        "attempts": list(resolution.get("attempts") or []),
    }
