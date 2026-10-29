from __future__ import annotations

from pathlib import Path

from . import enqueue
from .config import configured_sink_root, load_config
from .errors import PalError
from .paths import read_json

#: The closed sink manifest contract (T-109). A directory is a SAIPEN audit
#: inbox only when its `audit/MANIFEST.json` says so under a supported schema;
#: a file named MANIFEST.json alone proves nothing.
SINK_MANIFEST_KIND = "saipen-audit-inbox"
SINK_MANIFEST_SCHEMA_VERSIONS = (1,)


def _manifest_problems(path: Path) -> str | None:
    """Every reason this manifest is not a SAIPEN audit inbox, or None."""
    try:
        manifest = read_json(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return f"sink audit manifest is malformed: {exc}"
    if not isinstance(manifest, dict):
        return "sink audit manifest root is not an object"
    if "kind" not in manifest:
        return "sink audit manifest is missing kind"
    if manifest.get("kind") != SINK_MANIFEST_KIND:
        return (
            f"sink audit manifest kind is {manifest.get('kind')!r}, "
            f"not {SINK_MANIFEST_KIND!r}"
        )
    if "schema_version" not in manifest:
        return "sink audit manifest is missing schema_version"
    if manifest.get("schema_version") not in SINK_MANIFEST_SCHEMA_VERSIONS:
        return (
            f"sink audit manifest schema_version "
            f"{manifest.get('schema_version')!r} is unsupported "
            f"(supported: {', '.join(str(s) for s in SINK_MANIFEST_SCHEMA_VERSIONS)})"
        )
    return None


class AuditSink:
    def __init__(self, home: Path | str, *, root: Path):
        self.home = Path(home)
        self.root = Path(root).expanduser().resolve()
        self.audit_dir = self.root / "audit"

    def preflight(self) -> dict:
        if not self.root.is_dir():
            return {"ok": False, "reason": "sink root is not a directory"}
        if not self.audit_dir.is_dir():
            return {"ok": False, "reason": "sink audit directory is missing"}
        manifest = self.audit_dir / "MANIFEST.json"
        if not manifest.is_file():
            return {"ok": False, "reason": "sink audit manifest is missing"}
        problem = _manifest_problems(manifest)
        if problem is not None:
            return {"ok": False, "reason": problem}
        return {
            "ok": True,
            "root": str(self.root),
            "audit_dir": str(self.audit_dir),
            "manifest_kind": SINK_MANIFEST_KIND,
            "manifest_schema_version": 1,
        }

    def publish(self, finding: dict, body: str, *, reserve_number: int | None = None) -> dict:
        result = self.preflight()
        if not result["ok"]:
            raise PalError("SINK_UNAVAILABLE", result["reason"], next_action="keep audit staged and retry")
        return enqueue.enqueue_audit(
            self.home, finding, body, maintainer_root=self.root,
            private_ledger_home=self.home,
            reserve_number=reserve_number,
        )

    def verify(self, result: dict) -> bool:
        return enqueue.verify_audit(self.root / result["audit_path"], result["audit_sha256"])

    def lookup_receipt(self, finding_id: str) -> dict | None:
        return enqueue.lookup_receipt(self.home, finding_id)


def configured_sink(home: Path | str) -> tuple[str, AuditSink | None, str]:
    status, config, detail = load_config(home)
    if status == "unrecoverable":
        return status, None, detail
    root = configured_sink_root(home, config)
    if root is None:
        return "absent", None, "no sink configured"
    sink = AuditSink(home, root=root)
    preflight = sink.preflight()
    if not preflight["ok"]:
        return "invalid", None, preflight["reason"]
    return "ok", sink, ""
