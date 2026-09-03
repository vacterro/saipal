from __future__ import annotations

from pathlib import Path

from . import enqueue
from .config import configured_sink_root, load_config
from .errors import PalError


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
        return {"ok": True, "root": str(self.root), "audit_dir": str(self.audit_dir)}

    def publish(self, finding: dict, body: str) -> dict:
        result = self.preflight()
        if not result["ok"]:
            raise PalError("SINK_UNAVAILABLE", result["reason"], next_action="keep audit staged and retry")
        return enqueue.enqueue_audit(
            self.home, finding, body, maintainer_root=self.root,
            private_ledger_home=self.home,
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
