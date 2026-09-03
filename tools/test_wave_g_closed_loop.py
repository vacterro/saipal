"""Wave G: closed-loop SAIPEN integration.

Finding -> audit -> source receipt -> work -> disposition is a durable chain.
A rejected audit calibrates without rewriting history, and provenance can be
reconstructed from a cold restart.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import bundle as bundle_mod
from saipal_engine import closedloop as cl
from saipal_engine.errors import PalError
from saipal_engine.paths import sha256_text


def _drift_bundle(session_id: str = "drift-g-001") -> dict:
    payload = {
        "schema_version": 1,
        "session_id": session_id,
        "adapter": "generic",
        "project": {"name": "X", "git_head": "x", "root_fingerprint": "fx"},
        "runtime": {"provider": "openai", "model": "gpt-x", "reasoning_mode": "unknown"},
        "temperature": "COLD",
        "protocol": {"version": "7.231.9", "binding_status": "BOUND",
                     "git_head": "deadbeef", "registry_sha256": "a" * 64},
        "events": [
            {"seq": 1, "type": "PHASE_CHANGE",
             "facts": {"from_phase": "PLAN", "to_phase": "NOPE"}},
            {"seq": 2, "type": "SESSION_BOUNDARY", "facts": {}},
        ],
    }
    payload["session_sha256"] = bundle_mod.bundle_digest(payload)
    return payload


def _build_audit(home: Path) -> dict:
    """Run continue over a drift bundle and return the emitted audit record."""
    support.run_saipal("continue", home=home)
    support.write_inbox(home, "drift.json", _drift_bundle())
    code, payload, err = support.run_saipal_json("continue", home=home)
    assert code == 0, err
    assert payload is not None
    assert payload["audits_emitted"] == 1, f"expected 1 audit, got {payload['audits_emitted']}"
    findings = _findings(home)
    emitted = [f for f in findings if f.get("state") == "EMITTED" and f.get("audit")]
    assert emitted, "an EMITTED finding with an audit must exist"
    audit = emitted[0]["audit"]
    return {
        "audit_path": audit["audit_path"],
        "audit_sha256": audit["audit_sha256"],
        "audit_number": audit["audit_number"],
        "operation_id": audit["operation_id"],
        "finding_id": emitted[0]["finding_id"],
    }


def _findings(home: Path) -> list[dict]:
    index = home / "findings" / "index.json"
    if not index.exists():
        return []
    return list(json.loads(index.read_text(encoding="utf-8"))["findings"])


class ClosedLoop(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        self.audit = _build_audit(self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # -- acceptance bar 1: finding -> audit linkage is durable -------------- #

    def test_finding_audit_link_durable(self) -> None:
        status, links, detail = cl.load_links(self.home)
        self.assertEqual(status, "ok", detail)
        assert links is not None
        self.assertEqual(len(links["links"]), 1)
        entry = links["links"][0]
        self.assertEqual(entry["audit_number"], self.audit["audit_number"])
        self.assertEqual(entry["audit_path"], self.audit["audit_path"])
        self.assertTrue(entry["audit_sha256"])

    # -- acceptance bar 4: maintainer disposition import ------------------- #

    def test_disposition_import_writes_into_link_chain(self) -> None:
        entry = cl.import_maintainer_disposition(
            self.home,
            audit_number=self.audit["audit_number"],
            disposition="CONFIRMED_PROTOCOL_DEFECT",
            receipt_id="SRC-777",
            work_id="T-999",
            fix_version="7.300.0",
        )
        self.assertEqual(entry["disposition"], "CONFIRMED_PROTOCOL_DEFECT")
        self.assertEqual(entry["receipt_id"], "SRC-777")
        self.assertEqual(entry["work_id"], "T-999")
        self.assertEqual(entry["fix_version"], "7.300.0")

        # reload and assert durability
        status, links, _ = cl.load_links(self.home)
        self.assertEqual(status, "ok")
        assert links is not None
        saved = [e for e in links["links"] if e["audit_number"] == self.audit["audit_number"]]
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["disposition"], "CONFIRMED_PROTOCOL_DEFECT")

    # -- acceptance bar 6: no audit mutation on rejection ------------------ #

    def test_rejected_audit_is_calibration_not_deletion(self) -> None:
        before = self.home / "audit" / "staging" / f"{self.audit['audit_number']}.md"
        self.assertTrue(before.exists())
        digest_before = sha256_text(before.read_text(encoding="utf-8"))
        cl.import_maintainer_disposition(
            self.home, audit_number=self.audit["audit_number"],
            disposition="REJECTED_FINDING",
        )
        digest_after = sha256_text(before.read_text(encoding="utf-8"))
        self.assertEqual(digest_before, digest_after, "rejection must never touch the audit file")

    # -- acceptance bar 8: no SAIPAL protocol edits ------------------------- #

    def test_audit_file_is_read_only_for_saipal(self) -> None:
        from saipal_engine import audits as audits_mod
        body = audits_mod.build_audit_body({}, {}, {})
        # SAIPAL's own audit files may only be created through enqueue_audit;
        # no public API exists to edit an existing audit file.
        target_exists = any(
            hasattr(m, "delete_audit") or hasattr(m, "edit_audit")
            for m in (audits_mod,)
        )
        self.assertFalse(target_exists)

    def test_unknown_disposition_is_refused(self) -> None:
        with self.assertRaises(PalError) as ctx:
            cl.import_maintainer_disposition(
                self.home, audit_number=self.audit["audit_number"],
                disposition="NOT_A_THING",
            )
        self.assertEqual(ctx.exception.code, "VALIDATION_FAILED")

    # -- acceptance bar 10: cold restart reconstructs the chain ------------ #

    def test_provenance_reconstruction_survives_restart(self) -> None:
        cl.import_maintainer_disposition(
            self.home, audit_number=self.audit["audit_number"],
            disposition="ENGINE_FIX", work_id="T-1001", fix_version="7.300.0",
        )
        chain = cl.reconstruct_provenance(self.home, audit_number=self.audit["audit_number"])
        self.assertEqual(chain["audit_number"], self.audit["audit_number"])
        self.assertEqual(chain["finding_id"], self.audit.get("finding_id"))
        self.assertEqual(chain["disposition"], "ENGINE_FIX")
        self.assertEqual(chain["work_id"], "T-1001")
        self.assertEqual(chain["fix_version"], "7.300.0")


class MaintainerRootLinkage(unittest.TestCase):
    """Wave G acceptance bar 1: SAIPAL enqueues into the SAIPEN Audit Inbox.

    SAIPEN's `audit_enqueue` capability (audit/04) is not implemented in the
    live SAIPEN clone -- only its specs are. Until that lands, SAIPAL exercises
    the wire-level integration against a mocked maintainer root: a temp dir
    shaped like `<root>/audit/` plus an audit-envelope-shaped consumer. The test
    proves the SAIPAL side works exactly as the spec requires; the SAIPEN-side
    consumer is replaced when the real one ships.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        # the mocked maintainer root: a sibling of the SAIPAL home
        self.maintainer_root = self.tmp / "mocked-saipen"
        (self.maintainer_root / "audit").mkdir(parents=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _qualified_finding(self, finding_id: str = "PAL-9999") -> dict:
        return {
            "finding_id": finding_id,
            "fingerprint": "f" + finding_id,
            "state": "QUALIFIED",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P1",
            "confidence": "HIGH",
            "change_target": "ENGINE",
            "rule_ids": ["COMMAND_ROUTE_DRIFT"],
            "root_cause": "the command went outside the declared carrier surface",
            "protected_invariants": ["destructive_confirmation"],
            "harm_warnings": [],
            "occurrences": [{"session_id": "s-1", "episode_id": 0, "event_refs": [2]}],
            "protocol_bindings": [{"version": "7.231.9", "binding_status": "BOUND"}],
            "alternatives": [],
            "audit": None,
        }

    def test_enqueue_writes_into_a_maintainer_root(self) -> None:
        """A qualified finding enqueues into `<maintainer_root>/audit/N.md`.

        The audit number is monotonic per maintainer root, the file lives at
        `audit/N.md` relative to the root, and the digest matches the body.
        """
        from saipal_engine import enqueue as enqueue_mod
        from saipal_engine.paths import sha256_file

        finding = self._qualified_finding()
        body = (
            "# SAIPAL AUDIT — COMMAND_ROUTE_DRIFT\n"
            f"finding_id: {finding['finding_id']}\n"
            "maintainer_verdict: PENDING\n"
        )
        result = enqueue_mod.enqueue_audit(
            self.home, finding, body, maintainer_root=self.maintainer_root
        )

        # wire contract from audit/04: returned number, path, hash, operation
        self.assertEqual(result["audit_number"], 1)
        self.assertEqual(result["audit_path"], "audit/1.md")
        self.assertEqual(len(result["audit_sha256"]), 64)
        self.assertEqual(len(result["operation_id"]), 32)

        # the file lives where the spec says
        target = self.maintainer_root / "audit" / "1.md"
        self.assertTrue(target.exists())
        self.assertEqual(sha256_file(target), result["audit_sha256"])

        # SAIPAL's own home was untouched
        self.assertFalse((self.home / "audit" / "staging").exists())

        # the ledger lives next to the audits in the maintainer root
        entries = self.maintainer_root / "audit" / "entries.json"
        self.assertTrue(entries.exists())
        ledger = json.loads(entries.read_text(encoding="utf-8"))
        self.assertEqual(len(ledger["entries"]), 1)
        entry = ledger["entries"][0]
        self.assertEqual(entry["finding_id"], finding["finding_id"])
        self.assertEqual(entry["audit_sha256"], result["audit_sha256"])
        self.assertEqual(entry["enqueue_operation_id"], result["operation_id"])

    def test_idempotent_retry_returns_same_audit(self) -> None:
        """A retry with the same finding + content must not allocate a second audit."""
        from saipal_engine import enqueue as enqueue_mod

        finding = self._qualified_finding()
        body = "# SAIPAL AUDIT — COMMAND_ROUTE_DRIFT\nmaintainer_verdict: PENDING\n"
        first = enqueue_mod.enqueue_audit(
            self.home, finding, body, maintainer_root=self.maintainer_root
        )
        second = enqueue_mod.enqueue_audit(
            self.home, finding, body, maintainer_root=self.maintainer_root
        )
        self.assertEqual(first["audit_number"], second["audit_number"])
        self.assertEqual(first["audit_sha256"], second["audit_sha256"])
        self.assertEqual(first["operation_id"], second["operation_id"])

        # only one file exists
        audit_dir = self.maintainer_root / "audit"
        numbered = [p for p in audit_dir.iterdir() if p.suffix == ".md"]
        self.assertEqual(len(numbered), 1)

    def test_no_writes_outside_the_root(self) -> None:
        """The mocked maintainer root is the only place a SAIPAL audit lands."""
        from saipal_engine import enqueue as enqueue_mod

        finding = self._qualified_finding()
        body = "# SAIPAL AUDIT — COMMAND_ROUTE_DRIFT\nmaintainer_verdict: PENDING\n"
        enqueue_mod.enqueue_audit(
            self.home, finding, body, maintainer_root=self.maintainer_root
        )
        # no audit ever appears in SAIPAL's own home
        self.assertFalse((self.home / "audit").exists())
        # only the mocked root received the file
        self.assertTrue((self.maintainer_root / "audit" / "1.md").exists())


class LinkFailureResilience(unittest.TestCase):
    """T-009 red control: a corrupt link file must not silently lose the audit.

    pipeline.py used `except Exception: pass` around link_finding_audit, which
    swallowed any failure (corrupt closed_loop_links.json, OSError, etc.) after
    the audit was already on disk. The fix catches specific exceptions and logs
    a `closed_loop_link_failure` event, while the audit file survives.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _log_events(self) -> list[dict]:
        from saipal_engine import log as log_mod
        events, _ = log_mod.read_events(self.home)
        return events

    def test_link_failure_logs_event_and_keeps_audit(self) -> None:
        """Corrupt closed_loop_links.json → link_finding_audit raises PalError.

        The cycle must complete (exit 0), the audit must be emitted, and a
        `closed_loop_link_failure` event must appear in the log.
        """
        # write garbage so load_links returns "unrecoverable"
        (self.home / "closed_loop_links.json").write_text(
            "not valid json at all", encoding="utf-8"
        )

        # inject a drift bundle through the CLI
        support.write_inbox(self.home, "drift.json", _drift_bundle())
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None

        # audit still emitted
        self.assertEqual(payload["audits_emitted"], 1)

        # the failure event is in the log
        events = self._log_events()
        failures = [ev for ev in events if ev.get("event") == "closed_loop_link_failure"]
        self.assertEqual(len(failures), 1, f"expected 1 failure event, got {len(failures)}")
        fdata = failures[0].get("data", {})
        self.assertEqual(fdata["finding_id"], "PAL-0001")
        self.assertEqual(fdata["audit_number"], 1)
        self.assertIn("reason", fdata)
        self.assertIn("unreadable", fdata["reason"])


if __name__ == "__main__":
    unittest.main()
