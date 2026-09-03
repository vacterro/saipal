"""Wave E: audit producer, exercised through the real enqueue API.

Wave D findings reach immutable numbered audits. The mechanical pipeline only
emits findings for classes the mechanical detectors can fire; P0/P1 classes
like EVIDENCE_FABRICATION arrive from the LLM analyst. So these tests drive
the enqueue contract directly with hand-built QUALIFIED findings, plus the
cold-session "emit nothing" bar through the real CLI.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import audits as audits_mod
from saipal_engine import bundle as bundle_mod
from saipal_engine import enqueue as enqueue_mod
from saipal_engine import redact as redact_mod

COLD = "conformant-cold.json"


def _drift_bundle(session_id: str = "audit-drift-001") -> dict:
    events = [
        {"seq": 1, "type": "USER_MESSAGE", "ts": None, "loc": None, "digest": None,
         "facts": {}},
        {"seq": 2, "type": "PHASE_CHANGE", "ts": None, "loc": None, "digest": None,
         "facts": {"from_phase": "PLAN", "to_phase": "NOPE"}},
        {"seq": 3, "type": "SESSION_BOUNDARY", "ts": None, "loc": None, "digest": None,
         "facts": {}},
    ]
    payload = {
        "schema_version": 1,
        "session_id": session_id,
        "adapter": "generic",
        "project": {"name": "X", "git_head": "x", "root_fingerprint": "fx"},
        "runtime": {"provider": "openai", "model": "gpt-x", "reasoning_mode": "unknown"},
        "temperature": "COLD",
        "protocol": {"version": "7.231.9", "binding_status": "BOUND",
                     "git_head": "deadbeef", "registry_sha256": "b" * 64},
        "events": events,
    }
    payload["session_sha256"] = bundle_mod.bundle_digest(payload)
    return payload


def _qualified_finding(finding_id: str = "PAL-0001", *,
                       drift_class: str = "EVIDENCE_FABRICATION",
                       session_id: str = "audit-drift-001") -> dict:
    """A finding that passes the qualification gate: HIGH + BOUND + P1.

    `rule_ids` are resolved from the law surface, not set to the drift-class name:
    the audit gate requires the owner documents behind the cited rules, and a
    taxonomy label owns no document (T-049/T-050).
    """
    from saipal_engine import law as law_mod

    rule_ids = list(law_mod.resolve_law(drift_class)["rule_ids"])
    return {
        "finding_id": finding_id,
        "fingerprint": "f" + finding_id,
        "state": "QUALIFIED",
        "drift_class": drift_class,
        "severity": "P1",
        "confidence": "HIGH",
        "change_target": "CORE_PROTOCOL",
        "rule_ids": rule_ids,
        "root_cause": f"drift class {drift_class!r} contradicts the declared protocol",
        "protected_invariants": ["destructive_confirmation", "recovery_precedence"],
        "harm_warnings": [],
        "occurrences": [{"session_id": session_id, "episode_id": 0,
                         "event_refs": [2]}],
        "protocol_bindings": [{"version": "7.231.9", "binding_status": "BOUND"}],
        "alternatives": ["adapter noise"],
        "audit": None,
    }


def _findings(home: Path) -> list[dict]:
    index = home / "findings" / "index.json"
    if not index.exists():
        return []
    return list(json.loads(index.read_text(encoding="utf-8"))["findings"])


class AuditProducer(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _enqueue(self, finding: dict, body: str) -> dict:
        return enqueue_mod.enqueue_audit(self.home, finding, body, registry=None,
                                         maintainer_root=None)

    def _staging_files(self) -> list[Path]:
        staging = self.home / "audit" / "staging"
        return sorted(staging.glob("*.md")) if staging.is_dir() else []

    # -- acceptance bar 1: qualified finding -> exactly one audit ---------- #

    def test_qualified_finding_enqueues_exactly_one_audit(self) -> None:
        finding = _qualified_finding("PAL-0100")
        record = {"session_id": "audit-drift-001", "imported_at": "2026-01-01T00:00:00Z"}
        bundle = _drift_bundle()
        body = audits_mod.build_audit_body(finding, record, bundle, registry=None)
        self.assertTrue(audits_mod.passes_quality_gate(body, finding))

        result = self._enqueue(finding, body)
        files = self._staging_files()
        self.assertEqual(len(files), 1)
        self.assertEqual(result["audit_number"], 1)
        self.assertEqual(Path(result["audit_path"]).name, files[0].name)
        self.assertTrue(files[0].read_text(encoding="utf-8").startswith("# SAIPAL AUDIT"))

    # -- acceptance bar 2: audit numbering is monotonic -------------------- #

    def test_audit_numbering_is_monotonic_and_collision_safe(self) -> None:
        a = self._enqueue(_qualified_finding("PAL-0200"), "body A")
        b = self._enqueue(_qualified_finding("PAL-0201"), "body B")
        self.assertEqual(a["audit_number"], 1)
        self.assertEqual(b["audit_number"], 2)
        files = self._staging_files()
        self.assertEqual([p.stem for p in files], ["1", "2"])
        self.assertNotEqual(a["audit_path"], b["audit_path"])

    # -- acceptance bar 3: crash after enqueue does not duplicate ---------- #

    def test_crash_after_enqueue_does_not_duplicate(self) -> None:
        finding = _qualified_finding("PAL-0300")
        record = {"session_id": "audit-drift-001", "imported_at": "2026-01-01T00:00:00Z"}
        body = audits_mod.build_audit_body(finding, record, _drift_bundle(),
                                           registry=None)

        first = self._enqueue(finding, body)
        # Simulate a crash + retry with the exact same finding and body.
        second = self._enqueue(finding, body)
        files = self._staging_files()
        self.assertEqual(len(files), 1)
        self.assertEqual(first["audit_number"], second["audit_number"])
        self.assertEqual(first["audit_path"], second["audit_path"])

    # -- acceptance bar 4: existing audit is never overwritten ------------- #

    def test_existing_audit_is_never_overwritten(self) -> None:
        finding = _qualified_finding("PAL-0400")
        self._enqueue(finding, "FIRST BODY")
        self._enqueue(finding, "SECOND DIFFERENT BODY")

        files = self._staging_files()
        self.assertEqual(len(files), 2)
        contents = {p.read_text(encoding="utf-8") for p in files}
        self.assertIn("FIRST BODY", contents)
        self.assertNotIn("FIRST BODY", files[1].read_text(encoding="utf-8"))
        # The first slot kept the original body, the second got the new one.
        self.assertIn("SECOND DIFFERENT BODY", contents)

    # -- acceptance bar 5: secret plaintext is absent ---------------------- #

    def test_secret_plaintext_is_absent(self) -> None:
        redacted = redact_mod.redact_text("key sk-abc123def456ghijklmno")
        self.assertIn("[REDACTED", redacted)
        self.assertNotIn("sk-abc", redacted)

        redacted_dict = redact_mod.redact_dict(
            {"token": "sk-abc123def456ghijklmno", "nested": {"pw": "Bearer xyz123456789"}}
        )
        self.assertNotIn("sk-abc", json.dumps(redacted_dict))
        self.assertNotIn("Bearer xyz", json.dumps(redacted_dict))

    # -- acceptance bar 6: audit contains minimal provenance --------------- #

    def test_audit_contains_minimal_provenance(self) -> None:
        finding = _qualified_finding("PAL-0600")
        record = {"session_id": "audit-drift-001", "imported_at": "2026-01-01T00:00:00Z"}
        body = audits_mod.build_audit_body(finding, record, _drift_bundle(),
                                           registry=None)
        self._enqueue(finding, body)
        file = self._staging_files()[0]
        content = file.read_text(encoding="utf-8")

        self.assertIn("PAL-0600", content)
        self.assertIn("audit-drift-001", content)
        self.assertNotIn('"events":', content, "no raw event stream in audit")
        self.assertNotIn("from_phase", content, "no raw transcript content")
        self.assertLess(len(content), 8000)

    # -- acceptance bar 7: maintainer verdict starts PENDING --------------- #

    def test_maintainer_verdict_starts_pending(self) -> None:
        finding = _qualified_finding("PAL-0700")
        record = {"session_id": "audit-drift-001", "imported_at": "2026-01-01T00:00:00Z"}
        body = audits_mod.build_audit_body(finding, record, _drift_bundle(),
                                           registry=None)
        self._enqueue(finding, body)
        content = self._staging_files()[0].read_text(encoding="utf-8")
        self.assertIn("maintainer_verdict: PENDING", content)

    # -- acceptance bar 8: audit quality gate ------------------------------ #

    def test_audit_quality_gate(self) -> None:
        finding = _qualified_finding("PAL-0800")
        self.assertFalse(audits_mod.passes_quality_gate("", finding),
                         "empty body must fail the quality gate")

        record = {"session_id": "audit-drift-001", "imported_at": "2026-01-01T00:00:00Z"}
        body = audits_mod.build_audit_body(finding, record, _drift_bundle(),
                                           registry=None)
        self.assertTrue(audits_mod.passes_quality_gate(body, finding))

    # -- acceptance bar 9: multiple root causes -> separate audits --------- #

    def test_multiple_root_causes_produce_separate_audits(self) -> None:
        a = self._enqueue(_qualified_finding("PAL-0900", drift_class="EVIDENCE_FABRICATION"),
                          "audit EVIDENCE_FABRICATION")
        b = self._enqueue(_qualified_finding("PAL-0901",
                                             drift_class="DESTRUCTIVE_GATE_DRIFT"),
                          "audit DESTRUCTIVE_GATE_DRIFT")
        self.assertNotEqual(a["audit_number"], b["audit_number"])
        self.assertNotEqual(a["audit_path"], b["audit_path"])
        self.assertEqual(len(self._staging_files()), 2)

    # -- acceptance bar 10: no qualified findings -> nothing emitted ------- #

    def test_no_qualified_findings_emits_nothing(self) -> None:
        support.put_inbox(self.home, COLD)
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        self.assertEqual(payload["audits_emitted"], 0)
        self.assertEqual(_findings(self.home), [])
        self.assertFalse((self.home / "audit").exists(),
                         "no audit dir may be materialized without findings")


class ConcurrentPublisherRedControl(unittest.TestCase):
    """T-031 red control: two concurrent publishers must not race the same audit id.

    PAL-AUDIT-02 step 1 requires acquiring the audit inbox lock before allocating
    a number. Without the lock, two threads that both read the counter ledger
    before either writes it would race to the same ``audit/N.md``. This test
    launches two threads that each enqueue a distinct finding into the same
    home and proves exactly two distinct, non-colliding audit numbers result.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_concurrent_publishers_do_not_collide(self) -> None:
        import threading

        results: list[dict] = []
        errors: list[str] = []
        barrier = threading.Barrier(2)

        def _publish(finding_id: str, body: str) -> None:
            finding = _qualified_finding(finding_id)
            try:
                barrier.wait(timeout=5)
                result = enqueue_mod.enqueue_audit(self.home, finding, body)
                results.append(result)
            except Exception as exc:
                errors.append(f"{finding_id}: {exc}")

        t1 = threading.Thread(
            target=_publish, args=("PAL-CON1", "concurrent body 1")
        )
        t2 = threading.Thread(
            target=_publish, args=("PAL-CON2", "concurrent body 2")
        )
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        self.assertEqual(errors, [], f"publishers raised: {errors}")
        self.assertEqual(len(results), 2)
        numbers = sorted(r["audit_number"] for r in results)
        self.assertEqual(numbers, [1, 2], f"expected [1, 2], got {numbers}")
        self.assertNotEqual(
            results[0]["audit_path"], results[1]["audit_path"],
            "two findings must not land on the same file",
        )
        staging = self.home / "audit" / "staging"
        md_files = sorted(staging.glob("*.md"))
        self.assertEqual(len(md_files), 2)

    def test_lock_is_released_after_enqueue(self) -> None:
        """The audit inbox lock must not persist after a successful enqueue."""
        finding = _qualified_finding("PAL-LOCK1")
        enqueue_mod.enqueue_audit(self.home, finding, "lock test body")
        lock_file = self.home / "audit" / "staging" / "audit_inbox.lock"
        self.assertFalse(
            lock_file.exists(),
            "lock must be released after enqueue completes",
        )

    def test_lock_blocks_second_publisher(self) -> None:
        """When the lock is held, a second publisher must wait or take over."""
        import threading

        lock_dir = self.home / "audit" / "staging"
        lock_dir.mkdir(parents=True, exist_ok=True)
        lock = enqueue_mod.AuditInboxLock(lock_dir)
        self.assertTrue(lock.acquire())

        blocked = threading.Event()
        result_holder: list = []

        def _try_enqueue() -> None:
            finding = _qualified_finding("PAL-BLOCK")
            try:
                r = enqueue_mod.enqueue_audit(self.home, finding, "blocked body")
                result_holder.append(r)
            except Exception as exc:
                result_holder.append(exc)
            finally:
                blocked.set()

        t = threading.Thread(target=_try_enqueue)
        t.start()
        t.join(timeout=0.2)
        # The second publisher should still be blocked waiting for the lock
        self.assertFalse(
            blocked.is_set(),
            "second publisher must be blocked while the first holds the lock",
        )
        lock.release()
        t.join(timeout=10)
        self.assertTrue(blocked.is_set())
        self.assertIsInstance(result_holder[0], dict)


if __name__ == "__main__":
    unittest.main()
