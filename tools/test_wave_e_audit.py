"""Wave E: audit producer, exercised through the real enqueue API.

Wave D findings reach immutable numbered audits. The mechanical pipeline only
emits findings for classes the mechanical detectors can fire; P0/P1 classes
like EVIDENCE_FABRICATION arrive from the LLM analyst. So these tests drive
the enqueue contract directly with hand-built QUALIFIED findings, plus the
cold-session "emit nothing" bar through the real CLI.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import pal_test_support as support
from saipal_engine import audits as audits_mod
from saipal_engine import bundle as bundle_mod
from saipal_engine import enqueue as enqueue_mod
from saipal_engine import redact as redact_mod


def _normpath(text: str) -> str:
    import ntpath
    import posixpath

    return (ntpath if "\\" in text else posixpath).normpath(text)


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

class PendingRecoveryImmutability(unittest.TestCase):
    """W2-002 (SRC-005): a recovered pending entry must never overwrite the
    physical audit slot. The decision table is: file absent -> write; file
    present with the intended digest -> finalize only (zero writes to the
    file); file present with different bytes -> refuse and preserve. The same
    table applies to local staging and a maintainer sink with private
    bookkeeping; the digest check runs before any write in both shapes."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = support.make_home(Path(self.tmp.name))
        (self.home / "audit" / "staging").mkdir(parents=True, exist_ok=True)

    def _finding(self, finding_id: str = "F-W2-002") -> dict:
        return {"finding_id": finding_id, "rule_id": "PAL-TEST", "severity": "low"}

    def _force_pending(self) -> None:
        """Replay the crash that happened after the file write but before the
        second ledger write: the entry is pending while the slot exists."""
        entries_path = enqueue_mod._entries_path(self.home, None)
        entries = enqueue_mod._read_entries(entries_path)
        for entry in entries:
            if entry.get("finding_id") == self._finding()["finding_id"]:
                entry["pending"] = True
        enqueue_mod._write_ledger(entries_path, entries)

    def _sink_slot(self) -> Path:
        return self.sink / "audit" / "1.md"

    def test_a_crash_before_write_retry_writes_the_claimed_slot_once(self) -> None:
        finding = self._finding()
        first = enqueue_mod.enqueue_audit(self.home, finding, "THE BODY\n")
        self._force_pending()
        slot = self.home / "audit" / "staging" / "1.md"
        slot.unlink()
        second = enqueue_mod.enqueue_audit(self.home, finding, "THE BODY\n")
        self.assertEqual(slot.read_text(encoding="utf-8"), "THE BODY\n")
        self.assertEqual(second["audit_number"], first["audit_number"])
        pending = [
            e
            for e in enqueue_mod._read_entries(
                enqueue_mod._entries_path(self.home, None)
            )
            if e.get("finding_id") == finding["finding_id"]
        ]
        self.assertFalse(pending[0].get("pending"), "recovery must finalize the ledger")

    def test_b_crash_after_correct_write_retry_performs_zero_file_writes(self) -> None:
        finding = self._finding()
        first = enqueue_mod.enqueue_audit(self.home, finding, "THE BODY\n")
        self._force_pending()
        slot = self.home / "audit" / "staging" / "1.md"
        before_bytes = slot.read_bytes()
        before_mtime = slot.stat().st_mtime_ns
        second = enqueue_mod.enqueue_audit(self.home, finding, "THE BODY\n")
        self.assertEqual(slot.read_bytes(), before_bytes, "slot content must be untouched")
        self.assertEqual(slot.stat().st_mtime_ns, before_mtime, "slot mtime must be untouched")
        self.assertEqual(second["audit_number"], first["audit_number"],
                         "recovery keeps the original identity")
        pending = [
            e
            for e in enqueue_mod._read_entries(
                enqueue_mod._entries_path(self.home, None)
            )
            if e.get("finding_id") == finding["finding_id"]
        ]
        self.assertFalse(pending[0].get("pending"))

    def test_c_mismatched_existing_bytes_are_refused_and_preserved(self) -> None:
        from saipal_engine.errors import PalError

        finding = self._finding()
        enqueue_mod.enqueue_audit(self.home, finding, "THE BODY\n")
        self._force_pending()
        slot = self.home / "audit" / "staging" / "1.md"
        slot.write_text("maintainer-edited\n", encoding="utf-8")
        before = slot.read_bytes()
        with self.assertRaises(PalError) as caught:
            enqueue_mod.enqueue_audit(self.home, finding, "THE BODY\n")
        self.assertEqual(str(caught.exception.code), "EVIDENCE_MISMATCH")
        self.assertEqual(slot.read_bytes(), before, "existing bytes must be preserved")
        pending = [
            e
            for e in enqueue_mod._read_entries(
                enqueue_mod._entries_path(self.home, None)
            )
            if e.get("finding_id") == finding["finding_id"]
        ]
        self.assertTrue(pending[0].get("pending"), "the pending claim stays for the operator")

    def test_c_maintainer_sink_mismatch_is_refused_and_preserved(self) -> None:
        """The same decision table guards the external maintainer sink."""
        from saipal_engine.errors import PalError

        sink = Path(self.tmp.name) / "maintainer"
        (sink / "audit").mkdir(parents=True)
        private = Path(self.tmp.name) / "private"
        private.mkdir()
        finding = self._finding("F-W2-002-SINK")
        enqueue_mod.enqueue_audit(
            self.home, finding, "SINK BODY\n",
            maintainer_root=sink, private_ledger_home=private,
        )
        entries_path = enqueue_mod._entries_path(private, None)
        entries = enqueue_mod._read_entries(entries_path)
        for entry in entries:
            if entry.get("finding_id") == finding["finding_id"]:
                entry["pending"] = True
        enqueue_mod._write_ledger(entries_path, entries)
        slot = sink / "audit" / "1.md"
        slot.write_text("maintainer-edited\n", encoding="utf-8")
        before = slot.read_bytes()
        with self.assertRaises(PalError) as caught:
            enqueue_mod.enqueue_audit(
                self.home, finding, "SINK BODY\n",
                maintainer_root=sink, private_ledger_home=private,
            )
        self.assertEqual(str(caught.exception.code), "EVIDENCE_MISMATCH")
        self.assertEqual(slot.read_bytes(), before)


class PendingRecoveryConfinement(unittest.TestCase):
    """W2-002 closure retry (T-122): the recovery digest must judge the
    PHYSICAL node at the audit slot, never the node a symlink/junction/
    reparse point LEADS TO. A symlink that points at byte-identical content
    stored outside the intended root is an escape, not a recovered slot:
    matching external bytes cannot finalize a pending audit, dangling
    indirection must not create its target, and every resolution/stat/open/
    digest failure fails closed with the pending ledger claim preserved.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = support.make_home(Path(self.tmp.name))
        (self.home / "audit" / "staging").mkdir(parents=True, exist_ok=True)
        self.external = Path(self.tmp.name) / "external"
        self.external.mkdir()
        (self.external / "matching.md").write_text("THE BODY\n", encoding="utf-8")
        (self.external / "mismatched.md").write_text("foreign bytes\n", encoding="utf-8")

    def _finding(self, finding_id: str = "F-W2-002-CONF") -> dict:
        return {"finding_id": finding_id, "rule_id": "PAL-TEST", "severity": "low"}

    def _stage_pending(self, finding_id: str = "F-W2-002-CONF") -> None:
        """Allocate + finalize once, then replay the crash shape: pending
        entry, existing slot with the intended bytes."""
        finding = self._finding(finding_id)
        enqueue_mod.enqueue_audit(self.home, finding, "THE BODY\n")
        entries_path = enqueue_mod._entries_path(self.home, None)
        entries = enqueue_mod._read_entries(entries_path)
        for entry in entries:
            if entry.get("finding_id") == finding_id:
                entry["pending"] = True
        enqueue_mod._write_ledger(entries_path, entries)

    def _pending_state(self, finding_id: str = "F-W2-002-CONF") -> bool:
        entries_path = enqueue_mod._entries_path(self.home, None)
        for entry in enqueue_mod._read_entries(entries_path):
            if entry.get("finding_id") == finding_id:
                return bool(entry.get("pending"))
        raise AssertionError("no ledger entry for finding")

    def _slot(self) -> Path:
        return self.home / "audit" / "staging" / "1.md"

    def _symlink_or_skip(self, slot: Path, target: Path) -> str:
        """Create the strongest file-level indirection the platform allows.
        On Windows this needs symlink privilege or Developer Mode; tests that
        need an always-available Windows control use _indirect_dir_junction
        (a directory junction is creatable without elevation)."""
        if slot.is_symlink() or slot.exists():
            slot.unlink()
        try:
            slot.symlink_to(target)
            return "symlink"
        except OSError as exc:
            # The helper PROMISES a skip and used to re-raise instead, so an
            # unelevated Windows host reported six ERRORs that read like
            # confinement failures while measuring nothing but
            # SeCreateSymbolicLinkPrivilege. A host that cannot build the
            # indirection cannot measure the refusal.
            raise unittest.SkipTest(
                f"this host cannot create a file symlink: {exc}"
            ) from None

    def _make_junction(self, junction: Path, target: Path) -> None:
        """Create a directory junction without elevation (Windows)."""
        import _winapi  # junction creation on Windows

        _winapi.CreateJunction(str(target), str(junction))

    @unittest.skipUnless(os.name == "nt", "Windows reparse-point control")
    def test_windows_junction_escape_is_refused_and_external_bytes_preserved(self):
        """Named Windows live acceptance: staging replaced by a junction to an
        external directory holding byte-identical slot content. The junction
        itself is the escape (the slot name resolves through it); recovery
        must refuse without touching the external bytes. The detection must
        work WITHOUT elevation, so it cannot depend on os.lstat S_ISLNK (a
        junction is not a symlink to lstat); the reparse attribute is
        authority. On platforms without the ctypes probe the equivalent
        POSIX directory-symlink control below carries the same guarantee."""
        self._stage_pending()
        slot = self._slot()
        before = slot.read_bytes()
        staging = self.home / "audit" / "staging"
        clone = self.external / "staging-clone"
        clone.mkdir(parents=True)
        slot.replace(clone / "1.md")
        for item in list(staging.iterdir()):
            item.unlink()
        staging.rmdir()
        self._make_junction(staging, clone)
        from saipal_engine.errors import PalError

        with self.assertRaises(PalError):
            enqueue_mod.enqueue_audit(self.home, self._finding(), "THE BODY\n")
        # External clone bytes untouched, junction still in place, pending kept.
        self.assertEqual((clone / "1.md").read_bytes(), before)
        self.assertTrue(self._slot().exists())
        self.assertTrue(self._pending_state())

    def test_symlink_escape_to_matching_external_bytes_is_refused(self):
        """The strongest primitive available to the test environment: the slot
        name itself is a symlink to external byte-identical content."""
        self._stage_pending()
        slot = self._slot()
        external = self.external / "matching.md"
        before = external.read_bytes()
        primitive = self._symlink_or_skip(slot, external)
        from saipal_engine.errors import PalError

        with self.assertRaises(PalError) as caught:
            enqueue_mod.enqueue_audit(self.home, self._finding(), "THE BODY\n")
        self.assertIn(str(caught.exception.code), {"PATH_ESCAPE", "VALIDATION_FAILED"})
        self.assertEqual(external.read_bytes(), before, "external bytes must be preserved")
        self.assertTrue(slot.is_symlink(), f"{primitive} must not be consumed")
        self.assertTrue(self._pending_state())

    def test_symlink_escape_to_mismatched_external_bytes_is_refused(self):
        self._stage_pending()
        slot = self._slot()
        external = self.external / "mismatched.md"
        before = external.read_bytes()
        slot.unlink()
        self._symlink_or_skip(slot, external)
        from saipal_engine.errors import PalError

        with self.assertRaises(PalError):
            enqueue_mod.enqueue_audit(self.home, self._finding(), "THE BODY\n")
        self.assertEqual(external.read_bytes(), before)
        self.assertTrue(self._pending_state())

    def test_dangling_symlink_is_refused_and_target_never_created(self):
        self._stage_pending()
        slot = self._slot()
        target = self.external / "never-created.md"
        slot.unlink()
        self._symlink_or_skip(slot, target)
        from saipal_engine.errors import PalError

        with self.assertRaises(PalError):
            enqueue_mod.enqueue_audit(self.home, self._finding(), "THE BODY\n")
        self.assertFalse(target.exists(), "dangling indirection must not create its target")
        self.assertTrue(slot.is_symlink(), "the indirection itself must be preserved")
        self.assertTrue(self._pending_state())

    def test_dangling_internal_symlink_is_refused_and_target_never_created(self):
        """The closure-retry reproduction: the dangling target lies INSIDE the
        allowed root. `Path.exists()` follows the link and reads False, so the
        recovery branch used to be skipped entirely -- enqueue returned
        success and the guarded write created the symlink's target. Recovery
        inspection is now unconditional for a pending entry and judged by
        lstat, so this shape refuses closed."""
        self._stage_pending()
        slot = self._slot()
        internal_target = self.home / "audit" / "staging" / "elsewhere.md"
        slot.unlink()
        self._symlink_or_skip(slot, internal_target)
        from saipal_engine.errors import PalError

        with self.assertRaises(PalError) as caught:
            enqueue_mod.enqueue_audit(self.home, self._finding(), "THE BODY\n")
        self.assertIn(str(caught.exception.code), {"PATH_ESCAPE", "VALIDATION_FAILED"})
        self.assertFalse(internal_target.exists(), "inside-root target must remain absent")
        self.assertTrue(slot.is_symlink(), "the symlink itself must remain")
        self.assertTrue(self._pending_state(), "the pending ledger claim must remain")

    @unittest.skipIf(os.name == "nt", "POSIX fifo control")
    def test_non_regular_node_at_slot_is_refused(self):
        """A FIFO (or any non-regular node) at the slot is never trusted."""
        self._stage_pending()
        slot = self._slot()
        slot.unlink()
        os.mkfifo(str(slot))
        from saipal_engine.errors import PalError

        with self.assertRaises(PalError):
            enqueue_mod.enqueue_audit(self.home, self._finding(), "THE BODY\n")
        self.assertTrue(self._pending_state())

    @unittest.skipIf(os.name == "nt", "POSIX directory-symlink control; the Windows junction control carries the reparse case")
    def test_slot_outside_root_via_swapped_staging_directory_is_refused(self):
        """The audit directory itself swapped for a symlink to an external
        directory is an escape even when the inner slot looks regular."""
        self._stage_pending()
        staging = self.home / "audit" / "staging"
        external_dir = self.external / "staging-clone"
        external_dir.mkdir()
        slot = self._slot()
        before = slot.read_bytes()
        slot.replace(external_dir / "1.md")
        for item in list(staging.iterdir()):
            if item.is_dir():
                item.replace(external_dir / item.name)
            else:
                item.unlink()
        staging.rmdir()
        self._symlink_or_skip(staging, external_dir)
        from saipal_engine.errors import PalError

        with self.assertRaises(PalError):
            enqueue_mod.enqueue_audit(self.home, self._finding(), "THE BODY\n")
        self.assertEqual((external_dir / "1.md").read_bytes(), before)
        self.assertTrue(self._pending_state())

    def test_stat_failure_fails_closed(self):
        """A slot that cannot be stated fails closed, pending claim kept."""
        self._stage_pending()
        slot = self._slot()
        from saipal_engine.errors import PalError

        real_lstat = os.lstat

        def broken(path, *args, **kwargs):
            if _normpath(str(path)).endswith(_normpath(str(slot))):
                raise OSError("simulated stat failure")
            return real_lstat(path, *args, **kwargs)

        with unittest.mock.patch("saipal_engine.enqueue.os.lstat", broken):
            with self.assertRaises(PalError) as caught:
                enqueue_mod.enqueue_audit(self.home, self._finding(), "THE BODY\n")
        self.assertEqual(str(caught.exception.code), "VALIDATION_FAILED")
        self.assertTrue(self._pending_state())

    def test_open_failure_fails_closed(self):
        """A slot that lstats as regular but cannot be opened fails closed."""
        self._stage_pending()
        slot = self._slot()
        from saipal_engine.errors import PalError

        real_open = os.open

        def broken(path, flags, *args, **kwargs):
            if _normpath(str(path)).endswith(_normpath(str(slot))):
                raise OSError("simulated open failure")
            return real_open(path, flags, *args, **kwargs)

        with unittest.mock.patch("saipal_engine.enqueue.os.open", broken):
            with self.assertRaises(PalError) as caught:
                enqueue_mod.enqueue_audit(self.home, self._finding(), "THE BODY\n")
        self.assertEqual(str(caught.exception.code), "VALIDATION_FAILED")
        self.assertTrue(slot.is_file(), "slot bytes untouched")
        self.assertTrue(self._pending_state())

    def test_digest_mutation_mid_read_fails_closed(self):
        """A slot whose bytes mutate between lstat and the read-back fails
        closed on the digest mismatch instead of trusting a partial read."""
        self._stage_pending()
        slot = self._slot()
        before = slot.read_bytes()
        from saipal_engine.errors import PalError
        from saipal_engine import enqueue as eq

        real_open = os.open
        mutated = {"done": False}

        def opening(path, flags, *args, **kwargs):
            handle = real_open(path, flags, *args, **kwargs)
            if (
                not mutated["done"]
                and _normpath(str(path)).endswith(_normpath(str(slot)))
            ):
                mutated["done"] = True
                slot.write_bytes(b"swapped by an external writer\n")
            return handle

        with unittest.mock.patch("saipal_engine.enqueue.os.open", opening):
            with self.assertRaises(PalError) as caught:
                enqueue_mod.enqueue_audit(self.home, self._finding(), "THE BODY\n")
        self.assertIn(str(caught.exception.code), {"VALIDATION_FAILED", "EVIDENCE_MISMATCH"})
        self.assertTrue(self._pending_state())

    def test_maintainer_sink_symlink_escape_is_refused(self):
        """The same confinement governs the maintainer sink path."""
        sink = Path(self.tmp.name) / "maintainer"
        (sink / "audit").mkdir(parents=True)
        private = Path(self.tmp.name) / "private"
        private.mkdir()
        finding = self._finding("F-W2-002-SINK-CONF")
        enqueue_mod.enqueue_audit(
            self.home, finding, "SINK BODY\n",
            maintainer_root=sink, private_ledger_home=private,
        )
        entries_path = enqueue_mod._entries_path(private, None)
        entries = enqueue_mod._read_entries(entries_path)
        for entry in entries:
            if entry.get("finding_id") == finding["finding_id"]:
                entry["pending"] = True
        enqueue_mod._write_ledger(entries_path, entries)
        slot = sink / "audit" / "1.md"
        slot.unlink()
        external = self.external / "matching.md"
        before = external.read_bytes()
        self._symlink_or_skip(slot, external)
        from saipal_engine.errors import PalError

        with self.assertRaises(PalError):
            enqueue_mod.enqueue_audit(
                self.home, finding, "SINK BODY\n",
                maintainer_root=sink, private_ledger_home=private,
            )
        self.assertEqual(external.read_bytes(), before)
        for entry in enqueue_mod._read_entries(entries_path):
            if entry.get("finding_id") == finding["finding_id"]:
                self.assertTrue(entry.get("pending"))
                break


class MaintainerSinkRecoveryMatrix(PendingRecoveryImmutability):
    """The full W2-002 recovery matrix repeated on the maintainer sink path:
    each control re-runs with the sink's audit directory as the slot location
    and the private ledger as the bookkeeping home. The inherited controls
    are parameterized by writing through a sink instead of local staging."""

    def setUp(self) -> None:
        super().setUp()
        self.sink = Path(self.tmp.name) / "maintainer"
        (self.sink / "audit").mkdir(parents=True)
        self.private = Path(self.tmp.name) / "private"
        self.private.mkdir()

    # -- inherited helpers re-targeted at the maintainer sink path ----------

    def _enqueue(self, finding: dict, body: str) -> dict:
        return enqueue_mod.enqueue_audit(
            self.home, finding, body,
            maintainer_root=self.sink, private_ledger_home=self.private,
        )

    def _pending_entries(self, finding_id: str) -> list[dict]:
        entries_path = enqueue_mod._entries_path(self.private, None)
        return [
            e for e in enqueue_mod._read_entries(entries_path)
            if e.get("finding_id") == finding_id
        ]

    def _force_pending(self) -> None:
        entries_path = enqueue_mod._entries_path(self.private, None)
        entries = enqueue_mod._read_entries(entries_path)
        for entry in entries:
            if entry.get("finding_id") == self._finding()["finding_id"]:
                entry["pending"] = True
        enqueue_mod._write_ledger(entries_path, entries)

    def test_a_crash_before_write_retry_writes_the_claimed_slot_once(self) -> None:
        finding = self._finding()
        first = self._enqueue(finding, "SINK BODY\n")
        self._force_pending()
        slot = self._sink_slot()
        slot.unlink()
        second = self._enqueue(finding, "SINK BODY\n")
        self.assertEqual(slot.read_text(encoding="utf-8"), "SINK BODY\n")
        self.assertEqual(second["audit_number"], first["audit_number"])
        self.assertEqual(second["operation_id"], first["operation_id"])
        pending = self._pending_entries(finding["finding_id"])
        self.assertFalse(pending[0].get("pending"), "recovery must finalize the ledger")

    def test_b_crash_after_correct_write_retry_performs_zero_file_writes(self) -> None:
        finding = self._finding()
        first = self._enqueue(finding, "SINK BODY\n")
        self._force_pending()
        slot = self._sink_slot()
        before_bytes = slot.read_bytes()
        before_mtime = slot.stat().st_mtime_ns
        second = self._enqueue(finding, "SINK BODY\n")
        self.assertEqual(slot.read_bytes(), before_bytes, "slot content must be untouched")
        self.assertEqual(slot.stat().st_mtime_ns, before_mtime, "slot mtime must be untouched")
        self.assertEqual(second["audit_number"], first["audit_number"],
                         "recovery keeps the original identity")
        self.assertEqual(second["operation_id"], first["operation_id"])
        pending = self._pending_entries(finding["finding_id"])
        self.assertFalse(pending[0].get("pending"))

    def test_c_mismatched_existing_bytes_are_refused_and_preserved(self) -> None:
        from saipal_engine.errors import PalError

        finding = self._finding()
        self._enqueue(finding, "SINK BODY\n")
        self._force_pending()
        slot = self._sink_slot()
        slot.write_text("maintainer-edited\n", encoding="utf-8")
        before = slot.read_bytes()
        with self.assertRaises(PalError) as caught:
            self._enqueue(finding, "SINK BODY\n")
        self.assertEqual(str(caught.exception.code), "EVIDENCE_MISMATCH")
        self.assertEqual(slot.read_bytes(), before, "existing bytes must be preserved")
        pending = self._pending_entries(finding["finding_id"])
        self.assertTrue(pending[0].get("pending"), "the pending claim stays for the operator")

    def test_c_maintainer_sink_mismatch_is_refused_and_preserved(self) -> None:
        self.test_c_mismatched_existing_bytes_are_refused_and_preserved()

    def test_dangling_internal_symlink_sink_is_refused_and_target_never_created(self) -> None:
        """Maintainer-sink variant of the closure-retry reproduction."""
        from saipal_engine.errors import PalError

        finding = self._finding()
        self._enqueue(finding, "SINK BODY\n")
        self._force_pending()
        slot = self._sink_slot()
        internal_target = self.sink / "audit" / "elsewhere.md"
        slot.unlink()
        PendingRecoveryConfinement._symlink_or_skip(self, slot, internal_target)
        with self.assertRaises(PalError) as caught:
            self._enqueue(finding, "SINK BODY\n")
        self.assertIn(str(caught.exception.code), {"PATH_ESCAPE", "VALIDATION_FAILED"})
        self.assertFalse(internal_target.exists())
        self.assertTrue(slot.is_symlink())
        pending = self._pending_entries(finding["finding_id"])
        self.assertTrue(pending[0].get("pending"))


if __name__ == "__main__":
    unittest.main()
