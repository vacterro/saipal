"""SRC-004 (audit/3.md) clause dispositions -- red controls for the LIVE clauses.

Each test proves one audit clause is terminal on the REAL checkout, not by a
broad suite. The triage in audit/src-004-triage.md named six LIVE repairs:
W2-006 (transactional disposition import), W2-007 (finding delivery truth),
PERF-001 (session-index projection compaction), PERF-002 (index transaction
amplification), PERF-004 (DONE job compaction), PERF-005 (parsed-bundle cache).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import jobs as jobs_mod
from saipal_analyst import provenance as prov_mod
from saipal_engine import bundle as bundle_mod
from saipal_engine import closedloop as cl
from saipal_engine import publications as pub_mod
from saipal_engine import sessions as sessions_mod
from saipal_engine.errors import PalError
from saipal_engine.registry import load_registry


class W2_006DispositionTransactional(unittest.TestCase):
    """SRC-004 W2-006: a bad later row must not leave earlier rows committed."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        self.links_path = self.home / "closed_loop_links.json"
        self.links_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "links": [
                        {
                            "finding_id": "PAL-1",
                            "audit_number": 1,
                            "audit_path": "audit/1.md",
                            "audit_sha256": "a" * 64,
                            "receipt_id": None,
                            "work_id": None,
                            "disposition": None,
                            "fix_version": None,
                            "closed_at": None,
                        },
                        {
                            "finding_id": "PAL-2",
                            "audit_number": 2,
                            "audit_path": "audit/2.md",
                            "audit_sha256": "b" * 64,
                            "receipt_id": None,
                            "work_id": None,
                            "disposition": None,
                            "fix_version": None,
                            "closed_at": None,
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _batch(self, rows: list[dict]) -> Path:
        f = self.tmp / "batch.json"
        f.write_text(json.dumps(rows), encoding="utf-8")
        return f

    def test_valid_then_invalid_keeps_ledger_unchanged(self) -> None:
        before = self.links_path.read_bytes()
        f = self._batch(
            [
                {"audit_number": 1, "disposition": "ENGINE_FIX"},
                {"audit_number": 2, "disposition": "NOT_A_REAL_DISPOSITION"},
            ]
        )
        with self.assertRaises(PalError) as ctx:
            cl.import_disposition_file(self.home, f)
        self.assertEqual(ctx.exception.code, "VALIDATION_FAILED")
        self.assertEqual(self.links_path.read_bytes(), before, "zero writes on any invalid row")

    def test_fully_valid_batch_commits_all(self) -> None:
        f = self._batch(
            [
                {"audit_number": 1, "disposition": "ENGINE_FIX"},
                {"audit_number": 2, "disposition": "REJECTED_FINDING"},
            ]
        )
        imported = cl.import_disposition_file(self.home, f)
        self.assertEqual(len(imported), 2)
        status, links, _ = cl.load_links(self.home)
        self.assertEqual(status, "ok")
        assert links is not None
        by_num = {int(e["audit_number"]): e for e in links["links"]}
        self.assertEqual(by_num[1]["disposition"], "ENGINE_FIX")
        self.assertEqual(by_num[2]["disposition"], "REJECTED_FINDING")

    def test_contradictory_duplicate_rows_refused(self) -> None:
        before = self.links_path.read_bytes()
        f = self._batch(
            [
                {"audit_number": 1, "disposition": "ENGINE_FIX"},
                {"audit_number": 1, "disposition": "NO_CHANGE"},
            ]
        )
        with self.assertRaises(PalError) as ctx:
            cl.import_disposition_file(self.home, f)
        self.assertEqual(ctx.exception.code, "VALIDATION_FAILED")
        self.assertEqual(self.links_path.read_bytes(), before)

    def test_reimport_identical_batch_idempotent(self) -> None:
        f = self._batch([{"audit_number": 1, "disposition": "ENGINE_FIX"}])
        cl.import_disposition_file(self.home, f)
        first = self.links_path.read_bytes()
        imported = cl.import_disposition_file(self.home, f)
        self.assertEqual(len(imported), 1)
        self.assertEqual(self.links_path.read_bytes(), first, "byte-identical ledger on re-import")


class W2_007FindingDeliveryTruth(unittest.TestCase):
    """SRC-004 W2-007: the publication ledger is the authoritative delivery truth."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _finding(self, audit_number: int = 1, delivery: str | None = pub_mod.PENDING) -> dict:
        return {
            "finding_id": "PAL-1",
            "fingerprint": "fp-1",
            "state": "EMITTED",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P1",
            "confidence": "HIGH",
            "change_target": "ENGINE",
            "rule_ids": ["COMMAND_ROUTE_DRIFT"],
            "root_cause": "the command went outside the declared carrier surface",
            "protected_invariants": [],
            "harm_warnings": [],
            "occurrences": [{"session_id": "s-1", "episode_id": 0, "event_refs": [2]}],
            "protocol_bindings": [],
            "alternatives": [],
            "mechanical_confidence": "HIGH",
            "audit": {
                "audit_number": audit_number,
                "audit_sha256": "c" * 64,
                "audit_path": "audit/1.md",
                "delivery": delivery,
            },
        }

    def _findings_index(self) -> Path:
        p = self.home / "findings" / "index.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def test_mark_published_reconciles_finding_cache(self) -> None:
        pub_mod.record_pending(
            self.home,
            finding_id="PAL-1",
            audit_number=1,
            audit_path="audit/1.md",
            audit_sha256="c" * 64,
            reason="sink down",
        )
        index = self._findings_index()
        index.write_text(json.dumps({"schema_version": 1, "findings": [self._finding()]}), encoding="utf-8")

        pub_mod.mark_published(self.home, audit_number=1, audit_sha256="c" * 64)

        ledger = pub_mod.load_publications(self.home)
        self.assertEqual(ledger[1]["publications"][0]["status"], pub_mod.PUBLISHED)
        persisted = json.loads(index.read_text(encoding="utf-8"))["findings"][0]
        self.assertEqual(persisted["audit"]["delivery"], pub_mod.PUBLISHED)

    def test_delivery_status_derives_from_ledger_not_stale_cache(self) -> None:
        pub_mod.record_pending(
            self.home,
            finding_id="PAL-1",
            audit_number=1,
            audit_path="audit/1.md",
            audit_sha256="c" * 64,
            reason="sink down",
        )
        finding = self._finding(delivery=pub_mod.PENDING)
        # Stale cache, ledger still PENDING: reads PENDING.
        self.assertEqual(pub_mod.delivery_status(self.home, finding), pub_mod.PENDING)
        pub_mod.mark_published(self.home, audit_number=1, audit_sha256="c" * 64)
        # Ledger now PUBLISHED: the derived surface reads PUBLISHED even if the
        # finding cache has not been reconciled yet (cold-start convergence).
        stale_finding = self._finding(delivery=pub_mod.PENDING)
        self.assertEqual(pub_mod.delivery_status(self.home, stale_finding), pub_mod.PUBLISHED)

    def _force_entry_status(self, status: str) -> None:
        _status, ledger, _detail = pub_mod.load_publications(self.home)
        assert ledger is not None
        ledger["publications"][0]["status"] = status
        pub_mod.save_publications(self.home, ledger)

    def test_pending_ledger_overrides_stale_published_cache(self) -> None:
        pub_mod.record_pending(
            self.home,
            finding_id="PAL-1",
            audit_number=1,
            audit_path="audit/1.md",
            audit_sha256="c" * 64,
            reason="sink down",
        )
        stale = self._finding(delivery=pub_mod.PUBLISHED)
        self.assertEqual(
            pub_mod.delivery_status(self.home, stale), pub_mod.PENDING,
            "a PENDING ledger row is authoritative over a stale PUBLISHED cache",
        )

    def test_published_ledger_overrides_stale_pending_cache(self) -> None:
        pub_mod.record_pending(
            self.home,
            finding_id="PAL-1",
            audit_number=1,
            audit_path="audit/1.md",
            audit_sha256="c" * 64,
            reason="sink down",
        )
        pub_mod.mark_published(self.home, audit_number=1, audit_sha256="c" * 64)
        stale = self._finding(delivery=pub_mod.PENDING)
        self.assertEqual(
            pub_mod.delivery_status(self.home, stale), pub_mod.PUBLISHED,
            "a PUBLISHED ledger row is authoritative over a stale PENDING cache",
        )

    def test_quarantined_ledger_overrides_stale_published_cache(self) -> None:
        pub_mod.record_pending(
            self.home,
            finding_id="PAL-1",
            audit_number=1,
            audit_path="audit/1.md",
            audit_sha256="c" * 64,
            reason="sink down",
        )
        self._force_entry_status(pub_mod.QUARANTINED)
        stale = self._finding(delivery=pub_mod.PUBLISHED)
        self.assertEqual(
            pub_mod.delivery_status(self.home, stale), pub_mod.QUARANTINED,
            "a QUARANTINED ledger row is authoritative over a stale PUBLISHED cache",
        )

    def test_no_ledger_row_falls_back_to_finding_cache(self) -> None:
        finding = self._finding(delivery=pub_mod.PUBLISHED)
        self.assertEqual(
            pub_mod.delivery_status(self.home, finding), pub_mod.PUBLISHED,
            "no matching ledger row keeps the documented finding-cache fallback",
        )

    def test_wrong_audit_digest_must_not_override_finding(self) -> None:
        pub_mod.record_pending(
            self.home,
            finding_id="PAL-1",
            audit_number=1,
            audit_path="audit/1.md",
            audit_sha256="c" * 64,
            reason="sink down",
        )
        other_audit = self._finding(delivery=pub_mod.PENDING)
        other_audit["audit"]["audit_sha256"] = "d" * 64
        self.assertEqual(
            pub_mod.delivery_status(self.home, other_audit), pub_mod.PENDING,
            "a ledger row for a different audit digest must not override this finding",
        )

    def test_wrong_audit_number_must_not_override_finding(self) -> None:
        pub_mod.record_pending(
            self.home,
            finding_id="PAL-1",
            audit_number=1,
            audit_path="audit/1.md",
            audit_sha256="c" * 64,
            reason="sink down",
        )
        other_audit = self._finding(audit_number=2, delivery=pub_mod.PENDING)
        self.assertEqual(
            pub_mod.delivery_status(self.home, other_audit), pub_mod.PENDING,
            "a ledger row for a different audit number must not override this finding",
        )


class PERF_001IndexCompaction(unittest.TestCase):
    """SRC-004 PERF-001: no per-event projections in fresh or compacted records."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_fresh_record_has_no_evidence_refs(self) -> None:
        bundle = {
            "schema_version": 1,
            "session_id": "s-1",
            "adapter": "generic",
            "project": {"name": "X", "git_head": "x", "root_fingerprint": "fx"},
            "runtime": {"provider": "openai", "model": "gpt-x", "reasoning_mode": "unknown"},
            "temperature": "COLD",
            "protocol": {"version": "7.231.9", "binding_status": "BOUND",
                         "git_head": "deadbeef", "registry_sha256": "a" * 64},
            "events": [
                {"seq": 1, "type": "USER_MESSAGE", "facts": {}, "evidence_ref": "s#1"},
                {"seq": 2, "type": "SESSION_BOUNDARY", "facts": {}},
            ],
        }
        bundle["session_sha256"] = bundle_mod.bundle_digest(bundle)
        record = sessions_mod.new_record(
            bundle,
            source_ref="session_inbox/x.json",
            source_sha256="a" * 64,
            bundle_sha256=bundle["session_sha256"],
            generation=1,
            imported_at="2026-01-01T00:00:00Z",
            episodes=[{"index": 0, "start_seq": 1, "end_seq": 2, "kind": "single"}],
        )
        self.assertNotIn("evidence_refs", record)
        self.assertNotIn("mechanical_spans", record)

    def test_compact_index_removes_legacy_projections(self) -> None:
        index = {
            "schema_version": 1,
            "sessions": [
                {
                    "session_id": "s-1", "generation": 1, "status": "IMPORTED",
                    "temperature": "COLD", "last_analyzed_seq": 0, "imports": [],
                    "episodes": [], "semantic": {}, "event_count": 2,
                    "source_ref": "session_inbox/x.json", "source_sha256": "a" * 64,
                    "bundle_sha256": "b" * 64, "adapter": "generic",
                    "project": {"name": "X"}, "runtime": {}, "prefix_sha256": None,
                    "imported_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:00Z",
                    "evidence_refs": [{"seq": 1, "evidence_ref": "s#1"}],
                    "mechanical_spans": [{"start": 1, "end": 2}],
                    "protocol": {"binding_status": "UNKNOWN", "proof_level": "UNKNOWN"},
                }
            ],
        }
        compacted, changed = sessions_mod.compact_index(self.home, index)
        self.assertEqual(changed, 1)
        rec = compacted["sessions"][0]
        self.assertNotIn("evidence_refs", rec)
        self.assertNotIn("mechanical_spans", rec)


class PERF_002IndexTransaction(unittest.TestCase):
    """SRC-004 PERF-002: one continue cycle does not parse the index three times."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_import_inbox_accepts_and_returns_snapshot(self) -> None:
        from saipal_engine import inbox as inbox_mod

        index = {"schema_version": 1, "sessions": []}
        report = inbox_mod.import_inbox(self.home, registry=None, index=index)
        self.assertIsInstance(report["index"], dict)
        self.assertIs(report["index"], index, "caller snapshot reused, no reload")
        self.assertIn("index_changed", report)

    def test_continue_cycle_parses_the_index_once(self) -> None:
        """The audit's VERIFY: an unchanged cycle requires ONE index parse, not three."""
        import saipal
        import saipal_engine.inbox as inbox_mod
        from saipal_engine.registry import load_registry

        counts = {"load": 0}
        real_cycle_load = saipal.load_index
        real_inbox_load = inbox_mod.load_index

        def counting(home, *, registry=None):
            counts["load"] += 1
            return real_inbox_load(home, registry=registry)

        saipal.load_index = counting
        inbox_mod.load_index = counting
        try:
            _exit, _result = saipal._continue_cycle(self.home, load_registry())
        finally:
            saipal.load_index = real_cycle_load
            inbox_mod.load_index = real_inbox_load
        self.assertEqual(_exit, 0)
        self.assertEqual(
            counts["load"], 1,
            f"one continue cycle parsed the index {counts['load']} times "
            "(the audit measured three)",
        )


class PERF_004DoneJobCompaction(unittest.TestCase):
    """SRC-004 PERF-004: settled DONE jobs drop raw payloads."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        self._journal_path = self.home / "analyst" / "jobs.json"
        self._journal_path.parent.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _done_job(self) -> dict:
        return {
            "job_id": "j1", "session_id": "s-1", "episode_index": 0, "slice_index": 0,
            "unit_digest": "d", "finality": "FINAL", "stage": jobs_mod.DONE,
            "attempts": 1, "transport_attempts": 1, "submit_attempts": 1,
            "repairs": 0, "investigator_repairs": 0, "critic_repairs": 0,
            "finalizer_repairs": 0, "backend_type": "openai_compatible", "model": "m",
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
            "run_id": "r1", "attempt_ids": {}, "ambiguous_attempt_ids": [],
            "response_digest": "rd", "response_text": "raw investigator text " * 100,
            "investigator_repair_text": None, "critic_digest": None, "critic_payload": None,
            "critic_response_text": None, "critic_repair_text": None,
            "finalizer_digest": None, "finalizer_response_text": None,
            "finalizer_repair_text": None, "candidate_digest": "cd", "candidate": {"x": 1},
            "receipt_id": "R-1", "error_class": None, "error_detail": None,
            "next_retry_at": None, "verdict": "NO_DRIFT",
        }

    def test_provenance_ready_done_job_compacts(self) -> None:
        prov_mod.save_ledger(
            self.home, {"schema_version": 1, "updated_at": "2026-01-01T00:00:00Z",
                        "records": {"R-1": {"receipt_id": "R-1", "job_id": "j1"}}}
        )
        journal = {"schema_version": 2, "updated_at": "2026-01-01T00:00:00Z", "jobs": {"j1": self._done_job()}}
        changed = jobs_mod.compact_done_jobs(
            journal, self.home, provenance_receipts={"R-1"}
        )
        self.assertEqual(changed, 1)
        job = journal["jobs"]["j1"]
        self.assertIsNone(job["response_text"])
        self.assertIsNone(job["candidate"])
        self.assertEqual(job["response_digest"], "rd")
        self.assertEqual(job["candidate_digest"], "cd")
        self.assertEqual(job["receipt_id"], "R-1")

    def test_job_without_provenance_not_compacted(self) -> None:
        journal = {"schema_version": 2, "updated_at": "2026-01-01T00:00:00Z", "jobs": {"j1": self._done_job()}}
        changed = jobs_mod.compact_done_jobs(journal, self.home, provenance_receipts=set())
        self.assertEqual(changed, 0)
        self.assertIsNotNone(journal["jobs"]["j1"]["response_text"])

    def test_pre_done_never_compacted(self) -> None:
        job = self._done_job()
        job["stage"] = jobs_mod.REMOTE_OUTCOME_UNKNOWN
        journal = {"schema_version": 2, "updated_at": "2026-01-01T00:00:00Z", "jobs": {"j1": job}}
        changed = jobs_mod.compact_done_jobs(journal, self.home, provenance_receipts={"R-1"})
        self.assertEqual(changed, 0)
        self.assertIsNotNone(journal["jobs"]["j1"]["response_text"])


class PERF_005BundleCache(unittest.TestCase):
    """SRC-004 PERF-005: unchanged canonical bundle is parsed once, not twice."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        self.bundle_path = self.home / "bundle.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write_bundle(self) -> str:
        bundle = {
            "schema_version": 1,
            "session_id": "s-1",
            "adapter": "generic",
            "project": {"name": "X", "git_head": "x", "root_fingerprint": "fx"},
            "runtime": {"provider": "openai", "model": "gpt-x", "reasoning_mode": "unknown"},
            "temperature": "COLD",
            "protocol": {"version": "7.231.9", "binding_status": "BOUND",
                         "git_head": "deadbeef", "registry_sha256": "a" * 64},
            "events": [{"seq": 1, "type": "USER_MESSAGE", "facts": {}}],
        }
        bundle["session_sha256"] = bundle_mod.bundle_digest(bundle)
        self.bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        return bundle["session_sha256"]

    def test_unchanged_bundle_reuses_cache(self) -> None:
        bundle_mod.bundle_cache_clear()
        digest = self._write_bundle()
        parses = []
        real = bundle_mod.load_bundle_with_digest
        bundle_mod.load_bundle_with_digest = lambda *a, **k: (parses.append(1), real(*a, **k))[1]
        try:
            first = bundle_mod.load_bundle_file(self.bundle_path, registry=None, expected_sha256=digest)
            self.assertEqual(len(parses), 1, "first load parses once")
            second = bundle_mod.load_bundle_file(self.bundle_path, registry=None, expected_sha256=digest)
            self.assertEqual(len(parses), 1, "unchanged unit performs ZERO second JSON parse")
            self.assertEqual(first["session_id"], second["session_id"])
        finally:
            bundle_mod.load_bundle_with_digest = real

    def test_expected_digest_mismatch_invalidates(self) -> None:
        bundle_mod.bundle_cache_clear()
        digest = self._write_bundle()
        bundle_mod.load_bundle_file(self.bundle_path, registry=None, expected_sha256=digest)
        parses = []
        real = bundle_mod.load_bundle_with_digest
        bundle_mod.load_bundle_with_digest = lambda *a, **k: (parses.append(1), real(*a, **k))[1]
        try:
            # A different expected digest (a new generation claiming the same
            # path) must NOT hit the old cache entry.
            bundle_mod.load_bundle_file(self.bundle_path, registry=None, expected_sha256="f" * 64)
            self.assertEqual(len(parses), 1, "digest mismatch forces the full parse")
        finally:
            bundle_mod.load_bundle_with_digest = real

    def test_changed_bytes_invalidate(self) -> None:
        bundle_mod.bundle_cache_clear()
        digest = self._write_bundle()
        parses = []
        real = bundle_mod.load_bundle_with_digest
        bundle_mod.load_bundle_with_digest = lambda *a, **k: (parses.append(1), real(*a, **k))[1]
        try:
            bundle_mod.load_bundle_file(self.bundle_path, registry=None, expected_sha256=digest)
            self.assertEqual(len(parses), 1)
            # HOT extension: different bytes at the same path.
            bundle = json.loads(self.bundle_path.read_text(encoding="utf-8"))
            bundle["events"].append({"seq": 2, "type": "USER_MESSAGE", "facts": {}})
            bundle["session_sha256"] = bundle_mod.bundle_digest(bundle)
            self.bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            reloaded = bundle_mod.load_bundle_file(
                self.bundle_path, registry=None, expected_sha256=bundle["session_sha256"]
            )
            self.assertEqual(len(parses), 2, "changed bytes always reparse")
            self.assertEqual(len(reloaded["events"]), 2)
        finally:
            bundle_mod.load_bundle_with_digest = real


class PERF_005CachePolicyBinding(unittest.TestCase):
    """SRC-004 PERF-005 defect B: the cache never reuses a parse validated
    under an obsolete registry/spec policy. `parse_bundle` is
    registry-sensitive, so cache identity binds to the validation spec."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        self.bundle_path = self.home / "bundle.json"
        self.registry = load_registry()

    def tearDown(self) -> None:
        bundle_mod.bundle_cache_clear()
        self._tmp.cleanup()

    def _write_bundle(self) -> str:
        bundle = {
            "schema_version": 1,
            "session_id": "s-1",
            "adapter": "generic",
            "project": {"name": "X", "git_head": "x", "root_fingerprint": "fx"},
            "runtime": {"provider": "openai", "model": "gpt-x", "reasoning_mode": "unknown"},
            "temperature": "COLD",
            "protocol": {"version": "7.231.9", "binding_status": "BOUND",
                          "git_head": "deadbeef", "registry_sha256": "a" * 64},
            "events": [{"seq": 1, "type": "USER_MESSAGE", "facts": {}}],
        }
        bundle["session_sha256"] = bundle_mod.bundle_digest(bundle)
        self.bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        return bundle["session_sha256"]

    def _parses(self, call, counts=None):
        if counts is None:
            counts = {"n": 0}
        real = bundle_mod.load_bundle_with_digest

        def counting(*args, **kwargs):
            counts["n"] += 1
            return real(*args, **kwargs)

        bundle_mod.load_bundle_with_digest = counting
        try:
            result = call()
        finally:
            bundle_mod.load_bundle_with_digest = real
        return result, counts

    def test_same_bundle_same_registry_hits_cache(self) -> None:
        bundle_mod.bundle_cache_clear()
        digest = self._write_bundle()
        _first, counts = self._parses(
            lambda: bundle_mod.load_bundle_file(
                self.bundle_path, registry=self.registry, expected_sha256=digest
            )
        )
        _second, counts2 = self._parses(
            lambda: bundle_mod.load_bundle_file(
                self.bundle_path, registry=self.registry, expected_sha256=digest
            )
        )
        self.assertEqual((counts["n"], counts2["n"]), (1, 0), "identical policy reuses the parse")

    def test_changed_schema_version_policy_never_hits_and_rejects(self) -> None:
        bundle_mod.bundle_cache_clear()
        digest = self._write_bundle()
        bundle_mod.load_bundle_file(self.bundle_path, registry=self.registry, expected_sha256=digest)
        incompatible = support.load_registry_copy()
        incompatible["bundle_schema_version"] = 2
        counts = {"n": 0}
        with self.assertRaises(PalError) as caught:
            self._parses(
                lambda: bundle_mod.load_bundle_file(
                    self.bundle_path, registry=incompatible, expected_sha256=digest
                ),
                counts,
            )
        self.assertEqual(caught.exception.code, "BUNDLE_INVALID")
        self.assertEqual(counts["n"], 1, "changed schema policy must NOT reuse the cache")

    def test_changed_event_types_policy_never_hits(self) -> None:
        bundle_mod.bundle_cache_clear()
        digest = self._write_bundle()
        bundle_mod.load_bundle_file(self.bundle_path, registry=self.registry, expected_sha256=digest)
        # Superset policy: the bundle stays valid, but the validation spec is
        # materially different, so the previously cached parse must not answer.
        incompatible = support.load_registry_copy()
        incompatible["event_types"] = list(incompatible["event_types"]) + ["CUSTOM_TEST_EVENT"]
        _result, counts = self._parses(
            lambda: bundle_mod.load_bundle_file(
                self.bundle_path, registry=incompatible, expected_sha256=digest
            )
        )
        self.assertEqual(counts["n"], 1, "changed event-type policy must NOT reuse the cache")

    def test_changed_evidence_limits_policy_never_hits(self) -> None:
        bundle_mod.bundle_cache_clear()
        digest = self._write_bundle()
        bundle_mod.load_bundle_file(self.bundle_path, registry=self.registry, expected_sha256=digest)
        incompatible = support.load_registry_copy()
        incompatible["evidence_locator_limits"] = dict(
            incompatible["evidence_locator_limits"], max_source_digest_chars=2
        )
        _result, counts = self._parses(
            lambda: bundle_mod.load_bundle_file(
                self.bundle_path, registry=incompatible, expected_sha256=digest
            )
        )
        self.assertEqual(counts["n"], 1, "changed evidence-limits policy must NOT reuse the cache")

    def test_restored_registry_reuses_only_same_spec_entry(self) -> None:
        bundle_mod.bundle_cache_clear()
        digest = self._write_bundle()
        bundle_mod.load_bundle_file(self.bundle_path, registry=self.registry, expected_sha256=digest)
        variant = support.load_registry_copy()
        variant["event_types"] = list(variant["event_types"]) + ["CUSTOM_TEST_EVENT"]
        _result, variant_counts = self._parses(
            lambda: bundle_mod.load_bundle_file(
                self.bundle_path, registry=variant, expected_sha256=digest
            )
        )
        self.assertEqual(variant_counts["n"], 1, "different spec is a miss even for the same bytes")
        _restored, restored_counts = self._parses(
            lambda: bundle_mod.load_bundle_file(
                self.bundle_path, registry=self.registry, expected_sha256=digest
            )
        )
        self.assertEqual(
            restored_counts["n"], 1,
            "restoring the original policy may reuse only an entry validated "
            "under that exact spec -- the variant entry is not it",
        )
        _again, again_counts = self._parses(
            lambda: bundle_mod.load_bundle_file(
                self.bundle_path, registry=self.registry, expected_sha256=digest
            )
        )
        self.assertEqual(again_counts["n"], 0, "the revalidated entry is reusable again")

    def test_cache_bounded_and_eviction_deterministic(self) -> None:
        bundle_mod.bundle_cache_clear()
        digest = self._write_bundle()
        bundle_mod.load_bundle_file(self.bundle_path, registry=self.registry, expected_sha256=digest)
        others = []
        for index in range(bundle_mod._BUNDLE_CACHE_MAX + 2):
            other = self.home / f"other-{index}.json"
            other.write_text(
                self.bundle_path.read_text(encoding="utf-8").replace('"s-1"', f'"s-{index}"'),
                encoding="utf-8",
            )
            payload = json.loads(other.read_text(encoding="utf-8"))
            payload["session_sha256"] = bundle_mod.bundle_digest(payload)
            other.write_text(json.dumps(payload), encoding="utf-8")
            bundle_mod.load_bundle_file(other, registry=self.registry, expected_sha256=payload["session_sha256"])
            others.append((other.resolve(), payload["session_sha256"]))
        self.assertEqual(len(bundle_mod._BUNDLE_CACHE), bundle_mod._BUNDLE_CACHE_MAX)
        self.assertEqual(
            list(bundle_mod._BUNDLE_CACHE.keys()),
            [str(path) for path, _digest in others[-bundle_mod._BUNDLE_CACHE_MAX:]],
            "LRU eviction is deterministic: oldest loaded entry leaves first",
        )

    def test_spec_fingerprint_excludes_non_spec_registry_keys(self) -> None:
        noise = support.load_registry_copy()
        noise["unrelated_key"] = "value"
        self.assertEqual(
            bundle_mod._spec_fingerprint(noise), bundle_mod._spec_fingerprint(self.registry),
            "non-spec registry fields must not influence validation identity",
        )


class PERF_001EvidenceLocatorAuthority(unittest.TestCase):
    """SRC-004 defect C: the evidence command must resolve the locator from the
    canonical bundle bytes that match the indexed generation's `bundle_sha256`,
    never from a weaker inline parse or a stale index projection."""

    def setUp(self) -> None:
        import saipal

        self.saipal = saipal
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        self.registry = load_registry()
        self.inbox = self.home / "session_inbox"
        self.inbox.mkdir(parents=True, exist_ok=True)
        self.bundle_path = self.inbox / "evidence-1.json"

    def tearDown(self) -> None:
        bundle_mod.bundle_cache_clear()
        self._tmp.cleanup()

    def _bundle(self, locator_suffix: str = "1", extra: bool = False) -> dict:
        bundle = {
            "schema_version": 1,
            "session_id": "s-ev-1",
            "adapter": "generic",
            "project": {"name": "X", "git_head": "x", "root_fingerprint": "fx"},
            "runtime": {"provider": "openai", "model": "gpt-x", "reasoning_mode": "unknown"},
            "temperature": "COLD",
            "protocol": {"version": "7.231.9", "binding_status": "BOUND",
                          "git_head": "deadbeef", "registry_sha256": "a" * 64},
            "events": [
                {
                    "seq": 1,
                    "type": "USER_MESSAGE",
                    "facts": {},
                    "evidence_ref": {
                        "source_kind": "claude",
                        "source_session_id": f"ps-{locator_suffix}",
                        "source_digest": "b" * 64,
                        "role": "user",
                    },
                }
            ],
        }
        if extra:
            bundle["events"].append({"seq": 2, "type": "SESSION_BOUNDARY", "facts": {}})
        bundle["session_sha256"] = bundle_mod.bundle_digest(bundle)
        return bundle

    def _write(self, bundle: dict) -> str:
        self.bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        return bundle["session_sha256"]

    def _record(self, digest: str) -> dict:
        return {
            "session_id": "s-ev-1",
            "generation": 1,
            "source_ref": "session_inbox/evidence-1.json",
            "bundle_sha256": digest,
            "adapter": "generic",
        }

    def _resolve(self, record: dict, seq: int = 1) -> dict:
        return self.saipal._resolve_evidence_locator(self.home, self.registry, record, seq)

    def test_matching_canonical_bundle_returns_locator(self) -> None:
        digest = self._write(self._bundle())
        entry = self._resolve(self._record(digest))
        self.assertEqual(entry["seq"], 1)
        self.assertEqual(entry["evidence_ref"]["source_session_id"], "ps-1")

    def test_materially_changed_bundle_refuses(self) -> None:
        digest = self._write(self._bundle())
        changed = self._bundle(extra=True)
        changed_digest = self._write(changed)
        self.assertNotEqual(changed_digest, digest, "fixture: bytes really changed")
        with self.assertRaises(PalError) as caught:
            self._resolve(self._record(digest))
        self.assertEqual(caught.exception.code, "BUNDLE_INVALID")

    def test_locator_change_with_same_session_refuses(self) -> None:
        digest = self._write(self._bundle(locator_suffix="1"))
        moved = self._bundle(locator_suffix="2")
        moved_digest = self._write(moved)
        self.assertEqual(moved["session_id"], "s-ev-1", "same session id, moved locator")
        self.assertNotEqual(moved_digest, digest)
        with self.assertRaises(PalError) as caught:
            self._resolve(self._record(digest))
        self.assertEqual(caught.exception.code, "BUNDLE_INVALID")

    def test_malformed_canonical_bundle_refuses_not_legacy_fallback(self) -> None:
        digest = self._write(self._bundle())
        self.bundle_path.write_text("{ broken", encoding="utf-8")
        record = self._record(digest)
        # A stale legacy projection is present, but a PRESENT malformed
        # canonical bundle must refuse rather than hide behind it.
        record["evidence_refs"] = [{"seq": 1, "evidence_ref": "legacy"}]
        with self.assertRaises(PalError) as caught:
            self._resolve(record)
        self.assertEqual(caught.exception.code, "BUNDLE_INVALID")

    def test_digest_mismatch_refuses_not_legacy_fallback(self) -> None:
        changed = self._bundle(locator_suffix="9")
        changed_digest = self._write(changed)
        record = self._record("f" * 64)
        record["evidence_refs"] = [{"seq": 1, "evidence_ref": "legacy"}]
        self.assertNotEqual(changed_digest, record["bundle_sha256"])
        with self.assertRaises(PalError) as caught:
            self._resolve(record)
        self.assertEqual(caught.exception.code, "BUNDLE_INVALID")

    def test_absent_canonical_bundle_keeps_legacy_projection(self) -> None:
        digest = self._write(self._bundle())
        self.bundle_path.unlink()
        record = self._record(digest)
        record["evidence_refs"] = [{"seq": 1, "evidence_ref": "legacy"}]
        entry = self._resolve(record)
        self.assertEqual(entry["evidence_ref"], "legacy", "documented compatibility path")

    def test_matching_bundle_without_locator_for_seq_refuses(self) -> None:
        digest = self._write(self._bundle())
        with self.assertRaises(PalError) as caught:
            self._resolve(self._record(digest), seq=99)
        self.assertEqual(caught.exception.code, "EVIDENCE_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()