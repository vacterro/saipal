"""T-065 / audits W2-002 + W2-003: crash-safe submission, honest COLD dispatch.

W2-002 -- `submit_candidate` used the receipt as its idempotency authority but
committed it AFTER the effects it was meant to protect. A crash in between left
durable semantic and recurrence state with no operation identity, so the exact
retry was treated as novel and applied everything a second time.

W2-003 -- `dispatch_sources` treated "known COLD session id" as "same immutable
artifact" and returned before normalizing, so a COLD source rewritten in place
was suppressed before intake could compare digests.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pal_test_support as support
from saipal_engine import carrier as carrier_mod
from saipal_engine import dispatcher as dispatcher_mod
from saipal_engine import recurrence as recurrence_mod
from saipal_engine import sessions as sessions_mod
from saipal_engine import submit as submit_mod
from saipal_engine.registry import load_registry
from saipal_engine.submit import receipt_id as receipt_key

CLEAN = "no-finding-normal.json"
DRIFT = "agent-noncompliance-command-route.json"


class SubmitCrashRecovery(unittest.TestCase):
    """A fault anywhere before the receipt must converge on ONE application."""

    FIXTURE = CLEAN

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, self.FIXTURE)
        support.run_saipal("continue", home=self.home)
        self.carrier = carrier_mod.build_carrier(self.home, registry=self.registry)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def candidate(self, **overrides) -> dict:
        unit = self.carrier
        payload = {
            "schema_version": 1,
            "verdict": "NO_DRIFT",
            "unit_digest": unit["unit_digest"],
            "session_id": unit["session"]["session_id"],
            "episode_index": unit["episode"]["index"],
            "slice_index": unit["slice"]["index"],
            "disposition_class": "NO_DRIFT",
            "reasoning": "the span routed through the declared surface",
        }
        payload.update(overrides)
        return payload

    def submit(self, candidate: dict) -> dict:
        return submit_mod.submit_candidate(self.home, candidate, registry=self.registry)

    def record(self) -> dict:
        return [
            r
            for r in support.sessions_of(self.home)
            if r["session_id"] == self.carrier["session"]["session_id"]
        ][-1]

    def semantic(self) -> dict:
        return carrier_mod.semantic_state(self.record())

    def receipts(self) -> dict:
        status, payload, _detail = submit_mod.load_receipts(self.home)
        return payload if status == "ok" and payload else submit_mod.empty_receipts()

    def occurrences(self) -> int:
        data = recurrence_mod.load_recurrence(self.home)
        return sum(
            len(entry.get("occurrences") or [])
            for entry in (data.get("by_finding") or {}).values()
        )

    def crash_before_receipt(self):
        """Fault the write that COMMITS the receipt, leaving the effects applied.

        `_save_receipts` runs twice per fresh submission: once for the durable
        intention, once to commit the receipt. Failing the second reproduces the
        audit's window exactly -- effects durable, receipt absent.
        """
        real = submit_mod._save_receipts
        calls = {"n": 0}

        def flaky(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] >= 2:
                raise RuntimeError("crash before the receipt was committed")
            return real(*args, **kwargs)

        return mock.patch.object(submit_mod, "_save_receipts", flaky)

    # -- the intention journal --------------------------------------------- #

    def test_a_completed_submission_leaves_no_open_operation(self) -> None:
        self.submit(self.candidate())
        self.assertEqual(
            self.receipts()["operations"], [], "the receipt retires its own intention"
        )

    def test_a_crash_before_the_receipt_leaves_the_intention_behind(self) -> None:
        """The operation is what makes an interrupted attempt visible."""
        with self.crash_before_receipt():
            with self.assertRaises(RuntimeError):
                self.submit(self.candidate())
        operations = self.receipts()["operations"]
        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0]["receipt_id"], receipt_key(self.candidate()))
        self.assertEqual(self.receipts()["receipts"], [], "no receipt was committed")

    def test_the_retry_after_that_crash_applies_the_effect_once(self) -> None:
        """The audit's reproduction: recurrence must not advance twice."""
        before = self.occurrences()
        with self.crash_before_receipt():
            with self.assertRaises(RuntimeError):
                self.submit(self.candidate())
        mid = self.occurrences()
        self.assertEqual(mid, before + 1, "the first attempt did record its effect")

        receipt = self.submit(self.candidate())
        self.assertEqual(
            self.occurrences(), mid, "the retry must not record a second occurrence"
        )
        self.assertTrue(receipt["recovered"], "the retry must know it is a recovery")
        self.assertEqual(self.receipts()["operations"], [])

    def test_the_retry_advances_the_watermark_exactly_once(self) -> None:
        with self.crash_before_receipt():
            with self.assertRaises(RuntimeError):
                self.submit(self.candidate())
        self.assertEqual(self.semantic()["no_drift"], 0, "nothing was tallied yet")
        self.submit(self.candidate())
        state = self.semantic()
        self.assertEqual(state["no_drift"], 1)
        self.assertEqual(state["next_episode_index"], 1)

    def test_a_crash_after_the_receipt_still_advances_on_retry(self) -> None:
        """Red control: a receipt with no cursor move used to wedge the analyst.

        The retry hits the duplicate path, which must reconcile rather than return
        a stale position -- otherwise the same unit is offered forever while its
        own reply comes back as a duplicate.
        """
        original = sessions_mod.save_index
        calls = {"n": 0}

        def failing_save(*args, **kwargs):
            calls["n"] += 1
            raise RuntimeError("crash after the receipt")

        with mock.patch.object(sessions_mod, "save_index", failing_save):
            with self.assertRaises(RuntimeError):
                self.submit(self.candidate())
        self.assertEqual(calls["n"], 1)
        self.assertEqual(len(self.receipts()["receipts"]), 1, "the receipt committed")
        self.assertEqual(self.semantic()["next_episode_index"], 0, "the cursor did not move")

        again = self.submit(self.candidate())
        self.assertTrue(again["duplicate"])
        self.assertEqual(
            self.semantic()["next_episode_index"], 1, "the duplicate path must reconcile"
        )
        self.assertIs(sessions_mod.save_index, original)

    def test_tallies_are_counted_from_receipts_not_incremented(self) -> None:
        """Red control: an incremented tally is the one thing a retry can double."""
        self.submit(self.candidate())
        first = self.semantic()["no_drift"]
        for _ in range(3):
            self.submit(self.candidate())
        self.assertEqual(
            self.semantic()["no_drift"], first, "a duplicate must not re-tally"
        )

    def test_a_forged_tally_is_corrected_by_the_next_submission(self) -> None:
        """Derived beats asserted: a tampered counter cannot survive a recount."""
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        self.assertEqual(status, "ok")
        for record in index["sessions"]:
            semantic = dict(record.get("semantic") or {})
            semantic["no_drift"] = 999
            record["semantic"] = semantic
        sessions_mod.save_index(self.home, index, registry=self.registry)
        self.submit(self.candidate())
        self.assertEqual(self.semantic()["no_drift"], 1)

    def test_the_receipt_records_whether_it_recovered(self) -> None:
        receipt = self.submit(self.candidate())
        self.assertFalse(receipt["recovered"])
        stored = self.receipts()["receipts"][-1]
        self.assertFalse(stored["recovered"])

    def test_a_crash_writes_no_receipt_at_all(self) -> None:
        with self.crash_before_receipt():
            with self.assertRaises(RuntimeError):
                self.submit(self.candidate())
        self.assertEqual(self.receipts()["receipts"], [])

    def test_legacy_receipts_without_operations_still_load(self) -> None:
        (self.home / submit_mod.RECEIPTS_NAME).write_text(
            json.dumps({"schema_version": 1, "receipts": []}), encoding="utf-8"
        )
        status, payload, _detail = submit_mod.load_receipts(self.home)
        self.assertEqual(status, "ok")
        self.assertEqual(payload["operations"], [])
        self.submit(self.candidate())
        self.assertEqual(len(self.receipts()["receipts"]), 1)


class DriftSubmitCrashRecovery(SubmitCrashRecovery):
    """The same guarantees on the path that creates findings and audits."""

    FIXTURE = DRIFT

    def candidate(self, **overrides) -> dict:
        unit = self.carrier
        payload = {
            "schema_version": 1,
            "verdict": "DRIFT",
            "unit_digest": unit["unit_digest"],
            "session_id": unit["session"]["session_id"],
            "episode_index": unit["episode"]["index"],
            "slice_index": unit["slice"]["index"],
            "disposition_class": "ENGINE_ENFORCEMENT_GAP",
            "reasoning": "the engine accepted a route outside the closed surface",
            "rule_ids": ["PAL-CMD-01"],
            "event_refs": [unit["slice"]["start_seq"]],
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "severity": "P1",
            "confidence": "HIGH",
            "change_target": "ENGINE",
            "root_cause": "the closed command surface was not consulted",
            "challenge": {
                "prosecutor": "PAL-CMD-01 names the surface; the route is not in it",
                "defender": "the adapter may have mislabelled a shell command",
                "winner": "prosecutor",
                "loser_rejection": "the adapter recorded a canonical protocol token",
            },
            "alternatives": ["the adapter mislabelled a shell command"],
            "addressed_defences": [
                entry["code"] for entry in unit.get("defence_surface") or []
            ],
        }
        payload.update(overrides)
        return payload

    def findings(self) -> list[dict]:
        path = self.home / "findings" / "index.json"
        if not path.exists():
            return []
        return json.loads(path.read_text(encoding="utf-8"))["findings"]

    def test_tallies_are_counted_from_receipts_not_incremented(self) -> None:
        self.submit(self.candidate())
        first = self.semantic()["submitted"]
        for _ in range(3):
            self.submit(self.candidate())
        self.assertEqual(self.semantic()["submitted"], first)

    def test_a_forged_tally_is_corrected_by_the_next_submission(self) -> None:
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        for record in index["sessions"]:
            semantic = dict(record.get("semantic") or {})
            semantic["submitted"] = 999
            record["semantic"] = semantic
        sessions_mod.save_index(self.home, index, registry=self.registry)
        self.submit(self.candidate())
        self.assertEqual(self.semantic()["submitted"], 1)

    def test_the_retry_after_that_crash_applies_the_effect_once(self) -> None:
        """A drift retry converges on one finding, one occurrence, one audit."""
        with self.crash_before_receipt():
            with self.assertRaises(RuntimeError):
                self.submit(self.candidate())
        findings_after_crash = len(self.findings())
        occurrences_after_crash = self.occurrences()
        audits_after_crash = sorted(
            p.name for p in (self.home / "audit" / "staging").glob("*.md")
        )

        receipt = self.submit(self.candidate())
        self.assertTrue(receipt["recovered"])
        self.assertEqual(len(self.findings()), findings_after_crash, "one finding only")
        self.assertEqual(self.occurrences(), occurrences_after_crash, "one occurrence")
        self.assertEqual(
            sorted(p.name for p in (self.home / "audit" / "staging").glob("*.md")),
            audits_after_crash,
            "the retry must reuse the same audit slot",
        )

    def test_the_retry_advances_the_watermark_exactly_once(self) -> None:
        with self.crash_before_receipt():
            with self.assertRaises(RuntimeError):
                self.submit(self.candidate())
        self.assertEqual(self.semantic()["submitted"], 0)
        self.submit(self.candidate())
        self.assertEqual(self.semantic()["submitted"], 1)


class KeyedRecurrence(unittest.TestCase):
    """The primitive the recovery rests on: one keyed occurrence, written once."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = support.make_home(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def session(self) -> dict:
        return {
            "session_id": "s1",
            "adapter": "generic",
            "project": {"name": "P"},
            "protocol": {"version": "1.0.0"},
        }

    def count(self) -> int:
        data = recurrence_mod.load_recurrence(self.home)
        return sum(
            len(entry.get("occurrences") or [])
            for entry in (data.get("by_finding") or {}).values()
        )

    def test_a_keyed_negative_is_recorded_once(self) -> None:
        recurrence_mod.record_negative(self.home, self.session(), occurrence_id="k1")
        recurrence_mod.record_negative(self.home, self.session(), occurrence_id="k1")
        self.assertEqual(self.count(), 1)

    def test_a_different_key_is_a_different_occurrence(self) -> None:
        recurrence_mod.record_negative(self.home, self.session(), occurrence_id="k1")
        recurrence_mod.record_negative(self.home, self.session(), occurrence_id="k2")
        self.assertEqual(self.count(), 2)

    def test_an_unkeyed_write_stays_append_only(self) -> None:
        """The deterministic pipeline has no receipt to key on; it must still work."""
        recurrence_mod.record_negative(self.home, self.session())
        recurrence_mod.record_negative(self.home, self.session())
        self.assertEqual(self.count(), 2)

    def test_a_keyed_occurrence_is_recorded_once(self) -> None:
        finding = {
            "finding_id": "PAL-0001",
            "fingerprint": "fp",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "rule_ids": ["PAL-CMD-01"],
        }
        recurrence_mod.record_occurrence(
            self.home, finding, self.session(), occurrence_id="k1"
        )
        recurrence_mod.record_occurrence(
            self.home, finding, self.session(), occurrence_id="k1"
        )
        self.assertEqual(self.count(), 1)

    def test_the_rule_buckets_are_not_double_counted_either(self) -> None:
        finding = {
            "finding_id": "PAL-0001",
            "fingerprint": "fp",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "rule_ids": ["PAL-CMD-01"],
        }
        for _ in range(3):
            recurrence_mod.record_occurrence(
                self.home, finding, self.session(), occurrence_id="k1"
            )
        data = recurrence_mod.load_recurrence(self.home)
        self.assertEqual(data["by_rule"]["PAL-CMD-01"]["total"], 1)


class ColdDispatchIsDigestDecided(unittest.TestCase):
    """W2-003: a known COLD session id may never suppress a changed artifact.

    The fast path only fires for adapters whose `discover()` already knows the
    session id, so these tests drive `dispatch_sources` with a stub adapter that
    does -- the shipped `generic` adapter discovers files, not sessions, and would
    never reach the branch under test.
    """

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        self.source = self.tmp / "native.json"
        self.write_source("v1")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write_source(self, marker: str) -> None:
        payload = {
            "schema_version": 1,
            "session_id": "native-001",
            "adapter": "generic",
            "project": {"name": "NativeProject"},
            "runtime": {"provider": "p", "model": "m"},
            "temperature": "COLD",
            "protocol": {"version": "7.231.9", "registry_sha256": "a" * 64},
            "events": [
                {"seq": 1, "type": "USER_MESSAGE", "facts": {"task": marker}},
                {"seq": 2, "type": "ASSISTANT_MESSAGE", "facts": {"reply": marker}},
            ],
        }
        self.source.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def adapter(self):
        """A stub whose discovery knows the session id, like the real providers."""
        from saipal_engine.adapters import generic as generic_mod

        class SessionAwareAdapter:
            NAME = "generic"
            discover = staticmethod(
                lambda source_path: [
                    {"path": str(Path(source_path)), "session_id": "native-001"}
                ]
            )
            identity = staticmethod(generic_mod.identity)
            normalize = staticmethod(generic_mod.normalize)
            protocol_binding = staticmethod(generic_mod.protocol_binding)
            stable_watermark = staticmethod(generic_mod.stable_watermark)

        return SessionAwareAdapter

    def sources(self) -> list[dict]:
        return [
            {
                "id": "src-1",
                "kind": "generic",
                "path": str(self.source),
                "enabled": True,
            }
        ]

    def index(self) -> dict | None:
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        return index if status == "ok" else None

    def cycle(self) -> dict:
        """One dispatch + one intake, through the real functions."""
        from saipal_engine import inbox as inbox_mod
        from saipal_engine.adapters import ADAPTER_REGISTRY

        with mock.patch.dict(ADAPTER_REGISTRY, {"generic": self.adapter()}):
            report = dispatcher_mod.dispatch_sources(
                self.home,
                self.sources(),
                registry=self.registry,
                index=self.index(),
            )
        inbox_mod.import_inbox(self.home, registry=self.registry)
        return report

    def generations(self) -> list[int]:
        return sorted(
            int(record["generation"])
            for record in support.sessions_of(self.home)
            if record["session_id"] == "native-001"
        )

    def staged(self) -> Path:
        return next((self.home / "session_inbox").glob("generic-native-001-*.json"))

    def test_the_first_dispatch_stages_and_imports_the_session(self) -> None:
        report = self.cycle()
        self.assertEqual(len(report["imported"]), 1)
        self.assertEqual(self.generations(), [1])

    def test_an_unchanged_cold_source_is_skipped_without_normalizing(self) -> None:
        self.cycle()
        report = self.cycle()
        self.assertEqual(
            [entry.get("reason") for entry in report["unchanged"]],
            ["already indexed, cold"],
        )
        self.assertEqual(self.generations(), [1])

    def test_a_changed_cold_source_reaches_intake(self) -> None:
        """The audit's reproduction: a rewritten COLD artifact was suppressed."""
        self.cycle()
        self.write_source("v2-different-content")
        report = self.cycle()
        self.assertEqual(len(report["imported"]), 1, "the changed artifact must stage")
        self.assertEqual(
            self.generations(), [1, 2], "a changed digest must create generation 2"
        )

    def test_the_changed_source_is_never_reported_unchanged(self) -> None:
        self.cycle()
        self.write_source("v2-different-content")
        report = self.cycle()
        self.assertEqual(report["unchanged"], [])

    def test_three_cycles_over_two_artifacts_stay_at_two_generations(self) -> None:
        self.cycle()
        self.write_source("v2-different-content")
        self.cycle()
        self.cycle()
        self.assertEqual(self.generations(), [1, 2])

    def test_reverting_to_the_first_artifact_creates_no_third_generation(self) -> None:
        self.cycle()
        self.write_source("v2-different-content")
        self.cycle()
        self.write_source("v1")
        self.cycle()
        self.assertEqual(self.generations(), [1, 2])

    def test_a_staged_bundle_without_a_source_digest_is_normalized(self) -> None:
        """No cheap identity recorded means no cheap decision: re-read it."""
        self.cycle()
        staged = self.staged()
        payload = json.loads(staged.read_text(encoding="utf-8"))
        payload.pop("raw_source_sha256", None)
        payload.pop("session_sha256", None)
        staged.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.assertFalse(
            dispatcher_mod._unchanged_cold(
                self.adapter(), str(self.source), staged, self.registry
            )
        )

    def test_an_absent_staged_bundle_is_normalized(self) -> None:
        self.assertFalse(
            dispatcher_mod._unchanged_cold(
                self.adapter(),
                str(self.source),
                self.home / "session_inbox" / "nope.json",
                self.registry,
            )
        )

    def test_a_hot_staged_bundle_is_never_fast_pathed(self) -> None:
        """A HOT session can always grow; only COLD claims immutability."""
        self.cycle()
        staged = self.staged()
        payload = json.loads(staged.read_text(encoding="utf-8"))
        payload["temperature"] = "HOT"
        payload.pop("session_sha256", None)
        staged.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.assertFalse(
            dispatcher_mod._unchanged_cold(
                self.adapter(), str(self.source), staged, self.registry
            )
        )

    def test_an_unchanged_cold_bundle_is_fast_pathed(self) -> None:
        """The control: the optimization must still fire when it is honest."""
        self.cycle()
        self.assertTrue(
            dispatcher_mod._unchanged_cold(
                self.adapter(), str(self.source), self.staged(), self.registry
            )
        )

    def test_an_unreadable_source_is_normalized_not_guessed(self) -> None:
        self.cycle()
        staged = self.staged()
        self.source.unlink()
        self.assertFalse(
            dispatcher_mod._unchanged_cold(
                self.adapter(), str(self.source), staged, self.registry
            )
        )


class DispositionHistoryIsAppendOnly(unittest.TestCase):
    """A maintainer changing their mind is calibration, not a correction.

    `COMMANDS.md` already promised "a changed disposition appends history instead
    of rewriting it"; the code overwrote it in place, so prior verdicts -- the only
    record of what SAIPAL got wrong before -- were destroyed on revision.
    """

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)
        # The finding exists only after a semantic DRIFT verdict (PAL-ARCH-01).
        support.submit_drift(self.home, support.next_unit(self.home))
        links = self.home / "closed_loop_links.json"
        self.assertTrue(links.is_file(), "the drift fixture must have emitted an audit")
        self.audit_number = json.loads(links.read_text(encoding="utf-8"))["links"][0][
            "audit_number"
        ]

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def apply(self, disposition: str, **extra) -> dict:
        from saipal_engine import closedloop as closedloop_mod

        return closedloop_mod.import_maintainer_disposition(
            self.home, audit_number=self.audit_number, disposition=disposition, **extra
        )

    def link(self) -> dict:
        from saipal_engine import closedloop as closedloop_mod

        _status, payload, _detail = closedloop_mod.load_links(self.home)
        return [
            entry
            for entry in payload["links"]
            if entry["audit_number"] == self.audit_number
        ][0]

    def test_the_first_disposition_records_no_history(self) -> None:
        self.apply("ENGINE_FIX")
        self.assertEqual(self.link()["disposition"], "ENGINE_FIX")
        self.assertEqual(self.link().get("history", []), [])

    def test_a_changed_disposition_preserves_the_previous_one(self) -> None:
        self.apply("REJECTED_FINDING")
        self.apply("ENGINE_FIX", fix_version="7.240.0")
        link = self.link()
        self.assertEqual(link["disposition"], "ENGINE_FIX")
        self.assertEqual(link["fix_version"], "7.240.0")
        self.assertEqual(
            [row["disposition"] for row in link["history"]], ["REJECTED_FINDING"]
        )

    def test_every_revision_is_kept_in_order(self) -> None:
        for disposition in ("REJECTED_FINDING", "ENGINE_FIX", "NO_CHANGE"):
            self.apply(disposition)
        self.assertEqual(
            [row["disposition"] for row in self.link()["history"]],
            ["REJECTED_FINDING", "ENGINE_FIX"],
        )
        self.assertEqual(self.link()["disposition"], "NO_CHANGE")

    def test_a_superseded_entry_records_when_it_was_replaced(self) -> None:
        self.apply("REJECTED_FINDING")
        self.apply("ENGINE_FIX")
        superseded = self.link()["history"][0]
        self.assertTrue(superseded["superseded_at"])
        self.assertTrue(superseded["closed_at"], "the original closing time survives")

    def test_re_importing_the_same_verdict_is_idempotent(self) -> None:
        self.apply("ENGINE_FIX", fix_version="7.240.0")
        first = json.dumps(self.link(), sort_keys=True)
        self.apply("ENGINE_FIX", fix_version="7.240.0")
        self.assertEqual(json.dumps(self.link(), sort_keys=True), first)
        self.assertEqual(self.link().get("history", []), [])

    def test_a_changed_fix_version_alone_is_a_revision(self) -> None:
        self.apply("ENGINE_FIX", fix_version="7.240.0")
        self.apply("ENGINE_FIX", fix_version="7.241.0")
        self.assertEqual(
            [row["fix_version"] for row in self.link()["history"]], ["7.240.0"]
        )

    def test_the_calibration_surface_still_reads_the_current_verdict(self) -> None:
        """Red control: history must not shadow the verdict the analyst reads."""
        self.apply("REJECTED_FINDING")
        self.apply("ENGINE_FIX")
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        current = [
            row
            for row in unit["calibration"]
            if row["audit_number"] == self.audit_number
        ]
        self.assertEqual([row["disposition"] for row in current], ["ENGINE_FIX"])

    def test_the_cli_import_appends_history_too(self) -> None:
        for disposition in ("REJECTED_FINDING", "ENGINE_FIX"):
            path = self.tmp / f"{disposition}.json"
            path.write_text(
                json.dumps(
                    {
                        "dispositions": [
                            {
                                "audit_number": self.audit_number,
                                "disposition": disposition,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            code, _payload, err = support.run_saipal_json(
                "disposition", str(path), home=self.home
            )
            self.assertEqual(code, 0, err)
        self.assertEqual(
            [row["disposition"] for row in self.link()["history"]], ["REJECTED_FINDING"]
        )


class EnqueueSlotRecovery(unittest.TestCase):
    """A crash between allocating a slot and recording it must not orphan it.

    `enqueue_audit` allocated a number, wrote `audit/N.md`, and only then recorded
    the ledger entry. A crash in between left `N.md` referenced by nothing, and the
    retry allocated N+1 -- so the audit directory accumulated files no ledger
    entry names (audit W2-002).
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        (self.home / "audit" / "staging").mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def finding(self, finding_id: str = "PAL-9001") -> dict:
        return {
            "finding_id": finding_id,
            "state": "QUALIFIED",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "rule_ids": ["PAL-CMD-01"],
        }

    def staged(self) -> list[str]:
        return sorted(p.name for p in (self.home / "audit" / "staging").glob("*.md"))

    def entries(self) -> list[dict]:
        path = self.home / "audit" / "entries.json"
        if not path.exists():
            return []
        return json.loads(path.read_text(encoding="utf-8"))["entries"]

    def test_a_normal_enqueue_records_a_complete_entry(self) -> None:
        from saipal_engine import enqueue as enqueue_mod

        enqueue_mod.enqueue_audit(self.home, self.finding(), "body")
        self.assertEqual(self.staged(), ["1.md"])
        self.assertEqual(len(self.entries()), 1)
        self.assertNotIn("pending", self.entries()[0])
        self.assertEqual(enqueue_mod.incomplete_enqueues(self.home), [])

    def test_a_crash_after_the_file_leaves_a_pending_claim(self) -> None:
        from saipal_engine import enqueue as enqueue_mod

        real = enqueue_mod.sha256_file
        with mock.patch.object(
            enqueue_mod, "sha256_file", side_effect=RuntimeError("crash")
        ):
            with self.assertRaises(RuntimeError):
                enqueue_mod.enqueue_audit(self.home, self.finding(), "body")
        self.assertIs(enqueue_mod.sha256_file, real)
        self.assertEqual(self.staged(), ["1.md"])
        pending = enqueue_mod.incomplete_enqueues(self.home)
        self.assertEqual([row["audit_number"] for row in pending], [1])

    def test_the_retry_reuses_the_claimed_slot(self) -> None:
        """Red control: a fresh id would leave 1.md referenced by nothing."""
        from saipal_engine import enqueue as enqueue_mod

        with mock.patch.object(
            enqueue_mod, "sha256_file", side_effect=RuntimeError("crash")
        ):
            with self.assertRaises(RuntimeError):
                enqueue_mod.enqueue_audit(self.home, self.finding(), "body")

        result = enqueue_mod.enqueue_audit(self.home, self.finding(), "body")
        self.assertEqual(result["audit_number"], 1)
        self.assertEqual(self.staged(), ["1.md"], "no orphan slot may be left behind")
        self.assertEqual(enqueue_mod.incomplete_enqueues(self.home), [])

    def test_every_staged_file_is_named_by_the_ledger_after_recovery(self) -> None:
        from saipal_engine import enqueue as enqueue_mod

        with mock.patch.object(
            enqueue_mod, "sha256_file", side_effect=RuntimeError("crash")
        ):
            with self.assertRaises(RuntimeError):
                enqueue_mod.enqueue_audit(self.home, self.finding(), "body")
        enqueue_mod.enqueue_audit(self.home, self.finding(), "body")
        enqueue_mod.enqueue_audit(self.home, self.finding("PAL-9002"), "another body")
        referenced = sorted(f"{entry['audit_number']}.md" for entry in self.entries())
        self.assertEqual(referenced, self.staged())

    def test_a_pending_entry_is_not_a_completed_receipt(self) -> None:
        from saipal_engine import enqueue as enqueue_mod

        with mock.patch.object(
            enqueue_mod, "sha256_file", side_effect=RuntimeError("crash")
        ):
            with self.assertRaises(RuntimeError):
                enqueue_mod.enqueue_audit(self.home, self.finding(), "body")
        self.assertIsNone(
            enqueue_mod.lookup_receipt(self.home, "PAL-9001"),
            "an unconfirmed slot must not read as an emitted audit",
        )

    def test_a_different_body_still_takes_the_next_slot(self) -> None:
        """Recovery is per finding AND body: a changed audit is a new audit."""
        from saipal_engine import enqueue as enqueue_mod

        with mock.patch.object(
            enqueue_mod, "sha256_file", side_effect=RuntimeError("crash")
        ):
            with self.assertRaises(RuntimeError):
                enqueue_mod.enqueue_audit(self.home, self.finding(), "body")
        result = enqueue_mod.enqueue_audit(self.home, self.finding(), "a revised body")
        self.assertEqual(result["audit_number"], 2)

    def test_a_completed_enqueue_stays_idempotent(self) -> None:
        from saipal_engine import enqueue as enqueue_mod

        first = enqueue_mod.enqueue_audit(self.home, self.finding(), "body")
        second = enqueue_mod.enqueue_audit(self.home, self.finding(), "body")
        self.assertEqual(first, second)
        self.assertEqual(self.staged(), ["1.md"])


if __name__ == "__main__":
    unittest.main()
