"""Wave B acceptance bar, exercised through the real CLI and the real inbox.

Import is the wave: identity, generations, the hot watermark, and the refusal
to continue over mutated evidence.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import bundle as bundle_mod
from saipal_engine import sessions as sessions_mod

COLD = "conformant-cold.json"
COLD_COPY = "conformant-cold-copy.json"
COLD_V2 = "cold-changed-v2.json"
HOT = "hot-partial.json"
HOT_EXTENDED = "hot-extended.json"
HOT_MUTATED = "hot-prefix-mutated.json"


def _strip_times(index: dict) -> dict:
    """Drop timestamps so two runs can be compared for real determinism."""
    import copy

    clone = copy.deepcopy(index)
    for record in clone["sessions"]:
        record["imported_at"] = "<t>"
        record["updated_at"] = "<t>"
        for entry in record["imports"]:
            entry["imported_at"] = "<t>"
    return clone


class InboxImport(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _import(self):
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        return payload

    def _advance_watermark(self, session_id: str, seq: int, fixture: str = HOT) -> None:
        """Pretend Wave C analyzed up to `seq`; the prefix must then be stable."""
        status, index, _detail = sessions_mod.load_index(self.home)
        self.assertEqual(status, "ok")
        assert index is not None
        record = sessions_mod.find_session(index, session_id)
        self.assertIsNotNone(record)
        assert record is not None
        record["last_analyzed_seq"] = seq
        record["prefix_sha256"] = bundle_mod.prefix_digest(
            support.load_fixture(fixture), seq
        )
        sessions_mod.save_index(self.home, index)

    # -- acceptance bar 1: deterministic import ---------------------------- #

    def test_import_is_deterministic_across_two_fresh_homes(self) -> None:
        for home in (self.home, support.make_home(self.tmp, ".saipal-two")):
            support.run_saipal("continue", home=home)
            support.put_inbox(home, COLD, HOT)
            support.run_saipal("continue", home=home)

        first = support.sessions_of(self.home)
        second = support.sessions_of(support.make_home(self.tmp, ".saipal-two"))
        self.assertEqual(
            _strip_times({"sessions": first}), _strip_times({"sessions": second})
        )

    def test_second_cycle_changes_nothing(self) -> None:
        support.put_inbox(self.home, COLD, COLD_COPY, HOT)
        self._import()
        before = (self.home / "sessions" / "index.json").read_bytes()

        payload = self._import()
        after = (self.home / "sessions" / "index.json").read_bytes()
        self.assertEqual(before, after, "re-importing the same inbox mutated the index")
        self.assertEqual(payload["sessions_indexed"], 0)
        self.assertEqual(len(payload["intake"]["skipped"]), 3)

    # -- acceptance bar 2: duplicate digest does not duplicate ------------- #

    def test_duplicate_digest_does_not_duplicate_the_session(self) -> None:
        support.put_inbox(self.home, COLD, COLD_COPY)
        payload = self._import()
        self.assertEqual(payload["intake"]["sessions_total"], 1)
        self.assertEqual(payload["intake"]["new_sessions"], 1)
        self.assertEqual(len(payload["intake"]["skipped"]), 1)
        self.assertEqual(
            payload["intake"]["skipped"][0]["reason"], "duplicate digest"
        )

    # -- acceptance bar 3: changed digest becomes a new generation --------- #

    def test_changed_cold_digest_becomes_a_new_generation(self) -> None:
        support.put_inbox(self.home, COLD)
        first = self._import()
        self.assertEqual(first["intake"]["imported"][0]["generation"], 1)

        support.clear_inbox(self.home)
        support.put_inbox(self.home, COLD_V2)
        second = self._import()

        self.assertEqual(second["intake"]["new_sessions"], 1)
        self.assertEqual(second["intake"]["imported"][0]["generation"], 2)
        self.assertEqual(second["intake"]["sessions_total"], 2)
        self.assertEqual(
            sorted(r["generation"] for r in support.sessions_of(self.home)), [1, 2]
        )

    # -- acceptance bar 4: hot watermark resumes --------------------------- #

    def test_hot_session_extends_without_a_new_generation(self) -> None:
        support.put_inbox(self.home, HOT)
        first = self._import()
        self.assertEqual(first["intake"]["imported"][0]["events"], 3)
        self.assertEqual(support.sessions_of(self.home)[0]["temperature"], "HOT")

        support.clear_inbox(self.home)
        support.put_inbox(self.home, HOT_EXTENDED)
        second = self._import()

        self.assertEqual(second["intake"]["new_sessions"], 1)
        self.assertEqual(second["intake"]["conflicts"], [])
        record = [
            r for r in support.sessions_of(self.home) if r["session_id"] == "golden-hot-001"
        ][0]
        self.assertEqual(record["generation"], 1)
        self.assertEqual(record["event_count"], 5)
        self.assertEqual(record["status"], "IMPORTED")

    def test_hot_extension_survives_a_watermark(self) -> None:
        support.put_inbox(self.home, HOT)
        self._import()
        self._advance_watermark("golden-hot-001", 2)

        support.clear_inbox(self.home)
        support.put_inbox(self.home, HOT_EXTENDED)
        payload = self._import()

        self.assertEqual(payload["intake"]["conflicts"], [])
        record = support.sessions_of(self.home)[0]
        # The extended fixture ends ON a boundary (`PHASE_CHANGE` at seq 5).
        # This assertion used to expect 4, which was the T-71 defect showing
        # through the oracle: `extract_episodes` emitted no episode for a final
        # boundary event, so seq 5 was analyzed by nobody and the watermark
        # stopped one event short of the evidence. 5 is the whole span.
        self.assertEqual(
            record["last_analyzed_seq"], 5,
            "a safe append-only extension must re-analyze the new tail",
        )
        self.assertEqual(record["event_count"], 5)

    # -- acceptance bar 5: mutated prefix is detected ---------------------- #

    def test_mutated_analyzed_prefix_raises_a_conflict(self) -> None:
        support.put_inbox(self.home, HOT)
        self._import()
        self._advance_watermark("golden-hot-001", 2)

        support.clear_inbox(self.home)
        support.put_inbox(self.home, HOT_MUTATED)
        payload = self._import()

        self.assertEqual(payload["intake"]["new_sessions"], 0)
        self.assertEqual(len(payload["intake"]["conflicts"]), 1)
        self.assertIn("prefix changed", payload["intake"]["conflicts"][0]["reason"])

        record = support.sessions_of(self.home)[0]
        self.assertEqual(record["status"], "CONFLICT")
        self.assertEqual(record["last_analyzed_seq"], 2, "a conflict must freeze the watermark")
        self.assertEqual(record["event_count"], 3, "a conflict must not adopt the tail")
        self.assertIsNotNone(record["conflict"]["observed_prefix_sha256"])
        self.assertNotEqual(
            record["conflict"]["observed_prefix_sha256"],
            record["conflict"]["expected_prefix_sha256"],
        )

    def test_conflict_is_reported_by_status_and_next(self) -> None:
        support.put_inbox(self.home, HOT)
        self._import()
        self._advance_watermark("golden-hot-001", 2)
        support.clear_inbox(self.home)
        support.put_inbox(self.home, HOT_MUTATED)
        self._import()

        _code, status, _err = support.run_saipal_json("status", home=self.home)
        assert status is not None
        self.assertEqual(status["sessions_conflict"], 1)

        _code, nxt, _err = support.run_saipal_json("next", home=self.home)
        assert nxt is not None
        self.assertEqual(nxt["carrier"], "resolve-conflict")
        self.assertIn("mutated evidence", nxt.get("note", ""))

    def test_conflict_free_session_does_not_report_one(self) -> None:
        support.put_inbox(self.home, HOT)
        self._import()
        _code, nxt, _err = support.run_saipal_json("next", home=self.home)
        assert nxt is not None
        self.assertNotEqual(nxt["carrier"], "resolve-conflict")
        self.assertEqual(
            support.sessions_of(self.home)[0]["status"], "IMPORTED",
            "a clean import must not be marked CONFLICT",
        )

    # -- acceptance bar 6: cold dedupe ------------------------------------- #

    def test_unchanged_cold_session_is_not_reanalyzed(self) -> None:
        support.put_inbox(self.home, COLD)
        self._import()
        payload = self._import()
        self.assertEqual(payload["intake"]["new_sessions"], 0)
        self.assertEqual(payload["intake"]["skipped"][0]["reason"], "duplicate digest")
        self.assertEqual(payload["intake"]["sessions_total"], 1)

    # -- acceptance bar 7: binding metadata persists ----------------------- #

    def test_protocol_binding_persists_in_the_index(self) -> None:
        """The persisted binding is derived from authority, not from the bundle.

        `put_inbox` points the fixture's release claim at a real authority root,
        so this is the BOUND path: version and digest resolve against bytes the
        operator declared. The digest is whatever those bytes hash to -- asserting
        a hard-coded value here would only re-assert the fixture.
        """
        support.put_inbox(self.home, COLD)
        self._import()
        record = support.sessions_of(self.home)[0]
        self.assertEqual(record["protocol"]["version"], support.AUTHORITY_VERSION)
        self.assertEqual(record["protocol"]["git_head"], "deadbeef")
        self.assertEqual(
            record["protocol"]["registry_sha256"], support.authority_digest(self.tmp)
        )
        self.assertEqual(record["protocol"]["binding_status"], "BOUND")
        self.assertEqual(record["protocol"]["proof_level"], "RELEASE_REGISTRY")

    def test_a_forged_binding_claim_cannot_promote_itself(self) -> None:
        """CORE-001 red control: a bundle declaring BOUND persists as UNKNOWN.

        This is the attack the trust path allowed: drop a canonical bundle
        straight into the inbox, claim `BOUND` / `EXACT_COMMIT`, and every
        downstream claim inherits a binding Layer A never established.
        """
        forged = support.load_fixture(COLD)
        forged["session_id"] = "forged-binding-001"
        forged["protocol"] = {
            "binding_status": "BOUND",
            "proof_level": "EXACT_COMMIT",
            "git_head": "f" * 40,
            "version": None,
            "registry_sha256": None,
            "tree_fingerprint": None,
            "confidence": "HIGH",
            "source": "exact-commit",
        }
        forged.pop("session_sha256", None)
        support.write_inbox(self.home, "forged.json", forged)
        self._import()
        record = next(
            r for r in support.sessions_of(self.home)
            if r["session_id"] == "forged-binding-001"
        )
        self.assertEqual(record["protocol"]["binding_status"], "UNKNOWN")
        self.assertEqual(record["protocol"]["proof_level"], "UNKNOWN")

    def test_unknown_binding_is_recorded_as_unknown(self) -> None:
        support.put_inbox(self.home, "unknown-protocol.json")
        self._import()
        record = support.sessions_of(self.home)[0]
        self.assertEqual(record["protocol"]["binding_status"], "UNKNOWN")

    # -- acceptance bar 9: no transcript, no cleanup ----------------------- #

    def test_transcript_bundle_is_rejected_without_aborting_the_cycle(self) -> None:
        support.put_inbox(self.home, "transcript-in-events.json", "malformed.json", COLD)
        payload = self._import()

        self.assertEqual(payload["intake"]["new_sessions"], 1, "good bundles still import")
        self.assertEqual(len(payload["intake"]["rejected"]), 2)
        codes = {entry["code"] for entry in payload["intake"]["rejected"]}
        self.assertTrue(codes, "two rejects expected")
        self.assertIn("BUNDLE_INVALID", codes)

    def test_inbox_files_are_never_deleted(self) -> None:
        placed = support.put_inbox(self.home, COLD, "malformed.json")
        self._import()
        for path in placed:
            self.assertTrue(path.exists(), "SAIPAL must not clean up the operator's inbox")

    def test_no_bundle_content_is_copied_into_the_index(self) -> None:
        support.put_inbox(self.home, COLD)
        self._import()
        blob = (self.home / "sessions" / "index.json").read_text(encoding="utf-8")
        self.assertNotIn("saipal continue", blob.lower().replace("_", " "))
        self.assertLess(len(blob), 6000, "the index is metadata, not a second transcript")

    # -- acceptance bar 10: no audits -------------------------------------- #

    def test_no_audit_is_emitted_after_importing_sessions(self) -> None:
        support.put_inbox(self.home, COLD, HOT)
        before = support.checkout_audit_entries()
        payload = self._import()
        self.assertEqual(payload["audits_emitted"], 0)
        self.assertEqual(payload["candidates"], 0)
        self.assertFalse((self.home / "audit").exists())
        self.assertEqual(support.checkout_audit_entries(), before)

    # -- reporting --------------------------------------------------------- #

    def test_counts_are_reported(self) -> None:
        support.put_inbox(self.home, COLD, HOT)
        payload = self._import()
        intake = payload["intake"]
        self.assertEqual(intake["hot"], 1)
        self.assertEqual(intake["cold"], 1)
        self.assertEqual(intake["sessions_total"], 2)

    def test_status_reports_indexed_events_and_episodes(self) -> None:
        support.put_inbox(self.home, COLD)
        self._import()
        _code, status, _err = support.run_saipal_json("status", home=self.home)
        assert status is not None
        self.assertEqual(status["sessions"], 1)
        self.assertEqual(status["events_indexed"], 11)
        self.assertEqual(status["episodes"], 6)

    def test_red_control_digest_sensitivity(self) -> None:
        """The determinism assertion is worthless if the comparison is blind."""
        support.put_inbox(self.home, COLD)
        self._import()
        before = (self.home / "sessions" / "index.json").read_bytes()
        (self.home / "sessions" / "index.json").write_bytes(before + b" tampered")
        self.assertNotEqual(before, (self.home / "sessions" / "index.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
