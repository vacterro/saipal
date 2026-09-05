"""T-063 / audit CORE-002: session identity spans every generation.

`SESSIONS.md` PAL-SESSION-01 says identity is source identity plus digest: a
duplicate digest does not create a second session, a changed digest creates a new
generation. The implementation checked only the FIRST record for a session id, so
once generation 2 existed its digest was invisible -- and re-importing the same
artifact allocated another generation on every poll, growing the index without
bound and destroying the invariant.

These tests pin the audit's VERIFY list: A->B->B stays two generations, A->B->A
stays two and the reintroduced A is skipped, and five cycles of the same inputs
leave the index byte-stable.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import sessions as sessions_mod

COLD_A = "conformant-cold.json"
COLD_B = "cold-changed-v2.json"
COLD_A_COPY = "conformant-cold-copy.json"
HOT = "hot-partial.json"
HOT_EXTENDED = "hot-extended.json"

SESSION = "golden-cold-001"


class GenerationHelpers(unittest.TestCase):
    """The primitives every generation decision now rests on."""

    def index(self, *generations: int) -> dict:
        return {
            "schema_version": 1,
            "sessions": [
                {
                    "session_id": SESSION,
                    "generation": generation,
                    "imports": [{"sha256": f"digest-{generation}"}],
                }
                for generation in generations
            ]
            + [{"session_id": "other", "generation": 1, "imports": []}],
        }

    def test_records_for_session_returns_every_generation_in_order(self) -> None:
        records = sessions_mod.records_for_session(self.index(3, 1, 2), SESSION)
        self.assertEqual([r["generation"] for r in records], [1, 2, 3])

    def test_records_for_session_ignores_other_sessions(self) -> None:
        records = sessions_mod.records_for_session(self.index(1), SESSION)
        self.assertEqual([r["session_id"] for r in records], [SESSION])

    def test_records_for_an_unknown_session_is_empty(self) -> None:
        self.assertEqual(sessions_mod.records_for_session(self.index(1), "nope"), [])

    def test_records_for_an_absent_index_is_empty(self) -> None:
        self.assertEqual(sessions_mod.records_for_session(None, SESSION), [])

    def test_find_session_returns_the_freshest_generation(self) -> None:
        """Red control for the defect: the FIRST match is not the session."""
        record = sessions_mod.find_session(self.index(1, 2, 3), SESSION)
        self.assertEqual(record["generation"], 3)

    def test_latest_record_agrees_with_find_session(self) -> None:
        index = self.index(2, 1)
        self.assertEqual(
            sessions_mod.latest_record(index, SESSION),
            sessions_mod.find_session(index, SESSION),
        )

    def test_latest_generation_spans_every_record(self) -> None:
        self.assertEqual(sessions_mod.latest_generation(self.index(1, 2, 5), SESSION), 5)

    def test_latest_generation_of_an_unknown_session_is_zero(self) -> None:
        self.assertEqual(sessions_mod.latest_generation(self.index(1), "nope"), 0)

    def test_a_malformed_generation_does_not_crash_the_ordering(self) -> None:
        index = self.index(1)
        index["sessions"].append(
            {"session_id": SESSION, "generation": "later", "imports": []}
        )
        records = sessions_mod.records_for_session(index, SESSION)
        self.assertEqual(len(records), 2)
        self.assertEqual(sessions_mod.latest_generation(index, SESSION), 1)

    def test_already_imported_checks_every_generation(self) -> None:
        """The defect in one line: generation 2's digest must be visible."""
        records = sessions_mod.records_for_session(self.index(1, 2), SESSION)
        self.assertTrue(sessions_mod.already_imported(records, "digest-2"))
        self.assertTrue(sessions_mod.already_imported(records, "digest-1"))
        self.assertFalse(sessions_mod.already_imported(records, "digest-99"))

    def test_already_imported_still_accepts_one_record(self) -> None:
        record = {"imports": [{"sha256": "d"}]}
        self.assertTrue(sessions_mod.already_imported(record, "d"))
        self.assertFalse(sessions_mod.already_imported(record, "other"))

    def test_already_imported_tolerates_nothing(self) -> None:
        self.assertFalse(sessions_mod.already_imported(None, "d"))
        self.assertFalse(sessions_mod.already_imported([], "d"))


class CrossGenerationIntake(unittest.TestCase):
    """The real inbox, through the real CLI, over repeated polls."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def stage(self, fixture: str) -> dict:
        support.clear_inbox(self.home)
        support.put_inbox(self.home, fixture)
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        assert payload is not None
        return payload["intake"]

    def generations(self, session_id: str = SESSION) -> list[int]:
        return sorted(
            int(record["generation"])
            for record in support.sessions_of(self.home)
            if record["session_id"] == session_id
        )

    def index_bytes(self) -> bytes:
        return (self.home / "sessions" / "index.json").read_bytes()

    def test_a_then_b_is_two_generations(self) -> None:
        self.stage(COLD_A)
        self.stage(COLD_B)
        self.assertEqual(self.generations(), [1, 2])

    def test_a_then_b_then_b_stays_two_generations(self) -> None:
        """The audit's reproduction: the same V2 artifact must not grow the index."""
        self.stage(COLD_A)
        self.stage(COLD_B)
        third = self.stage(COLD_B)
        self.assertEqual(self.generations(), [1, 2])
        self.assertEqual(third["new_sessions"], 0)
        self.assertEqual(
            [entry["reason"] for entry in third["skipped"]], ["duplicate digest"]
        )

    def test_a_then_b_then_a_stays_two_generations(self) -> None:
        """A reintroduced older artifact is a digest already seen, not a new one."""
        self.stage(COLD_A)
        self.stage(COLD_B)
        third = self.stage(COLD_A)
        self.assertEqual(self.generations(), [1, 2])
        self.assertEqual(third["new_sessions"], 0)
        self.assertEqual(
            [entry["reason"] for entry in third["skipped"]], ["duplicate digest"]
        )

    def test_five_cycles_leave_the_index_byte_stable(self) -> None:
        self.stage(COLD_A)
        self.stage(COLD_B)
        settled = self.index_bytes()
        for cycle in range(5):
            self.stage(COLD_A if cycle % 2 else COLD_B)
            self.assertEqual(
                self.index_bytes(), settled, f"cycle {cycle} mutated a settled index"
            )
        self.assertEqual(self.generations(), [1, 2])

    def test_a_renamed_copy_of_the_freshest_generation_is_skipped(self) -> None:
        """Identity is digest, never filename -- across generations too."""
        self.stage(COLD_A)
        self.stage(COLD_B)
        support.clear_inbox(self.home)
        support.put_inbox(self.home, COLD_A_COPY)
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["intake"]["new_sessions"], 0)
        self.assertEqual(self.generations(), [1, 2])

    def test_a_genuinely_new_digest_still_allocates_the_next_generation(self) -> None:
        """The control: dedup must not block real new evidence."""
        self.stage(COLD_A)
        self.stage(COLD_B)
        mutated = support.load_fixture(COLD_A)
        mutated["events"].append(
            {
                "seq": 99,
                "type": "ASSISTANT_MESSAGE",
                "ts": None,
                "loc": None,
                "digest": None,
                "facts": {"note": "a third artifact"},
            }
        )
        mutated.pop("session_sha256", None)
        support.clear_inbox(self.home)
        support.write_inbox(self.home, "cold-v3.json", mutated)
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["intake"]["new_sessions"], 1)
        self.assertEqual(self.generations(), [1, 2, 3])

    def test_generations_never_collide_on_a_number(self) -> None:
        self.stage(COLD_A)
        self.stage(COLD_B)
        self.stage(COLD_A)
        self.assertEqual(len(self.generations()), len(set(self.generations())))

    def test_provenance_records_no_duplicate_import(self) -> None:
        self.stage(COLD_A)
        self.stage(COLD_B)
        self.stage(COLD_B)
        for record in support.sessions_of(self.home):
            digests = [entry["sha256"] for entry in record["imports"]]
            self.assertEqual(
                len(digests), len(set(digests)), "a skipped digest must not be recorded"
            )


class HotResumeUsesTheFreshestGeneration(unittest.TestCase):
    """A HOT session that already has several generations must extend the newest."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _cycle(self, fixture: str) -> dict:
        support.clear_inbox(self.home)
        support.put_inbox(self.home, fixture)
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        return payload["intake"]

    def _hot(self) -> list[dict]:
        return [
            record
            for record in support.sessions_of(self.home)
            if record["session_id"] == "golden-hot-001"
        ]

    def test_a_hot_session_extends_in_place(self) -> None:
        self._cycle(HOT)
        self._cycle(HOT_EXTENDED)
        records = self._hot()
        self.assertEqual([r["generation"] for r in records], [1])
        self.assertEqual(records[0]["event_count"], 5)

    def test_re_importing_the_extended_hot_bundle_is_skipped(self) -> None:
        self._cycle(HOT)
        self._cycle(HOT_EXTENDED)
        again = self._cycle(HOT_EXTENDED)
        self.assertEqual(again["new_sessions"], 0)
        self.assertEqual([r["generation"] for r in self._hot()], [1])

    def test_a_second_generation_becomes_the_extension_target(self) -> None:
        """With two generations present, the newest is the one that grows.

        A first-match lookup would have extended generation 1 and left the real
        latest evidence untouched -- the HOT half of the same defect.
        """
        self._cycle(HOT)
        # Force a second generation by hand: a COLD-style re-import of the same
        # session id, which is what a changed artifact produces.
        from saipal_engine import sessions as sessions_lib

        status, index, _detail = sessions_lib.load_index(self.home)
        self.assertEqual(status, "ok")
        first = [r for r in index["sessions"] if r["session_id"] == "golden-hot-001"][0]
        clone = dict(first)
        clone["generation"] = 2
        clone["event_count"] = 3
        clone["imports"] = [dict(entry) for entry in first["imports"]]
        clone["imports"][0] = dict(clone["imports"][0], sha256="f" * 64, generation=2)
        clone["bundle_sha256"] = "f" * 64
        index["sessions"].append(clone)
        sessions_lib.save_index(self.home, index)

        self._cycle(HOT_EXTENDED)
        records = {int(r["generation"]): r for r in self._hot()}
        self.assertEqual(sorted(records), [1, 2])
        self.assertEqual(
            records[2]["event_count"], 5, "the freshest generation must be the one extended"
        )
        self.assertEqual(
            records[1]["event_count"], 3, "a superseded generation must be left alone"
        )


if __name__ == "__main__":
    unittest.main()
