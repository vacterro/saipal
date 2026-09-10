"""T-121 clause 3 (ROLE 9/10/11/32): conflict triage is derived, canonical state.

The freshest-record CONFLICT population is the canonical forensic truth;
`.saipal/conflict_triage.json` is operational derived state. The controls
here prove the consistency contract:

- identity: unique triage ids == current conflict ids (no duplicates,
  no stale resolved ids, conflicts_total == row count == current count);
- staleness: any drift between the triage file and the current conflict
  population reports triage_stale=true instead of silently passing;
- surfacing: doctor and watch --status carry
  conflicts_current/triaged/untriaged/stale/operator_review_required and
  agree with each other;
- read-only: the control itself never mutates the home.
"""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import supervisor as sup_mod

CONFLICT = "hot-prefix-mutated.json"


def _conflicted_home(tmp_root: str) -> Path:
    """A home whose current population carries exactly one CONFLICT session.

    Same arming pattern as the hardening suite: analyze a HOT prefix, then
    feed a mutated prefix under a stable watermark so intake records a
    historical rewrite conflict.
    """
    from saipal_engine import bundle as bundle_mod
    from saipal_engine import sessions as sessions_mod

    home = support.make_home(Path(tmp_root))
    support.put_inbox(home, "hot-partial.json")
    support.run_saipal("continue", home=home)
    status, index, _detail = sessions_mod.load_index(home)
    record = sessions_mod.find_session(index, "golden-hot-001")
    record["last_analyzed_seq"] = 2
    record["prefix_sha256"] = bundle_mod.prefix_digest(
        support.load_fixture("hot-partial.json"), 2
    )
    sessions_mod.save_index(home, index)
    support.clear_inbox(home)
    support.put_inbox(home, CONFLICT)
    support.run_saipal("continue", home=home)
    support.clear_inbox(home)
    return home


class TriageIdentityControl(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = _conflicted_home(self._tmp.name)
        corpus = sup_mod._corpus_state(self.home)
        self.assertEqual(corpus["conflicts_current"], 1)
        # No triage file yet: everything is untriaged and stale.
        self.assertTrue(corpus["triage_stale"])
        self.assertEqual(corpus["conflicts_untriaged"], 1)

    def _write_triage(self, payload: dict) -> None:
        (self.home / "conflict_triage.json").write_text(
            json.dumps(payload, indent=1), encoding="utf-8"
        )

    def _valid_triage(self) -> dict:
        corpus = sup_mod._corpus_state(self.home)
        rows = [
            {
                "session_id": row["session_id"],
                "generation": row["generation"],
                "temperature": "HOT",
                "disposition": "EXPECTED_MUTATION_ACCEPTED",
                "operator_review_required": False,
                "conflict_material_sha256": row["conflict_material_sha256"],
            }
            for row in corpus["conflict_rows"]
        ]
        return {
            "schema_version": 2,
            "material_digest_version": corpus.get("material_digest_version", 1),
            "conflicts_total": len(rows),
            "rows": rows,
        }

    def test_matching_triage_is_not_stale(self) -> None:
        self._write_triage(self._valid_triage())
        corpus = sup_mod._corpus_state(self.home)
        self.assertFalse(corpus["triage_stale"])
        self.assertEqual(corpus["conflicts_triaged"], 1)
        self.assertEqual(corpus["conflicts_untriaged"], 0)

    def test_stale_resolved_id_reports_stale(self) -> None:
        payload = self._valid_triage()
        payload["rows"][0]["session_id"] = "ses_resolved_long_ago"
        self._write_triage(payload)
        corpus = sup_mod._corpus_state(self.home)
        self.assertTrue(corpus["triage_stale"])
        self.assertEqual(corpus["conflicts_triaged"], 0)
        self.assertEqual(corpus["conflicts_untriaged"], 1)

    def test_duplicate_rows_report_stale(self) -> None:
        payload = self._valid_triage()
        payload["rows"].append(copy.deepcopy(payload["rows"][0]))
        payload["conflicts_total"] = 2
        self._write_triage(payload)
        corpus = sup_mod._corpus_state(self.home)
        self.assertTrue(corpus["triage_stale"])

    def test_wrong_total_reports_stale(self) -> None:
        payload = self._valid_triage()
        payload["conflicts_total"] = 12
        self._write_triage(payload)
        corpus = sup_mod._corpus_state(self.home)
        self.assertTrue(corpus["triage_stale"])

    def test_unreadable_triage_reports_stale_not_crash(self) -> None:
        (self.home / "conflict_triage.json").write_text("{broken", encoding="utf-8")
        corpus = sup_mod._corpus_state(self.home)
        self.assertTrue(corpus["triage_stale"])
        self.assertEqual(corpus["triage_file"], "unreadable")

    def test_operator_review_flag_is_counted(self) -> None:
        payload = self._valid_triage()
        payload["rows"][0]["operator_review_required"] = True
        self._write_triage(payload)
        corpus = sup_mod._corpus_state(self.home)
        self.assertEqual(corpus["operator_review_required"], 1)

    def test_control_is_read_only(self) -> None:
        before = support.tree_digest(self.home)
        sup_mod._corpus_state(self.home)
        self.assertEqual(support.tree_digest(self.home), before)


class MaterialTriageIdentity(unittest.TestCase):
    """ROLE 20260910 §8 A-H: a disposition binds to MATERIAL conflict evidence.

    The pre-material check bound triage only to the session-id set; mutating
    the same session into a NEW conflict (new generation, changed prefix
    digests, changed source_ref or sequence) left triage_stale=False. The
    controls here prove the material digest binds dispositions to evidence.

    Critical tests mutate the ACTUAL canonical session index, not fake hashes.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = _conflicted_home(self._tmp.name)

    def _load_corpus(self):
        return sup_mod._corpus_state(self.home)

    def _write_valid_triage(self) -> None:
        """Write a triage row from the current production corpus."""
        corpus = self._load_corpus()
        row = corpus["conflict_rows"][0]
        payload = {
            "schema_version": 2,
            "material_digest_version": corpus.get("material_digest_version", 1),
            "conflicts_total": 1,
            "rows": [{
                "session_id": row["session_id"],
                "generation": row["generation"],
                "temperature": "HOT",
                "disposition": "EXPECTED_MUTATION_ACCEPTED",
                "operator_review_required": False,
                "conflict_material_sha256": row["conflict_material_sha256"],
            }],
        }
        (self.home / "conflict_triage.json").write_text(
            json.dumps(payload, indent=1), encoding="utf-8"
        )

    def _assert_current(self) -> None:
        corpus = self._load_corpus()
        self.assertFalse(corpus["triage_stale"])

    def _assert_stale(self) -> None:
        corpus = self._load_corpus()
        self.assertTrue(corpus["triage_stale"])

    def _mutate_index(self, mutator) -> None:
        """Mutate the session index and save."""
        from saipal_engine import sessions as sessions_mod
        status, index, _ = sessions_mod.load_index(self.home)
        mutator(index)
        sessions_mod.save_index(self.home, index)

    def _get_conflict_rec(self, index):
        for r in index.get("sessions", []):
            if r.get("status") == "CONFLICT":
                return r
        return None

    def test_a_same_id_same_evidence_is_fresh(self) -> None:
        self._write_valid_triage()
        self._assert_current()

    def test_b_same_id_new_generation_is_stale(self) -> None:
        self._write_valid_triage()
        def bump(idx):
            rec = self._get_conflict_rec(idx)
            rec["generation"] = int(rec.get("generation") or 1) + 1
        self._mutate_index(bump)
        self._assert_stale()

    def test_c_same_id_changed_observed_prefix_is_stale(self) -> None:
        self._write_valid_triage()
        self._mutate_index(lambda idx: self._get_conflict_rec(idx)["conflict"].update({
            "observed_prefix_sha256": "0" * 64
        }))
        self._assert_stale()

    def test_d_same_id_changed_expected_prefix_is_stale(self) -> None:
        self._write_valid_triage()
        self._mutate_index(lambda idx: self._get_conflict_rec(idx)["conflict"].update({
            "expected_prefix_sha256": "1" * 64
        }))
        self._assert_stale()

    def test_e_same_id_changed_source_ref_is_stale(self) -> None:
        self._write_valid_triage()
        self._mutate_index(lambda idx: self._get_conflict_rec(idx)["conflict"].update({
            "source_ref": "session_inbox/other.json"
        }))
        self._assert_stale()

    def test_f_same_id_changed_last_analyzed_seq_is_stale(self) -> None:
        self._write_valid_triage()
        self._mutate_index(lambda idx: self._get_conflict_rec(idx)["conflict"].update({
            "last_analyzed_seq": int(self._get_conflict_rec(idx)["conflict"].get("last_analyzed_seq", 0)) + 1
        }))
        self._assert_stale()

    def test_g_only_detected_at_change_stays_fresh(self) -> None:
        self._write_valid_triage()
        # detected_at is NOT part of the material digest: identical evidence
        # legitimately re-observed later keeps its disposition current.
        self._mutate_index(lambda idx: self._get_conflict_rec(idx)["conflict"].update({
            "detected_at": "2099-01-01T00:00:00Z"
        }))
        self._assert_current()

    def test_h_resolved_generation_removes_conflict_stale(self) -> None:
        # Advance the conflict session to a new generation (IMPORTED/COLD)
        # The old CONFLICT record is superseded; triage for old material is stale.
        self._write_valid_triage()
        self._mutate_index(lambda idx: self._get_conflict_rec(idx).update({"status": "IMPORTED"}))
        self._assert_stale()

    def test_wrong_material_digest_version_is_stale(self) -> None:
        """Generic control: mismatched digest version marks triage stale."""
        self._write_valid_triage()
        # Flip version in the triage file only
        payload = json.loads((self.home / "conflict_triage.json").read_text(encoding="utf-8"))
        payload["material_digest_version"] = 99
        (self.home / "conflict_triage.json").write_text(json.dumps(payload, indent=1), encoding="utf-8")
        self._assert_stale()

    def test_wrong_stored_digest_is_stale(self) -> None:
        """Generic control: wrong stored digest is stale (replaces stale_digest fakes)."""
        corpus = self._load_corpus()
        row = corpus["conflict_rows"][0]
        payload = {
            "schema_version": 2,
            "material_digest_version": corpus.get("material_digest_version", 1),
            "conflicts_total": 1,
            "rows": [{
                "session_id": row["session_id"],
                "generation": row["generation"],
                "disposition": "EXPECTED_MUTATION_ACCEPTED",
                "operator_review_required": False,
                "conflict_material_sha256": "0" * 64,  # deliberately wrong
            }],
        }
        (self.home / "conflict_triage.json").write_text(json.dumps(payload, indent=1), encoding="utf-8")
        self._assert_stale()


class TriageStatusSurfacing(unittest.TestCase):
    """ROLE 32: doctor and watch --status expose the triage truth, identically."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = _conflicted_home(self._tmp.name)

    def test_doctor_and_watch_agree_on_triage_truth(self) -> None:
        code, payload, err = support.run_saipal_json("doctor", home=self.home)
        self.assertEqual(code, 0, err)
        corpus = sup_mod.watch_status(self.home)["corpus"]
        triage = payload["conflict_triage"]
        for key in (
            "conflicts_current",
            "conflicts_triaged",
            "conflicts_untriaged",
            "triage_stale",
            "operator_review_required",
        ):
            self.assertEqual(triage[key], corpus[key], key)

    def test_human_doctor_names_the_triage_line(self) -> None:
        code, out, err = support.run_saipal("doctor", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertIn("conflicts: current=", out)
        self.assertIn("stale=True", out)  # no triage file yet


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
