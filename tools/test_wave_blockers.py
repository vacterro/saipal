"""T-102: read-only binding blocker diagnostics.

The corpus is overwhelmingly unbound; the operator needs one screen that says
WHY and whether enrollment/rebind can unlock it. These controls pin the
aggregation: closed reason set, counts plus representative session ids, no
writes, and the recoverability split.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine.blockers import binding_blockers


def _record(session_id: str, *, protocol: dict | None, status: str = "IMPORTED") -> dict:
    record = {
        "session_id": session_id,
        "status": status,
        "episodes": [],
        "protocol": protocol or {},
    }
    return record


class BlockerBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))


class Aggregation(BlockerBase):
    def _index_with(self, records: list[dict]) -> dict:
        return {"schema_version": 1, "sessions": records}

    def test_no_identity_groups_under_identity_absent(self) -> None:
        report = binding_blockers(
            self.home,
            index=self._index_with(
                [_record("s1", protocol={}), _record("s2", protocol=None)]
            ),
        )
        rows = {row["reason"]: row for row in report["blockers"]}
        self.assertEqual(rows["IDENTITY_ABSENT"]["count"], 2)
        self.assertIn("s1", rows["IDENTITY_ABSENT"]["representative_sessions"])
        self.assertIn("s2", rows["IDENTITY_ABSENT"]["representative_sessions"])
        self.assertFalse(rows["IDENTITY_ABSENT"]["recoverable"])

    def test_no_authority_groups_under_trusted_authority_absent(self) -> None:
        from saipal_engine.config import load_config, save_config

        _status, config, _detail = load_config(self.home)
        config["protocol_authority"] = {
            "git_repository": None,
            "release_root": None,
            "snapshot_root": None,
        }
        save_config(self.home, config)
        protocol = {
            "version": "7.231.9",
            "registry_sha256": "a" * 64,
            "binding_status": "PARTIAL",
        }
        report = binding_blockers(
            self.home, index=self._index_with([_record("s1", protocol=protocol)])
        )
        rows = {row["reason"]: row for row in report["blockers"]}
        self.assertEqual(rows["TRUSTED_AUTHORITY_ABSENT"]["count"], 1)
        self.assertTrue(rows["TRUSTED_AUTHORITY_ABSENT"]["recoverable"])

    def test_malformed_claims_are_never_recoverable(self) -> None:
        protocol = {
            "git_head": "not-hex",
            "binding_status": "UNKNOWN",
        }
        report = binding_blockers(
            self.home, index=self._index_with([_record("s1", protocol=protocol)])
        )
        rows = {row["reason"]: row for row in report["blockers"]}
        self.assertEqual(rows["MALFORMED_CLAIM"]["count"], 1)
        self.assertFalse(rows["MALFORMED_CLAIM"]["recoverable"])

    def test_bound_sessions_never_appear_in_blockers(self) -> None:
        protocol = {"binding_status": "BOUND"}
        report = binding_blockers(
            self.home, index=self._index_with([_record("s1", protocol=protocol)])
        )
        self.assertEqual(report["counts"]["bound"], 1)
        self.assertEqual(report["blockers"], [])

    def test_counts_partition_the_corpus(self) -> None:
        records = [
            _record("b1", protocol={"binding_status": "BOUND"}),
            _record("p1", protocol={"binding_status": "PARTIAL", "version": "1.0"}),
            _record("u1", protocol={"binding_status": "UNKNOWN"}),
        ]
        report = binding_blockers(self.home, index=self._index_with(records))
        self.assertEqual(report["counts"]["current_sessions_total"], 3)
        self.assertEqual(report["counts"]["bound"], 1)
        self.assertEqual(report["counts"]["partial"], 1)
        self.assertEqual(report["counts"]["unknown"], 1)

    def test_representative_sample_is_bounded(self) -> None:
        from saipal_engine.blockers import SAMPLE_LIMIT

        records = [
            _record(f"s{i}", protocol={}) for i in range(SAMPLE_LIMIT + 10)
        ]
        report = binding_blockers(self.home, index=self._index_with(records))
        rows = {row["reason"]: row for row in report["blockers"]}
        self.assertEqual(rows["IDENTITY_ABSENT"]["count"], SAMPLE_LIMIT + 10)
        self.assertEqual(len(rows["IDENTITY_ABSENT"]["representative_sessions"]), SAMPLE_LIMIT)

    def test_blocker_report_is_read_only(self) -> None:
        listing_before = sorted(p.name for p in self.home.rglob("*"))
        protocol = {"version": "1.0", "binding_status": "PARTIAL"}
        binding_blockers(
            self.home, index=self._index_with([_record("s1", protocol=protocol)])
        )
        listing_after = sorted(p.name for p in self.home.rglob("*"))
        self.assertEqual(listing_before, listing_after, "diagnostics must write nothing")


class DoctorIntegration(BlockerBase):
    def test_doctor_exposes_binding_blockers(self) -> None:
        code, payload, err = support.run_saipal_json("doctor", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertIn("binding_blockers", payload)
        self.assertTrue(payload["binding_blockers"]["ok"])

    def test_cli_coverage_is_read_only_and_routes(self) -> None:
        code, payload, err = support.run_saipal_json("coverage", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertTrue(payload["binding_blockers"])
        self.assertTrue(payload["read_only"])
        self.assertIn("counts", payload)


class GenerationTruth(BlockerBase):
    """T-114: indexed RECORD totals and CURRENT session totals are named.

    283 indexed records across generations and 273 freshest-generation
    sessions are both valid numbers; presenting them under one unnamed
    "session" metric makes the operator think a contradiction happened.
    """

    def test_doctor_names_indexed_records_and_current_sessions(self) -> None:
        code, payload, err = support.run_saipal_json("doctor", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertIn("indexed_records_total", payload)
        self.assertIn("current_sessions_total", payload)
        self.assertIn("current_binding_counts", payload)
        # Current breakdown mirrors the blockers report's current population.
        counts = (payload.get("binding_blockers") or {}).get("counts") or {}
        self.assertEqual(
            payload["current_sessions_total"], counts.get("current_sessions_total")
        )

    def test_per_kind_trust_is_not_any_pin_anywhere(self) -> None:
        """One pinned kind must not make another unpinned root look trusted."""
        from saipal_engine import authority as authority_mod
        from saipal_engine.config import load_config, save_config
        from saipal_engine.blockers import _per_kind_trust

        releases = Path(self._tmp.name) / "releases"
        releases.mkdir(parents=True, exist_ok=True)
        target = releases / "7.231.9" / "saipal"
        target.mkdir(parents=True)
        import shutil

        shutil.copy(
            Path(__file__).resolve().parents[1] / "saipal" / "REGISTRY.json",
            target / "REGISTRY.json",
        )
        # release_root configured AND pinned; git_repository configured but unpinned.
        authority_mod.enroll(self.home, "release_root", releases)
        _status, config, _detail = load_config(self.home)
        config["protocol_authority"]["git_repository"] = str(
            Path(self._tmp.name) / "some-repo"
        )
        save_config(self.home, config)

        trust = _per_kind_trust(self.home)
        self.assertEqual(trust["release_root"], "TRUSTED")
        self.assertEqual(
            trust["git_repository"], "LEGACY_UNPINNED",
            "a configured but unpinned kind is LEGACY_UNPINNED per kind",
        )

        # A git-commit claim with release_root TRUSTED but git absent:
        # classified by the GIT kind's own trust, never generically.
        from saipal_engine.blockers import _classify

        record = {"protocol": {"git_head": "a" * 40}, "status": "IMPORTED"}
        self.assertEqual(
            _classify(record, authority_declared=True, trust=trust),
            "LEGACY_UNPINNED",
        )
        absent = dict(trust)
        absent["git_repository"] = "ABSENT"
        self.assertEqual(
            _classify(record, authority_declared=True, trust=absent),
            "TRUSTED_AUTHORITY_ABSENT",
        )


if __name__ == "__main__":
    unittest.main()
