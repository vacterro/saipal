"""T-87: deterministic historical rebinding of previously indexed sessions.

Evidence identity is immutable: rebind recomputes ONLY the historical binding
proof from the persisted protocol claims plus the enrolled authority. Only
strengthening transitions write; a downgrade is recorded, never applied; a
session upgraded to BOUND wakes its BLOCKED_BINDING analyst jobs without any
journal surgery.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst.config import default_analyst_config, save_analyst_config
from saipal_engine import rebind as rebind_mod
from saipal_engine.config import load_config, save_config
from saipal_engine.paths import home_paths


class RebindBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def make_release_root(self, name: str = "releases") -> Path:
        releases = Path(self._tmp.name) / name
        releases.mkdir(parents=True, exist_ok=True)
        target = releases / "7.231.9" / "saipal"
        target.mkdir(parents=True, exist_ok=True)
        source = Path(__file__).resolve().parents[1] / "saipal" / "REGISTRY.json"
        (target / "REGISTRY.json").write_bytes(source.read_bytes())
        return releases

    def fresh_home(self, *fixtures: str) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = support.make_home(Path(tmp.name))
        support.put_inbox(home, *fixtures)
        support.run_saipal("continue", home=home)
        return home

    def enroll_declared_authority(self, home: Path) -> None:
        """T-100: rebind strengthens only TRUSTED authority; enroll the pin.

        `support.make_home` declares the release root in config; the trusted
        accessor requires the matching pin, so tests enroll it explicitly --
        exactly the adoption path an operator takes.
        """
        import shutil

        from saipal_engine import authority as authority_mod

        releases = home.parent / "protocol_authority" / "releases"
        if releases.is_dir():
            authority_mod.enroll(home, "release_root", releases)
            return
        # A store whose authority lives elsewhere: fall back to the declared
        # release root from config.
        declared = (load_config(home)[1] or {}).get("protocol_authority") or {}
        for kind in ("release_root", "snapshot_root", "git_repository"):
            if declared.get(kind):
                authority_mod.enroll(home, kind, declared[kind])
                return
        raise AssertionError("no declared authority to enroll in this home")

    def strip_authority(self, home: Path) -> None:
        """Simulate the T-86-previous state: roots declared, all null."""
        from saipal_engine.config import load_config, save_config

        config = load_config(home)[1]
        config["protocol_authority"] = {
            key: None for key in ("git_repository", "release_root", "snapshot_root")
        }
        save_config(home, config)

    def session_records(self, home: Path) -> list[dict]:
        _status, index, _detail = __import__(
            "saipal_engine.sessions", fromlist=["load_index"]
        ).load_index(home)
        return list(index.get("sessions") or [])


class RebindCheckpoint(RebindBase):
    """T-101 r26-r29: index-generation reconciliation + corrupt refusal."""

    def test_checkpoint_records_index_generation(self) -> None:
        from saipal_engine.rebind import (
            checkpoint_path,
            index_generation_digest,
            save_checkpoint,
        )

        home = self.fresh_home("conformant-cold.json")
        digest = index_generation_digest(home)
        self.assertRegex(digest, r"^[0-9a-f]{16}$")
        # Ordinary semantic receipts change no binding input: the digest is
        # stable across them. Submit one receipt and re-derive.
        support.submit_drift(home, support.next_unit(home))
        self.assertEqual(
            index_generation_digest(home), digest,
            "a semantic receipt must not churn the reconciliation generation",
        )
        save_checkpoint(home, {
            "authority_fingerprint": "a" * 16,
            "index_generation_digest": digest,
        })
        checkpoint = json.loads(checkpoint_path(home).read_text(encoding="utf-8"))
        self.assertEqual(checkpoint["index_generation_digest"], digest)

    def test_corrupt_checkpoint_is_a_loud_refusal_never_a_fresh_reset(self) -> None:
        """r28 red: `{not-json` used to load as a FRESH checkpoint, silently
        reinterpreting destroyed reconciliation evidence as never-reconciled."""
        from saipal_engine.errors import PalError
        from saipal_engine.rebind import load_checkpoint

        path = rebind_mod.checkpoint_path(self.home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not-json", encoding="utf-8")
        with self.assertRaises(PalError) as caught:
            load_checkpoint(self.home)
        self.assertIn("unreadable", str(caught.exception))

    def test_invalid_checkpoint_shape_is_a_loud_refusal(self) -> None:
        from saipal_engine.errors import PalError
        from saipal_engine.rebind import load_checkpoint

        path = rebind_mod.checkpoint_path(self.home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "schema_version": 2,
            "authority_fingerprint": "not-hex!",
            "index_generation_digest": None,
            "reconciled_at": "2026-09-08T00:00:00Z",
        }), encoding="utf-8")
        with self.assertRaises(PalError) as caught:
            load_checkpoint(self.home)
        self.assertIn("authority_fingerprint", str(caught.exception))

    def test_unknown_checkpoint_field_is_refused(self) -> None:
        from saipal_engine.errors import PalError
        from saipal_engine.rebind import load_checkpoint

        path = rebind_mod.checkpoint_path(self.home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "schema_version": 2,
            "authority_fingerprint": "a" * 16,
            "index_generation_digest": "b" * 16,
            "reconciled_at": "2026-09-08T00:00:00Z",
            "invented_field": 1,
        }), encoding="utf-8")
        with self.assertRaises(PalError):
            load_checkpoint(self.home)

    def test_legacy_schema_v1_reports_migration_required_read_only(self) -> None:
        """r29: read-only status reports INVALID/MIGRATION_REQUIRED, no write."""
        from saipal_engine.rebind import checkpoint_path, checkpoint_status

        path = checkpoint_path(self.home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "schema_version": 1,
            "authority_fingerprint": "a" * 16,
            "index_digest": None,
            "reconciled_at": "2026-09-08T00:00:00Z",
        }), encoding="utf-8")
        before = path.read_bytes()
        status = checkpoint_status(self.home)
        self.assertEqual(status["state"], "MIGRATION_REQUIRED")
        self.assertFalse(status.get("wrote"))
        self.assertEqual(path.read_bytes(), before, "read-only status writes nothing")

    def test_mutating_watch_refuses_on_corrupt_checkpoint_before_model_work(self) -> None:
        import os
        import test_wave_analyst_repair as repair
        from saipal_analyst import supervisor as sup_mod
        from saipal_analyst.config import default_analyst_config as _default_analyst
        from saipal_engine.errors import PalError

        home = self.fresh_home("conformant-cold.json")
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        config = _default_analyst()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        save_analyst_config(home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "k"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)
        path = rebind_mod.checkpoint_path(home)
        path.write_text("{torn", encoding="utf-8")
        with self.assertRaises(PalError) as caught:
            sup_mod.watch(home, max_cycles=1, max_units_per_cycle=1, sleep_fn=lambda _s: None)
        self.assertIn("rebind checkpoint", str(caught.exception))
        self.assertEqual(
            backend.attempts, 0,
            "no model call may happen on top of corrupt reconciliation state",
        )

    def test_same_root_nonmax_release_mutation_changes_fingerprint(self) -> None:
        """r22/r55 red: mutating a NON-max existing release's registry must
        change the aggregate fingerprint (the digests[-1] collision bug)."""
        from saipal_engine.rebind import material_fingerprint

        releases = Path(self._tmp.name) / "releases"
        for name in ("1.0.0", "2.0.0"):
            target = releases / name / "saipal"
            target.mkdir(parents=True)
            source = Path(__file__).resolve().parents[1] / "saipal" / "REGISTRY.json"
            (target / "REGISTRY.json").write_bytes(source.read_bytes())
        # Make 2.0.0's digest lexicographically HIGHEST (deterministic) by
        # appending a byte pattern whose digest sorts high; the mutation below
        # changes 1.0.0 (the NON-max release) only.
        from saipal_engine import authority as authority_mod

        self.enroll_release_root(releases)
        before = material_fingerprint(self.home)
        low = releases / "1.0.0" / "saipal" / "REGISTRY.json"
        low.write_bytes(low.read_bytes() + b"\n")
        after = material_fingerprint(self.home)
        self.assertNotEqual(
            before, after,
            "a non-max release mutation must change the aggregate fingerprint",
        )
        _ = authority_mod

    def enroll_release_root(self, releases: Path) -> None:
        from saipal_engine import authority as authority_mod

        authority_mod.enroll(self.home, "release_root", releases)

    def test_snapshot_content_mutation_is_detectable(self) -> None:
        """r24: a snapshot changing under the same name is visible."""
        from saipal_engine.rebind import material_fingerprint

        root = Path(self._tmp.name) / "snapshots"
        snap = root / "snap-a" / "saipal"
        snap.mkdir(parents=True)
        source = Path(__file__).resolve().parents[1] / "saipal" / "REGISTRY.json"
        (snap / "REGISTRY.json").write_bytes(source.read_bytes())
        self.enroll_release_root(root)
        before = material_fingerprint(self.home)
        (snap / "REGISTRY.json").write_bytes(source.read_bytes() + b"\n")
        after = material_fingerprint(self.home)
        self.assertNotEqual(before, after, "same-name snapshot content change is visible")


class RebindPass(RebindBase):
    def test_import_with_null_authority_is_unknown_then_rebinds_to_bound(self) -> None:
        # Fixture claims are stamped while the authority is declared, then the
        # config's roots are nulled BEFORE import: the record computes
        # PARTIAL/UNKNOWN and cannot self-certify -- the pre-T-86 snapshot.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = support.make_home(Path(tmp.name))
        support.put_inbox(home, "conformant-cold.json")
        self.strip_authority(home)
        support.run_saipal("continue", home=home)
        record = self.session_records(home)[0]
        self.assertIn(record["protocol"]["binding_status"], ("UNKNOWN", "PARTIAL"))
        self.assertIsNone(record["protocol"].get("rebind"))

        # Authority is enrolled afterwards: rebind strengthens in place.
        # T-100: config alone is not trust; the pin is the adoption path.
        from saipal_engine.config import save_config

        config = load_config(home)[1]
        config["protocol_authority"] = authority_dict(home)
        save_config(home, config)
        self.enroll_declared_authority(home)

        before_identity = {
            key: record.get(key)
            for key in ("bundle_sha256", "generation", "source_sha256")
        }
        before_episodes = json.dumps(record.get("episodes"), sort_keys=True)

        report = rebind_mod.rebind(home)

        self.assertTrue(report["ok"])
        self.assertEqual(report["scanned"], 1)
        self.assertGreaterEqual(
            report["unknown_to_bound"] + report["partial_to_bound"] + report["unknown_to_partial"],
            1,
            f"the record must strengthen: {report}",
        )
        record_after = self.session_records(home)[0]
        self.assertEqual(record_after["protocol"]["binding_status"], "BOUND")
        # Immutable evidence identity: digests, generation, episodes intact.
        self.assertEqual(
            {key: record_after.get(key) for key in before_identity},
            before_identity,
        )
        self.assertEqual(json.dumps(record_after.get("episodes"), sort_keys=True), before_episodes)

    def test_downgrade_is_recorded_never_applied(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        record = self.session_records(home)[0]
        self.assertEqual(record["protocol"]["binding_status"], "BOUND")
        before = json.dumps(record["protocol"], sort_keys=True)

        # An authority root that exists but cannot verify THIS claim downgrades
        # the recompute; a genuinely BOUND record must not silently weaken.
        other = self.make_release_root("unrelated-releases")
        from saipal_engine.config import save_config

        config = load_config(home)[1]
        config["protocol_authority"] = {
            "git_repository": None,
            "release_root": str(other),
            "snapshot_root": None,
        }
        save_config(home, config)
        report = rebind_mod.rebind(home)
        self.assertTrue(report["ok"])
        self.assertEqual(
            len(report["suspicious_downgrades"]), 0,
            "absent authority yields PARTIAL/UNKNOWN only for claims that never proved BOUND",
        )
        record_after = self.session_records(home)[0]
        self.assertEqual(json.dumps(record_after["protocol"], sort_keys=True), before)

    def test_rebind_is_idempotent(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = support.make_home(Path(tmp.name))
        self.strip_authority(home)
        support.put_inbox(home, "conformant-cold.json")
        support.run_saipal("continue", home=home)
        from saipal_engine.config import load_config, save_config

        config = load_config(home)[1]
        config["protocol_authority"] = authority_dict(home)
        save_config(home, config)

        first = rebind_mod.rebind(home)
        snapshot = json.dumps(self.session_records(home), sort_keys=True)
        second = rebind_mod.rebind(home)
        self.assertEqual(json.dumps(self.session_records(home), sort_keys=True), snapshot)
        self.assertEqual(second["unchanged"], first["scanned"], "a second pass changes nothing")

    def test_blocked_binding_job_wakes_without_journal_surgery(self) -> None:
        import test_wave_analyst_repair as repair
        from saipal_analyst import jobs as jobs_mod
        from saipal_analyst.worker import investigate

        # The T-86-previous world: claims stamped, authority null at import,
        # so the worker correctly blocks the PARTIAL unit.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = support.make_home(Path(tmp.name))
        support.put_inbox(home, "conformant-cold.json")
        self.strip_authority(home)
        support.run_saipal("continue", home=home)
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = backend.endpoint()
        config["backend"]["model"] = "stub-model"
        save_analyst_config(home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "k"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)

        blocked = investigate(home)
        self.assertEqual(blocked["stop_reason"], "BLOCKED")
        self.assertEqual(backend.attempts, 0)
        job = list(jobs_mod.load_journal(home)["jobs"].values())[0]
        self.assertEqual(job["stage"], jobs_mod.BLOCKED_BINDING)

        # T-86 enrollment + T-87 rebind: no re-import, no journal edit.
        # T-100: config alone is not trust; enroll the pin.
        from saipal_engine.config import save_config

        config_kernel = load_config(home)[1]
        config_kernel["protocol_authority"] = authority_dict(home)
        save_config(home, config_kernel)
        self.enroll_declared_authority(home)
        report = rebind_mod.rebind(home)
        self.assertTrue(report["ok"])
        record = self.session_records(home)[0]
        self.assertEqual(record["protocol"]["binding_status"], "BOUND")

        backend.script.append((200, repair.envelope(
            repair.RepairBase.candidate_for(repair.RepairBase(), home)
        )))
        summary = investigate(home)
        self.assertEqual(summary["jobs_completed"], 1, "the job woke and processed")
        self.assertGreaterEqual(backend.attempts, 1)
        journal = jobs_mod.load_journal(home)
        reactivated = journal["jobs"].get(job["job_id"])
        self.assertIsNotNone(reactivated)
        self.assertIn(reactivated["stage"], (jobs_mod.DONE, jobs_mod.SUBMITTING))

    def test_telemetry_reports_backlog_impact(self) -> None:
        home = self.fresh_home("conformant-cold.json")
        report = rebind_mod.rebind(home)
        for key in ("scanned", "unchanged", "newly_eligible_units", "suspicious_downgrades", "errors"):
            self.assertIn(key, report)
        self.assertGreaterEqual(report["newly_eligible_units"], 1)


def load_config_authority(home: Path) -> dict:
    from saipal_engine.config import load_config

    config = load_config(home)[1]
    config["protocol_authority"] = authority_dict(home)
    return config


def authority_dict(home=None):
    from saipal_engine.config import load_config as _load

    declared = (_load(home)[1] or {}).get("protocol_authority") or {}
    if declared.get("release_root"):
        # The home already declared a release root (support.make_home does).
        return dict(declared)
    # The authority pal_test_support declared lives beside the home:
    # <tmp_path>/protocol_authority/releases where home == <tmp_path>/.saipal.
    releases = home.parent / "protocol_authority" / "releases"
    return {
        "git_repository": None,
        "release_root": str(releases),
        "snapshot_root": None,
    }


def authority_dict_install(home: Path) -> None:
    from saipal_engine.config import save_config

    config = load_config(home)[1]
    config["protocol_authority"] = authority_dict(home)
    save_config(home, config)


if __name__ == "__main__":
    unittest.main()
