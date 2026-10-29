"""T-85: forensic source inventory, persistent enrollment and health.

Discovery reports each adapter's candidate store truthfully (an unconfigured
adapter never reads as "all sessions"); enrollment is a deliberate atomic
write that requires recognized structure and refuses duplicate paths under
different spellings; health memory records consecutive failures without ever
turning a source outage into semantic evidence.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import source_health as sh_mod
from saipal_engine.errors import PalError
from saipal_engine.sources import load_sources


class DiscoveryTruth(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def test_unconfigured_adapters_reported_not_claimed(self) -> None:
        from saipal_engine.sources import sources_report

        report = sources_report(self.home)
        self.assertTrue(report)
        for kind, row in report.items():
            if kind != "opencode":
                # No silent "all sessions" claim: an unconfigured adapter shows
                # its discovery state and zero fabricated session counts.
                self.assertIn(
                    row.get("discovery"), ("unconfigured", "vendor-location", "configured", "auto"),
                    f"{kind} must name its discovery method",
                )
                self.assertIsInstance(row.get("status"), str)

    def test_discover_is_read_only(self) -> None:
        from saipal_engine.sources import discover

        rows = discover(self.home)
        self.assertIsInstance(rows, list)
        self.assertFalse((self.home / "sources.json").exists(), "discovery writes nothing")


class Enrollment(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        self.store = Path(self._tmp.name) / "claude-store"
        self.store.mkdir(parents=True)
        (self.store / "session-1.jsonl").write_text('{"type": "x"}\n', encoding="utf-8")

    def test_enroll_persists_atomically_with_verified_structure(self) -> None:
        result = sh_mod.enroll_source(
            self.home, kind="claude", path=self.store, source_id="claude-main"
        )
        self.assertTrue(result["ok"])
        status, payload, _detail = load_sources(self.home)
        self.assertEqual(status, "ok")
        ids = [s["id"] for s in payload["sources"]]
        self.assertIn("claude-main", ids)

    def test_duplicate_enrollment_is_idempotent_across_path_spellings(self) -> None:
        """T-112: identical re-enrollment (same canonical path + kind) is a
        no-op that preserves id and enabled state; it never mints a second
        source or refuses an operator re-running the same command."""
        first = sh_mod.enroll_source(self.home, kind="claude", path=self.store, source_id="a")
        # Dot segments name the same existing store on either platform.
        # Case aliases additionally apply on the supported Windows filesystem;
        # uppercasing /tmp on POSIX names a different, absent directory.
        variants = [self.store / ".." / self.store.name]
        if os.name == "nt":
            variants.append(Path(str(self.store).swapcase()))
        for variant in variants:
            with self.subTest(path=variant):
                self.assertNotEqual(str(variant), str(self.store))
                self.assertTrue(variant.samefile(self.store))
                again = sh_mod.enroll_source(self.home, kind="claude", path=variant, source_id="b")
                self.assertTrue(again["ok"])
                self.assertEqual(again["id"], "a", "re-enrollment must keep the existing id")
                self.assertTrue(again.get("unchanged"))
        _status, payload, _d = load_sources(self.home)
        self.assertEqual(len(payload["sources"]), 1)
        self.assertEqual(payload["sources"][0]["id"], "a")
        _ = first

    def test_same_path_conflicting_kind_is_refused_zero_write(self) -> None:
        sh_mod.enroll_source(self.home, kind="claude", path=self.store, source_id="a")
        with self.assertRaises(PalError) as caught:
            sh_mod.enroll_source(self.home, kind="opencode", path=self.store, source_id="b")
        self.assertIn("conflict", str(caught.exception))
        _status, payload, _d = load_sources(self.home)
        self.assertEqual(len(payload["sources"]), 1)
        self.assertEqual(payload["sources"][0]["kind"], "claude")

    def test_enrollment_requires_recognized_structure(self) -> None:
        missing = Path(self._tmp.name) / "missing"
        with self.assertRaises(PalError) as caught:
            sh_mod.enroll_source(self.home, kind="claude", path=missing)
        self.assertIn("does not exist", str(caught.exception))
        # An empty dir IS a recognized structure (EMPTY is a state, not a
        # refusal) -- a deliberately different contract from a missing path.
        _status, payload, _d = load_sources(self.home)
        self.assertIsNone(payload, "the refused enrollment wrote nothing")

    def test_unknown_adapter_refused(self) -> None:
        with self.assertRaises(PalError):
            sh_mod.enroll_source(self.home, kind="not-an-adapter", path=self.store)


class SetupBypassClosed(unittest.TestCase):
    """T-99: legacy `setup --source`/`setup --protocol-*` cannot bypass the
    canonical enrollment gates."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))
        self.store = Path(self._tmp.name) / "claude-store"
        self.store.mkdir(parents=True)
        (self.store / "session-1.jsonl").write_text('{"type": "x"}\n', encoding="utf-8")

    def test_setup_source_nonexistent_path_refused(self) -> None:
        missing = Path(self._tmp.name) / "does-not-exist"
        code, payload, _err = support.run_saipal_json(
            "setup", "--source", str(missing), "--kind", "generic", home=self.home
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "INVALID_SOURCE_REGISTRY")
        _status, sources_payload, _detail = load_sources(self.home)
        self.assertEqual(
            (sources_payload or {}).get("sources") or [],
            [],
            "no nonexistent source may be persisted through any setup path",
        )

    def test_setup_source_unknown_adapter_refused(self) -> None:
        empty = Path(self._tmp.name) / "empty-store"
        empty.mkdir()
        code, payload, _err = support.run_saipal_json(
            "setup", "--source", str(empty), "--kind", "unknown-adapter", home=self.home
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "INVALID_SOURCE_REGISTRY")

    def test_refused_setup_destroys_nothing_byte_for_byte(self) -> None:
        """T-112 red: a refused setup must leave sources.json byte-identical.

        The old shim pre-deleted matching path entries and saved the registry
        BEFORE enrollment validation, so refusing `--kind not-an-adapter`
        against a valid enrolled path emptied sources.json.
        """
        code, _payload, err = support.run_saipal_json(
            "setup", "--source", str(self.store), "--kind", "claude", home=self.home
        )
        self.assertEqual(code, 0, err)
        from saipal_engine.paths import home_paths

        sources_path = home_paths(self.home).sources
        self.assertTrue(sources_path.exists())
        before = sources_path.read_bytes()
        code, payload, _err = support.run_saipal_json(
            "setup", "--source", str(self.store), "--kind", "not-an-adapter",
            home=self.home,
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "INVALID_SOURCE_REGISTRY")
        self.assertEqual(
            sources_path.read_bytes(),
            before,
            "a refused setup must be byte-for-byte zero-write",
        )

    def test_successful_resetup_preserves_identity_and_enabled_state(self) -> None:
        """T-112 red: re-running the same setup is a no-op, not a re-mint.

        The old shim deleted the entry and re-enrolled, changing
        stable-id -> claude-01 and enabled=false -> true.
        """
        code, _payload, err = support.run_saipal_json(
            "setup", "--source", str(self.store), "--kind", "claude", home=self.home
        )
        self.assertEqual(code, 0, err)
        from saipal_engine.sources import load_sources, save_sources

        # Operator deliberately disabled it after enrollment.
        _s, payload, _d = load_sources(self.home)
        payload["sources"][0]["enabled"] = False
        save_sources(self.home, payload)
        before = payload["sources"][0]

        code, _payload, err = support.run_saipal_json(
            "setup", "--source", str(self.store), "--kind", "claude", home=self.home
        )
        self.assertEqual(code, 0, err)
        _s, payload, _d = load_sources(self.home)
        self.assertEqual(len(payload["sources"]), 1)
        after = payload["sources"][0]
        self.assertEqual(after["id"], before["id"])
        self.assertEqual(after["enabled"], False, "enrollment must not flip enabled")
        self.assertEqual(after["kind"], "claude")

    def test_setup_alias_and_sources_enroll_cli_identical(self) -> None:
        """T-112: legacy setup alias and `sources enroll` CLI behave the same."""
        code, _p, err = support.run_saipal_json(
            "setup", "--source", str(self.store), "--kind", "claude", home=self.home
        )
        self.assertEqual(code, 0, err)
        from saipal_engine.sources import load_sources

        _s, payload, _d = load_sources(self.home)
        setup_entry = dict(payload["sources"][0])
        # Wipe and re-enroll through the first-class CLI.
        from saipal_engine.paths import home_paths

        home_paths(self.home).sources.unlink()
        code, payload, err = support.run_saipal_json(
            "sources", "enroll", "--kind", "claude", "--path", str(self.store),
            home=self.home,
        )
        self.assertEqual(code, 0, err)
        _s, payload, _d = load_sources(self.home)
        cli_entry = payload["sources"][0]
        self.assertEqual(setup_entry["kind"], cli_entry["kind"])
        self.assertEqual(setup_entry["path"], cli_entry["path"])
        self.assertEqual(setup_entry["enabled"], cli_entry["enabled"])
        # And the same idempotency contract through the CLI.
        code, again, _err = support.run_saipal_json(
            "sources", "enroll", "--kind", "claude", "--path", str(self.store),
            home=self.home,
        )
        self.assertEqual(code, 0)
        self.assertTrue(again.get("unchanged"))
        self.assertEqual(again["id"], cli_entry["id"])

    def test_sources_enable_disable_is_deliberate(self) -> None:
        code, _p, err = support.run_saipal_json(
            "setup", "--source", str(self.store), "--kind", "claude", home=self.home
        )
        self.assertEqual(code, 0, err)
        code, payload, err = support.run_saipal_json(
            "sources", "disable", "claude-01", home=self.home
        )
        self.assertEqual(code, 0, err)
        self.assertFalse(payload["enabled"])
        code, payload, err = support.run_saipal_json(
            "sources", "enable", "claude-01", home=self.home
        )
        self.assertEqual(code, 0, err)
        self.assertTrue(payload["enabled"])
        from saipal_engine.sources import load_sources

        _s, payload, _d = load_sources(self.home)
        self.assertTrue(payload["sources"][0]["enabled"])

    def test_setup_protocol_git_non_git_directory_refused(self) -> None:
        # A normal existing directory is NOT a git repository: it must never
        # become a declared git_repository authority, and no pin may be left.
        plain = Path(self._tmp.name) / "plain-dir"
        plain.mkdir()
        code, payload, _err = support.run_saipal_json(
            "setup", "--protocol-git", str(plain), home=self.home
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "VALIDATION_FAILED")
        self.assertIn(
            "not a git repository",
            str(payload.get("detail") or payload.get("message") or payload),
        )
        from saipal_engine import authority as authority_mod
        from saipal_engine.config import load_config

        _s, config, _d = load_config(self.home)
        self.assertIsNone((config["protocol_authority"] or {}).get("git_repository"))
        pinning = authority_mod.load_pinning(self.home)
        self.assertEqual((pinning.get("roots") or {}).get("git_repository"), None)

    def test_setup_authority_alias_matches_canonical_enrollment(self) -> None:
        # A valid enrollment through the setup alias must produce the SAME
        # durable state as the canonical authority-enroll: config root plus
        # a pinning record.
        from saipal_engine import authority as authority_mod
        from saipal_engine.config import load_config

        releases = Path(self._tmp.name) / "releases"
        releases.mkdir()
        code, payload, _err = support.run_saipal_json(
            "setup", "--protocol-releases", str(releases), home=self.home
        )
        self.assertEqual(code, 0)
        _s, config, _d = load_config(self.home)
        self.assertEqual(
            (config["protocol_authority"] or {}).get("release_root"), str(releases)
        )
        pinning = authority_mod.load_pinning(self.home)
        self.assertIn("release_root", (pinning.get("roots") or {}))


class CycleAttribution(unittest.TestCase):
    """T-97: real intake attributes import outcomes back to each source."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def test_cycle_intake_attributes_imports_to_their_source(self) -> None:
        from saipal_analyst import supervisor as sup_mod
        from saipal_engine.sources import save_sources

        store = Path(self._tmp.name) / "claude-store"
        store.mkdir(parents=True)
        (store / "conformant-cold.jsonl").write_text(
            json.dumps(
                support.stamp_binding(self.home, support.load_fixture("conformant-cold.json"))
            ),
            encoding="utf-8",
        )
        save_sources(self.home, {
            "schema_version": 1,
            "sources": [{"id": "claude-main", "kind": "claude", "path": str(store), "enabled": True}],
        })
        result = sup_mod._cycle_intake(self.home)
        self.assertEqual(result["sessions_imported"], 1)
        from saipal_engine.source_health import load_health

        health = load_health(self.home)
        record = (health.get("sources") or {}).get("claude-main") or {}
        self.assertEqual(
            record.get("sessions_imported"), 1,
            f"health must attribute the real import to the source: {record}",
        )
        self.assertGreaterEqual(record.get("sessions_seen", 0), 0)
        self.assertIsNotNone(record.get("last_import_at"))
        self.assertIsNotNone(record.get("last_success_at"))
        self.assertIsNone(
            record.get("watermark"),
            "an unknown watermark is null, never zero",
        )
        # A second cycle: the same session is unchanged, still attributed.
        result2 = sup_mod._cycle_intake(self.home)
        health = load_health(self.home)
        record = (health.get("sources") or {}).get("claude-main") or {}
        self.assertGreaterEqual(
            record.get("sessions_unchanged", 0), 1,
            f"the unchanged re-dispatch must be attributed: {record}",
        )
        _ = result2

    def test_health_schema_v1_migrates_explicitly(self) -> None:
        path = self.home / "source_health.json"
        path.write_text(json.dumps({
            "schema_version": 1,
            "updated_at": "2026-09-01T00:00:00Z",
            "sources": {"s1": {
                "source_id": "s1",
                "last_discovery_ok": True,
                "last_import_ok": True,
                "sessions_seen": 3,
                "sessions_imported": 2,
                "last_error": None,
                "consecutive_failures": 0,
            }},
        }), encoding="utf-8")
        health = sh_mod.load_health(self.home)
        record = health["sources"]["s1"]
        self.assertEqual(record["sessions_imported"], 2)
        self.assertEqual(record["sessions_unchanged"], 0)
        self.assertIsNone(record["last_import_at"])
        self.assertIsNone(record["watermark"])
        # Read-only: the on-disk file is NOT migrated by a read.
        raw = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(raw["schema_version"], 1, "reads never migrate on disk")


class HealthMemory(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def test_health_schema_is_closed(self) -> None:
        payload = sh_mod.fresh_health()
        self.assertEqual(sh_mod.health_problems(payload), [])
        payload["nope"] = 1
        self.assertIn("unknown source health field 'nope'", sh_mod.health_problems(payload))

    def test_consecutive_failures_recorded_and_cleared(self) -> None:
        sh_mod.record_source_import(self.home, source_id="s1", error="store unreadable")
        sh_mod.record_source_import(self.home, source_id="s1", error="still unreadable")
        record = sh_mod.load_health(self.home)["sources"]["s1"]
        self.assertEqual(record["consecutive_failures"], 2)
        self.assertFalse(record["last_import_ok"])
        sh_mod.record_source_import(self.home, source_id="s1", sessions_seen=3, sessions_imported=3)
        record = sh_mod.load_health(self.home)["sources"]["s1"]
        self.assertEqual(record["consecutive_failures"], 0)
        self.assertTrue(record["last_import_ok"])
        self.assertEqual(record["sessions_imported"], 3)

    def test_source_outage_is_never_semantic_evidence(self) -> None:
        # The health record carries operational facts only; nothing in it can
        # produce a verdict, a finding, or coverage.
        record = sh_mod.record_source_import(self.home, source_id="s1", error="outage")
        for forbidden in ("verdict", "drift", "finding", "receipt"):
            self.assertNotIn(forbidden, record)


if __name__ == "__main__":
    unittest.main()
