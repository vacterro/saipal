"""T-039: historical rule retrieval from an exact commit, release or snapshot.

A session is judged by the protocol that governed it, so the rule TEXT must come
from the identity the session carries -- not from the protocol installed today.
This module proves the retrieval layer is bounded, read-only, authority-scoped,
and that a transcript cannot steer it at a filesystem path.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import config as config_mod
from saipal_engine import historical as hist
from saipal_engine import pipeline as pipeline_mod
from saipal_engine.registry import load_registry

PROTOCOL_DIR = support.REPO_ROOT / "saipal"
RULE = "PAL-CMD-01"


def _authority_tree(root: Path) -> Path:
    """A minimal but real protocol surface: the registry plus its owner docs."""
    target = root / "saipal"
    target.mkdir(parents=True, exist_ok=True)
    registry = json.loads((PROTOCOL_DIR / "REGISTRY.json").read_text(encoding="utf-8-sig"))
    owners = sorted(set(registry["rule_owners"].values()))
    for owner in owners:
        source = support.REPO_ROOT / owner
        (root / owner).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, root / owner)
    shutil.copyfile(PROTOCOL_DIR / "REGISTRY.json", target / "REGISTRY.json")
    return root


def _git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, timeout=10, check=True)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


class RuleSectionExtraction(unittest.TestCase):
    """The retrieved surface is the rule's own section, bounded and exact."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = _authority_tree(Path(self.tmp.name) / "snapshot")
        self.fingerprint = hist.protocol_tree_fingerprint(self.root, registry=self.registry)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_snapshot_root_must_be_keyed_by_fingerprint(self) -> None:
        """A snapshot root is `<root>/<fingerprint>/`, not the tree itself."""
        result = hist.read_historical_rules(
            {"tree_fingerprint": self.fingerprint},
            [RULE],
            snapshot_root=self.root.parent,
            registry=self.registry,
        )
        self.assertEqual(result["status"], "UNAVAILABLE")

    def test_fingerprint_keyed_snapshot_resolves(self) -> None:
        staged = Path(self.tmp.name) / "snapshots"
        staged.mkdir()
        shutil.copytree(self.root, staged / self.fingerprint)
        result = hist.read_historical_rules(
            {"tree_fingerprint": self.fingerprint},
            [RULE],
            snapshot_root=staged,
            registry=self.registry,
        )
        self.assertEqual(result["status"], "RESOLVED")
        self.assertEqual(result["source"], "CAPTURED_FINGERPRINT")
        self.assertEqual(result["identity"], self.fingerprint)
        rule = result["rules"][0]
        self.assertEqual(rule["rule_id"], RULE)
        self.assertEqual(rule["owner"], "saipal/COMMANDS.md")
        self.assertTrue(rule["text"].startswith(f"## {RULE}"))
        self.assertNotIn("\n## PAL-CMD-02", rule["text"])

    def test_mutated_snapshot_fails_the_fingerprint(self) -> None:
        """Red control: a snapshot whose bytes changed cannot claim the identity."""
        staged = Path(self.tmp.name) / "snapshots"
        staged.mkdir()
        shutil.copytree(self.root, staged / self.fingerprint)
        target = staged / self.fingerprint / "saipal" / "COMMANDS.md"
        target.write_text(target.read_text(encoding="utf-8") + "\ntampered\n", encoding="utf-8")
        result = hist.read_historical_rules(
            {"tree_fingerprint": self.fingerprint},
            [RULE],
            snapshot_root=staged,
            registry=self.registry,
        )
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertTrue(any("fingerprint mismatch" in a["reason"] for a in result["attempts"]))

    def test_release_root_requires_a_matching_registry_digest(self) -> None:
        releases = Path(self.tmp.name) / "releases"
        version = "7.238.1"
        shutil.copytree(self.root, releases / version)
        digest = hist.sha256_bytes(
            (releases / version / "saipal" / "REGISTRY.json").read_bytes()
        )
        good = hist.read_historical_rules(
            {"version": version, "registry_sha256": digest},
            [RULE],
            release_root=releases,
            registry=self.registry,
        )
        self.assertEqual(good["status"], "RESOLVED")
        self.assertEqual(good["source"], "RELEASE_REGISTRY")

        bad = hist.read_historical_rules(
            {"version": version, "registry_sha256": "b" * 64},
            [RULE],
            release_root=releases,
            registry=self.registry,
        )
        self.assertEqual(bad["status"], "UNAVAILABLE")
        self.assertTrue(any("digest mismatch" in a["reason"] for a in bad["attempts"]))


class AuthorityScoping(unittest.TestCase):
    """The transcript selects an identity, never a path."""

    def setUp(self) -> None:
        self.registry = load_registry()

    def test_unconfigured_authority_is_reported_not_guessed(self) -> None:
        result = hist.read_historical_rules(
            {"version": "7.0.0", "registry_sha256": "a" * 64},
            [RULE],
            registry=self.registry,
        )
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(
            [a["reason"] for a in result["attempts"]], ["authority not configured"]
        )

    def test_version_traversal_cannot_escape_the_release_root(self) -> None:
        """Red control: `../` in a version must not reach a sibling directory."""
        with tempfile.TemporaryDirectory() as td:
            releases = Path(td) / "releases"
            (releases / "real").mkdir(parents=True)
            result = hist.read_historical_rules(
                {"version": "../secret", "registry_sha256": "a" * 64},
                [RULE],
                release_root=releases,
                registry=self.registry,
            )
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertTrue(
            any("invalid release identity" in a["reason"] for a in result["attempts"])
        )

    def test_unsafe_owner_path_in_a_historical_registry_is_refused(self) -> None:
        """Red control: a historical registry claiming an escaping owner is refused."""
        with tempfile.TemporaryDirectory() as td:
            root = _authority_tree(Path(td) / "snap")
            registry_path = root / "saipal" / "REGISTRY.json"
            payload = json.loads(registry_path.read_text(encoding="utf-8-sig"))
            payload["rule_owners"][RULE] = "../../etc/passwd"
            registry_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ValueError):
                hist.protocol_tree_fingerprint(root, registry=self.registry)

    def test_invalid_rule_id_is_refused_before_any_read(self) -> None:
        with self.assertRaises(ValueError):
            hist.read_historical_rules({}, ["not-a-rule"], registry=self.registry)
        with self.assertRaises(ValueError):
            hist.read_historical_rules({}, [], registry=self.registry)

    def test_too_many_rule_ids_is_refused(self) -> None:
        limit = int(self.registry["historical_rule_limits"]["max_rule_ids"])
        ids = [f"PAL-CMD-{index:02d}" for index in range(limit + 2)]
        with self.assertRaises(ValueError):
            hist.read_historical_rules({}, ids, registry=self.registry)


@unittest.skipUnless(_git_available(), "git is unavailable")
class ExactCommitAuthority(unittest.TestCase):
    """An exact commit resolves only through a real Git authority."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = _authority_tree(Path(self.tmp.name) / "repo")
        self._git("init", "-q")
        self._git("config", "user.email", "pal@example.invalid")
        self._git("config", "user.name", "pal")
        # Git line-ending translation would rewrite the committed bytes, so the
        # blob digest would no longer match the file this test measured. That is
        # a property of the local git config, not of SAIPAL, so it is pinned off
        # here -- otherwise the test silently measures core.autocrlf instead.
        self._git("config", "core.autocrlf", "false")
        self._git("config", "core.eol", "lf")
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "protocol snapshot")
        self.head = self._git("rev-parse", "HEAD").strip().lower()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _git(self, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(self.repo), *args],
            capture_output=True, text=True, timeout=30, check=True,
        )
        return completed.stdout

    def test_exact_commit_resolves_the_rule_from_history(self) -> None:
        result = hist.read_historical_rules(
            {"git_head": self.head},
            [RULE],
            git_repository=self.repo,
            registry=self.registry,
        )
        self.assertEqual(result["status"], "RESOLVED")
        self.assertEqual(result["source"], "EXACT_COMMIT")
        self.assertEqual(result["identity"], self.head)
        self.assertTrue(result["rules"][0]["text"].startswith(f"## {RULE}"))

    def test_fake_commit_falls_through_and_never_claims_exact(self) -> None:
        """Red control: a well-shaped but absent commit resolves nothing exact."""
        result = hist.read_historical_rules(
            {"git_head": "a" * 40},
            [RULE],
            git_repository=self.repo,
            registry=self.registry,
        )
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(
            [a["source"] for a in result["attempts"]], ["EXACT_COMMIT"]
        )

    def test_conflicting_captured_registry_digest_rejects_the_commit(self) -> None:
        """A captured digest that disagrees with the commit is not silently ignored."""
        result = hist.read_historical_rules(
            {"git_head": self.head, "registry_sha256": "c" * 64},
            [RULE],
            git_repository=self.repo,
            registry=self.registry,
        )
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertTrue(
            any("conflicts with exact commit" in a["reason"] for a in result["attempts"])
        )

    def test_commit_authority_wins_over_a_weaker_release_root(self) -> None:
        releases = Path(self.tmp.name) / "releases"
        shutil.copytree(self.repo, releases / "7.0.0", ignore=shutil.ignore_patterns(".git"))
        digest = hist.sha256_bytes(
            (releases / "7.0.0" / "saipal" / "REGISTRY.json").read_bytes()
        )
        result = hist.read_historical_rules(
            {"git_head": self.head, "version": "7.0.0", "registry_sha256": digest},
            [RULE],
            git_repository=self.repo,
            release_root=releases,
            registry=self.registry,
        )
        self.assertEqual(result["source"], "EXACT_COMMIT")


class CompactSurface(unittest.TestCase):
    """What travels with a finding is identity plus digests, never rule text."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self.tmp = tempfile.TemporaryDirectory()
        root = _authority_tree(Path(self.tmp.name) / "tree")
        self.fingerprint = hist.protocol_tree_fingerprint(root, registry=self.registry)
        self.snapshots = Path(self.tmp.name) / "snapshots"
        self.snapshots.mkdir()
        shutil.copytree(root, self.snapshots / self.fingerprint)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_compact_surface_carries_digests_and_no_text(self) -> None:
        resolution = hist.read_historical_rules(
            {"tree_fingerprint": self.fingerprint},
            [RULE],
            snapshot_root=self.snapshots,
            registry=self.registry,
        )
        compact = hist.compact_rule_surface(resolution)
        self.assertEqual(compact["status"], "RESOLVED")
        self.assertEqual(compact["source"], "CAPTURED_FINGERPRINT")
        serialized = json.dumps(compact)
        self.assertNotIn("closed command surface", serialized)
        entry = compact["rules"][0]
        self.assertEqual(entry["rule_id"], RULE)
        self.assertEqual(len(entry["document_sha256"]), 64)
        self.assertEqual(len(entry["text_sha256"]), 64)
        self.assertGreater(entry["text_chars"], 0)

    def test_compact_surface_of_an_unavailable_resolution_keeps_the_reasons(self) -> None:
        resolution = hist.read_historical_rules(
            {"version": "9.9.9", "registry_sha256": "a" * 64},
            [RULE],
            registry=self.registry,
        )
        compact = hist.compact_rule_surface(resolution)
        self.assertEqual(compact["status"], "UNAVAILABLE")
        self.assertEqual(compact["rules"], [])
        self.assertTrue(compact["attempts"])


class ConfiguredAuthority(unittest.TestCase):
    """The operator declares authority roots; the runtime reads them from config."""

    def test_default_config_declares_every_authority_key_as_unset(self) -> None:
        authority = config_mod.default_config()["protocol_authority"]
        self.assertEqual(set(authority), set(config_mod.AUTHORITY_KEYS))
        self.assertTrue(all(value is None for value in authority.values()))

    def test_unknown_authority_key_is_a_validation_failure(self) -> None:
        payload = config_mod.default_config()
        payload["protocol_authority"]["elsewhere"] = "/tmp"
        problems = config_mod.validate_config(payload)
        self.assertTrue(any("unknown key" in problem for problem in problems))

    def test_setup_records_authority_and_doctor_reports_it(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = support.make_home(Path(td))
            releases = Path(td) / "releases"
            releases.mkdir()
            support.run_saipal("continue", home=home)
            code, payload, err = support.run_saipal_json(
                "setup", "--protocol-releases", str(releases), home=home
            )
            self.assertEqual(code, 0, err)
            self.assertEqual(
                payload["protocol_authority"], {"release_root": str(releases)}
            )
            code, doctor, err = support.run_saipal_json("doctor", home=home)
            self.assertEqual(code, 0, err)
            self.assertTrue(doctor["protocol_authority_configured"])
            self.assertEqual(
                doctor["protocol_authority"]["release_root"], str(releases)
            )
            self.assertIsNone(doctor["protocol_authority"]["git_repository"])

    def test_setup_refuses_an_absent_authority_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = support.make_home(Path(td))
            support.run_saipal("continue", home=home)
            missing = Path(td) / "nope"
            code, payload, _err = support.run_saipal_json(
                "setup", "--protocol-git", str(missing), home=home
            )
            self.assertEqual(code, 2)
            self.assertEqual(payload["code"], "USAGE")
            status, config, _detail = config_mod.load_config(home)
            self.assertEqual(status, "ok")
            self.assertIsNone((config["protocol_authority"] or {}).get("git_repository"))


class PipelineIntegration(unittest.TestCase):
    """The reader is wired into analysis, cached, and inert when unconfigured."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self.tmp = tempfile.TemporaryDirectory()
        root = _authority_tree(Path(self.tmp.name) / "tree")
        self.fingerprint = hist.protocol_tree_fingerprint(root, registry=self.registry)
        self.snapshots = Path(self.tmp.name) / "snapshots"
        self.snapshots.mkdir()
        shutil.copytree(root, self.snapshots / self.fingerprint)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_unconfigured_reader_is_not_configured_and_reads_nothing(self) -> None:
        reader = pipeline_mod.HistoricalRuleReader({}, registry=self.registry)
        self.assertFalse(reader.configured)

    def test_reader_resolves_and_caches_one_identity_per_rule_set(self) -> None:
        reader = pipeline_mod.HistoricalRuleReader(
            {"snapshot_root": self.snapshots}, registry=self.registry
        )
        self.assertTrue(reader.configured)
        protocol = {"tree_fingerprint": self.fingerprint}
        first = reader.read(protocol, [RULE])
        second = reader.read(protocol, [RULE])
        self.assertEqual(first["status"], "RESOLVED")
        self.assertIs(first, second)

    def test_reader_returns_none_for_an_empty_rule_set(self) -> None:
        reader = pipeline_mod.HistoricalRuleReader(
            {"snapshot_root": self.snapshots}, registry=self.registry
        )
        self.assertIsNone(reader.read({"tree_fingerprint": self.fingerprint}, []))

    def test_finding_shape_carries_the_compact_surface(self) -> None:
        reader = pipeline_mod.HistoricalRuleReader(
            {"snapshot_root": self.snapshots}, registry=self.registry
        )
        surface = reader.read({"tree_fingerprint": self.fingerprint}, [RULE])
        shaped = pipeline_mod._finding_shape(
            {
                "drift_class": "COMMAND_ROUTE_DRIFT",
                "rule_ids": [RULE],
                "mechanical_confidence": "HIGH",
            },
            {"session_id": "s1", "protocol": {"tree_fingerprint": self.fingerprint}},
            surface,
        )
        self.assertEqual(shaped["historical_rule_surface"]["status"], "RESOLVED")

    def test_audit_body_quotes_the_surface_by_identity_not_text(self) -> None:
        from saipal_engine import audits as audits_mod

        reader = pipeline_mod.HistoricalRuleReader(
            {"snapshot_root": self.snapshots}, registry=self.registry
        )
        surface = reader.read({"tree_fingerprint": self.fingerprint}, [RULE])
        finding = {
            "finding_id": "PAL-0001",
            "rule_ids": [RULE],
            "root_cause": "command routed outside the closed surface",
            "severity": "P1",
            "confidence": "HIGH",
            "change_target": "ENGINE",
            "drift_class": "COMMAND_ROUTE_DRIFT",
            "occurrences": [{"session_id": "s1", "episode_id": 0, "event_refs": [1]}],
            "protocol_bindings": [{"binding_status": "BOUND"}],
            "protected_invariants": ["verify"],
            "harm_warnings": [],
            "historical_rule_surface": surface,
        }
        body = audits_mod.build_audit_body(
            finding,
            {"session_id": "s1", "imported_at": "2026-01-01T00:00:00Z"},
            {"adapter": "generic", "project": {"name": "X"}, "protocol": {}},
            registry=self.registry,
        )
        self.assertIn("CAPTURED_FINGERPRINT", body)
        self.assertIn(self.fingerprint, body)
        self.assertNotIn("closed command surface", body)


if __name__ == "__main__":
    unittest.main()
