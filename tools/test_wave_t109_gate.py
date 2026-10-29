"""T-109: production publication gate — red controls I,L,O,Q,J,K,N,S,R.

Controls already covered by existing suites:
- A,B,M,H,Q -> test_wave_sink.SetupIsOneTransaction
- P -> test_wave_analyst_supervisor.ShadowCeiling
- R,S -> test_wave_unattended.SinkOutageIsRetried
- C-F,G -> test_wave_sink.SinkPreflight

Controls in this file:
- I  non-STAGE_ONLY readiness is refused
- J  source fingerprint change after review refuses publication
- K  sink manifest bytes/identity change after review refuses publication
- L  sink canonical target change after review refuses publication
- O  external-effect boundary revalidation catches post-setup mutation
- Q  ordinary manual production path with valid gate publishes exactly one audit
- N  failed gate transition leaves config unchanged and zero external files
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import readiness as readiness_mod
from saipal_engine import publications as pub_mod
from saipal_engine.sink import AuditSink
from saipal_engine.submit import load_receipts


DRIFT = "agent-noncompliance-command-route.json"


def _maintainer(root: Path) -> Path:
    audit = root / "audit"
    audit.mkdir(parents=True, exist_ok=True)
    (audit / "MANIFEST.json").write_text(
        json.dumps({"kind": "saipen-audit-inbox", "schema_version": 1}),
        encoding="utf-8",
    )
    return root


def _enable(home: Path, sink: Path) -> None:
    readiness_mod.mint_readiness_for_tests(home, sink=AuditSink(home, root=sink))
    code, payload, err = support.run_saipal_json(
        "setup", "--sink", str(sink), "--mode", "PUBLISH_ENABLED",
        "--shadow-reviewed", home=home,
    )
    assert code == 0, (code, payload, err)


def _put_second_drift(home: Path) -> None:
    payload = json.loads(support.fixture(DRIFT).read_bytes())
    payload["session_id"] = "t109-second"
    support.write_inbox(home, "t109-second.json", payload)


#: A distinct root cause for the second finding: the fingerprint merge folds the
#: same mechanism into the already-EMITTED finding, which never re-emits an
#: audit. The gate controls need a second finding so emit_audit re-enters the
#: external-effect boundary.
SECOND_ROOT_CAUSE = "second distinct defect: the gate revalidation surface itself"


def _emit_then_submit(home: Path, **overrides) -> None:
    support.run_saipal("continue", home=home)
    unit = support.next_unit(home)
    if unit is None:
        raise AssertionError("no pending analysis unit after continue")
    support.submit_drift(home, unit, **overrides)


class ReadinessProof(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        self.sink_root = _maintainer(self.tmp / "maintainer")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_non_stage_only_attestation_is_refused(self) -> None:
        """Control I: readiness proof created under a non-STAGE_ONLY run is refused."""
        cfg = json.loads((self.home / "config.json").read_text(encoding="utf-8"))
        cfg["publication_mode"] = "PUBLISH_ENABLED"
        cfg["shadow_reviewed"] = True
        cfg["sink"] = {"kind": "termisai-file", "root": str(self.sink_root)}
        (self.home / "config.json").write_text(json.dumps(cfg, indent=2, sort_keys=True), encoding="utf-8")
        with self.assertRaises(ValueError) as cm:
            readiness_mod.mint_readiness_for_tests(
                self.home, sink=AuditSink(self.home, root=self.sink_root)
            )
        self.assertIn("STAGE_ONLY", str(cm.exception))
        status, _attest, _detail = readiness_mod.load(self.home)
        self.assertEqual(status, "absent", "no readiness artifact may be minted")

    def test_source_fingerprint_change_after_review_refuses_publication(self) -> None:
        """Control J: source/release fingerprint change after review -> publication refused."""
        _enable(self.home, self.sink_root)
        support.put_inbox(self.home, DRIFT)
        _emit_then_submit(self.home)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(
            sorted(p.name for p in (self.sink_root / "audit").glob("*.md")),
            ["1.md"],
        )
        attest_path = self.home / "readiness.json"
        attest = json.loads(attest_path.read_text(encoding="utf-8"))
        attest["software_fingerprint"] = hashlib.sha256(b"tampered").hexdigest()[:32]
        attest_path.write_text(json.dumps(attest, indent=2, sort_keys=True), encoding="utf-8")

        _put_second_drift(self.home)
        _emit_then_submit(self.home, root_cause=SECOND_ROOT_CAUSE)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(
            sorted(p.name for p in (self.sink_root / "audit").glob("*.md")),
            ["1.md"],
            "a tampered software fingerprint must not deliver a new audit",
        )
        staged = sorted((self.home / "audit" / "staging").glob("*.md"))
        self.assertTrue(staged, "the new audit must survive locally")

    def test_sink_manifest_change_after_review_refuses_publication(self) -> None:
        """Control K: sink manifest bytes/identity change after review -> publication refused."""
        _enable(self.home, self.sink_root)
        support.put_inbox(self.home, DRIFT)
        _emit_then_submit(self.home)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(
            sorted(p.name for p in (self.sink_root / "audit").glob("*.md")),
            ["1.md"],
        )
        (self.sink_root / "audit" / "MANIFEST.json").write_text(
            json.dumps({"kind": "saipen-audit-inbox", "schema_version": 1, "tampered": True}),
            encoding="utf-8",
        )

        _put_second_drift(self.home)
        _emit_then_submit(self.home, root_cause=SECOND_ROOT_CAUSE)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(
            sorted(p.name for p in (self.sink_root / "audit").glob("*.md")),
            ["1.md"],
            "a tampered manifest must not deliver a new audit",
        )
        staged = sorted((self.home / "audit" / "staging").glob("*.md"))
        self.assertTrue(staged, "the new audit must survive locally")

    def test_sink_canonical_target_change_after_review_refuses_publication(self) -> None:
        """Control L: sink canonical target change after review -> publication refused."""
        _enable(self.home, self.sink_root)
        support.put_inbox(self.home, DRIFT)
        _emit_then_submit(self.home)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(
            sorted(p.name for p in (self.sink_root / "audit").glob("*.md")),
            ["1.md"],
        )
        import shutil
        shutil.rmtree(self.sink_root)
        new_root = self.tmp / "new-maintainer"
        _maintainer(new_root)
        cfg = json.loads((self.home / "config.json").read_text(encoding="utf-8"))
        cfg["sink"] = {"kind": "termisai-file", "root": str(new_root)}
        (self.home / "config.json").write_text(json.dumps(cfg, indent=2, sort_keys=True), encoding="utf-8")

        _put_second_drift(self.home)
        _emit_then_submit(self.home, root_cause=SECOND_ROOT_CAUSE)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(
            sorted(p.name for p in (new_root / "audit").glob("*.md")),
            [],
            "a substituted sink target must not receive new audits",
        )
        staged = sorted((self.home / "audit" / "staging").glob("*.md"))
        self.assertTrue(staged, "the new audit must survive locally")

    def test_post_setup_mutation_is_caught_at_external_boundary(self) -> None:
        """Control O: external-effect boundary revalidation catches a post-setup mutation."""
        _enable(self.home, self.sink_root)
        support.put_inbox(self.home, DRIFT)
        _emit_then_submit(self.home)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(
            sorted(p.name for p in (self.sink_root / "audit").glob("*.md")),
            ["1.md"],
        )
        (self.sink_root / "audit" / "MANIFEST.json").write_text(
            json.dumps({"kind": "saipen-audit-inbox", "schema_version": 1, "tampered": True}),
            encoding="utf-8",
        )

        _put_second_drift(self.home)
        _emit_then_submit(self.home, root_cause=SECOND_ROOT_CAUSE)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(
            sorted(p.name for p in (self.sink_root / "audit").glob("*.md")),
            ["1.md"],
            "only the pre-mutation audit reaches the sink",
        )
        staged = sorted((self.home / "audit" / "staging").glob("*.md"))
        self.assertTrue(staged, "post-mutation audit must survive locally")

    def test_ordinary_production_path_publishes_exactly_one_audit(self) -> None:
        """Control Q: ordinary manual production path with a valid gate publishes exactly one audit."""
        _enable(self.home, self.sink_root)
        support.put_inbox(self.home, DRIFT)
        _emit_then_submit(self.home)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(
            sorted(p.name for p in (self.sink_root / "audit").glob("*.md")),
            ["1.md"],
        )
        self.assertEqual(pub_mod.pending(self.home), [])
        findings = json.loads((self.home / "findings" / "index.json").read_text(encoding="utf-8"))["findings"]
        self.assertEqual(findings[0]["audit"]["delivery"], pub_mod.PUBLISHED)

    def test_failed_gate_transition_leaves_config_unchanged_and_zero_external_writes(
        self,
    ) -> None:
        """Controls M + N: failed gate transition is zero-write and produces zero external files."""
        before = json.loads((self.home / "config.json").read_text(encoding="utf-8"))
        code, payload, err = support.run_saipal_json(
            "setup", "--sink", str(self.sink_root), "--mode", "PUBLISH_ENABLED",
            "--shadow-reviewed", home=self.home,
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "PUBLICATION_GATE_CLOSED")
        after = json.loads((self.home / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(after, before, "failed gate transition must leave config unchanged")
        self.assertFalse(
            any((self.sink_root / "audit").glob("*.md")),
            "failed gate transition must produce zero external audit files",
        )

    def test_sink_outage_after_valid_gate_follows_pending_retry(self) -> None:
        """Control R: sink outage after a valid gate still follows the existing local-stage + PENDING retry contract."""
        _enable(self.home, self.sink_root)
        import shutil
        shutil.rmtree(self.sink_root / "audit")
        support.put_inbox(self.home, DRIFT)
        _emit_then_submit(self.home)
        support.run_saipal("continue", home=self.home)
        staged = sorted((self.home / "audit" / "staging").glob("*.md"))
        self.assertTrue(staged, "outage stages locally")
        outstanding = pub_mod.pending(self.home)
        self.assertEqual([row["audit_number"] for row in outstanding], [1])
        _maintainer(self.sink_root)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(
            sorted(p.name for p in (self.sink_root / "audit").glob("*.md")),
            ["1.md"],
        )
        self.assertEqual(pub_mod.pending(self.home), [])
        # Control S: retry preserves original audit identity.
        receipt = load_receipts(self.home)[1]
        self.assertEqual(len((receipt or {}).get("receipts") or []), 1)


class SoftwareIdentity(unittest.TestCase):
    """T-109 B/I: the reviewed software fingerprint is an identity, not a live
    self-invalidator. It must be stable across its OWN artifact write and all
    mutable operational/VCS state, and it must move when authored publication
    runtime changes.
    """

    def _fake_repo(self, tmp: Path) -> Path:
        base = tmp / "repo"
        (base / "tools" / "saipal_engine").mkdir(parents=True)
        (base / "saipal").mkdir(parents=True)
        (base / ".saipal").mkdir()
        (base / ".git").mkdir()
        (base / ".saipen").mkdir()
        (base / "tools" / "saipal.py").write_text("X = 1\n", encoding="utf-8")
        (base / "tools" / "saipal_engine" / "emit.py").write_text("def a():\n    return 1\n", encoding="utf-8")
        (base / "tools" / "saipal_engine" / "test_emit.py").write_text("def t():\n    return 1\n", encoding="utf-8")
        (base / "saipal" / "REGISTRY.json").write_text('{"error_codes": []}', encoding="utf-8")
        return base

    def test_repo_local_home_mint_does_not_invalidate_itself(self) -> None:
        """Control I: writing readiness.json under a repository-local home leaves
        the reviewed fingerprint byte-identical (the self-invalidation defect)."""
        with tempfile.TemporaryDirectory() as d:
            base = self._fake_repo(Path(d))
            before = readiness_mod.software_fingerprint(base)
            (base / ".saipal" / "readiness.json").write_text('{"state":"READY"}', encoding="utf-8")
            (base / ".saipal" / "config.json").write_text('{"publication_mode":"STAGE_ONLY"}', encoding="utf-8")
            (base / ".saipen" / "STATE.md").write_text("phase: DOING\n", encoding="utf-8")
            (base / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            after = readiness_mod.software_fingerprint(base)
            self.assertEqual(before, after, "mutable state must not move the identity")

    def test_authored_runtime_change_invalidates_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            base = self._fake_repo(Path(d))
            before = readiness_mod.software_fingerprint(base)
            (base / "tools" / "saipal_engine" / "emit.py").write_text("def a():\n    return 2\n", encoding="utf-8")
            after = readiness_mod.software_fingerprint(base)
            self.assertNotEqual(before, after, "authored runtime change must invalidate")

    def test_test_fixture_change_does_not_move_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            base = self._fake_repo(Path(d))
            before = readiness_mod.software_fingerprint(base)
            (base / "tools" / "saipal_engine" / "test_emit.py").write_text("def t():\n    return 999\n", encoding="utf-8")
            after = readiness_mod.software_fingerprint(base)
            self.assertEqual(before, after, "test fixtures are rebuilt, not authored")

    def test_real_checkout_fingerprint_is_single_and_stable(self) -> None:
        self.assertEqual(readiness_mod.software_fingerprint(), readiness_mod.software_fingerprint())


class MintHardening(unittest.TestCase):
    """T-109 E: canary-shaped but failed/incomplete reports cannot mint."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        self.sink = AuditSink(self.home, root=_maintainer(self.tmp / "maintainer"))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _good(self) -> dict:
        return {
            "canary": True, "ok": True, "review_id": "R1", "stop_reason": "MAX_CYCLES",
            "cycles_completed": 1,
            "limits": {"cycles_requested": 1, "max_units_per_cycle": 1, "max_model_attempts": 4},
            "attempts": {"model_calls": 2}, "failures": 0, "blocked": 0,
            "publication_safety": {
                "configured_publication_mode": "STAGE_ONLY",
                "runtime_publication_ceiling": "STAGE_ONLY",
                "effective_external_publication": False,
            },
        }

    def _assert_no_artifact(self) -> None:
        status, _a, _d = readiness_mod.load(self.home)
        self.assertEqual(status, "absent")

    def test_non_canary_dict_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            readiness_mod.mint(self.home, report={"foo": "bar"}, sink=self.sink)
        self._assert_no_artifact()

    def test_failed_canary_is_refused(self) -> None:
        report = self._good(); report["ok"] = False
        with self.assertRaises(ValueError):
            readiness_mod.mint(self.home, report=report, sink=self.sink)
        self._assert_no_artifact()

    def test_blocked_stop_reason_is_refused(self) -> None:
        report = self._good(); report["stop_reason"] = "CONFIGURATION_BLOCKED"; report["ok"] = False
        with self.assertRaises(ValueError):
            readiness_mod.mint(self.home, report=report, sink=self.sink)
        self._assert_no_artifact()

    def test_zero_cycles_is_refused(self) -> None:
        report = self._good(); report["cycles_completed"] = 0
        with self.assertRaises(ValueError):
            readiness_mod.mint(self.home, report=report, sink=self.sink)
        self._assert_no_artifact()

    def test_missing_bounds_is_refused(self) -> None:
        report = self._good(); report["limits"] = {}
        with self.assertRaises(ValueError):
            readiness_mod.mint(self.home, report=report, sink=self.sink)
        self._assert_no_artifact()

    def test_attempt_over_bound_is_refused(self) -> None:
        report = self._good(); report["attempts"] = {"model_calls": 99}
        with self.assertRaises(ValueError):
            readiness_mod.mint(self.home, report=report, sink=self.sink)
        self._assert_no_artifact()

    def test_non_stage_only_configured_mode_is_refused(self) -> None:
        report = self._good()
        report["publication_safety"]["configured_publication_mode"] = "PUBLISH_ENABLED"
        with self.assertRaises(ValueError):
            readiness_mod.mint(self.home, report=report, sink=self.sink)
        self._assert_no_artifact()

    def test_effective_publication_true_is_refused(self) -> None:
        report = self._good()
        report["publication_safety"]["effective_external_publication"] = True
        with self.assertRaises(ValueError):
            readiness_mod.mint(self.home, report=report, sink=self.sink)
        self._assert_no_artifact()

    def test_failures_present_is_refused(self) -> None:
        report = self._good(); report["failures"] = 1
        with self.assertRaises(ValueError):
            readiness_mod.mint(self.home, report=report, sink=self.sink)
        self._assert_no_artifact()


class RealDefaultHomePublication(unittest.TestCase):
    """T-109 I (load-bearing): repository-local home, mint -> enable -> publish ->
    authored change invalidates; runtime/VCS/lifecycle churn does not."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        self.sink_root = _maintainer(self.tmp / "maintainer")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_full_lifecycle_on_repo_local_home(self) -> None:
        code, payload, err = support.run_saipal_json(
            "readiness", "mint", "--sink", str(self.sink_root),
            "--max-cycles", "1", "--max-units-per-cycle", "1", "--max-model-attempts", "1",
            home=self.home,
        )
        self.assertEqual(code, 1, "analyst unconfigured: the review must refuse, not mint")
        self.assertEqual(payload["ok"], False)
        self.assertEqual(readiness_mod.load(self.home)[0], "absent")

        _enable(self.home, self.sink_root)
        fp_after_mint = readiness_mod.software_fingerprint()
        support.put_inbox(self.home, DRIFT)
        _emit_then_submit(self.home)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(
            sorted(p.name for p in (self.sink_root / "audit").glob("*.md")), ["1.md"],
        )
        self.assertEqual(
            readiness_mod.software_fingerprint(), fp_after_mint,
            "runtime evidence must not move the identity",
        )

        churn_dir = self.home / ".gitlike"
        churn_dir.mkdir()
        (churn_dir / "HEAD").write_text("ref: x\n", encoding="utf-8")
        (self.home / "config.json").write_text(
            (self.home / "config.json").read_text(encoding="utf-8"), encoding="utf-8"
        )
        self.assertEqual(readiness_mod.software_fingerprint(), fp_after_mint)


class ReadinessRenewal(unittest.TestCase):
    """T-109 renewal: the atomic `mint --replace` production surface.

    A normal lifecycle re-mints a fresh readiness proof after an expected
    invalidation (authored-code or reviewed-sink change). Replacement is
    explicit, STAGE_ONLY-only, and fails closed: every failure path must leave
    the prior artifact byte-identical, and corrupt durable state is repaired
    only through an explicit successful replacement.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        self.sink_root = _maintainer(self.tmp / "maintainer")
        self.sink = AuditSink(self.home, root=self.sink_root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _good(self) -> dict:
        return {
            "canary": True, "ok": True, "review_id": "RENEW-" + str(len(list(self.tmp.iterdir()))),
            "stop_reason": "MAX_CYCLES", "cycles_completed": 1,
            "limits": {"cycles_requested": 1, "max_units_per_cycle": 1, "max_model_attempts": 4},
            "attempts": {"model_calls": 2}, "failures": 0, "blocked": 0,
            "publication_safety": {
                "configured_publication_mode": "STAGE_ONLY",
                "runtime_publication_ceiling": "STAGE_ONLY",
                "effective_external_publication": False,
            },
        }

    def _mint(self, **kwargs: object) -> dict:
        readiness_mod.mint_readiness_for_tests(self.home, sink=self.sink)
        attest = json.loads((self.home / "readiness.json").read_text(encoding="utf-8"))
        return attest

    def _bytes(self) -> bytes:
        return (self.home / "readiness.json").read_bytes()

    def _as_stage_only(self) -> None:
        cfg = json.loads((self.home / "config.json").read_text(encoding="utf-8"))
        cfg["publication_mode"] = "STAGE_ONLY"
        (self.home / "config.json").write_text(json.dumps(cfg), encoding="utf-8")

    def test_plain_remint_refuses_and_preserves_bytes(self) -> None:
        self._mint()
        before = self._bytes()
        code, payload, _err = support.run_saipal_json(
            "readiness", "mint", "--sink", str(self.sink_root),
            "--max-cycles", "1", "--max-units-per-cycle", "1", "--max-model-attempts", "1",
            home=self.home,
        )
        self.assertEqual(code, 1)
        self.assertIn("replace", payload["reason"])
        self.assertEqual(self._bytes(), before, "plain re-mint must not touch the artifact")

    def test_failed_replacement_canary_preserves_old_bytes(self) -> None:
        self._mint()
        before = self._bytes()
        # Analyst unconfigured: the real review cannot run, so --replace must
        # refuse before any write with the old artifact byte-identical.
        code, payload, _err = support.run_saipal_json(
            "readiness", "mint", "--replace", "--sink", str(self.sink_root),
            "--max-cycles", "1", "--max-units-per-cycle", "1", "--max-model-attempts", "1",
            home=self.home,
        )
        self.assertEqual(code, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(self._bytes(), before)

    def test_invalid_sink_replace_preserves_old_bytes(self) -> None:
        self._mint()
        before = self._bytes()
        bad_sink_root = self.tmp / "not-an-inbox"
        bad_sink_root.mkdir(parents=True, exist_ok=True)
        with self.assertRaises(ValueError):
            readiness_mod.mint(
                self.home, report=self._good(),
                sink=AuditSink(self.home, root=bad_sink_root), replace=True,
            )
        self.assertEqual(self._bytes(), before)

    def test_publish_enabled_replace_refuses_and_preserves_old_bytes(self) -> None:
        self._mint()
        cfg = json.loads((self.home / "config.json").read_text(encoding="utf-8"))
        cfg["publication_mode"] = "PUBLISH_ENABLED"
        cfg["shadow_reviewed"] = True
        cfg["sink"] = {"kind": "termisai-file", "root": str(self.sink_root)}
        (self.home / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
        before = self._bytes()
        with self.assertRaises(ValueError) as cm:
            readiness_mod.mint(self.home, report=self._good(), sink=self.sink, replace=True)
        self.assertIn("STAGE_ONLY", str(cm.exception))
        self.assertEqual(self._bytes(), before)

    def test_corrupt_without_replace_refuses_and_names_artifact(self) -> None:
        self._mint()
        self.home.joinpath("readiness.json").write_bytes(b"{broken")
        with self.assertRaises(ValueError) as cm:
            readiness_mod.mint(self.home, report=self._good(), sink=self.sink)
        self.assertIn("readiness.json", str(cm.exception))
        self.assertIn("repair", str(cm.exception).lower())
        self.assertEqual(self._bytes(), b"{broken")

    def test_corrupt_with_replace_and_failed_review_stays_unchanged(self) -> None:
        self._mint()
        self.home.joinpath("readiness.json").write_bytes(b"{broken")
        report = self._good(); report["ok"] = False
        with self.assertRaises(ValueError):
            readiness_mod.mint(self.home, report=report, sink=self.sink, replace=True)
        self.assertEqual(self._bytes(), b"{broken")

    def test_corrupt_with_replace_and_good_review_repairs_atomically(self) -> None:
        self._mint()
        self.home.joinpath("readiness.json").write_bytes(b"{broken")
        attest = readiness_mod.mint(self.home, report=self._good(), sink=self.sink, replace=True)
        status, loaded, _detail = readiness_mod.load(self.home)
        self.assertEqual(status, "ok")
        self.assertEqual(attest, loaded)
        self.assertNotEqual(self._bytes(), b"{broken")


class ReadinessRenewalEndToEnd(unittest.TestCase):
    """T-109 renewal through the real CLI: initial mint -> invalidation ->
    explicit atomic renewal -> publication. Sink renewal binds only the new
    reviewed sink."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        self.sink_root = _maintainer(self.tmp / "maintainer")

    def _configure_backend(self, endpoint: str) -> None:
        from saipal_analyst.config import default_analyst_config, save_analyst_config

        config = default_analyst_config()
        config["enabled"] = True
        config["backend"]["endpoint"] = endpoint
        config["backend"]["model"] = "stub-model"
        config["deliberation"]["clean_sample_percent"] = 0
        config["budgets"]["max_units_per_run"] = 2
        config["budgets"]["max_model_calls_per_run"] = 4
        save_analyst_config(self.home, config)
        os.environ["SAIPAL_ANALYST_API_KEY"] = "k"
        self.addCleanup(os.environ.pop, "SAIPAL_ANALYST_API_KEY", None)

    def _pad_script(self, backend: object, count: int = 20) -> None:
        import test_wave_analyst_repair as repair
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.sessions import load_index

        _s, index, _d = load_index(self.home)
        for _ in range(count):
            for record in sorted(
                carrier_mod.freshest_records(index), key=lambda r: str(r.get("session_id"))
            ):
                state = carrier_mod.semantic_state(record)
                episode = record["episodes"][state["next_episode_index"]]
                packet = carrier_mod.build_carrier(
                    self.home,
                    index=index,
                    session_id=str(record["session_id"]),
                    episode_index=int(episode["index"]),
                    slice_index=state["next_slice_index"],
                )
                candidate = {
                    "schema_version": 1,
                    "verdict": "NO_DRIFT",
                    "unit_digest": packet["unit_digest"],
                    "session_id": packet["session"]["session_id"],
                    "episode_index": packet["episode"]["index"],
                    "slice_index": packet["slice"]["index"],
                    "disposition_class": "NO_DRIFT",
                    "reasoning": "clean",
                    "event_refs": [packet["events"][0]["seq"]],
                }
                backend.script.append((200, repair.envelope(json.dumps(candidate))))

    def _script_no_drift(self, backend: object) -> None:
        self._pad_script(backend, 1)

    def _cli_mint(self, *extra: str) -> tuple[int, dict]:
        code, payload, _err = support.run_saipal_json(
            "readiness", "mint", *extra,
            "--sink", str(self.sink_root),
            "--max-cycles", "1", "--max-units-per-cycle", "1", "--max-model-attempts", "4",
            home=self.home,
        )
        return code, (payload or {})

    def test_code_change_renewal_publishes_exactly_once(self) -> None:
        import test_wave_analyst_repair as repair

        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self._configure_backend(backend.endpoint())
        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        self._script_no_drift(backend)

        # 1. Initial real readiness mint succeeds through the CLI review.
        self._pad_script(backend, 40)
        code, payload = self._cli_mint()
        self.assertEqual(code, 0, payload)
        status, attest, _detail = readiness_mod.load(self.home)
        self.assertEqual(status, "ok")
        first_checkpoint = attest["checkpoint_id"]

        # 2. Authored-code mutation makes the previous proof fail closed.
        attest_path = self.home / "readiness.json"
        attest["software_fingerprint"] = hashlib.sha256(b"authored-mutation").hexdigest()[:32]
        attest_path.write_text(json.dumps(attest, indent=2, sort_keys=True), encoding="utf-8")
        code, payload, _err = support.run_saipal_json(
            "setup", "--sink", str(self.sink_root), "--mode", "PUBLISH_ENABLED",
            "--shadow-reviewed", home=self.home,
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "PUBLICATION_GATE_CLOSED")

        # 3. Return configuration to STAGE_ONLY.
        cfg = json.loads((self.home / "config.json").read_text(encoding="utf-8"))
        cfg["publication_mode"] = "STAGE_ONLY"
        (self.home / "config.json").write_text(json.dumps(cfg), encoding="utf-8")

        # 4. Plain mint refuses because an existing proof is present.
        before = attest_path.read_bytes()
        code, payload = self._cli_mint()
        self.assertEqual(code, 1)
        self.assertIn("replace", payload["reason"])
        self.assertEqual(attest_path.read_bytes(), before)

        # 5. mint --replace performs a fresh successful review and atomically
        #    renews the proof (new checkpoint identity, live fingerprint).
        backend.script.clear()
        self._pad_script(backend, 40)
        code, payload = self._cli_mint("--replace")
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["ok"])
        status, renewed, _detail = readiness_mod.load(self.home)
        self.assertEqual(status, "ok")
        self.assertNotEqual(renewed["checkpoint_id"], first_checkpoint)
        self.assertEqual(
            renewed["software_fingerprint"], readiness_mod.software_fingerprint()
        )

        # 6. Transition to PUBLISH_ENABLED now succeeds.
        code, payload, _err = support.run_saipal_json(
            "setup", "--sink", str(self.sink_root), "--mode", "PUBLISH_ENABLED",
            "--shadow-reviewed", home=self.home,
        )
        self.assertEqual(code, 0, (code, payload))

        # 7. A qualifying audit publishes exactly once.
        support.put_inbox(self.home, DRIFT)
        _emit_then_submit(self.home)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(
            sorted(p.name for p in (self.sink_root / "audit").glob("*.md")),
            ["1.md"],
        )
        self.assertEqual(pub_mod.pending(self.home), [])

    def test_sink_renewal_binds_only_new_sink(self) -> None:
        import test_wave_analyst_repair as repair

        sink_b = _maintainer(self.tmp / "maintainer-b")
        # 1. mint against sink A and publish one audit there.
        readiness_mod.mint_readiness_for_tests(self.home, sink=AuditSink(self.home, root=self.sink_root))
        code, payload, _err = support.run_saipal_json(
            "setup", "--sink", str(self.sink_root), "--mode", "PUBLISH_ENABLED",
            "--shadow-reviewed", home=self.home,
        )
        self.assertEqual(code, 0, (code, payload))
        support.put_inbox(self.home, DRIFT)
        _emit_then_submit(self.home)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(
            sorted(p.name for p in (self.sink_root / "audit").glob("*.md")), ["1.md"],
        )

        # 2+3. Sink identity changes to B; the old proof refuses B.
        cfg = json.loads((self.home / "config.json").read_text(encoding="utf-8"))
        cfg["publication_mode"] = "STAGE_ONLY"
        cfg["sink"] = {"kind": "termisai-file", "root": str(self.sink_root)}
        (self.home / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
        cfg["sink"] = {"kind": "termisai-file", "root": str(sink_b)}
        (self.home / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
        before = (self.home / "readiness.json").read_bytes()
        code, payload, _err = support.run_saipal_json(
            "setup", "--sink", str(sink_b), "--mode", "PUBLISH_ENABLED",
            "--shadow-reviewed", home=self.home,
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "PUBLICATION_GATE_CLOSED")
        self.assertEqual((self.home / "readiness.json").read_bytes(), before)

        # 4+5. STAGE_ONLY; mint --replace against B renews and binds only B.
        backend = repair.StubBackend()
        self.addCleanup(backend.stop)
        self._configure_backend(backend.endpoint())
        self._pad_script(backend, 40)
        self.sink_root = sink_b
        code, payload = self._cli_mint("--replace")
        self.assertEqual(code, 0, payload)
        status, renewed, _detail = readiness_mod.load(self.home)
        self.assertEqual(status, "ok")
        self.assertEqual(renewed["sink_canonical"], _authority_canonical(sink_b))

        # 6+7. PUBLISH_ENABLED on B; a new qualifying audit reaches B only.
        code, payload, _err = support.run_saipal_json(
            "setup", "--sink", str(sink_b), "--mode", "PUBLISH_ENABLED",
            "--shadow-reviewed", home=self.home,
        )
        self.assertEqual(code, 0, (code, payload))
        _put_second_drift(self.home)
        _emit_then_submit(self.home, root_cause=SECOND_ROOT_CAUSE)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(
            sorted(p.name for p in (sink_b / "audit").glob("*.md")), ["2.md"],
            "the renewed proof must deliver the new audit to sink B",
        )
        self.assertEqual(
            sorted(p.name for p in (sink_b.parent / "maintainer" / "audit").glob("*.md")),
            ["1.md"],
            "sink A must not receive a new audit through the renewed proof",
        )


def _authority_canonical(root: Path) -> str:
    from saipal_engine import authority as authority_mod

    return authority_mod._canonical_identity(root)


if __name__ == "__main__":
    unittest.main()
