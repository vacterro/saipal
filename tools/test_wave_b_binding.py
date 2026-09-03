"""Wave B: protocol binding and the no-hindsight rule (PAL-SESSION-03).

A session governed by V1 cannot violate a rule that only exists in V2. That is
not a nuance, it is the whole difference between forensics and fortune telling.
"""

from __future__ import annotations

import unittest

import pal_test_support as support
from saipal_engine.sessions import binding_proof_of, binding_status_of, historical_applicability


COMMIT = "a" * 40
REGISTRY_DIGEST = "b" * 64
TREE_FINGERPRINT = "c" * 64


class BindingStatus(unittest.TestCase):
    def test_empty_protocol_is_unknown(self) -> None:
        self.assertEqual(binding_status_of({}), "UNKNOWN")
        self.assertEqual(binding_status_of(None), "UNKNOWN")

    def test_declared_status_cannot_self_promote(self) -> None:
        self.assertEqual(binding_status_of({"binding_status": "BOUND"}), "UNKNOWN")

    def test_abbreviated_commit_is_not_exact_proof(self) -> None:
        proof = binding_proof_of({"git_head": "deadbeef", "binding_status": "BOUND"})
        self.assertEqual(proof["proof_level"], "UNKNOWN")
        self.assertEqual(proof["binding_status"], "UNKNOWN")

    def test_plausible_but_fake_full_commit_is_rejected(self) -> None:
        proof = binding_proof_of(
            {"git_head": COMMIT, "binding_status": "BOUND"},
            commit_exists=lambda _head: False,
        )
        self.assertEqual(proof["proof_level"], "UNKNOWN")
        self.assertIn("not found", proof["reason"])

    def test_exact_commit_requires_authority_resolution(self) -> None:
        unresolved = binding_proof_of({"git_head": COMMIT})
        resolved = binding_proof_of({"git_head": COMMIT}, commit_exists=lambda head: head == COMMIT)
        self.assertEqual(unresolved["binding_status"], "UNKNOWN")
        self.assertEqual(resolved["binding_status"], "BOUND")
        self.assertEqual(resolved["proof_level"], "EXACT_COMMIT")

    def test_release_registry_without_authority_is_partial(self) -> None:
        """CORE-001 red control: syntactically valid release identity without
        authority must NOT produce BOUND -- the transcript cannot self-certify."""
        proof = binding_proof_of({"version": "7.231.9", "registry_sha256": REGISTRY_DIGEST})
        self.assertEqual(proof["binding_status"], "PARTIAL")
        self.assertEqual(proof["proof_level"], "RELEASE_REGISTRY")

    def test_captured_fingerprint_without_authority_is_partial(self) -> None:
        """CORE-001 red control: syntactically valid fingerprint without
        authority must NOT produce BOUND."""
        proof = binding_proof_of({"tree_fingerprint": TREE_FINGERPRINT})
        self.assertEqual(proof["binding_status"], "PARTIAL")
        self.assertEqual(proof["proof_level"], "CAPTURED_FINGERPRINT")

    def test_release_registry_pair_is_bound_with_authority(self) -> None:
        """CORE-001: verified release authority produces BOUND."""
        import tempfile
        from pathlib import Path
        from saipal_engine.historical import _registry_from_bytes
        from saipal_engine.registry import REGISTRY_KIND, SCHEMA_VERSION
        from saipal_engine.paths import sha256_bytes
        # Build a minimal release authority directory with correct registry.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reg = {"kind": REGISTRY_KIND, "schema_version": SCHEMA_VERSION, "rule_owners": {}}
            import json
            reg_bytes = json.dumps(reg, sort_keys=True).encode("utf-8")
            reg_digest = sha256_bytes(reg_bytes)
            # Write registry into version directory
            ver_dir = root / "7.231.9" / "saipal"
            ver_dir.mkdir(parents=True)
            (ver_dir / "REGISTRY.json").write_bytes(reg_bytes)
            proof = binding_proof_of(
                {"version": "7.231.9", "registry_sha256": reg_digest},
                authority={"release_root": str(root)},
            )
            self.assertEqual(proof["binding_status"], "BOUND")
            self.assertEqual(proof["proof_level"], "RELEASE_REGISTRY")

    def test_release_registry_digest_mismatch_is_partial(self) -> None:
        """CORE-001 red control: mismatched digest must not produce BOUND."""
        import tempfile
        from pathlib import Path
        from saipal_engine.registry import REGISTRY_KIND, SCHEMA_VERSION
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            import json
            reg = {"kind": REGISTRY_KIND, "schema_version": SCHEMA_VERSION, "rule_owners": {}}
            reg_bytes = json.dumps(reg, sort_keys=True).encode("utf-8")
            ver_dir = root / "7.231.9" / "saipal"
            ver_dir.mkdir(parents=True)
            (ver_dir / "REGISTRY.json").write_bytes(reg_bytes)
            proof = binding_proof_of(
                {"version": "7.231.9", "registry_sha256": "d" * 64},  # wrong digest
                authority={"release_root": str(root)},
            )
            self.assertEqual(proof["binding_status"], "PARTIAL")
            self.assertIn("mismatch", proof["reason"])

    def test_captured_tree_fingerprint_is_bound_with_authority(self) -> None:
        """CORE-001: verified snapshot authority produces BOUND."""
        import tempfile
        from pathlib import Path
        from saipal_engine.historical import protocol_tree_fingerprint
        from saipal_engine.registry import REGISTRY_KIND, SCHEMA_VERSION
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            import json
            reg = {"kind": REGISTRY_KIND, "schema_version": SCHEMA_VERSION, "rule_owners": {}}
            reg_bytes = json.dumps(reg, sort_keys=True).encode("utf-8")
            from saipal_engine.paths import sha256_bytes
            actual_fp = protocol_tree_fingerprint(root, reader=lambda rel: reg_bytes)
            # Write into the fingerprint-named directory
            fp_dir = root / actual_fp / "saipal"
            fp_dir.mkdir(parents=True)
            (fp_dir / "REGISTRY.json").write_bytes(reg_bytes)
            proof = binding_proof_of(
                {"tree_fingerprint": actual_fp},
                authority={"snapshot_root": str(root)},
            )
            self.assertEqual(proof["binding_status"], "BOUND")
            self.assertEqual(proof["proof_level"], "CAPTURED_FINGERPRINT")

    def test_version_alone_is_partial(self) -> None:
        self.assertEqual(binding_status_of({"version": "7.231.9"}), "PARTIAL")

    def test_nothing_usable_is_unknown(self) -> None:
        self.assertEqual(binding_status_of({"confidence": "HIGH"}), "UNKNOWN")

    def test_index_records_the_binding_of_every_fixture(self) -> None:
        """Without authority the strongest honest answer is PARTIAL, not BOUND.

        The fixtures carry a release identity, which is a *claim*. Proving it
        needs the operator's authority, so with none configured a claimed
        release is PARTIAL, a bare version is PARTIAL, and nothing usable is
        UNKNOWN. `put_inbox` supplies a real authority, which is where the same
        fixture becomes BOUND (see `test_wave_b_inbox`).
        """
        self.assertEqual(
            binding_status_of(support.load_fixture("conformant-cold.json")["protocol"]),
            "PARTIAL",
        )
        self.assertEqual(
            binding_status_of(support.load_fixture("old-session-v1.json")["protocol"]), "PARTIAL"
        )
        self.assertEqual(
            binding_status_of(support.load_fixture("unknown-protocol.json")["protocol"]), "UNKNOWN"
        )


class NoHindsight(unittest.TestCase):
    #: `binding_status` inside a protocol mapping is a claim and is never read as
    #: proof. A caller that already has a verified session record passes its
    #: status explicitly -- that is the `binding_status=` argument below.
    OLD = {"version": "1.0.0"}
    CURRENT = {
        "git_head": COMMIT,
        "version": "7.231.9",
        "registry_sha256": REGISTRY_DIGEST,
    }

    def test_unknown_binding_never_allows_a_violation_claim(self) -> None:
        result = historical_applicability({}, rule_introduced_in="1.0.0")
        self.assertFalse(result["violation_claimable"])
        self.assertIn("binding unknown", result["reason"])
        self.assertEqual(result["session_protocol_status"], "UNKNOWN")

    def test_rule_newer_than_the_governing_version_is_not_a_violation(self) -> None:
        result = historical_applicability(self.OLD, rule_introduced_in="2.0.0")
        self.assertFalse(result["violation_claimable"])
        self.assertIn("after the governing version", result["reason"])
        self.assertEqual(result["governing_version"], "1.0.0")

    def test_rule_older_than_the_governing_version_is_claimable(self) -> None:
        result = historical_applicability(self.OLD, rule_introduced_in="0.9.0")
        self.assertTrue(result["violation_claimable"])
        self.assertEqual(result["reason"], "")

    def test_same_version_rule_is_claimable(self) -> None:
        self.assertTrue(
            historical_applicability(self.OLD, rule_introduced_in="1.0.0")["violation_claimable"]
        )

    def test_bound_current_session_is_claimable(self) -> None:
        result = historical_applicability(
            self.CURRENT, rule_introduced_in="2.0.0", binding_status="BOUND"
        )
        self.assertTrue(result["violation_claimable"])
        self.assertEqual(result["session_protocol_status"], "BOUND")

    def test_a_claimed_binding_inside_the_protocol_is_ignored(self) -> None:
        """CORE-001 red control: the mapping cannot promote itself.

        Passing the same evidence with `binding_status: BOUND` written into it,
        and no verified status from the caller, must yield the derived PARTIAL.
        """
        forged = dict(self.CURRENT, binding_status="BOUND")
        result = historical_applicability(forged, rule_introduced_in="2.0.0")
        self.assertEqual(result["session_protocol_status"], "PARTIAL")

    def test_no_rule_version_means_no_hindsight_check(self) -> None:
        self.assertTrue(historical_applicability(self.OLD)["violation_claimable"])

    def test_red_control_numeric_not_lexicographic_versions(self) -> None:
        """7.9 is older than 7.10. A string compare gets this backwards."""
        old = {"version": "7.9.0"}
        self.assertFalse(
            historical_applicability(old, rule_introduced_in="7.10.0")["violation_claimable"]
        )
        self.assertTrue(
            historical_applicability(old, rule_introduced_in="7.8.0")["violation_claimable"]
        )


class CurrentProtection(unittest.TestCase):
    def test_unknown_without_fix_data(self) -> None:
        result = historical_applicability({"version": "1.0.0"})
        self.assertEqual(result["current_protocol_protection"], "UNKNOWN")

    def test_protected_when_the_fix_shipped(self) -> None:
        result = historical_applicability(
            {"version": "1.0.0"},
            fix_version="2.0.0",
            current_version="3.0.0",
        )
        self.assertEqual(result["current_protocol_protection"], "PROTECTED")

    def test_still_vulnerable_before_the_fix(self) -> None:
        result = historical_applicability(
            {"version": "1.0.0"},
            fix_version="2.5.0",
            current_version="2.0.0",
        )
        self.assertEqual(result["current_protocol_protection"], "STILL_VULNERABLE")

    def test_retrospective_field_is_separate_from_the_claim(self) -> None:
        """Hindsight is forbidden; the retrospective field is the legal outlet."""
        result = historical_applicability(
            {"version": "1.0.0"},
            rule_introduced_in="2.0.0",
            fix_version="2.0.0",
            current_version="3.0.0",
        )
        self.assertFalse(result["violation_claimable"])
        self.assertEqual(result["current_protocol_protection"], "PROTECTED")


if __name__ == "__main__":
    unittest.main()
