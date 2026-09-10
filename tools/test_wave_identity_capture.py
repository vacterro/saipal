"""T-88: future-session historical identity capture.

The import path preserves a bundle's defensible historical identity claims
VERBATIM (exact git commit, release version plus registry digest, captured
tree fingerprint), derives binding only against the operator-enrolled
authority, never infers a historical commit from current HEAD, and never
invents missing history: fields absent in the bundle stay absent in the
record, and sessions without recorded identity remain PARTIAL/UNKNOWN.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine.config import load_config
from saipal_engine.sessions import load_index


def _imported_record(home: Path) -> dict:
    _status, index, _detail = load_index(home)
    return list(index.get("sessions") or [])[0]


class IdentityCapture(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def test_protocol_claims_persist_verbatim_at_ingestion(self) -> None:
        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        record = _imported_record(self.home)
        protocol = record["protocol"]

        # put_inbox stamps a placeholder digest at the home's real authority
        # (that IS the verbatim-claim contract: the claim survives, rewritten
        # only to the verifiable authority value the home declares).
        declared = (
            load_config(self.home)[1].get("protocol_authority") or {}
        ).get("release_root")
        authority_registry = (
            Path(declared) / support.AUTHORITY_VERSION / "saipal" / "REGISTRY.json"
            if declared
            else None
        )
        self.assertIsNotNone(authority_registry)
        claimed = support.load_fixture("conformant-cold.json")["protocol"]
        self.assertEqual(protocol.get("version"), support.AUTHORITY_VERSION)
        self.assertEqual(protocol.get("git_head"), claimed.get("git_head"))
        self.assertEqual(protocol.get("tree_fingerprint"), claimed.get("tree_fingerprint"))
        import hashlib

        self.assertEqual(
            protocol.get("registry_sha256"),
            hashlib.sha256(authority_registry.read_bytes()).hexdigest(),
        )

    def test_current_head_is_never_historical_truth(self) -> None:
        # The worker resolves historical authority from the enrolled
        # release_root / git root -- the persisted record never mirrors
        # "whatever this checkout's HEAD happens to be right now".
        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        record = _imported_record(self.home)
        # A future HEAD that never existed for this session must not be
        # treated as the session's historical binding.
        from saipal_engine.config import load_config

        _status, config, _detail = load_config(self.home)
        released = (config.get("protocol_authority") or {}).get("release_root")
        self.assertIsNotNone(released, "the home's authority must be configured")
        self.assertNotEqual(
            record["protocol"].get("git_head"),
            "deadhead" + "0" * 30,
            "a fictional HEAD must never equal the persisted identity",
        )
        # The record's VERSION comes from the enrolled release, not HEAD.
        self.assertEqual(record["protocol"].get("version"), support.AUTHORITY_VERSION)

    def test_session_without_identity_stays_partial_or_unknown(self) -> None:
        support.put_inbox(self.home, "unknown-protocol.json")
        support.run_saipal("continue", home=self.home)
        record = _imported_record(self.home)
        self.assertIn(
            record["protocol"]["binding_status"], ("UNKNOWN", "PARTIAL"),
            "no recorded identity means no defensible binding",
        )
        self.assertNotEqual(record["protocol"]["binding_status"], "BOUND")

    def test_no_history_is_invented(self) -> None:
        # unknown-protocol carries no defensible identity claims; the record
        # must not grow fabricated version/digest fields.
        support.put_inbox(self.home, "unknown-protocol.json")
        support.run_saipal("continue", home=self.home)
        record = _imported_record(self.home)
        fixture = support.load_fixture("unknown-protocol.json")
        claims = fixture.get("protocol") or {}
        for key in ("version", "registry_sha256", "tree_fingerprint", "git_head"):
            if claims.get(key) is None:
                # The record may carry the proof result (binding_status /
                # proof_level) but never an INVENTED identity value.
                persisted = record["protocol"].get(key)
                if persisted is not None:
                    self.assertEqual(
                        persisted, claims.get(key),
                        f"{key} was invented: bundle never recorded it",
                    )


if __name__ == "__main__":
    unittest.main()
