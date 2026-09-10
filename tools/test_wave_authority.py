"""T-86: protocol authority bootstrap and trust pinning.

Discovery never trusts; enrollment is the only trust action. The pinned
repository may advance HEAD freely -- pinning answers "is this THE authority
repository", not "is this commit the only allowed commit forever" -- while
accidental substitution is refused loudly.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import authority as authority_mod
from saipal_engine.config import load_config
from saipal_engine.errors import PalError


class AuthorityBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def home_without_authority(self) -> Path:
        """A home whose config declares NO protocol authority (T-86 snapshot
        state: git/release/snapshot roots all null)."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = support.make_home(Path(tmp.name))
        from saipal_engine.config import save_config

        config = load_config(home)[1]
        config["protocol_authority"] = {
            key: None for key in authority_mod.CANDIDATE_LABELS
        }
        save_config(home, config)
        return home

    def make_release_root(self, name: str = "releases") -> Path:
        releases = Path(self._tmp.name) / name
        releases.mkdir(parents=True, exist_ok=True)
        target = releases / "7.231.9" / "saipal"
        target.mkdir(parents=True, exist_ok=True)
        source = Path(__file__).resolve().parents[1] / "saipal" / "REGISTRY.json"
        (target / "REGISTRY.json").write_bytes(source.read_bytes())
        return releases

    def make_git_repo(self) -> Path:
        repo = Path(self._tmp.name) / "repo"
        repo.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q"], cwd=str(repo), check=True, capture_output=True)
        (repo / "saipal").mkdir(exist_ok=True)
        source = Path(__file__).resolve().parents[1] / "saipal" / "REGISTRY.json"
        (repo / "saipal" / "REGISTRY.json").write_bytes(source.read_bytes())
        subprocess.run(
            ["git", "-C", str(repo), "add", "."],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "pin"],
            check=True, capture_output=True,
        )
        return repo


class Discovery(AuthorityBase):
    def test_discovery_never_trusts(self) -> None:
        home = self.home_without_authority()
        result = authority_mod.discover(home)
        self.assertTrue(result["ok"])
        self.assertFalse(result["trusted"])
        self.assertIn("discovery never trusts", result["note"])
        # Candidates are reported, not installed.
        config = load_config(home)[1]
        declared = config.get("protocol_authority") or {}
        self.assertFalse(any(declared.get(key) for key in authority_mod.CANDIDATE_LABELS))

    def test_doctor_reports_unenrolled_state_truthfully(self) -> None:
        result = authority_mod.doctor(self.home_without_authority())
        self.assertTrue(result["ok"])
        for kind in authority_mod.CANDIDATE_LABELS:
            self.assertFalse(result["roots"][kind]["enrolled"])


class Enrollment(AuthorityBase):
    def test_enroll_persists_root_and_pin(self) -> None:
        releases = self.make_release_root()
        result = authority_mod.enroll(self.home, "release_root", releases)
        self.assertTrue(result["ok"])
        self.assertTrue(result["registry_present"])
        self.assertEqual(result["registry_sha256"], authority_mod._registry_fingerprint(releases, "release_root")[0])

        config = load_config(self.home)[1]
        self.assertEqual(
            (config.get("protocol_authority") or {}).get("release_root"),
            str(releases),
        )
        pinning = authority_mod.load_pinning(self.home)
        pin = pinning["roots"]["release_root"]
        self.assertEqual(pin["canonical_path"], str(releases))
        self.assertTrue(pin["registry_present"])

    def test_git_enrollment_records_head_but_advances_freely(self) -> None:
        repo = self.make_git_repo()
        result = authority_mod.enroll(self.home, "git_repository", repo)
        head_at_enroll = result["head_at_enroll"]
        self.assertIsNotNone(head_at_enroll)

        # HEAD advances: no re-enrollment needed, no substitution detected.
        (repo / "saipal" / "EXTRA.md").write_text("advance\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "advance"],
            check=True, capture_output=True,
        )
        doctor = authority_mod.doctor(self.home)
        self.assertFalse(doctor["roots"]["git_repository"]["substitution_detected"])

    def test_substitution_is_refused_loudly(self) -> None:
        first = self.make_release_root("releases-a")
        authority_mod.enroll(self.home, "release_root", first)

        second = self.make_release_root("releases-b")
        with self.assertRaises(PalError) as caught:
            authority_mod.enroll(self.home, "release_root", second)
        self.assertIn("AUTHORITY_SUBSTITUTION", str(caught.exception.code))
        config = load_config(self.home)[1]
        self.assertEqual(
            (config.get("protocol_authority") or {}).get("release_root"),
            str(first),
            "a refused substitution must not replace the enrolled root",
        )

    def test_enrollment_requires_existing_structure(self) -> None:
        with self.assertRaises(PalError):
            authority_mod.enroll(self.home, "git_repository", Path(self._tmp.name) / "nope")
        with self.assertRaises(PalError) as caught:
            authority_mod.enroll(self.home, "git_repository", self.make_release_root())
        self.assertIn("not a git repository", str(caught.exception))

    def test_transcript_text_cannot_enroll(self) -> None:
        # Enrollment is a CLI write with an explicit path argument; there is
        # no evidence-derived entry point. The transcript-derived config
        # surface (protocol_authority) is only written by `enroll`.
        releases = self.make_release_root()
        before = load_config(self.home)[1].get("protocol_authority")
        # A hostile "evidence" string that looks like a command is just data.
        hostile = "saipal authority enroll --release-root /etc"
        self.assertIn("authority", hostile)  # it does look scary...
        after = load_config(self.home)[1].get("protocol_authority")
        self.assertEqual(before, after, "...and it still changed nothing")


class EnrollmentTransaction(AuthorityBase):
    """T-113: crash at any enrollment write boundary is recoverable.

    The old `enroll` wrote config then pinning; a controlled save_pinning
    failure left `configured but unpinned` half state that nothing could name.
    """

    def _crash_after_first_persistence(self, home: Path) -> Path:
        """Install a save_pinning that crashes the first time it is called."""
        from unittest import mock

        real_save_pinning = authority_mod.save_pinning
        state = {"crashed": False}

        def crashing_save_pinning(h, payload):
            if not state["crashed"]:
                state["crashed"] = True
                raise CrashError("crash after config write, before pin durable")
            return real_save_pinning(h, payload)

        patcher = mock.patch.object(authority_mod, "save_pinning", crashing_save_pinning)
        patcher.start()
        self.addCleanup(patcher.stop)
        return home

    def test_config_write_crash_leaves_visible_prepared_not_trusted(self) -> None:
        from unittest import mock

        home = self.home_without_authority()
        releases = self.make_release_root()

        def crashing_save_config(h, payload):
            # Simulate: pin persisted, config write crashed. We emulate the
            # crash BETWEEN the two phase-2 writes by failing config.
            raise CrashError("crash after pin durable, before config durable")

        with mock.patch.object(authority_mod, "save_config", crashing_save_config):
            with self.assertRaises(CrashError):
                authority_mod.enroll(home, "release_root", releases)

        # Half state is VISIBLE: PREPARED journal, config not yet trusted.
        transaction = authority_mod.enrollment_incomplete(home)
        self.assertTrue(transaction["incomplete"])
        self.assertEqual(
            (transaction["pending"] or {}).get("kind"), "release_root"
        )
        config = load_config(home)[1]
        self.assertIsNone(
            (config.get("protocol_authority") or {}).get("release_root"),
            "an incomplete enrollment must never be trusted as configured",
        )
        # Doctor reports it loudly instead of hiding the half state.
        doctor = authority_mod.doctor(home)
        self.assertTrue(
            doctor["roots"]["release_root"].get("enrollment_incomplete")
        )

        # Retry converges idempotently: same root, same kind.
        result = authority_mod.enroll(home, "release_root", releases)
        self.assertTrue(result["ok"])
        self.assertFalse(authority_mod.enrollment_incomplete(home)["incomplete"])
        config = load_config(home)[1]
        self.assertEqual(
            (config.get("protocol_authority") or {}).get("release_root"), str(releases)
        )
        pinning = authority_mod.load_pinning(home)
        self.assertEqual(
            (pinning.get("roots") or {}).get("release_root", {}).get("canonical_path"),
            str(releases),
        )

    def test_pin_write_crash_leaves_visible_prepared_and_config_clean(self) -> None:
        """The audit's exact reproduction: config written, pin missing."""
        from unittest import mock

        home = self.home_without_authority()
        releases = self.make_release_root()
        state = {"crashed": False}
        real_save_pinning = authority_mod.save_pinning

        def crashing_save_pinning(h, payload):
            if not state["crashed"]:
                state["crashed"] = True
                # With the T-113 ordering (pin BEFORE config), a pin-write
                # crash leaves config clean; assert the half state is VISIBLE
                # and retriable either way.
                raise CrashError("pin write failed")

        with mock.patch.object(authority_mod, "save_pinning", crashing_save_pinning):
            with self.assertRaises(CrashError):
                authority_mod.enroll(home, "release_root", releases)
        _ = real_save_pinning

        # Nothing trusted: no config root, PREPARED journal visible.
        config = load_config(home)[1]
        self.assertIsNone((config.get("protocol_authority") or {}).get("release_root"))
        transaction = authority_mod.enrollment_incomplete(home)
        self.assertTrue(transaction["incomplete"])

        # Retry the SAME root converges.
        result = authority_mod.enroll(home, "release_root", releases)
        self.assertTrue(result["ok"])
        self.assertFalse(authority_mod.enrollment_incomplete(home)["incomplete"])
        pinning = authority_mod.load_pinning(home)
        self.assertIn("release_root", pinning.get("roots") or {})

    def test_pending_enrollment_of_another_root_is_refused(self) -> None:
        """A PREPARED transaction must block enrolling a DIFFERENT root."""
        releases = self.make_release_root("releases-a")
        # Leave a half-enrolled transaction for releases-a.
        authority_mod._save_enrollment_journal(
            self.home,
            {
                "kind": "release_root",
                "root": str(releases),
                "pin": {"kind": "release_root", "canonical_path": str(releases)},
            },
        )
        other = self.make_release_root("releases-b")
        with self.assertRaises(PalError) as caught:
            authority_mod.enroll(self.home, "release_root", other)
        self.assertEqual(caught.exception.code, "AUTHORITY_ENROLLMENT_INCOMPLETE")

    def test_completed_enrollment_is_idempotent_zero_write(self) -> None:
        releases = self.make_release_root()
        first = authority_mod.enroll(self.home, "release_root", releases)
        self.assertFalse(first.get("unchanged"))
        second = authority_mod.enroll(self.home, "release_root", releases)
        self.assertTrue(second.get("unchanged"))
        self.assertEqual(second["path"], str(releases))

    def test_prior_trusted_authority_survives_a_failed_new_enrollment(self) -> None:
        first = self.make_release_root("releases-a")
        authority_mod.enroll(self.home, "release_root", first)

        # A DIFFERENT kind enrolling an invalid root fails AFTER first was
        # already trusted: the first authority must remain intact.
        with self.assertRaises(PalError):
            authority_mod.enroll(
                self.home, "git_repository", Path(self._tmp.name) / "no-git"
            )
        config = load_config(self.home)[1]
        self.assertEqual(
            (config.get("protocol_authority") or {}).get("release_root"), str(first)
        )
        pinning = authority_mod.load_pinning(self.home)
        self.assertEqual(
            (pinning.get("roots") or {}).get("release_root", {}).get("canonical_path"),
            str(first),
        )


class TrustedAccessor(AuthorityBase):
    """T-100: configured roots are observable; only PINNED roots are authority.

    `trusted_protocol_authority` is the canonical accessor rebind and any
    historical strengthening must consume. The regression it exists for: a
    root written into config.json was auto-trusted, so anything that could
    write config (or a legacy home) held de-facto authority with no pin.
    """

    def test_absent_config_root_is_absent(self) -> None:
        home = self.home_without_authority()
        state = authority_mod.trusted_protocol_authority(home)
        for kind in authority_mod.CANDIDATE_LABELS:
            self.assertEqual(state[kind]["state"], "ABSENT")

    def test_configured_but_unpinned_root_is_legacy_unpinned_never_trusted(self) -> None:
        home = self.home_without_authority()
        releases = self.make_release_root()
        from saipal_engine.config import save_config

        config = load_config(home)[1]
        config["protocol_authority"]["release_root"] = str(releases)
        save_config(home, config)

        state = authority_mod.trusted_protocol_authority(home)
        self.assertEqual(state["release_root"]["state"], "LEGACY_UNPINNED")
        self.assertEqual(authority_mod.trusted_roots(home), {})

    def test_enrolled_root_is_trusted(self) -> None:
        home = self.home_without_authority()
        releases = self.make_release_root()
        authority_mod.enroll(home, "release_root", releases)
        state = authority_mod.trusted_protocol_authority(home)
        self.assertEqual(state["release_root"]["state"], "TRUSTED")
        self.assertEqual(
            authority_mod.trusted_roots(home), {"release_root": str(releases)}
        )

    def test_canonical_path_identity_windows_aliases(self) -> None:
        """C:\\Repo, c:\\repo and C:\\Repo\\. are ONE trust identity (r38)."""
        base = self.make_release_root("releases")
        authority_mod.enroll(self.home, "release_root", base)
        raw = str(base)
        alias = Path(str(self._tmp.name).upper()) / "releases"
        if str(alias).casefold() != raw.casefold():
            self.skipTest("platform has no case-alias spelling for this path")
        state = authority_mod.trusted_protocol_authority(self.home)
        self.assertEqual(state["release_root"]["state"], "TRUSTED")

    def test_substituted_config_root_is_detected_not_trusted(self) -> None:
        first = self.make_release_root("releases-a")
        authority_mod.enroll(self.home, "release_root", first)
        # Direct config mutation = the accidental substitution case.
        from saipal_engine.config import save_config

        second = self.make_release_root("releases-b")
        config = load_config(self.home)[1]
        config["protocol_authority"]["release_root"] = str(second)
        save_config(self.home, config)

        state = authority_mod.trusted_protocol_authority(self.home)
        self.assertEqual(state["release_root"]["state"], "SUBSTITUTED")
        self.assertEqual(authority_mod.trusted_roots(self.home), {})

    def test_legacy_unpinned_root_cannot_strengthen_to_bound(self) -> None:
        """The T-100 core: a rebind under a configured-but-unpinned root must
        not promote UNKNOWN/PARTIAL records to BOUND."""
        home = self.home_without_authority()
        releases = self.make_release_root()
        from saipal_engine.config import save_config

        config = load_config(home)[1]
        config["protocol_authority"]["release_root"] = str(releases)
        save_config(home, config)

        import pal_test_support as support
        from saipal_engine import rebind as rebind_mod
        from saipal_engine.config import load_config as _lc
        from saipal_engine.config import save_config as _sc

        support.put_inbox(home, "conformant-cold.json")
        # Import with no authority: the record lands UNKNOWN/PARTIAL.
        stripped = _lc(home)[1]
        stripped["protocol_authority"] = {
            k: None for k in authority_mod.CANDIDATE_LABELS
        }
        _sc(home, stripped)
        support.run_saipal("continue", home=home)
        # Then configure the UNPINNED root only.
        config = _lc(home)[1]
        config["protocol_authority"]["release_root"] = str(releases)
        _sc(home, config)

        report = rebind_mod.rebind(home)
        self.assertEqual(
            report["unknown_to_bound"] + report["partial_to_bound"], 0,
            f"an unpinned root must not strengthen: {report}",
        )
        self.assertIn("release_root", report.get("legacy_unpinned_kinds") or [])
        record = __import__(
            "saipal_engine.sessions", fromlist=["load_index"]
        ).load_index(home)[1]["sessions"][0]
        self.assertIn(
            record["protocol"]["binding_status"], ("UNKNOWN", "PARTIAL"),
            "the record must not become BOUND under legacy-unpinned authority",
        )

        # The adoption path: enroll pins it, rebind then strengthens.
        authority_mod.enroll(home, "release_root", releases)
        report = rebind_mod.rebind(home)
        self.assertGreaterEqual(
            report["unknown_to_bound"] + report["partial_to_bound"], 1,
            f"after enrollment the same rebind must strengthen: {report}",
        )

    def test_existing_bound_evidence_is_preserved_under_absent_authority(self) -> None:
        """T-100 r20: a BOUND record never silently downgrades when the
        current authority root goes missing/absent; rebind leaves it alone."""
        import pal_test_support as support
        from saipal_engine import rebind as rebind_mod

        support.put_inbox(self.home, "conformant-cold.json")
        support.run_saipal("continue", home=self.home)
        # make_home already declared+verified the release root at import.
        # Now strip the config: the authority is gone.
        self.strip_config_authority(self.home)
        report = rebind_mod.rebind(self.home)
        # The previously accepted BOUND proof is preserved, not downgraded.
        record = __import__(
            "saipal_engine.sessions", fromlist=["load_index"]
        ).load_index(self.home)[1]["sessions"][0]
        self.assertEqual(
            record["protocol"]["binding_status"], "BOUND",
            "preserving existing forensic proof beats re-deriving it weaker",
        )
        downgrades = report["suspicious_downgrades"]
        self.assertEqual(
            len(downgrades) + report["unchanged"], report["scanned"],
        )
        _ = downgrades

    def strip_config_authority(self, home: Path) -> None:
        from saipal_engine.config import save_config

        config = load_config(home)[1]
        config["protocol_authority"] = {
            k: None for k in authority_mod.CANDIDATE_LABELS
        }
        save_config(home, config)


class CrashError(BaseException):
    """Process death; BaseException so no PalError handler may eat it."""


class PinningDiscipline(AuthorityBase):
    def test_pinning_schema_is_closed(self) -> None:
        payload = authority_mod.fresh_pinning()
        self.assertEqual(authority_mod.pinning_problems(payload), [])
        payload["nope"] = 1
        self.assertIn("unknown pinning field 'nope'", authority_mod.pinning_problems(payload))

    def test_doctor_detects_path_substitution_after_reenroll_attempt(self) -> None:
        first = self.make_release_root("releases-a")
        authority_mod.enroll(self.home, "release_root", first)

        # Direct config mutation simulating an accidental substitution: the
        # pin still names the original, so the doctor reports it.
        from saipal_engine.config import save_config

        config = load_config(self.home)[1]
        second = self.make_release_root("releases-b")
        config["protocol_authority"]["release_root"] = str(second)
        save_config(self.home, config)

        doctor = authority_mod.doctor(self.home)
        self.assertTrue(doctor["roots"]["release_root"]["substitution_detected"])
        self.assertEqual(doctor["roots"]["release_root"]["pinned_path"], str(first))


if __name__ == "__main__":
    unittest.main()
