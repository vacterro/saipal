"""T-052: the maintainer home sink, end to end (PAL-AUDIT-02).

`PUBLISH_ENABLED` was unreachable. `setup` applied the mode, the sink root and the
authority as three separate config saves, so the mode was validated before the
sink root it requires existed — and nothing could set `shadow_reviewed` at all.
The safest possible failure, and completely silent: the operator configured a
sink, got no error worth noticing, and audits kept piling up in local staging.

Config is now one transaction, shadow review is an explicit flag, and publication
is proved by a real file arriving in a real maintainer inbox.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import config as config_mod
from saipal_engine.sink import configured_sink

DRIFT = "agent-noncompliance-command-route.json"


def _maintainer(root: Path) -> Path:
    audit = root / "audit"
    audit.mkdir(parents=True, exist_ok=True)
    (audit / "MANIFEST.json").write_text(
        json.dumps({"kind": "saipen-audit-inbox", "schema_version": 1}), encoding="utf-8"
    )
    return root


class SetupIsOneTransaction(unittest.TestCase):
    """Mode + sink in one command must succeed; a bad argument must change nothing."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        self.sink = _maintainer(self.tmp / "maintainer")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def config(self) -> dict:
        status, config, detail = config_mod.load_config(self.home)
        self.assertEqual(status, "ok", detail)
        return config

    def test_publish_enabled_is_reachable_in_one_command(self) -> None:
        """The regression this ticket exists for."""
        code, payload, err = support.run_saipal_json(
            "setup", "--sink", str(self.sink), "--mode", "PUBLISH_ENABLED",
            "--shadow-reviewed", home=self.home,
        )
        self.assertEqual(code, 0, err)
        config = self.config()
        self.assertEqual(config["publication_mode"], "PUBLISH_ENABLED")
        self.assertTrue(config["shadow_reviewed"])
        self.assertEqual(config["sink"]["root"], str(self.sink))

    def test_publish_enabled_without_shadow_review_is_refused(self) -> None:
        code, payload, _err = support.run_saipal_json(
            "setup", "--sink", str(self.sink), "--mode", "PUBLISH_ENABLED", home=self.home
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "VALIDATION_FAILED")
        self.assertIn("shadow_reviewed", payload["message"])

    def test_publish_enabled_without_a_sink_is_refused(self) -> None:
        code, payload, _err = support.run_saipal_json(
            "setup", "--mode", "PUBLISH_ENABLED", "--shadow-reviewed", home=self.home
        )
        self.assertEqual(code, 1)
        self.assertIn("sink.root", payload["message"])

    def test_a_refused_setup_leaves_the_old_config_untouched(self) -> None:
        before = self.config()
        support.run_saipal_json(
            "setup", "--mode", "PUBLISH_ENABLED", "--shadow-reviewed", home=self.home
        )
        self.assertEqual(self.config(), before, "a failed setup must not half-apply")

    def test_an_absent_sink_root_is_refused_before_anything_is_written(self) -> None:
        before = self.config()
        code, payload, _err = support.run_saipal_json(
            "setup", "--sink", str(self.tmp / "nope"), home=self.home
        )
        self.assertEqual(code, 2)
        self.assertEqual(payload["code"], "USAGE")
        self.assertEqual(self.config(), before)

    def test_shadow_review_can_be_withdrawn(self) -> None:
        support.run_saipal_json(
            "setup", "--sink", str(self.sink), "--mode", "PUBLISH_ENABLED",
            "--shadow-reviewed", home=self.home,
        )
        code, payload, _err = support.run_saipal_json(
            "setup", "--no-shadow-reviewed", home=self.home
        )
        # Withdrawing review while PUBLISH_ENABLED is live is refused: that pair
        # is exactly the state the flag exists to prevent.
        self.assertEqual(code, 1)
        self.assertTrue(self.config()["shadow_reviewed"])

    def test_stage_only_needs_no_shadow_review(self) -> None:
        code, _payload, err = support.run_saipal_json(
            "setup", "--mode", "STAGE_ONLY", home=self.home
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(self.config()["publication_mode"], "STAGE_ONLY")

    def test_setup_with_no_arguments_is_still_a_usage_error(self) -> None:
        code, payload, _err = support.run_saipal_json("setup", home=self.home)
        self.assertEqual(code, 2)
        self.assertEqual(payload["code"], "USAGE")

    def test_sink_and_authority_apply_together(self) -> None:
        releases = self.tmp / "releases"
        releases.mkdir()
        code, _payload, err = support.run_saipal_json(
            "setup", "--sink", str(self.sink), "--protocol-releases", str(releases),
            home=self.home,
        )
        self.assertEqual(code, 0, err)
        config = self.config()
        self.assertEqual(config["sink"]["root"], str(self.sink))
        self.assertEqual(config["protocol_authority"]["release_root"], str(releases))


class SinkPreflight(unittest.TestCase):
    """A sink is only usable when it is really an audit inbox."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_no_sink_configured_reports_absent(self) -> None:
        status, sink, detail = configured_sink(self.home)
        self.assertEqual(status, "absent")
        self.assertIsNone(sink)

    def test_a_directory_without_an_audit_inbox_is_invalid(self) -> None:
        bare = self.tmp / "bare"
        bare.mkdir()
        support.run_saipal_json("setup", "--sink", str(bare), home=self.home)
        status, sink, detail = configured_sink(self.home)
        self.assertEqual(status, "invalid")
        self.assertIn("audit directory", detail)

    def test_an_audit_inbox_without_a_manifest_is_invalid(self) -> None:
        root = self.tmp / "nomanifest"
        (root / "audit").mkdir(parents=True)
        support.run_saipal_json("setup", "--sink", str(root), home=self.home)
        status, _sink, detail = configured_sink(self.home)
        self.assertEqual(status, "invalid")
        self.assertIn("manifest", detail)

    def test_a_real_inbox_preflights_ok(self) -> None:
        sink_root = _maintainer(self.tmp / "maintainer")
        support.run_saipal_json("setup", "--sink", str(sink_root), home=self.home)
        status, sink, detail = configured_sink(self.home)
        self.assertEqual(status, "ok", detail)
        self.assertTrue(sink.preflight()["ok"])

    def test_doctor_reports_the_sink_state(self) -> None:
        sink_root = _maintainer(self.tmp / "maintainer")
        support.run_saipal_json("setup", "--sink", str(sink_root), home=self.home)
        code, payload, err = support.run_saipal_json("doctor", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["sink_status"], "ok")


class PublishEndToEnd(unittest.TestCase):
    """An audit reaches the maintainer inbox; the bookkeeping never does."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        self.sink = _maintainer(self.tmp / "maintainer")
        code, _payload, err = support.run_saipal_json(
            "setup", "--sink", str(self.sink), "--mode", "PUBLISH_ENABLED",
            "--shadow-reviewed", home=self.home,
        )
        self.assertEqual(code, 0, err)
        support.put_inbox(self.home, DRIFT)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def inbox_files(self) -> list[str]:
        return sorted(p.name for p in (self.sink / "audit").glob("*.md"))

    def test_a_qualified_audit_arrives_in_the_maintainer_inbox(self) -> None:
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["audits_emitted"], 1)
        self.assertEqual(self.inbox_files(), ["1.md"])

    def test_the_published_audit_is_attributable(self) -> None:
        support.run_saipal("continue", home=self.home)
        text = (self.sink / "audit" / "1.md").read_text(encoding="utf-8")
        self.assertIn("model=gpt-5", text)
        self.assertIn("saipal/COMMANDS.md", text)

    def test_private_bookkeeping_stays_inside_the_home(self) -> None:
        support.run_saipal("continue", home=self.home)
        self.assertTrue((self.home / "audit" / "ledger.json").is_file())
        self.assertTrue((self.home / "audit" / "entries.json").is_file())
        self.assertFalse((self.sink / "audit" / "ledger.json").exists())
        self.assertFalse((self.sink / "audit" / "entries.json").exists())

    def test_publication_is_exactly_once(self) -> None:
        support.run_saipal("continue", home=self.home)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(self.inbox_files(), ["1.md"], "one finding, one audit")

    def test_a_vanished_sink_stages_locally_and_logs_the_failure(self) -> None:
        """Red control: an unavailable sink is a retry, not a lost finding."""
        import shutil

        shutil.rmtree(self.sink / "audit")
        code, payload, err = support.run_saipal_json("continue", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["audits_emitted"], 1)
        staged = sorted((self.home / "audit" / "staging").glob("*.md"))
        self.assertTrue(staged, "the audit must survive locally")
        events = [
            json.loads(line)
            for line in (self.home / "LOG.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertTrue(any(e["event"] == "sink_publish_failure" for e in events))

    def test_stage_only_never_touches_the_sink(self) -> None:
        support.run_saipal_json("setup", "--mode", "STAGE_ONLY", home=self.home)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(self.inbox_files(), [])
        self.assertTrue(sorted((self.home / "audit" / "staging").glob("*.md")))

    def test_publish_blocked_never_touches_the_sink(self) -> None:
        support.run_saipal_json("setup", "--mode", "PUBLISH_BLOCKED", home=self.home)
        support.run_saipal("continue", home=self.home)
        self.assertEqual(self.inbox_files(), [])

    def test_the_receipt_chain_survives_publication(self) -> None:
        support.run_saipal("continue", home=self.home)
        links = json.loads(
            (self.home / "closed_loop_links.json").read_text(encoding="utf-8")
        )["links"]
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["audit_number"], 1)

    def test_a_maintainer_disposition_closes_the_loop(self) -> None:
        support.run_saipal("continue", home=self.home)
        path = self.tmp / "d.json"
        path.write_text(
            json.dumps({"dispositions": [{"audit_number": 1, "disposition": "ENGINE_FIX"}]}),
            encoding="utf-8",
        )
        code, payload, err = support.run_saipal_json("disposition", str(path), home=self.home)
        self.assertEqual(code, 0, err)
        links = json.loads(
            (self.home / "closed_loop_links.json").read_text(encoding="utf-8")
        )["links"]
        self.assertEqual(links[0]["disposition"], "ENGINE_FIX")
        self.assertIsNotNone(links[0]["closed_at"])


if __name__ == "__main__":
    unittest.main()
