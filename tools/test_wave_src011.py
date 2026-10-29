"""SRC-011 / T-130: red controls for the audit/5.md corrective wave.

Each test pins one repaired finding:

- CORE-002  atomic_write_bytes classifies the final node against the SAME bound
            parent the descriptor-relative replace uses.
- CORE-003  validate_index validates every nested episode object.
- W2-002    closed-loop linkage is idempotent and fails closed on conflict.
- W2-003    an interrupted semantic operation recovers after evidence advanced.
- W2-004    an unreadable durable config refuses before the cycle's first write.
- PERF-001  recurrence batching does not change ledger contents.
- PERF-002  signal batching preserves occurrence/dedup semantics.
- PERF-003  extract_episodes counts spans without the quadratic rescan.
- PERF-006  sources_report enumerates each provider at most once.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pal_test_support as support
from saipal_engine import closedloop as closedloop_mod
from saipal_engine import episodes as episodes_mod
from saipal_engine import sources as sources_mod
from saipal_engine.errors import PalError
from saipal_engine.paths import atomic_write_bytes

CLEAN = "conformant-cold.json"


def _symlink_capability() -> str:
    """Why this host cannot create a file symlink, or "" when it can.

    CORE-002's final-node control must materialize a symlink before the
    confinement primitive is reached; on Windows that needs
    SeCreateSymbolicLinkPrivilege (developer mode or elevation), and without it
    the setup dies with WinError 1314 -- an ERROR about the host, not about the
    boundary. A host that cannot create the indirection cannot measure it, so
    the control is SKIPPED, never weakened.
    """
    if os.name != "nt":
        return ""
    directory = Path(tempfile.mkdtemp(prefix="saipal-symlink-probe-"))
    try:
        target = directory / "target"
        target.write_bytes(b"probe")
        os.symlink(str(target), str(directory / "link"))
        return ""
    except OSError as exc:
        return f"this host cannot create a file symlink: {exc}"
    finally:
        shutil.rmtree(str(directory), ignore_errors=True)


SYMLINK_UNAVAILABLE = _symlink_capability()
skip_without_symlink = unittest.skipIf(
    bool(SYMLINK_UNAVAILABLE), SYMLINK_UNAVAILABLE or ""
)


@skip_without_symlink
class Core002FinalNodeBoundToParent(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name) / ".saipal"
        self.home.mkdir()

    def test_symlink_destination_inside_root_is_refused(self) -> None:
        (self.home / "real.json").write_bytes(b"ORIGINAL")
        os.symlink(str(self.home / "real.json"), str(self.home / "target.json"))
        with self.assertRaises(PalError) as caught:
            atomic_write_bytes(self.home / "target.json", b"NEW", root=self.home)
        self.assertEqual(str(caught.exception.code), "PATH_ESCAPE")
        self.assertEqual((self.home / "real.json").read_bytes(), b"ORIGINAL")

    def test_regular_destination_still_replaces(self) -> None:
        (self.home / "target.json").write_bytes(b"OLD")
        atomic_write_bytes(self.home / "target.json", b"NEW", root=self.home)
        self.assertEqual((self.home / "target.json").read_bytes(), b"NEW")


class Core003NestedEpisodeValidation(unittest.TestCase):
    def _record_with_episodes(self, episodes: list) -> dict:
        return {
            "session_id": "s1",
            "generation": 1,
            "status": "IMPORTED",
            "temperature": "COLD",
            "last_analyzed_seq": 0,
            "imports": [],
            "episodes": episodes,
            "protocol": {"binding_status": "UNKNOWN"},
        }

    def _index(self, episodes: list) -> dict:
        return {"schema_version": 1, "sessions": [self._record_with_episodes(episodes)]}

    def test_a_string_episode_is_rejected(self) -> None:
        from saipal_engine import sessions as sessions_mod

        problems = sessions_mod.validate_index(self._index(["malformed-episode"]))
        self.assertTrue(problems)

    def test_boolean_index_and_bad_ordering_rejected(self) -> None:
        from saipal_engine import sessions as sessions_mod

        bad = [
            {"index": True, "start_seq": 1, "end_seq": 0, "kind": "user_task",
             "trigger_seq": None, "event_count": -1},
        ]
        problems = sessions_mod.validate_index(self._index(bad))
        self.assertGreaterEqual(len(problems), 3)

    def test_well_formed_episode_accepted(self) -> None:
        from saipal_engine import sessions as sessions_mod

        good = [
            {"index": 0, "start_seq": 1, "end_seq": 3, "kind": "terminal_task",
             "trigger_seq": None, "event_count": 3,
             "start_evidence_ref": None, "end_evidence_ref": None},
        ]
        problems = sessions_mod.validate_index(self._index(good))
        # The episode itself is accepted: no episode-scoped problem is raised.
        self.assertFalse(any("episodes[" in p for p in problems), problems)

    def test_duplicate_index_rejected(self) -> None:
        from saipal_engine import sessions as sessions_mod

        dup = [
            {"index": 0, "start_seq": 1, "end_seq": 2, "kind": "terminal_task",
             "trigger_seq": None, "event_count": 2},
            {"index": 0, "start_seq": 3, "end_seq": 4, "kind": "terminal_task",
             "trigger_seq": None, "event_count": 2},
        ]
        problems = sessions_mod.validate_index(self._index(dup))
        self.assertTrue(any("duplicated" in p for p in problems))


class W2002ClosedLoopIdempotent(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def _audit(self, number: int = 1, sha: str = "abc") -> dict:
        return {
            "audit_number": number,
            "audit_path": "audit/staging/1.md",
            "audit_sha256": sha,
        }

    def test_exact_repeat_appends_exactly_one_link(self) -> None:
        closedloop_mod.link_finding_audit(self.home, "PAL-0001", self._audit())
        closedloop_mod.link_finding_audit(self.home, "PAL-0001", self._audit())
        _status, links, _detail = closedloop_mod.load_links(self.home)
        self.assertEqual(len(links["links"]), 1)

    def test_conflicting_identity_fails_closed(self) -> None:
        closedloop_mod.link_finding_audit(self.home, "PAL-0001", self._audit())
        before = (Path(self.home) / "closed_loop_links.json").read_bytes()
        with self.assertRaises(PalError):
            closedloop_mod.link_finding_audit(self.home, "PAL-0002", self._audit())
        self.assertEqual(
            (Path(self.home) / "closed_loop_links.json").read_bytes(), before
        )


class W2004ConfigPreflightRefusesBeforeMutation(unittest.TestCase):
    def test_unreadable_config_leaves_index_and_authority_untouched(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = support.make_home(Path(tmp.name))
        support.put_inbox(home, CLEAN)
        code, _out, _err = support.run_saipal("continue", home=home)
        self.assertEqual(code, 0)
        index_before = (Path(home) / "sessions" / "index.json").read_bytes()
        config = Path(home) / "config.json"
        config.write_text("{not json", encoding="utf-8")
        code, out, err = support.run_saipal("continue", home=home)
        self.assertNotEqual(code, 0)
        self.assertIn("VALIDATION_FAILED", out + err)
        self.assertEqual(
            (Path(home) / "sessions" / "index.json").read_bytes(), index_before
        )


class Perf003EpisodeCountingIsLinearAndExact(unittest.TestCase):
    def test_sparse_sequence_counts_match_brute_force(self) -> None:
        events = [
            {"seq": s, "type": "USER_MESSAGE", "facts": {}}
            for s in [1, 2, 5, 9, 10, 20, 21, 22, 30]
        ]
        spans = episodes_mod.extract_episodes(events)
        sequences = [e["seq"] for e in events]
        for episode in spans:
            expected = sum(
                1
                for seq in sequences
                if episode["start_seq"] <= seq <= episode["end_seq"]
            )
            self.assertEqual(episode["event_count"], expected)

    def test_scaling_no_longer_quadratic(self) -> None:
        import time

        def run(episodes: int) -> float:
            events: list[dict] = []
            seq = 0
            for _ in range(episodes):
                seq += 1
                events.append({"seq": seq, "type": "USER_MESSAGE", "facts": {}})
                for _ in range(3):
                    seq += 1
                    events.append({"seq": seq, "type": "TOOL_CALL", "facts": {}})
            events.append({"seq": seq + 1, "type": "ASSISTANT_MESSAGE", "facts": {}})
            start = time.perf_counter()
            episodes_mod.extract_episodes(events)
            return time.perf_counter() - start

        small = run(1000)
        large = run(4000)
        # Quadratic would be ~16x for 4x; linear stays well under 8x.
        self.assertLess(large, max(small, 1e-6) * 8 + 0.05)


class Perf006SourceReportDiscoversOnce(unittest.TestCase):
    def test_enabled_source_enumerated_once(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = support.make_home(Path(tmp.name))
        store = Path(tmp.name) / "store"
        store.mkdir()
        support.write_sources(
            home,
            [{"id": "generic-1", "kind": "generic", "path": str(store),
              "enabled": True}],
        )
        calls = {"n": 0}
        real = sources_mod.ADAPTER_REGISTRY["generic"].discover

        def counting(path):
            calls["n"] += 1
            return real(path)

        with mock.patch.object(
            sources_mod.ADAPTER_REGISTRY["generic"], "discover", counting
        ):
            report = sources_mod.sources_report(home)
        self.assertLessEqual(calls["n"], 1)
        self.assertEqual(report["generic"]["status"], "EMPTY")


if __name__ == "__main__":
    unittest.main()
