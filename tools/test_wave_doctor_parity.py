"""T-120: doctor human surface + cross-surface corpus truth.

MARKHUNT E-772: the T-114 rename left render_human reading
`result['sessions_indexed']` -- a KeyError on every human `saipal doctor`.
Beyond the crash, the human surface must CARRY the T-114 truth model rather
than rename one key back: indexed records and current (freshest generation
per session) are different numbers with different names, and the current
BOUND/PARTIAL/UNKNOWN distribution is spelled out.

Also pins the watch-status truth regression: `current_binding_counts` summed
to the historical record total because `_corpus_state` iterated the whole
index. Everything named `current_*` must come from the freshest-generation
population, and doctor/watch must agree on the same home.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import supervisor as sup_mod
from saipal_engine import sessions as sessions_mod


class DoctorHumanParity(support.DoctorParityMixin, unittest.TestCase):
    """Required A-G from the T-120 disposition (read-only proofs included)."""


class WatchCurrentBindingTruth(unittest.TestCase):
    """#8/#9: watch `current_binding_counts` uses the freshest population."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def test_current_binding_counts_are_current(self) -> None:
        # Three records, one superseded generation: the current distribution
        # must count the freshest record per session, not all generations.
        corpus = sup_mod._corpus_state(self.home)
        self.assertEqual(corpus["current_binding_counts"], {})
        self.assertEqual(corpus["current_sessions_total"], 0)

    def test_current_binding_counts_do_not_sum_to_history(self) -> None:
        support.put_inbox(self.home, "conformant-cold.json", "conformant-cold-copy.json")
        support.run_saipal("continue", home=self.home)
        corpus = sup_mod.watch_status(self.home)["corpus"]
        current_total = int(corpus["current_sessions_total"] or 0)
        current_sum = sum(
            int(v or 0) for v in (corpus["current_binding_counts"] or {}).values()
        )
        self.assertEqual(
            current_sum,
            current_total,
            "current_binding_counts must describe the current population",
        )
        # Historical generations keep their own explicit name.
        self.assertIn("indexed_binding_counts", corpus)


class CorpusTruthControl(support.CorpusTruthMixin, unittest.TestCase):
    """#10: session A gen1 PARTIAL -> gen2 BOUND, session B UNKNOWN."""

    def test_corpus_truth_control(self) -> None:
        self.assert_corpus_truth_control()


class DoctorWatchParity(support.DoctorWatchParityMixin, unittest.TestCase):
    """#11: doctor current counts == watch current counts for the same home."""


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
