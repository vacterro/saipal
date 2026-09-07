"""T-040: the analysis carrier -- what `next` actually hands the analyst.

Before this, `next` named a carrier and the analyst had to rediscover the work.
The carrier is now the whole bounded unit: session identity, one semantic
episode, its events, evidence locators, historical binding and rule surface,
mechanical signals, recurrence and prior maintainer calibration.

Two invariants carry the weight: the carrier is READ-ONLY (so an agent may poll
it), and the SEMANTIC position is separate from the mechanical one (so finishing
`continue` does not silently declare the analyst done).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import carrier as carrier_mod
from saipal_engine import sessions as sessions_mod
from saipal_engine.registry import load_registry, require_string_list

DRIFT = "agent-noncompliance-command-route.json"
CONFLICT_BASE = "hot-partial.json"
CONFLICT_MUTATED = "hot-prefix-mutated.json"


class CarrierShape(unittest.TestCase):
    """The carrier is the declared shape, and nothing outside it."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_carrier_validates_against_the_registry_shape(self) -> None:
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertEqual(carrier_mod.carrier_problems(unit, registry=self.registry), [])

    def test_carrier_names_every_analysis_input_the_contract_promises(self) -> None:
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        for field in (
            "session", "episode", "events", "evidence_refs", "protocol",
            "applicable_law", "historical_rule_surface", "signals",
            "recurrence", "calibration", "open_candidates",
        ):
            self.assertIn(field, unit, f"carrier must carry {field}")
        self.assertEqual(unit["session"]["session_id"], "golden-agent-noncompliance-001")
        self.assertIn("provider", unit["session"]["runtime"])
        self.assertEqual(unit["protocol"]["binding_status"], "BOUND")
        self.assertEqual(unit["applicable_law"]["status"], "RESOLVED")
        self.assertTrue(unit["applicable_law"]["rule_ids"])

    def test_carrier_events_are_scoped_to_the_episode(self) -> None:
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        start = unit["episode"]["start_seq"]
        end = unit["episode"]["end_seq"]
        self.assertTrue(unit["events"])
        for event in unit["events"]:
            self.assertGreaterEqual(event["seq"], start)
            self.assertLessEqual(event["seq"], end)

    def test_carrier_never_carries_raw_transcript_keys(self) -> None:
        """Red control: PAL-SESSION-01's forbidden keys must not reach Layer B."""
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        forbidden = set(require_string_list(self.registry, "forbidden_event_keys"))
        for event in unit["events"]:
            self.assertFalse(forbidden & set(event), f"raw content key in {event}")

    def test_carrier_problems_rejects_a_forbidden_key(self) -> None:
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        unit["events"][0]["transcript"] = "the whole conversation"
        problems = carrier_mod.carrier_problems(unit, registry=self.registry)
        self.assertTrue(any("forbidden raw key" in problem for problem in problems))

    def test_carrier_problems_rejects_an_unknown_field(self) -> None:
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        unit["free_text_advice"] = "trust me"
        problems = carrier_mod.carrier_problems(unit, registry=self.registry)
        self.assertTrue(any("unknown carrier field" in problem for problem in problems))

    def test_carrier_problems_rejects_a_wrong_schema_version(self) -> None:
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        unit["schema_version"] = 99
        problems = carrier_mod.carrier_problems(unit, registry=self.registry)
        self.assertTrue(any("schema_version" in problem for problem in problems))

    def test_carrier_problems_rejects_an_unknown_carrier_kind(self) -> None:
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        unit["carrier"] = "vibes"
        problems = carrier_mod.carrier_problems(unit, registry=self.registry)
        self.assertTrue(any("outside" in problem for problem in problems))

    def test_events_are_bounded_by_the_registry_limit(self) -> None:
        limit = int(self.registry["carrier_limits"]["max_events"])
        home = support.make_home(self.tmp, ".saipal-big")
        support.run_saipal("continue", home=home)
        big = {
            "schema_version": 1,
            "session_id": "carrier-big-001",
            "adapter": "generic",
            "project": {"name": "X"},
            "runtime": {"provider": "p", "model": "m"},
            "temperature": "COLD",
            "protocol": {"version": "7.231.9", "registry_sha256": "a" * 64},
            "events": [
                {"seq": index, "type": "TOOL_CALL", "facts": {"tool": "bash"}}
                for index in range(1, limit + 50)
            ],
        }
        support.write_inbox(home, "carrier-big.json", big)
        support.run_saipal("continue", home=home)
        unit = carrier_mod.build_carrier(home, registry=self.registry)
        self.assertEqual(unit["session"]["session_id"], "carrier-big-001")
        self.assertEqual(len(unit["events"]), limit)
        self.assertTrue(unit["episode"]["events_truncated"])


class ReadOnly(unittest.TestCase):
    """Building a carrier writes nothing -- an agent may poll it freely."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_build_carrier_changes_no_byte_in_the_home(self) -> None:
        before = support.tree_digest(self.home)
        carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertEqual(support.tree_digest(self.home), before)

    def test_next_command_changes_no_byte_in_the_home(self) -> None:
        before = support.tree_digest(self.home)
        code, payload, err = support.run_saipal_json("next", home=self.home)
        self.assertEqual(code, 0, err)
        self.assertEqual(support.tree_digest(self.home), before)
        self.assertIn("analysis_carrier", payload)

    def test_repeated_next_returns_the_same_unit(self) -> None:
        """No hidden advance: `next` is a question, not a claim."""
        _code, first, _err = support.run_saipal_json("next", home=self.home)
        _code, second, _err = support.run_saipal_json("next", home=self.home)
        self.assertEqual(
            first["analysis_carrier"]["episode"], second["analysis_carrier"]["episode"]
        )


class SemanticPosition(unittest.TestCase):
    """Semantic analysis has its own watermark, separate from the mechanical one."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _record(self) -> dict:
        return support.sessions_of(self.home)[0]

    def test_import_seeds_a_semantic_position(self) -> None:
        state = carrier_mod.semantic_state(self._record())
        self.assertEqual(state["next_episode_index"], 0)
        self.assertFalse(state["exhausted"])

    def test_mechanically_exhausted_session_still_owes_semantic_work(self) -> None:
        """The regression this ticket exists for: `continue` must not idle `next`."""
        record = self._record()
        self.assertTrue(
            (record.get("analysis") or {}).get("episodes_exhausted"),
            "precondition: the deterministic pass finished this session",
        )
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertEqual(unit["carrier"], "analyze-episodes")

    def test_semantic_exhaustion_idles_the_carrier(self) -> None:
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        self.assertEqual(status, "ok")
        index["sessions"][0]["semantic"] = {
            "next_episode_index": 0, "exhausted": True, "submitted": 0, "no_drift": 0
        }
        sessions_mod.save_index(self.home, index, registry=self.registry)
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertEqual(unit["carrier"], "idle")
        self.assertIsNone(unit["session"])

    def test_semantic_position_selects_the_named_episode(self) -> None:
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        episodes = index["sessions"][0]["episodes"]
        if len(episodes) < 2:
            self.skipTest("fixture has a single episode")
        index["sessions"][0]["semantic"] = {
            "next_episode_index": 1, "exhausted": False, "submitted": 1, "no_drift": 0
        }
        sessions_mod.save_index(self.home, index, registry=self.registry)
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertEqual(unit["episode"]["index"], episodes[1]["index"])

    def test_a_position_past_the_last_episode_is_idle_not_a_crash(self) -> None:
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        index["sessions"][0]["semantic"] = {
            "next_episode_index": 9999, "exhausted": False, "submitted": 0, "no_drift": 0
        }
        sessions_mod.save_index(self.home, index, registry=self.registry)
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertEqual(unit["carrier"], "idle")

    def test_a_malformed_semantic_block_falls_back_to_the_start(self) -> None:
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        index["sessions"][0]["semantic"] = {"next_episode_index": "soon"}
        sessions_mod.save_index(self.home, index, registry=self.registry)
        state = carrier_mod.semantic_state(support.sessions_of(self.home)[0])
        self.assertEqual(state["next_episode_index"], 0)

    def test_a_non_object_semantic_block_is_an_index_validation_failure(self) -> None:
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        index["sessions"][0]["semantic"] = "done"
        problems = sessions_mod.validate_index(index, registry=self.registry)
        self.assertTrue(any("semantic must be an object" in problem for problem in problems))


class ConflictNeverStarvesTheAnalyst(unittest.TestCase):
    """A frozen CONFLICT is an operator task; it must not block analysis."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _conflict(self) -> None:
        support.put_inbox(self.home, CONFLICT_BASE)
        support.run_saipal("continue", home=self.home)
        status, index, _detail = sessions_mod.load_index(self.home, registry=self.registry)
        for record in index["sessions"]:
            if record["session_id"] == "golden-hot-001":
                record["last_analyzed_seq"] = 2
                from saipal_engine import bundle as bundle_mod

                bundle = bundle_mod.load_bundle_file(
                    self.home / "session_inbox" / CONFLICT_BASE, registry=self.registry
                )
                record["prefix_sha256"] = bundle_mod.prefix_digest(bundle, 2)
        sessions_mod.save_index(self.home, index, registry=self.registry)
        support.clear_inbox(self.home)
        support.put_inbox(self.home, CONFLICT_MUTATED)
        support.run_saipal("continue", home=self.home)

    def test_a_conflicted_session_is_never_handed_to_the_analyst(self) -> None:
        self._conflict()
        record = next(
            r for r in support.sessions_of(self.home) if r["session_id"] == "golden-hot-001"
        )
        self.assertEqual(record["status"], "CONFLICT")
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        if unit["session"] is not None:
            self.assertNotEqual(unit["session"]["session_id"], "golden-hot-001")

    def test_conflict_alone_reports_resolve_conflict(self) -> None:
        self._conflict()
        _code, payload, _err = support.run_saipal_json("next", home=self.home)
        self.assertEqual(payload["carrier"], "resolve-conflict")
        self.assertEqual(payload["sessions_conflict"], 1)

    def test_analysis_work_outranks_a_frozen_conflict_but_still_reports_it(self) -> None:
        self._conflict()
        support.clear_inbox(self.home)
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)
        _code, payload, _err = support.run_saipal_json("next", home=self.home)
        self.assertEqual(payload["carrier"], "analyze-episodes")
        self.assertEqual(payload["sessions_conflict"], 1)
        self.assertIn("await conflict resolution", payload["note"])


class IdleAndDegraded(unittest.TestCase):
    """Idle is a real answer, and a missing bundle is reported, not crashed."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_an_empty_home_yields_the_idle_carrier(self) -> None:
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertEqual(unit["carrier"], "idle")
        self.assertIsNone(unit["session"])
        self.assertEqual(carrier_mod.carrier_problems(unit, registry=self.registry), [])

    def test_an_absent_bundle_is_reported_with_the_pointer(self) -> None:
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)
        (self.home / "session_inbox" / DRIFT).unlink()
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertEqual(unit["carrier"], "analyze-episodes")
        self.assertIn("unreadable", unit["note"])
        self.assertEqual(unit["session"]["source_ref"], f"session_inbox/{DRIFT}")

    def test_an_unrecoverable_index_refuses_instead_of_returning_idle(self) -> None:
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)
        (self.home / "sessions" / "index.json").write_text("{", encoding="utf-8")
        from saipal_engine.errors import PalError

        with self.assertRaises(PalError):
            carrier_mod.build_carrier(self.home, registry=self.registry)


class CarrierContext(unittest.TestCase):
    """Recurrence, calibration and open candidates reach the analyst."""

    def setUp(self) -> None:
        self.registry = load_registry()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = support.make_home(self.tmp)
        support.run_saipal("continue", home=self.home)
        support.put_inbox(self.home, DRIFT)
        support.run_saipal("continue", home=self.home)
        support.submit_drift(self.home, support.next_unit(self.home))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_recurrence_reaches_the_carrier(self) -> None:
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertIn("by_model", unit["recurrence"])
        self.assertIn("by_project", unit["recurrence"])

    def test_prior_maintainer_calibration_reaches_the_carrier(self) -> None:
        links = self.home / "closed_loop_links.json"
        self.assertTrue(links.is_file(), "the drift fixture must have emitted an audit")
        payload = json.loads(links.read_text(encoding="utf-8"))
        audit_number = payload["links"][0]["audit_number"]
        disposition = self.tmp / "d.json"
        disposition.write_text(
            json.dumps(
                {
                    "dispositions": [
                        {"audit_number": audit_number, "disposition": "NO_CHANGE"}
                    ]
                }
            ),
            encoding="utf-8",
        )
        code, _payload, err = support.run_saipal_json(
            "disposition", str(disposition), home=self.home
        )
        self.assertEqual(code, 0, err)
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertEqual(unit["calibration"][0]["disposition"], "NO_CHANGE")

    def test_evidence_command_matches_the_real_read_only_surface(self) -> None:
        """The carrier tells the analyst how to reopen evidence, in one exact form."""
        unit = carrier_mod.build_carrier(self.home, registry=self.registry)
        self.assertTrue(unit["evidence_command"].startswith("saipal --json evidence "))
        self.assertIn(unit["session"]["session_id"], unit["evidence_command"])


if __name__ == "__main__":
    unittest.main()
