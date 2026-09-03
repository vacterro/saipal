"""Wave A: STATE.json is machine-owned, and recovery is refusal (PAL-BOOT-02)."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from saipal_engine import state as state_mod
from saipal_engine.errors import PalError
from saipal_engine.state import (
    STATE_ABSENT,
    STATE_OK,
    STATE_UNRECOVERABLE,
    fresh_state,
    load_state,
    save_state,
    validate_state,
)

import pal_test_support as support


class StateContract(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = support.make_home(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_fresh_state_validates(self) -> None:
        self.assertEqual(validate_state(fresh_state()), [])

    def test_round_trip_survives_restart(self) -> None:
        payload = fresh_state()
        payload["phase"] = "BLOCKED"
        payload["queue"]["hot"] = 3
        save_state(self.home, payload)

        status, loaded, _detail = load_state(self.home)
        self.assertEqual(status, STATE_OK)
        assert loaded is not None
        self.assertEqual(loaded["phase"], "BLOCKED")
        self.assertEqual(loaded["queue"]["hot"], 3)
        self.assertIsInstance(loaded["updated"], str)

    def test_absent_state_is_absent_not_broken(self) -> None:
        status, payload, _detail = load_state(self.home)
        self.assertEqual(status, STATE_ABSENT)
        self.assertIsNone(payload)

    def test_malformed_json_is_unrecoverable(self) -> None:
        (self.home / "STATE.json").write_text("{not json at all", encoding="utf-8")
        status, payload, detail = load_state(self.home)
        self.assertEqual(status, STATE_UNRECOVERABLE)
        self.assertIsNone(payload)
        self.assertIn("unreadable", detail)

    def test_unknown_field_is_unrecoverable(self) -> None:
        payload = fresh_state()
        payload["totally_new_field"] = "surprise"
        problems = validate_state(payload)
        self.assertTrue(any("unknown field" in p for p in problems))

    def test_illegal_phase_is_unrecoverable(self) -> None:
        payload = fresh_state()
        payload["phase"] = "ANALYZE"
        problems = validate_state(payload)
        self.assertTrue(any("phase" in p for p in problems))

    def test_negative_queue_is_unrecoverable(self) -> None:
        payload = fresh_state()
        payload["queue"]["cold"] = -1
        problems = validate_state(payload)
        self.assertTrue(any("negative" in p for p in problems))

    def test_wrong_schema_version_is_unrecoverable(self) -> None:
        payload = fresh_state()
        payload["schema_version"] = 99
        problems = validate_state(payload)
        self.assertTrue(any("schema_version" in p for p in problems))

    def test_saving_an_invalid_state_writes_nothing(self) -> None:
        good = fresh_state()
        save_state(self.home, good)
        before = (self.home / "STATE.json").read_bytes()

        broken = fresh_state()
        broken["phase"] = "NOPE"
        with self.assertRaises(PalError) as caught:
            save_state(self.home, broken)
        self.assertEqual(caught.exception.code, "STATE_UNRECOVERABLE")
        self.assertEqual(
            (self.home / "STATE.json").read_bytes(),
            before,
            "a refused save must leave the previous state byte-identical",
        )

    def test_corrupt_state_file_is_never_overwritten_by_continue(self) -> None:
        garbage = b"/* someone's lunch */"
        target = self.home / "STATE.json"
        target.write_bytes(garbage)

        status, _payload, _detail = load_state(self.home)
        self.assertEqual(status, STATE_UNRECOVERABLE)
        # Nothing in the load path is allowed to repair it.
        self.assertEqual(target.read_bytes(), garbage)

    def test_red_control_validation_reads_the_registry(self) -> None:
        """Add the bogus field to the closed set; validation must stop objecting."""
        payload = fresh_state()
        payload["totally_new_field"] = "surprise"
        self.assertTrue(validate_state(payload))

        mutated = support.load_registry_copy()
        mutated["state"]["known_fields"] = sorted(
            set(mutated["state"]["known_fields"]) | {"totally_new_field"}
        )
        with mock.patch.object(state_mod, "load_registry", return_value=mutated):
            self.assertEqual(validate_state(payload, registry=mutated), [])

    def test_red_control_removing_a_required_field_is_detected(self) -> None:
        mutated = support.load_registry_copy()
        mutated["state"]["required_fields"] = mutated["state"]["required_fields"] + [
            "not_present_anywhere"
        ]
        problems = validate_state(fresh_state(), registry=mutated)
        self.assertTrue(any("not_present_anywhere" in p for p in problems))

    def test_state_is_json_with_stable_key_order(self) -> None:
        save_state(self.home, fresh_state())
        raw = (self.home / "STATE.json").read_text(encoding="utf-8")
        parsed = json.loads(raw)
        self.assertEqual(
            raw,
            json.dumps(parsed, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        )

    def test_deep_copy_of_state_is_independent(self) -> None:
        payload = fresh_state()
        clone = copy.deepcopy(payload)
        clone["queue"]["hot"] = 42
        self.assertEqual(payload["queue"]["hot"], 0)


if __name__ == "__main__":
    unittest.main()
