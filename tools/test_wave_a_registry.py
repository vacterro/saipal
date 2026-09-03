"""Wave A: the registry is the machine authority, and it is a closed set."""

from __future__ import annotations

import re
import unittest

from saipal_engine.commands import (
    available_commands,
    load_shortcut_table,
    resolve_shortcut,
)
from saipal_engine.registry import load_registry, require_mapping, require_string_list

ENUM_KEYS = (
    "carrier_phases",
    "next_carriers",
    "temperature_enum",
    "finding_lifecycle",
    "confidence_enum",
    "severity_enum",
    "drift_taxonomy",
    "change_target_enum",
    "audit_publication_states",
)

RULE_ID_RE = re.compile(r"^PAL-[A-Z]+-\d{2}$")


class RegistryFacts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry()

    def test_identity(self) -> None:
        self.assertEqual(self.registry["kind"], "saipal-machine-registry")
        self.assertEqual(self.registry["schema_version"], 1)

    def test_every_enum_is_non_empty_and_unique(self) -> None:
        for key in ENUM_KEYS:
            with self.subTest(key=key):
                values = require_string_list(self.registry, key)
                self.assertTrue(values, f"{key} is empty")
                self.assertEqual(len(values), len(set(values)), f"{key} has duplicates")

    def test_rule_ids_are_well_formed(self) -> None:
        owners = require_mapping(self.registry, "rule_owners")
        self.assertTrue(owners)
        for rule, owner in owners.items():
            with self.subTest(rule=rule):
                self.assertRegex(rule, RULE_ID_RE)
                self.assertTrue(owner.startswith("saipal/"), owner)

    def test_write_action_sets_are_disjoint(self) -> None:
        actions = require_mapping(self.registry, "write_actions")
        allowed = set(actions["allowed"])
        reserved = set(actions["reserved"])
        forbidden = set(actions["forbidden"])
        self.assertFalse(allowed & reserved, "an action is both allowed and reserved")
        self.assertFalse(allowed & forbidden, "an action is both allowed and forbidden")
        self.assertFalse(reserved & forbidden, "an action is both reserved and forbidden")

    def test_audit_enqueue_is_allowed_after_wave_e(self) -> None:
        actions = require_mapping(self.registry, "write_actions")
        self.assertIn("enqueue_audit", actions["allowed"])
        self.assertNotIn("enqueue_audit", actions["forbidden"])

    def test_every_forbidden_action_targets_the_outside_world(self) -> None:
        for action in require_mapping(self.registry, "write_actions")["forbidden"]:
            with self.subTest(action=action):
                self.assertTrue(
                    action.startswith(("mutate_", "create_", "edit_", "delete_")),
                    f"{action} does not read like an external mutation",
                )

    def test_commands_and_shortcuts_agree(self) -> None:
        commands = set(available_commands(self.registry))
        self.assertEqual(
            {"continue", "status", "next", "report", "evidence", "setup", "doctor",
             "submit", "disposition", "trigger", "sessions"},
            commands,
        )
        for alias, expansion in load_shortcut_table().items():
            with self.subTest(alias=alias):
                parts = expansion.split()
                self.assertEqual(parts[0], "saipal", expansion)
                self.assertIn(parts[1], commands, expansion)

    def test_cc_resolves_to_continue(self) -> None:
        self.assertEqual(resolve_shortcut("cc"), "saipal continue")
        self.assertIsNone(resolve_shortcut("scan"), "an unimplemented alias must not resolve")

    def test_deferred_semantics_name_real_rules(self) -> None:
        owners = set(require_mapping(self.registry, "rule_owners"))
        for wave, entry in require_mapping(self.registry, "deferred_semantics").items():
            with self.subTest(wave=wave):
                if isinstance(entry, dict):
                    rules = entry.get("rules") or []
                    self.assertIn("introduced_in", entry, f"{wave} missing introduced_in")
                else:
                    rules = list(entry) if isinstance(entry, (list, tuple)) else []
                self.assertTrue(rules, f"{wave} claims no deferred rules")
                self.assertTrue(set(rules) <= owners, f"{wave} defers unknown rules: {set(rules) - owners}")

    def test_error_codes_are_closed_and_non_empty(self) -> None:
        codes = require_string_list(self.registry, "error_codes")
        self.assertTrue(codes)
        self.assertEqual(len(codes), len(set(codes)), "duplicate error code")
        for code in codes:
            with self.subTest(code=code):
                self.assertRegex(code, r"^[A-Z][A-Z0-9_]+$")


if __name__ == "__main__":
    unittest.main()
