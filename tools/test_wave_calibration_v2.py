"""T-053: Disposition/calibration v2 integration tests.

Verifies that prior maintainer decisions imported into closed_loop_links.json
feed back into candidate/carrier scoring, downgrade findings that were previously
rejected without confirm, and render enriched calibration objects.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_engine import carrier as carrier_mod
from saipal_engine import closedloop as cl_mod
from saipal_engine import pipeline as pipeline_mod
from saipal_engine.registry import load_registry

DRIFT = "agent-noncompliance-command-route.json"


class CalibrationFeedback(unittest.TestCase):
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

    def test_calibrate_finding_empty_history(self) -> None:
        res = cl_mod.calibrate_finding(self.home, {"finding_id": "PAL-9999", "drift_class": "COMMAND_ROUTE_DRIFT"})
        self.assertEqual(res["total_dispositions"], 0)
        self.assertEqual(res["confidence_adjustment"], "NONE")

    def test_calibrate_finding_with_rejection(self) -> None:
        # Import a rejection for PAL-0001
        links_data = {
            "schema_version": 1,
            "links": [
                {
                    "finding_id": "PAL-0001",
                    "audit_number": 1,
                    "disposition": "REJECTED_FINDING",
                    "fix_version": None,
                    "closed_at": "2026-09-01T00:00:00Z"
                }
            ]
        }
        cl_mod.save_links(self.home, links_data)
        res = cl_mod.calibrate_finding(self.home, {"finding_id": "PAL-0001", "drift_class": "COMMAND_ROUTE_DRIFT"})
        self.assertEqual(res["total_dispositions"], 1)
        self.assertEqual(res["rejected"], 1)
        self.assertEqual(res["confidence_adjustment"], "DOWNGRADE_LOW")

    def test_carrier_calibration_includes_receipt_and_closed_at(self) -> None:
        links_data = {
            "schema_version": 1,
            "links": [
                {
                    "finding_id": "PAL-0001",
                    "audit_number": 1,
                    "disposition": "CONFIRMED_PROTOCOL_DEFECT",
                    "receipt_id": "rcp-1234",
                    "fix_version": "7.240.0",
                    "closed_at": "2026-09-01T12:00:00Z"
                }
            ]
        }
        cl_mod.save_links(self.home, links_data)
        cal = carrier_mod._calibration(self.home, 10)
        self.assertEqual(len(cal), 1)
        self.assertEqual(cal[0]["receipt_id"], "rcp-1234")
        self.assertEqual(cal[0]["closed_at"], "2026-09-01T12:00:00Z")


if __name__ == "__main__":
    unittest.main()
