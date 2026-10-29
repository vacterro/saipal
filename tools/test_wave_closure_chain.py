"""Closure-chain control: a `## DONE` row whose phase chain never reached SHIP.

The defect class, measured on this project's own memory: T-125 reached `## DONE`
with `closure_mode`, `owner`, `claim_time` and, in history, real VERIFY evidence
-- everything every field-based check looks at -- while its LOG carried no
canonical finish record at all. The chain stopped at VERIFY; E-950/E-951 closed
the record by hand. The field-based lifecycle planner skips such a row before it
reads history (it reopens only rows with NO closure_mode, NO owner, NO
claim_time and no evidence); the validator's own `[gate-closure]` analogue
inspects finish events that EXIST, so an absent one is invisible to it.

These tests pin the new control and the repair route that must not launder the
gap: an APPEND-ONLY attestation that names the chain actually reached, disclaims
gate authority in its own text, and docks the gap to real Work on BOARD.
"""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import validate

FINISH = "ticket finished via SAIOPS -- completion (from SHIP)"
ATTEST = "closure-chain-gap attested for"
DISCLAIM = "not gate proof"


def logged(row: str, *, owner: str = "buffy", closure: bool = True) -> str:
    """One BOARD row with the fields a canonical completion writes."""
    fields = f" | owner: {owner} | claim_time: 2026-09-16T06:00:00Z"
    if closure:
        fields += " | closure_mode: own_patch"
    if "| verify:" not in row:
        fields += " | verify: full discovery green"
    return f"- [x] {row}{fields}"


def board(*done: str, todo: tuple[str, ...] = ()) -> str:
    return (
        "# BOARD\n\n## TODO\n\n"
        + "\n".join(todo)
        + "\n\n## DONE\n\n"
        + "\n".join(done)
        + "\n"
    )


def line(
    event: int,
    text: str,
    *,
    ticket: str | None = "T-125",
    taxonomy: str = "DEC",
    op: str | None = "op",
) -> str:
    slots = f" [T-{ticket[2:]}]" if ticket else ""
    slots += " [agent: tester]"
    if op:
        slots += f" [op: {op}-{event:032x}]"
    return (
        f"- 16.09.26 06:00 [E-{event}] [parent: E-{event - 1}]"
        f"{slots} {taxonomy}: {text}"
    )


def log(*lines: str) -> str:
    return "\n".join(lines) + "\n"


def verified_chain(ticket: str = "T-125", first: int = 940) -> list[str]:
    """The chain T-125 actually reached: SCOUT -> BUILD -> VERIFY, then no SHIP."""
    return [
        line(first, "transition to SCOUT", ticket=ticket),
        line(first + 1, "transition to BUILD", ticket=ticket),
        line(first + 2, "transition to VERIFY", ticket=ticket),
        line(
            first + 3,
            "VERIFY T-125 PASS -- 1627 unit OK, 309 val OK, compileall OK",
            ticket=ticket,
            taxonomy="RUN",
        ),
    ]


def attestation(
    subject: str = "T-125",
    *,
    names: str = "T-127",
    disclaimer: str = DISCLAIM,
    taxonomy: str = "DEC",
    slot: bool = True,
) -> str:
    """The repair record: append-only, now-dated, one `DEC` decision."""
    text = (
        f"{ATTEST} {subject} -- the ## DONE record is historical evidence, "
        f"{disclaimer}: its chain stopped at VERIFY and its consequences are "
        f"owned by the corrective successor {names}."
    )
    return line(958, text, ticket=subject if slot else None, taxonomy=taxonomy)


class ClosureChainAudit(unittest.TestCase):
    """The audit itself, on synthetic project memory."""

    def test_governed_done_with_no_finish_record_is_unattested(self) -> None:
        audit = validate.closure_chain_report(
            board(logged("T-125 [P0] PAL-WRITE-01 write-boundary closure")),
            log(*verified_chain(), line(951, "T-125 DONE -- write confinement closed")),
        )
        self.assertEqual(audit["unattested"], ["T-125"])
        self.assertEqual(audit["closed"], [])
        self.assertEqual(audit["judged"], ["T-125"])

    def test_the_defect_is_invisible_to_fields_and_legible_in_the_chain(self) -> None:
        """The RED control: every field is present, only the chain is missing.

        This is exactly what made the gap survive: `closure_mode`, `owner`,
        `claim_time` and a verify: line are the planner's skip condition, and
        the phase chain is never consulted. The audit must read the CHAIN.
        """
        fields = validate._board_rows(board(logged("T-125 [P0] closure")), "## DONE")[0][1]
        self.assertTrue(validate._CLOSURE_MODE_RE.search(fields))
        self.assertIn("owner:", fields)
        self.assertIn("claim_time:", fields)
        audit = validate.closure_chain_report(
            board(logged("T-125 [P0] closure")),
            log(*verified_chain(), line(951, "T-125 DONE -- write confinement closed")),
        )
        self.assertEqual(audit["chains"]["T-125"], ["SCOUT", "BUILD", "VERIFY"])
        self.assertNotIn("SHIP", audit["chains"]["T-125"])
        self.assertEqual(audit["unattested"], ["T-125"])

    def test_ship_finish_record_closes_the_chain(self) -> None:
        audit = validate.closure_chain_report(
            board(logged("T-124 [P0] corrective")),
            log(
                line(879, "transition to SHIP -- REVIEW: SHIP verdict", ticket="T-124"),
                line(880, FINISH, ticket="T-124"),
            ),
        )
        self.assertEqual(audit["closed"], ["T-124"])
        self.assertEqual(audit["unattested"], [])
        self.assertIn("SHIP", audit["chains"]["T-124"])

    def test_run_taxonomy_is_not_a_completion(self) -> None:
        """Authority belongs to the record type that carries it (narrative leak)."""
        audit = validate.closure_chain_report(
            board(logged("T-125 [P0] closure")),
            log(line(951, FINISH, ticket="T-125", taxonomy="RUN")),
        )
        self.assertEqual(audit["unattested"], ["T-125"])

    def test_finish_record_from_any_other_phase_is_not_a_chain(self) -> None:
        """A recorded SKIPPED-GATE closure is history, not gate proof.

        `finish_ticket` refuses every non-SHIP closure, so a `(from VERIFY)`
        finish record is the pre-fix defect's own shape: the record may stand,
        but it proves the chain never reached SHIP and the audit must say so.
        """
        audit = validate.closure_chain_report(
            board(logged("T-125 [P0] closure")),
            log(
                *verified_chain(),
                line(951, "ticket finished via SAIOPS -- completion (from VERIFY)"),
            ),
        )
        self.assertEqual(audit["closed"], [])
        self.assertEqual(audit["unattested"], ["T-125"])
        self.assertNotIn("SHIP", audit["chains"]["T-125"])

    def test_legacy_generation_is_exempt_and_still_counted(self) -> None:
        audit = validate.closure_chain_report(
            board(
                logged("T-125 [P0] closure"),
                logged("T-108 [P3] terminal", closure=False),
                logged("T-001 Wave C", closure=False),
            ),
            log(line(80, "transition to VERIFY", ticket="T-108", op=None)),
        )
        self.assertEqual(audit["frontier"], 125)
        self.assertEqual(audit["judged"], ["T-125"])
        self.assertEqual(audit["legacy"], ["T-108", "T-001"])
        self.assertEqual(len(audit["judged"]) + len(audit["legacy"]), len(audit["rows"]))

    def test_frontier_falls_back_to_mechanized_events(self) -> None:
        """No closure_mode anywhere: the operation layer's own marker decides."""
        audit = validate.closure_chain_report(
            board(logged("T-070 multi-generation", closure=False), logged("T-001 Wave C", closure=False)),
            log(line(70, "transition to VERIFY", ticket="T-070")),
        )
        self.assertIsNone(audit["frontier"])
        self.assertEqual(audit["judged"], ["T-070"])
        self.assertEqual(audit["unattested"], ["T-070"])
        self.assertEqual(audit["legacy"], ["T-001"])

    def test_attestation_repairs_the_gap_without_needing_a_gate(self) -> None:
        audit = validate.closure_chain_report(
            board(
                logged("T-125 [P0] closure"),
                todo=("- [/] T-127 [P0] corrective successor to T-125",),
            ),
            log(*verified_chain(), attestation()),
        )
        self.assertEqual(audit["unattested"], [])
        self.assertEqual(audit["closed"], [])
        self.assertEqual(audit["attested"]["T-125"]["event"], 958)
        self.assertTrue(audit["attested"]["T-125"]["declares_historical_evidence"])
        self.assertEqual(audit["attested"]["T-125"]["names"], ["T-127"])
        self.assertEqual(audit["stale"], [])
        self.assertEqual(audit["undeclared"], [])
        self.assertEqual(audit["phantom_refs"], [])

    def test_repair_record_must_disclaim_gate_authority(self) -> None:
        audit = validate.closure_chain_report(
            board(
                logged("T-125 [P0] closure"),
                todo=("- [/] T-127 [P0] corrective successor to T-125",),
            ),
            log(attestation(disclaimer="gate proof")),
        )
        self.assertEqual(audit["undeclared"], ["T-125"])
        # A record that reads like a completion does not close the gap honestly;
        # it is reported as an undeclared repair AND leaves the audit failing.
        self.assertEqual(audit["attested"]["T-125"]["declares_historical_evidence"], False)

    def test_repair_record_naming_work_that_is_not_on_board(self) -> None:
        audit = validate.closure_chain_report(
            board(logged("T-125 [P0] closure")),
            log(attestation(names="T-999")),
        )
        self.assertEqual(audit["phantom_refs"], ["T-999"])

    def test_attestation_on_a_closed_record_is_stale_drift(self) -> None:
        audit = validate.closure_chain_report(
            board(logged("T-125 [P0] closure")),
            log(line(880, FINISH, ticket="T-125"), attestation()),
        )
        self.assertEqual(audit["closed"], ["T-125"])
        self.assertEqual(audit["stale"], ["T-125"])

    def test_run_taxonomy_cannot_carry_the_repair_record(self) -> None:
        audit = validate.closure_chain_report(
            board(logged("T-125 [P0] closure")),
            log(attestation(taxonomy="RUN")),
        )
        self.assertEqual(audit["attested"], {})
        self.assertEqual(audit["unattested"], ["T-125"])

    def test_attestation_without_a_ticket_slot_still_resolves_its_subject(self) -> None:
        audit = validate.closure_chain_report(
            board(
                logged("T-125 [P0] closure"),
                todo=("- [/] T-127 [P0] successor to T-125",),
            ),
            log(attestation(slot=False)),
        )
        self.assertIn("T-125", audit["attested"])
        self.assertEqual(audit["attested"]["T-125"]["names"], ["T-127"])


class ClosureChainCheck(unittest.TestCase):
    """`check_closure_chain` over a checkout's own `.saipen/` memory."""

    def run_check(self, board_text: str, log_text: str) -> tuple[validate.Report, str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".saipen").mkdir()
            (root / ".saipen" / "BOARD.md").write_text(board_text, encoding="utf-8")
            (root / ".saipen" / "LOG.md").write_text(log_text, encoding="utf-8")
            report = validate.Report()
            out = io.StringIO()
            with mock.patch.object(validate, "_ROOT", root), contextlib.redirect_stdout(out):
                validate.check_closure_chain(report)
            return report, out.getvalue()

    def test_failure_names_the_phase_chain_that_stopped(self) -> None:
        report, out = self.run_check(
            board(logged("T-125 [P0] PAL-WRITE-01 closure")),
            log(*verified_chain(), line(951, "T-125 DONE -- write confinement closed")),
        )
        self.assertFalse(report.ok)
        self.assertEqual(len(report.failures), 1)
        self.assertIn("T-125", report.failures[0])
        self.assertIn("SCOUT > BUILD > VERIFY", report.failures[0])
        self.assertIn("never by synthesizing the missing gate", report.failures[0])
        self.assertIn("T-125", out)

    def test_attested_gap_passes_and_is_reported_as_historical(self) -> None:
        report, out = self.run_check(
            board(
                logged("T-125 [P0] closure"),
                todo=("- [/] T-127 [P0] corrective successor to T-125",),
            ),
            log(*verified_chain(), attestation()),
        )
        self.assertTrue(report.ok, report.failures)
        self.assertIn("historical evidence, never gate proof", out)
        self.assertIn("T-125 (E-958)", out)
        self.assertIn("T-127", out)

    def test_missing_project_memory_is_declared_not_silently_passed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = validate.Report()
            out = io.StringIO()
            with mock.patch.object(validate, "_ROOT", Path(tmp)), contextlib.redirect_stdout(out):
                validate.check_closure_chain(report)
        self.assertTrue(report.ok)
        self.assertIn("not applicable", out.getvalue())


class LiveProjectMemory(unittest.TestCase):
    """The control applied to THIS checkout's memory, when it is present.

    `.saipen/` is local state (gitignored) and absent from a clean clone, so its
    absence is declared rather than treated as a failure -- but where it exists
    it is the real subject of this audit.
    """

    BOARD = validate._ROOT / ".saipen" / "BOARD.md"
    LOG = validate._ROOT / ".saipen" / "LOG.md"

    def audit(self) -> dict:
        if not (self.BOARD.is_file() and self.LOG.is_file()):
            self.skipTest("this checkout carries no .saipen project memory")
        return validate.closure_chain_report(
            self.BOARD.read_text(encoding="utf-8"),
            self.LOG.read_text(encoding="utf-8"),
        )

    def test_no_unattested_current_generation_done_record(self) -> None:
        audit = self.audit()
        self.assertEqual(audit["unattested"], [])
        self.assertEqual(audit["stale"], [])
        self.assertEqual(audit["undeclared"], [])
        self.assertEqual(audit["phantom_refs"], [])

    def test_every_done_record_is_classified(self) -> None:
        audit = self.audit()
        self.assertEqual(
            len(audit["judged"]) + len(audit["legacy"]),
            len(audit["rows"]),
            "every ## DONE record is either governed or explicitly legacy",
        )
        self.assertTrue(audit["rows"], "a DONE section with no rows would prove nothing")


if __name__ == "__main__":
    unittest.main()
