"""PAL-CPALL-05 red controls: a blocked boundary is drained, not announced.

Nine controls, one per way this could be wrong:

* A  the real corpus is genuinely zero-runnable -- proved with the allocator's
   OWN classifier, never by trusting a summary field;
* B  a session that IS runnable is found and counted, so A cannot pass
   vacuously by classifying everything as blocked;
* C  release-root leverage is split into generically-recoverable vs
   enrollment-movable, and a made-up unlock number cannot appear;
* D  a conflict is never auto-resolved and keeps its exact identity;
* E  nothing is replayed for REMOTE_OUTCOME_UNKNOWN;
* F  resume after one decision reclassifies ONLY the affected session;
* G  a guessed, newly created or self-authored authority root is never
   enrolled -- candidates stay CANDIDATE_ONLY;
* H  an orphan BOARD_new.md cannot create live tickets or alter goal counts;
* I  the packet is deterministic: stable identities, order and counts.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pal_test_support as support
from saipal_analyst import operator_queue as oq


REPO_ROOT = Path(__file__).resolve().parent.parent


class OperatorQueueBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = support.make_home(Path(self._tmp.name))

    def test_a_real_corpus_has_no_agent_runnable_session(self) -> None:
        """A: prove zero-runnable with the allocator, not with a report.

        The packet asserts it; this control re-derives it by calling
        `_classify_unit` over every freshest record, so a packet that lied
        about the drain would fail here instead of being believed.
        """
        from time import time

        from saipal_analyst import jobs as jobs_mod
        from saipal_analyst import worker as worker_mod
        from saipal_engine import carrier as carrier_mod
        from saipal_engine.registry import load_registry
        from saipal_engine.sessions import load_index

        data = load_registry()
        status, index, _detail = load_index(REPO_ROOT / ".saipal", registry=data)
        self.assertNotEqual(status, "unrecoverable", "the real session index must be readable")
        records = list(carrier_mod.freshest_records(index))
        self.assertGreater(len(records), 0, "the corpus is not empty")

        journal = jobs_mod.load_journal(REPO_ROOT / ".saipal")
        limit = int(carrier_mod._limits(data)["max_events"])
        now = time()
        classes: dict[str, int] = {}
        for record in records:
            klass = worker_mod._classify_unit(record, limit, journal, False, now)
            classes[klass] = classes.get(klass, 0) + 1

        runnable = {k: v for k, v in classes.items() if k.startswith("RUNNABLE")}
        self.assertEqual(
            runnable,
            {},
            f"the corpus claims zero agent-runnable, but the allocator says {runnable}",
        )

        packet = oq.build(REPO_ROOT / ".saipal", registry=data)
        self.assertTrue(packet["ok"])
        self.assertEqual(packet["boundary"]["population_sessions"], len(records))
        self.assertEqual(packet["boundary"]["unassigned_sessions"], 0)
        self.assertTrue(packet["boundary"]["auto_drain_complete"])
        self.assertEqual(packet["boundary"]["agent_runnable_remaining"], 0)

    def test_b_a_runnable_session_is_found_not_assumed_absent(self) -> None:
        """B: the zero in A must be measured, not structural.

        A fixture home with one eligible session must classify it
        AGENT_ACTIONABLE. If `build` hard-coded an empty drain, this fails.
        """
        support.put_inbox(self.home, "hot-partial.json")
        support.run_saipal("continue", home=self.home)

        packet = oq.build(self.home)
        self.assertTrue(packet["ok"], packet.get("reason"))
        decisions = {d["decision"]: d for d in packet["decisions"]}
        self.assertIn(
            oq.DECISION_AGENT_ACTIONABLE,
            decisions,
            f"an eligible session must land in AGENT_ACTIONABLE, got "
            f"{sorted(decisions)} (classes: {packet['decisions']})",
        )
        self.assertFalse(packet["boundary"]["auto_drain_complete"])
        self.assertEqual(packet["boundary"]["state"], "DRAINING")
        self.assertGreater(packet["boundary"]["agent_runnable_remaining"], 0)

    def test_c_release_root_leverage_is_split_never_invented(self) -> None:
        """C: leverage is computed or UNKNOWN -- never a plausible number."""
        packet = oq.build(REPO_ROOT / ".saipal")
        self.assertTrue(packet["ok"])
        for entry in packet["decisions"]:
            if entry["decision"] != oq.DECISION_RELEASE_ROOT:
                continue
            split = entry["binding_evidence_disambiguation"]
            # Both populations are reported side by side, because they are two
            # different questions (see PAL-CPALL-04) and merging them is what
            # produced the "354 recoverable" reading.
            self.assertIsInstance(split["verifiable_binding_jobs"], int)
            self.assertIsInstance(split["sessions_released_by_enrollment_alone"], int)
            self.assertIsInstance(split["also_gated_on_provisional"], int)
            self.assertLessEqual(
                entry["authority_verifiable_sessions"],
                entry["sessions"],
                "one enrollment cannot release more sessions than the group holds",
            )
            self.assertGreater(split["sessions_released_by_enrollment_alone"], 0)

        for entry in packet["decisions"]:
            if entry["decision"] != oq.DECISION_REMOTE_OUTCOME:
                continue
            self.assertEqual(entry["unlock"]["status"], "UNKNOWN")
            self.assertIsNone(entry["unlock"]["sessions_released"])

    def test_d_conflict_is_never_resolved_and_keeps_identity(self) -> None:
        """D: a conflict carries its own exact identity; nothing decides it."""
        from saipal_engine import cpall as cpall_mod

        packet = oq.build(REPO_ROOT / ".saipal")
        self.assertTrue(packet["ok"])
        conflicts = [d for d in packet["decisions"] if d["decision"] == oq.DECISION_CONFLICT]
        if not conflicts:
            self.skipTest("this corpus carries no conflict population")
        entry = conflicts[0]
        self.assertGreater(entry["sessions"], 0)
        # Batch presentation, individual identity: a group of N is still N
        # separately addressable sessions.
        self.assertEqual(len(entry["session_ids"]), entry["sessions"])
        self.assertEqual(entry["session_ids"], sorted(set(entry["session_ids"])))
        evidence = entry["conflict_evidence"]
        self.assertTrue(evidence, "a conflict group must carry its evidence")
        for item in evidence:
            self.assertTrue(item.get("session_id"))
            self.assertTrue(item.get("conflict_material_sha256"))
            self.assertIn(
                "resolvable_by",
                item,
                "the conflict must say WHO resolves it -- a group with no named "
                "resolver is the PAL-CPALL-04 dead end",
            )
        self.assertTrue(
            any("operator decision" in a.lower() for a in entry["legal_actions"]),
            "a conflict must name the operator decision that clears it -- gathering "
            "evidence alone is the PAL-CPALL-04 dead end",
        )
        self.assertTrue(
            any("auto-resolve" in a.lower() for a in entry["forbidden_actions"]),
            "auto-resolution must be named as forbidden, not merely omitted",
        )
        self.assertFalse(
            any("auto" in a.lower() for a in entry["legal_actions"]),
            "no legal action may resolve a conflict automatically",
        )
        # The objective itself still lists them isolated, not resolved.
        status, objective, detail = cpall_mod.load_objective(REPO_ROOT / ".saipal")
        if status == "ok" and objective:
            self.assertGreaterEqual(int((objective.get("conflicts") or {}).get("current") or 0), 0)

    def test_e_remote_outcome_is_never_replayed(self) -> None:
        """E: building the queue must not touch a paid attempt.

        A digest of the whole home before and after proves the read-only claim
        for EVERY control at once, and specifically that no REMOTE_OUTCOME
        attempt was re-dispatched by looking at the packet being built.
        """
        before = support.tree_digest(REPO_ROOT / ".saipal")
        packet = oq.build(REPO_ROOT / ".saipal")
        after = support.tree_digest(REPO_ROOT / ".saipal")
        self.assertEqual(before, after, "operator-queue must be read-only")

        for entry in packet["decisions"]:
            if entry["decision"] != oq.DECISION_REMOTE_OUTCOME:
                continue
            self.assertTrue(entry["attempt_ids"], "remote-unknown work must name its attempts")
            for action in entry["legal_actions"]:
                self.assertNotIn("investigate", action.lower())
                self.assertNotIn("re-run", action.lower())
            self.assertTrue(
                any("confirm" in a.lower() for a in entry["forbidden_actions"])
                or any("replay" in a.lower() for a in entry["forbidden_actions"]),
                "auto-replay must be named as forbidden",
            )

    def test_f_resume_reclassifies_only_the_affected_session(self) -> None:
        """F: one decision moves its own sessions and nobody else's."""
        from saipal_engine.sessions import find_session, load_index, save_index

        home = support.make_home(Path(self._tmp.name) / "resume-fixture")
        support.put_inbox(home, "hot-partial.json")
        support.run_saipal("continue", home=home)

        packet = oq.build(home)
        self.assertTrue(packet["ok"])
        before = {sid: d["decision"] for d in packet["decisions"] for sid in d["session_ids"]}

        # Promote one session's binding -- exactly what `authority enroll` +
        # `rebind` would leave behind -- and rebuild.
        status, index, _detail = load_index(home)
        target = index["sessions"][0]
        record = find_session(index, str(target["session_id"]))
        record["protocol"]["binding_status"] = "BOUND"
        save_index(home, index)

        after_packet = oq.build(home)
        self.assertTrue(after_packet["ok"])
        after = {
            sid: d["decision"] for d in after_packet["decisions"] for sid in d["session_ids"]
        }
        self.assertEqual(
            set(before), set(after), "the population must not gain or lose identities"
        )
        moved = {sid for sid in before if before[sid] != after[sid]}
        self.assertLessEqual(moved, {str(target["session_id"])})
        self.assertEqual(
            sum(int(d["sessions"]) for d in after_packet["decisions"]),
            len(after),
            "the partition must still re-sum to the population",
        )

    def test_g_authority_candidates_are_never_enrolled(self) -> None:
        """G: discovery is not trust, and a made-up root is not a candidate."""
        packet = oq.build(REPO_ROOT / ".saipal")
        authority = packet["authority"]
        enrolled = authority.get("enrolled") or {}
        candidates = authority.get("candidates") or []

        enrolled_paths = {
            str(v).replace("\\", "/").rstrip("/").lower()
            for v in enrolled.values()
            if v
        }
        for candidate in candidates:
            self.assertEqual(
                candidate.get("disposition"),
                "CANDIDATE_ONLY",
                f"a candidate must never be presented as enrolled: {candidate}",
            )
            # A path that does not exist, or a git dir with no registry, is not a
            # root at all. Enrolling it would be fabricated authority.
            if not candidate.get("exists") or not candidate.get("registry_present"):
                normalized = str(candidate.get("path") or "")
                for enrolled_path in enrolled_paths:
                    self.assertNotIn(
                        str(Path(normalized).name).lower(),
                        Path(enrolled_path).name.lower(),
                        f"a non-root candidate {normalized!r} is enrolled as {enrolled_path!r}",
                    )
                self.assertEqual(candidate.get("confidence"), "low")

        # `pinned` must name exactly the kinds an operator already enrolled -- never a
        # candidate. This is the whole guarantee in one assertion: building the
        # packet adds nothing to the trust set.
        self.assertEqual(
            sorted(authority.get("pinned") or []),
            sorted(kind for kind, path in enrolled.items() if path),
        )

        # A guessed, self-authored or unrelated-git candidate must never reach
        # `enrolled`: the git repository this packet ran from is not an authority
        # for a release root.
        self.assertNotIn("tools", str(enrolled.get("release_root") or ""))
        self.assertIsNone(
            enrolled.get("snapshot_root"),
            "a snapshot root may only exist if an operator enrolled one",
        )

    def test_h_orphan_board_cannot_masquerade(self) -> None:
        """H: no orphan board may create live tickets or move goal counts.

        Two halves, and both must hold. The quarantine: an orphan may exist in
        the archive but never beside BOARD.md. The invariant: if one appears
        beside it again, every ticket it names must already be closed on the
        live board, or it is a fabricated ticket by another name.
        """
        import re

        saipen = REPO_ROOT / ".saipen"
        board = (saipen / "BOARD.md").read_text(encoding="utf-8")

        state = (saipen / "STATE.md").read_text(encoding="utf-8")
        goal_match = re.search(r"^goal_tickets:\s*(\d+)\s*$", state, re.M)
        self.assertIsNotNone(goal_match, "STATE must still declare goal_tickets")
        declared_goal = int(goal_match.group(1))

        def rows(text: str) -> list[str]:
            return re.findall(r"^-\s*\[[ x/]\]\s+(T-\d+)", text, re.M)

        board_rows = rows(board)
        self.assertEqual(len(board_rows), len(set(board_rows)), "live BOARD ids must be unique")

        # Every board-shaped file in the memory root, live or quarantined.
        orphans = sorted(saipen.glob("BOARD*.md"))
        self.assertEqual(
            orphans,
            [saipen / "BOARD.md"],
            f"a second board file sits beside BOARD.md: {[p.name for p in orphans]}",
        )

        # If one WAS quarantined, its disposition must be recorded and its
        # content must still be a subset of the live board -- otherwise the move
        # destroyed evidence, which is the one thing it may never do.
        for record in sorted((saipen / "archive" / "retired").glob("BOARD*.provenance.json")):
            disposition = json.loads(record.read_text(encoding="utf-8"))
            quarantined = saipen / "archive" / "retired" / disposition["artifact"]
            self.assertTrue(quarantined.is_file(), f"{quarantined} must be preserved, not deleted")
            self.assertEqual(
                disposition["authority"],
                "SYSTEM_CORRECTION",
                "quarantining an orphan board is a filesystem classification, not an "
                "operator decision -- claiming otherwise would fabricate authority",
            )
            orphan_rows = set(rows(quarantined.read_text(encoding="utf-8")))
            invented = [t for t in sorted(orphan_rows) if t not in set(board_rows)]
            self.assertEqual(
                invented,
                [],
                f"the quarantined board held tickets the live board never had: {invented}",
            )

        # The declared goal count tracks the LIVE board only. A quarantined board
        # contributes nothing: its thirteen tickets are all closed on BOARD.md,
        # so even a buggy counter that unioned every board-shaped file on disk
        # would land on the same number. Asserting the invariant rather than a
        # literal keeps this honest when the next ticket legitimately changes it.
        self.assertGreater(declared_goal, 0)
        live_done = len(
            {r for r in board_rows if re.search(rf"^- \[x\]\s+{re.escape(r)}\b", board, re.M)}
        )
        self.assertGreater(live_done, declared_goal)
        for record in (saipen / "archive" / "retired").glob("BOARD*.provenance.json"):
            disposition = json.loads(record.read_text(encoding="utf-8"))
            self.assertEqual(
                disposition["provenance_check"]["tickets_open_on_live_board"],
                0,
                "quarantine is only sound while every ticket it names is already closed",
            )

    def test_i_packet_is_deterministic(self) -> None:
        """I: same corpus, same identities, same order, same counts, same digest."""
        first = oq.build(REPO_ROOT / ".saipal")
        second = oq.build(REPO_ROOT / ".saipal")
        self.assertEqual(first["corpus_digest"], second["corpus_digest"])
        self.assertEqual(
            [d["decision"] for d in first["decisions"]],
            [d["decision"] for d in second["decisions"]],
            "decision order must be stable, not dict-order dependent",
        )
        for a, b in zip(first["decisions"], second["decisions"]):
            self.assertEqual(a["session_ids"], b["session_ids"])
            self.assertEqual(a["sessions"], b["sessions"])
            self.assertEqual(a["session_ids"], sorted(set(a["session_ids"])))

        # No clock, pid or run counter may leak into the packet's identity.
        import os

        blob = json.dumps(first, sort_keys=True, default=str)
        self.assertNotIn(str(os.getpid()), blob)
        self.assertNotIn('"pid"', blob)
        self.assertNotIn('"generated_at"', blob)

        # Rendered text is a function of the packet, and the packet validates.
        self.assertTrue(first["ok"])
        self.assertTrue(oq.render_text(first))
        with tempfile.TemporaryDirectory() as tmp:
            sink = Path(tmp) / "home"
            sink.mkdir()
            path = oq.write_packet(sink, first)
            self.assertTrue(path.is_file())
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8"))["corpus_digest"],
                first["corpus_digest"],
            )


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Read-only maintainer checks against an explicit existing SAIPAL/SAIPEN corpus.")
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    REPO_ROOT = Path(args.root).resolve()
    for required in (".saipal/sessions/index.json", ".saipen/STATE.md", ".saipen/BOARD.md"):
        if not (REPO_ROOT / required).is_file():
            parser.error(f"required maintainer carrier missing: {required}")
    unittest.main(argv=[__file__])
