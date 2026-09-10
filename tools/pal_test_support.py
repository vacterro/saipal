"""Shared test machinery for the SAIPAL suite.

Deliberately not named `test_*` so unittest discovery never collects it.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent
SAIPAL_CLI = TOOLS_DIR / "saipal.py"


def python_exe() -> str:
    return sys.executable


def tool_root() -> Path:
    return REPO_ROOT


def checkout_audit_entries() -> set[str]:
    """Names directly under the checkout's `audit/`, empty when there is none.

    SAIPAL must never emit an audit into its own checkout, but `audit/` is also
    the operator's SAIPEN audit inbox, so an absent directory is not the property
    to assert -- a run that adds nothing to it is. Comparing the listing across a
    run proves that in a working checkout as well as a bare one.
    """
    directory = REPO_ROOT / "audit"
    if not directory.is_dir():
        return set()
    return {path.name for path in directory.iterdir()}


def run_saipal(*args: str, home: Path | str | None = None, cwd: Path | str | None = None):
    """Run the CLI in a subprocess. Returns `(exit_code, stdout, stderr)`."""
    command = [python_exe(), "-B", str(SAIPAL_CLI)]
    if home is not None:
        command += ["--home", str(home)]
    command += list(args)
    completed = subprocess.run(
        command,
        cwd=str(cwd or REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return completed.returncode, completed.stdout, completed.stderr


def run_saipal_json(*args: str, home: Path | str | None = None):
    """Run the CLI with `--json` and return `(exit_code, payload, stderr)`."""
    code, out, err = run_saipal("--json", *args, home=home)
    try:
        payload = json.loads(out.strip())
    except ValueError:
        payload = None
    return code, payload, err


def make_home(tmp_path: Path, name: str = ".saipal") -> Path:
    home = Path(tmp_path) / name
    home.mkdir(parents=True, exist_ok=True)
    _declare_authority(home, authority_root(tmp_path))
    return home


#: The version every BOUND fixture claims. The authority directory is keyed by
#: it, because a release identity selects a directory *inside* the operator's
#: declared root (PAL-SESSION-03).
AUTHORITY_VERSION = "7.231.9"


def authority_root(tmp_path: Path) -> Path:
    """A real, on-disk release authority built from this checkout's protocol.

    A bundle cannot grant itself `BOUND`: the persisted binding is derived by
    re-reading the operator-declared authority and matching digests. So a test
    that needs a BOUND session needs a genuine authority, and the honest way to
    get one is to publish this checkout's own protocol surface as release
    `AUTHORITY_VERSION` and let the digest fall out of the bytes.
    """
    root = Path(tmp_path) / "protocol_authority" / "releases" / AUTHORITY_VERSION
    target = root / "saipal"
    if not (target / "REGISTRY.json").is_file():
        shutil.copytree(REPO_ROOT / "saipal", target, dirs_exist_ok=True)
    return Path(tmp_path) / "protocol_authority" / "releases"


def authority_digest(tmp_path: Path) -> str:
    """SHA-256 of the authority's REGISTRY.json -- the release proof material."""
    releases = authority_root(tmp_path)
    raw = (releases / AUTHORITY_VERSION / "saipal" / "REGISTRY.json").read_bytes()
    return hashlib.sha256(raw).hexdigest()


def _declare_authority(home: Path, releases: Path) -> None:
    """Write the home's config with that authority declared, once."""
    config = home / "config.json"
    if config.exists():
        return
    config.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "publication_mode": "STAGE_ONLY",
                "shadow_reviewed": False,
                "sink": {"kind": "termisai-file", "root": None},
                "protocol_authority": {
                    "git_repository": None,
                    "release_root": str(releases),
                    "snapshot_root": None,
                },
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _authority_for_home(home: Path) -> Path | None:
    """The declared release root of an already-configured home."""
    config = Path(home) / "config.json"
    try:
        declared = json.loads(config.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    root = ((declared.get("protocol_authority") or {}).get("release_root"))
    return Path(root) if isinstance(root, str) and root else None


def stamp_binding(home: Path, payload: object) -> object:
    """Point a fixture's release claim at this home's real authority.

    Fixtures carry placeholder digests (`"a" * 64`). A placeholder cannot be
    verified against anything, so leaving it in place would make every fixture
    PARTIAL and would test nothing. Stamping rewrites the claim to the authority
    the home actually declares -- and recomputes `session_sha256`, because the
    digest covers the protocol block.

    Only a bundle that already claims a release identity is stamped. A fixture
    with no version, or with a version this authority never published, is left
    exactly as written: those are the UNKNOWN/PARTIAL cases.
    """
    if not isinstance(payload, dict):
        return payload
    protocol = payload.get("protocol")
    if not isinstance(protocol, dict):
        return payload
    declared = protocol.get("registry_sha256")
    if not isinstance(declared, str) or len(declared) != 64:
        return payload
    releases = _authority_for_home(home)
    if releases is None:
        return payload
    registry = releases / AUTHORITY_VERSION / "saipal" / "REGISTRY.json"
    if not registry.is_file():
        return payload
    protocol["version"] = AUTHORITY_VERSION
    protocol["registry_sha256"] = hashlib.sha256(registry.read_bytes()).hexdigest()
    if "session_sha256" in payload:
        sys.path.insert(0, str(TOOLS_DIR))
        from saipal_engine import bundle as bundle_mod

        payload["session_sha256"] = bundle_mod.bundle_digest(payload)
    return payload


def golden_dir() -> Path:
    """`tests/golden_sessions/` -- the fixture corpus from 12_TEST_PLAN.md."""
    return REPO_ROOT / "tests" / "golden_sessions"


def fixture(name: str) -> Path:
    path = golden_dir() / name
    if not path.is_file():
        raise AssertionError(f"missing golden fixture {name}")
    return path


def load_fixture(name: str) -> dict:
    return json.loads(fixture(name).read_text(encoding="utf-8"))


def put_inbox(home: Path, *names: str) -> list[Path]:
    """Copy golden fixtures into a home's session inbox, preserving names.

    A fixture that claims a release identity is re-pointed at the home's real
    protocol authority on the way in (`stamp_binding`), because a placeholder
    digest cannot be verified and would silently make every fixture PARTIAL.
    Deliberately broken fixtures -- unparsable, or carrying a digest that does
    not match their own content -- are copied byte-for-byte: rewriting them
    would repair the exact defect they exist to prove.
    """
    inbox = Path(home) / "session_inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    placed = []
    for name in names:
        target = inbox / name
        raw = fixture(name).read_bytes()
        payload = _stampable(home, raw)
        if payload is None:
            target.write_bytes(raw)
        else:
            target.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        placed.append(target)
    return placed


def _stampable(home: Path, raw: bytes) -> dict | None:
    """The stamped bundle, or None when the fixture must be copied verbatim."""
    sys.path.insert(0, str(TOOLS_DIR))
    from saipal_engine import bundle as bundle_mod

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    declared = payload.get("session_sha256")
    if isinstance(declared, str) and declared != bundle_mod.bundle_digest(payload):
        return None
    return stamp_binding(home, payload)


def clear_inbox(home: Path) -> None:
    """Empty the inbox. Tests that stage one bundle at a time need this."""
    inbox = Path(home) / "session_inbox"
    if inbox.is_dir():
        for path in inbox.iterdir():
            if path.is_file():
                path.unlink()


def write_inbox(home: Path, name: str, payload: object) -> Path:
    """Write an arbitrary bundle into the inbox under the given filename.

    The binding claim is stamped against the home's authority for the same
    reason `put_inbox` does it: a test asking for a BOUND session must get one
    from real proof, not from a declaration.
    """
    inbox = Path(home) / "session_inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    target = inbox / name
    target.write_text(
        json.dumps(stamp_binding(home, payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return target


def sessions_of(home: Path) -> list[dict]:
    index_path = Path(home) / "sessions" / "index.json"
    if not index_path.is_file():
        return []
    return list(json.loads(index_path.read_text(encoding="utf-8"))["sessions"])


def write_sources(home: Path, sources: list[dict]) -> None:
    payload = {"schema_version": 1, "sources": sources}
    (Path(home) / "sources.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )


def tree_digest(root: Path | str) -> str:
    """One digest over every file's relative path and bytes.

    Used to prove a read-only command changed nothing. Sensitive to content,
    names, additions and deletions.
    """
    base = Path(root)
    digest = hashlib.sha256()
    for path in sorted(base.rglob("*")):
        if path.is_dir():
            continue
        digest.update(path.relative_to(base).as_posix().encode("utf-8"))
        digest.update(path.read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()


def load_registry_copy() -> dict:
    """A deep copy of the real registry, for mutation (red-control) tests."""
    sys.path.insert(0, str(TOOLS_DIR))
    from saipal_engine.registry import load_registry

    registry = load_registry()
    return json.loads(json.dumps(registry))


def next_unit(home: Path) -> dict | None:
    """The pending analysis carrier, or None when the analyst is idle."""
    code, payload, err = run_saipal_json("next", home=home)
    if code != 0:
        return None
    return (payload or {}).get("analysis_carrier")


def drift_candidate(unit: dict, **overrides) -> dict:
    """A well-formed DRIFT candidate answering the given carrier unit."""
    """A well-formed DRIFT candidate answering the given carrier unit."""
    payload = {
        "schema_version": 1,
        "verdict": "DRIFT",
        "unit_digest": unit["unit_digest"],
        "session_id": unit["session"]["session_id"],
        "episode_index": unit["episode"]["index"],
        "disposition_class": "ENGINE_ENFORCEMENT_GAP" if "change_target" not in overrides else (
            "PROTOCOL_DEFECT" if overrides.get("change_target") in
                ("CORE_PROTOCOL", "COMMANDS", "PHASE_CONTRACT", "SOURCE_CONTRACT",
                 "EXECUTION_POLICY") else "ENGINE_ENFORCEMENT_GAP"
        ),
        "reasoning": "the engine accepted a route outside the closed surface",
        "rule_ids": ["PAL-CMD-01"],
        "event_refs": [unit["episode"]["start_seq"]],
        "drift_class": "COMMAND_ROUTE_DRIFT",
        "severity": "P1",
        "confidence": "HIGH",
        "change_target": "ENGINE",
        "root_cause": "the closed command surface was not consulted",
        "challenge": {
            "prosecutor": "PAL-CMD-01 names the surface; the route is not in it",
            "defender": "the adapter may have normalized a user alias",
            "winner": "prosecutor",
            "loser_rejection": "the canonical token was recorded verbatim",
        },
        "alternatives": ["the user invoked a shell alias"],
        "addressed_defences": [
            entry["code"] for entry in unit.get("defence_surface") or []
        ],
    }
    payload.update(overrides)
    return payload


def submit_drift(home: Path, unit: dict | None = None, **overrides) -> dict:
    """Create a confirmed finding the sanctioned way: a semantic DRIFT submission.

    The authority pass made this the ONLY path to a finding, so every legacy
    test that used to get one from `continue` uses this helper instead. Pass a
    carrier `unit` to answer a specific episode, or omit it to answer the next
    pending unit.
    """
    if unit is None:
        unit = next_unit(home)
    assert unit is not None, "no pending analysis unit; run continue first"
    path = Path(home).parent / f"drift-{unit['session']['session_id']}-{unit['episode']['index']}.json"
    path.write_text(json.dumps(drift_candidate(unit, **overrides)), encoding="utf-8")
    code, out, err = run_saipal("--json", "submit", str(path), home=home)
    if out:
        try:
            payload = json.loads(out)
            err = (err or "") + "\n" + json.dumps(payload, indent=1)
        except (ValueError, TypeError):
            pass
    if code != 0:
        raise AssertionError(f"submit failed ({code}): {err}")
    return json.loads(out)


# --------------------------------------------------------------------------- #
# T-120 shared proof helpers: doctor parity, corpus truth, doctor/watch parity
# --------------------------------------------------------------------------- #


class DoctorParityMixin:
    """The required T-120 doctor acceptance matrix, as reusable controls.

    A. human `saipal doctor` exits 0 (the MARKHUNT E-772 red control)
    B. `saipal --json doctor` exits 0
    C. human and JSON agree on the truth-model fields
    D. missing authority renders cleanly
    E. no configured sources renders cleanly
    F. corrupt durable state reports INVALID/MIGRATION_REQUIRED without a
       traceback
    G. both variants are read-only (state digests before/after)
    """

    def _fresh_home(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = make_home(Path(self._tmp.name))
        return self.home

    def test_a_human_doctor_exits_zero(self) -> None:
        home = self._fresh_home()
        support_run = run_saipal("doctor", home=home)
        code, out, err = support_run
        self.assertEqual(code, 0, f"human doctor crashed: {err}")
        self.assertIn("indexed_records:", out)
        self.assertIn("current_sessions:", out)

    def test_b_json_doctor_exits_zero(self) -> None:
        home = self._fresh_home()
        code, payload, err = run_saipal_json("doctor", home=home)
        self.assertEqual(code, 0, err)
        self.assertTrue(payload)
        self.assertEqual(payload["command"], "doctor")

    def test_c_human_and_json_agree_on_truth_model(self) -> None:
        home = self._fresh_home()
        put_inbox(home, "conformant-cold.json")
        run_saipal("continue", home=home)
        code, payload, err = run_saipal_json("doctor", home=home)
        self.assertEqual(code, 0, err)
        code_h, out, err_h = run_saipal("doctor", home=home)
        self.assertEqual(code_h, 0, err_h)
        # The same truth model, not two hand-maintained renderers drifting.
        self.assertIn(f"indexed_records: {payload['indexed_records_total']}", out)
        self.assertIn(f"current_sessions: {payload['current_sessions_total']}", out)
        self.assertNotIn(
            "\nsessions: ", out, "the ambiguous pre-T-114 field must stay gone"
        )
        bindings = payload["current_binding_counts"] or {}
        for key in ("BOUND", "PARTIAL", "UNKNOWN"):
            self.assertIn(f"{key}={bindings.get(key)}", out)
        blockers = (payload.get("binding_blockers") or {}).get("blockers") or []
        for row in blockers[:5]:
            self.assertIn(f"binding_blocker: {row['reason']} x{row['count']}", out)

    def test_d_missing_authority_renders_cleanly(self) -> None:
        home = self._fresh_home()
        # make_home declares an authority; strip it to prove the none-configured
        # path renders without crashing on either surface.
        config_path = Path(home) / "config.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["protocol_authority"] = {
            "git_repository": None,
            "release_root": None,
            "snapshot_root": None,
        }
        config_path.write_text(json.dumps(config), encoding="utf-8")
        code, payload, err = run_saipal_json("doctor", home=home)
        self.assertEqual(code, 0, err)
        self.assertFalse(payload["protocol_authority_configured"])
        code_h, out, err_h = run_saipal("doctor", home=home)
        self.assertEqual(code_h, 0, err_h)
        self.assertIn("protocol_authority: none configured", out)
        self.assertIn("current binding: BOUND=0 PARTIAL=0 UNKNOWN=0", out)

    def test_e_no_configured_sources_renders_cleanly(self) -> None:
        home = self._fresh_home()
        code, payload, err = run_saipal_json("doctor", home=home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["sources_count"], 0)
        self.assertEqual(payload["sources_configured"], [])
        code_h, out, err_h = run_saipal("doctor", home=home)
        self.assertEqual(code_h, 0, err_h)
        self.assertIn("sources: 0", out)

    def test_f_corrupt_state_diagnosed_not_traceback(self) -> None:
        home = self._fresh_home()
        # Corrupt the recurrence ledger: doctor may diagnose it but must never
        # traceback, and the read-only surfaces report INVALID/MIGRATION_REQUIRED.
        recurrence = Path(home) / "recurrence.json"
        if not recurrence.is_file():
            recurrence.write_text("{}", encoding="utf-8")
        recurrence.write_text("{corrupt", encoding="utf-8")
        code_h, out, err_h = run_saipal("doctor", home=home)
        self.assertEqual(code_h, 0, err_h or out)
        self.assertNotIn("Traceback", err_h)
        code, payload, err = run_saipal_json("doctor", home=home)
        self.assertEqual(code, 0, err)
        from saipal_engine.recurrence import recurrence_status

        self.assertIn(recurrence_status(home), ("INVALID", "MIGRATION_REQUIRED"))

    def test_g_both_doctor_variants_are_read_only(self) -> None:
        home = self._fresh_home()
        put_inbox(home, "conformant-cold.json")
        run_saipal("continue", home=home)
        before = tree_digest(home)
        code, _out, err = run_saipal("doctor", home=home)
        self.assertEqual(code, 0, err)
        self.assertEqual(tree_digest(home), before, "human doctor mutated the home")
        code, _payload, err = run_saipal_json("doctor", home=home)
        self.assertEqual(code, 0, err)
        self.assertEqual(tree_digest(home), before, "json doctor mutated the home")


class CorpusTruthMixin:
    """#10: the required generation-truth corpus control."""

    def assert_corpus_truth_control(self) -> None:
        from saipal_engine.sessions import (
            find_session,
            load_index,
            save_index,
        )

        home = self._truth_home()
        # Session A generation 1: imported with the home's authority, then the
        # record's binding is demoted to PARTIAL (index surgery, the same
        # pattern the hardening suite uses to arm state). Session A generation
        # 2 = BOUND arrives as a COLD copy with a real authority digest.
        # Session B = UNKNOWN (no protocol claim, never stamped).
        put_inbox(home, "hot-partial.json")
        run_saipal("continue", home=home)
        status, index, _detail = load_index(home)
        record = find_session(index, "golden-hot-001")
        record["protocol"]["binding_status"] = "PARTIAL"
        record["protocol"]["confidence"] = "MEDIUM"
        save_index(home, index)
        clear_inbox(home)
        import copy

        gen2 = copy.deepcopy(load_fixture("conformant-cold.json"))
        gen2["session_id"] = "golden-hot-001"
        gen2["temperature"] = "COLD"
        write_inbox(home, "golden-hot-001-gen2.json", gen2)
        put_inbox(home, "unknown-protocol.json")  # session B = UNKNOWN
        run_saipal("continue", home=home)

        # Sanity: the corpus really is A gen1 PARTIAL, A gen2 BOUND, B UNKNOWN.
        status, index, _detail = load_index(home)
        by_key = {
            (rec["session_id"], int(rec.get("generation") or 0)): (
                rec.get("protocol") or {}
            ).get("binding_status")
            for rec in index["sessions"]
        }
        self.assertEqual(by_key.get(("golden-hot-001", 1)), "PARTIAL")
        self.assertEqual(by_key.get(("golden-hot-001", 2)), "BOUND")
        self.assertEqual(by_key.get(("golden-unbound-001", 1)), "UNKNOWN")

        code, payload, err = run_saipal_json("doctor", home=home)
        self.assertEqual(code, 0, err)
        self.assertEqual(payload["indexed_records_total"], 3)
        self.assertEqual(payload["current_sessions_total"], 2)
        current = payload["current_binding_counts"] or {}
        self.assertEqual(current.get("BOUND"), 1, "session A gen 2 is BOUND")
        self.assertEqual(current.get("UNKNOWN"), 1, "session B is UNKNOWN")
        self.assertEqual(current.get("PARTIAL"), 0, "gen 1 PARTIAL is history")
        # Historical generations keep their own explicitly named distribution.
        history = payload.get("binding_counts") or {}
        self.assertEqual(history.get("PARTIAL"), 1)
        self.assertEqual(history.get("BOUND"), 1)
        self.assertEqual(history.get("UNKNOWN"), 1)
        # And watch-status agrees with doctor on the current population.
        from saipal_analyst import supervisor as sup_mod

        corpus = sup_mod.watch_status(home)["corpus"]
        self.assertEqual(corpus["current_binding_counts"], {"BOUND": 1, "UNKNOWN": 1})

    def _truth_home(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        home = make_home(Path(self._tmp.name))
        return home


class DoctorWatchParityMixin:
    """#11: doctor and watch must agree on the CURRENT population."""

    def test_doctor_and_watch_agree_on_current_population(self) -> None:
        from saipal_analyst import supervisor as sup_mod

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        home = make_home(Path(self._tmp.name))
        put_inbox(home, "conformant-cold.json", "unknown-protocol.json")
        run_saipal("continue", home=home)
        code, payload, err = run_saipal_json("doctor", home=home)
        self.assertEqual(code, 0, err)
        corpus = sup_mod.watch_status(home)["corpus"]
        self.assertEqual(
            payload["indexed_records_total"], corpus["indexed_records_total"]
        )
        self.assertEqual(
            payload["current_sessions_total"], corpus["current_sessions_total"]
        )
        # Normalize the key set for comparison: watch omits zero classes when
        # no session ever carried them, doctor always names all three.
        doctor_counts = {
            key: int(value or 0)
            for key, value in (payload["current_binding_counts"] or {}).items()
            if int(value or 0) > 0
        }
        self.assertEqual(doctor_counts, corpus["current_binding_counts"])
        # Both must partition the same population: the counts sum to the
        # current total, not to history.
        current_sum = sum(
            int(v or 0) for v in (payload["current_binding_counts"] or {}).values()
        )
        self.assertEqual(current_sum, payload["current_sessions_total"])
