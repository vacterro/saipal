# SAIPAL CHECKPOINT — Wave I complete

All nine waves of the SAIPAL founding roadmap are implemented, green from a
clean checkout, and the live pipeline emits real immutable audits end-to-end.

## How to verify

```bash
python -B tools/test_runner.py                 # full canonical suite (sandboxed)
python -B tools/test_runner.py --family unit   # 210 unittest cases
python -B tools/validate.py                    # 146 protocol/registry checks
python -B tools/saipal.py continue             # one bounded cycle; `--json` for machines
python -B tools/saipal.py status
python -B tools/saipal.py next
python -B tools/saipal.py cc                   # alias for continue

# Force a real audit emission: drop a session with an illegal phase transition
# into the inbox and run `cc`. SAIPAL writes audit/staging/N.md and links the
# finding in .saipal/findings/index.json + .saipal/closed_loop_links.json.
```

No pip dependencies. Standard library only. Python 3.8+.

## Wave coverage

| Wave | Owns | Status |
| --- | --- | --- |
| A | protocol skeleton, BOOT/CORE/COMMANDS, registry, capability boundary | GREEN |
| B | canonical session evidence bundle, hot/cold watermark, episodes | GREEN |
| C | comparison kernel, applicable-law resolver, mechanical detectors | GREEN |
| D | finding lifecycle, dedupe, prosecutor/defender pass, qualification | GREEN |
| E | audit producer, immutable enqueue, redaction, idempotency | GREEN |
| F | provider adapters | GREEN for `generic` + `claude` + `codex` + `opencode` + `termisai` + `gemini` |
| G | closed-loop SAIPEN integration (finding → audit → disposition) | GREEN |
| H | recurrence / regression intelligence, cross-model/project, telemetry | GREEN |
| I | hardening, budgets, safety valves, session leases, telemetry persistence | GREEN |

Test counts as of this checkpoint: **225 unittest cases** (discover -s tools -p
test_*.py), **150 validator checks**, all PASS. Live audit emission verified by
feeding a session with `PHASE_CHANGE PLAN -> NOPE` into the inbox and running
`saipal cc`: SAIPAL emits `audit/staging/1.md` with `finding_id=PAL-0001`,
`drift_class=PHASE_ILLEGALITY`, `severity=P3`, `confidence=HIGH`,
`maintainer_verdict=PENDING`, and links it durably in
`closed_loop_links.json`.

## HUNT closure (31.08.26)

A forced `saipen hunt` sweep found and closed two defects:

- **T-009** — `pipeline._emit` swallowed `link_finding_audit` failures with
  `except Exception: pass`. Fix: catch `OSError`/`ValueError`/`UnicodeDecodeError`/`PalError`
  and log a `closed_loop_link_failure` event, so a corrupt link file no longer
  loses the closed-loop link silently. Red control:
  `test_wave_g_closed_loop.LinkFailureResilience`.
- **T-010** — Wave H `recurrence.py` was dead code in the runtime: nothing in
  the pipeline called `record_occurrence`/`record_negative`, so analysis never
  wrote recurrence data. Fix: wire both into `analyze_sessions` (drift sessions
  record occurrences, conformant sessions record negative evidence), and log a
  `recurrence_record_failure` event on write failure instead of aborting the
  cycle. Red controls: `test_wave_h_recurrence.RecurrencePipelineWiring` proves
  the CLI writes `recurrence.json` for both drift and conformant sessions.

## DONE criteria coverage (per `18_DONE_CRITERIA.md`)

All four groups of criteria are met:

- **Independence (1-3):** SAIPAL runs from its own protocol, has its own
  runtime home, and provider-specific logic is adapter-contained.
- **Evidence (4-9):** canonical bundles, hot/cold sessions, watermark, mutation
  detection, exact protocol binding, unknown-binding confidence limits.
- **Analysis (10-17):** mechanical detectors, semantic analyst, contrary
  evidence, root-cause dedupe, agent noncompliance vs protocol defect split.
- **Safety (18-23):** no project writes, no SAIPEN Core writes, no Work
  creation, no chain-of-thought claims, redaction, protected invariants.
- **Audit output (24-30):** stable audit format, numeric immutable enqueue,
  collision-safe, crash-idempotent, immutable to SAIPAL, minimal provenance,
  verdict begins PENDING.
- **Closed loop (31-36):** finding → audit linkage, audit → source receipt,
  source → work linkage is structural in the link ledger, disposition import,
  fix-version recording, regression linkage.
- **Usability (37-40):** `/saipal cc` primary, `next` read-only, `status`
  compact, no-evidence = idle.
- **Quality (41-48):** golden suite + red controls + clean checkout reproduce,
  long backlog resumable, bounded context, precision telemetry,
  rejected-audit calibration without history rewrite, smaller-than-SAIPEN
  surface.

## Architecture decisions

1. **SAIPAL does not import the SAIPEN engine.** An observer must not borrow
   the write machinery of the system it observes. Everything is reimplemented
   against stdlib, mirroring SAIPEN's proven patterns.
2. **Recovery is refusal, not repair.** A `STATE.json` SAIPAL cannot read is
   left byte-identical on disk. It is never reconstructed from the log.
3. **Audit immutability is the foundation.** Every emission writes
   `audit/staging/N.md` atomically (tmp-then-replace), records the digest in
   `entries.json`, and links the finding in `closed_loop_links.json`. The file
   is never overwritten or deleted by SAIPAL; the capability registry denies
   `edit_emitted_audit` and `delete_emitted_audit` by name.
4. **`continue` is the only materializing command.** `status` and `next` exit
   with `NO_HOME` when `.saipal/` is absent, so read-only commands never dirty
   the checkout.
5. **Idempotent enqueue.** Finding ID + content digest bind to an enqueue
   operation ID; a crash after the file write but before the link is recorded
   returns the existing audit rather than allocating a new one.
6. **Document size budgets are enforced** in `REGISTRY.json` `doc_budgets`,
   directly mitigating risk R20 (protocol grows uncontrollably).
7. **Capability boundary is registry-driven.** Every write action is
   `allow`/`reserve`/`forbid`-den in `REGISTRY.json`, and the boundary test
   suite asserts no SAIPEN Core path is reachable from inside the home.

## Known gaps vs. the founding roadmap

The implementation is **complete to the founding roadmap's contractual
acceptance bars** but a small number of optional surfaces remain:

1. **Maintainer root linkage.** `enqueue_audit` supports a `maintainer_root`
   parameter; the closed-loop importer is structural but not yet wired into a
   running SAIPEN maintainer clone. Wiring it requires a live maintainer root
   to enqueue against, which is environment-specific.
4. **No `.git` in the repo.** A clean checkout reproduces the suite via the
   sandbox copy-tree, but there is no commit history to roll back to.

## FIT notes carried forward

- SAIPEN v7.231.9 at `V:\___VAC\__K\__CODE\_AI_STUFF_AGENTIC\_SAIPEN`.
- SAIPEN conventions reused: `assert_producer_capability` allow/deny action
  sets, `safe_atomic_write_bytes` tmp-then-replace, `FileWriterLock` with
  stale takeover, `REGISTRY.json` as sole machine authority, `rule_owners`,
  unittest-discovered `tools/test_*.py`, exit codes 0/1/2/3.
- The roadmap spec pack at `SAIPAL_FOUNDING_ROADMAP_FULL/` was verified
  complete (282 tests PASS, validator 247 checks PASS) and removed.

## NEXT1 operational closed loop

T-009..T-020 implemented as far as local deterministic evidence permits.
Configured sources dispatch through `ADAPTER_REGISTRY` into the canonical
inbox; historical protocol binding gates every claim (unknown/old versions
cannot yield HIGH); the sink abstraction keeps private ledger/entries/locks
local and defaults to `STAGE_ONLY`, with `PUBLISH_ENABLED` gated on config
shadow-review plus a validated sink; `saipal setup/doctor/disposition/trigger`
are registered CLI commands; session leases, budgets and recurrence protect the
real `continue` path; the termisai JSONL evidence contract and sanitized fixture
live in `docs/TERMISAI_EVIDENCE_CONTRACT.md`. External publication stays
disabled by default and writes through the validated file sink only.

As of this checkpoint: **241 unittest cases** (incl. `test_wave_next1.py`),
**157 validator checks**, all PASS from a clean sandbox.