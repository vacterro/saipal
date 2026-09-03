# SAIPAL OPERATIONAL HANDOFF

## Architecture

SAIPAL is a stdlib-only forensic protocol observer, split into a deterministic
kernel (Layer A) and a replaceable analyst agent (Layer B). One `continue` cycle:
recover own state, dispatch configured sources through registered adapters into the
canonical inbox, import bundles into the session index, segment episodes, run
mechanical detectors and the signal generator, qualify findings through the
challenge and do-no-harm passes, and enqueue immutable numbered audits. Semantic
analysis is a separate loop: `next` hands out one bounded carrier, the analyst
reasons, `submit` absorbs exactly one structured candidate, and `report` states
the verdict with its coverage.

## Configured paths

- Runtime home: `.saipal/` (explicit `--home`, `SAIPAL_HOME`, or nearest ancestor).
- Sources: `.saipal/sources.json` (`id`, `kind`, `path`, `enabled`).
- Config: `.saipal/config.json` (publication mode, sink root, shadow flag).
- Session inbox: `.saipal/session_inbox/`. Session index: `.saipal/sessions/index.json`.
- Findings: `.saipal/findings/index.json`. Staged audits: `.saipal/audit/staging/`.
- Ledger, recurrence, telemetry: `.saipal/audit/`, `.saipal/recurrence.json`,
  `.saipal/telemetry.json`. Locks/leases: `.saipal/locks/`.
- Closed loop: `.saipal/closed_loop_links.json`.

## Source capabilities

Adapters in `ADAPTER_REGISTRY`: generic (canonical JSON), claude, codex,
opencode, termisai (JSONL), gemini. Dispatch is per-source isolated: a broken
source is rejected without wedging others. Raw sources are never mutated.
Termisai evidence contract: `docs/TERMISAI_EVIDENCE_CONTRACT.md`.

## Sink contract

External writes go through the validated file sink only (`kind: termisai-file`,
configured root, `audit/` + `MANIFEST.json` required). SAIPAL writes exactly the
numbered `audit/N.md`; private ledger, entries and counters stay in `.saipal/`.
Sink interface: `preflight`, `publish`, `verify`, `lookup_receipt`.
No arbitrary detector-selected paths.

## Commands

- `continue` / `cc` — one bounded cycle. `continue --drain` repeats bounded
  cycles until idle, blocked by a `CONFLICT`, or the safety valve trips.
- `next` — the next analysis carrier (one bounded semantic unit).
- `submit FILE|-` — absorb one analyst candidate; Layer B's only write path.
- `report` — the drift report: verdict, coverage, per-finding rule/owner/
  attribution/fix surface, staged audits.
- `status`, `sessions [N]`, `evidence SESSION EVENT`, `doctor` — read-only.
- `setup` — configure sources/sink/publication mode/protocol authority atomically.
- `disposition FILE.json` — idempotent closed-loop intake.
- `trigger` — coalescing pending-run request.
- `--version`, `--help`.

## Test proof

- `python -B tools/test_runner.py` — canonical suite (unit + validator), clean checkout.
- `python -B tools/validate.py` — protocol/registry drift gate.
- `python -B -m compileall tools` — bytecode compile check.
- Suite: 690 unit tests across waves A-I, the semantic analyst loop and the drift
  report; 271 validator checks.

## Measurements

- Session import, dispatch, analysis, submission, audit emission, drift reporting
  and disposition intake are all exercised through the real `tools/saipal.py` CLI.
- Version 0.2.0 marked the first operational closed loop; 0.4.0 adds the drift
  report surface and authority-derived protocol binding.

## Publication

Default `STAGE_ONLY`. `PUBLISH_ENABLED` requires `shadow_reviewed: true` and a
validated sink root, both in config. A sink failure keeps the finding staged,
logs `sink_publish_failure`, and retries on the next cycle. Collision never
overwrites: allocation skips occupied slots.

## Failure modes

- Corrupt STATE/sources/config: refusal, zero writes, preserved evidence.
- Sink unavailable: staged audit, pending next action, bounded retry.
- Budget hit: exact continuation checkpoint, resumable next cycle.
- Lease contention: session skipped, never double-analyzed.
- Broken source: per-source rejection, other sources proceed.

## Deferred provider adapters

Real TERMISAI structured-event export is not yet produced by TERMISAI; the
JSONL file contract is the documented current evidence surface. Producer-side
canonical export remains the preferred future design (T-011 option A).
