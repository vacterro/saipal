# SAIPAL CHECKPOINT — Wave I complete

All nine waves of the SAIPAL founding roadmap are implemented, green from a
clean checkout, and the live pipeline emits real immutable audits end-to-end.

## Current verification truth (T-120 contract)

This section is the SINGLE source of verification truth for the repository.
Every other document (README, handoff, audits) must either reference this
checkpoint or carry the SAME counts WITH the same checkpoint identity below.
Hand-maintained independent counters are forbidden: when the suite grows,
this is the one record to re-derive.

```yaml
checkpoint_id: T-164-VERIFY-2026-10-14-R13
commit: 90e72a8 (HEAD) plus T-164 exclusive shortcut ownership pal (cc collision removal)
method: |
  python -B -m unittest discover -s tools -p "test_*.py"   # from the checkout root
  python -B tools/validate.py
  python -B -m compileall tools
unittest_cases: 1821
validator_checks: 334
result: |
  Executed verdict in the certifying shell (R13, 2026-10-14): `python -B -m
  unittest discover -s tools -p "test_*.py"` -> Ran 1821 tests, OK (skipped=71),
  ZERO failures and ZERO errors; `python -B tools/validate.py` -> 334/334
  conformant; `python -B -m compileall -q tools` clean. The +11 cases over R12 are
  tools/test_wave_pal_shortcut.py (PAL shortcut controls A-I) and the negative
  control in tools/test_wave_a_continue.py. R12's own result text and numbers are
  preserved verbatim below; nothing is rewritten, only superseded the way R12
  superseded R11.
  Re-derived for the T-135 `/goal cpall` wave, which ADDED executable code
  (tools/saipal_engine/cpall.py, the canonical conflict-population API in
  carrier.py, the `cpall`/`goal` command surface) plus tools/test_wave_cpall.py,
  so the counts above replace the R5 record of 1680 cases / 316 checks. R5's own
  result text and numbers are preserved verbatim below; nothing is rewritten,
  only superseded the way R5 superseded R4.
  Executed verdict in the certifying shell (R7 re-derivation, 2026-09-28): Ran 1753
  tests -> 1705 pass, 31 ERROR, 17 skipped (zero failures). The +22 cases over R6 are
  the credential-policy controls (the shared predicate, the transport gate and the
  latch digest), two fairness controls (a 1,300-unit session must not starve a
  10-unit one, and the slice budget stays a checkpoint while it drains), the
  blocked-unit isolation controls (a blocked unit must not end a slice that still
  has eligible sessions), the terminal-state controls (an empty eligible set over a
  backlog that still lacks verdicts BLOCKS the family and names its population
  classes instead of slicing forever; a CONFLICT alone never unsettles the
  mechanical family) and the blocked-population triage controls (each class of
  unanalyzable session names the canonical command that moves it, or says no such
  command exists); the semantic wall R6 recorded was then repaired in the SOURCE
  instead of being worked around in the operator's config, and one R6-era control
  (test_wave_analyst_repair.test_15) was corrected to assert the refusal where it
  still applies. All 31 ERRORs are ONE environment condition, measured inside the
  test bodies and unrelated to the cpall surface: `os.symlink(...)` raises
  `OSError: [WinError 1314] A required privilege is not held by the client`,
  because this process token carries no SeCreateSymbolicLinkPrivilege (symlink
  creation refuses both under %TEMP% and under V:\). The PAL-WRITE-01
  symlink-confinement controls and test_wave_src011.Core002FinalNodeBoundToParent
  therefore could not execute; their sibling controls skip on the same
  capability, which is why the skip count is 17 rather than 11. They are NOT
  claimed green and NOT reclassified as skips -- the platform_limitations
  paragraph below already refuses to infer one platform's result from another's,
  so an unexecuted control is recorded as exactly that. `python -B tools/validate.py`
  -> 331/331 conformant; `python -B -m compileall tools` clean.
  R9 re-derived for the T-137 `/goal cpall` convergence wave (2026-09-29). The
  executable delta is one kernel guard: `cpall._classify_slice` now names the
  canonical way back (`authority enroll` + `rebind`) on a semantic family that is
  BLOCKED because the worker reports NO eligible unit while only binding-blocked
  units remain. Previously that reason said only "an operator decision ... makes
  them eligible again", which does not say WHICH decision and leaves re-running the
  slice -- the one action that cannot work -- as the reader's default. One new red
  control pins it
  (`SemanticWalls.test_a_purely_binding_blocked_slice_blocks_the_family`), written
  so the pre-fix tree fails it. The rest of the wave is TEST-SIDE only, and it
  removes 37 false ERRORs rather than changing any control's claim: three modules
  materialized a file symlink in `setUp` without checking that the host can create
  one, so on an unelevated Windows token (`os.symlink` -> WinError 1314) they
  reported 31 ERRORs in `test_wave_pal_write_01` / `test_wave_src011` plus 6 in
  `test_wave_e_audit` -- numbers that read like confinement failures while
  measuring only SeCreateSymbolicLinkPrivilege.
  `test_wave_e_audit._symlink_or_skip` is the sharpest form of it: the name
  promised a skip and the body re-raised. Symlink-dependent controls now SKIP on a
  host that cannot build the indirection (the same contract
  `PosixDescriptorLifetime` already used off POSIX); junction-based controls still
  EXECUTE, because a directory junction needs no privilege. This SUPERSEDES the "31
  ERROR ... NOT reclassified as skips" verdict of R7/R8, which measured the same
  environment condition but left it recorded as unknown coverage. The controls are
  still not claimed green -- they are unexecuted on this host, and that is what the
  skip says.
  Executed verdict in the certifying shell (R9, 2026-09-29): Ran 1778 tests, read
  as 1661 PASS + 65 skipped + ZERO failures + ZERO errors (measured twice, before
  and after the cpall guard; the 1000-operation bounded-fd junction control builds
  with `_winapi.CreateJunction` on THIS host's executed platform, not by inference
  from POSIX); `python -B tools/validate.py` -> 332/332 conformant;
  `python -B -m compileall tools` clean. Real-home evidence for the guard: one
  bounded slice (`goal cpall --slices 1`) advanced units 322 -> 326 on loopback
  `qwen3.5:9b` and reported `4 judged, 1 unit(s) blocked`, the objective staying
  ACTIVE over 17,842 eligible units.
  R10 re-derived for the T-139 `/goal cpall` wave (2026-09-30). The executable
  delta is one defect repair in `saipal_analyst/requeue.py`: `_apply` wrote the
  requeue history entry's `reason` straight from the operator's optional
  `--reason`, so the canonical bare command -- the one every triage surface
  names -- produced `reason: None` and then failed the journal's own closed
  schema check (`jobs._requeue_problems`: "requeues[0] needs a reason"). The
  effect was that a requeue the protocol had ADMITTED refused to persist, and
  because the refusal is a whole-journal save, the 4 admissible requeues in the
  same pass were all lost with it. The history entry now falls back to the
  decision that admitted the requeue ("semantic refusal requeued for one fresh
  attempt") when the operator supplies no note, so the closed field is never
  empty and an operator note still wins when given. One new red control pins it
  (`RequeueCore.test_an_unannotated_requeue_still_records_why_it_was_admitted`),
  written so the pre-fix tree fails it on the whole-journal refusal. The +1 case
  over R9 is exactly that control.
  Executed verdict in the certifying shell (R10, 2026-09-30): `python -B -m
  unittest discover -s tools -p "test_*.py"` -> Ran 1788 tests, OK (skipped=71),
  ZERO failures and ZERO errors; `python -B tools/validate.py` -> 332/332
  conformant; `python -B -m compileall tools` clean. Real-home evidence on this
  host, loopback `qwen3.5:9b`: the bare `analyst-requeue` -- the command the
  triage names, previously refused outright -- then wrote 4 units
  (`allowance: 1 fresh attempt(s) per unit`, `wrote: True`), and bounded
  `cpall` slices served them with real model calls, advancing units 326 -> 355
  with accepted receipts before the wall below re-appeared. The wall is NOT
  claimed repaired and is NOT protocol drift: the 9B model keeps returning
  candidate output the contract refuses (`BLOCKED_OUTPUT` -- "challenge is only
  admissible on a DRIFT verdict", "missing required field 'reasoning'",
  "candidate slice_index None does not match the packet's 0"), each after its
  single requeue allowance is spent. That is the wall R8 and R9 already
  measured on this home, and `analyst-requeue` answers it by design: a repeat
  refusal under an unchanged analyst config IS the answer. The objective reached
  `OPERATOR_BLOCKED` naming the wall, with 425 `BLOCKED_BINDING` units, 11
  isolated CONFLICT sessions and 5 `REMOTE_OUTCOME_UNKNOWN` jobs all refused
  BY NAME with their own canonical command.
  R11 re-derived for the T-145 `/goal cpall` wave (2026-10-01). The executable
  delta is the BLOCKED_BINDING triage split in `saipal_analyst/doctor.py`: the
  wall published ONE recovery command (`authority enroll` + `rebind`) for the
  whole class, but enrolling an authority root moves a unit only when its
  session carries an artifact a root can actually check (a full commit id, a
  registry digest or a tree fingerprint). `_binding_evidence_split` now
  partitions the class into `authority_verifiable` (enrol-movable) and
  `evidence_absent` (a bare version string or no protocol claim at all, which no
  authority root can change), the human `doctor` line prints the split, and the
  `BLOCKED_BINDING` caveat names `binding_evidence` -- so re-running the slice,
  the one action PAL-CPALL-04 forbids as a dead end, is no longer the reader's
  default on the 418-of-425 evidence-absent units measured on the real home. Two
  new golden fixtures back the controls as committed repository content:
  `version-only-protocol.json` (`protocol.version` only -> evidence-absent) and
  `unverifiable-commit.json` (`protocol.git_head` set -> enrol-movable); the +2
  cases over R10 are the two partition controls that pin them.
  Executed verdict in the certifying shell (R11, 2026-10-01): `python -B -m
  unittest discover -s tools -p "test_*.py"` -> Ran 1801 tests, OK (skipped=71),
  ZERO failures and ZERO errors; `python -B tools/validate.py` -> 332/332
  conformant; `python -B -m compileall tools` clean.
  R9 also recorded a real defect it did NOT repair, so it is not claimed green: the
  analyst worker charges its durable budget ledger
  (`.saipal/analyst/budget.json`) with a read-modify-write
  (`budgets.record_consumption`: `load_ledger` -> mutate -> `save_ledger`) from
  inside `investigate()`, and the supervisor fences `import_inbox` and `rebind`
  under `writer_fence(root)` while calling `investigate()` OUTSIDE any fence. A live
  `PermissionError: [WinError 5]` on the temp-file rename plus a stranded
  `.budget.json.<hex>.tmp` in this home are the observable residue, and a silently
  LOST charge is the failure mode the ledger exists to prevent. Filed as T-138,
  not fixed here: a durable cross-process writer boundary is its own ticket.
  R7 also carries the T-135 credential repair: the analyst credential requirement
  is an EGRESS requirement, owned by one predicate
  (`saipal_analyst.config.credential_verdict`) and enforced identically by the
  transport, the calibration preflight and `doctor` -- an unset `api_key_env` is
  inert on a loopback endpoint and still fails closed on a remote one, and the
  backend circuit latch is pinned to that verdict, so a stale AUTH open clears
  itself once the condition it was opened for stops holding. Evidence on the real
  home: latch `CLOSED`, and one bounded slice (`goal cpall --slices 1 --units 3`)
  advanced units 19 -> 22 with three accepted receipts on loopback `qwen3.5:9b` in
  216 s. No remote egress was approved and no credential was invented. A later
  two-slice run added no unit and said so instead of hiding it: two units were
  refused as inadmissible model output (`BLOCKED_OUTPUT` -- unknown candidate
  fields, invalid JSON) and one timed out (`BACKEND_RETRYABLE`). Small-model output
  compliance, not cpall, is what still limits that home; the objective stayed
  ACTIVE and every refusal is journaled. R7 then measured WHY that home cannot
  drain: a read-only tally through the worker's own classifier found 628 freshest
  sessions with ZERO runnable (433 terminal -- 425 of them binding-blocked -- 130
  provisional-disabled, 37 done, 11 stale), while the kernel still counted 18,100
  episodes without a receipt. Two source fixes followed: a blocked unit no longer
  ends a slice that still has eligible sessions, and the worker now reports its
  allocation answer structurally (`population_classes`, `no_eligible_unit`,
  `no_analyzable_unit`) so cpall maps an empty eligible set over a verdict-less
  backlog to a BLOCKED family naming those classes. Same real home after the fix,
  one bounded slice, 3 s, no model calls: `family semantic: BLOCKED - the worker
  reports no analyzable unit remains, yet 18100 unit(s) still lack a verdict (433
  terminal, 130 provisional disabled, 37 done, 11 stale)`, with
  `FAMILY_BLOCKED:semantic` in `unresolved`. The objective stays ACTIVE only
  because the mechanical family still has real work (4 sessions analysed per cycle,
  54 signals raised); it answers OPERATOR_BLOCKED when that family is DONE. R7 then
  removed the last thing standing between that home and a terminal answer: the
  mechanical family's settle condition was the cycle's `idle` boolean, which also
  folds in "a session is in CONFLICT" -- so with 11 CONFLICT sessions and ZERO
  analysis debt (measured: 630 records, none owing episodes) the family could never
  settle and the objective could never terminate. It now settles on the cycle's own
  debts (nothing imported, no indexed record owing locally processable episodes) and
  conflicts stay isolated operator items. Measured after: `goal cpall` on the real
  home reached `OPERATOR_BLOCKED` in 2 slices / 5 seconds (and, on a fresh
  invocation with a new objective id, in 1 slice), with `mechanical: DONE`,
  `semantic: BLOCKED` naming 433 terminal / 132 provisional-disabled / 37 done / 11
  stale sessions, `state_reason: operator authority required for: semantic; 11
  isolated conflict(s) stay operator-resolved`, and a `BLOCKED` report in
  `.saipal/cpall_reports.jsonl`.
  R8 re-derived for the T-136 refusal-requeue wave (2026-09-28), which added
  executable code (tools/saipal_analyst/requeue.py, the `analyst-requeue` command
  surface, the optional `budgets.max_requeues_per_unit`, the journal's `requeues`
  schema and the triage's per-class refusal split) plus tools/test_wave_analyst_requeue.py,
  so the counts above replace R7's 1753 cases / 331 checks.
  Executed verdict in the certifying shell (R8, 2026-09-28): Ran 1774 tests ->
  1726 pass, 31 ERROR, 17 skipped (ZERO failures). The +21 cases over R7 are the
  requeue contract: one fresh attempt per refused unit with the refused payload
  and paid-attempt identity CLEARED (so the next pass makes a real call instead of
  re-judging bytes already known to be inadmissible), admission only under CHANGED
  material or an explicit recorded `--force`, a durable allowance that a reload
  cannot reset, `--class` narrowing that can never silently drop an unknown refusal
  class, the named refusals for the neighbouring walls (`BLOCKED_BINDING`,
  `REMOTE_OUTCOME_UNKNOWN`, `STALE`, a session that left the index), the journal
  schema validation for the history, the live-worker refusal and the dry run that
  writes nothing, plus the triage control that now asserts the canonical command
  where R7 asserted an explicit gap. All 31 ERRORs are the SAME single environment
  condition recorded in R7, measured inside the bodies and unrelated to this wave:
  `os.symlink(...)` raises `OSError: [WinError 1314] A required privilege is not
  held by the client` because this process token carries no
  SeCreateSymbolicLinkPrivilege, so those PAL-WRITE-01 / src011 confinement controls
  remain recorded as NOT EXECUTED, never green and never reclassified as skips.
  `python -B tools/validate.py` -> 332/332 conformant;
  `python -B -m compileall tools` clean.
  R8 also carries the real-home evidence for the requeue: the triage previously
  named `BLOCKED_OUTPUT 8` as the one class with NO canonical action. Measured on
  the real home, those 8 journaled refusals are 4 candidate refusals
  (`BLOCKED_OUTPUT` -- unknown candidate fields, invalid JSON), 3 exhausted
  transport retries (`BACKEND_RETRYABLE_EXHAUSTED`) and 1 historical credential
  refusal (`BACKEND_AUTH`) -- three classes under one label, which is why the
  triage now publishes `refusal_classes` beside the count. `analyst-requeue`
  re-opened all 8 (allowance 1 each, digest 52b58a13909d, `wrote: True`) while
  refusing the 425 `BLOCKED_BINDING` units BY NAME with the authority command, and
  a bounded one-unit slice afterwards served one of them with a REAL model call
  (`investigator_calls: 1`, latency 120.094 s, `timeouts: 1`): the unit moved to
  `RETRY_WAIT` with `BACKEND_RETRYABLE` -- recoverable, not lost -- and the
  allocator's own population report went from `RUNNABLE_FINAL: 0` to
  `RUNNABLE_FINAL: 7` on that home. What limits that unit is now the config's
  120 s client timeout against a 9B model, not the contract and not a silent spin.
platform_executions: |
  Windows: EXECUTED (primary platform; win32, Python 3.11.9, x64).
  1753/1753
  discovered by the certifying shell as 1705 PASS + 31 ERROR (symlink privilege
  absent, WinError 1314 -- see `result:`) + 17 skipped, zero failures; validate.py
  331/331 conformant; compileall clean. Re-run as R7 against the T-135 code tree
  after (a) the credential requirement became one predicate shared by the
  transport, the calibration preflight and `doctor`, and (b) the semantic family
  produced real accepted receipts on the real home; only WAVE_I_CHECKPOINT.md
  itself was re-derived afterwards, and validate.py was re-run on the final tree.
  [R5 measurement, kept as history] 1680/1680
  unittest OK (11 skipped), validate.py 316/316, compileall clean.
  [R5 result, kept as history]
  ALL PASS (11 platform-skipped) on the executed platform. Re-derived as R5 for
  the 0.4.3 release tree after the public-surface showcase wave (README rebuilt,
  docs/ added, localized mirrors marked deferred, handoff relocated to
  docs/internal/). No executable code changed relative to R4, so counts are
  unchanged; APPENDS to T-130-VERIFY-2026-09-18-R4 and does not rewrite it.
  Supersedes it as the CURRENT truth because its POSIX line is stale (see
  platform_executions).
  POSIX: UNVERIFIED-FOR-CERTIFICATION (partial, Cygwin -- NOT Linux-certified).
  FOCUSED-EXECUTED
  on a genuine POSIX interpreter on the dev host (Cygwin 3.6.10, Cygwin Python
  3.12.12, os.name=posix): the single-process canonical discovery ran to
  completion with NO descriptor exhaustion (1680 tests; zero
  'Too many open files' -- the T-127/SRC-006 fd-leak defect is measurably
  repaired), validate.py PASS (314 checks as measured there; the gate has
  since grown to 316 on the release tree), compileall clean, and the focused controls
  passed: PosixDescriptorLifetime 6/6 incl. the 1000-operation bounded-fd
  control, test_wave_unattended 35 OK, test_wave_lock_ownership 30 OK,
  test_wave_e_audit 33 OK (1 skip). One REAL failure:
  test_wave_pal_write_01.AtomicWriteParentSwapRace -- root cause is the HOST,
  not a proven Linux defect (Cygwin openat re-resolves the path instead of
  pinning the inode, so the parent-swap refusal cannot fire there; measured,
  see LOG E-1020). Real Linux full-suite certification therefore remains
  DEFERRED VERIFICATION DEBT (T-127 BLOCKED_EXTERNAL) and is NOT claimed green.
  Evidence: .saipen LOG E-1020/E-1021/E-1026; T-132 gate-execution record.
platform_limitations: |
  The two platforms do not share one mechanism and neither result may be
  inferred from the other.

  Windows (executed): no directory fds in stdlib Python, so the boundary is
  strongest-practical -- the home and every parent level are re-verified by the
  non-following reparse probe immediately before each I/O, every
  symlink/junction/reparse indirection refuses, and the final lock node is
  classified with lstat + the reparse attribute before the O_EXCL create. The
  residual window is a non-reparse (delete+recreate) namespace swap between the
  last probe and the I/O, which cannot be closed without handle-based APIs
  stdlib does not expose. CORE-001 binds the active WriterFence to the physical
  home identity (`_ACTIVE_FENCE_IDENTITY` + `_assert_active_fence_identity`) at
  `_open_confined_dir` and reentrant `WriterFence.acquire`. CORE-002 classifies
  the atomic-write final node fd-relatively where a directory fd exists and by
  the reparse-verified path otherwise.

  POSIX (focused-executed on Cygwin; NOT Linux-certified): the mechanism is a
  fully descriptor-relative boundary -- the COMPLETE absolute home path is
  walked component-by-component from the filesystem root with per-level
  O_NOFOLLOW|O_DIRECTORY, the parent walk, O_NOFOLLOW|O_EXCL create and
  dir-fd-relative rename/unlink all run under that fd, and every owned
  descriptor has exactly one close path in a `finally` (`_close_fd`). The
  descriptor-lifetime defect class is repaired and evidenced there; the
  parent-swap race refusal is certified on REAL LINUX only, because Cygwin
  openat semantics diverge. Re-derive on a Linux checkout before quoting this
  block for Linux.
```

### Corrective successor -- T-127 (source receipt SRC-006)

An independent execution of the previous tree on a real POSIX runtime measured
deterministic linear descriptor growth (100 `atomic_write_bytes` took the fd
count 4 -> 104, 100 `confined_append_line` 104 -> 204, 100 `confined_mkdir`
204 -> 304, and 100 `confined_create_exclusive` + `confined_unlink` cycles
304 -> 504, until discovery died with `OSError: [Errno 24] Too many open
files`) and reproduced three further boundary bypasses: `append_event`
bootstrapped a home through an indirection, trigger claim/release mutated home
state with raw `os.replace`/`os.unlink`, and stale-takeover cleanup read and
deleted an unbound absolute claim path.

That invalidated the CROSS-PLATFORM closure claim -- not the Windows result.
T-125 history, its BOARD row and E-951 are untouched; the corrective evidence is
APPENDED. T-127 (P0) repaired the descriptor ownership contract, removed
`append_event`'s ownership of home bootstrap, bound the confinement root to the
complete lexical chain, routed trigger claim/release through the confined
primitives, and bound the stale-takeover cleanup to the verified physical parent
that the confined rename moved the claim into. The counts above are re-derived
from THIS tree; T-125-VERIFY-2026-09-16-R3 must not be quoted as evidence of it,
and T-126 remains parked pending POSIX execution of the corrected tree.

### Closure-chain control and the T-125 repair -- E-959

T-125 reached `## DONE` with every FIELD a canonical completion writes
(`closure_mode`, `owner`, `claim_time`, a `verify:` line) and no canonical
finish record at all: its phase chain stopped at VERIFY (E-948) and E-950/E-951
closed it by hand. Nothing caught it, and the two mechanisms that come closest
cannot see it -- the SAIOPS `[gate-closure]` check inspects finish events that
EXIST, so an absent one is invisible to it, and the lifecycle repair planner
judges FIELDS (it emits no atom for a field-complete record; measured on this
tree: 0 atoms, `T-125` is not legacy generation at frontier T-109).

The control now lives in `tools/validate.py` as `[closure chain]`: every
`## DONE` record of the current generation (at/above the project's own
`closure_mode` frontier, T-109) must carry its own `(from SHIP)` finish record
-- or an append-only ATTESTATION naming the chain actually reached. The repair
is deliberately NOT a synthesized gate: E-959 is a now-dated `DEC` that says
what happened, disclaims gate authority in its own text (`not gate proof`),
names the corrective successor that owns the consequences (T-127, source
receipt SRC-006), and writes no phase event, no `closure_mode` and no
historical line. The check fails a record whose attestation is undeclared, is
stale (it answers a gap that has since closed, or none at all), or names Work
that is on no BOARD row. `test_wave_closure_chain.py` pins all of it, including
the refusal of a `RUN` line and the legacy boundary.

Re-derive after every material change and update ONLY this block plus any
README line that carries the checkpoint id. A count without the
`checkpoint_id` it came from is not a fact, it is a decoration.

## How to verify

```bash
python -B tools/test_runner.py                 # full canonical suite (sandboxed)
python -B -m unittest discover -s tools -p "test_*.py"   # canonical discovery
python -B tools/validate.py                    # protocol/registry checks
python -B tools/saipal.py continue             # one bounded cycle; `--json` for machines
python -B tools/saipal.py status
python -B tools/saipal.py next
python -B tools/saipal.py pal                   # alias for continue

# Force a real audit emission: drop a session with an illegal phase transition
# into the inbox and run `pal`. SAIPAL writes audit/staging/N.md and links the
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

Test counts as of the founding checkpoint (HISTORICAL — superseded by the
Current verification truth block above): **225 unittest cases** (discover -s
tools -p test_*.py), **150 validator checks**, all PASS. Live audit emission verified by
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

- SAIPEN v7.231.9 at a sibling local checkout (path withheld from the public surface).
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

As of that checkpoint (HISTORICAL — superseded by the Current verification
truth block above): **241 unittest cases** (incl. `test_wave_next1.py`),
**157 validator checks**, all PASS from a clean sandbox.
