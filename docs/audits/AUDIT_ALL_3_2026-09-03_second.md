# _SAIPAL — Audit Handoff

RUN_ID: acb-mtlw6abk-b8ad2f120ad4417fab5c
GENERATED_AT: 2026-09-03T22:39:26.500761
PROJECT_NAME: SAIPAL
TARGET: /mnt/data/_SAIPAL_03.09.26-T22-00-57.zip -> extracted project root /mnt/data/saipal_audit_core
BASELINE: VERSION 0.3.0; archive SHA256 177c3aeb64ec099042148ee20500be4612352f5720aed192fad52ca3756bf5a5; AUDAPACK manifest created_at 2026-09-03T22:00:58.321018
GIT_CONTEXT: ABSENT - archive contains no .git; _AUDAPACK_MANIFEST.json records empty git branch/head
SAIPEN_CONTEXT: STALE - .saipen/STATE.md remains BUILD/T-055, updated 2026-09-02T17:52:34Z with last_event 255 while .saipen/LOG.md contains E-256; BOARD carries older audit backlog T-061..T-067; live implementation was treated as authoritative
TOTAL_TICKETS: 24
STATUS: AUDIT_ALL_3: COMPLETE

## Summary of Wave Audits
- Wave 1 (Core): 5 tickets (baseline: VERSION 0.3.0; archive SHA256 177c3aeb64ec099042148ee20500be4612352f5720aed192fad52ca3756bf5a5; AUDAPACK manifest created_at 2026-09-03T22:00:58.321018)
- Wave 2 (Second Wave): 13 tickets (baseline: VERSION 0.3.0; archive SHA256 177c3aeb64ec099042148ee20500be4612352f5720aed192fad52ca3756bf5a5; AUDAPACK manifest created_at 2026-09-03T22:00:58.321018)
- Wave 3 (Performance): 6 tickets (baseline: VERSION 0.3.0; archive SHA256 177c3aeb64ec099042148ee20500be4612352f5720aed192fad52ca3756bf5a5; inspected tree aggregate SHA256 d09bc3994ab2d6daac3630d92c4563ac0e060f2b51f621f28c7411b283ee7082; AUDAPACK manifest created_at 2026-09-03T22:00:58.321018)

---
## 01 — AUDIT CORE
PROJECT_NAME: SAIPAL
DATE_TIME: 2026-09-03T22:01:00+03:00
CAMPAIGN_PROFILE: quick3
CAMPAIGN_PROFILE_VERSION: 1.0.0
CAMPAIGN_RUN_ID: acb-mtlw6abk-b8ad2f120ad4417fab5c
CAMPAIGN_MANIFEST_SHA256: 97d9d053e37e6597a8559008911f84b28f799f326a97c69ebc5b304690defa72
WAVE_ID: core
WAVE_INDEX: 1
WAVE_COUNT: 3
WAVE: AUDIT CORE
TARGET: /mnt/data/_SAIPAL_03.09.26-T22-00-57.zip -> extracted project root /mnt/data/saipal_audit_core
BASELINE: VERSION 0.3.0; archive SHA256 177c3aeb64ec099042148ee20500be4612352f5720aed192fad52ca3756bf5a5; AUDAPACK manifest created_at 2026-09-03T22:00:58.321018
PREVIOUS_WAVE_SHA256: NONE
GIT_CONTEXT: ABSENT - archive contains no .git; _AUDAPACK_MANIFEST.json records empty git branch/head
SAIPEN_CONTEXT: STALE - .saipen/STATE.md remains BUILD/T-055, updated 2026-09-02T17:52:34Z with last_event 255 while .saipen/LOG.md contains E-256; BOARD carries older audit backlog T-061..T-067; live implementation was treated as authoritative
AUDIT_SCOPE: entrypoint/continue lifecycle; canonical bundle validation/intake; session identity/generations; protocol historical binding and authority resolution; analysis checkpoint/budget state; lease lifecycle; state/idle/drain transitions; registry/manifest contracts; focused regression tests
TEST_STATUS: TEST_FAILED
TEST_LIMITATION: NONE
VERIFIED_INSTEAD: tools/validate.py PASS with 270 checks; tools/test_wave_b_binding.py ran 24 tests and FAILED 2; isolated temporary-home reproductions verified binding self-promotion, authority-root escape, ignored Git authority, cross-generation dedup failure, analysis budget/cursor failure, SessionLease path crash/leak, and premature --drain termination
STATUS: AUDIT_CORE: COMPLETE
TICKETS: 5
HANDOFF: IMPLEMENTATION_AGENT
COVERAGE_INSPECTED: VERSION; README.md; _AUDAPACK_MANIFEST.json; .saipen/{STATE.md,BOARD.md,LOG.md}; saipal/{CORE.md,SESSIONS.md,COMMANDS.md,MANIFEST.json,REGISTRY.json}; tools/saipal.py; tools/saipal_engine/{bundle.py,config.py,dispatcher.py,historical.py,inbox.py,sessions.py,pipeline.py,hardening.py,state.py}; tools/{validate.py,test_runner.py,test_wave_b_binding.py,test_wave_b_inbox.py,test_wave_i_hardening.py,pal_test_support.py}; canonical fixtures used by Wave B
COVERAGE_DEFERRED: deep provider-adapter behavior; maintainer sink/disposition/closed-loop crash recovery; ownership-fencing races; trigger race/torn-log handling; performance/scaling surfaces reserved for later waves
CROSS_WAVE_REFERENCES: NONE from this campaign run. Existing .saipen BOARD entries T-061/T-063/T-064 independently overlap CORE-001..CORE-004 below; they were context only, not accepted as evidence. T-055 is the currently active implementation and is independently covered by CORE-005.
RESIDUAL_UNCERTAINTY: archive provenance cannot be tied to a Git commit because .git is absent; no external authorities/services were contacted; defects below are demonstrated against the supplied archive itself
ACB_CHAIN_RECEIPT: startcore-mtlw4t9v-e10a53ab15a4

[P0] [CORE-001] tools/saipal_engine/{sessions.py:new_record,binding_proof_of,binding_status_of; inbox.py:import_inbox; dispatcher.py:dispatch_sources} — historical binding trust boundary is bypassable and authority resolution is inconsistent

EVIDENCE:
- Contract: saipal/CORE.md:52-56 says proof levels are executable, not caller assertions, and EXACT_COMMIT must be resolved through configured protocol authority.
- Contract: saipal/SESSIONS.md:85-97 says proof_level is derived by Layer A and is never granted by bundle-declared binding_status.
- Contract: saipal/SESSIONS.md:10 and 128-134 explicitly permit canonical bundles to be dropped directly into .saipal/session_inbox/.
- sessions.py:192-202 trusts any incoming protocol.binding_status and copies it into the session record instead of recomputing proof.
- sessions.py:427-440 binding_status_of() likewise returns an existing binding_status verbatim despite its own docstring saying status is derived from proof.
- sessions.py:368-370 reads only release_root and snapshot_root from authority. The configured git_repository is ignored; dispatcher.py:80 therefore cannot establish EXACT_COMMIT through normal configured authority.
- config.py:104-126 and COMMANDS.md:122-127 explicitly define git_repository as an operator-owned authority root.
- Reproduction with a real temporary Git repository and its real 40-hex HEAD:
  authority={"git_repository": <repo>}
  binding_proof_of({"git_head": <existing HEAD>}, authority=...)
  -> {"proof_level":"UNKNOWN","binding_status":"UNKNOWN","reason":"git commit is syntactically valid but unverified"}.
- sessions.py:269-303 builds release authority path as Path(release_root) / version without validating version or enforcing containment.
- historical.py:231-244 performs the missing _SAFE_VERSION validation on the corresponding historical-reader path, proving the two authority implementations disagree.
- Reproduction: release_root=<tmp>/releases, valid registry placed at sibling <tmp>/outside/saipal/REGISTRY.json, protocol.version="../outside" with its real SHA-256.
  binding_proof_of(...) -> {"proof_level":"RELEASE_REGISTRY","binding_status":"BOUND",...}.
  A bundle-controlled version therefore escapes the configured release authority and is accepted as authoritative.
- Direct canonical inbox reproduction with git_head="deadbeef", binding_status="BOUND", proof_level="UNKNOWN", no authority:
  import_inbox() -> new_sessions=1;
  persisted protocol remains binding_status="BOUND", proof_level="UNKNOWN".
  validate_index() accepts this contradictory pair.
- tools/test_wave_b_binding.py FAILED:
  test_declared_status_cannot_self_promote expected UNKNOWN but received BOUND.
- The same test module contains a contradictory legacy positive at lines 150-183: CURRENT declares BOUND in raw protocol and expects historical_applicability() to honor it without providing authority/preverified status.

DEFECT:
The historical-law boundary is not closed. Dispatcher-produced bundles are assumed to be trusted even though the documented canonical-inbox path bypasses dispatcher; raw bundle prose can therefore self-promote a session to BOUND. At the same time, legitimate configured Git authority is ignored, while release authority can be escaped through a transcript-controlled version path. This permits false historical attribution and high-confidence protocol claims against evidence that Layer A never independently bound. It is a fundamental forensic-correctness failure.

REPAIR:
- Centralize binding derivation at the canonical Layer-A intake boundary. new_record/import_inbox must always derive binding_status/proof_level from independent evidence; never preserve a bundle's declared status as proof.
- Treat dispatcher binding fields as hints/evidence, not a privileged trust marker, unless an explicit internal verified-proof object exists that cannot originate in canonical input.
- Wire authority["git_repository"] into EXACT_COMMIT verification using the same authority-owned Git resolver used by HistoricalRuleReader.
- For RELEASE_REGISTRY, validate version with the same safe identity rule as historical.py and resolve only a direct authority-owned release identity. Enforce resolved-path containment under release_root before reading.
- Keep CAPTURED_FINGERPRINT under the same centralized resolver semantics.
- Strengthen validate_index(): impossible combinations such as BOUND+UNKNOWN or BOUND+INSTALLED_RELEASE must be rejected. BOUND must correspond to an independently defensible proof level.
- Make binding_status_of() derive from evidence by default. If callers need an already-verified stored status, represent that distinction explicitly instead of inferring trust from the presence of a string field.
- Update contradictory Wave-B tests so raw protocol assertions never self-certify; tests requiring a bound current session must provide an authority resolver or an explicit trusted-record input.

VERIFY:
- Direct-inbox bundle declaring BOUND with no authority imports only as UNKNOWN/PARTIAL according to independently verified evidence.
- A fake/abbreviated/full-but-missing commit never becomes BOUND.
- A real full commit inside configured git_repository becomes EXACT_COMMIT/BOUND through normal dispatcher and direct-inbox intake.
- version="../outside", absolute paths, separators, drive syntax and equivalent traversal identities never cause reads outside release_root and never produce BOUND.
- Correct release and snapshot identities inside configured roots still bind.
- validate_index rejects BOUND+UNKNOWN and other impossible proof/status pairs.
- `python -B tools/test_wave_b_binding.py` passes after replacing the stale self-certifying positive test with authority-backed evidence.
- Add end-to-end red controls for both dispatcher and direct canonical-inbox paths.

[P1] [CORE-002] tools/saipal_engine/{sessions.py:find_session,already_imported; inbox.py:import_inbox} — session identity checks only the first generation, breaking COLD idempotence

EVIDENCE:
- Contract: saipal/SESSIONS.md:27-29: duplicate digest does not create a second session; changed digest creates a new generation.
- Contract: saipal/SESSIONS.md:73-74: COLD unchanged digest means skip; changed digest means new generation.
- sessions.py:155-159 find_session() returns the first record matching session_id.
- sessions.py:173-177 already_imported() examines only the imports attached to that one record.
- inbox.py:82 obtains that first record and lines 90-97 dedupe/new-generation decisions are based on it.
- Deterministic reproduction:
  conformant-cold.json -> new=1 total=1
  cold-changed-v2.json -> new=1 total=2
  cold-changed-v2.json again -> new=1 total=3, skipped=[]
- Resulting generations:
  gen1 digest d3cc9a920b04bc3799cf970a08ef769b4891f1aeb85382b2848dc9ad98632c87
  gen2 digest 3063cc077c0a28e18e57c9932f5d11c47de4d5ec52fcc536bd35764dd73f7366
  gen3 digest 3063cc077c0a28e18e57c9932f5d11c47de4d5ec52fcc536bd35764dd73f7366
- The identical V2 artifact therefore allocates another generation on every later import.

DEFECT:
Generation-aware identity is implemented with a first-match lookup. Once generation 2 exists, its digest is invisible to dedup because all later checks continue against generation 1. The same primitive is also unsafe for future HOT decisions because "the session" is not necessarily the latest generation. Repeated polling can inflate the index indefinitely and destroy the stated source-identity-plus-digest invariant.

REPAIR:
- Introduce records_for_session(index, session_id) and a deterministic latest_record/latest_generation helper.
- Before allocating any generation, dedupe bundle_sha256 across imports of every generation belonging to that session identity.
- For COLD: any prior matching digest => skip; genuinely unseen digest => latest_generation+1.
- For HOT: operate on the appropriate latest generation, not the first matching record.
- Keep provenance deterministic and do not append duplicate import records for an already-seen digest.

VERIFY:
- A -> B -> B remains exactly two generations.
- A -> B -> A remains exactly two generations and the reintroduced A is skipped.
- Repeat the same A/B inputs for at least 5 cycles with constant session count and byte-stable index after the first two unique digests.
- HOT append/resume tests operate on the latest generation and preserve prefix-conflict semantics.
- Add the cross-generation cases to the canonical inbox acceptance suite.

[P1] [CORE-003] tools/saipal_engine/pipeline.py:analyze_sessions — event budgets are not charged on no-drift work and persisted analysis cursors are never consumed

EVIDENCE:
- Contract: saipal/COMMANDS.md:92-94 says each run is bounded; hitting a limit checkpoints the exact continuation position and returns resumably without losing progress.
- pipeline.py:287 always starts from the complete record["episodes"] list.
- pipeline.py never slices from record["analysis"]["next_episode_index"] or last_analyzed_seq.
- pipeline.py:291 checks the budget before processing an episode.
- pipeline.py:297-299 handles a no-candidate episode by advancing analyzed_up_to and continuing.
- events_analyzed and telemetry are debited only at lines 318 and 322-324, which are unreachable for the no-candidate path.
- Reproduction with max_events=1 and detector result forced to [] over the six-episode conformant fixture:
  sessions_analyzed=1
  events_analyzed=0
  record.analysis={"analyzed_up_to_seq":11,"episodes_exhausted":true,"next_episode_index":6,...}
  The cycle processed all six episodes / seq through 11 while consuming zero event budget.
- Reproduction with max_events=1 and one rejected candidate per episode, repeated three times:
  cycle 1 -> events=1, analyzed_up_to_seq=1, next_episode_index=1, episodes_exhausted=false
  cycle 2 -> events=1, analyzed_up_to_seq=1, next_episode_index=1, episodes_exhausted=false
  cycle 3 -> events=1, analyzed_up_to_seq=1, next_episode_index=1, episodes_exhausted=false
  The durable checkpoint is written but ignored, so every resume reprocesses episode 0 forever.
- pipeline.py:253 uses one global budget_hit; after a budget hit the outer session loop at 266 is not terminated. Untouched later sessions can still be entered, counted at line 326 and written with analysis state derived from the already-hit global budget.

DEFECT:
The budget is accounting candidate-producing work instead of analyzed evidence, while the purported continuation cursor is write-only. Conformant/no-drift sessions can bypass max_events entirely; candidate-producing sessions can become permanently non-progressing across continue calls. This breaks both resource bounding and resumability, and also makes telemetry/state claims untrustworthy.

REPAIR:
- Load a per-record resume cursor from persisted analysis.next_episode_index, with last_analyzed_seq/prefix data used as consistency guards.
- Iterate only the unprocessed tail.
- Compute/debit the episode span for every episode actually analyzed, regardless of whether it produces zero, rejected, or accepted candidates.
- Enforce the event/time budget before starting additional work. Define an explicit policy for an individual episode larger than the remaining budget so it cannot either silently overshoot or starve forever.
- Persist next_episode_index immediately from the actual next unprocessed unit.
- Derive episodes_exhausted from that record's cursor reaching len(episodes), not from a global `not budget_hit`.
- Once any global cycle budget is hit, checkpoint the current record and terminate the outer session loop; do not count or mutate untouched later sessions.
- Keep telemetry debit and returned events_analyzed derived from the same span-accounting primitive.

VERIFY:
- max_events=1 with no-candidate episodes processes only the policy-allowed amount, charges it, checkpoints, and advances monotonically over subsequent cycles.
- Repeated candidate-producing max_events=1 cycles produce strictly increasing next_episode_index/analyzed_up_to_seq until exhausted; no episode is reprocessed.
- Multi-session test proves a budget hit in session A leaves session B untouched and uncounted.
- Returned events_analyzed equals telemetry delta and actual processed event-span cost for no-drift, rejected and accepted candidate paths.
- A full-budget normal run still exhausts the canonical fixture in one cycle.

[P1] [CORE-004] tools/saipal_engine/{hardening.py:SessionLease; pipeline.py:analyze_sessions; bundle.py:validate_bundle} — valid session IDs can crash lease acquisition and several post-acquire exits leak leases

EVIDENCE:
- bundle.py:95-98 accepts any non-empty string as session_id; path separators and other filesystem syntax are valid bundle data.
- hardening.py:110-115 constructs the lease pathname directly as `lease-{session_id}.json`.
- Reproduction using a schema-valid canonical bundle with session_id="foo/bar":
  import_inbox -> new_sessions=1
  analyze_sessions -> PalError:
  "cannot create session lease: [Errno 2] No such file or directory: '.../.saipal/locks/lease-foo/bar.json'"
- The accepted logical identifier has therefore become filesystem path structure.
- pipeline.py:275-277 acquires the lease.
- pipeline.py:278-280 immediately `continue`s when the referenced bundle no longer exists, without release.
- Only bundle-load PalError at lines 281-285 releases explicitly; there is no try/finally covering the complete held-lease region.
- Missing-bundle reproduction:
  import conformant-cold.json;
  delete its inbox file;
  analyze_sessions -> sessions_analyzed=0;
  `.saipal/locks/lease-golden-cold-001.json` remains on disk.
- Future work on that session is then blocked until stale-lock recovery rather than immediately recoverable.

DEFECT:
An external logical identifier is used as a filename instead of being encoded into a safe key, so valid input can crash the primary analysis path. Lease lifetime is also manually balanced across only some exits; a missing bundle or any unhandled exception after acquire leaves a false ownership artifact.

REPAIR:
- Derive the lease filename from a deterministic filesystem-safe key, preferably SHA-256 of the canonical session_id; keep the original session_id only inside payload/diagnostics.
- Do not attempt to sanitize by deleting a few characters; hashing avoids Windows reserved characters, separators, length limits and alias collisions.
- After successful acquire, wrap the entire dependent region in try/finally or make SessionLease a context manager so every return/continue/exception releases exactly once.
- Missing/unreadable/moved bundle paths must release before continuing.
- Preserve ownership-fencing changes for the dedicated robustness wave; do not entangle them with this filename/lifetime fix except where needed for correct release semantics.

VERIFY:
- Valid IDs containing `/`, `\`, `:`, Unicode, dots, spaces and very long strings produce safe flat lease files and do not alter directory structure.
- Two distinct session IDs cannot map to the same lease key.
- Missing bundle after acquire leaves zero lease files.
- Inject exceptions after acquire at bundle load, detector analysis, finding merge and recurrence paths; every case releases the lease.
- Existing contention/stale-lease tests remain green.

[P1] [CORE-005] tools/saipal.py:{_continue_cycle,cmd_continue} + tools/saipal_engine/hardening.py:check_safety_valves — new T-055 `continue --drain` declares idle from intake activity instead of remaining backlog and can stop with unfinished analysis

EVIDENCE:
- .saipen/STATE.md identifies T-055 as the active BUILD task.
- .saipen/LOG.md E-255 defines T-055 as a backlog-draining loop: repeat bounded cycles until idle/blocked/safety-valve; "Each cycle: next -> continue -> repeat"; caps 100 cycles, 3600s, 10 audits/cycle.
- tools/saipal.py:153 unconditionally writes state.phase="IDLE" after every cycle.
- tools/saipal.py:154-160 writes queue.hot/cold from inbox.py totals; inbox.py:115-116 counts every indexed HOT/COLD record, not pending analysis units.
- tools/saipal.py:187 defines cycle idle solely as `not intake["imported"] and not intake["conflicts"]`.
- Existing indexed sessions with analysis.episodes_exhausted=false therefore do not prevent idle.
- cmd_continue --drain lines 251-263 checks that intake-derived idle before its productive fallback and exits immediately when idle=true.
- Controlled reproduction:
  pre-import one conformant COLD session;
  leave its identical canonical bundle in inbox so the next intake is only a duplicate;
  set analysis budget to one event with six episodes pending;
  run cmd_continue(..., ["--drain"]).
  Result:
    exit=0
    drain_cycles=1
    drain_outcome="idle"
    cycle_idle=true
    cycle_sessions_analyzed=1
    cycle_events_analyzed=1
    record.analysis.episodes_exhausted=false
    next_episode_index=1
    episode_count=6
  Five episodes remain, but the drain command reports "backlog drained".
- cmd_next already contains a read-only semantic backlog signal: tools/saipal.py:694-716 builds the analysis carrier and selects analyze-episodes when pending work exists. `--drain` does not use the same truth source.
- SafetyValve.max_cycles defaults to 100, but cmd_continue increments/runs the cycle at lines 227-230 before checking the valve at 242-249.
- hardening.py:71 rejects only when cycle_count > max_cycles. Consequently cycle 101 has already executed before a max_cycles=100 violation can stop the loop.
- Search of current tests found SafetyValve unit checks in test_wave_i_hardening.py but no acceptance test for `continue --drain` backlog exhaustion or premature-idle behavior.

DEFECT:
T-055 has no authoritative "work remains" invariant. Intake inactivity is being mistaken for system idleness even when durable semantic checkpoints explicitly say analysis remains. State simultaneously claims IDLE, and --drain terminates successfully with unfinished work. The safety-cycle cap is also enforced after the extra cycle has already run. The newly implemented primary feature therefore does not satisfy its own backlog-draining contract.

REPAIR:
- Introduce/reuse one read-only backlog/carrier predicate for both `next`, state reporting and `--drain`; pending analysis must be derived from durable session/checkpoint state, not whether this cycle imported a new file.
- Prefer the existing build_carrier/cmd_next semantics or extract their underlying carrier selection into a shared function so `next` and `--drain` cannot drift.
- Distinguish:
  * clean idle: no pending automatic work;
  * blocked: only operator-required conflict/refusal remains;
  * runnable: pending analysis/import/automatic lifecycle work remains.
- Set state.phase/queue from that same predicate. Do not write IDLE while a resumable analysis carrier exists.
- In the drain loop, evaluate the authoritative pending-work state after each cycle; continue while runnable, stop only on true clean idle, explicit operator block, or safety valve.
- Enforce cycle/time safety before starting a cycle that would exceed the cap. Preserve post-cycle audit-count validation as needed, but max_cycles=100 must execute at most 100 cycles.
- Add explicit drain acceptance tests rather than relying only on SafetyValve helper tests.

VERIFY:
- Preindexed six-episode session + max_events=1 drains through successive cycles until episodes_exhausted=true; it never returns drain_outcome=idle while next_episode_index < episode_count.
- A duplicate-only inbox with pending analysis remains runnable.
- A duplicate-only inbox with all sessions exhausted returns clean idle without an extra cycle.
- Conflict-only state returns blocked according to the defined carrier precedence.
- `saipal next` and `continue --drain` agree on whether automatic work remains.
- STATE phase/queue agree with the same durable backlog truth.
- max_cycles=1 executes at most one cycle; max_cycles=100 executes at most 100.
- Add regression tests for T-055 covering pending-analysis, clean-idle, conflict, safety-cycle and time-cap exits.

CORE_DONE_WHEN: CORE-001 authority trust is centralized and direct/raw bundles cannot self-bind or escape configured roots; CORE-002 import is idempotent across all generations; CORE-003 budgets charge every analyzed span and durable cursors resume monotonically; CORE-004 every accepted session_id has a safe lease and every held lease is released on all exits; CORE-005 --drain/state/next share one durable backlog predicate and drain cannot report idle before all automatic work is exhausted; focused regressions pass and `python -B tools/validate.py` remains green.

---
## 02 — AUDIT SECOND WAVE
PROJECT_NAME: SAIPAL
DATE_TIME: 2026-09-03T22:21:07+03:00
CAMPAIGN_PROFILE: quick3
CAMPAIGN_PROFILE_VERSION: 1.0.0
CAMPAIGN_RUN_ID: acb-mtlw6abk-b8ad2f120ad4417fab5c
CAMPAIGN_MANIFEST_SHA256: 97d9d053e37e6597a8559008911f84b28f799f326a97c69ebc5b304690defa72
WAVE_ID: second
WAVE_INDEX: 2
WAVE_COUNT: 3
WAVE: AUDIT SECOND WAVE
TARGET: /mnt/data/_SAIPAL_03.09.26-T22-00-57.zip -> extracted audit root /mnt/data/saipal_w2
BASELINE: VERSION 0.3.0; archive SHA256 177c3aeb64ec099042148ee20500be4612352f5720aed192fad52ca3756bf5a5; AUDAPACK manifest created_at 2026-09-03T22:00:58.321018
PREVIOUS_WAVE_SHA256: NONE
GIT_CONTEXT: ABSENT - archive contains no .git; _AUDAPACK_MANIFEST.json records empty Git branch/head
SAIPEN_CONTEXT: STALE - .saipen/STATE.md remains BUILD/T-055 with last_event 255 while .saipen/LOG.md reaches E-256; BOARD T-061..T-067 used only as work-state context
AUDIT_SCOPE: writer/lease ownership; crash/retry transaction boundaries; dispatcher progression and source mutation; setup atomicity; audit enqueue durability; closed-loop disposition/import; recurrence durability/spread semantics; sink retry; finding-audit linkage; append-log sequencing; trigger lifecycle; focused boundary tests
TEST_STATUS: TEST_PARTIAL
TEST_LIMITATION: `PYTHONPATH=tools python -B -m unittest -v test_wave_a_lock test_wave_a_log test_wave_disposition test_wave_spread test_wave_g_closed_loop test_wave_sink` exceeded the 120-second execution limit while running `test_wave_sink.PublishEndToEnd.test_publication_is_exactly_once`; every test whose result was printed before the timeout passed. `python -B tools/validate.py` separately passed all 270 checks.
VERIFIED_INSTEAD: deterministic temporary-home and fault-injection reproductions verified stale-owner lock deletion, empty-lock takeover, submit double-application after crash, dispatcher starvation, changed-COLD suppression, failed-setup mutation, enqueue duplicate allocation after crash, partial disposition commits, bool audit-number acceptance, recurrence overwrite, missing runtime clean-model evidence, non-retried sink publication, non-retried closed-loop linkage, log sequence regression, and late-trigger loss
STATUS: SECOND_WAVE: COMPLETE
TICKETS: 13
HANDOFF: IMPLEMENTATION_AGENT
COVERAGE_INSPECTED: VERSION; README.md; _AUDAPACK_MANIFEST.json; .saipen/{STATE.md,BOARD.md,LOG.md}; saipal/{CORE.md,COMMANDS.md,SESSIONS.md,FINDINGS.md,AUDITS.md,ANALYSIS.md,REGISTRY.json}; tools/saipal.py; tools/saipal_engine/{paths.py,hardening.py,enqueue.py,submit.py,dispatcher.py,sources.py,config.py,closedloop.py,recurrence.py,pipeline.py,sink.py,log.py,findings.py}; generic adapter and canonical fixtures; tools/{validate.py,test_wave_a_lock.py,test_wave_a_log.py,test_wave_disposition.py,test_wave_spread.py,test_wave_submit.py,test_wave_g_closed_loop.py,test_wave_sink.py,test_wave_next1.py}
COVERAGE_DEFERRED: exhaustive provider-specific adapter races; SQLite snapshot internals; actual Windows multi-process race execution; raw power-loss/fsync behavior beyond injected write-boundary failures; performance/scaling surfaces reserved for wave 3; remainder of full formal test suite after timeout
CROSS_WAVE_REFERENCES: CORE-004 owns SessionLease pathname safety and guaranteed release; W2-001 below separately owns stale-owner fencing/create-write races across all lock types. CORE-002 owns generation-wide inbox dedup; W2-004 owns dispatcher suppression that prevents changed COLD evidence from reaching that logic. CORE-005 owns the shared durable backlog/idle predicate; W2-003 adds dispatcher.pending/cursor requirements and W2-013 adds trigger ownership to that predicate. CORE-001 and CORE-003 remain valid and are not duplicated here.
RESIDUAL_UNCERTAINTY: archive provenance cannot be tied to a Git commit because .git is absent; the previous wave exists as conversation output rather than a canonical byte artifact, so no SHA-256 was invented; crash tests inject failures at Python persistence boundaries rather than simulating physical power loss; the trigger race is established from deterministic operation ordering plus filesystem-state reproduction rather than a synchronized Windows multi-process run
ACB_CHAIN_RECEIPT: second-mtlwo4xl-211f705bbabf

[P0] [W2-001] tools/saipal_engine/{paths.py:HomeLock,hardening.py:SessionLease,enqueue.py:AuditInboxLock} - lock files have no ownership fencing, allowing a stale holder to delete a replacement live lock

EVIDENCE:
- HomeLock._payload() at paths.py:318-330 generates a new random `owner` value but the HomeLock instance never retains that token.
- HomeLock.release() at paths.py:377-382 unconditionally unlinks the lock whenever its local `_held` flag is true; it does not reread the lock or prove that the on-disk owner is still itself.
- SessionLease has the same pattern: `_payload()` at hardening.py:121-128 generates a fresh owner; release at 185-190 unconditionally unlinks the current lease path.
- SessionLease.refresh() at 198-212 calls `_payload()` again, so even a refresh changes the declared owner rather than preserving an acquisition identity.
- AuditInboxLock uses the same random-owner/no-fencing pattern and unconditional release.
- HomeLock stale handling at paths.py:361-375 converts unreadable, malformed, or temporarily empty lock contents into `age=ttl+1,pid=0` and immediately permits unlink/takeover.
- The existing formal test `test_wave_a_lock.HomeLockContract.test_unreadable_lock_is_treated_as_stale` passes, so the dangerous malformed/empty-lock takeover behavior is currently codified as expected behavior.
- Deterministic reproduction:
  `home_acquire_A True`
  `home_B_survives_A_release False`
  `session_acquire_A True`
  `session_B_survives_A_release False`
  `audit_acquire_A True`
  `audit_B_survives_A_release False`
  `empty_home_taken_over True`
- Reproduction replaced A's lock file with a valid live B-owner payload before calling A.release(); A deleted B in all three implementations.

DEFECT:
The filesystem node is treated as proof of ownership, but ownership can change after acquisition. A stale process can therefore delete a successor's valid lock and admit concurrent writers. There is also an O_EXCL create-before-payload window where another process can observe the newly created empty file, classify it as stale, unlink it, and acquire independently. This defeats the project's single-writer invariant and can expose state/index/ledger files to concurrent mutation.

REPAIR:
- Generate one immutable owner/fencing token during lock-object construction or acquisition and retain it on the instance.
- Persist that exact token on acquire and refresh; refresh must not invent a new owner.
- Release only if a reread proves the current on-disk owner token equals the holder's token. If ownership changed, clear local `_held` without deleting the successor.
- Apply identical ownership semantics to HomeLock, SessionLease, and AuditInboxLock through one shared primitive if practical.
- Do not classify an empty/newly malformed lock as immediately stale. Use a bounded create/write grace based on file metadata or an atomic fully-populated acquisition representation.
- Preserve dead-PID/TTL recovery, but takeover must be fenced against another process replacing the node between inspection and deletion.
- Keep CORE-004's SessionLease safe-filename and try/finally lifetime repair separate from this ownership-fencing repair.

VERIFY:
- A acquires; B legitimately replaces/takes over; A.release leaves B intact for all three lock types.
- Refresh preserves the same owner token.
- A newly O_EXCL-created but not-yet-populated lock cannot be stolen during the create/write window.
- Dead-owner and genuinely expired locks remain recoverable.
- Two simultaneous contenders never both report ownership.
- Add explicit stale-holder-release and create/write-race regression tests; revise the current unreadable-lock test so transient empty creation is not equivalent to proven stale ownership.

[P0] [W2-002] tools/saipal_engine/submit.py:submit_candidate - idempotency receipt is committed after irreversible side effects, so crash/retry double-applies a submission

EVIDENCE:
- submit_candidate performs its duplicate/receipt lookup at submit.py:250-272.
- For an accepted candidate it then mutates recurrence and semantic progress before the receipt is durable:
  - drift absorption at 280-283;
  - NO_DRIFT recurrence mutation at 285;
  - semantic advancement at 287;
  - session index save at 288.
- The operation receipt is only constructed/appended/saved at 290-303.
- Fault injection forced `_save_receipts` to raise after those earlier writes.
- Reproduction:
  `first_error RuntimeError fault-after-effects-before-receipt`
  initial semantic:
  `{'next_episode_index': 0, 'exhausted': False, 'submitted': 0, 'no_drift': 0, 'provisional': 0}`
  after failed submission:
  `{'next_episode_index': 1, 'exhausted': False, 'submitted': 0, 'no_drift': 1, 'provisional': 0}`
  `receipts_exists False`
  recurrence occurrences after failed attempt: `2`
- Retrying the exact same candidate produced:
  `retry_duplicate False`
  semantic NO_DRIFT count `2`
  recurrence occurrences `3`.
- The retry therefore cannot recognize the prior committed effects because its idempotency proof is precisely the write that was lost.

DEFECT:
The receipt is a post-hoc record rather than a transaction boundary. Any crash/error after a downstream write but before receipt persistence converts an exact retry into a second logical submission. Recurrence counts and semantic accounting become permanently inflated; DRIFT paths can analogously duplicate finding-side effects.

REPAIR:
- Introduce a durable operation record keyed by deterministic receipt/operation identity before applying externally visible effects.
- Use explicit states such as PREPARED/APPLYING/COMMITTED or an equivalent recoverable journal.
- Make every downstream mutation idempotent against that operation identity.
- On restart/retry, reconcile a PREPARED/APPLYING operation: detect which effects are already present, finish missing effects exactly once, then mark COMMITTED.
- Keep the final user-facing receipt as the committed projection, not the sole evidence that execution started.
- Ensure DRIFT finding absorption, recurrence mutation, semantic advancement and session-index mutation all participate in the same operation.

VERIFY:
- Inject failure after every durable step in submit_candidate and retry the identical candidate.
- Every fault point converges to exactly one semantic advancement, one recurrence effect, one finding absorption where applicable, and one committed receipt.
- Repeated committed retries are byte-stable no-ops.
- Restart between each stage has the same result as an uninterrupted submission.

[P1] [W2-003] tools/saipal_engine/dispatcher.py:dispatch_sources + tools/saipal.py:_continue_cycle - dispatch budget has no progression cursor and counts successes rather than attempts, permanently starving tail candidates

EVIDENCE:
- dispatch_sources restarts candidate traversal from the beginning on every call.
- At dispatcher.py:49-53, once the processed count reaches `max_per_source`, later candidates are only counted as pending; no durable cursor/watermark is stored.
- `processed` is incremented for indexed/unchanged/imported candidates but rejected candidates at 97-98 do not consume the bound.
- Deterministic 55-candidate reproduction with `max_per_source=50`:
  cycle 1: `imported=50 pending=5 processed=50`
  after those 50 became indexed, cycle 2:
  `imported=0 unchanged=50 pending=5 processed=50`
- The first 50 unchanged candidates consume every future cycle, so candidates 51-55 are unreachable forever.
- Reproduction with 73 rejected candidates and budget 10:
  `rejected=73 pending=0 processed=0`
- Thus the advertised bound limits successful classifications, not source attempts/work.
- `_continue_cycle` receives dispatch results, but its current idle decision does not account for `dispatch.pending`, so --drain can additionally declare completion while dispatcher work remains. The generic idle defect is already CORE-005.

DEFECT:
There is no monotonic source progression invariant. Stable early candidates can permanently consume the same budget while later evidence is never visited, and pathological rejected input bypasses the resource bound entirely. Restarting cannot help because progression exists only in local iteration order.

REPAIR:
- Bound candidate attempts, not only successful/unchanged operations; every candidate inspected must consume the cycle budget.
- Persist a per-source continuation cursor/watermark or equivalent deterministic progression token.
- Reconcile the cursor safely if the source membership/order changes; do not assume array index alone is durable identity.
- Ensure fairness across multiple enabled sources so one large source cannot indefinitely starve another.
- Feed `dispatch.pending` into the authoritative backlog predicate implemented for CORE-005.
- Persist enough state to resume correctly after process restart.

VERIFY:
- 55 stable candidates with budget 50 process 50 on cycle 1 and the remaining 5 on cycle 2, then become idle.
- 73 invalid candidates with budget 10 attempt at most 10 and report 63 pending.
- Restart after cycle 1 resumes at remaining work rather than the first 50.
- Multiple sources each make bounded forward progress.
- --drain cannot report idle while dispatch.pending > 0.

[P1] [W2-004] tools/saipal_engine/dispatcher.py:dispatch_sources - COLD source is skipped by session_id before current content is normalized or digested

EVIDENCE:
- dispatcher.py:54-68 accepts a candidate-declared session_id and, if that ID already exists, marks a COLD source `"already indexed, cold"` and continues.
- Adapter normalization occurs only later at 69-85.
- Consequently the current source artifact is never read/digested before deciding that it is unchanged.
- Custom adapter reproduction:
  - V1 dispatched/imported: `first_imported 1 indexed 1 normalize_calls 1`.
  - Source then changed to V2 while preserving the same session_id.
  - Second dispatch: `second_imported 0 unchanged [{'source': 'sid1', 'reason': 'already indexed, cold'}] normalize_calls 1`.
- The unchanged decision therefore came solely from logical session_id; normalize was never invoked for V2.
- CORE-002 concerns generation-wide dedup after a changed bundle reaches inbox import. This defect occurs earlier and prevents changed evidence from ever reaching that logic.

DEFECT:
COLD means immutable captured evidence, but the dispatcher equates identity with content. If an adapter's discover phase exposes a stable session_id while the backing artifact changes, later evidence is silently suppressed. Generation semantics cannot repair evidence that dispatch refuses to inspect.

REPAIR:
- Never declare COLD unchanged solely because session_id already exists.
- Use a trustworthy cheap source identity/fingerprint when an adapter can provide one; otherwise normalize and compute the canonical digest.
- Compare the resulting digest against all imported generations for the session.
- Let unchanged digest skip; novel digest must flow into generation allocation.
- Keep any fast path explicitly tied to a content fingerprint, not a logical name.

VERIFY:
- V1 followed by identical V1 skips safely.
- V1 followed by changed V2 with the same session_id is dispatched and becomes generation 2.
- Retrying V2 remains idempotent after CORE-002.
- Adapters lacking a cheap trustworthy fingerprint are normalized rather than guessed unchanged.

[P1] [W2-005] tools/saipal.py:cmd_setup - setup commits source-registry changes before validating the rest of the requested configuration and can generate duplicate source IDs

EVIDENCE:
- cmd_setup mutates and saves sources around saipal.py:395-406.
- Publication mode, sink, authority and maintainer-state validation/writes occur afterward at 408-459.
- Reproduction invoking setup with a valid source plus invalid `PUBLISH_ENABLED` configuration:
  `invalid_setup_error PalError refusing invalid config: PUBLISH_ENABLED requires shadow_reviewed; PUBLISH_ENABLED requires configured sink.root`
  but afterward:
  `sources_after_failed [{'enabled': True, 'id': 'src1', 'kind': 'generic', ...}]`
- The command reported failure while still committing part of the requested operation.
- Replacement allocation removes the matching path and then uses `src{len(sources)+1}`.
- With existing `src1=A, src2=B`, replacing A leaves one record and chooses `src2`, colliding with B.
- Reproduction:
  `replace_existing_error PalError refusing to write an invalid source registry: duplicate source id 'src2'`.

DEFECT:
Setup is a multi-file logical operation implemented as independent immediate writes. Validation failure after the first write leaves configuration inconsistent with the command result, and count-based ID allocation assumes IDs are contiguous after deletions/replacements.

REPAIR:
- Construct prospective sources/config/authority/state entirely in memory.
- Validate the complete requested configuration before the first durable mutation.
- Preserve an existing source ID when replacing that same source.
- For a genuinely new source, allocate a deterministic unused ID rather than `len+1`.
- Serialize setup under one home writer lock.
- For unavoidable multi-file commits, add a recoverable setup journal or deterministic rollback/reconciliation so interruption cannot expose a half-applied configuration.

VERIFY:
- Every invalid setup invocation leaves all touched files byte-identical.
- Replacing src1 while src2 exists preserves src1 rather than colliding.
- Sparse IDs such as src1/src7 allocate an actually free value.
- Inject failure between each setup file write; restart converges either to the old complete configuration or the new complete configuration, never a mixture.

[P1] [W2-006] tools/saipal_engine/enqueue.py:enqueue_audit - audit file becomes durable before its idempotency receipt, so retry allocates a second audit after a crash

EVIDENCE:
- enqueue_audit checks existing entries first.
- It allocates an audit number, writes/verifies the final audit file, and only afterward appends the receipt/ledger entry.
- Fault injection made the ledger write fail after the audit file was already durable.
- Reproduction:
  `enqueue_first_error RuntimeError`
  `enqueue_files_after_crash ['1.md']`
- Retrying the same finding/content:
  `enqueue_retry_number 2`
  `enqueue_files_after_retry ['1.md', '2.md']`.
- The counter had already advanced and the missing ledger receipt prevented the orphaned first file from being recognized as the same operation.

DEFECT:
Audit ID allocation, audit publication and idempotency bookkeeping do not share a recoverable transaction. A crash in the small but real post-file/pre-ledger window produces duplicate immutable audit artifacts and consumes additional audit numbers.

REPAIR:
- Persist an enqueue operation/intention containing finding identity, body digest and selected audit number before final publication.
- On retry, reconcile incomplete operations:
  - expected file exists with expected digest -> finalize the ledger;
  - expected file absent -> write the same allocated slot and finalize;
  - file exists with conflicting digest -> fail closed.
- Do not allocate a new number merely because the final receipt is missing.
- Keep operation recovery idempotent across restart.
- Coordinate this primitive with W2-002 so submission can safely depend on enqueue without creating a second independent exactly-once hole.

VERIFY:
- Fault after ID reservation, file creation, fsync/verification and ledger write each converges to one audit file and one receipt.
- Exact retry returns the original audit number.
- Conflicting pre-existing file never gets overwritten or silently adopted.

[P1] [W2-007] tools/saipal_engine/closedloop.py:{import_maintainer_disposition,import_disposition_file} - disposition import is destructive, non-atomic, and accepts boolean audit numbers

EVIDENCE:
- closedloop.py states that SAIPAL does not edit its own history, yet import_maintainer_disposition overwrites the current link's `disposition`, `fix_version`, `closed_at`, receipt/work identifiers in place.
- No immutable disposition revision history is retained.
- import_disposition_file validates and applies rows sequentially rather than validating the entire batch first.
- Reproduction with row 1 valid and row 2 invalid:
  `disp_batch_error PalError disposition 'BOGUS' is not a closed-loop value`
  but row 1 remained committed:
  `disp_after_partial {... 'disposition': 'NO_CHANGE', 'receipt_id': 'R1', 'closed_at': ...}`
- A failed batch therefore has observable partial effects.
- Audit-number validation uses `isinstance(audit_number, int)`, which accepts Python bool.
- Reproduction using `audit_number: true`:
  `bool_accepted 1 ENGINE_FIX`.
- Re-importing a later disposition replaces the previous top-level record rather than preserving the historical sequence.

DEFECT:
The closed-loop record is being used simultaneously as latest state and history. Partial batch commits make file-level import non-atomic, and Python's bool/int subtype relation lets malformed external data target audit 1. Subsequent maintainer revisions erase prior disposition provenance.

REPAIR:
- Fully parse and validate every row before mutating any link.
- Require `type(audit_number) is int` or equivalent strict schema validation; reject booleans explicitly.
- Apply the validated batch to an in-memory copy and persist once atomically.
- Store append-only disposition revisions keyed by stable receipt/work identity.
- If compatibility requires top-level latest fields, derive/update them as a projection while retaining the immutable revision list.
- Make exact receipt replay a no-op and define explicit behavior for conflicting revisions.

VERIFY:
- One invalid row leaves the entire ledger byte-identical.
- `true` and `false` audit numbers are rejected.
- Two legitimate disposition revisions remain reconstructable in order.
- Exact replay does not create duplicate history.
- A valid multi-row file commits in one durable transition.

[P1] [W2-008] tools/saipal_engine/recurrence.py:load_recurrence/record_* - corrupt or unsupported recurrence state is silently treated as absence and overwritten

EVIDENCE:
- load_recurrence returns an empty recurrence structure both when the file is genuinely missing and when reading/parsing/validation fails.
- Writers then mutate that empty replacement and persist it.
- Reproduction wrote a parseable recurrence document with unsupported `schema_version: 999` and sentinel historical data.
- Calling record_negative replaced it with a fresh schema-1 object:
  `after_bad_schema {'by_finding': {'CONFORMANT': ...}, 'by_rule': {}, 'schema_version': 1}`
- The prior incompatible/sentinel content disappeared.
- pipeline._record_recurrence intends to catch and log recurrence corruption without aborting a cycle, but corruption is swallowed by the loader before an exception can reach that handler.

DEFECT:
"Absent" and "unrecoverable" state are collapsed. A future-version, damaged, or otherwise invalid recurrence ledger is interpreted as a blank ledger and destructively rewritten during normal analysis, destroying evidence precisely when compatibility is uncertain.

REPAIR:
- Return explicit `missing | ok | unrecoverable` status or raise a typed error for invalid existing state.
- Initialize only on genuine absence.
- Existing malformed/unsupported state must refuse recurrence mutation and preserve original bytes.
- Let pipeline's existing failure path log the problem while continuing analysis if recurrence is non-critical.
- Only transform unsupported schema through an explicit validated migration.

VERIFY:
- Missing recurrence initializes normally.
- Valid recurrence appends normally.
- Malformed JSON, unsupported schema and invalid structural shape remain byte-for-byte unchanged after record_occurrence/record_negative attempts and produce a failure signal/log.
- Explicit supported migration, if added, is independently tested.

[P1] [W2-009] tools/saipal_engine/recurrence.py:{record_negative,_breakdown,spread} - runtime conformant evidence cannot become clean-model evidence for an actual drift class

EVIDENCE:
- record_negative writes clean sessions under synthetic drift_class `CONFORMANT`.
- `_breakdown` filters recurrence observations by exact requested drift_class.
- spread("COMMAND_ROUTE_DRIFT"), for example, therefore cannot see clean runtime observations stored as CONFORMANT.
- Reproduction recorded one COMMAND_ROUTE_DRIFT occurrence and one clean session from another model:
  `classification: SINGLE_MODEL`
  `clean_models: []`
  `contradicted_by_a_clean_model: False`
  guidance: `"observed under one model only, with no comparison available..."`
- Existing unit tests can construct clean observations directly inside a drift-class bucket and therefore pass without exercising the runtime record_negative path.

DEFECT:
The comparison model needed by PAL-FINDING spread reasoning is not produced by normal runtime writes. A clean model that actually obeyed a relevant rule cannot contradict an isolated drifting model because clean evidence is placed in a bucket that spread never consults. This biases fix-surface decisions toward "no comparison available."

REPAIR:
- Record negative evidence against the specific rule/comparison scopes that the clean episode actually exercised.
- Map those exercised rule IDs to drift-class comparison keys.
- Do not count an unrelated clean session as clean evidence for every drift class.
- An aggregate CONFORMANT entry may remain for global statistics, but it cannot be the sole negative-evidence representation.

VERIFY:
- Model A drifts on PAL-CMD-01 and model B demonstrably exercises PAL-CMD-01 conformantly -> B appears in clean_models and contradiction=true.
- Model B clean on an unrelated rule does not count against PAL-CMD-01 drift.
- Cross-model and cross-project positive recurrence classifications remain unchanged.
- Add an end-to-end runtime test that uses record_negative rather than hand-constructing the recurrence ledger.

[P1] [W2-010] tools/saipal_engine/pipeline.py:emit_audit - transient external sink failure is converted into terminal EMITTED state with no publication retry

EVIDENCE:
- In PUBLISH_ENABLED mode, pipeline.py:422-431 catches sink failure and falls back to local enqueue.
- Regardless of whether publication reached the configured sink, lines 434-440 attach the local audit result and advance the finding lifecycle to `EMITTED`.
- No durable pending-publication state is created.
- Reproduction using the actual sink-test setup:
  first cycle with sink unavailable:
  `sink_first_emitted 1 finding_states [('PAL-0001', 'EMITTED')]`
- After restoring a valid sink and running another continue:
  `sink_second_emitted 0 sink_files []`.
- The existing test named `test_a_vanished_sink_stages_locally_and_logs_the_failure` passes, but it verifies only local fallback/logging, not eventual retry.

DEFECT:
Local staging and external publication are conflated into one terminal lifecycle state. Once the fallback changes the finding to EMITTED, normal cycles have no carrier telling them that the requested external delivery never happened. A transient sink outage therefore becomes permanent delivery loss.

REPAIR:
- Separate "audit durably generated/staged" from "configured sink publication confirmed."
- Persist a publication operation containing the same audit identity/digest and target sink.
- On sink failure, retain PENDING/RETRYABLE publication state.
- At later cycle startup/continue, retry the same immutable audit idempotently.
- Mark external delivery complete only after sink acknowledgement plus any configured digest verification.
- Reuse the existing audit; never regenerate a new audit merely to retry transport.

VERIFY:
- Sink absent -> exactly one local audit plus durable pending-publication state.
- Restore sink -> next continue publishes that same audit and clears pending state.
- Further continues create no duplicate.
- Restart while pending still retries correctly.
- Permanent incompatible sink errors remain visible as blocked/refused rather than falsely EMITTED.

[P1] [W2-011] tools/saipal_engine/pipeline.py:emit_audit + closedloop.py:link_finding_audit - finding-to-audit link failure is logged once and then becomes unrecoverable

EVIDENCE:
- pipeline.emit_audit marks the finding EMITTED before calling link_finding_audit.
- closed-loop link failure is caught at pipeline.py:447-460 and reduced to a log event.
- There is no durable retry operation.
- Runtime search found no later reconciliation caller that retries failed finding/audit links.
- Reproduction with corrupt closed-loop ledger:
  first cycle: `link_first_emitted 1`
- After repairing the ledger and running another cycle:
  `link_second_emitted 0 links []`.
- Because the finding is already terminal EMITTED, the repaired subsystem never receives the missing link.

DEFECT:
The audit artifact and finding lifecycle can commit while their provenance edge fails. Logging preserves knowledge that an error happened, but does not preserve executable work to repair it. Provenance reconstruction is permanently incomplete after a transient closed-loop write failure.

REPAIR:
- Treat finding->audit linkage as a durable idempotent operation.
- Persist a pending link intent before or together with the transition to the terminal lifecycle.
- Reconcile pending links on startup/continue.
- Make link_finding_audit idempotent by stable finding+audit identity so retries cannot duplicate edges.
- Only declare fully closed publication state after required provenance links are durable, or represent "audit emitted / link pending" explicitly.

VERIFY:
- Corrupt link ledger -> audit survives and a pending link operation remains.
- Repair ledger -> next continue automatically creates exactly one link.
- Restart between emission and linking recovers.
- Conflicting existing link fails closed without erasing provenance.

[P1] [W2-012] tools/saipal_engine/log.py:last_seq/append_event - more than 64 KiB of malformed/torn tail causes sequence numbering to restart from 1

EVIDENCE:
- `TAIL_WINDOW = 65536`.
- last_seq reads only the last 64 KiB at log.py:59-68.
- It skips malformed records inside that window, but if no valid record is found returns 0 at line 86.
- OSError is also collapsed to 0 at 71-72.
- append_event computes `last_seq(...) + 1`.
- Reproduction created a valid event with seq 41 followed by more than 70,000 bytes of malformed tail:
  `last_seq_corrupt_tail 0`
- Next append produced:
  `appended_seq_after_corrupt_tail 1`.
- Existing torn-tail tests pass because their corrupt tail is small enough that the previous valid record remains inside the fixed window.

DEFECT:
The recovery algorithm assumes a valid prior record always exists in the final 64 KiB. Once corruption exceeds that arbitrary window, the append-only evidence log silently reuses sequence numbers. Any consumer relying on monotonic seq for ordering/checkpointing can no longer distinguish new events from historical sequence space.

REPAIR:
- Scan backwards in bounded chunks until a valid prior complete record is found or BOF is reached.
- Correctly handle records split across chunk boundaries.
- Missing/empty file may return 0; unreadable existing file should fail closed rather than masquerading as empty.
- Validate seq as a non-boolean non-negative integer and define behavior for structurally valid but regressing historical records.

VERIFY:
- Valid seq 41 plus >64 KiB malformed tail -> next append is 42.
- Repeat with malformed tail spanning several backward-read chunks.
- Torn final partial line works.
- Empty/missing log starts at 1.
- I/O failure does not reset numbering.
- Existing read_events malformed-line accounting remains intact.

[P1] [W2-013] tools/saipal.py:{cmd_trigger,_continue_cycle} - trigger cleanup can delete a trigger created during an already-running cycle before that trigger's work is observed

EVIDENCE:
- cmd_trigger creates the canonical `trigger.json` when none exists and immediately reports that a run is scheduled.
- `_continue_cycle` performs dispatch/intake/analysis first and only near the end unconditionally deletes the canonical trigger file.
- It does not atomically claim the trigger that caused the current cycle.
- Therefore a new trigger may be created after this cycle already passed the work it was meant to wake, but before end-of-cycle cleanup.
- Deterministic ordering reproduction:
  `trigger_before_cycle_exists True`
  `new_trigger_survives_late_cleanup False`.
- The newly written trigger marker was removed by the same late unconditional cleanup path even though it represented future work.

DEFECT:
The canonical trigger path serves simultaneously as pending-event storage and as the current cycle's consumed marker. Without a claim identity, cleanup cannot distinguish "the trigger this cycle consumed" from "a later trigger that arrived while this cycle was running." This is a classic lost-wakeup race.

REPAIR:
- At cycle start, atomically claim the trigger present at that moment by renaming it to a cycle/owner-specific claimed path.
- Only delete the claimed marker after successful handling.
- A new trigger written to canonical `trigger.json` during the cycle must remain for the next cycle.
- On failure after claim, preserve/requeue the claim deterministically so work is not lost.
- Integrate canonical/claimed trigger state into CORE-005's authoritative backlog/drain predicate.
- Preserve trigger coalescing if desired, but only for events known to have been incorporated into a cycle.

VERIFY:
- Create trigger B after cycle A has claimed/read its trigger but before A finishes; B remains after A cleanup and is consumed by the next cycle.
- Rapid duplicate triggers coalesce without losing the final wakeup.
- Crash immediately after claim leaves recoverable pending work.
- --drain does not report idle while either canonical or recoverable claimed trigger work remains.

SECOND_WAVE_DONE_WHEN: all writer/lease releases are ownership-fenced; submission and audit enqueue survive every injected crash boundary exactly once; dispatcher attempts are bounded and resume beyond prior prefixes; changed COLD evidence reaches digest/generation logic; failed setup is zero-mutation and source IDs remain collision-free; disposition batches are atomic with immutable revision history; corrupt recurrence is preserved and runtime clean evidence participates in relevant spread comparisons; sink publication and finding-audit linkage remain durably retryable until confirmed; LOG sequencing survives arbitrarily long malformed tails without regression; trigger consumption is atomically claimed with no lost wakeups; focused regressions pass, `python -B tools/validate.py` remains green, and the previously timing-out targeted test set completes successfully.

---
## 03 — AUDIT PERFORMANCE
PROJECT_NAME: SAIPAL
DATE_TIME: 2026-09-03T22:32:54+03:00
CAMPAIGN_PROFILE: quick3
CAMPAIGN_PROFILE_VERSION: 1.0.0
CAMPAIGN_RUN_ID: acb-mtlw6abk-b8ad2f120ad4417fab5c
CAMPAIGN_MANIFEST_SHA256: 97d9d053e37e6597a8559008911f84b28f799f326a97c69ebc5b304690defa72
WAVE_ID: performance
WAVE_INDEX: 3
WAVE_COUNT: 3
WAVE: AUDIT PERFORMANCE / STABILITY / EFFECTIVENESS
TARGET: /mnt/data/_SAIPAL_03.09.26-T22-00-57.zip -> extracted project root /mnt/data/saipal_perf
BASELINE: VERSION 0.3.0; archive SHA256 177c3aeb64ec099042148ee20500be4612352f5720aed192fad52ca3756bf5a5; inspected tree aggregate SHA256 d09bc3994ab2d6daac3630d92c4563ac0e060f2b51f621f28c7411b283ee7082; AUDAPACK manifest created_at 2026-09-03T22:00:58.321018
PREVIOUS_WAVE_SHA256: NONE
GIT_CONTEXT: ABSENT - supplied archive contains no .git; _AUDAPACK_MANIFEST.json records empty branch/head
SAIPEN_CONTEXT: STALE - .saipen/STATE.md remains BUILD/T-055 with last_event 255 while .saipen/LOG.md reaches E-256; BOARD T-067 already identifies the same performance surfaces, but findings below were independently reverified against live implementation and runtime data
AUDIT_SCOPE: detector/analyst scaling; canonical inbox parsing/hash/write amplification; source dispatcher and HOT adapter polling; OpenCode SQLite normalization/identity; session-index load/save/storage amplification; recurrence write granularity; status/log memory bounds; current runtime-state sizes; focused functional regressions
TEST_STATUS: TEST_PASSED
TEST_LIMITATION: NONE
VERIFIED_INSTEAD: `python -B tools/validate.py` PASS 270 checks; `python -B -m compileall -q tools` PASS; 70 focused functional tests PASS across Wave B episodes, Wave C detectors, Wave H recurrence, Wave I hardening, SourceDispatcher, OpenCode SQLite adapter and state contracts; isolated synthetic/read-only benchmarks independently reproduced detector quadratic scaling, 36.6MB inbox rescans, unused HOT watermark advantage, 11.1MB session-index amplification, recurrence N-write amplification and unbounded LOG materialization
STATUS: PERFORMANCE: COMPLETE
TICKETS: 6
HANDOFF: IMPLEMENTATION_AGENT
COVERAGE_INSPECTED: VERSION; _AUDAPACK_MANIFEST.json; .saipen/{STATE.md,BOARD.md,LOG.md}; .saipal runtime state including sessions/index.json, session_inbox, recurrence.json, LOG.jsonl; tools/saipal.py::{_continue_cycle,_load_read_only,cmd_status,cmd_next}; tools/saipal_engine/{detectors,analyst,pipeline,inbox,bundle,dispatcher,sessions,episodes,carrier,coverage,recurrence,log}.py; tools/saipal_engine/adapters/{opencode,generic,claude,codex,gemini,termisai}.py; performance-adjacent tests
COVERAGE_DEFERRED: exhaustive real-provider large-store profiling outside the supplied local archive; Windows-specific filesystem/cache timing; multi-hour RSS/soak testing; full 661-test canonical suite was not required for this focused performance pass
CROSS_WAVE_REFERENCES: CORE-002 cross-generation digest correctness and W2-004 changed-COLD detection must constrain PERF-002 intake shortcuts; W2-003 owns durable dispatcher cursor/fairness while PERF-003 owns HOT source-history avoidance; CORE-003 owns correct event-budget accounting while PERF-001 optimizes detector access only; W2-001 ownership fencing must survive any shared-index/dirty-write refactor in PERF-004; W2-008/W2-009 recurrence corruption and semantic fixes constrain PERF-005 batching; W2-012 LOG sequence recovery is independent from PERF-006 streaming status. Existing project ticket T-067 already summarizes PERF-001..PERF-006 from an earlier campaign and is corroborated, not used as primary evidence.
RESIDUAL_UNCERTAINTY: absolute benchmark timings are sandbox-specific and must not be treated as Windows timings; scaling ratios and I/O amplification were directly reproduced; current LOG is only 4,846 bytes so PERF-006 is a proven long-run memory-bound defect rather than today's dominant cost; previous current-campaign wave exists as conversation output rather than a canonical byte artifact, so no SHA-256 was fabricated
ACB_CHAIN_RECEIPT: performance-mtlx2dwl-489384d818ea

[P1] [PERF-001] PROVEN BOTTLENECK tools/saipal_engine/detectors.py::{_events,_span,detect_all,detect_active_work_preemption,detect_source_closure_false_green} / tools/saipal_engine/analyst.py::contrary_evidence_pass

EVIDENCE:
- detectors.py:93-104 copies the complete event array and linearly filters the entire bundle every time `_span()` is called for one episode.
- Four of the five registered detectors use `_span()`; `detect_active_work_preemption()` additionally performs a complete `_events(bundle)` scan for each discovered work switch at lines 287-296.
- `detect_source_closure_false_green()` performs another complete event-stream scan at lines 388-393.
- `detect_all()` lines 412-427 invokes every detector independently for every episode, so their repeated full-stream work multiplies.
- analyst.py:207-241 copies and scans the complete event stream again for every candidate during contrary-evidence analysis.
- Independently reproduced synthetic no-candidate benchmark using the real detector registry and 10 events per episode:
  1,000 events / 100 episodes -> 0.020714s median
  2,000 / 200 -> 0.083337s
  4,000 / 400 -> 0.338247s
  8,000 / 800 -> 1.305039s
- Doubling workload repeatedly costs approximately 4x, demonstrating O(events × episodes), effectively quadratic growth when episode count grows proportionally with events.
- Current supplied runtime already contains 49,546 indexed events and 14,785 episodes.

ISSUE:
The analysis hot path repeatedly rediscovers episode spans and post-event facts from the complete bundle. Long sessions therefore grow much more expensive than their added evidence warrants, and candidate-producing sessions add another full-stream pass per candidate.

OPTIMIZE:
- Build one ordered event-position index when a canonical bundle is loaded for analysis.
- Resolve every episode's start/end sequence to array offsets once and pass offset ranges/views through detectors.
- Cache registry-derived detector constants once per analysis run rather than rebuilding closed sets repeatedly where practical.
- Precompute suffix facts needed by detectors that intentionally inspect later evidence, such as whether a terminal/closure event follows a sequence.
- Make contrary-evidence scanning use indexed episode bounds rather than restarting at event zero for every candidate.
- Avoid `list(bundle["events"])` copies on detector hot paths.

GUARDRAIL:
- Sequence numbers are ordered but need not be contiguous; offsets must be resolved by mapping/bisect, not `seq == list index`.
- `detect_active_work_preemption` and `detect_source_closure_false_green` deliberately inspect events after a local trigger; optimization must preserve that semantic reach.
- User overrides before a candidate inside the episode must remain visible to contrary-evidence logic.
- Candidate ordering, rule_ids, event_refs, confidence, no-hindsight behavior and emitted finding identity must remain structurally identical.

VERIFY:
1. Existing Wave B/C detector fixtures remain structurally identical before/after optimization.
2. Add 1k/2k/4k/8k proportional scaling regression.
3. Doubling events+episodes should approach ~2x rather than current ~4x, with a tolerant CI threshold.
4. Candidate-heavy benchmark proves contrary-evidence processing does not restore quadratic growth.
5. Memory remains O(events + episodes), never O(events × episodes).

[P1] [PERF-002] PROVEN BOTTLENECK tools/saipal_engine/inbox.py::import_inbox / tools/saipal_engine/bundle.py::{load_bundle_file,validate_bundle,bundle_digest,canonical_bytes}

EVIDENCE:
- Current `.saipal/session_inbox` contains 99 canonical JSON files totaling 36,639,390 bytes.
- `import_inbox()` lines 70-80 fully reads, parses, validates and canonically hashes every inbox artifact every invocation before duplicate handling.
- `validate_bundle()` lines 126-131 recalculates `bundle_digest()` whenever `session_sha256` is present.
- `import_inbox()` line 80 immediately calculates `bundle_digest()` again, yielding two canonical JSON serializations/hashes per ordinary bundle.
- `save_index()` is unconditional at inbox.py:106 even after a scan with no meaningful index mutation.
- Temporary-home reproduction using the supplied 99-file inbox:
  pass 1: 1.108649s
  pass 2: 0.979739s
  profiled pass: 1.341s / 1,891,525 calls.
- Profiled pass contained:
  `load_bundle_file`: 99 calls / 0.878s cumulative
  `parse_bundle` + `validate_bundle`: 99 / 0.680s
  `bundle_digest`: 198 calls / 0.480s
  JSON encoding: 201 calls / 0.493s
  `_validate_events`: 99 calls / 0.435s.
- 95 of the 99 files were already duplicate-digest skips in that run, yet all still paid the complete parse/validation/hash cost. Two repeatedly imported artifacts are explained by the independently reported CORE-002 identity defect and do not affect this I/O amplification conclusion.

ISSUE:
The durable forensic inbox behaves like a transient queue that is reprocessed from byte zero every cycle. Continue cost therefore grows with all historical retained evidence instead of new or changed evidence. Large canonical hashing is also duplicated inside each pass.

OPTIMIZE:
- Add a durable intake receipt/cache keyed by artifact path plus a cryptographically trustworthy byte/content identity and prior disposition.
- Fast-path exact previously consumed bytes without reparsing canonical JSON.
- Revalidate whenever content changes under the same filename.
- Compute canonical bundle digest once after parsing and reuse it for declared-digest validation and import identity.
- Build session/generation digest lookup maps once per intake pass rather than repeatedly linearly searching the session index.
- Track index dirtiness and skip `save_index()` when intake did not mutate authoritative state.
- Where SAIPAL itself atomically creates an inbox artifact, persist or return its already-known digest so the immediately following intake does not regenerate equivalent work.

GUARDRAIL:
- Filename, mtime and size alone are insufficient evidence of unchanged forensic content.
- A previously rejected artifact must be retried if its bytes change.
- Same-name changed COLD evidence must still reach generation logic after W2-004.
- CORE-002 global generation dedup and HOT prefix-conflict detection must not be bypassed.
- Canonical inbox files remain immutable evidence from SAIPAL's perspective; no cleanup/delete optimization.

VERIFY:
1. First pass validates N artifacts normally.
2. Second byte-identical pass performs zero canonical bundle JSON parses/hashes and zero session-index write.
3. Change one valid artifact under the same filename -> only that artifact is reparsed and reconciled.
4. Change one previously rejected artifact -> it is retried.
5. COLD generation and HOT conflict outcomes stay identical to the corrected reference implementation.
6. Rebenchmark the current 99-file/36.6MB fixture; unchanged intake should become bounded metadata/receipt work rather than ~1 second of complete JSON processing.

[P1] [PERF-003] PROVEN BOTTLENECK tools/saipal_engine/dispatcher.py::dispatch_sources / tools/saipal_engine/adapters/opencode.py::{stable_watermark,normalize,identity,_read_rows}

EVIDENCE:
- Every adapter exposes `stable_watermark()`, but repository-wide search finds no runtime caller outside the adapter definitions.
- `dispatch_sources()` lines 69-85 performs full `adapter.normalize()` for known HOT candidates on every poll before deciding whether output changed.
- OpenCode `stable_watermark()` lines 234-250 executes one cheap SQLite `count(*)`.
- OpenCode `normalize()` line 611 loads all historical message+part rows through `_read_rows()`, JSON-decodes them and rebuilds all canonical events.
- OpenCode `normalize()` then calls `identity()` at line 814.
- `identity()` lines 199-231 performs another complete `part` query and constructs one giant concatenated JSON string before hashing it, so one normalization reads historical part data twice and allocates a full-history intermediate blob.
- Independently reproduced synthetic OpenCode SQLite measurements:
  1,000 parts: watermark 0.000211s; normalize 0.010614s; identity 0.003736s; normalize/watermark 50.3x
  2,000: 0.000283s; 0.020394s; 0.007476s; 72.2x
  4,000: 0.000708s; 0.048010s; 0.016983s; 67.8x
  8,000: 0.000956s; 0.101411s; 0.032926s; 106.1x.
- Current session index contains 35 HOT sessions, so unchanged-HOT polling is a routine operating path.

ISSUE:
HOT polling is proportional to complete provider-session history even when nothing changed. The project already implements a cheap progress probe but does not use it. OpenCode then duplicates history traversal again for identity construction.

OPTIMIZE:
- Define one dispatcher probe contract returning a cheap stable provider watermark plus the evidence needed to decide whether full normalization is necessary.
- Persist the last accepted provider watermark/fingerprint with HOT session state.
- If provider-specific guarantees prove the source unchanged, skip normalization entirely.
- On growth, normalize only the verified tail from a durable provider cursor/offset/row key and merge it with the accepted canonical prefix.
- Periodically or conditionally perform full verification where provider mutation semantics require it.
- For OpenCode identity, feed rows incrementally into SHA-256 instead of materializing `"".join(...)`.
- Reuse rows already loaded during normalization rather than querying unchanged parts a second time.

GUARDRAIL:
- `count(*)` alone is not sufficient proof if provider rows can mutate in place; the fast path must reflect actual provider guarantees or fall back to full verification.
- HOT prefix mutation must still produce CONFLICT.
- W2-003's durable dispatcher cursor/fairness and attempt accounting remain authoritative.
- W2-004's COLD change detection must not be replaced with a session-id shortcut.
- Hidden/reasoning filtering and stable evidence locator generation must remain identical.

VERIFY:
1. Unchanged HOT session performs no full normalize.
2. Append N provider rows -> cost scales with N appended rows, not total historical rows.
3. Tail-normalized canonical bundle equals fresh full normalization for the same final source.
4. Mutate an accepted prefix -> full verification/conflict path detects it.
5. Restart preserves provider cursor/watermark safely.
6. OpenCode 1k/2k/4k/8k unchanged polls become approximately constant/sublinear rather than current linear full normalization.

[P1] [PERF-004] PROVEN BOTTLENECK tools/saipal_engine/sessions.py::{load_index,save_index,new_record} / tools/saipal_engine/inbox.py::_extend_hot / tools/saipal_engine/pipeline.py::analyze_sessions / tools/saipal.py::{_continue_cycle,cmd_status}

EVIDENCE:
- Current `.saipal/sessions/index.json` is 11,129,891 bytes for only 101 session records.
- It embeds 14,785 episode objects, 6,812 `mechanical_spans` and 15,520 copied `evidence_refs`.
- Re-serializing the supplied index while removing one field at a time measured:
  `episodes`: 2,552,251 bytes = 22.93%
  `mechanical_spans`: 1,449,748 bytes = 13.03%
  `evidence_refs`: 6,934,001 bytes = 62.30%.
- Removing all three from that representation leaves 193,891 bytes, a 98.26% reduction. This measures duplication potential, not permission to discard required semantics.
- Repository-wide search finds `mechanical_spans` persisted in sessions.py/inbox.py but no runtime consumer.
- Current-index benchmark:
  `load_index()` median 0.06444s
  `save_index()` median 0.11127s.
- `_continue_cycle()` loads the large index at lines 104 and 131; `import_inbox()` separately loads/saves it internally; analysis then receives and eventually saves it again.
- `analyze_sessions()` lines 344-346 unconditionally saves findings index, the complete session index and telemetry even when no session is analyzed.
- Temporary-home no-work benchmark with every session exhausted:
  `sessions_analyzed=0`, `events_analyzed=0`, `findings_created=0`
  median `analyze_sessions()` = 0.08374s while still rewriting the 11.1MB session index.
- `cmd_status()` loads the session index in `_load_read_only()` and then loads it again at line 678 before coverage.
- Actual supplied-baseline `saipal --json status` measured 0.93s wall time and 153,356KB maximum RSS in this sandbox.

ISSUE:
Authoritative mutable state and large duplicated/derived historical metadata share one monolithic JSON document. Every tiny state transition, no-op analysis pass and status call pays multi-megabyte parse/validation/allocation costs, and write paths replace the entire historical structure.

OPTIMIZE:
- Stop persisting `mechanical_spans` after parity tests confirm it has no consumer.
- Add dirty tracking: no authoritative mutation means no session-index rewrite.
- Thread one already-loaded index through a continue transaction wherever correctness/locking permits instead of reloading it at each phase.
- Make `cmd_status()` reuse the already-loaded index for coverage.
- Split hot mutable session metadata from large per-session derived history through compact sidecars or another bounded store.
- Avoid duplicating full `evidence_ref` payloads where canonical bundles already retain the immutable reference; store compact lookup data only where random access actually requires it.
- Preserve an explicit schema/version migration for existing 11MB indexes rather than silently dropping fields.

GUARDRAIL:
- Episodes were derived under historical segmentation rules; they must never be regenerated under a newer registry without preserving the governing segmentation version/contract.
- Canonical bundles remain immutable forensic source evidence.
- HOT prefix digest, generation, source imports, protocol binding, conflict state and semantic cursor remain durable.
- Any sidecar treated as authoritative requires schema/digest linkage and atomic persistence; otherwise it must remain rebuildable cache.
- Shared-index reuse must retain W2-001 ownership fencing and single-writer semantics.

VERIFY:
1. Migrate the supplied 101-session index with identical status, coverage, evidence and next-carrier results.
2. No-work analysis performs zero session-index write.
3. One modified session writes only the compact affected durable state, not unrelated historical megabytes.
4. `status` loads session state once and remains behavior-compatible.
5. Existing supplied state footprint drops materially; document the measured result rather than forcing the theoretical 98.26% ceiling.
6. Restart/corruption tests preserve fail-closed forensic behavior.

[P2] [PERF-005] PROVEN BOTTLENECK tools/saipal_engine/pipeline.py::_record_recurrence / tools/saipal_engine/recurrence.py::{load_recurrence,save_recurrence,record_occurrence,record_negative}

EVIDENCE:
- `_record_recurrence()` lines 378-386 invokes `record_occurrence()` once for every finding produced by one session.
- Every `record_occurrence()` lines 132-137 loads the complete recurrence ledger, mutates one occurrence, validates/serializes it and atomically rewrites the complete ledger.
- `record_negative()` has the same load-whole/save-whole transaction for one clean observation.
- Current recurrence ledger is 47,581 bytes, so the cost is currently modest but grows directly with accumulated observations.
- Independent synthetic ledger containing 5,000 existing occurrences serialized to 1,964,278 bytes.
- Adding 20 findings through the current public per-finding API took 0.419215s.
- Equivalent one-load + 20 in-memory `_bump_occurrence()` operations + one atomic save took 0.016220s.
- The same logical mutation was ~25.8x faster when persisted once.

ISSUE:
Persistence granularity is one full-ledger transaction per finding rather than one transaction per logical session/submission batch. Cost grows as O(new_findings × historical_ledger_size), producing needless parse, allocation, serialization, fsync and atomic-replace amplification.

OPTIMIZE:
- Add a batch recurrence API that loads once, applies an ordered list of occurrences in memory, validates once and atomically saves once.
- Have `_record_recurrence()` send the whole session result set through that batch API.
- Keep single-occurrence methods as wrappers for genuine one-item callers.
- Avoid a write for an empty/idempotently already-recorded batch once W2-002 exactly-once submission recovery exists.

GUARDRAIL:
- W2-008 requires malformed/unsupported recurrence state to fail closed and remain untouched; batching must not initialize over corrupt state.
- W2-009 requires rule-scoped clean comparison semantics; batching cannot collapse or globally smear negative evidence.
- One batch remains one atomic durable transition, not an in-place partially writable structure.
- Occurrence ordering and recurrence verdicts must be identical to sequential reference behavior.

VERIFY:
1. Sequential reference and batch update produce equivalent validated recurrence content for the same ordered observations.
2. Instrumentation proves one load and one save for N findings from one session.
3. Failure before final atomic save leaves the previous ledger byte-identical.
4. Retry remains exactly once after W2-002 recovery work.
5. Repeat the 5,000-existing + 20-new benchmark and retain an order-of-magnitude reduction.

[P2] [PERF-006] STRONGLY EVIDENCED WASTE tools/saipal_engine/log.py::read_events / tools/saipal.py::_load_read_only

EVIDENCE:
- `read_events()` lines 89-114 calls `LOG.jsonl.read_bytes()`, decodes the complete byte array, creates a complete `splitlines()` result, JSON-parses all valid records and retains every record dict in `events`.
- `_load_read_only()` uses that complete lifetime list only for `len(events)` and malformed-line count.
- LOG is append-only, so status memory and CPU have no natural upper bound.
- Current supplied LOG is only 4,846 bytes, so the defect is not presently dominant.
- Independent 100,000-event synthetic LOG:
  file size 9,288,895 bytes
  `read_events()` time 0.956707s
  events returned 100,000
  traced peak allocation 93.72MB.
- The caller needed only two scalar counts, so nearly all retained event objects were transient status-only allocation.

ISSUE:
A constant-size observability answer materializes and retains the complete lifetime append log. In unattended long-running operation, `status` acquires O(total-log-size) latency and memory spikes for data it does not return.

OPTIMIZE:
- Add a streaming `log_stats()` iterator that maintains only valid-event and malformed-line counters.
- Use it from status/read-only surfaces that need only counts.
- Keep `read_events()` for callers that genuinely require complete event bodies.
- Where other callers require only tails/ranges, expose bounded iterator/tail APIs rather than returning the lifetime log.
- If later adding persisted counters for constant-time status, make them verifiable checkpoints linked to file offset/size/digest; do not replace the append-only evidence source with an unchecked counter.

GUARDRAIL:
- Preserve exact malformed-line counting and UTF-8 replacement behavior.
- Never truncate, normalize or repair LOG during a read.
- Torn final lines remain visible as malformed evidence.
- W2-012's backward sequence-recovery repair remains independent and must continue to locate the true last durable sequence.

VERIFY:
1. Streaming stats exactly match `read_events()` counts on mixed valid/malformed/torn fixtures.
2. 10MB and 50MB synthetic logs show approximately constant working memory.
3. Missing/empty LOG behavior remains unchanged.
4. Status output stays structurally identical except for reduced resource use.
5. Existing consumers needing full event bodies remain behavior-compatible.

PERFORMANCE_DONE_WHEN: PERF-001..PERF-006 have explicit regression/performance controls; detector/analyst processing scales near-linearly on proportional episode streams; unchanged canonical inbox evidence is not reparsed/rehashed every cycle; unchanged HOT sources avoid full-history normalization and append work is tail-proportional without weakening prefix-conflict detection; session state is dirty-written, loaded once per logical phase where safe, and materially compacted without changing historical semantics; recurrence performs one atomic load/save per logical batch; status does not materialize the lifetime LOG; all referenced CORE/W2 correctness invariants remain green; `python -B tools/validate.py` remains >=270/270; compileall passes; focused functional tests stay green; and dedicated scaling tests demonstrate bounded CPU/memory growth.

---
ALL_3_DONE_WHEN: 3/3 waves validated and combined into canonical handoff package.