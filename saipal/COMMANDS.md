<!-- OWNER: saipal/COMMANDS.md -->
<!-- RULES: PAL-CMD-01, PAL-CMD-02, PAL-CMD-03 -->
<!-- ENUMS: carrier_phases=IDLE,RECOVER,BLOCKED; next_carriers=idle,resume-session,advance-candidate,resolve-conflict,analyze-episodes,discover-sources -->
# COMMANDS — the operator surface

Carrier phases: `IDLE`, `RECOVER`, `BLOCKED`.

`next` carriers: `idle`, `resume-session`, `advance-candidate`,
`resolve-conflict`, `analyze-episodes`, `discover-sources`. On
`analyze-episodes`, `next` also returns the full analysis carrier — the bounded
unit of work owned by `ANALYSIS.md`.

Global options precede the command. Canonical JSON forms are
`saipal --json next`, `saipal --json continue`, and, once registered,
`saipal --json evidence ...`. Post-command `--json` is not accepted.

## PAL-CMD-01 — closed command surface

The executable surface is exactly these commands plus the alias below.

| Command | Alias | Mutates | Purpose |
| --- | --- | --- | --- |
| `saipal continue` | `pal` | yes | run one bounded analysis cycle |
| `saipal status` | — | never | compact carrier summary |
| `saipal next` | — | never | the next analysis carrier to pick up |
| `saipal report` | — | never | the drift report: findings, attribution, coverage |
| `saipal evidence SESSION EVENT` | — | never | bounded untrusted evidence window around an event |
| `saipal setup` | — | yes | configure sources, sink, publication mode |
| `saipal sources doctor\|discover` | — | never | read-only source health report and discovery candidates; discovery never trusts |
| `saipal sources enroll\|enable\|disable\|remove` | — | yes | the canonical source-control write gate: enrollment and state changes are config-only; provider evidence is never deleted |
| `saipal doctor` | — | never | read-only diagnosis report |
| `saipal submit FILE\|-` | — | yes | absorb one analyst candidate (Layer B's only write path) |
| `saipal disposition` | — | yes | import maintainer disposition JSON |
| `saipal trigger` | — | yes | request one pending run (coalescing) |
| `saipal sessions [N]` | — | never | list known sessions, freshest first (N = limit, default 25) |
| `saipal analyst-setup` | — | yes | create/adjust the analyst runtime config (disabled by default) |
| `saipal analyst-doctor` | — | never | read-only analyst readiness report plus the blocked-population triage: which class of session is not analyzable, and the canonical command for each class (no network, no tokens) |
| `saipal analyst-status` | — | never | read-only worker state: journal, budgets, last run |
| `saipal analyst-requeue` | `--dry-run`, `--class C`, `--limit N`, `--reason T`, `--force` | worker lock | re-open units the candidate contract refused: one FRESH attempt each, admitted only under changed material or `--force`, budgeted by `budgets.max_requeues_per_unit` |
| `saipal investigate` | — | yes | autonomous semantic loop: allocate, deliberate, submit, repeat within budget; `--calibrate [--seed S]` runs the bounded shadow calibration through the same worker (explicit `--max-units N` required, never drains, STAGE_ONLY only) |
| `saipal watch` | — | yes | foreground unattended supervisor: bounded semantic cycles through the real worker, durable checkpoint, adaptive wake, single-owner lock; `--status` is read-only and works while the supervisor runs; `--max-cycles N` bounds it; refuses non-STAGE_ONLY publication loudly |
| `saipal readiness status` | — | never | read-only publication-gate readiness state (absent/ok/unrecoverable + attestation) |
| `saipal readiness mint --sink PATH --max-cycles N --max-units-per-cycle N --max-model-attempts N` | — | yes | run a real bounded STAGE_ONLY convergence review and mint the durable readiness proof from its actual report; refused on any failed/incomplete review; refuses to overwrite an existing or corrupt proof unless `--replace` authorizes atomic renewal |
| `saipal authority doctor\|discover` | — | never | read-only protocol authority health and candidates; discovery never trusts |
| `saipal authority enroll (--git-repository\|--release-root\|--snapshot-root) PATH` | — | yes | the ONE explicit trust action: persists the root plus pinning metadata (substitution detected, HEAD free to advance) |
| `saipal coverage` | — | never | read-only binding blocker planner: what still blocks historical rebind eligibility |
| `saipal operator-queue [--write]` | — | only with `--write` | ONE canonical operator queue (PAL-CPALL-05): every session partitioned into exactly one decision, each group carrying exact identities, the evidence, the missing decision, the legal and forbidden actions, the expected effect and the unlocks it depends on; ranked by sessions released per decision, `UNKNOWN` where leverage cannot be computed. Read-only and model-free by default; `--write` persists the deterministic packet and refuses an incomplete one |
| `saipal rebind [--dry-run]` | — | yes | deterministic historical rebinding: recomputes binding proof from enrolled authority, writes only strengthening transitions, reports newly eligible units; downgrade attempts recorded never applied |
| `saipal cpall [--status\|--stop]` | — | yes | `/goal cpall`: one DURABLE objective that chains bounded mechanical and semantic slices until a truthful terminal state (rules in `CPALL.md`); `--status` is read-only, `--stop` cancels explicitly |
| `saipal goal cpall\|status\|stop` | — | yes | the `/goal` operator form; the leading `/goal` slash token routes here, so `/goal cpall` is exactly `saipal goal cpall` |

Bare `saipal` means `saipal continue`, and `/saipal pal` is the same command where
slash routing exists. Aliases live in `REGISTRY.json` under `shortcuts`, never in
prose; an alias resolves to its canonical command before dispatch, and a shortcut
is a command, not a greeting.

`cpall` is the ONLY command that is not bounded to one process: `/goal cpall`
accepts a durable autonomous convergence objective, and its rules live in
`CPALL.md` (PAL-CPALL-01..03), not here. `continue`, `--drain`, `investigate` and
`watch` keep exactly the bounded semantics documented above.

Exit codes: `0` success, `1` refused, `2` usage error, `3` no SAIPAL home. The
code decides the exit status wherever it was raised: a `USAGE` refusal from
inside a subcommand still exits `2`.

## PAL-CMD-02 — status and next never write

`status`, `next`, `report`, `evidence`, `sessions`, `operator-queue` and
`doctor` are strictly read-only: they never create or materialize the home,
normalize sessions, create or merge findings, enqueue audits, append to the log,
or touch an analyzed project or SAIPEN Core. All refuse with `NO_HOME` when no
home exists and say so with a next action. `analyst-requeue` is the way back for
a refused unit — the journal-side twin of `rebind`: one fresh attempt, only under
changed material.
`analyst-doctor`/`analyst-status` are read-only and never
call a network; `analyst-setup` writes only `.saipal/analyst.json`; only
`investigate` may call a model (config- and egress-gated); `continue` never does.
`status` prints a compact summary and never dumps transcripts or finding text.

`next` reports the next carrier. On `analyze-episodes` it also returns the
`analysis_carrier` for the pending semantic episode (contents owned by
`ANALYSIS.md`), including the `slice` naming which bounded window of that episode
this is. It stays read-only, so `next` may be polled and returns the same unit
until the semantic position advances. Pending semantic work outranks a frozen
`CONFLICT` — an operator task that never resolves itself — and the conflict count
is still reported alongside.

`evidence SESSION EVENT [--before N] [--after N]` resolves the indexed event's
provider locator and returns one bounded `UNTRUSTED EVIDENCE` envelope without
creating a home, advancing a watermark, caching, logging or creating findings.
Reasoning locators are refused as `EVIDENCE_INADMISSIBLE`, never widened.

## PAL-CMD-03 — continue is bounded and honest

`continue` walks this order and stops at the first step producing work:

1. claim the pending trigger, then recover own state;
2. retry any staged audit a sink has not confirmed;
3. dispatch configured sources through their adapters;
4. import canonical bundles from the inbox;
5. analyze episodes into findings;
6. emit qualified audits;
7. checkpoint and return idle.

Rules of the road:

- No evidence means clean idle, and idle is a successful outcome. `continue`
  never fabricates a finding to look busy.
- Each run is bounded by limits on sessions, events, candidates, context and time.
  Hitting a limit checkpoints the exact continuation position and returns a
  resumable next action; it never loses progress.
- A refusal is a result: a code, a reason and a next action.
- `continue` may materialize an absent home: recovering its own state is its first
  legal act. With no configured sources and the default tool-root home it
  auto-discovers known agent session stores (opencode, via SQLite); an explicit
  `--home` / `SAIPAL_HOME` deployment never auto-discovers.

`continue` reports per cycle: `dispatched`, `imported`, `skipped`, `rejected`,
`conflicts` and the resulting hot/cold counts. A rejected source or bundle never
aborts the cycle. Sessions are taken freshest-first; an already-indexed COLD
session is skipped only when its raw source still hashes to what was staged — a
known session id is not proof the artifact is unchanged — and hot sessions are
re-read for new tail events.

### `continue --drain` — repeat until there is nothing left

`--drain` is the only argument `continue` accepts and it is opt-in: a bare
`continue` remains exactly one cycle. With it, bounded cycles repeat until a real
terminal condition, reported as `drain_outcome`: `idle` (the backlog drained),
`blocked` (a `CONFLICT` needs the operator) or `safety_valve` (the cycle, time or
audit-per-cycle cap in `hardening.SafetyValve` tripped). Totals are summed and
every per-cycle result kept, so a drained run is as auditable as its cycles.
`--drain` remains bounded to one process; only `cpall` chains across processes.

## report — the drift report

`saipal report` answers "did the protocol drift, and how do you know?" from the
findings index, the session index and the semantic receipts. `verdict` is a
closed set: `NO_EVIDENCE` (nothing indexed), `NOT_EXAMINED` (evidence indexed, no
episode judged yet), `NO_DRIFT_SO_FAR`, `DRIFT_SUSPECTED` (findings exist but none
qualified) or `DRIFT_REPORTED` (an audit was emitted). Every report carries
**coverage beside the verdict** — episodes judged, provisional, pending, plus the
slice counts behind them — because "no drift" is only meaningful next to how much
was actually examined, and a clean verdict over an unexamined home is the tool
reporting its own idleness.

Per finding it names lifecycle state, drift class, severity/confidence, change
target, rule ids with owner documents, causal key, occurrence count, recurrence
spread, do-not-weaken warnings, any do-no-harm block or provisional hold, and the
audit number when emitted. Attribution names the models, providers and projects
behind the occurrences. It writes nothing and may run at any point.

## sessions — fresh-first session list

`saipal sessions [N]` lists known sessions, freshest first, with temperature,
status, event count, the analyzed watermark and exhaustion. Read-only; at most one
argument (the limit, default 25).

## setup — explicit one-time configuration

`saipal setup --source PATH --kind K --sink PATH --mode MODE --maintainer PATH`
validates every argument before committing anything, so the old config survives a
failed setup untouched. Publication defaults to `STAGE_ONLY`; `PUBLISH_ENABLED`
requires `--shadow-reviewed` AND a validated sink root AND a matching durable
readiness proof in the same call — the flag alone was never authority.

## readiness — the production publication gate (T-109)

`PUBLISH_ENABLED` is proof-based; `--shadow-reviewed` alone is NOT sufficient.

1. Keep the home `STAGE_ONLY` and configure the maintainer sink root.
2. Mint the durable proof with a real bounded `STAGE_ONLY` canary:
   `saipal readiness mint --sink PATH --max-cycles N --max-units-per-cycle N
   --max-model-attempts N` writes `.saipal/readiness.json` from that ACTUAL
   report; failed, blocked or incomplete reviews are refused and nothing mints.
3. Transition explicitly:
   `saipal setup --sink PATH --mode PUBLISH_ENABLED --shadow-reviewed`. The gate
   revalidates proof, sink identity/manifest and the reviewed software fingerprint
   against LIVE state; a mismatch is a zero-write `PUBLICATION_GATE_CLOSED`.
4. Every external-effect boundary (new audit AND pending-audit retry) revalidates
   the same gate. A refusal stages/keeps the audit locally `PENDING` — evidence is
   never lost, never delivered.

A normal `watch --canary` run never enables publication; minting is its own
explicit operator act, and the proof invalidates when authored publication/runtime
code changes while staying stable across state churn.

Historical protocol authority is declared here and only here, as existing
directories: `--protocol-git PATH` (a SAIPEN Git repository),
`--protocol-releases PATH` (roots named `<version>/`), `--protocol-snapshots
PATH` (roots named `<tree_fingerprint>/`). A session's binding selects an
identity *inside* a declared root; a transcript never names a path. Undeclared
means retrieval reports `authority not configured` and analysis continues.

## submit — the analyst boundary

`saipal submit FILE.json` (or `-`) absorbs exactly one structured candidate
(`ANALYSIS.md` PAL-ANALYSIS-04/05). The kernel re-derives the unit from its own
index and refuses, with zero writes, a malformed candidate
(`CANDIDATE_INADMISSIBLE`), one answering another unit or stale evidence
(`CANDIDATE_OUT_OF_SCOPE`), an unindexed session or episode
(`EVIDENCE_NOT_FOUND`), or a frozen `CONFLICT` (`SESSION_CONFLICT`).

An accepted `DRIFT` candidate merges through the normal finding lifecycle — the
do-no-harm gate, qualification threshold and audit quality gate all still decide.
`NO_DRIFT` and `INSUFFICIENT_EVIDENCE` record negative evidence. Either way the
semantic position advances once and a receipt is returned naming the slice;
re-submitting one unit's verdict and reasoning returns that receipt and changes
nothing else.

**A submission survives being interrupted.** The intention is journalled before
any effect and retired by the receipt, and every effect is idempotent (recurrence
keyed by receipt, findings merged on fingerprint, audit slots on content digest,
forward-only cursors, tallies recounted from receipts), so a retried crash
converges on one application rather than doubling one.

## disposition — closed-loop intake

`saipal disposition FILE.json` imports compact maintainer result metadata
(`audit_number`, `disposition`, optional `receipt_id`, `work_id`, `fix_version`)
from a `dispositions` array. Import is idempotent per audit number; a changed
disposition appends the superseded verdict to that link's `history` instead of
rewriting it — a maintainer who changed their mind is calibration evidence.

## trigger — unattended coalescing

`saipal trigger` records one pending run; rapid repeats coalesce into one. A cycle
**claims** the token present at its start, so a trigger arriving mid-cycle stays
pending for the next one instead of being acknowledged and discarded, and a claim
left by a crashed cycle is honoured. Triggers never bypass the home lock, source
stability, budget, quality gate or publication mode.

## Outside the surface

`scan`, `show <id>` and `replay <session>` are not commands: they are refused as
unknown and nothing routes them. Adding one is a deliberate registry + docs + test
migration, never an argparse edit.
