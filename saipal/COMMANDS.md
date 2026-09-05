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
| `saipal continue` | `cc` | yes | run one bounded analysis cycle |
| `saipal status` | — | never | compact carrier summary |
| `saipal next` | — | never | the next analysis carrier to pick up |
| `saipal report` | — | never | the drift report: findings, attribution, coverage |
| `saipal evidence SESSION EVENT` | — | never | bounded untrusted evidence window around an event |
| `saipal setup` | — | yes | configure sources, sink, publication mode |
| `saipal doctor` | — | never | read-only diagnosis report |
| `saipal submit FILE\|-` | — | yes | absorb one analyst candidate (Layer B's only write path) |
| `saipal disposition` | — | yes | import maintainer disposition JSON |
| `saipal trigger` | — | yes | request one pending run (coalescing) |
| `saipal sessions [N]` | — | never | list known sessions, freshest first (N = limit, default 25) |

Bare `saipal` means `saipal continue`, and `/saipal cc` is the same command where
slash routing exists. Aliases live in `REGISTRY.json` under `shortcuts`, never in
prose; an alias resolves to its canonical command before dispatch, and a shortcut
is a command, not a greeting.

Exit codes: `0` success, `1` refused, `2` usage error, `3` no SAIPAL home. The
code decides the exit status wherever it was raised: a `USAGE` refusal from
inside a subcommand still exits `2`.

## PAL-CMD-02 — status and next never write

`status`, `next`, `report`, `evidence`, `sessions` and `doctor` are strictly
read-only. They must not create or materialize the home, normalize sessions,
create/merge/qualify findings, enqueue audits, append to the log, or touch an
analyzed project or SAIPEN Core. All refuse with `NO_HOME` when no home exists, and
say so with a next action rather than silently creating one.

`status` prints a compact summary only. It never dumps transcripts, event
payloads, or full finding text.

`next` reports the next carrier. On `analyze-episodes` it also returns the
`analysis_carrier` for the pending semantic episode (contents owned by
`ANALYSIS.md`), including the `slice` naming which bounded window of that episode
this is. Building it stays read-only, so `next` may be polled and returns
the same unit until the semantic position advances. Pending semantic work
outranks a frozen `CONFLICT` — an operator task that never resolves itself — and
the conflict count is still reported alongside.

`evidence SESSION EVENT [--before N] [--after N]` resolves the indexed event's
provider locator and returns one bounded `UNTRUSTED EVIDENCE` envelope. It does
not create a home, advance a watermark, cache, log, create findings or mutate
provider storage. Reasoning locators are refused as `EVIDENCE_INADMISSIBLE` and
never widened into surrounding output. `doctor` reports home, source config,
adapter availability, sink preflight, publication mode, declared historical
protocol authority, staged audits and lock state.

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

- No evidence means clean idle. Idle is a successful outcome.
- `continue` never fabricates a finding to look busy.
- Each run is bounded by limits on sessions, events, candidates, context and
  time. Hitting a limit checkpoints the exact continuation position and returns
  a resumable next action; it never loses progress.
- A refusal is a result, reported with a code, a reason and a next action.
- `continue` may materialize an absent home: recovering its own state is its
  first legal act.
- With no configured sources and the default tool-root home, `continue`
  auto-discovers known agent session stores (opencode, via its SQLite
  database). An explicit `--home` / `SAIPAL_HOME` deployment never
  auto-discovers: isolated homes reach only what the operator configured.

`continue` reports per cycle: `dispatched`, `imported`, `skipped`, `rejected`,
`conflicts` and the resulting hot/cold counts. A rejected source or bundle never
aborts the cycle. Sessions are taken freshest-first; an already-indexed COLD
session is skipped only when its raw source still hashes to what was staged — a
known session id is not proof the artifact is unchanged — and hot sessions are
re-read for new tail events.

### `continue --drain` — repeat until there is nothing left

`--drain` is the only argument `continue` accepts, and it is opt-in: a bare
`continue` remains exactly one cycle. With it, bounded cycles repeat until a real
terminal condition, reported as `drain_outcome`: `idle` (the backlog drained),
`blocked` (a `CONFLICT` needs the operator) or `safety_valve` (the cycle, time or
audit-per-cycle cap in `hardening.SafetyValve` tripped). Totals are summed across
cycles and every per-cycle result is kept, so a drained run is as auditable as the
individual cycles it replaced.

## report — the drift report

`saipal report` is the operator-facing answer to "did the protocol drift, and how
do you know?". It reads the findings index, the session index and the semantic
receipts, and returns one verdict plus the evidence behind it. `verdict` is a
closed set: `NO_EVIDENCE` (nothing indexed), `NOT_EXAMINED` (evidence indexed, no
episode judged yet), `NO_DRIFT_SO_FAR`, `DRIFT_SUSPECTED` (findings exist but none
qualified) or `DRIFT_REPORTED` (an audit was emitted). Every report carries
**coverage beside the verdict** — episodes judged, provisional, pending, plus the
slice counts behind them — because "no drift" is only meaningful next to how much
was actually examined. A clean verdict over an unexamined home is the tool
reporting its own idleness, so that case has its own verdict.

Per finding it names: lifecycle state, drift class, severity/confidence, change
target, rule ids with their owner documents, the causal key, occurrence count,
recurrence spread, do-not-weaken warnings, any do-no-harm block, any provisional
hold, and the audit number when one was emitted. Attribution answers who drifted:
the models, providers and projects behind that finding's occurrences. It writes
nothing, so it may be run at any point in a cycle.

## sessions — fresh-first session list

`saipal sessions [N]` lists known sessions, freshest first, with temperature,
status, event count, the analyzed watermark and whether analysis is exhausted. It
is read-only and takes at most one argument (the limit, default 25).

## setup — explicit one-time configuration

`saipal setup --source PATH --kind K --sink PATH --mode MODE --maintainer PATH`
validates every argument before committing anything. The old config survives a
failed setup untouched. Publication defaults to `STAGE_ONLY`; `PUBLISH_ENABLED`
requires `--shadow-reviewed` AND a validated sink root in the same call —
applying them as separate writes made `PUBLISH_ENABLED` unreachable.

Historical protocol authority is declared here and only here, as existing
directories: `--protocol-git PATH` (a SAIPEN Git repository),
`--protocol-releases PATH` (roots named `<version>/`), `--protocol-snapshots
PATH` (roots named `<tree_fingerprint>/`). A session's binding selects an
identity *inside* a declared root; a transcript never names a path. Undeclared
means retrieval reports `authority not configured` and analysis continues.

## submit — the analyst boundary

`saipal submit FILE.json` (or `-` for stdin) absorbs exactly one structured
candidate (`ANALYSIS.md` PAL-ANALYSIS-04/05). The kernel re-derives the unit from
its own index and refuses, with zero writes, a candidate that is malformed
(`CANDIDATE_INADMISSIBLE`), answers another unit or stale evidence
(`CANDIDATE_OUT_OF_SCOPE`), names an unindexed session or episode
(`EVIDENCE_NOT_FOUND`) or targets a frozen `CONFLICT` (`SESSION_CONFLICT`).

An accepted `DRIFT` candidate merges through the normal finding lifecycle — the
do-no-harm gate, qualification threshold and audit quality gate all still decide.
`NO_DRIFT` and `INSUFFICIENT_EVIDENCE` record negative evidence. Either way the
semantic position advances once — to the next slice of a paged episode, or past the
episode when the last slice is judged — and a receipt is returned naming the slice;
re-submitting the same verdict and reasoning for one unit returns that receipt,
reconciles the position and changes nothing else.

**A submission survives being interrupted.** The intention is journalled before any
effect and retired by the receipt, and every effect is idempotent: recurrence writes
keyed by receipt, findings merged on fingerprint, audit slots on content digest,
forward-only cursors and verdict tallies recounted from the receipts. A crashed
submission retried therefore converges on one application rather than doubling one.

## disposition — closed-loop intake

`saipal disposition FILE.json` imports compact maintainer result metadata
(`audit_number`, `disposition`, optional `receipt_id`, `work_id`,
`fix_version`) from a JSON `dispositions` array. Import is idempotent per
audit number; a changed disposition appends the superseded verdict to that link's
`history` instead of rewriting it, because a maintainer who changed their mind is
itself calibration evidence.

## trigger — unattended coalescing

`saipal trigger` records one pending run. Rapid repeated triggers coalesce into
one; a cycle **claims** the token present at its start, so a trigger arriving
mid-cycle stays pending for the next one rather than being acknowledged and
discarded, and a claim left by a crashed cycle is honoured. Triggers never bypass
the home lock, source stability, budget, quality gate or publication mode.

## Outside the surface

`scan`, `show <id>` and `replay <session>` are not commands. They are refused as
unknown and nothing routes them. Adding one is a deliberate registry + docs +
test migration, never an argparse edit.
