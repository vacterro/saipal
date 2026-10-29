# Running `/goal cpall`

`/goal cpall` starts **one durable objective**: keep processing eligible SAIPAL
work, and the work that becomes eligible because of it, until a truthful terminal
state — across batch budgets, model contexts, process restarts, backend outages
and isolated conflicts, without you re-issuing `cc`, `continue` or `drain`. The
process is disposable; the objective is not. Rule text: `saipal/CPALL.md`
(PAL-CPALL-01..03); command surface: `saipal/COMMANDS.md`.

## Start, inspect, stop

```bash
python -B tools/saipal.py goal cpall            # start or resume the objective
python -B tools/saipal.py goal status           # read-only: state, coverage, conflicts
python -B tools/saipal.py goal stop --reason "…"  # CANCELLED; evidence is kept
python -B tools/saipal.py cpall --slices 2      # bounded process, same objective
python -B tools/saipal.py cpall --units 10      # units per semantic slice
```

- `/goal cpall`, `goal cpall` and `cpall` are the same command.
- A second invocation while the objective is live is idempotent: it reports
  `cpall already active; attached to existing objective <id>` and starts no
  second worker. After a terminal state it opens a **new** objective id.
- `--slices N` bounds the *process*, never the objective: the objective stays
  `ACTIVE` and resumable, and the next invocation continues the same id.
- A bounded run releases its lease on exit, so the next invocation resumes at
  once. A run that dies releases nothing; the lease is then recovered from
  machine evidence (a gone PID on this host) or, for another host's lease, after
  its TTL.
- `status` is read-only and never reports `IDLE`/`DONE` because a slice ended.

## Execution semantics

Slices are **at-least-once**: a crash between a submission and its cursor
checkpoint replays that slice, and the same unit may be judged twice. Accepted
results are still **effectively exactly-once**, because the submission boundary
is idempotent per unit — receipt identity is the unit plus the verdict and
reasoning digest — so a replay returns the first receipt and advances the
semantic cursor once. Fairness is part of convergence, not a nicety: a session
with 1,300 pending units does not starve one with 10; carrier allocation owns the
policy and `cpall` keeps slicing until both are drained.

## Reading the state

| state | meaning | what it obliges you to do |
| --- | --- | --- |
| `ACTIVE` | eligible work remains | nothing; run it again (or let the supervisor) |
| `WAITING` | a recoverable condition: backend down, rate limit, retry delay, foreign lock | optionally fix the condition; it retries on its own schedule |
| `OPERATOR_BLOCKED` | every independent workstream is exhausted and what remains needs your authority (conflicts, egress consent, ambiguous source of truth) | resolve the named items, then start a new objective |
| `COMPLETED` | no eligible work, no scheduled continuation, no recoverable failure remains | nothing |
| `SAFETY_STOP` | a real invariant violation, persisted with its name | read the objective's `unresolved` entry before resuming |
| `CANCELLED` | you stopped it | nothing; previous evidence is intact |

Progress reports are written to `.saipal/cpall_reports.jsonl` (start, periodic
progress, state change, blocker, recovery, final) and the last few are echoed by
`status`. Report *delivery* is separate from checkpointing: a failed report is
recorded and retried, and never corrupts or ends the run.

`conflicts:` is unambiguous on every surface: `current` is the freshest-generation
population — the work items an operator must resolve — while `indexed` counts
every recorded occurrence, including superseded generations. The difference is
history, never a second work item.

## What it will not do

- It will not silently finish blocked, conflicted, failed or unanalysed work:
  `WAITING` never degrades into done, and a conflicted session is isolated and
  named rather than counted as complete.
- It will not approve remote evidence egress, resolve provenance conflicts,
  rewrite historical evidence or fabricate progress.
- It will not invent an ETA while throughput is unstable, and it will not treat a
  local budget, a batch boundary, a checkpoint, a context boundary or a process
  restart as a reason to stop.

## The terminal answer

On a home whose semantic backlog is unanalyzable and whose mechanical side has
nothing left, `cpall` stops with the truth instead of slicing forever:

```
cpall: OPERATOR_BLOCKED [cpall-...]
  family mechanical: DONE - intake and mechanical analysis are idle and no audit is undelivered
  family semantic: BLOCKED - the worker reports no analyzable unit remains, yet 18102 unit(s)
                           still lack a verdict (433 terminal, 132 provisional disabled, 37 done, 11 stale)
state_reason: operator authority required for: semantic; 11 isolated conflict(s) stay operator-resolved
```

`OPERATOR_BLOCKED` is reached only after every independent workstream is done —
that is what makes it information rather than a shrug. Resolve the named classes
(see the triage below), then run `/goal cpall` again; the objective re-opens and
re-examines both families.

## Reading the blocked population

`python -B tools/saipal.py analyst-doctor` ends with the triage that answers "why is
my semantic backlog not moving?" — the classes the analyst's own allocator
excluded, each with the canonical command that moves it (and, where a class has
no command, an explicit gap instead of a guess):

```
blocked: 563 unit(s) cannot be analyzed, 0 runnable (of 611 sessions)
  BLOCKED_BINDING 425: python -B tools/saipal.py coverage
  PROVISIONAL_DISABLED 130: python -B tools/saipal.py investigate --with-provisional --max-units N
  BLOCKED_OUTPUT 8: python -B tools/saipal.py analyst-requeue --dry-run
next blocked action: 425 BLOCKED_BINDING unit(s): python -B tools/saipal.py coverage
```

Binding walls are planned in detail by `saipal coverage` (blocker reasons,
recoverability, representative sessions), enrolled with `saipal authority enroll`
and applied with `saipal rebind`.

## A refused unit is not a lost unit

`analyst-requeue` is the way back for a unit the candidate contract refused
(`BLOCKED` in the journal) — the journal-side twin of `rebind`: rebind wakes a
unit whose *authority* became sufficient, requeue wakes a unit whose *answer* was
refused. Without it, a refusal was terminal: the allocator treats `BLOCKED` as
terminal, so the unit was neither pending nor analysable and no command named it
ever again.

It buys **one fresh attempt**, and it is deliberately hard to spin:

- the refused attempt's raw response, repair text, candidate, critic payload and
  paid-attempt identity are CLEARED, so the next pass makes a new call with its
  own repair allowance rather than re-judging bytes already known to be
  inadmissible;
- it is admitted only when the material that produced the refusal CHANGED (the
  analyst config digest — a different model, endpoint or budget) or under an
  explicit, recorded `--force`;
- it is budgeted by `budgets.max_requeues_per_unit` (default 1, `0` disables the
  path), a durable counter carried in the job, so a crash cannot reset it;
- every other wall keeps its own owner and is refused **by name**:
  `BLOCKED_BINDING` → `authority enroll` + `rebind`,
  `REMOTE_OUTCOME_UNKNOWN` → the paid-attempt policy (it is never auto-replayed),
  `STALE` → re-import.

Every refused class is eligible by default — `BLOCKED_OUTPUT`, `VALIDATION_FAILED`,
`BACKEND_AUTH`, exhausted transport retries, and any class the protocol has not met
before. An allow-list would silently drop the class nobody thought of, which is the
failure this command removes; `--class NAME` is how you narrow it deliberately. The
triage prints the split by class (`refusal_classes`) so the group label cannot
claim more than the journal supports.

The refusal stays auditable: its digests, reason and the material it was paid
under are recorded in the job's `requeues` history.

```
python -B tools/saipal.py analyst-requeue --dry-run     # what would happen
python -B tools/saipal.py analyst-requeue --limit 5 --reason "model swapped to 14b"
```

Name the reason: a requeue does not repair a model, so a repeat refusal under an
unchanged config is the answer, and the journal will say exactly that.

## When it looks stuck

`goal status` prints the per-family disposition with its reason, plus the retry
schedule and the backend identity. Four shapes recur:

- **`semantic … WAITING` with a retry time** — the analyst backend is unavailable;
  it is retried with bounded backoff.
- **`semantic … BLOCKED - … fix the configuration …`, or an objective in
  `OPERATOR_BLOCKED` naming `semantic`** — the analyst's own refusal, quoted
  verbatim (a missing key, or a backend circuit opened on an `AUTH` failure).
  A credential requirement is an **egress** requirement, enforced by one
  predicate (`config.credential_verdict`) at the transport, the calibration
  preflight and `doctor`: a loopback endpoint has no remote party, so an unset
  `api_key_env` is inert there and the call proceeds header-less, while a
  non-loopback endpoint without its variable fails closed before a socket
  exists. `python -B tools/saipal.py analyst-doctor` shows the effective backend;
  the circuit latch is pinned to that verdict, so changing the config — or the
  verdict itself — half-opens it on the next attempt. A time-boxed circuit
  instead reads `backend circuit OPEN until <epoch>` and clears itself.
- **`semantic … ACTIVE - the analyst blocked the unit: historical binding is
  insufficient…`** — the analyst refuses to judge a unit because its provenance
  binding is `PARTIAL`. An authority problem, not a backend problem: see
  `saipal authority enroll`, `saipal rebind`, or accept the wall explicitly.
- **`semantic slice ran (…): N judged, M unit(s) blocked`** — the slice judged
  real units and one or more units were refused (inadmissible model output, or a
  session whose binding is insufficient). A blocked unit is a property of THAT
  unit: it is journaled, the slice keeps working through other sessions, and the
  family stays `ACTIVE` instead of backing off. Read the journal for the block
  reason; nothing is marked done.
- **`mechanical … DONE` while `semantic` keeps returning zero units** — the
  mechanical side has converged; check `mechanical_units_completed` (analyzer
  events) before reading `units_completed` (accepted semantic receipts) as
  "stalled".
- **`semantic … BLOCKED - the worker reports no analyzable unit remains, yet N
  unit(s) still lack a verdict (… classes …)`** — the strongest wall there is.
  The worker examined its whole population and found nothing it may analyse,
  while the kernel still counts N units without a receipt; the named classes are
  the reason (terminal/unbound sessions, provisional investigation not enabled,
  model-output blocks). It is an operator decision — `saipal authority enroll` /
  `rebind`, enable provisional work, use a different model, or accept the wall —
  and the objective answers `OPERATOR_BLOCKED` once the mechanical family is
  `DONE`.

Performance notes and the full invariant list live in the project's knowledge
base (`.saipen/KNOWLEDGE/CPALL.md`); the measured control-plane cost of a real
slice is ~13 % of its wall time, dominated by the queue scan. On the real home a
single bounded slice with `--units 3` produced three accepted semantic receipts
in 216 s (~0.8 units/min) against a local 9B model.
