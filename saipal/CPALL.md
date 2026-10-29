<!-- OWNER: saipal/CPALL.md -->
<!-- RULES: PAL-CPALL-01, PAL-CPALL-02, PAL-CPALL-03, PAL-CPALL-04, PAL-CPALL-05 -->
<!-- ENUMS: cpall_states=ACTIVE,WAITING,OPERATOR_BLOCKED,COMPLETED,SAFETY_STOP,CANCELLED; cpall_families=mechanical,semantic -->
# CPALL — durable autonomous convergence

`/goal cpall` means: **keep processing all currently eligible work, and all work
that becomes eligible as a consequence of it, until SAIPAL reaches a truthful
terminal state.** Not one `cc`, not one `--drain`, not one carrier budget, not
one model context window, not one process lifetime.

`cpall` states: `ACTIVE`, `WAITING`, `OPERATOR_BLOCKED`, `COMPLETED`,
`SAFETY_STOP`, `CANCELLED`. Work families: `mechanical`, `semantic`.

## PAL-CPALL-01 — the objective is durable, the process is disposable

A cpall run is one persisted objective at `.saipal/cpall.json`, never a chat
convention and never a long-lived process. The objective records its id, state,
start/last-progress/last-checkpoint/last-report times, per-family dispositions,
counters (discovered, completed, remaining, eligible, blocked, conflict, retry),
sessions touched and completed, the durable cursor, the retry schedule, the
isolated conflict set with each conflict's material evidence, the failure
ledger, the report ledger and the current owner lease.

Only `COMPLETED`, `SAFETY_STOP` and `CANCELLED` are terminal. Everything else is
resumable, and a new process reconstructs the whole run from repository state:
the objective, the session index and the semantic receipts. No continuity lives
in conversational memory.

A budget — units per slice, model calls, wall clock, carrier count, slice
budget — is a **checkpoint boundary**. Hitting one persists progress and starts
the next bounded slice from the durable cursor. It never terminates the goal. A
bounded run also releases its lease on the way out, so the next invocation
resumes immediately instead of attaching to a process that has already exited.

Execution semantics are explicit: slices are **at-least-once** — a crash between
a submission and its cursor checkpoint replays that slice — and accepted
semantic results are **effectively exactly-once** anyway, because the submission
boundary is idempotent per unit (receipt identity is keyed by unit, verdict and
reasoning digest, so a replay returns the first receipt and advances the semantic
position once). Durability is required of the checkpoint, never of the process.

Fairness is a convergence requirement, not a nicety: a session with 1,300 pending
units must not starve one with 10. Carrier allocation owns the fairness policy;
`cpall` owns its consequence — the small session reaches its last unit long
before the large one, and the objective's session counters show both.

## PAL-CPALL-02 — one owner, truthful terminal states

One active owner may mutate a home's objective at a time, under a fenced lease
with a TTL and a live-owner probe. A lease belonging to this host is decided by
its process: a PID that still answers keeps the lease even past its TTL (killing
a healthy worker to take its home is worse than waiting), and a PID that is gone
makes the lease stale **now** rather than when the TTL happens to lapse. A lease
taken on another host cannot be probed locally, so its TTL decides. A crash, a
reboot, a stale lock, PID reuse or an abandoned worker is therefore recovered
automatically rather than by hand. A second
`/goal cpall` while the same objective is live is idempotent: it reports
`cpall already active; attached to existing objective <id>` and starts no second
worker. Cancellation is explicit (`/goal stop`), persists `CANCELLED`, stops
future retries, releases ownership and preserves every completed unit, receipt
and conflict record.

A family's state follows the WORKER's authoritative answer about its backlog, not
the kernel's count of units without a verdict. When the allocator reports that no
analyzable unit remains — or that the eligible set is exhausted with blocked
units recorded — while units still lack a verdict, those units are BLOCKED, not
absent: the classes the allocator excluded (terminal/unbound, provisional-
disabled, stale) are named in the family reason, the family goes `BLOCKED`, and
the objective reaches `OPERATOR_BLOCKED` once every other family is `DONE`. A
family that stayed `ACTIVE` there would slice forever over a backlog that can
never converge — the silent spin this rule exists to forbid.

The mechanical family settles on the cycle's DEBTS — nothing imported by the last
pass, no indexed record still owing locally processable episodes, no undelivered
audit — never on the cycle's `idle` boolean, which also folds in "some session is
in CONFLICT". A conflict is an isolated operator item (`derive_state` answers for
it), so counting it as mechanical work made the family unsettleable on a home with
any conflict at all, and the objective could not reach a terminal state. When the
mechanical family does settle and a semantic wall remains, the terminal state names
both: `operator authority required for: semantic; N isolated conflict(s) stay
operator-resolved`, where N is the number of conflict SESSIONS an operator
resolves.

`COMPLETED` requires that no eligible mechanical work, no eligible semantic
work, no scheduled continuation and no recoverable transient failure remains,
and the report must say why that is true. `WAITING` is what a recoverable
condition produces (backend down, rate limit, retry delay, foreign lock,
resource pressure): it persists a retry path and may never silently degrade into
done. `OPERATOR_BLOCKED` is reserved for a decision only an operator can make,
and even then every independent workstream continues first. `SAFETY_STOP` is a
real invariant violation, persisted with its exact name and recovery path.

A slice that advanced nothing but NAMED a wall — an analyst unit the worker
journaled as `BLOCKED_BINDING` or `BLOCKED` — carries that wall in its family
disposition reason and in the failure ledger, so a run blocked on protocol
authority can never read like a healthy one. Only a genuinely idle or merely
budget-bounded slice is a zero-failure slice.

## PAL-CPALL-03 — conflicts isolate, they never freeze

A `CONFLICT` is one operator-blocked work item, not a global stop. The affected
session is isolated with its exact conflict evidence and material digest
persisted, its episodes are removed from the eligible remainder, its watermark
stays frozen, and every unrelated eligible session keeps converging. `cpall`
reaches `OPERATOR_BLOCKED` only after all independent executable work is
exhausted.

The same isolation applies one level down, inside the worker: a unit the analyst
must block — an inadmissible model response, or a session whose historical
binding is insufficient — is a property of THAT unit. It is journaled and
counted, and the slice continues with every other eligible session instead of
ending on the first block. A run still stops as `BLOCKED` once nothing eligible
remains, and a slice that both judged units and blocked one names both in its
family reason (`N judged, M unit(s) blocked`).

`conflicts: N` is unambiguous: `current` is the freshest-generation population —
the operator-facing work items — and `indexed` counts every recorded occurrence
including superseded generations. The difference is history, never a second work
item. One derivation in the kernel owns those numbers, so `status`, `next`,
`report`, `doctor` and `watch --status` cannot disagree.

## PAL-CPALL-04 — a refusal has a canonical way back, and it costs something

No unit may be permanently lost, and no unit may be re-attempted for free. A unit
the candidate contract refused (`BLOCKED` in the analyst journal) is re-opened by
`saipal analyst-requeue` — the journal-side twin of `rebind`: rebind wakes a unit
whose *authority* became sufficient, requeue wakes a unit whose *answer* was
refused. Journal surgery is not a path; a command with a contract is.

A requeue buys exactly one FRESH attempt. The refused attempt's raw response,
repair text, candidate, critic payload and paid-attempt identity are cleared, so
the next pass makes a new call with its own repair allowance rather than
re-judging bytes already known to be inadmissible. It is admitted only when the
material that produced the refusal CHANGED — the analyst config digest, the same
identity the AUTH latch is pinned to — or under an explicit, recorded `--force`.
It is bounded by `budgets.max_requeues_per_unit`, a durable counter carried in the
job. A requeue does not repair a model: a repeat refusal under an unchanged config
is the answer, and the operator is told so by name.

Every other wall keeps its own owner: `BLOCKED_BINDING` belongs to
`authority enroll` + `rebind`, `REMOTE_OUTCOME_UNKNOWN` to the paid-attempt policy,
`STALE` to re-import. Those are refused with the canonical command attached, never
silently reactivated. When the worker reports no eligible unit remains and only
binding-blocked units are left, the family is `BLOCKED` and its reason carries
`authority enroll` + `rebind` — the wall's own owner, on the surface the objective
publishes. "An operator decision makes them eligible again" is not an answer: it
never says WHICH decision, and re-running the slice is the one action that cannot
work. The refusal is preserved by digest in the job's requeue history, so what was refused, why, and under which material stays auditable.

Reporting is durable and separate from delivery: the objective is checkpointed
on every slice, and the operator-facing progress record
(`.saipal/cpall_reports.jsonl`, plus the objective's bounded history) is emitted
on a configurable cadence — start, periodic progress, state change, blocker,
recovery and final. A failed report delivery is recorded and retried later; it
never corrupts or terminates the run.

## PAL-CPALL-05 — `OPERATOR_BLOCKED` is a drained boundary, not a shrug

Reaching `OPERATOR_BLOCKED` is a CLAIM: everything the agent may lawfully do is
done, and the remainder is exactly this set of human decisions. A state that
merely reports a blocker fails this rule the moment a safe, authorized action
still exists. `saipal operator-queue` discharges the claim — read-only and
model-free, derived from repository state, partitioning every session into
exactly ONE decision so the counts cannot disagree with the population.

**Unlike metrics are never merged.** "Recoverable" is not one number. A session
whose *reason* is fixable (`coverage`) and one carrying an artifact an authority
root can check (`analyst-doctor`) are different populations; the queue reports
both with the overlap and each one's allocator class named, because the
provisional check and the journal lookup disagree on some sessions and the
disagreement is the finding.

**A decision names its own unlock.** Each group carries exact identities, the
evidence, what is missing, the LEGAL and FORBIDDEN actions, the expected effect
and its dependent unlocks. Ranking is by sessions released, computed where
computable and marked `UNKNOWN` — never invented — where it is not. `UNKNOWN` is
an answer; a fabricated number is not.

**Nothing is invented.** Authority roots stay `CANDIDATE_ONLY` until an operator
supplies a real one: guessed paths, new empty directories, self-generated
material and unrelated git repositories are candidates, never enrolled.
Conflicts keep their identity and are batched without being merged;
`REMOTE_OUTCOME_UNKNOWN` is never replayed; provisional policy is never silently
enabled — where the flag is the whole wall, that is a PRODUCT limitation, not
corpus corruption. Terminal HISTORY is separated from terminal ENTRIES that
block convergence: the first is finished work, the second is unfinished work
that looks finished.

**The boundary answers five questions separately** — automated work complete,
corpus fully resolved, operator work remaining, permanently unverifiable, unsafe
to replay. Collapsing them is how a blocked corpus reads as a finished one.

**Resume is deterministic.** Nothing is derived from a clock, a pid or iteration
order; identities and counts are sorted. After one operator decision the rebuilt
queue reclassifies ONLY the affected sessions, which is what makes "did my
decision land?" checkable without a diff.
