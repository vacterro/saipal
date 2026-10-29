# SAIPAL architecture

A conceptual model for operators. The authoritative protocol lives in
`saipal/` (`saipal/ARCHITECTURE.md` owns the two-layer boundary; `saipal/REGISTRY.json`
is the machine authority).

## The two layers

```
   evidence (transcripts)                operator / maintainer
          │                                       ▲
          ▼                                       │ numbered audits
┌──────────────────────────┐            ┌──────────────────────────┐
│  Layer A — kernel        │   audit    │  human decides           │
│  stdlib-only, no model   │───────────▶└──────────────────────────┘
│  • digest + index        │                     ▲
│  • bind protocol version │                     │ one structured candidate
│  • mechanical detectors  │            ┌────────┴─────────────────┐
│  • findings, do-no-harm  │            │  Layer B — analyst       │
│  • enqueue (the only     │◀───────────│  any capable agent/model │
│    audit write path)     │  submit    │  prosecutor/defender     │
└──────────────────────────┘            └──────────────────────────┘
```

The kernel never calls a model and never reads meaning. The analyst never writes
state directly: `saipal submit` is its only write path, and the kernel
re-derives the unit it answers from its own index before accepting anything.
That split is what makes the tool auditable — the part that can hallucinate
cannot write, and the part that writes cannot interpret.

## The home (`.saipal/`)

The home is a plain directory of files you can read with any editor:

| Path | Contents |
| --- | --- |
| `STATE.json` | current cycle state, watermarks, checkpoint position |
| `LOG.jsonl` | append-only event log of the engine's own actions |
| `sources.json`, `config.json` | configured evidence feeds; publication mode, sink, protocol authority |
| `session_inbox/` | landing zone for canonical bundles; raw sources are never mutated |
| `sessions/index.json` | the session index: every imported session, generation, binding |
| `evidence/` | content-addressed raw event evidence backing the index |
| `findings/index.json` | deduplicated findings with lifecycle, occurrences, confirmation |
| `audit/staging/N.md` | numbered immutable audits (`audit/ledger.json` records digests) |
| `closed_loop_links.json` | finding → audit → disposition linkage ledger |
| `recurrence.json`, `telemetry.json`, `signals.json` | recurrence ledger, run/usage telemetry, mechanical signal ledger |
| `locks/` | fenced writer locks and the supervisor lease |

An absent home is never created by read-only commands (`status`, `next`,
`report`, `doctor`, `evidence`, `sessions` refuse with `NO_HOME`); only
`continue` (and explicit setup commands) may materialize one.

## Locks and fencing

Every mutating command takes a fenced lock under `locks/` before it touches
state. A lock carries a unique owner token; refresh and release re-read the node
and only act when the on-disk token still equals the holder's, so a successor
owner can never be overwritten by a stale process. A long-running `watch`
supervisor holds its own lease, refreshes it well before expiry, and fails
closed (`OWNERSHIP_LOST`) if ownership is ever gone. Two writers therefore
cannot interleave silently: the second one is refused `WRITER_BUSY` and exits.

## Intake and protocol binding

Sources are declared explicitly (`saipal setup --source PATH --kind KIND`).
Every cycle dispatches sources through per-source adapters into the inbox —
per-source isolation means a broken source is rejected without wedging others,
and a source outage is never treated as semantic evidence. Import is
content-addressed: a bundle's identity is its digest, and a re-import of the
same bytes is a no-op.

Each session carries a claim about which protocol version governed it. SAIPAL
never trusts that claim: the binding is *proved* against an operator-enrolled
protocol authority (a Git repository, a release root or a snapshot root) by
matching real bytes. Proof levels are `BOUND` / `PARTIAL` / `UNKNOWN`. `saipal
authority enroll` is the one explicit trust action; `saipal rebind`
recomputes proof from enrolled authority without touching evidence identity,
and only ever strengthens.

## Findings and verification

Detectors and the analyst feed one finding lifecycle:

```
NEW → QUALIFIED → EMITTED
         │
         └─ provisional / blocked / held (per the do-no-harm and quality gates)
```

- **Identity is a normalized causal key** (root cause + rule + evidence class),
  so a rephrased report of the same defect merges rather than duplicates, and
  recurrence is tracked per exact evidence occurrence.
- **Qualification requires a semantic DRIFT confirmation** tied to one of the
  finding's own occurrences, judged against a `BOUND` authority. Mechanical
  signals alone are triage-only hints for the analyst; they never stage audits.
- **The do-no-harm gate** blocks a "fix" recommendation that reaches a protected
  invariant without declaring it, or one whose disposition blames a model where
  the protocol is at fault.
- **The audit quality gate** refuses to emit placeholder or evidence-free audit
  bodies.

## Audits and publication

A qualified finding becomes `audit/staging/N.md`: numbered, collision-safe,
crash-idempotent (the slot allocation is content-addressed, so a crash-and-retry
returns the same audit rather than allocating a second one), and recorded in the
ledger with its digest. SAIPAL itself never edits or deletes an emitted audit —
the capability registry denies `edit_emitted_audit` and `delete_emitted_audit`
by name.

Delivery is a separate fact from staging. The default mode is `STAGE_ONLY`
(files stay local). `PUBLISH_ENABLED` is proof-gated: an operator must mint a
durable readiness proof from a real bounded convergence review
(`saipal readiness mint`), configure a validated sink, and enable publication in
the same call that presents the review flag. Every external-effect boundary
revalidates that gate against live state; a failed delivery stages the audit
locally and records a retryable pending publication, so evidence is never lost.

## Recovery and continuation

- A `STATE.json` SAIPAL cannot read is refused and left byte-identical on disk —
  recovery is refusal, never reconstruction from the log.
- Every cycle ends in a checkpoint; hitting a budget (sessions, events, context,
  time) records the exact continuation position and returns a resumable next
  action.
- Analyst submissions are journalled before any effect and retired by the
  receipt; every effect (recurrence writes, finding merges, audit slots,
  cursors) is idempotent per receipt, so a crashed submission can be retried to
  converge on one application.
- A crashed cycle leaves the fenced lock for stale takeover; a claim left by a
  crashed run is honoured rather than dropped.

## Filesystem confinement

SAIPAL's writes are confined to its own home by construction (PAL-WRITE rules):

- every confined primitive opens its target through the *entire verified path
  chain* — on POSIX component-by-component with `O_NOFOLLOW|O_DIRECTORY`
  directory descriptors, on Windows with a non-following reparse probe before
  each I/O;
- symlink, junction and reparse indirection is refused rather than followed;
- final-node creation is `O_EXCL` (or the reparse-verified equivalent), so an
  attacker-swapped node is detected at create time;
- transcript text can never name or widen a write path — it is data, not
  authority (PAL-EVIDENCE-02);
- the residual Windows window (a non-reparse delete+recreate swap between the
  last probe and the I/O) is documented in
  [`WAVE_I_CHECKPOINT.md`](../WAVE_I_CHECKPOINT.md) and closable only with
  handle-based APIs the stdlib does not expose.

Tests pin all of this, including a thousand-operation descriptor-lifetime
control (`tools/test_wave_pal_write_01.py`) that proves fd counts stay bounded
without relying on garbage collection or process exit.
