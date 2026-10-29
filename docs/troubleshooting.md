# Troubleshooting

Common states and how to read them. Exit codes: `0` success, `1` refused,
`2` usage error, `3` no SAIPAL home.

## No home / where is my state

- `refused [NO_HOME]` — a read-only command ran where no home exists.
  Read-only commands never create one on purpose. Run `saipal continue` once to
  materialize `.saipal/`, or point at an explicit home with `--home PATH` or
  `SAIPAL_HOME`.
- `refused [HOME_UNRESOLVED]` — home resolution failed (e.g. an explicit path
  that cannot be used). Fix the path or the environment variable.

## Refusals that mean "nothing was written"

| Code | Meaning | What to do |
| --- | --- | --- |
| `VALIDATION_FAILED` | input failed validation; state untouched | fix the argument; re-run |
| `CANDIDATE_INADMISSIBLE` | analyst candidate malformed or out of schema | the refusal lists every violation; fix the JSON |
| `CANDIDATE_OUT_OF_SCOPE` | candidate answers a different (or stale) unit | re-read the carrier with `saipal --json next` |
| `EVIDENCE_NOT_FOUND` | session/event not in the index | import first (`continue`); check the id |
| `SESSION_CONFLICT` | session frozen pending operator triage | resolve the conflict, then retry |
| `PATH_ESCAPE` / `CAPABILITY_DENIED` | a write or action outside the allowed boundary | expected refusal; check your configuration |

## Writers, locks and leases

- `refused [WRITER_BUSY]` — another cycle, worker or supervisor holds the home
  lock. Either is legitimate: wait, or stop the other process. Two writers never
  interleave silently.
- `LOCK_STALE` — a lock left by a crashed process was detected. Stale takeover
  is automatic and safe (ownership tokens are re-verified before any mutation).
- A `watch` supervisor reporting `OWNERSHIP_LOST` stopped itself because its
  lease was lost — by design it makes no further shared writes. Restart it.
- A `trigger` that reports `coalesced: true` means a run was already pending;
  rapid triggers merge into one.

## Sources and evidence

- A source shows `UNAVAILABLE`/`MISCONFIGURED` in `sources doctor` — a broken
  source is isolated and never wedges the others; fix or disable it and
  continue. A source outage is never semantic evidence.
- `BUNDLE_INVALID` / `INBOX_UNREADABLE` — a bundle in the inbox is malformed;
  it is rejected without aborting the cycle. The rest of the inbox still
  imports.
- `EVIDENCE_MISMATCH` — raw bytes no longer match the staged digest. Intentional
  mutation of an already-indexed source is treated as new evidence, never as a
  rewrite of history.
- Sessions stuck `UNKNOWN` binding — no protocol authority is enrolled, or the
  claim cannot be proved. Run `authority doctor`, enroll a real authority with
  `authority enroll`, then `rebind`. `UNKNOWN` sessions still analyze; they just
  cannot yield HIGH-confidence audits.

## Publication

- `PUBLICATION_GATE_CLOSED` — publication was requested without a valid
  readiness proof + reviewed sink. The audit stays staged locally (`PENDING`);
  nothing is lost. Follow the gate flow in `saipal/COMMANDS.md` (`readiness
  mint`, then `setup --mode PUBLISH_ENABLED --shadow-reviewed`).
- `SINK_UNAVAILABLE` — the sink is down or misconfigured. Audits remain staged;
  delivery is retried on a later cycle.
- `SEMANTIC_CONFIRMATION_REQUIRED` — an emit path was reached for a finding
  without a bound semantic DRIFT confirmation. This is the do-not-stage gate
  doing its job; run the analyst loop for the finding's evidence unit.

## State recovery

- `STATE_UNRECOVERABLE` — `STATE.json` exists but cannot be trusted. SAIPAL
  refuses and leaves the file byte-identical: recovery is refusal, never
  reconstruction from the log. Restore from backup or start a fresh home.
- Interrupted cycle — just run `continue` again. Checkpoints carry the exact
  continuation position; nothing has to be redone or guessed.
- Interrupted submit — safe to retry. The intention was journalled before any
  effect and the receipt retires it; effects are idempotent, so the retry
  converges instead of doubling.

## When the report looks wrong

- Verdict `NOT_EXAMINED` with sessions indexed — normal: no episode has been
  judged yet. Run `continue`, then the analyst loop (`--json next` → `submit`).
- Verdict `NO_DRIFT_SO_FAR` — read it *with* the coverage line; it only means
  what has been judged so far was clean.
- A finding you disagree with — that is what `disposition` and the prosecutor/
  defender `challenge` block are for; rejected-audit calibration is recorded,
  never rewritten.
