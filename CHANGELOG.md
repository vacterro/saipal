# Changelog

Product-level notes. Deep ticket evidence lives in the project's internal state
and logs; historical checkpoints are preserved in `WAVE_I_CHECKPOINT.md`.

## 0.4.3

The founding protocol roadmap is complete and the project is parked at a stable,
usable stage. Highlights since 0.4.2:

- **Explicit lifecycle and state.** Every cycle checkpoints an exact continuation
  position; interrupted runs resume from explicit state instead of restarting.
  `continue --drain` repeats bounded cycles until a real terminal condition
  (idle, operator-blocked, or safety valve) and stays fully auditable.
- **Intake and finding integrity.** Per-source intake with health truth and
  timestamps; HOT watermark polling skips re-normalizing unchanged history;
  canonical-bundle-backed evidence locators and single-parse intake; recurrence
  rows anchored to one exact evidence occurrence, so rephrased or grown findings
  never double-count.
- **Analyst loop hardening.** Structured candidate intake with closed-set
  validation (verdicts, challenge, alternatives); submissions journalled before
  any effect and idempotent per receipt, so a crashed submit can be retried to
  convergence; durable budget windows and circuit breakers for unattended use.
- **Audit and publication truth.** `EMITTED` means locally staged and is never
  conflated with external delivery; publication stays `STAGE_ONLY` by default,
  and enabling it requires an operator-minted readiness proof from a real
  bounded review plus a validated sink — revalidated at every external-effect
  boundary.
- **Write-boundary hardening (PAL-WRITE).** Confined filesystem primitives
  rebuilt around verified path chains, exclusive final-node creation and
  refusals of symlink/junction/reparse indirection; descriptor ownership made
  explicit with bounded fd lifetime under sustained operation (the founding
  fd-leak defect is repaired and evidenced); trigger claim/release and
  stale-takeover cleanup routed through confined primitives only.
- **Verification truth discipline.** One checkpointed source of test/validator
  counts (`WAVE_I_CHECKPOINT.md`), enforced by the validator; closure-chain
  auditing for work records; release-freshness and hygiene controls.

Platform posture: Windows verified as the primary platform (1,821 unittest
cases, 334 validator checks, compileall clean on the release tree; checkpoint
`T-164-VERIFY-2026-10-14-R13`). POSIX focused descriptor-lifetime controls
executed and passing; full POSIX certification on a real Linux host is deferred
verification debt, not a known unresolved defect. See `docs/verification.md`.

## 0.4.2

Recurrence anchor dedupe; semantic authority boundary — mechanical signals are
triage-only, DRIFT confirmation required, BIND-only historical authority;
legacy mechanical publications quarantined; analyst-confirm merge preserved.

## 0.4.1

Analyst confirmation merges onto mechanical findings; paged episodes, sink
retry, trigger coalescing.

## 0.4.0

Forensic protocol observer with the analyst loop closed: canonical session
bundles, episodes, mechanical detectors, prosecutor/defender semantic loop,
finding lifecycle with do-no-harm gate, immutable numbered audits, closed-loop
dispositions.
