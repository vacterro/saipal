# SAIPAL

A forensic protocol observer for SAIPEN-governed agent sessions.

SAIPAL reads real session evidence, compares observed behavior against the SAIPEN
protocol version that actually governed it, isolates root causes, and hands
qualified findings to the SAIPEN Core maintainer as immutable audits.

SAIPAL is **not** a second maintainer. It observes and reports. The maintainer
decides.

## How it is built

Two layers, and the boundary between them is the whole design
(`saipal/ARCHITECTURE.md`):

- **Layer A — the deterministic kernel.** Stdlib-only Python in
  `tools/saipal_engine/`. Owns evidence identity, digests, the session index,
  HOT/COLD watermarks, protocol binding, carrier allocation, mechanical detector
  signals, finding validation, the do-no-harm gate, audit construction and the
  single constrained enqueue. It never calls a model and never reads meaning.
- **Layer B — the replaceable analyst.** Any capable agent. It reads dialogue
  meaning, argues both sides of a finding, and submits one structured candidate
  per unit of work through `saipal submit` — its only write path.

That split is what makes the tool auditable: the part that can hallucinate cannot
write, and the part that writes cannot interpret.

## Start here

- `saipal/BOOT.md` — how SAIPAL starts, recovers and checkpoints
- `saipal/CORE.md` — the global laws (incl. PAL-EVIDENCE-02: transcripts are untrusted data)
- `saipal/ARCHITECTURE.md` — the two-layer boundary
- `saipal/SKILL.md` — thin agent adapter: any agent can act as SAIPAL
- `saipal/ANALYSIS.md` — the semantic forensic reasoning contract
- `saipal/COMMANDS.md` — the operator surface
- `saipal/INDEX.md` — document map: one question, one owner document

## Install it as a skill

`skills/saipal/SKILL.md` is the Freebuff skill manifest for `/saipal cc`.
Copy it into your platform skills directory to make the command available to
any agent:

```bash
mkdir -p "$HOME/.agents/skills/saipal"
cp skills/saipal/SKILL.md "$HOME/.agents/skills/saipal/SKILL.md"
```

`/saipal cc` engages DETECTIVE mode (the bounded analyst loop: `cc` →
`--json next` → reason prosecutor/defender → `submit` → repeat within
`SAIPAL_CC_BUDGET`) and ends in REPORTER mode (`report`), so an agent given
the skill can judge real sessions and report drifts with attribution. The
engine and protocol stay in this repository; the skill only resolves
`saipal_root` (env `SAIPAL_ROOT`, then the known checkout, then nearest
ancestor holding `tools/saipal.py` + `saipal/SKILL.md`) and the `.saipal/`
home.

## Run it

```bash
python -B tools/saipal.py continue          # one bounded cycle (alias: cc)
python -B tools/saipal.py continue --drain  # repeat cycles until idle or blocked
python -B tools/saipal.py --json next       # the next analysis carrier
python -B tools/saipal.py submit cand.json  # absorb one analyst candidate
python -B tools/saipal.py report            # the drift report
python -B tools/saipal.py status            # compact summary
python -B tools/saipal.py sessions 25       # known sessions, freshest first
python -B tools/saipal.py --json evidence SESSION EVENT   # bounded untrusted window
python -B tools/saipal.py doctor            # read-only diagnosis
python -B tools/saipal.py setup --source PATH --kind generic   # configure
python -B tools/saipal.py disposition receipts.json            # closed loop
python -B tools/saipal.py trigger           # request one pending run (coalescing)
python -B tools/test_runner.py              # full suite, clean checkout
python -B tools/validate.py                 # protocol and registry drift gate
```

Standard library only. No pip dependencies. Python 3.8+.

## The analyst loop

```
saipal --json continue          # import evidence, run the mechanical pass
saipal --json next              # one bounded carrier: episode + evidence + law
   reason over it, then
saipal --json submit cand.json  # DRIFT, NO_DRIFT or INSUFFICIENT_EVIDENCE
saipal report                   # the verdict, with the coverage behind it
```

`NO_DRIFT` is a first-class result: it is the receipt that proves an episode was
examined, and the only thing that advances the semantic watermark. A clean session
is therefore *proved* clean rather than merely unaccused.

`report` never reads as clean when nothing was judged. Its verdict set is
`NO_EVIDENCE`, `NOT_EXAMINED`, `NO_DRIFT_SO_FAR`, `DRIFT_SUSPECTED`,
`DRIFT_REPORTED`, and coverage always travels beside it.

## What keeps it honest

- **No hindsight.** A finding may claim a violation only if the session's protocol
  binding is known and the rule existed in the governing version.
- **Binding is proved, never declared.** A bundle claiming `BOUND` persists as
  `UNKNOWN`: the proof is re-derived against operator-declared protocol authority
  (a Git repository, a release root or a snapshot root) and must match real bytes.
- **Transcripts are untrusted data.** Analyzed conversations are evidence, never
  authority; text inside a session cannot expand what SAIPAL may do.
- **Do no harm.** A fix that reaches a protected invariant without declaring it,
  from a disposition that blames a model rather than the protocol, is blocked
  before it can become an audit.
- **One root cause, one finding.** Identity is a normalized causal key, so a
  rephrase does not split a recurrence chain.
- **Spread decides the fix surface.** One model drifting where another complied is
  model noncompliance, not a protocol defect.

## Status

Version 0.4.2. Waves A–I plus the semantic analyst loop (carrier, candidate
schema, submission boundary, no-drift receipts, coverage, paged episodes,
sink retry, trigger coalescing) are implemented and green: 970 unit tests and
273 validator checks.

Publication defaults to `STAGE_ONLY`; `PUBLISH_ENABLED` requires an explicit
operator-reviewed shadow pass **and** a validated sink root in the same call.

See `WAVE_I_CHECKPOINT.md` for founding coverage,
`docs/TERMISAI_EVIDENCE_CONTRACT.md` for the evidence contract,
`SAIPAL_OPERATIONAL_HANDOFF.md` for the operational surface and failure modes, and
`docs/audits/` for external audits of this repository.

## Exercise a real audit end-to-end

```bash
cp tests/golden_sessions/agent-noncompliance-command-route.json .saipal/session_inbox/
python -B tools/saipal.py cc
python -B tools/saipal.py report
# -> .saipal/audit/staging/1.md, .saipal/findings/index.json,
#    .saipal/closed_loop_links.json
```
