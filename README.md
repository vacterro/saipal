# SAIPAL

**Forensic observation of AI agent sessions against their governing protocol.**

SAIPAL turns AI agent sessions into inspectable, durable project state. It indexes
session transcripts as evidence, checks what the agent actually did against the
protocol that governed the session, records findings, and hands qualified drift
reports to a human maintainer as immutable, numbered audits. The part that can
hallucinate cannot write; the part that writes cannot interpret.

| | |
| --- | --- |
| Language | Python 3.8+, standard library only — no pip dependencies |
| Platform | Windows verified (primary); POSIX focused controls executed, full POSIX certification deferred |
| Verification | Canonical suite and protocol validator; see [docs/verification.md](docs/verification.md) |
| Status | **v0.4.3** — usable, parked (SIDE1); see [CHANGELOG.md](CHANGELOG.md) |

## Why SAIPAL exists

AI coding agents are productive and opaque. When a session ends — normally, or in
the middle of something — the only record of what happened is the conversation
itself, which lives in a vendor's storage, rots with every new session, and cannot
be audited. Humans end up re-reading transcripts to answer simple questions: what
did the agent change, was it allowed to, did anyone verify it, what is still open.

SAIPAL moves that answer into your own filesystem, as plain files:

- **Explicit state.** A project gets a local `.saipal/` home with an index,
  findings, audits and telemetry. You can read every byte of it.
- **Judged sessions, not accused ones.** Episodes are examined one at a time; a
  clean session is *proved* clean, and the report always shows coverage next to
  the verdict.
- **Audits a human can act on.** Qualified drift becomes a numbered, immutable
  markdown audit — never silently rewritten or deleted by SAIPAL itself.
- **Work that survives interruption.** Cycles checkpoint exactly where they
  stopped; a crashed run resumes from explicit state instead of starting over.

## How it works

Two layers, and the boundary between them is the whole design:

- **Layer A — the deterministic kernel** (`tools/saipal_engine/`). Stdlib-only
  Python that owns evidence identity, digests, the session index, protocol
  binding, mechanical detector signals, finding validation, the do-no-harm gate,
  audit construction and the single constrained audit enqueue. It never calls a
  model and never reads meaning.
- **Layer B — the replaceable analyst.** Any capable agent or model. It reads
  dialogue meaning, argues both sides of a finding (prosecutor/defender), and
  submits one structured candidate per unit of work through `saipal submit` —
  its only write path.

Transcripts are treated as untrusted data: text inside a session can never expand
what SAIPAL is allowed to do. A drift claim must cite a rule that existed in the
protocol version that actually governed the session, and the binding to that
version is proved against real bytes — never taken from the transcript's word.

## Quick start

Requires Python 3.8+ (tested on 3.11). No installation; run from a clone.

```bash
# 1. Configure a source of sessions (a folder of canonical JSON bundles works as-is)
python -B tools/saipal.py setup --source tests/golden_sessions --kind generic

# 2. Run one bounded cycle: dispatch sources, index sessions, run the mechanical pass
python -B tools/saipal.py continue

# 3. Inspect the result
python -B tools/saipal.py status
python -B tools/saipal.py report
```

That is the mechanical loop. `setup`, `continue`, `submit` and the documented
analyst/convergence commands have explicit state-writing contracts;
`status`, `report`, `next`, `sessions`, `evidence` and `doctor` are strictly
read-only. Exit codes: `0` success, `1` refused, `2` usage error, `3` no home.

By default SAIPAL keeps its state in `.saipal/` under the checkout. Use
`--home PATH` or the `SAIPAL_HOME` environment variable to point it anywhere
else — read-only commands never create a home, and an explicit home reaches only
what you configured. Publication is staged locally by default (`STAGE_ONLY`);
nothing leaves the machine until an operator explicitly mints a readiness proof
and enables a sink.

POSIX note: on Linux, use `python3` and the same commands; the paths SAIPAL
reads are configured the same way. See [docs/verification.md](docs/verification.md)
for what has and has not been exercised on POSIX.

## A worked example

Sessions enter as canonical JSON bundles (adapters for several agent tools are
built in; `generic` takes a simple documented format). From intake to audit:

```text
canonical bundles (tests/golden_sessions/)          evidence enters the inbox
  └─ saipal continue                                 indexed; mechanical pass runs
       └─ mechanical signal raised (triage-only)     e.g. PHASE_ILLEGALITY
            └─ saipal --json next                    one bounded analysis carrier:
                 episode + evidence + applicable law
                 an analyst reasons prosecutor/defender, then
               └─ saipal submit candidate.json        verdict: DRIFT / NO_DRIFT /
                    INSUFFICIENT_EVIDENCE — the only write path for Layer B
                  └─ a DRIFT confirmed against a bound protocol authority
                       becomes a numbered, immutable audit:
                       .saipal/audit/staging/1.md
```

Three properties of that loop are the point:

- A submission is journalled before any effect and retired by its receipt, so a
  crashed submit can be retried without doubling anything.
- A DRIFT verdict only becomes an audit when the semantic confirmation is tied to
  a *bound* historical protocol authority. Suspicion alone never stages a file.
- `NO_DRIFT` is a first-class result — the receipt proving an episode was
  examined — and the only thing that advances the semantic watermark.

To follow the analyst boundary by hand, feed the noncompliance fixture and open
one bounded analysis carrier (the evidence command shows the same window from
the provider's own store when the session came from a configured provider
source):

```bash
cp tests/golden_sessions/agent-noncompliance-command-route.json .saipal/session_inbox/
python -B tools/saipal.py continue
python -B tools/saipal.py --json next           # the bounded carrier: episode + evidence + law
python -B tools/saipal.py report                # verdict + coverage + attribution
```

(With an analyst backend configured (`saipal analyst-setup --enable`, an
OpenAI-compatible endpoint), `saipal investigate` runs that loop unattended
within explicit budgets; without one it stops truthfully with `CONFIG_DISABLED`
and the mechanical signals and reports still work.)

## Important concepts

| Concept | What it means |
| --- | --- |
| Home | `.saipal/` — the state root: `sessions/`, `findings/`, `audit/`, `evidence/`, `locks/`, `LOG.jsonl`, `STATE.json`, `telemetry.json` |
| Source | A configured, read-only evidence feed (folder, provider store); raw sources are never mutated |
| Session / episode / slice | A bundle of events; segmented into episodes; long episodes page into slices — the bounded unit the analyst judges |
| Protocol binding | Proof of which protocol version governed a session (`BOUND` / `PARTIAL` / `UNKNOWN`); `UNKNOWN` can never reach a HIGH-confidence audit |
| Finding | A deduplicated drift claim with a causal key; lifecycle `NEW → QUALIFIED → EMITTED`; one root cause, one finding |
| Audit | Numbered immutable markdown in `audit/staging/N.md`; never overwritten or deleted by SAIPAL |
| Analyst loop | `next` → reason → `submit`, repeated within budget; the unattended form is `saipal watch` |

The full model — including locks and fencing, intake, publication and the
recovery flow — is in [docs/architecture.md](docs/architecture.md). The normal
operating rhythms (new project, incoming requirement, interrupted session,
verification, closure) are in [docs/workflow.md](docs/workflow.md).

## Repository layout

```
tools/saipal.py           CLI entry point
tools/saipal_engine/      Layer A kernel (stdlib-only modules)
tools/saipal_analyst/     Layer B worker runtime (unattended semantic loop)
tools/validate.py         protocol/registry drift gate
tools/test_*.py           the unittest suite
tools/test_runner.py      full suite from a clean checkout
saipal/                   the protocol: BOOT, CORE, ARCHITECTURE, COMMANDS,
                          SESSIONS, FINDINGS, AUDITS, ANALYSIS, SKILL, INDEX,
                          REGISTRY.json (machine authority), MANIFEST.json
skills/saipal/SKILL.md    agent skill manifest for the `/saipal pal` loop
tests/golden_sessions/    canonical fixture sessions, including a hostile-injection case
docs/                     architecture, workflow, verification, troubleshooting
audit/                    triage notes from external audits
```

## Verification status

- **Windows (primary):** source verification commands and the current
  acceptance record are in [docs/verification.md](docs/verification.md).
  Platform-skipped controls are recorded separately from executed passes.
- **POSIX:** the canonical suite was executed to completion on a POSIX
  interpreter with no descriptor exhaustion, and the focused descriptor-lifetime
  and lock-ownership controls passed. Certification on a *real Linux* host is
  **deferred verification debt**, not a known unresolved defect; the one
  divergence observed was host-specific (Cygwin `openat` re-resolves paths
  instead of pinning inodes). Do not treat POSIX as fully certified.

Counts live in exactly one place — the **Current verification truth** block of
[`WAVE_I_CHECKPOINT.md`](WAVE_I_CHECKPOINT.md). Historical checkpoint
identities stay attached to their original measurements; counts are re-derived after
every material change. Run them yourself any time:

```bash
python -B -m unittest discover -s tools -p "test_*.py"
python -B tools/validate.py
python -B -m compileall tools
```

Details and history: [docs/verification.md](docs/verification.md).

## Platform status and limitations

- **Windows is the primary supported platform.** The write-boundary is
  strongest-practical there (reparse-probe before every I/O, symlink/junction
  refusal, `O_EXCL` final-node create); a non-reparse delete+recreate swap in the
  final window is a documented residual, closable only with handle-based APIs the
  stdlib does not expose.
- **POSIX full certification is deferred**, as described above.
- **Publication is proof-gated, not safety-gated.** `PUBLISH_ENABLED` requires an
  explicit operator-reviewed readiness proof and a validated sink; even then,
  SAIPAL reports findings — it does not guarantee their correctness, and the
  maintainer decides.
- **No autonomous architecture claims.** SAIPAL observes, judges bounded units
  of evidence, and reports. It is not a self-driving engineer, and a clean
  report only ever means *as much was examined as the coverage line says*.
- Project state lives in `.saipal/` (git-ignored by design); nothing in it is
  required to understand this README.

## Development notes

SAIPAL is currently maintained as a personal, single-maintainer project and is
parked at a stable stage (SIDE1): issues and ideas are welcome, but there is no
contribution pipeline, CLA or roadmap process to plug into yet. Bug reports with
a reproducing command are the most useful input. The protocol under `saipal/` is
the contract: `REGISTRY.json` is the machine authority, `validate.py` is the
gate that keeps prose, registry and runtime from drifting apart, and any new
command or rule is a deliberate registry + docs + test migration.

- Protocol index: [`saipal/INDEX.md`](saipal/INDEX.md)
- Command surface: [`saipal/COMMANDS.md`](saipal/COMMANDS.md)
- Internal operational handoff (failure modes, sink contract):
  [`docs/internal/SAIPAL_OPERATIONAL_HANDOFF.md`](docs/internal/SAIPAL_OPERATIONAL_HANDOFF.md)
- Changelog: [`CHANGELOG.md`](CHANGELOG.md)

No license file is currently published; all rights reserved by the author until
one is added.

<!-- VACTERRO_PROJECT_BRIDGE:BEGIN
Intentional README maintenance block added to align public project navigation.
Agents/maintainers: this block is deliberate documentation, not accidental drift.
Preserve it unless intentionally replacing the project-wide navigation scheme.
-->
---

## Project network

This repository is part of the broader **SAIPEN / vacterro** project ecosystem.

[**Author hub**](https://github.com/vacterro) · [**SAIPEN HQ**](https://github.com/saipenhq) · [**SAIPEN Core**](https://github.com/vacterro/saipen) · [**ZAICODE**](https://github.com/vacterro/zaicode) · [**FastPrompter**](https://github.com/vacterro/FastPrompter) · [**SAIPEN Community**](https://discord.gg/SEYaYkuVgN)

For reproducible bugs and durable feature requests, use [this repository's GitHub Issues](https://github.com/vacterro/saipal/issues). Use Discord for quick discussion, screenshots, and cross-project feedback.

<!-- VACTERRO_PROJECT_BRIDGE:END -->

<!-- VACTERRO_SUPPORT:BEGIN -->
---
<sub>If this project is useful to you, optional support: [Buy Me a Coffee](https://buymeacoffee.com/vacuum34) · [Boosty](https://boosty.to/vacuum34/donate) · [PayPal](https://paypal.me/AlexNelin) · [other ways](https://github.com/vacterro/vacterro/blob/main/SUPPORT.md)</sub>
<!-- VACTERRO_SUPPORT:END -->
