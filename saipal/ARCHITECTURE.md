<!-- OWNER: saipal/ARCHITECTURE.md -->
<!-- RULES: PAL-ARCH-01 -->
# ARCHITECTURE — the two-layer boundary

SAIPAL is split into two deliberately separated layers. This document owns
that boundary; every engine module and every agent protocol lives on exactly
one side of it.

## Layer A — deterministic forensic kernel

Stdlib-only Python in `tools/saipal_engine/`. Owns everything that must be
deterministic, crash-recoverable and structurally validated:

- source discovery, read-only adapter access, normalization
- evidence identity, digests, session index
- HOT/COLD watermarks, protocol binding
- carrier allocation, evidence-window production
- mechanical detector signals (the **signal generator**)
- finding schema validation, dedupe, qualification invariants
- audit construction, redaction, immutable enqueue
- recurrence, dispositions, locks, crash recovery, telemetry

Layer A never calls an LLM. It never reads conversation meaning. It produces
**signals** and **structurally validated artifacts** — that is all.

## Layer B — replaceable analyst agent

An arbitrary AI agent (OpenCode, Claude Code, Codex, Gemini, future) that:

- reads dialogue meaning and reconstructs user intent
- recognizes instruction/protocol contradictions
- compares observed behavior to governing rules
- considers multiple explanations, identifies root cause
- recommends the narrowest maintainer direction
- constructs structured candidate findings

The analyst submits candidates back to Layer A through a constrained
submission boundary. It never writes arbitrary project files. It never
writes findings, audits or state directly.

## The signal generator contract

`tools/saipal_engine/analyst.py` is NOT a semantic analyst. It is a
deterministic **signal generator** — it maps mechanical detector output to
structured hypothesis templates. It answers "where should I look?", never
"what is the final truth?".

The real semantic analyst (Layer B) receives those signals as one input among
many, alongside evidence windows, historical rules and prior recurrence.

## Capability boundary

The registry separates two namespaces:

- `analyst_actions` is the Layer-B callable surface. It permits reading a
  carrier, reading admissible evidence, and submitting a structured candidate.
- `write_actions` is Layer A's internal mutation surface. It is never an
  analyst capability namespace.

Layer B performs zero direct write actions. `submit_candidate` is a validated
request handled by Layer A; it is not a write primitive. Layer A may validate,
write, merge or qualify a finding and may internally call `enqueue_audit`.
The analyst cannot call `enqueue_audit` directly. T-041/T-042 still own the
candidate schema and executable submission command; this boundary does not
pretend those later surfaces already exist.

No provider-specific semantic logic lives in Layer A.

## References

- `CORE.md` — the global laws that govern both layers
- `REGISTRY.json` — the machine authority for the boundary
- `COMMANDS.md` — the operator surface that bridges both layers
