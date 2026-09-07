<!-- OWNER: saipal/FINDINGS.md -->
<!-- RULES: PAL-FINDING-01, PAL-FINDING-02, PAL-FINDING-03 -->
<!-- ENUMS: finding_lifecycle=SUSPECTED,OBSERVED,BOUND,CHALLENGED,QUALIFIED,REJECTED,MERGED,BLOCKED,STALE,EMITTED; confidence_enum=HIGH,MEDIUM,LOW; severity_enum=P0,P1,P2,P3; drift_taxonomy=COMMAND_ROUTE_DRIFT,ACTIVE_WORK_PREEMPTION,BOARD_PRIORITY_DRIFT,PHASE_ILLEGALITY,PHASE_SKIP,SOURCE_AUTHORITY_DRIFT,SOURCE_CLOSURE_FALSE_GREEN,EVIDENCE_FABRICATION,RECOVERY_ORDER_DRIFT,DESTRUCTIVE_GATE_DRIFT,CONTINUE_IDLE_FALSE_POSITIVE,IMPROVE_PRECEDENCE_DRIFT,AUDIT_INBOX_DRIFT,HUSH_NARRATION_DRIFT,HUSH_SAFETY_SUPPRESSION,PROTOCOL_ENGINE_SPLIT,ADAPTER_COMMAND_SPLIT,COLD_RESUME_FAILURE,CHAT_MEMORY_AUTHORITY,FALSE_DONE,ACCIDENTAL_SUCCESS,RULE_LOAD_FAILURE,CONTEXT_OVERLOAD; change_target_enum=CORE_PROTOCOL,COMMANDS,PHASE_CONTRACT,SOURCE_CONTRACT,EXECUTION_POLICY,ENGINE,ADAPTER,HARNESS,CONFORMANCE_TEST,DOCUMENTATION,MODEL_GUIDANCE,NO_CHANGE,UNKNOWN -->
# FINDINGS — discipline over volume

This document owns the finding contract. The goal is a small number of findings
precise enough that the maintainer can reproduce, confirm or reject them
without rediscovering the session.

## PAL-FINDING-01 — lifecycle and dedupe

Lifecycle states: `SUSPECTED`, `OBSERVED`, `BOUND`, `CHALLENGED`, `QUALIFIED`,
`REJECTED`, `MERGED`, `BLOCKED`, `STALE`, `EMITTED`.

`SUSPECTED` is the pre-semantic floor: the state of every mechanical detector
signal and every legacy finding that was created before the semantic authority
boundary. A finding cannot leave `SUSPECTED` for a post-semantic state without
a semantic DRIFT confirmation tied to its evidence unit.

`EMITTED` means the finding reached an enqueued audit.

A finding is identified by its **fingerprint**, built from rule family, drift
class, normalized causal mechanism and change target. Session id is never the
primary identity dimension.

Merge behavior:

- many occurrences of one root cause → one finding with many evidence
  occurrences;
- different root causes in one session → separate findings;
- a weak or ambiguous candidate → `BLOCKED` or `REJECTED`, staying internal.

Drift taxonomy:

```text
COMMAND_ROUTE_DRIFT          ACTIVE_WORK_PREEMPTION     BOARD_PRIORITY_DRIFT
PHASE_ILLEGALITY             PHASE_SKIP                 SOURCE_AUTHORITY_DRIFT
SOURCE_CLOSURE_FALSE_GREEN   EVIDENCE_FABRICATION       RECOVERY_ORDER_DRIFT
DESTRUCTIVE_GATE_DRIFT       CONTINUE_IDLE_FALSE_POSITIVE
IMPROVE_PRECEDENCE_DRIFT     AUDIT_INBOX_DRIFT          HUSH_NARRATION_DRIFT
HUSH_SAFETY_SUPPRESSION      PROTOCOL_ENGINE_SPLIT      ADAPTER_COMMAND_SPLIT
COLD_RESUME_FAILURE          CHAT_MEMORY_AUTHORITY      FALSE_DONE
ACCIDENTAL_SUCCESS           RULE_LOAD_FAILURE          CONTEXT_OVERLOAD
```

## PAL-FINDING-02 — confidence and severity

Confidence is `HIGH`, `MEDIUM` or `LOW`.

`HIGH` requires all four: exact observed evidence, applicable protocol
binding, a clear expected rule, and no simpler alternative explanation.

Severity is `P0`, `P1`, `P2` or `P3`. Severity measures impact, not emotional
intensity, and never inflates on model brand alone.

Change target is one of: `CORE_PROTOCOL`, `COMMANDS`, `PHASE_CONTRACT`,
`SOURCE_CONTRACT`, `EXECUTION_POLICY`, `ENGINE`, `ADAPTER`, `HARNESS`,
`CONFORMANCE_TEST`, `DOCUMENTATION`, `MODEL_GUIDANCE`, `NO_CHANGE`,
`UNKNOWN`.

Suggested qualification thresholds:

- **Route A** — `P0`/`P1` + `HIGH` + protocol bound;
- **Route B** — `P2` + `HIGH` + reproduced or recurrent;
- **Route C** — mechanically proven protocol contradiction.

A `LOW` one-off style observation stays internal.

An isolated clear model failure under a clear rule normally points at no
protocol change, stronger executable enforcement, adapter guidance, a
conformance test, or model guidance. It does not justify rewriting CORE to
legalize bad behavior.

**The spread is computed, not assumed.** Recurrence classifies each drift class as
`SINGLE_MODEL`, `CROSS_MODEL`, `CROSS_PROJECT`, `CROSS_MODEL_AND_PROJECT` or
`UNKNOWN`, and reports which models drifted and which complied. The analyst
receives that verdict in the carrier and the audit records the version it was
judged against.

The decisive case is a compliant model beside a drifting one under the same rule:
that is model noncompliance, and the fix surface is enforcement, guidance or a
conformance test. The same drift under several models points the other way — at
the protocol or its executable enforcement.

## PAL-FINDING-03 — challenge pass and do-no-harm

Every `P0`/`P1` finding and every `CORE_PROTOCOL`-targeted finding survives two
passes:

- **pass A** argues why this is real protocol drift;
- **pass B** argues why it is not.

The final classifier explicitly records why the losing explanation was
rejected.

Before qualification, search for contrary evidence: a later tool result, a
later checkpoint, an explicit user override, a recovery event, adapter
normalization evidence, a missing owner document, or an environment/tool
failure. Do not stop at the first apparent contradiction.

**No semantic DRIFT verdict, no qualification.** The authority boundary is
executable, not documentary: `qualification_threshold` refuses every finding
that does not carry a semantic confirmation tied to its evidence unit
(receipt id, DRIFT verdict, session, episode, unit digest) — whatever the
mechanical confidence, severity, recurrence spread, protocol binding or
current lifecycle state. Mechanical evidence may prioritize investigation and
travel with a finding as supporting evidence; it can never by itself
establish protocol drift.

Every qualified finding states its protected invariants. If a proposed fix
could weaken destructive confirmation, recovery precedence, source closure,
`VERIFY`, `REVIEW`, provenance or cold continuation, the finding must redirect
the fix or warn the maintainer explicitly.

**The do-no-harm gate runs before qualification, mechanically.** A finding
whose change target could reach a protected invariant is checked against that
invariant set, and every warning it raises is recorded on the finding as
`harm_warnings`. A rule enforced only by prose is a rule a weak model skips;
the gate is executable and its result is part of the finding.
