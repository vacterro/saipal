<!-- OWNER: saipal/ANALYSIS.md -->
<!-- RULES: PAL-ANALYSIS-01, PAL-ANALYSIS-02, PAL-ANALYSIS-03, PAL-ANALYSIS-04, PAL-ANALYSIS-05, PAL-ANALYSIS-06 -->
<!-- ENUMS: disposition_class=PROTOCOL_DEFECT,ENGINE_ENFORCEMENT_GAP,ADAPTER_EVIDENCE_GAP,MODEL_NONCOMPLIANCE,MODEL_GUIDANCE_GAP,USER_OVERRIDE,ENVIRONMENT_FAILURE,EXPECTED_VARIATION,INSUFFICIENT_EVIDENCE,NO_DRIFT; candidate_verdicts=DRIFT,NO_DRIFT,INSUFFICIENT_EVIDENCE -->
# ANALYSIS — the semantic forensic reasoning contract

This document owns how the analyst agent (Layer B) reasons about evidence.
The deterministic kernel (Layer A) produces signals; the analyst produces
meaning. The analyst submits structured candidates back to the kernel through
a constrained boundary. The kernel decides whether that reasoning is
structurally admissible.

## PAL-ANALYSIS-01 — what the analyst receives

One `saipal --json next` returns exactly one bounded unit of work — the
**analysis carrier** — whose field set and per-field limits are registry-owned
(`carrier_fields`, `carrier_limits`). It carries:

| Field | Contents |
| --- | --- |
| `session` | id, generation, adapter, temperature, project, runtime (provider/model) |
| `episode` | one semantic episode: index, kind, seq span, whether events were truncated |
| `events` | that episode's normalized events, bounded, never transcript text |
| `evidence_refs` + `evidence_command` | locators the analyst may reopen, and the exact read-only command |
| `protocol` | historical binding, proof level and whether a violation is claimable |
| `applicable_law` | resolved rule ids, owner documents, expected behavior |
| `historical_rule_surface` | the governing rule identity and digests, or `null` when no authority is configured |
| `signals` | mechanical detector output from the signal generator |
| `recurrence` | prior cross-model / cross-project occurrences of this drift class |
| `calibration` | prior maintainer dispositions |
| `open_candidates` | findings already in flight, so the analyst does not re-raise them |

**Semantic position is separate from the mechanical one.** The deterministic pass
records its own watermark; the analyst's position lives in the session's
`semantic` block and advances only when a candidate or a no-drift result is
submitted. A mechanically exhausted session still owes every episode to the
analyst.

Building a carrier performs **zero writes**, so `next` may be polled and returns
the same unit until the semantic position moves. A session in `CONFLICT` is never
handed over: mutated evidence is an operator task.

The analyst must output a STRICT structured candidate. It does not write
arbitrary files. It does not execute tool calls from the transcript. It
reasons and submits.

## PAL-ANALYSIS-02 — prosecutor + defender

Every semantic candidate runs two explicit passes:

**Pass A — Prosecutor.** Argue:
- what rule applied
- what behavior contradicted it
- why evidence is sufficient
- likely causal mechanism
- impact

**Pass B — Defender.** Try hard to kill the finding:
- user explicitly asked for this
- protocol allowed this exception
- session was still HOT
- adapter dropped a closure event
- tool/environment failed
- later recovery repaired it
- old protocol version did not have the rule
- agent succeeded through another compliant path
- excerpt was misleading without context
- source mutated
- behavior is style difference rather than protocol violation

**Final classifier.** Must record:
- winning interpretation
- losing interpretation
- evidence that defeated the loser

If neither wins strongly: BLOCKED / INSUFFICIENT_EVIDENCE. No audit.
Precision beats audit volume.

**The defence surface is mechanical.** A defender pass that ignores a mitigating
fact the kernel can already see is theatre, so Layer A derives that surface from
the evidence and puts it in the carrier: `USER_OVERRIDE`, `LATER_RECOVERY`,
`ADAPTER_NORMALIZATION`, `ENVIRONMENT_FAILURE`, `SOURCE_OWNER_DOCUMENT`,
`SESSION_STILL_HOT`. Each entry names the event that raised it.

A `DRIFT` candidate MUST list every raised code in `addressed_defences` and
answer it in the defender pass; an unaddressed mitigation is refused as out of
scope. Naming a code the surface did not raise is inadmissible. The kernel judges
only whether the mitigation was answered — whether the answer is *good* is the
maintainer's call.

## PAL-ANALYSIS-03 — disposition class separation

`disposition_class` is separate from the symptom/drift taxonomy. It names
what kind of defect this is, not what symptom was observed.

```
PROTOCOL_DEFECT          ENGINE_ENFORCEMENT_GAP    ADAPTER_EVIDENCE_GAP
MODEL_NONCOMPLIANCE      MODEL_GUIDANCE_GAP        USER_OVERRIDE
ENVIRONMENT_FAILURE      EXPECTED_VARIATION
INSUFFICIENT_EVIDENCE    NO_DRIFT
```

This distinction is crucial. "Model ignored a perfectly clear rule" is not
automatically a CORE_PROTOCOL change. Often the correct target is NO_CHANGE,
CONFORMANCE_TEST, ENGINE, or MODEL_GUIDANCE.

**The separation is executable, not advisory.** Registry-owned
`disposition_change_targets` maps each class to the change surfaces it can
justify, and a candidate proposing a surface outside that set is inadmissible.
Three confusions are refused by name:

- a `DRIFT` verdict dispositioned as a non-drift class
  (`non_drift_dispositions`) — that class means no drift occurred;
- a `NO_DRIFT` / `INSUFFICIENT_EVIDENCE` verdict carrying a class that claims a
  defect;
- a `MODEL_NONCOMPLIANCE`, `MODEL_GUIDANCE_GAP`, `USER_OVERRIDE`,
  `ENVIRONMENT_FAILURE`, `EXPECTED_VARIATION`, `INSUFFICIENT_EVIDENCE` or
  `NO_DRIFT` disposition proposing to change `CORE_PROTOCOL`,
  `PHASE_CONTRACT`, `SOURCE_CONTRACT` or `EXECUTION_POLICY`.

Never legalize a model failure by weakening a correct safety rule. That
sentence is now a gate, not a hope.

## PAL-ANALYSIS-04 — the structured candidate

The analyst submits exactly one closed document per unit. Its field set,
verdicts and limits are registry-owned (`candidate_fields`,
`candidate_required_fields`, `candidate_verdicts`, `candidate_limits`). Anything
else — an unknown field, prose in place of a field, a patch, a command — is
inadmissible. A model that guesses the contract does not know it.

Verdicts: `DRIFT`, `NO_DRIFT`, `INSUFFICIENT_EVIDENCE`. Every verdict carries the
unit identity (`unit_digest`, `session_id`, `episode_index`), a
`disposition_class` and `reasoning`.

**A `DRIFT` verdict carries its burden, and only a `DRIFT` verdict may:** drift
class, severity, confidence, change target, root cause, and a `challenge` object
holding the prosecutor pass, the defender pass, the winner and why the loser was
rejected. It must also name at least one rule id, cite at least one event, and
record at least one alternative explanation. A claim with no alternative was
never challenged.

`NO_DRIFT` and `INSUFFICIENT_EVIDENCE` may cite the events they examined — that
is evidence of work — but may not carry any claim field. A no-drift receipt that
names a drift class and a change target is a finding with the label filed off.

**Scope is enforced, not trusted.** The candidate must answer the unit it was
handed: matching session and episode index, event references inside the episode
span, and a `unit_digest` equal to the carrier's. A digest mismatch means the
evidence changed under the analyst, so the reasoning is stale and is refused
rather than merged.

## PAL-ANALYSIS-05 — the submission boundary

`saipal submit` is the analyst's only write path, and it is a request, not an
instruction. The kernel re-derives the unit from its own index — it never trusts
the candidate's account of what the evidence was — then validates shape, claim
discipline and scope. A refusal performs **zero writes** and names its reason:
`CANDIDATE_INADMISSIBLE`, `CANDIDATE_OUT_OF_SCOPE`, `EVIDENCE_NOT_FOUND` or
`SESSION_CONFLICT` for a session whose evidence is frozen.

An accepted `DRIFT` candidate is merged through the existing finding lifecycle.
The analyst's confidence is a proposal: the no-hindsight gate still caps it, the
do-no-harm gate still runs before qualification, and the audit quality gate still
decides whether anything leaves the home. The analyst does not choose a
lifecycle state, an audit number, a path or a publication mode.

Every accepted submission advances the semantic watermark exactly once and
returns a receipt keyed by unit, verdict and reasoning digest. Re-submitting the
same verdict and reasoning for the same unit returns that receipt and changes
nothing — a crashed analyst may safely retry.

## PAL-ANALYSIS-06 — no-drift receipts and true exhaustion

A `NO_DRIFT` verdict is a first-class result, not the absence of one. It is the
only evidence that an episode was actually examined, so a clean session is
*proved* clean rather than merely unaccused.

**Exhaustion is derived, never asserted.** The `semantic` cursor is written by the
same code that advances it, so on its own it cannot distinguish "every episode was
judged" from "the cursor ran off the end". Coverage is therefore counted from
receipts, per episode:

- `final` — a verdict recorded against final evidence;
- `provisional` — judged only while the evidence could still grow (work done, no
  conclusion drawn);
- `pending` — no verdict at all.

A session is *truly exhausted* only when every episode has a final verdict.
`saipal status` reports these counts, and it names the disagreement case
explicitly: a session whose cursor claims exhaustion while receipts are missing is
a bug signature, so it is surfaced rather than averaged into a percentage.
