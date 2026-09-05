<!-- OWNER: saipal/AUDITS.md -->
<!-- RULES: PAL-AUDIT-01, PAL-AUDIT-02, PAL-AUDIT-03 -->
<!-- ENUMS: audit_publication_states=DRAFT,REDACTED,ENQUEUED,REJECTED_BY_GATE -->
# AUDITS — the only external write

This document owns the audit contract. The contract is implemented: audits are
built, redacted, gated, numbered and enqueued by the runtime.

## PAL-AUDIT-01 — immutability and ownership transfer

An audit is written once and never edited.

Before a successful enqueue, SAIPAL owns the candidate. After a successful
enqueue, the SAIPEN Audit Inbox owns the file. SAIPAL never edits, overwrites
or deletes an emitted audit.

A materially changed recurrence is a **new** audit linked by `related_audit`
or `amends_audit`. It is never an edit in place.

Publication states: `DRAFT`, `REDACTED`, `ENQUEUED`, `REJECTED_BY_GATE`.

A `REJECTED_BY_GATE` audit is not an error. It is the quality gate working:
the audit failed to answer the required questions and stays internal.

## PAL-AUDIT-02 — constrained enqueue only

SAIPAL may not choose filesystem paths. The enqueue is a single constrained
operation that:

1. acquires the audit inbox lock;
2. allocates a monotonic audit id and records the claim as `pending`;
3. writes temp then atomically renames to `audit/N.md`;
4. verifies the final digest and confirms the claim;
5. returns audit number, path, hash and operation id.

Numbering is monotonic and durable. Gaps are never reused. If the inbox holds
`1`, `2`, `5`, the next audit is `6`.

Idempotency binds `finding_id` + `audit_content_sha256` + enqueue operation id
+ returned audit number. A crash after file creation but before the local
checkpoint must not duplicate the audit: the slot was claimed before the file
existed, so the retry reuses that number and every file in the audit directory
stays named by a ledger entry. An unconfirmed claim is never a receipt.

**Publication is policy-gated, not always-on.** `config.json` carries
`publication_mode`: `STAGE_ONLY` (the default — audits land in the local
`audit/staging/`), `PUBLISH_ENABLED` (a validated external sink receives the
numbered audit; requires an operator-reviewed shadow pass) or
`PUBLISH_BLOCKED`. Private bookkeeping — the counter ledger, the entries
ledger, the lock — always stays inside the SAIPAL home; an external sink
receives the numbered audit file and nothing else.

An unavailable sink is not a lost finding: the audit stages locally, the failure
is logged, and the delivery is recorded as **pending** so a later cycle retries it
before doing new work. Local staging is not delivery — `EMITTED` means the audit
exists, `delivery: PUBLISHED` means the sink verifiably has it — and a retry
republishes that exact number and body, never a fresh audit.

## PAL-AUDIT-03 — minimal evidence, mandatory redaction

An audit carries minimal provenance, never a transcript dump: session id,
event sequence, digest, short relevant excerpt, and STATE/LOG/tool references.

**Identity is first-class.** A maintainer routes an audit by asking which model,
provider and agent produced the behavior, in which project, against which rule,
and which document owns that rule. Every emitted audit therefore names:
provider/model/agent, project name with root fingerprint and git head, session id
with generation, temperature and episode finality, the resolved `rule_ids` and the
owner documents behind them, plus the finding's `causal_key` so recurrence chains
are traceable by mechanism rather than by wording.

Secrets are redacted before enqueue. At minimum: API keys, access tokens,
passwords, cookies, `Authorization` headers and credential-bearing URLs.
Redaction emits `[REDACTED sha256=<digest>]` where useful.

The audit gate refuses to enqueue unless the audit answers, in order:

1. what happened, 2. where, 3. which model/project/adapter, 4. which protocol
version, 5. which rule applied, 6. what was observed, 7. why it is a
contradiction, 8. why it is not a simpler explanation, 9. where the likely fix
surface is, 10. what must not be weakened, 11. how to reproduce, 12. how to
prove closure.

**Answering means substantive content in the field that carries the answer, not a
present heading and not a populated neighbour.** Each question names the exact
fields that answer it, and every one of them must carry content: two questions can
share a section, so section-level checking let a blank `models` field pass on the
strength of a populated `projects` field beside it. A placeholder value
(`UNKNOWN`, `N/A`, `TBD`, generic filler) is not content.

Every emitted audit starts with `maintainer_verdict: PENDING`. SAIPAL never
sets a verdict.
