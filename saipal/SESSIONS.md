<!-- OWNER: saipal/SESSIONS.md -->
<!-- RULES: PAL-SESSION-01, PAL-SESSION-02, PAL-SESSION-03, PAL-SESSION-04, PAL-SESSION-05, PAL-SESSION-06 -->
<!-- ENUMS: temperature_enum=HOT,COLD; adapters=generic,claude,codex,opencode,termisai,gemini; session_status=IMPORTED,CONFLICT; episode_finality=FINAL,PROVISIONAL; binding_status=BOUND,PARTIAL,UNKNOWN; binding_proof_levels=EXACT_COMMIT,RELEASE_REGISTRY,CAPTURED_FINGERPRINT,INSTALLED_RELEASE,UNKNOWN; historical_protection=PROTECTED,STILL_VULNERABLE,UNKNOWN; historical_rule_status=RESOLVED,UNAVAILABLE; historical_rule_sources=EXACT_COMMIT,RELEASE_REGISTRY,CAPTURED_FINGERPRINT,UNKNOWN; event_types=USER_MESSAGE,ASSISTANT_MESSAGE,COMMAND,TOOL_CALL,TOOL_RESULT,FILE_READ,FILE_WRITE,STATE_SNAPSHOT,BOARD_SNAPSHOT,LOG_EVENT,GIT_EVENT,PHASE_CHANGE,SOURCE_EVENT,ERROR,SESSION_BOUNDARY; episode_boundary_kinds=user_task,command,work_switch,phase_change,source_intake,recovery,terminal_task; evidence_locator_fields=source_kind,source_session_id,source_message_id,source_part_id,source_digest,role; evidence_source_kinds=opencode,claude,codex,gemini; evidence_roles=user,assistant,tool,unknown -->
# SESSIONS — canonical session evidence

Provider adapters normalize **into** this form. They may never redefine it.

## PAL-SESSION-01 — canonical bundle identity

A bundle is one JSON file dropped into `.saipal/session_inbox/`.

| Field | Meaning |
| --- | --- |
| `schema_version` | bundle schema version; only the registry's `bundle_schema_version` is accepted |
| `session_id` | stable identifier inside the source |
| `session_sha256` | digest of the canonical bundle content |
| `adapter` | adapter that produced it; one of the registry's `adapters` |
| `project` | analyzed project identity (`name`, `root_fingerprint`, `git_head`) |
| `runtime` | provider / model / reasoning_mode when known |
| `started_at`, `ended_at` | boundaries when known |
| `temperature` | `HOT` or `COLD` |
| `protocol` | protocol binding when known |
| `events` | normalized observable events |
| `raw_source_ref` | where the raw transcript came from |
| `raw_source_sha256` | digest of the raw transcript when known |

Identity is **source identity plus digest**, never a filename. A duplicate
digest does not create a second session. A changed digest creates a new
generation.

### Event contract

Every event carries:

| Field | Rule |
| --- | --- |
| `seq` | stable integer sequence number, strictly increasing |
| `type` | one of the closed `event_types` |
| `ts` | timestamp when known, else null |
| `loc` | source location when known, else null |
| `digest` | sha256 of the referenced content, else null |
| `facts` | minimal extracted structured facts |
| `evidence_ref` | optional compact provider locator; never transcript text |

An event never carries the transcript. The keys `content`, `text`, `body`,
`transcript`, `raw`, `message` and `payload` are **forbidden** on an event, and
a string inside `facts` longer than `evidence_budgets.max_excerpt_chars` is
rejected. Evidence is a digest plus structured facts plus a short excerpt —
a session bundle is not a second copy of the conversation.

An OpenCode locator uses stable provider session, message and part ids plus
the part digest and role. It never invents an id. Registry-owned field and
length limits keep locators compact. If one provider part yields multiple
events, those events share one locator. Reasoning parts remain inadmissible
and receive no canonical event or retrievable locator.

Evidence windows reopen only the configured/discovered provider source behind
an indexed locator. They are bounded by registry item, total-character and
single-item limits, exclude reasoning before window construction, identify
provider/project/model/session, and carry an `UNTRUSTED EVIDENCE` warning plus
a deterministic window digest. Reading a window has zero analysis side effects.

## PAL-SESSION-02 — temperature and stable watermark

A **hot** source may still be changing. Analyze only up to a stable watermark;
store `last_analyzed_seq` and `prefix_sha256`. On resume, verify the
already-analyzed prefix is unchanged.

- prefix unchanged → the session grew; keep the generation, extend the tail;
- prefix changed → status `CONFLICT`, `last_analyzed_seq` frozen, nothing
  silently continued over mutated evidence.

A **cold** source is complete and immutable. Unchanged digest means skip;
changed digest means a new generation, because a different artifact arrived.

One session id may therefore hold several generations. Semantic analysis is
offered for the **freshest generation only**: a candidate names a session plus an
episode index, so offering a superseded generation would hand out a unit the
submission boundary cannot address. Older generations keep their receipts as
history; they are not re-offered.

## PAL-SESSION-03 — protocol binding metadata

Every bundle carries binding metadata even when unknown. Fields: `git_head`,
`version`, `registry_sha256`, `tree_fingerprint`, `binding_status`,
`proof_level`, `confidence`, `source`.

`binding_status` is `BOUND`, `PARTIAL` or `UNKNOWN`. See `PAL-BINDING-01` in
`CORE.md` for the preference order.

`proof_level` is derived by Layer A, never granted by transcript prose or by a
bundle's declared `binding_status`:

1. `EXACT_COMMIT` — a full 40- or 64-hex Git object id resolved by the
   configured protocol authority;
2. `RELEASE_REGISTRY` — version plus a 64-hex SHA-256 registry digest;
3. `CAPTURED_FINGERPRINT` — a 64-hex SHA-256 protocol-tree fingerprint;
4. `INSTALLED_RELEASE` — version metadata only, therefore `PARTIAL`;
5. `UNKNOWN` — no defensible proof.

A syntactically plausible commit is not proof. Without an authority resolver,
or when resolution fails, it is rejected as exact-commit evidence and cannot
promote a binding. A valid weaker proof may still be selected independently.

No hindsight: a finding may claim a protocol violation against a session only
when the session's binding is known and the rule existed in the governing
version. A rule introduced later produces no historical violation; it may only
populate the separate retrospective field `current_protocol_protection`
(`PROTECTED`, `STILL_VULNERABLE` or `UNKNOWN`).

### Historical rule retrieval

The Layer A `read_historical_rules()` function resolves rule surface text from a
session's protocol binding, using operator-declared authority roots. Status is
`RESOLVED` (the rule text was retrieved from the exact commit, release or
snapshot specified by the binding) or `UNAVAILABLE` (the identity could not be
resolved, the authority was unconfigured, or the document was absent). The
resolution is a machine-checked digest pair, not a file path from the transcript.

Sources: `EXACT_COMMIT` (a full 40- or 64-hex Git object id resolved by the
configured Git authority), `RELEASE_REGISTRY` (version paired with a registry
digest), `CAPTURED_FINGERPRINT` (a protocol-tree SHA-256 fingerprint),
`UNKNOWN` (no identity or no authority). This is the same ordering as the
binding proof levels in `PAL-BINDING-01`; the retrieval layer is a read-only
fallback chain over the same roots.

The compact surface reaching a finding carries the status, source, identity,
registry digest and per-rule `document_sha256` digests — never the full rule
text. An operator re-fetches the text from the same authority using the
identity and document digest.

## PAL-SESSION-04 — generic, deterministic intake

`.saipal/session_inbox/` accepts canonical bundles only. An unreadable or
schema-invalid bundle is **reported and skipped**, never partially imported and
never repaired.

Import is deterministic: the same inbox in the same order produces the same
session index, byte for byte. Inbox files are scanned in name order so the
result does not depend on the filesystem.

Each import appends to the session's `imports` provenance list
(`source_ref`, `sha256`, `generation`, `imported_at`). Nothing is deleted from
the inbox — SAIPAL observes, it does not clean up after the operator.

## PAL-SESSION-05 — episode boundary hooks

Segmentation is **preparation only**. SAIPAL marks boundaries; it does not
compare, judge or emit anything about them.

Mechanical spans preserve provider markers, including every OpenCode
`step-start` and `step-finish`. Semantic episodes are a separate conservative
projection. Boundary kinds: `user_task`, `command`, `work_switch`,
`phase_change`, `source_intake`, `recovery`, `terminal_task`.

A new user request may open a semantic episode. Provider step markers,
individual tool calls, file writes and bookkeeping do not. Session termination
closes the trailing episode; it does not fabricate an empty next episode.

The mapping from event types to boundaries is mechanical and declared in the
runtime, not guessed per session. What happened inside an episode is decided by
the comparison kernel (detectors plus the analyst), never by the segmenter.

## PAL-SESSION-06 — HOT is provisional, COLD is final

An episode is `FINAL` or `PROVISIONAL`. Every episode of a COLD session is final:
the artifact is complete. In a HOT session only the trailing episode is
provisional — the earlier ones were closed by a later boundary and cannot grow.

Reasoning about a provisional episode is legitimate and often the most useful
work available, but it is reasoning about an unfinished sentence:

- the verdict and its finding are recorded, labelled `PROVISIONAL`, with the
  reason it is held;
- **no audit ever leaves the home**, whatever the confidence or severity;
- the semantic watermark does **not** advance past it, so the next cycle hands the
  analyst the grown version of the same episode;
- the receipt records the finality it was judged under, so a later reader can
  tell which conclusions rested on partial evidence.

A held finding is released by the same root cause being re-submitted against
final evidence: the finding is one root cause, not one episode, so it becomes
`FINAL` and the hold is dropped rather than a second finding being created.
