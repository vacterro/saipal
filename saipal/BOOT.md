<!-- OWNER: saipal/BOOT.md -->
<!-- RULES: PAL-BOOT-01, PAL-BOOT-02 -->
# BOOT — how SAIPAL starts

BOOT stays tiny. It answers six questions and nothing else.

## 1. Where is the SAIPAL home?

The runtime home is a directory named `.saipal/`.

Resolution order (`PAL-BOOT-01`):

1. `--home <path>` if given;
2. `SAIPAL_HOME` environment variable;
3. nearest ancestor of the current directory containing `.saipal/`;
4. `<tool root>/.saipal/` — the SAIPAL repository itself.

SAIPAL never creates a second home inside an analyzed project, and never
creates one inside a SAIPEN project.

## 2. How do I read STATE?

`.saipal/STATE.json` is the only carrier state file.

It is machine-owned JSON. It is read as data. It is never inferred from prose.

If `STATE.json` is absent, unreadable, or fails the closed-field check, see §3.

## 3. How do I recover?

Recovery is refusal, not repair (`PAL-BOOT-02`).

| Condition | Behavior |
| --- | --- |
| home absent | `continue` materializes the home; `status`/`next` refuse with `NO_HOME` |
| `STATE.json` absent | `continue` starts a fresh carrier; read-only commands refuse with `NO_HOME` |
| `STATE.json` malformed | refuse with `STATE_UNRECOVERABLE`; never overwrite, never guess |
| lock held by a live run | refuse with `WRITER_BUSY` |
| lock stale (dead owner or past TTL) | take over, log the takeover |

A malformed `STATE.json` is preserved on disk. SAIPAL does not delete it and
does not reconstruct it from `LOG.jsonl`.

## 4. How do I choose the next analysis carrier?

`continue` walks one ordered list and stops at the first item that yields work:

1. recover own state;
2. resume the current unfinished session or episode;
3. discover session sources and index new evidence;
4. advance unfinished finding candidates;
5. emit qualified audits;
6. checkpoint and return idle.

No work found at any step means **clean idle**, not invented work.

## 5. Which owner document do I load?

Exactly one owner document per rule family. The `rule_owners` map in
`saipal/REGISTRY.json` is the sole authority. Load the owner of the rule you
are enforcing; do not load the whole protocol.

| Concern | Owner |
| --- | --- |
| starting, home, recovery | `BOOT.md` |
| global invariants | `CORE.md` |
| command surface and semantics | `COMMANDS.md` |
| session evidence contracts | `SESSIONS.md` |
| finding contracts | `FINDINGS.md` |
| audit contracts | `AUDITS.md` |

## 6. How do I checkpoint?

Append to `.saipal/LOG.jsonl` first, then atomically replace
`.saipal/STATE.json`. Both writes go through the home write boundary in
`CORE.md`. A crash between the two is recoverable because `LOG.jsonl` is
append-only and `STATE.json` is replaced atomically.
