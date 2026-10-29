# Working with SAIPAL

The normal operating rhythms. Command behavior is owned by `saipal/COMMANDS.md`;
this page is the practical map. One principle runs through all of it: **project
state is not conversational context.** An agent's session memory lives with the
vendor and evaporates with the session; SAIPAL's state lives in `.saipal/` and
survives interruption by design. When a model or a terminal window disappears,
the next session resumes from explicit files, not from memory.

## Starting with a new project

```bash
python -B tools/saipal.py setup --source PATH --kind generic   # declare evidence
python -B tools/saipal.py continue                             # first cycle materializes .saipal/
python -B tools/saipal.py doctor                               # read-only health check
```

- `setup` validates every argument before writing; a failed setup leaves the
  previous configuration untouched.
- The first `continue` materializes the home, imports the source, and checkpoints.
- With no sources configured and the default tool-root home, `continue`
  auto-discovers known agent session stores. An explicit `--home`/`SAIPAL_HOME`
  deployment never auto-discovers — isolated homes reach only what you configured.
- Declaring a protocol authority (`saipal authority enroll --git-repository PATH`)
  is optional but recommended: it is what lets session bindings strengthen from
  `UNKNOWN`/`PARTIAL` to `BOUND`, which is what allows HIGH-confidence findings
  at all.

## Adding a requirement (intake)

A new request, bug report or idea enters as evidence, not as a conversation:

1. The requirement is captured as a canonical bundle (or lands through a
   configured source) and enters the inbox.
2. The next `continue` imports and indexes it; episodes are segmented.
3. Mechanical detectors run; anything suspicious becomes a triage-only signal
   that orders the analyst's queue — it is never itself an asserted finding.
4. An analyst (human or model) picks up `saipal --json next` units, judges each
   bounded slice, and `submit`s `DRIFT`, `NO_DRIFT` or `INSUFFICIENT_EVIDENCE`.
5. Confirmed drift merges into the finding lifecycle; the maintainer reads the
   resulting audit and decides what happens next.

Importantly, SAIPAL tracks work *about* your sessions; it deliberately does not
manage your project's own backlog — that stays in whatever issue tracker you use.

## Existing projects

Nothing special is required. Point a source at the session store or bundle
folder, run `continue` (or `continue --drain` for the whole backlog), and read
`report`. Re-runs are cheap and idempotent: COLD sessions are re-read only when
their raw bytes changed, HOT sessions are read for new tail events, and the
index deduplicates by content digest.

## Verifying and closing work

`saipal report` is the verification answer, and it is honest by construction:

- The verdict is a closed set: `NO_EVIDENCE`, `NOT_EXAMINED`, `NO_DRIFT_SO_FAR`,
  `DRIFT_SUSPECTED`, `DRIFT_REPORTED` — and coverage (episodes judged, pending)
  always travels beside it.
- A clean verdict never reads as clean while evidence is unexamined; that state
  has its own verdict (`NOT_EXAMINED`).
- Each finding names its rule ids, owner documents, causal key, recurrence
  spread, attribution (which models/projects drifted) and audit number.

"Done" therefore looks like: the coverage line says everything was judged, the
report's verdict stands, and any audits were dispositioned by the maintainer
(`saipal disposition FILE.json` imports results idempotently — a changed verdict
is appended as history, never overwritten, because a maintainer changing their
mind is itself calibration evidence).

## Interrupted work

Session interruption is the case SAIPAL is built for:

- A cycle that hits a budget checkpoints the exact continuation position and
  returns a resumable next action; the next `continue` picks up there.
- A crashed analyst submission is retried safely: the intention is journalled
  before any effect and retired by the receipt, and every effect is idempotent.
- A crashed cycle's lock is stale-taken-over safely; its pending trigger claim
  is honoured.
- The unattended form (`saipal watch`) runs bounded cycles with a durable
  checkpoint, single-owner supervision, and a graceful stop that leaves
  recoverable state. `saipal watch --status` is read-only and works while the
  supervisor runs.

## Unattended / continuation-oriented use

```bash
python -B tools/saipal.py trigger        # request one run; rapid triggers coalesce
python -B tools/saipal.py watch --max-cycles N
```

The semantic loop can run unattended too, once an analyst backend is configured
(`saipal analyst-setup --enable` points at an OpenAI-compatible endpoint;
`investigate --max-units N` runs one bounded batch). Without a backend it stops
truthfully with `CONFIG_DISABLED` rather than pretending to work.

`watch` enforces publication mode loudly: a shadow run refuses to flip to
`PUBLISH_ENABLED` mid-flight, and a mode change between cycles stops it with
`PUBLICATION_MODE_BLOCKED` rather than continuing under changed rules. Budgets
(model attempts, semantic units per window) survive restart, so unattended runs
cannot quietly spend more than configured.
