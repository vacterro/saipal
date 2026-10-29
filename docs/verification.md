# Verification status

One canonical statement of what has and has not been verified, kept in sync with
the single-source-of-truth block in [`WAVE_I_CHECKPOINT.md`](../WAVE_I_CHECKPOINT.md)
(whose `checkpoint_id` stamps the counts). Re-derive after any material change:

```bash
python -B -m unittest discover -s tools -p "test_*.py"   # canonical suite
python -B tools/validate.py                              # protocol/registry drift gate
python -B -m compileall tools                            # bytecode compile check
```

`python -B tools/verify_operator_corpus.py --root ROOT` retains the original
maintainer corpus assertions separately from the private-free fixture suite.
It requires an explicitly supplied existing `.saipal` corpus and `.saipen`
carriers; it never chooses a live corpus by default. Its result applies only
to that supplied corpus. Passing the public fixture suite does not attest that
an operator's current corpus is drained or otherwise satisfies those assertions.

Counts quoted anywhere else in the repository carry the checkpoint id they came
from, or they are not facts — the validator enforces that.

## Historical Windows measurement

The following result belongs to the named historical checkpoint, not to
a newly published source revision. Executed on that release tree (checkpoint `T-130-VERIFY-2026-09-18-R5`):

| Check | Result |
| --- | --- |
| `python -B -m unittest discover -s tools -p "test_*.py"` | **1,680 tests, OK (11 platform-skipped)** |
| `python -B tools/validate.py` | **316/316 checks pass** |
| `python -B -m compileall tools` | **clean** |

The 11 skips are platform-conditional controls (POSIX-only primitives, symlink
availability, an external-clone control) — they skip *here* by design and run
where their platform applies. The suite includes red controls for the founding
defect classes: write-boundary escapes, descriptor lifetime, lock ownership and
refresh races, crash-and-retry idempotence, hostile transcript injection, and
drain/budget termination.

## POSIX / Linux

Truthful current posture, stated in both directions:

- **Executed (focused + full run):** the canonical suite was run to completion
  on a genuine POSIX interpreter available on the development host (Cygwin
  Python 3.12, `os.name=posix`) — 1,680 tests with **zero descriptor
  exhaustion** (`Too many open files` never appeared; the founding T-127 fd-leak
  defect is measurably repaired), `validate.py` green (314 checks as measured
  there), `compileall` clean.
  The focused descriptor-lifetime control (`PosixDescriptorLifetime`, including
  the thousand-confined-operations bound) passed 6/6, and the unattended,
  lock-ownership and audit corridors passed their focused runs. A handful of
  initial errors were environmental (missing `git` on that PATH) and went green
  natively.
- **Not certified:** one real failure occurred — the atomic-write parent-swap
  race control — and its root cause is the *host*, not a proven Linux defect:
  Cygwin's `openat` re-resolves the path instead of pinning the inode, so that
  specific refusal cannot fire there (real Linux `openat` pins the inode and the
  control refuses via `ENOENT`). Full certification therefore awaits execution
  on a **real Linux host** and is recorded as **deferred verification debt**
  (ticket T-127, blocked external until such a host is available).

Consequently: POSIX is **not** claimed fully verified, and POSIX is **not**
known to be broken — the descriptor-lifetime defect that motivated the focused
controls is repaired and evidenced; the remaining question is certification on
faithful Linux semantics. The two platforms do not share one mechanism, and
neither result may be inferred from the other.

## What is deliberately not claimed

- No claim of correctness for the findings SAIPAL produces — the tool reports
  evidence; the maintainer decides.
- No claim that the residual Windows write-boundary window (non-reparse
  delete+recreate between probe and I/O) is closed — it is documented, and
  closing it requires handle-based APIs the Python stdlib does not expose.
- No claim that Cygwin results transfer to Linux, or Windows results to POSIX.
- `.github/workflows/posix-verification.yml` defines the required Linux
  suites. Its presence is not evidence that a hosted run passed; inspect the
  run bound to the published commit before claiming Linux certification.

## Historical evidence

Prior checkpoints (R3, R4 and earlier) are preserved in
[`WAVE_I_CHECKPOINT.md`](../WAVE_I_CHECKPOINT.md) with their own checkpoint ids
and are append-only: newer checkpoints supersede their *counts*, never rewrite
their history. External audit notes live in [`docs/audits/`](audits/).
