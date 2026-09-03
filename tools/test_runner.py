#!/usr/bin/env python
"""The SAIPAL canonical suite.

Every family runs against a disposable copy of the checkout, so "clean checkout
reproduces green" is actually exercised rather than assumed.

    python -B tools/test_runner.py                 # everything
    python -B tools/test_runner.py --family unit   # just the unit tests
    python -B tools/test_runner.py --no-sandbox    # run in place
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

IGNORE = shutil.ignore_patterns(
    ".git",
    ".saipal",
    ".freebuff",
    ".workbuddy-ai",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "*.pyc",
)


@dataclass
class TestFamily:
    name: str
    command: tuple[str, ...]
    timeout: int = 600


@dataclass
class FamilyResult:
    name: str
    exit_code: int
    seconds: float
    tail: str = ""
    skipped: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.skipped or self.exit_code == 0


def families() -> tuple[TestFamily, ...]:
    python = sys.executable
    return (
        TestFamily(
            "unit",
            (
                python,
                "-B",
                "-m",
                "unittest",
                "discover",
                "-s",
                "tools",
                "-p",
                "test_*.py",
                "-v",
            ),
            900,
        ),
        TestFamily("validator", (python, "-B", "tools/validate.py"), 300),
    )


def run_family(family: TestFamily, cwd: Path) -> FamilyResult:
    started = time.time()
    try:
        completed = subprocess.run(
            list(family.command),
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=family.timeout,
        )
    except subprocess.TimeoutExpired:
        return FamilyResult(
            family.name,
            1,
            time.time() - started,
            tail=f"TIMEOUT after {family.timeout}s",
        )
    except OSError as exc:
        return FamilyResult(family.name, 1, time.time() - started, tail=f"cannot run: {exc}")

    stream = completed.stdout or ""
    tail = "\n".join(stream.strip().splitlines()[-25:])
    if completed.returncode != 0 and completed.stderr:
        tail += "\n" + "\n".join(completed.stderr.strip().splitlines()[-10:])
    return FamilyResult(family.name, completed.returncode, time.time() - started, tail)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the SAIPAL canonical suite.")
    parser.add_argument("--family", action="append", help="run only this family")
    parser.add_argument("--root", default=str(ROOT), help="checkout to test")
    parser.add_argument("--no-sandbox", action="store_true", help="run in place")
    parser.add_argument("--json", action="store_true", help="machine-readable summary")
    args = parser.parse_args(argv)

    selected = families()
    if args.family:
        wanted = set(args.family)
        unknown = wanted - {f.name for f in selected}
        if unknown:
            print(f"unknown family: {sorted(unknown)}", file=sys.stderr)
            return 2
        selected = tuple(f for f in selected if f.name in wanted)

    source = Path(args.root).resolve()
    workdir = source
    sandbox: str | None = None

    if not args.no_sandbox:
        sandbox = tempfile.mkdtemp(prefix="saipal-sandbox-")
        workdir = Path(sandbox) / source.name
        shutil.copytree(str(source), str(workdir), ignore=IGNORE)

    results: list[FamilyResult] = []
    try:
        for family in selected:
            if not args.json:
                print(f"[{family.name}] running in {workdir}")
            result = run_family(family, workdir)
            results.append(result)
            if not args.json:
                status = "PASS" if result.ok else "FAIL"
                print(f"[{family.name}] {status} in {result.seconds:.1f}s")
                if not result.ok:
                    print(result.tail)
    finally:
        if sandbox:
            shutil.rmtree(sandbox, ignore_errors=True)

    failed = [r for r in results if not r.ok]

    if args.json:
        print(
            json.dumps(
                {
                    "ok": not failed,
                    "families": [
                        {
                            "name": r.name,
                            "exit_code": r.exit_code,
                            "seconds": round(r.seconds, 2),
                            "ok": r.ok,
                        }
                        for r in results
                    ],
                },
                indent=2,
            )
        )
        return 0 if not failed else 1

    print()
    if not failed:
        print(f"SAIPAL suite is green: {len(results)} families passed.")
        return 0
    print(f"SAIPAL suite is RED: {len(failed)} of {len(results)} families failed.")
    for result in failed:
        print(f"  - {result.name} (exit {result.exit_code})")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
