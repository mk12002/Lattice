#!/usr/bin/env python3
"""Reproducible benchmark harness for Lattice.

Scans one or more targets and prints a Markdown table of findings, priority
counts, readiness score, and wall-clock time — the same measurements recorded
in docs/ACCURACY_NOTES.md. Uses only the standard library plus Lattice itself
(no third-party deps), so it runs anywhere Lattice runs.

Usage:
    python benchmarks/run.py                       # scan the bundled fixtures
    python benchmarks/run.py PATH [PATH ...]       # scan arbitrary trees
    python benchmarks/run.py --clone age paramiko  # clone & scan public repos

The --clone shortcuts map to the repositories audited in ACCURACY_NOTES.md.
Cloning requires `git` and network access; without --clone the harness is
fully offline and deterministic.
"""

from __future__ import annotations

import argparse
import shutil

# subprocess is used only for `git clone` of explicit, hardcoded URLs (--clone).
import subprocess  # nosec B404
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

from lattice.core.engine import scan
from lattice.core.models import Priority
from lattice.core.severity import readiness_score
from lattice.detectors.registry import all_detectors

#: --clone shortcuts -> (git URL, subdirectory to scan or "" for the whole repo)
_KNOWN_REPOS = {
    "age": ("https://github.com/FiloSottile/age", ""),
    "paramiko": ("https://github.com/paramiko/paramiko", ""),
    "node-jsonwebtoken": ("https://github.com/auth0/node-jsonwebtoken", ""),
}

_PRIORITY_ORDER = (Priority.P0, Priority.P1, Priority.P2, Priority.P3, Priority.NONE)


def _bench_one(label: str, target: Path) -> dict:
    detectors = all_detectors()
    start = time.perf_counter()
    cbom = scan(target, detectors)
    elapsed = time.perf_counter() - start
    counts = Counter(f.assessment.priority for f in cbom.findings)
    return {
        "label": label,
        "files": cbom.stats.files_scanned,
        "findings": len(cbom.findings),
        "score": readiness_score(cbom.findings),
        "seconds": elapsed,
        "counts": counts,
    }


def _clone(name: str, into: Path) -> Path:
    url, subdir = _KNOWN_REPOS[name]
    dest = into / name
    # Fixed argument list; url comes only from the hardcoded _KNOWN_REPOS map.
    # `git` is resolved from PATH by design (a dev/benchmark convenience tool).
    cmd = ["git", "clone", "--depth", "1", "--quiet", url, str(dest)]
    subprocess.run(cmd, check=True)  # nosec B603 B607
    return dest / subdir if subdir else dest


def _print_table(rows: list[dict]) -> None:
    header = (
        "| Target | Files | Findings | "
        + " | ".join(p.value for p in _PRIORITY_ORDER)
        + " | Readiness | Time (s) |"
    )
    sep = "|" + "---|" * (len(_PRIORITY_ORDER) + 5)
    print(header)
    print(sep)
    for r in rows:
        cells = " | ".join(str(r["counts"].get(p, 0)) for p in _PRIORITY_ORDER)
        print(
            f"| {r['label']} | {r['files']} | {r['findings']} | {cells} "
            f"| {r['score']}/100 | {r['seconds']:.2f} |"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lattice benchmark harness")
    parser.add_argument("paths", nargs="*", help="paths to scan (default: bundled fixtures)")
    parser.add_argument(
        "--clone",
        nargs="+",
        choices=sorted(_KNOWN_REPOS),
        metavar="REPO",
        help="clone and scan known public repos: " + ", ".join(sorted(_KNOWN_REPOS)),
    )
    args = parser.parse_args(argv)

    rows: list[dict] = []
    tmp: Path | None = None
    try:
        if args.clone:
            if shutil.which("git") is None:
                print("error: --clone requires git on PATH", file=sys.stderr)
                return 2
            tmp = Path(tempfile.mkdtemp(prefix="lattice-bench-"))
            for name in args.clone:
                rows.append(_bench_one(name, _clone(name, tmp)))
        for raw in args.paths:
            path = Path(raw)
            if not path.exists():
                print(f"error: path not found: {path}", file=sys.stderr)
                return 2
            rows.append(_bench_one(path.name or str(path), path))
        if not rows:
            fixtures = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
            rows.append(_bench_one("tests/fixtures", fixtures))
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)

    _print_table(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
