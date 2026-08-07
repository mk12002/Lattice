"""Use Lattice as a library: scan a path and inspect findings — no CLI, no files.

Run:  python examples/python_api.py [PATH]   (defaults to the test fixtures)
"""

from __future__ import annotations

import sys
from pathlib import Path

from lattice.core.engine import scan
from lattice.core.severity import readiness_score
from lattice.detectors.registry import all_detectors


def main() -> None:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tests/fixtures")

    # scan() returns a pure CBOM value — no I/O, no exit code. That is the whole
    # public API you need to build your own tooling on top of Lattice.
    cbom = scan(target, all_detectors())

    print(f"scanned {cbom.stats.files_scanned} files: {len(cbom.findings)} findings")
    print(f"readiness score: {readiness_score(cbom.findings)}/100\n")

    # findings are already in deterministic (priority, path, line) order
    for finding in cbom.sorted_findings():
        a, s = finding.asset, finding.assessment
        print(f"[{s.priority.value:4}] {a.algorithm:10} {a.file_path}:{a.line_number}")
        print(f"        {s.justification}")
        if s.pqc_replacement:
            print(f"        migrate to: {s.pqc_replacement}")


if __name__ == "__main__":
    main()
