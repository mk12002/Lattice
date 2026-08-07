"""Scan, write all three report formats, and gate on P0 — the CI pattern in Python.

This mirrors `lattice scan <path> --format all --fail-on P0` but shows how to do
it programmatically (e.g. inside a larger build tool).

Run:  python examples/scan_and_gate.py [PATH] [OUT_DIR]
Exit: 0 if no P0 findings, 1 if any P0 finding is present.
"""

from __future__ import annotations

import sys
from pathlib import Path

from lattice.core.engine import scan
from lattice.core.models import Priority
from lattice.detectors.registry import all_detectors
from lattice.emitters import cbom_emitter, html_emitter, sarif_emitter


def main() -> int:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tests/fixtures")
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("lattice-report")

    cbom = scan(target, all_detectors())

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "cbom.json").write_text(cbom_emitter.emit(cbom), encoding="utf-8")
    (out_dir / "report.html").write_text(html_emitter.emit(cbom), encoding="utf-8")
    (out_dir / "findings.sarif").write_text(sarif_emitter.emit(cbom), encoding="utf-8")

    # gate: fail if any non-accepted finding is P0 (broken-today or HNDL key exchange)
    p0 = [
        f
        for f in cbom.findings
        if f.accepted_reason is None and f.assessment.priority == Priority.P0
    ]
    print(f"wrote reports to {out_dir}/  -  {len(p0)} P0 finding(s)")
    return 1 if p0 else 0


if __name__ == "__main__":
    sys.exit(main())
