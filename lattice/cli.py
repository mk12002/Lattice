"""Lattice command-line interface (Phase 2 minimal: scan --format cbom; full CLI in Phase 5)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from lattice import __version__


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``lattice`` console script."""
    parser = argparse.ArgumentParser(prog="lattice", description="Crypto-agility scanner")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("version", help="print the Lattice version")
    scan_parser = sub.add_parser("scan", help="scan a path and emit a CBOM")
    scan_parser.add_argument("path", nargs="?", default=".")
    scan_parser.add_argument("--format", default="cbom", choices=["cbom"])
    scan_parser.add_argument("--out", default="lattice-report")
    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"lattice {__version__}")
        return 0
    if args.command == "scan":
        return _run_scan(args)
    parser.print_help()
    return 0


def _run_scan(args: argparse.Namespace) -> int:
    from lattice.core.engine import scan
    from lattice.detectors.python_det import PythonDetector
    from lattice.emitters import cbom_emitter

    target = Path(args.path)
    if not target.exists():
        print(f"error: path not found: {target}", file=sys.stderr)
        return 2
    cbom = scan(target, [PythonDetector()])
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "cbom.json"
    out_file.write_text(cbom_emitter.emit(cbom), encoding="utf-8", newline="\n")
    print(f"wrote {out_file} ({len(cbom.findings)} findings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
