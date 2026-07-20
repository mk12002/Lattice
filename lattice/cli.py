"""Lattice command-line interface.

Contract:
    lattice scan <path> [--format cbom|html|sarif|all] [--out DIR]
                        [--fail-on P0|P1|P2|P3] [--exclude GLOB]...
                        [--languages py,java,js,go,c,rust,csharp]
                        [--policy cnsa2] [--quiet]
    lattice diff <baseline.json> <current.json> [--fail-on-new P0|P1|P2|P3]
    lattice rules list
    lattice version

Exit codes: 0 = success; 1 = --fail-on / --policy / --fail-on-new gate met;
2 = usage error. A malformed input file never crashes a scan — it is
skipped with a warning that appears in the scan summary. Findings accepted
in lattice.toml never trip a gate.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from lattice import __version__

_FORMATS = ("cbom", "html", "sarif", "all")
_OUTPUT_FILES = {"cbom": "cbom.json", "html": "report.html", "sarif": "findings.sarif"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lattice",
        description="Crypto-agility and post-quantum-readiness scanner.",
    )
    sub = parser.add_subparsers(dest="command")

    scan_parser = sub.add_parser("scan", help="scan a path and emit reports")
    scan_parser.add_argument("path", nargs="?", default=".", help="file or directory to scan")
    scan_parser.add_argument(
        "--format",
        default="html",
        choices=_FORMATS,
        help="output format (default: html)",
    )
    scan_parser.add_argument(
        "--out", default="lattice-report", metavar="DIR", help="output directory"
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["P0", "P1", "P2", "P3"],
        metavar="{P0,P1,P2,P3}",
        help="exit non-zero if findings at or above this priority exist",
    )
    scan_parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="glob pattern to exclude (repeatable)",
    )
    scan_parser.add_argument(
        "--languages",
        metavar="LIST",
        help="comma-separated detector selection: py,java,js,go,c,rust,csharp (default: all)",
    )
    scan_parser.add_argument(
        "--policy",
        choices=["cnsa2"],
        help="also evaluate findings against a compliance profile; violations exit 1",
    )
    scan_parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=1_000_000,
        metavar="N",
        help="per-file size cap in bytes (default: 1000000)",
    )
    scan_parser.add_argument("--quiet", action="store_true", help="suppress progress output")

    diff_parser = sub.add_parser(
        "diff", help="compare two CBOM JSON files and report cryptographic drift"
    )
    diff_parser.add_argument("baseline", help="baseline CBOM JSON (e.g. from main)")
    diff_parser.add_argument("current", help="current CBOM JSON (e.g. from this branch)")
    diff_parser.add_argument(
        "--fail-on-new",
        choices=["P0", "P1", "P2", "P3"],
        metavar="{P0,P1,P2,P3}",
        help="exit non-zero if new findings at or above this priority appeared",
    )

    rules_parser = sub.add_parser("rules", help="knowledge-base commands")
    rules_sub = rules_parser.add_subparsers(dest="rules_command")
    rules_sub.add_parser("list", help="print the algorithm knowledge base as a table")

    sub.add_parser("version", help="print the Lattice version")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``lattice`` console script."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"lattice {__version__}")
        return 0
    if args.command == "rules":
        if args.rules_command == "list":
            _print_rules()
            return 0
        parser.parse_args(["rules", "--help"])
        return 2
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "diff":
        return _run_diff(args)
    parser.print_help()
    return 0


def _run_diff(args: argparse.Namespace) -> int:
    from pathlib import Path as _Path

    from lattice.core.diff import CbomLoadError, diff, render_text
    from lattice.core.models import Priority

    try:
        result = diff(_Path(args.baseline), _Path(args.current))
    except CbomLoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(render_text(result), end="")
    if args.fail_on_new:
        regressions = result.new_at_or_above(Priority(args.fail_on_new))
        if regressions:
            print(
                f"drift gate: {regressions} new finding(s) at or above {args.fail_on_new}",
                file=sys.stderr,
            )
            return 1
    return 0


def _run_scan(args: argparse.Namespace) -> int:
    from lattice.core.engine import scan
    from lattice.core.models import Priority
    from lattice.detectors.registry import detectors_for
    from lattice.emitters import cbom_emitter, html_emitter, sarif_emitter

    target = Path(args.path)
    if not target.exists():
        print(f"error: path not found: {target}", file=sys.stderr)
        return 2
    if args.max_file_bytes <= 0:
        print("error: --max-file-bytes must be a positive integer", file=sys.stderr)
        return 2

    languages = None
    if args.languages:
        languages = [token.strip() for token in args.languages.split(",") if token.strip()]
    try:
        detectors = detectors_for(languages)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    cbom = scan(
        target,
        detectors,
        exclude=tuple(args.exclude),
        max_bytes=args.max_file_bytes,
    )

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    emitters = {
        "cbom": cbom_emitter.emit,
        "html": html_emitter.emit,
        "sarif": sarif_emitter.emit,
    }
    selected = list(emitters) if args.format == "all" else [args.format]
    for fmt in selected:
        out_file = out_dir / _OUTPUT_FILES[fmt]
        out_file.write_text(emitters[fmt](cbom), encoding="utf-8", newline="\n")
        if not args.quiet:
            print(f"wrote {out_file}")

    if not args.quiet:
        _print_summary(cbom)
    for warning in cbom.stats.warnings:
        print(f"warning: {warning}", file=sys.stderr)

    exit_code = 0
    if args.policy:
        from lattice.core.policy import POLICIES

        policy = POLICIES[args.policy]
        violations = policy.evaluate(cbom.sorted_findings())
        if violations:
            print(
                f"policy {policy.name}: {len(violations)} algorithm(s) outside the "
                "allowed set",
                file=sys.stderr,
            )
            for violation in violations:
                print(f"  - {violation.message}", file=sys.stderr)
            print(f"  note: {policy.caveat}", file=sys.stderr)
            exit_code = 1
        elif not args.quiet:
            print(f"policy {policy.name}: no detected algorithm outside the allowed set")
            print(f"  note: {policy.caveat}")

    if args.fail_on:
        threshold = Priority(args.fail_on).rank
        gated = sum(
            1
            for f in cbom.findings
            if f.accepted_reason is None and f.assessment.priority.rank <= threshold
        )
        if gated:
            print(
                f"fail-on gate: {gated} finding(s) at or above {args.fail_on}",
                file=sys.stderr,
            )
            exit_code = 1
    return exit_code


def _print_summary(cbom) -> None:
    from lattice.core.models import Priority
    from lattice.core.severity import readiness_score

    counts = cbom.priority_counts()
    summary = "  ".join(
        f"{p.value}={counts[p]}"
        for p in (Priority.P0, Priority.P1, Priority.P2, Priority.P3, Priority.NONE)
    )
    print(
        f"scanned {cbom.stats.files_scanned} files "
        f"({cbom.stats.files_skipped} skipped): {len(cbom.findings)} findings"
    )
    print(f"priorities: {summary}")
    print(f"readiness score: {readiness_score(cbom.findings)}/100")
    if cbom.stats.skipped_reasons:
        shown = cbom.stats.skipped_reasons[:10]
        print(f"skipped files ({len(cbom.stats.skipped_reasons)} total):", file=sys.stderr)
        for reason in shown:
            print(f"  - {reason}", file=sys.stderr)
        if len(cbom.stats.skipped_reasons) > len(shown):
            print("  - ...", file=sys.stderr)


def _print_rules() -> None:
    from lattice.rules.algorithms import ALGORITHMS

    headers = ("Algorithm", "Family", "Quantum", "Classical", "PQC replacement")
    rows = [
        (
            name,
            info.family.value,
            info.quantum_status.value,
            info.classical_status.value,
            info.pqc_replacement or "-",
        )
        for name, info in sorted(ALGORITHMS.items())
    ]
    widths = [
        max(len(headers[i]), *(len(row[i]) for row in rows)) for i in range(len(headers))
    ]
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))


if __name__ == "__main__":
    sys.exit(main())
