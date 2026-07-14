"""Scan orchestration: walk files -> route to detectors -> assess -> assemble CBOM.

The engine never imports a concrete detector or emitter (dependency rule);
callers hand it the detector list. One malformed file must never kill a
scan: detector exceptions are recorded as skipped-file warnings and the
scan continues.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from lattice import __version__
from lattice.core.models import CBOM, CryptoAsset, Family, Finding
from lattice.core.severity import assess, unknown_assessment
from lattice.core.walker import DEFAULT_MAX_FILE_BYTES, Walker
from lattice.detectors.base import Detector

#: families that are inventoried rather than algorithm-graded
_INVENTORY_FAMILIES = frozenset({Family.LIBRARY})


def make_finding(asset: CryptoAsset) -> Finding:
    """Assess one asset against the knowledge base (or inventory it honestly)."""
    from lattice.rules.algorithms import lookup

    if asset.usage_family in _INVENTORY_FAMILIES:
        reason = asset.note or "crypto component present; usage not confirmed by a call site"
        return Finding(asset, unknown_assessment(asset, reason))
    info = lookup(asset.algorithm)
    if info is None:
        reason = asset.note or f"'{asset.algorithm}' is not in the knowledge base; inventoried without judgment"
        return Finding(asset, unknown_assessment(asset, reason))
    return Finding(asset, assess(asset, info))


def scan(
    target: Path,
    detectors: list[Detector],
    exclude: tuple[str, ...] = (),
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> CBOM:
    """Scan ``target`` with ``detectors`` and return the assembled CBOM."""
    target = target.resolve()
    walker = Walker(target, exclude=exclude, max_bytes=max_bytes)
    findings: list[Finding] = []
    root = target if target.is_dir() else target.parent

    for path, content in walker.walk():
        rel = PurePosixPath(path.relative_to(root).as_posix())
        walker.stats.files_scanned += 1
        for detector in detectors:
            if not detector.applies_to(rel):
                continue
            if content is None and not getattr(detector, "accepts_binary", False):
                continue
            try:
                assets = list(detector.detect(rel, content or ""))
            except Exception as exc:  # noqa: BLE001 - a bad file must not kill the scan
                walker.stats.files_skipped += 1
                walker.stats.skipped_reasons.append(
                    f"{rel}: {detector.name} detector error ({exc.__class__.__name__})"
                )
                continue
            findings.extend(make_finding(asset) for asset in assets)

    cbom = CBOM(
        tool_version=__version__,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        target=str(target),
        findings=sorted(findings, key=Finding.sort_key),
        stats=walker.stats,
    )
    return cbom
