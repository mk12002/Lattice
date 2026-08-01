"""CBOM drift detection: compare two Lattice CBOM JSON documents.

``lattice diff baseline.json current.json`` answers the question CI
actually asks: *did this change make our cryptography worse?* Because
Lattice output is deterministic, two CBOMs diff meaningfully.

Findings are keyed by (algorithm, file path, priority) — line numbers are
deliberately excluded so pure code motion doesn't read as churn — and
compared as multisets. "New" means the current scan has more occurrences
of a key than the baseline; "resolved" means fewer.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from lattice.core.models import Priority

#: (algorithm, file path, priority) -> identity of a finding for drift purposes
_Key = tuple[str, str, str]


class CbomLoadError(Exception):
    """Raised when a file is not a readable Lattice/CycloneDX CBOM."""


@dataclass
class DiffResult:
    """Outcome of comparing two CBOMs."""

    new: list[tuple[_Key, int]] = field(default_factory=list)
    resolved: list[tuple[_Key, int]] = field(default_factory=list)
    baseline_score: int | None = None
    current_score: int | None = None

    def new_at_or_above(self, threshold: Priority) -> int:
        """Count of new findings at or above a priority threshold."""
        return sum(
            count
            for (_, _, priority), count in self.new
            if priority != Priority.NONE.value
            and Priority(priority).rank <= threshold.rank
        )


def _as_list(value: object) -> list:
    """Return ``value`` if it is a list, else an empty list.

    ``diff`` reads two JSON files that may be malformed or hostile. A crafted
    document could set ``components`` to a string or ``properties`` to a
    number; treating a non-list as empty keeps the parser total instead of
    letting an AttributeError or an accidental character-iteration escape.
    """
    return value if isinstance(value, list) else []


def _prop_map(component: object) -> dict[str, object]:
    """Property name -> value for a component, tolerating malformed entries."""
    result: dict[str, object] = {}
    for prop in _as_list(component.get("properties") if isinstance(component, dict) else None):
        if isinstance(prop, dict):
            result[str(prop.get("name"))] = prop.get("value")
    return result


def _first_location(component: dict) -> str:
    evidence = component.get("evidence")
    occurrences = _as_list(evidence.get("occurrences") if isinstance(evidence, dict) else None)
    for occurrence in occurrences:
        if isinstance(occurrence, dict) and "location" in occurrence:
            return str(occurrence.get("location", "?"))
    return "?"


def _load(path: Path) -> tuple[Counter[_Key], int | None]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CbomLoadError(f"{path}: not a readable CBOM JSON ({exc})") from exc
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise CbomLoadError(f"{path}: missing CycloneDX bomFormat marker")
    keys: Counter[_Key] = Counter()
    for component in _as_list(doc.get("components")):
        if not isinstance(component, dict):
            continue
        properties = _prop_map(component)
        priority = str(properties.get("lattice:priority", Priority.NONE.value))
        location = _first_location(component)
        keys[(str(component.get("name", "?")), location, priority)] += 1
    score: int | None = None
    for prop in _as_list(doc.get("properties")):
        if isinstance(prop, dict) and prop.get("name") == "lattice:readinessScore":
            try:
                score = int(prop.get("value"))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                score = None
    return keys, score


def diff(baseline_path: Path, current_path: Path) -> DiffResult:
    """Compare two CBOM files; deterministic ordering in the result."""
    baseline, baseline_score = _load(baseline_path)
    current, current_score = _load(current_path)
    result = DiffResult(baseline_score=baseline_score, current_score=current_score)
    for key in sorted(set(baseline) | set(current), key=_sort_key):
        delta = current[key] - baseline[key]
        if delta > 0:
            result.new.append((key, delta))
        elif delta < 0:
            result.resolved.append((key, -delta))
    return result


def _sort_key(key: _Key) -> tuple[int, str, str]:
    algorithm, location, priority = key
    try:
        rank = Priority(priority).rank
    except ValueError:
        rank = Priority.NONE.rank
    return (rank, location, algorithm)


def render_text(result: DiffResult) -> str:
    """Human-readable drift summary (deterministic)."""
    lines: list[str] = []
    if result.baseline_score is not None and result.current_score is not None:
        arrow = "->"
        lines.append(
            f"readiness score: {result.baseline_score} {arrow} {result.current_score}"
        )
    if not result.new and not result.resolved:
        lines.append("no cryptographic drift: the two CBOMs match")
        return "\n".join(lines) + "\n"
    if result.new:
        lines.append(f"new findings ({sum(c for _, c in result.new)}):")
        for (algorithm, location, priority), count in result.new:
            suffix = f" x{count}" if count > 1 else ""
            lines.append(f"  + [{priority}] {algorithm} in {location}{suffix}")
    if result.resolved:
        lines.append(f"resolved findings ({sum(c for _, c in result.resolved)}):")
        for (algorithm, location, priority), count in result.resolved:
            suffix = f" x{count}" if count > 1 else ""
            lines.append(f"  - [{priority}] {algorithm} in {location}{suffix}")
    return "\n".join(lines) + "\n"


def render_json(result: DiffResult) -> str:
    """Machine-readable drift summary (deterministic).

    Lets CI systems and dashboards consume drift the way they consume the
    CBOM/SARIF. Ordering matches ``render_text`` (already deterministic).
    """

    def entries(items: list[tuple[_Key, int]]) -> list[dict]:
        return [
            {
                "algorithm": algorithm,
                "location": location,
                "priority": priority,
                "count": count,
            }
            for (algorithm, location, priority), count in items
        ]

    document = {
        "baselineReadinessScore": result.baseline_score,
        "currentReadinessScore": result.current_score,
        "new": entries(result.new),
        "resolved": entries(result.resolved),
        "summary": {
            "new": sum(c for _, c in result.new),
            "resolved": sum(c for _, c in result.resolved),
        },
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
