"""Model tests: deterministic ordering is a hard product requirement."""

from __future__ import annotations

import random

from lattice.core.models import (
    CBOM,
    Assessment,
    ClassicalStatus,
    Confidence,
    CryptoAsset,
    Finding,
    Priority,
    QuantumStatus,
)


def _finding(priority: Priority, path: str, line: int, algorithm: str = "RSA") -> Finding:
    asset = CryptoAsset(
        algorithm=algorithm,
        file_path=path,
        line_number=line,
        detector="test",
        confidence=Confidence.HIGH,
    )
    assessment = Assessment(
        quantum_status=QuantumStatus.BROKEN,
        classical_status=ClassicalStatus.SECURE,
        hndl_relevant=True,
        priority=priority,
        pqc_replacement=None,
        justification="test",
    )
    return Finding(asset, assessment)


def test_sort_is_deterministic_under_shuffle():
    findings = [
        _finding(Priority.P2, "b.py", 10),
        _finding(Priority.P0, "a.py", 5),
        _finding(Priority.P0, "a.py", 1),
        _finding(Priority.NONE, "z.py", 1),
        _finding(Priority.P1, "a.py", 1),
        _finding(Priority.P0, "b.py", 1),
        _finding(Priority.P0, "a.py", 1, algorithm="MD5"),
    ]
    expected = sorted(findings, key=Finding.sort_key)
    rng = random.Random(1234)
    for _ in range(25):
        shuffled = findings[:]
        rng.shuffle(shuffled)
        assert sorted(shuffled, key=Finding.sort_key) == expected


def test_priority_rank_ordering():
    ranks = [Priority.P0.rank, Priority.P1.rank, Priority.P2.rank, Priority.P3.rank,
             Priority.NONE.rank]
    assert ranks == sorted(ranks)
    assert Priority.P0.rank == 0


def test_cbom_priority_counts_zero_filled():
    cbom = CBOM(tool_version="0", generated_at="t", target=".")
    counts = cbom.priority_counts()
    assert set(counts) == set(Priority)
    assert all(v == 0 for v in counts.values())
    cbom.findings.append(_finding(Priority.P0, "a.py", 1))
    assert cbom.priority_counts()[Priority.P0] == 1
