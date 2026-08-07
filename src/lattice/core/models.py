"""Shared data structures: the spine every detector and emitter builds on.

Design rules:
- Immutable-where-possible dataclasses (``frozen=True``).
- Every finding traces to a concrete file and line; nothing is inferred.
- ``Finding`` defines a stable sort key (priority, path, line, algorithm) so
  all emitter output is deterministic across runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Confidence(StrEnum):
    """How certain the detector is that the matched pattern is real crypto usage.

    AST-level matches in a parsed language are HIGH; regex matches in dynamic
    languages are MEDIUM or LOW. Emitters must surface this honestly.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Family(StrEnum):
    """Cryptographic family of an asset (drives the HNDL heuristic)."""

    SYMMETRIC_CIPHER = "symmetric-cipher"
    ASYMMETRIC_CIPHER = "asymmetric-cipher"
    SIGNATURE = "signature"
    KEY_EXCHANGE = "key-exchange"
    HASH = "hash"
    KDF = "kdf"
    MAC = "mac"
    RNG = "rng"
    PROTOCOL = "protocol"  # TLS versions / cipher-suite configuration
    KEY_MATERIAL = "key-material"  # certificates and key files found on disk
    LIBRARY = "library"  # crypto library declared in a dependency manifest


class QuantumStatus(StrEnum):
    """Quantum-computer exposure of an algorithm.

    BROKEN    -- Shor's algorithm defeats it (RSA, DSA, DH, ECC).
    WEAKENED  -- Grover's algorithm halves effective strength; larger
                 parameters restore the margin (AES-128, SHA-256).
    SAFE      -- believed quantum-resistant (ML-KEM, ML-DSA, SLH-DSA,
                 symmetric at >=256-bit).
    NA        -- not applicable / already classically broken.
    """

    BROKEN = "broken"
    WEAKENED = "weakened"
    SAFE = "safe"
    NA = "n/a"


class ClassicalStatus(StrEnum):
    """Classical (non-quantum) security status.

    BROKEN_USAGE marks a structurally unsafe *usage* (e.g. ECB mode) even
    when the underlying cipher is sound. WEAK_USAGE marks risky-but-not-
    broken usage (e.g. unauthenticated CBC). UNKNOWN is for assets Lattice
    inventories without judging (e.g. a crypto library named in a manifest).
    """

    SECURE = "secure"
    DEPRECATED = "deprecated"
    BROKEN = "broken"
    BROKEN_USAGE = "broken-usage"
    WEAK_USAGE = "weak-usage"
    UNKNOWN = "unknown"


class Priority(StrEnum):
    """Migration priority. P0 is most urgent; NONE means compliant/informational."""

    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    NONE = "none"

    @property
    def rank(self) -> int:
        """Numeric rank for ordering and --fail-on comparison (P0 = 0)."""
        return _PRIORITY_RANK[self]


_PRIORITY_RANK: dict[Priority, int] = {
    Priority.P0: 0,
    Priority.P1: 1,
    Priority.P2: 2,
    Priority.P3: 3,
    Priority.NONE: 4,
}


@dataclass(frozen=True)
class CryptoAsset:
    """One concrete cryptographic usage matched at a real file and line.

    ``algorithm`` is the canonical name (resolved through the knowledge-base
    synonym map by the detector). ``usage_family`` lets a detector override
    the knowledge-base family when the call site disambiguates usage
    (e.g. ``Signature.getInstance("SHA256withRSA")`` is RSA *as a signature*,
    which changes its HNDL exposure).
    """

    algorithm: str
    file_path: str
    line_number: int
    detector: str
    confidence: Confidence
    snippet: str = ""
    key_size: int | None = None
    curve: str | None = None
    mode: str | None = None
    usage_family: Family | None = None
    note: str = ""
    #: kind of crypto material for on-disk artifacts ("private-key",
    #: "certificate", "keystore"); None for in-code algorithm usage
    material: str | None = None


@dataclass(frozen=True)
class Assessment:
    """The severity model's judgment of one asset."""

    quantum_status: QuantumStatus
    classical_status: ClassicalStatus
    hndl_relevant: bool
    priority: Priority
    pqc_replacement: str | None
    justification: str


@dataclass(frozen=True)
class Finding:
    """A detected asset plus its assessment. The unit of all reports.

    ``accepted_reason`` is set when a ``lattice.toml`` acceptance matches:
    the finding stays in every report (an inventory must stay complete) but
    is excluded from the readiness score and the --fail-on gate.
    """

    asset: CryptoAsset
    assessment: Assessment
    accepted_reason: str | None = None

    def sort_key(self) -> tuple[int, str, int, str]:
        """Stable, deterministic ordering: priority, then path, line, algorithm."""
        return (
            self.assessment.priority.rank,
            self.asset.file_path,
            self.asset.line_number,
            self.asset.algorithm,
        )


@dataclass
class ScanStats:
    """Bookkeeping for the scan itself (surfaced so failures are never silent)."""

    files_scanned: int = 0
    files_skipped: int = 0
    skipped_reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class CBOM:
    """The complete scan result: metadata + deterministically ordered findings.

    ``generated_at`` is the single timestamp permitted anywhere in the
    output; everything else must be byte-identical across runs.
    """

    tool_version: str
    generated_at: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)

    def sorted_findings(self) -> list[Finding]:
        """Findings in the canonical deterministic order."""
        return sorted(self.findings, key=Finding.sort_key)

    def priority_counts(self) -> dict[Priority, int]:
        """Count of findings per priority (all priorities present, zero-filled)."""
        counts = {p: 0 for p in Priority}
        for f in self.findings:
            counts[f.assessment.priority] += 1
        return counts
