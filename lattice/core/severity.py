"""Severity model: quantum risk, classical risk, HNDL heuristic, migration priority.

The scoring is a small deterministic decision procedure specified by a truth
table (tests/test_severity.py encodes it in full). Precedence:

1. Classically broken (or broken *usage*, e.g. ECB) outranks everything —
   broken today beats broken later. -> P0
2. Quantum-broken with HNDL exposure (key exchange / asymmetric encryption:
   captured ciphertext is decryptable once a quantum computer exists) -> P0.
   Quantum-broken without HNDL (signatures: a recorded signature mostly
   cannot be retro-forged) -> P1.
3. Classically deprecated -> P2.
4. Quantum-weakened (Grover) -> P2 for ciphers/KDFs, P3 for hashes (usable
   today, larger sizes preferred long-term).
5. Otherwise compliant -> NONE.

The HNDL rule is a *heuristic*: it assumes key-exchange and asymmetric-
encryption traffic can be captured and stored, while signatures have little
retroactive value. It cannot see what data a given call actually protects.
"""

from __future__ import annotations

from lattice.core.models import (
    Assessment,
    ClassicalStatus,
    CryptoAsset,
    Family,
    Finding,
    Priority,
    QuantumStatus,
)
from lattice.rules.algorithms import AlgorithmInfo

#: Families whose captured traffic/ciphertext retains value to a future
#: quantum-equipped adversary (harvest-now-decrypt-later).
_HNDL_FAMILIES = frozenset({Family.KEY_EXCHANGE, Family.ASYMMETRIC_CIPHER})

#: Weights used by the readiness score. Documented in every report.
_SCORE_WEIGHTS: dict[Priority, float] = {
    Priority.P0: 1.0,
    Priority.P1: 0.6,
    Priority.P2: 0.3,
    Priority.P3: 0.1,
    Priority.NONE: 0.0,
}


def effective_family(asset: CryptoAsset, info: AlgorithmInfo) -> Family:
    """Family used for scoring: the detector's usage context wins over the table.

    Example: RSA defaults to asymmetric-cipher (HNDL-relevant), but a call
    site like ``Signature.getInstance("SHA256withRSA")`` pins it to
    signature usage, which is not HNDL-relevant.
    """
    return asset.usage_family or info.family


def hndl_relevant(family: Family) -> bool:
    """Whether the family's captured ciphertext is decryptable-later (heuristic)."""
    return family in _HNDL_FAMILIES


def classical_risk(asset: CryptoAsset, info: AlgorithmInfo) -> ClassicalStatus:
    """Classical status of this *usage*: mode-of-operation flags override the algorithm.

    ECB mode is structurally broken usage regardless of the cipher; CBC
    without authentication is weak usage (padding-oracle prone) — flagged
    only when the algorithm itself is otherwise fine.
    """
    if asset.mode is not None:
        mode = asset.mode.upper()
        if mode == "ECB":
            return ClassicalStatus.BROKEN_USAGE
        if mode == "CBC" and info.classical_status == ClassicalStatus.SECURE:
            return ClassicalStatus.WEAK_USAGE
    return info.classical_status


def quantum_risk(info: AlgorithmInfo) -> QuantumStatus:
    """Quantum status straight from the knowledge base."""
    return info.quantum_status


def assess(asset: CryptoAsset, info: AlgorithmInfo) -> Assessment:
    """Produce the full assessment for one asset. Pure and deterministic."""
    family = effective_family(asset, info)
    q = quantum_risk(info)
    c = classical_risk(asset, info)
    hndl = q == QuantumStatus.BROKEN and hndl_relevant(family)

    if c in (ClassicalStatus.BROKEN, ClassicalStatus.BROKEN_USAGE):
        priority = Priority.P0
        if c == ClassicalStatus.BROKEN_USAGE:
            justification = (
                f"{asset.algorithm} in {asset.mode} mode is structurally unsafe today "
                "(identical plaintext blocks leak); switch to an AEAD mode such as GCM."
            )
        else:
            justification = (
                f"{asset.algorithm} is classically broken today, independent of "
                "quantum computing; replace immediately."
            )
    elif q == QuantumStatus.BROKEN and hndl:
        priority = Priority.P0
        justification = (
            f"{asset.algorithm} {family.value} is broken by Shor's algorithm and "
            "captured ciphertext is decryptable later (harvest-now-decrypt-later)."
        )
    elif q == QuantumStatus.BROKEN:
        priority = Priority.P1
        justification = (
            f"{asset.algorithm} {family.value} is broken by Shor's algorithm; migrate "
            "before quantum capability arrives (no harvest-now-decrypt-later capture value)."
        )
    elif c == ClassicalStatus.DEPRECATED:
        priority = Priority.P2
        justification = (
            f"{asset.algorithm} is deprecated for new use; plan migration to "
            f"{info.pqc_replacement or 'a modern replacement'}."
        )
    elif c == ClassicalStatus.WEAK_USAGE:
        priority = Priority.P2
        justification = (
            f"{asset.algorithm} in {asset.mode} mode without authentication is "
            "padding-oracle prone; use an AEAD mode (GCM or ChaCha20-Poly1305)."
        )
    elif q == QuantumStatus.WEAKENED:
        if family == Family.HASH:
            priority = Priority.P3
            justification = (
                f"{asset.algorithm} is usable today; Grover's algorithm halves its "
                "preimage margin, so prefer larger outputs for long-lived designs."
            )
        else:
            priority = Priority.P2
            justification = (
                f"{asset.algorithm} is weakened by Grover's algorithm; "
                f"{info.pqc_replacement or 'stronger parameters'} restores the margin."
            )
    else:
        priority = Priority.NONE
        justification = f"{asset.algorithm} is quantum-resistant and classically secure."

    return Assessment(
        quantum_status=q,
        classical_status=c,
        hndl_relevant=hndl,
        priority=priority,
        pqc_replacement=info.pqc_replacement,
        justification=justification,
    )


def unknown_assessment(asset: CryptoAsset, reason: str) -> Assessment:
    """Assessment for assets Lattice inventories without judging.

    Used for crypto libraries named in dependency manifests and unparseable
    key material: they belong in the CBOM, but inventing a risk grade for
    them would be false confidence.
    """
    return Assessment(
        quantum_status=QuantumStatus.NA,
        classical_status=ClassicalStatus.UNKNOWN,
        hndl_relevant=False,
        priority=Priority.NONE,
        pqc_replacement=None,
        justification=reason,
    )


def readiness_score(findings: list[Finding]) -> int:
    """Post-quantum readiness score, 0-100, transparently computed.

    Formula: ``100 * (1 - sum(weight(priority)) / count(findings))`` with
    weights P0=1.0, P1=0.6, P2=0.3, P3=0.1, compliant=0. An empty scan (no
    crypto found) scores 100 — there is nothing to migrate. The formula is
    printed alongside the score in every report; it measures the severity-
    weighted share of findings, not real-world breach likelihood.
    """
    if not findings:
        return 100
    penalty = sum(_SCORE_WEIGHTS[f.assessment.priority] for f in findings)
    return round(100 * (1 - penalty / len(findings)))
