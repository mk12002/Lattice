"""Scoring truth table (Appendix C of the execution plan). This is the spec."""

from __future__ import annotations

import pytest

from lattice.core.models import (
    ClassicalStatus,
    Confidence,
    CryptoAsset,
    Family,
    Finding,
    Priority,
    QuantumStatus,
)
from lattice.core.severity import assess, readiness_score, unknown_assessment
from lattice.rules.algorithms import lookup


def _asset(algorithm: str, mode: str | None = None, usage: Family | None = None) -> CryptoAsset:
    return CryptoAsset(
        algorithm=algorithm,
        file_path="x.py",
        line_number=1,
        detector="test",
        confidence=Confidence.HIGH,
        mode=mode,
        usage_family=usage,
    )


def _priority(algorithm: str, mode: str | None = None, usage: Family | None = None) -> Priority:
    asset = _asset(algorithm, mode=mode, usage=usage)
    info = lookup(algorithm)
    assert info is not None, f"{algorithm} missing from knowledge base"
    return assess(asset, info).priority


# The full truth table: (algorithm, mode, usage_family) -> expected priority.
TRUTH_TABLE = [
    # RSA key exchange / encryption: quantum-broken + HNDL -> P0
    ("RSA", None, None, Priority.P0),
    # DH / ECDH key exchange: same HNDL exposure -> P0
    ("DH", None, None, Priority.P0),
    ("ECDH", None, None, Priority.P0),
    ("X25519", None, None, Priority.P0),
    # Signatures: quantum-broken but no HNDL capture value -> P1
    ("ECDSA", None, None, Priority.P1),
    ("EDDSA", None, None, Priority.P1),
    ("Ed25519", None, None, Priority.P1),
    ("DSA", None, None, Priority.P1),
    ("RSA", None, Family.SIGNATURE, Priority.P1),  # RSA pinned to signature usage
    # Broken today, independent of quantum -> P0
    ("MD5", None, None, Priority.P0),
    ("SHA-1", None, None, Priority.P0),
    ("DES", None, None, Priority.P0),
    ("RC4", None, None, Priority.P0),
    # ECB is broken usage regardless of cipher -> P0
    ("AES-256", "ECB", None, Priority.P0),
    ("AES-128", "ECB", None, Priority.P0),
    # Deprecated -> P2
    ("3DES", None, None, Priority.P2),
    ("BLOWFISH", None, None, Priority.P2),
    # Grover-weakened ciphers/KDFs -> P2
    ("AES-128", None, None, Priority.P2),
    ("AES-128", "GCM", None, Priority.P2),
    ("PBKDF2", None, None, Priority.P2),
    # Unauthenticated CBC on an otherwise-fine cipher -> P2
    ("AES-256", "CBC", None, Priority.P2),
    # Compliant -> NONE
    ("AES-256", "GCM", None, Priority.NONE),
    ("AES-256", None, None, Priority.NONE),
    ("CHACHA20", None, None, Priority.NONE),
    ("ML-KEM", None, None, Priority.NONE),
    ("ML-DSA", None, None, Priority.NONE),
    ("SLH-DSA", None, None, Priority.NONE),
    ("HMAC", None, None, Priority.NONE),
    ("ARGON2", None, None, Priority.NONE),
    ("SHA-384", None, None, Priority.NONE),
    # Grover-weakened hash: usable today -> P3
    ("SHA-256", None, None, Priority.P3),
]


@pytest.mark.parametrize("algorithm,mode,usage,expected", TRUTH_TABLE)
def test_truth_table(algorithm, mode, usage, expected):
    assert _priority(algorithm, mode=mode, usage=usage) == expected


def test_hndl_flag_set_only_for_capturable_families():
    rsa = assess(_asset("RSA"), lookup("RSA"))
    assert rsa.hndl_relevant is True
    ecdsa = assess(_asset("ECDSA"), lookup("ECDSA"))
    assert ecdsa.hndl_relevant is False
    rsa_sig = assess(_asset("RSA", usage=Family.SIGNATURE), lookup("RSA"))
    assert rsa_sig.hndl_relevant is False
    md5 = assess(_asset("MD5"), lookup("MD5"))
    assert md5.hndl_relevant is False


def test_ecb_reported_as_broken_usage():
    a = assess(_asset("AES-256", mode="ECB"), lookup("AES-256"))
    assert a.classical_status == ClassicalStatus.BROKEN_USAGE
    assert a.priority == Priority.P0


def test_every_assessment_has_justification():
    for algorithm, mode, usage, _expected in TRUTH_TABLE:
        a = assess(_asset(algorithm, mode=mode, usage=usage), lookup(algorithm))
        assert a.justification.strip(), f"no justification for {algorithm}/{mode}/{usage}"


def test_unknown_assessment_is_honest():
    a = unknown_assessment(_asset("somecryptolib"), "library present; usage not confirmed")
    assert a.priority == Priority.NONE
    assert a.quantum_status == QuantumStatus.NA
    assert a.classical_status == ClassicalStatus.UNKNOWN


def _finding(algorithm: str, priority_mode: str | None = None) -> Finding:
    asset = _asset(algorithm, mode=priority_mode)
    return Finding(asset, assess(asset, lookup(algorithm)))


def test_readiness_score_bounds_and_ordering():
    assert readiness_score([]) == 100
    clean = [_finding("AES-256"), _finding("ML-KEM"), _finding("SHA-384")]
    assert readiness_score(clean) == 100
    all_p0 = [_finding("MD5"), _finding("RSA")]
    assert readiness_score(all_p0) == 0
    mixed = clean + all_p0
    assert 0 < readiness_score(mixed) < 100
    # more compliant findings -> higher score (monotonicity)
    assert readiness_score(clean + [_finding("MD5")]) > readiness_score(all_p0)
