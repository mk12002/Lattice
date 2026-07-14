"""Knowledge-base integrity tests: every name resolves, no contradictory entries."""

from __future__ import annotations

from lattice.core.models import ClassicalStatus, QuantumStatus
from lattice.rules.algorithms import ALGORITHMS, SYNONYMS, lookup


def test_every_canonical_name_resolves():
    for name, info in ALGORITHMS.items():
        resolved = lookup(name)
        assert resolved is info, f"canonical name {name!r} failed to resolve"
        # case/separator-insensitive
        assert lookup(name.lower()) is info
        assert lookup(name.replace("-", "_")) is info


def test_every_synonym_resolves_to_existing_canonical():
    for syn, canonical in SYNONYMS.items():
        assert canonical in ALGORITHMS, f"synonym {syn!r} points at unknown {canonical!r}"
        info = lookup(syn)
        assert info is not None and info.name == canonical, f"synonym {syn!r} failed"


def test_unknown_names_return_none():
    assert lookup("ROT13-DELUXE") is None
    assert lookup("") is None


def test_no_contradictory_entries():
    """A quantum-safe, classically-secure entry is already a target: no replacement."""
    for name, info in ALGORITHMS.items():
        if (
            info.quantum_status == QuantumStatus.SAFE
            and info.classical_status == ClassicalStatus.SECURE
        ):
            assert info.pqc_replacement is None, f"{name} is a target but has a replacement"
        # anything not fully safe+secure must tell the user where to go
        if info.classical_status in (ClassicalStatus.BROKEN, ClassicalStatus.DEPRECATED):
            assert info.pqc_replacement, f"{name} is weak but names no replacement"
        if info.quantum_status == QuantumStatus.BROKEN:
            assert info.pqc_replacement, f"{name} is quantum-broken but names no replacement"


def test_key_synonyms_spot_checks():
    assert lookup("prime256v1").name == "ECDSA"
    assert lookup("secp256r1").name == "ECDSA"
    assert lookup("Rijndael").name == "AES"
    assert lookup("Ed25519").name == "EDDSA"
    assert lookup("X25519").name == "ECDH"  # key agreement, not signature
    assert lookup("Kyber768").name == "ML-KEM"
    assert lookup("Dilithium").name == "ML-DSA"
    assert lookup("SPHINCS+").name == "SLH-DSA"
    assert lookup("DESede").name == "3DES"
    assert lookup("SHA").name == "SHA-1"  # bare JCA "SHA" is SHA-1
    assert lookup("sha_256").name == "SHA-256"
    assert lookup("chacha20-poly1305").name == "CHACHA20"
