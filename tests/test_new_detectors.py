"""Fixture tests for the Rust and C# detectors (v0.2 fan-out)."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from lattice.core.engine import make_finding
from lattice.core.models import Confidence, Priority
from lattice.detectors.csharp_det import CSharpDetector
from lattice.detectors.rust_det import RustDetector

FIXTURES = Path(__file__).parent / "fixtures"


def _detect(detector, relative: str):
    content = (FIXTURES / relative).read_text(encoding="utf-8")
    return list(detector.detect(PurePosixPath(relative), content))


def _classified(detector, relative: str):
    return sorted(
        (f.asset.algorithm, f.asset.mode, f.assessment.priority)
        for f in (make_finding(a) for a in _detect(detector, relative))
    )


def test_rust_fixture():
    expected = sorted(
        [
            ("MD5", None, Priority.P0),
            ("AES-128", "ECB", Priority.P0),
            ("RSA", None, Priority.P0),
            ("AES", "GCM", Priority.P2),  # crate use: key size honestly unknown
            ("CHACHA20", None, Priority.NONE),
        ]
    )
    assert _classified(RustDetector(), "rust/crypto_usage.rs") == expected
    rsa = next(a for a in _detect(RustDetector(), "rust/crypto_usage.rs") if a.algorithm == "RSA")
    assert rsa.key_size == 2048
    assert all(
        a.confidence == Confidence.MEDIUM
        for a in _detect(RustDetector(), "rust/crypto_usage.rs")
    )


def test_csharp_fixture():
    expected = sorted(
        [
            ("MD5", None, Priority.P0),
            ("AES", "ECB", Priority.P0),
            ("RSA", None, Priority.P0),
            ("AES", "GCM", Priority.P2),
            ("PBKDF2", None, Priority.P2),
        ]
    )
    assert _classified(CSharpDetector(), "csharp/CryptoExamples.cs") == expected
    rsa = next(
        a for a in _detect(CSharpDetector(), "csharp/CryptoExamples.cs") if a.algorithm == "RSA"
    )
    assert rsa.key_size == 3072
    aes_ecb = next(
        a
        for a in _detect(CSharpDetector(), "csharp/CryptoExamples.cs")
        if a.algorithm == "AES" and a.mode == "ECB"
    )
    assert "same file" in aes_ecb.note  # file-level mode binding is stated honestly


def test_csharp_weak_hmac_digest_coreported():
    detector = CSharpDetector()
    source = "var mac = new HMACMD5(key);\n"
    algorithms = {a.algorithm for a in detector.detect(PurePosixPath("Mac.cs"), source)}
    assert algorithms == {"HMAC", "MD5"}


def test_csharp_ecdh_and_bouncycastle():
    detector = CSharpDetector()
    source = (
        "using Org.BouncyCastle.Crypto;\n"
        "var ecdh = ECDiffieHellman.Create();\n"
    )
    findings = [make_finding(a) for a in detector.detect(PurePosixPath("Kx.cs"), source)]
    by_algorithm = {f.asset.algorithm: f for f in findings}
    assert by_algorithm["ECDH"].assessment.priority == Priority.P0  # HNDL key exchange
    assert by_algorithm["BouncyCastle.NET"].assessment.priority == Priority.NONE


def test_rust_ring_and_pqc_crates():
    detector = RustDetector()
    source = (
        "use ml_kem::MlKem768;\n"
        "let alg = &ring::signature::ED25519;\n"
        "let aead = &ring::aead::AES_256_GCM;\n"
    )
    findings = [make_finding(a) for a in detector.detect(PurePosixPath("lib.rs"), source)]
    triples = sorted((f.asset.algorithm, f.assessment.priority) for f in findings)
    assert triples == [
        ("AES-256", Priority.NONE),
        ("EDDSA", Priority.P1),
        ("ML-KEM", Priority.NONE),
    ]
