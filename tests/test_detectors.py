"""Gate 3: every fan-out detector finds exactly its fixture's known assets."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest

from lattice.core.engine import make_finding, scan
from lattice.core.models import Confidence, Family, Priority
from lattice.detectors.c_cpp_det import CCppDetector
from lattice.detectors.config_det import ConfigDetector
from lattice.detectors.dependency_det import DependencyDetector
from lattice.detectors.go_det import GoDetector
from lattice.detectors.java_det import JavaDetector
from lattice.detectors.javascript_det import JavaScriptDetector
from lattice.detectors.registry import all_detectors

FIXTURES = Path(__file__).parent / "fixtures"


def _detect(detector, relative: str):
    content = (FIXTURES / relative).read_text(encoding="utf-8")
    return list(detector.detect(PurePosixPath(relative), content))


def _classified(detector, relative: str):
    """(algorithm, mode, priority) triples for every asset in a fixture."""
    return sorted(
        (
            f.asset.algorithm,
            f.asset.mode,
            f.assessment.priority,
        )
        for f in (make_finding(a) for a in _detect(detector, relative))
    )


def test_java_fixture():
    expected = sorted(
        [
            ("AES", "ECB", Priority.P0),
            ("MD5", None, Priority.P0),
            ("RSA", None, Priority.P0),
            ("ECDSA", None, Priority.P1),
            ("HMAC", None, Priority.NONE),
            ("BouncyCastle", None, Priority.NONE),
        ]
    )
    assert _classified(JavaDetector(), "java/CryptoExamples.java") == expected
    rsa = next(
        a for a in _detect(JavaDetector(), "java/CryptoExamples.java") if a.algorithm == "RSA"
    )
    assert rsa.confidence == Confidence.MEDIUM  # regex on a string literal, marked honestly


def test_javascript_fixture():
    expected = sorted(
        [
            ("SHA-1", None, Priority.P0),
            ("AES-128", "ECB", Priority.P0),
            ("RSA", None, Priority.P0),
            ("AES-256", "GCM", Priority.NONE),
            ("PBKDF2", None, Priority.P2),
            ("node-forge", None, Priority.NONE),
        ]
    )
    assert _classified(JavaScriptDetector(), "javascript/crypto_usage.js") == expected
    rsa = next(
        a
        for a in _detect(JavaScriptDetector(), "javascript/crypto_usage.js")
        if a.algorithm == "RSA"
    )
    assert rsa.key_size == 2048


def test_go_fixture():
    expected = sorted(
        [
            ("MD5", None, Priority.P0),
            ("RSA", None, Priority.P0),
            ("SHA-256", None, Priority.P3),
            ("CHACHA20", None, Priority.NONE),
        ]
    )
    assert _classified(GoDetector(), "go/main.go") == expected
    assert all(a.confidence == Confidence.HIGH for a in _detect(GoDetector(), "go/main.go"))


def test_c_cpp_fixture():
    expected = sorted(
        [
            ("MD5", None, Priority.P0),
            ("AES-128", "ECB", Priority.P0),
            ("RSA", None, Priority.P0),
            ("AES-256", "GCM", Priority.NONE),
        ]
    )
    assert _classified(CCppDetector(), "c_cpp/legacy_crypto.c") == expected


def test_config_tls_fixture():
    expected = sorted(
        [
            ("TLS-1.0", None, Priority.P2),
            ("TLS-1.1", None, Priority.P2),
            ("TLS-1.2", None, Priority.NONE),
            ("RC4", None, Priority.P0),
            ("3DES", None, Priority.P2),
        ]
    )
    assert _classified(ConfigDetector(), "config/tls.conf") == expected


def test_config_certificate_extracts_signature_oid():
    findings = [make_finding(a) for a in _detect(ConfigDetector(), "config/server.crt")]
    triples = sorted((f.asset.algorithm, f.assessment.priority) for f in findings)
    assert triples == [("RSA", Priority.P1), ("SHA-1", Priority.P0)]
    assert all(f.asset.material == "certificate" for f in findings)
    # RSA in a certificate is signature usage: quantum-broken but not HNDL
    rsa = next(f for f in findings if f.asset.algorithm == "RSA")
    assert rsa.assessment.hndl_relevant is False


def test_config_private_key_location_only_never_contents():
    raw = (FIXTURES / "config/server.key").read_text(encoding="utf-8")
    key_body = "RkFLRSBLRVkg"  # start of the (fake) base64 body
    assert key_body in raw  # the fixture really contains body material
    assets = _detect(ConfigDetector(), "config/server.key")
    assert len(assets) == 1
    asset = assets[0]
    assert asset.algorithm == "RSA"
    assert asset.material == "private-key"
    assert key_body not in asset.snippet
    assert key_body not in asset.note
    finding = make_finding(asset)
    assert finding.assessment.priority == Priority.P0  # conservative: HNDL-scored


def test_config_ssh_public_key():
    assets = _detect(ConfigDetector(), "config/id_ed25519.pub")
    assert [a.algorithm for a in assets] == ["EDDSA"]
    assert "AAAA" not in assets[0].snippet  # key material never echoed
    assert make_finding(assets[0]).assessment.priority == Priority.P1


def test_config_keystore_binary_presence_only():
    detector = ConfigDetector()
    assert detector.accepts_binary is True
    assets = list(detector.detect(PurePosixPath("secrets/legacy.p12"), ""))
    assert len(assets) == 1
    assert assets[0].material == "keystore"
    assert make_finding(assets[0]).assessment.priority == Priority.NONE


@pytest.mark.parametrize(
    "manifest,expected",
    [
        ("dependencies/requirements.txt", {"cryptography", "pycrypto"}),
        ("dependencies/package.json", {"node-forge", "bcrypt"}),
        ("dependencies/go.mod", {"golang.org/x/crypto"}),
        ("dependencies/pom.xml", {"bcprov-jdk18on"}),
        ("dependencies/Cargo.toml", {"md-5", "ring"}),
    ],
)
def test_dependency_manifests(manifest, expected):
    assets = _detect(DependencyDetector(), manifest)
    assert {a.algorithm for a in assets} == expected
    for asset in assets:
        assert asset.usage_family == Family.LIBRARY
        finding = make_finding(asset)
        assert finding.assessment.priority == Priority.NONE  # inventory, not judgment
        assert "usage not confirmed" in asset.note


def test_dependency_malformed_manifest_yields_nothing():
    detector = DependencyDetector()
    assert list(detector.detect(PurePosixPath("package.json"), "{not json")) == []
    assert list(detector.detect(PurePosixPath("Cargo.toml"), "= broken [toml")) == []


def test_gate3_full_fixture_tree_has_no_false_negatives():
    """Scan the entire fixture tree with every detector: the union of all
    per-fixture known answers must be present with correct classification."""
    cbom = scan(FIXTURES, all_detectors())
    got = {
        (f.asset.file_path.rsplit("/", 1)[-1], f.asset.algorithm, f.assessment.priority)
        for f in cbom.findings
    }
    required = {
        ("broken_hash.py", "MD5", Priority.P0),
        ("quantum_vulnerable.py", "RSA", Priority.P0),
        ("safe_crypto.py", "AES-256", Priority.NONE),
        ("safe_crypto.py", "CHACHA20", Priority.NONE),
        ("CryptoExamples.java", "AES", Priority.P0),
        ("CryptoExamples.java", "MD5", Priority.P0),
        ("CryptoExamples.java", "RSA", Priority.P0),
        ("CryptoExamples.java", "ECDSA", Priority.P1),
        ("crypto_usage.js", "SHA-1", Priority.P0),
        ("crypto_usage.js", "AES-128", Priority.P0),
        ("crypto_usage.js", "RSA", Priority.P0),
        ("crypto_usage.js", "AES-256", Priority.NONE),
        ("crypto_usage.js", "PBKDF2", Priority.P2),
        ("main.go", "MD5", Priority.P0),
        ("main.go", "RSA", Priority.P0),
        ("main.go", "CHACHA20", Priority.NONE),
        ("legacy_crypto.c", "MD5", Priority.P0),
        ("legacy_crypto.c", "AES-128", Priority.P0),
        ("legacy_crypto.c", "RSA", Priority.P0),
        ("tls.conf", "RC4", Priority.P0),
        ("tls.conf", "TLS-1.0", Priority.P2),
        ("server.crt", "SHA-1", Priority.P0),
        ("server.key", "RSA", Priority.P0),
        ("id_ed25519.pub", "EDDSA", Priority.P1),
        ("requirements.txt", "pycrypto", Priority.NONE),
        ("crypto_usage.rs", "MD5", Priority.P0),
        ("crypto_usage.rs", "AES-128", Priority.P0),
        ("crypto_usage.rs", "RSA", Priority.P0),
        ("CryptoExamples.cs", "MD5", Priority.P0),
        ("CryptoExamples.cs", "AES", Priority.P0),
        ("CryptoExamples.cs", "RSA", Priority.P0),
        ("crypto_usage.rb", "MD5", Priority.P0),
        ("crypto_usage.rb", "AES-128", Priority.P0),
        ("crypto_usage.rb", "RSA", Priority.P0),
        ("crypto_usage.php", "SHA-1", Priority.P0),
        ("crypto_usage.php", "AES-128", Priority.P0),
        ("crypto_usage.php", "RSA", Priority.P0),
        ("CryptoUsage.swift", "MD5", Priority.P0),
        ("CryptoUsage.swift", "ECDH", Priority.P0),
        ("CryptoExamples.kt", "MD5", Priority.P0),
        ("CryptoExamples.kt", "RSA", Priority.P0),
    }
    missing = required - got
    assert not missing, f"false negatives: {sorted(missing)}"
