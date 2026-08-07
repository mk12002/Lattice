"""Fixture tests for the Ruby, PHP, Swift, and Kotlin detectors (v0.3 fan-out)."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from lattice.core.engine import make_finding
from lattice.core.models import Confidence, Priority
from lattice.detectors.java_det import JavaDetector
from lattice.detectors.php_det import PHPDetector
from lattice.detectors.ruby_det import RubyDetector
from lattice.detectors.swift_det import SwiftDetector

FIXTURES = Path(__file__).parent / "fixtures"


def _detect(detector, relative: str):
    content = (FIXTURES / relative).read_text(encoding="utf-8")
    return list(detector.detect(PurePosixPath(relative), content))


def _classified(detector, relative: str):
    return sorted(
        (f.asset.algorithm, f.asset.mode, f.assessment.priority)
        for f in (make_finding(a) for a in _detect(detector, relative))
    )


def test_ruby_fixture():
    expected = sorted(
        [
            ("MD5", None, Priority.P0),
            ("AES-128", "ECB", Priority.P0),
            ("RSA", None, Priority.P0),
            ("AES-256", "GCM", Priority.NONE),
        ]
    )
    assert _classified(RubyDetector(), "ruby/crypto_usage.rb") == expected
    rsa = next(a for a in _detect(RubyDetector(), "ruby/crypto_usage.rb") if a.algorithm == "RSA")
    assert rsa.key_size == 2048
    assert all(
        a.confidence == Confidence.MEDIUM for a in _detect(RubyDetector(), "ruby/crypto_usage.rb")
    )


def test_php_fixture():
    expected = sorted(
        [
            ("SHA-1", None, Priority.P0),
            ("AES-128", "ECB", Priority.P0),
            ("RSA", None, Priority.P0),
            ("AES-256", "GCM", Priority.NONE),
            ("BCRYPT", None, Priority.NONE),
        ]
    )
    assert _classified(PHPDetector(), "php/crypto_usage.php") == expected


def test_swift_fixture():
    expected = sorted(
        [
            ("MD5", None, Priority.P0),
            ("ECDH", None, Priority.P0),  # Curve25519.KeyAgreement -> HNDL
            ("ECDSA", None, Priority.P1),  # P256.Signing -> signature
            ("AES", "GCM", Priority.P2),  # key size not determinable
            ("CHACHA20", None, Priority.NONE),
        ]
    )
    assert _classified(SwiftDetector(), "swift/CryptoUsage.swift") == expected


def test_kotlin_fixture_via_java_detector():
    # the Java detector applies to .kt; Kotlin uses the JCA identically
    assert JavaDetector().applies_to(PurePosixPath("x.kt"))
    expected = sorted(
        [
            ("MD5", None, Priority.P0),
            ("AES", "ECB", Priority.P0),
            ("RSA", None, Priority.P0),
            ("ECDSA", None, Priority.P1),
        ]
    )
    assert _classified(JavaDetector(), "kotlin/CryptoExamples.kt") == expected


def test_swift_commoncrypto_legacy():
    detector = SwiftDetector()
    source = "let algo = kCCAlgorithm3DES\nlet md = CC_SHA1(ptr, len, out)\n"
    algorithms = {a.algorithm for a in detector.detect(PurePosixPath("Legacy.swift"), source)}
    assert algorithms == {"3DES", "SHA-1"}


def test_php_sodium_and_pbkdf2():
    detector = PHPDetector()
    source = (
        "<?php\n"
        "$sig = sodium_crypto_sign_detached($m, $sk);\n"
        "$k = hash_pbkdf2('sha256', $pw, $salt, 600000);\n"
    )
    findings = {a.algorithm for a in detector.detect(PurePosixPath("s.php"), source)}
    assert "EDDSA" in findings
    assert "PBKDF2" in findings
