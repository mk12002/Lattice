"""Gate 2: the walking skeleton finds exactly the known Python fixture assets."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

from lattice.core.engine import scan
from lattice.core.models import Confidence, Priority
from lattice.detectors.python_det import PythonDetector
from lattice.emitters import cbom_emitter

FIXTURES = Path(__file__).parent / "fixtures" / "python"


def _detect(filename: str):
    detector = PythonDetector()
    content = (FIXTURES / filename).read_text(encoding="utf-8")
    return list(detector.detect(PurePosixPath(filename), content))


def test_broken_hash_fixture():
    assets = _detect("broken_hash.py")
    assert len(assets) == 1
    a = assets[0]
    assert a.algorithm == "MD5"
    assert a.confidence == Confidence.HIGH
    assert a.line_number == 12
    assert "md5" in a.snippet


def test_quantum_vulnerable_fixture():
    assets = _detect("quantum_vulnerable.py")
    assert len(assets) == 1
    a = assets[0]
    assert a.algorithm == "RSA"
    assert a.key_size == 2048
    assert a.confidence == Confidence.HIGH


def test_safe_fixture():
    assets = _detect("safe_crypto.py")
    names = sorted((a.algorithm, a.mode) for a in assets)
    assert names == [("AES-256", "GCM"), ("CHACHA20", None)]
    assert all(a.confidence == Confidence.HIGH for a in assets)
    aes = next(a for a in assets if a.algorithm == "AES-256")
    assert aes.key_size == 256


def test_aliased_imports_and_ast_edge_cases():
    detector = PythonDetector()
    source = (
        "import hashlib\n"
        "from hashlib import sha1 as weak\n"
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "h = hashlib.new('md5')\n"
        "w = weak(b'x')\n"
        "c = Cipher(algorithms.AES(b'0123456789abcdef'), modes.ECB())\n"
    )
    assets = list(detector.detect(PurePosixPath("edge.py"), source))
    by_algorithm = {a.algorithm: a for a in assets}
    assert set(by_algorithm) == {"MD5", "SHA-1", "AES-128"}
    aes = by_algorithm["AES-128"]
    assert aes.mode == "ECB"
    assert aes.key_size == 128  # 16-byte literal key


def test_syntax_error_falls_back_to_low_confidence_regex():
    detector = PythonDetector()
    source = "def broken(:\n    x = md5_digest  # not valid python\n"
    assets = list(detector.detect(PurePosixPath("bad.py"), source))
    assert all(a.confidence == Confidence.LOW for a in assets)


def test_end_to_end_scan_classifies_fixtures(tmp_path):
    cbom = scan(FIXTURES, [PythonDetector()])
    by_algorithm = {f.asset.algorithm: f for f in cbom.findings}
    assert set(by_algorithm) == {"MD5", "RSA", "AES-256", "CHACHA20"}
    assert by_algorithm["MD5"].assessment.priority == Priority.P0
    rsa = by_algorithm["RSA"]
    assert rsa.assessment.priority == Priority.P0
    assert rsa.assessment.hndl_relevant is True
    assert by_algorithm["AES-256"].assessment.priority == Priority.NONE
    assert by_algorithm["CHACHA20"].assessment.priority == Priority.NONE
    # findings arrive pre-sorted
    assert cbom.findings == cbom.sorted_findings()


def test_cbom_emitter_valid_and_deterministic():
    cbom_a = scan(FIXTURES, [PythonDetector()])
    cbom_b = scan(FIXTURES, [PythonDetector()])
    out_a, out_b = cbom_emitter.emit(cbom_a), cbom_emitter.emit(cbom_b)
    doc = json.loads(out_a)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert all(
        c["type"] in ("cryptographic-asset", "library") for c in doc["components"]
    )
    rsa = next(c for c in doc["components"] if c["name"] == "RSA")
    assert rsa["evidence"]["occurrences"][0]["location"].endswith("quantum_vulnerable.py")
    props = {p["name"]: p["value"] for p in rsa["properties"]}
    assert props["lattice:priority"] == "P0"
    assert props["lattice:hndl"] == "true"
    # byte-identical modulo the single timestamp
    normalized_a = out_a.replace(cbom_a.generated_at, "T")
    normalized_b = out_b.replace(cbom_b.generated_at, "T")
    assert normalized_a == normalized_b
