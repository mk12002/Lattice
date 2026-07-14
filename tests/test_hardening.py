"""Phase 6 hardening: walker edge cases, parser fuzzing, readiness sanity."""

from __future__ import annotations

import os
import random
from pathlib import Path, PurePosixPath

import pytest

from lattice.core.engine import scan
from lattice.core.severity import readiness_score
from lattice.core.walker import Walker
from lattice.detectors.base import redact
from lattice.detectors.config_det import (
    ConfigDetector,
    _certificate_signature_oid,
    _decode_oid,
    _read_tlv,
    _spki_algorithm_oid,
)
from lattice.detectors.registry import all_detectors

FIXTURES = Path(__file__).parent / "fixtures"


# -- walker edge cases -------------------------------------------------------------


def test_empty_file_is_harmless(tmp_path):
    (tmp_path / "empty.py").write_text("", encoding="utf-8")
    cbom = scan(tmp_path, all_detectors())
    assert cbom.findings == []


def test_size_cap_skips_huge_files(tmp_path):
    (tmp_path / "huge.py").write_text("import hashlib\n" + "x = 1\n" * 200_000, encoding="utf-8")
    (tmp_path / "small.py").write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    cbom = scan(tmp_path, all_detectors(), max_bytes=10_000)
    assert {f.asset.algorithm for f in cbom.findings} == {"MD5"}
    assert any("size cap" in reason for reason in cbom.stats.skipped_reasons)


def test_binary_masquerading_as_source_is_skipped(tmp_path):
    (tmp_path / "fake.py").write_bytes(b"\x00\x01\x02 md5 rsa \x00\xff")
    cbom = scan(tmp_path, all_detectors())
    assert cbom.findings == []


def test_non_utf8_file_still_scans(tmp_path):
    content = "import hashlib\nhashlib.md5(b'caf\xe9')\n".encode("latin-1")
    (tmp_path / "legacy.py").write_bytes(content)
    cbom = scan(tmp_path, all_detectors())
    assert {f.asset.algorithm for f in cbom.findings} == {"MD5"}


def test_deeply_nested_directories(tmp_path):
    deep = tmp_path
    for i in range(25):
        deep = deep / f"level{i}"
    deep.mkdir(parents=True)
    (deep / "deep.py").write_text("import hashlib\nhashlib.sha1(b'x')\n", encoding="utf-8")
    cbom = scan(tmp_path, all_detectors())
    assert {f.asset.algorithm for f in cbom.findings} == {"SHA-1"}


def test_gitignore_respected(tmp_path):
    (tmp_path / ".gitignore").write_text("generated/\n*.tmp.py\n", encoding="utf-8")
    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "ignored.py").write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    (tmp_path / "scratch.tmp.py").write_text(
        "import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8"
    )
    (tmp_path / "kept.py").write_text("import hashlib\nhashlib.sha1(b'x')\n", encoding="utf-8")
    cbom = scan(tmp_path, all_detectors())
    assert {f.asset.algorithm for f in cbom.findings} == {"SHA-1"}


def test_vendored_trees_skipped_by_default(tmp_path):
    vendored = tmp_path / "node_modules" / "pkg"
    vendored.mkdir(parents=True)
    (vendored / "dep.js").write_text("crypto.createHash('md5')\n", encoding="utf-8")
    (tmp_path / "app.js").write_text("crypto.createHash('sha1')\n", encoding="utf-8")
    cbom = scan(tmp_path, all_detectors())
    assert {f.asset.algorithm for f in cbom.findings} == {"SHA-1"}


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privileges on Windows")
def test_symlink_loop_does_not_hang(tmp_path):
    (tmp_path / "real.py").write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    (tmp_path / "loop").symlink_to(tmp_path, target_is_directory=True)
    cbom = scan(tmp_path, all_detectors())
    assert {f.asset.algorithm for f in cbom.findings} == {"MD5"}


def test_mixed_safe_and_broken_in_one_file(tmp_path):
    (tmp_path / "mixed.py").write_text(
        "import hashlib\n"
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "legacy = hashlib.md5(b'x')\n"
        "aes = AESGCM(AESGCM.generate_key(bit_length=256))\n",
        encoding="utf-8",
    )
    cbom = scan(tmp_path, all_detectors())
    by_algorithm = {f.asset.algorithm: f.assessment.priority.value for f in cbom.findings}
    assert by_algorithm == {"MD5": "P0", "AES-256": "none"}


def test_clean_repo_scores_100():
    cbom = scan(FIXTURES / "python" / "safe_crypto.py", all_detectors())
    assert cbom.findings, "safe fixture must still be detected"
    assert readiness_score(cbom.findings) == 100


def test_walker_deterministic_ordering(tmp_path):
    for name in ("b.py", "a.py", "c.py"):
        (tmp_path / name).write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    paths_a = [p.name for p, _ in Walker(tmp_path).walk()]
    paths_b = [p.name for p, _ in Walker(tmp_path).walk()]
    assert paths_a == paths_b == sorted(paths_a)


# -- config/DER parser fuzzing --------------------------------------------------------


def test_der_walkers_never_raise_on_garbage():
    rng = random.Random(20260714)
    for length in (0, 1, 2, 5, 16, 64, 300):
        for _ in range(200):
            blob = bytes(rng.randrange(256) for _ in range(length))
            _certificate_signature_oid(blob)  # must not raise
            _spki_algorithm_oid(blob)
            _read_tlv(blob, 0)
            _decode_oid(blob)


def test_config_detector_never_raises_on_malformed_text():
    detector = ConfigDetector()
    rng = random.Random(42)
    samples = [
        "-----BEGIN CERTIFICATE-----\nnot base64 at all !!!\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n" + "A" * 5000,  # unterminated block
        "-----BEGIN RSA PRIVATE KEY-----",  # header only
        "ssl_protocols ;;;;\nssl_ciphers\n",
        "\x01\x7f garbage ssl_protocols TLSv1\n",
        "".join(chr(rng.randrange(32, 127)) for _ in range(2000)),
    ]
    for sample in samples:
        list(detector.detect(PurePosixPath("fuzz.pem"), sample))  # must not raise


def test_malformed_certificate_reports_presence_only():
    detector = ConfigDetector()
    content = "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n"
    assets = list(detector.detect(PurePosixPath("bad.crt"), content))
    assert len(assets) == 1
    assert assets[0].algorithm == "UNKNOWN"
    assert "presence" in assets[0].note


# -- redaction ---------------------------------------------------------------------------


def test_redact_masks_long_token_runs():
    secret = "AKIA" + "B" * 40
    assert "AKIA" not in redact(f"key = '{secret}'")
    assert redact("short = 'abc123'") == "short = 'abc123'"


def test_redact_drops_pem_lines():
    assert redact("-----BEGIN RSA PRIVATE KEY-----") == "[PEM material redacted]"
