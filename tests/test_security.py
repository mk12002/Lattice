"""Security regression tests.

Each test pins a specific hardening decision so it can't silently regress.
Lattice's threat model is "scan a possibly-hostile repository and never
leak, crash, or hang", so these exercise the untrusted-input surfaces:
symlinks planted in a scanned tree, malformed CBOMs handed to ``diff``,
pathological files aimed at the detectors, and the CLI's own argument
handling.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import PurePosixPath

import pytest

from lattice.cli import main
from lattice.core.diff import CbomLoadError, diff
from lattice.core.engine import scan
from lattice.detectors.base import LineIndex
from lattice.detectors.java_det import JavaDetector
from lattice.detectors.registry import all_detectors

# -- symlink handling: a hostile repo must not exfiltrate outside files -------------


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privileges on Windows")
def test_symlinked_file_is_not_followed(tmp_path):
    secret = tmp_path / "outside_secret.txt"
    secret.write_text("import hashlib\nhashlib.md5(b'SECRET-KEY-MATERIAL')\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import hashlib\nhashlib.sha1(b'x')\n", encoding="utf-8")
    # a symlink planted inside the scanned tree, pointing at the outside file
    link = repo / "innocent.py"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted in this environment")

    cbom = scan(repo, all_detectors())
    algorithms = {f.asset.algorithm for f in cbom.findings}
    assert algorithms == {"SHA-1"}  # only the real file; the symlink was skipped
    # the outside file's contents never reached any finding
    for f in cbom.findings:
        assert "SECRET-KEY-MATERIAL" not in f.asset.snippet
    assert any("symlink" in r for r in cbom.stats.skipped_reasons)


# -- diff must never crash on malformed-but-valid JSON ------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        '{"bomFormat": "CycloneDX", "components": "not-a-list"}',
        '{"bomFormat": "CycloneDX", "components": [42, "str", null, {"name": "RSA"}]}',
        '{"bomFormat": "CycloneDX", "components": [{"properties": "nope"}]}',
        '{"bomFormat": "CycloneDX", "components": [{"evidence": 7}]}',
        '{"bomFormat": "CycloneDX", "components": [{"evidence": {"occurrences": "x"}}]}',
        '{"bomFormat": "CycloneDX", "properties": [{"name": "lattice:readinessScore", "value": "NaN"}]}',
        '{"bomFormat": "CycloneDX", "components": [{"properties": [1, 2, {"name": "lattice:priority", "value": "P0"}]}]}',
    ],
)
def test_diff_survives_malformed_cbom(tmp_path, payload):
    good = tmp_path / "good.json"
    good.write_text(
        '{"bomFormat": "CycloneDX", "components": [], "properties": []}', encoding="utf-8"
    )
    bad = tmp_path / "bad.json"
    bad.write_text(payload, encoding="utf-8")
    # must not raise; a crafted CBOM is untrusted input to `lattice diff`
    result = diff(good, bad)
    assert isinstance(result.new, list)
    assert isinstance(result.resolved, list)


def test_diff_rejects_non_cyclonedx_and_non_json(tmp_path):
    plain = tmp_path / "a.json"
    plain.write_text('{"hello": "world"}', encoding="utf-8")
    other = tmp_path / "b.json"
    other.write_text('{"bomFormat": "CycloneDX", "components": []}', encoding="utf-8")
    with pytest.raises(CbomLoadError):
        diff(plain, other)
    garbage = tmp_path / "c.json"
    garbage.write_text("\x00\x01 not json at all {{{", encoding="utf-8")
    with pytest.raises(CbomLoadError):
        diff(garbage, other)


def test_diff_top_level_not_an_object(tmp_path):
    arr = tmp_path / "arr.json"
    arr.write_text("[1, 2, 3]", encoding="utf-8")
    other = tmp_path / "b.json"
    other.write_text('{"bomFormat": "CycloneDX", "components": []}', encoding="utf-8")
    with pytest.raises(CbomLoadError):
        diff(arr, other)


# -- LineIndex correctness + linear-time behavior -----------------------------------


def test_line_index_matches_naive_count():
    content = "a\nbb\n\nccc\nd"
    index = LineIndex(content)
    for offset in range(len(content) + 1):
        assert index.line_of(offset) == content.count("\n", 0, offset) + 1


def test_java_detector_scales_linearly_on_many_matches():
    """A file crafted with thousands of getInstance calls must stay near-linear.

    The pre-LineIndex implementation counted newlines from the start per
    match (quadratic); a 6000-match file would take seconds. This asserts it
    completes well under a generous bound.
    """
    body = 'Cipher.getInstance("AES/ECB/PKCS5Padding");\n' * 6000
    detector = JavaDetector()
    start = time.perf_counter()
    findings = list(detector.detect(PurePosixPath("Big.java"), body))
    elapsed = time.perf_counter() - start
    assert findings  # it still detects
    assert elapsed < 5.0, f"Java detector too slow ({elapsed:.1f}s) — quadratic regression?"


# -- CLI argument validation --------------------------------------------------------


def test_cli_rejects_non_positive_max_file_bytes(tmp_path):
    (tmp_path / "app.py").write_text("import hashlib\n", encoding="utf-8")
    out = tmp_path / "rep"
    assert main(["scan", str(tmp_path), "--out", str(out), "--max-file-bytes", "0"]) == 2
    assert main(["scan", str(tmp_path), "--out", str(out), "--max-file-bytes", "-1"]) == 2


# -- no secret material in any output, end to end (belt-and-suspenders) --------------


def test_private_key_bytes_never_reach_any_output(tmp_path):
    key = tmp_path / "server.key"
    key.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "SUPERSECRETPRIVATEKEYBYTESdEADbEEF0123456789ABCDEF\n"
        "-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    out = tmp_path / "rep"
    assert main(["scan", str(tmp_path), "--format", "all", "--out", str(out), "--quiet"]) == 0
    for name in ("cbom.json", "report.html", "findings.sarif"):
        text = (out / name).read_text(encoding="utf-8")
        assert "SUPERSECRETPRIVATEKEYBYTES" not in text
        assert "dEADbEEF0123456789ABCDEF" not in text
    # the key's presence is still reported (location + type only)
    doc = json.loads((out / "cbom.json").read_text(encoding="utf-8"))
    assert any(c.get("name") == "RSA" for c in doc["components"])


def test_scan_never_writes_outside_the_out_dir(tmp_path):
    (tmp_path / "app.py").write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    out = tmp_path / "nested" / "report"
    assert main(["scan", str(tmp_path), "--format", "all", "--out", str(out), "--quiet"]) == 0
    written = {p.name for p in out.iterdir()}
    assert written == {"cbom.json", "report.html", "findings.sarif"}
