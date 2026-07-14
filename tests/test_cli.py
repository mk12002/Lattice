"""Gate 5: CLI contract — exit codes, filtering, robustness, rules table."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lattice.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_version(capsys):
    assert main(["version"]) == 0
    assert "lattice 0.1.0" in capsys.readouterr().out


def test_scan_all_formats(tmp_path, capsys):
    code = main(["scan", str(FIXTURES / "python"), "--format", "all", "--out", str(tmp_path)])
    assert code == 0
    for name in ("cbom.json", "report.html", "findings.sarif"):
        assert (tmp_path / name).exists(), f"{name} missing"
    json.loads((tmp_path / "cbom.json").read_text(encoding="utf-8"))
    json.loads((tmp_path / "findings.sarif").read_text(encoding="utf-8"))
    out = capsys.readouterr().out
    assert "readiness score" in out


def test_fail_on_gate_nonzero_with_p0(tmp_path):
    code = main(
        ["scan", str(FIXTURES / "python"), "--format", "cbom", "--out", str(tmp_path),
         "--fail-on", "P0", "--quiet"]
    )
    assert code == 1


def test_fail_on_gate_zero_without_matching_priority(tmp_path):
    # the safe fixture alone has only compliant findings
    code = main(
        ["scan", str(FIXTURES / "python" / "safe_crypto.py"), "--format", "cbom",
         "--out", str(tmp_path), "--fail-on", "P0", "--quiet"]
    )
    assert code == 0


def test_fail_on_threshold_includes_higher_priorities(tmp_path):
    # P3 threshold must also trip on P0 findings (at or above)
    code = main(
        ["scan", str(FIXTURES / "python"), "--format", "cbom", "--out", str(tmp_path),
         "--fail-on", "P3", "--quiet"]
    )
    assert code == 1


def test_exclude_filters_files(tmp_path):
    out = tmp_path / "rep"
    code = main(
        ["scan", str(FIXTURES / "python"), "--format", "cbom", "--out", str(out),
         "--exclude", "broken_hash.py", "--exclude", "quantum_vulnerable.py", "--quiet"]
    )
    assert code == 0
    doc = json.loads((out / "cbom.json").read_text(encoding="utf-8"))
    names = {c["name"] for c in doc["components"]}
    assert "MD5" not in names and "RSA" not in names
    assert "AES-256" in names


def test_languages_filter(tmp_path):
    out = tmp_path / "rep"
    code = main(
        ["scan", str(FIXTURES), "--format", "cbom", "--out", str(out),
         "--languages", "go", "--quiet"]
    )
    assert code == 0
    doc = json.loads((out / "cbom.json").read_text(encoding="utf-8"))
    locations = {
        occ["location"]
        for c in doc["components"]
        for occ in c["evidence"]["occurrences"]
    }
    assert any(loc.endswith("main.go") for loc in locations)
    assert not any(loc.endswith(".java") for loc in locations)
    # config + dependency detectors stay active regardless of --languages
    assert any(loc.endswith("tls.conf") for loc in locations)


def test_unknown_language_is_usage_error(tmp_path):
    code = main(
        ["scan", str(FIXTURES), "--format", "cbom", "--out", str(tmp_path),
         "--languages", "cobol", "--quiet"]
    )
    assert code == 2


def test_missing_path_is_usage_error(tmp_path):
    assert main(["scan", str(tmp_path / "nope"), "--quiet"]) == 2


def test_malformed_file_warns_but_scan_succeeds(tmp_path, capsys):
    (tmp_path / "bad.py").write_text("def broken(:\n  md5(\n", encoding="utf-8")
    (tmp_path / "good.py").write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    out = tmp_path / "rep"
    code = main(["scan", str(tmp_path), "--format", "cbom", "--out", str(out)])
    assert code == 0
    doc = json.loads((out / "cbom.json").read_text(encoding="utf-8"))
    md5_hits = [c for c in doc["components"] if c["name"] == "MD5"]
    assert md5_hits, "the well-formed file must still be scanned"


def test_rules_list_prints_full_table(capsys):
    assert main(["rules", "list"]) == 0
    out = capsys.readouterr().out
    for name in ("RSA", "ML-KEM", "MD5", "AES-256", "SHA-3", "TLS-1.0"):
        assert name in out
    assert "PQC replacement" in out


@pytest.mark.parametrize("fmt", ["cbom", "html", "sarif"])
def test_single_format_writes_only_that_file(tmp_path, fmt):
    out = tmp_path / "rep"
    code = main(
        ["scan", str(FIXTURES / "python"), "--format", fmt, "--out", str(out), "--quiet"]
    )
    assert code == 0
    written = {p.name for p in out.iterdir()}
    assert written == {{"cbom": "cbom.json", "html": "report.html", "sarif": "findings.sarif"}[fmt]}
