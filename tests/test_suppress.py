"""Acceptance-file (lattice.toml) behavior: visible, gated out, auditable."""

from __future__ import annotations

import datetime as dt
import json

from lattice.cli import main
from lattice.core.engine import scan
from lattice.core.severity import readiness_score
from lattice.core.suppress import load_acceptances
from lattice.detectors.registry import all_detectors

BROKEN_PY = "import hashlib\nhashlib.md5(b'x')\n"


def _write_repo(tmp_path, accept_toml: str | None):
    (tmp_path / "legacy.py").write_text(BROKEN_PY, encoding="utf-8")
    if accept_toml is not None:
        (tmp_path / "lattice.toml").write_text(accept_toml, encoding="utf-8")


def test_acceptance_marks_finding_and_restores_score(tmp_path):
    _write_repo(
        tmp_path,
        '[[accept]]\nalgorithm = "MD5"\nreason = "cache key, not security; TICKET-1"\n',
    )
    cbom = scan(tmp_path, all_detectors())
    assert len(cbom.findings) == 1  # stays in the inventory
    finding = cbom.findings[0]
    assert finding.accepted_reason == "cache key, not security; TICKET-1"
    assert readiness_score(cbom.findings) == 100  # excluded from the score


def test_acceptance_path_glob_scopes_the_accept(tmp_path):
    (tmp_path / "other.py").write_text(BROKEN_PY, encoding="utf-8")
    _write_repo(
        tmp_path,
        '[[accept]]\nalgorithm = "MD5"\npath = "legacy*"\nreason = "scoped accept"\n',
    )
    cbom = scan(tmp_path, all_detectors())
    accepted = {f.asset.file_path: f.accepted_reason is not None for f in cbom.findings}
    assert accepted["legacy.py"] is True
    assert accepted["other.py"] is False


def test_accepted_findings_do_not_trip_fail_on(tmp_path):
    _write_repo(
        tmp_path,
        '[[accept]]\nalgorithm = "md5"\nreason = "synonym also resolves"\n',
    )
    out = tmp_path / "rep"
    code = main(
        ["scan", str(tmp_path), "--format", "cbom", "--out", str(out), "--fail-on", "P0", "--quiet"]
    )
    assert code == 0
    doc = json.loads((out / "cbom.json").read_text(encoding="utf-8"))
    md5 = next(c for c in doc["components"] if c["name"] == "MD5")
    props = {p["name"]: p["value"] for p in md5["properties"]}
    assert props["lattice:accepted"] == "true"
    assert "synonym" in props["lattice:acceptedReason"]


def test_acceptance_without_reason_is_rejected_with_warning(tmp_path):
    _write_repo(tmp_path, '[[accept]]\nalgorithm = "MD5"\n')
    acceptances, warnings = load_acceptances(tmp_path)
    assert acceptances == []
    assert any("no reason" in w for w in warnings)
    cbom = scan(tmp_path, all_detectors())
    assert cbom.findings[0].accepted_reason is None  # still active


def test_expired_acceptance_reactivates_finding(tmp_path):
    _write_repo(
        tmp_path,
        '[[accept]]\nalgorithm = "MD5"\nreason = "was temporary"\nexpires = 2020-01-01\n',
    )
    acceptances, warnings = load_acceptances(tmp_path, today=dt.date(2026, 7, 14))
    assert acceptances == []
    assert any("expired" in w for w in warnings)


def test_future_expiry_still_accepts(tmp_path):
    _write_repo(
        tmp_path,
        '[[accept]]\nalgorithm = "MD5"\nreason = "until migration"\nexpires = 2099-01-01\n',
    )
    acceptances, warnings = load_acceptances(tmp_path, today=dt.date(2026, 7, 14))
    assert len(acceptances) == 1
    assert warnings == []


def test_malformed_toml_warns_and_accepts_nothing(tmp_path):
    _write_repo(tmp_path, "[[accept\nbroken")
    acceptances, warnings = load_acceptances(tmp_path)
    assert acceptances == []
    assert warnings and "unreadable" in warnings[0]


def test_sarif_carries_standard_suppressions(tmp_path):
    _write_repo(
        tmp_path,
        '[[accept]]\nalgorithm = "MD5"\nreason = "tracked in TICKET-9"\n',
    )
    out = tmp_path / "rep"
    assert main(["scan", str(tmp_path), "--format", "sarif", "--out", str(out), "--quiet"]) == 0
    doc = json.loads((out / "findings.sarif").read_text(encoding="utf-8"))
    result = doc["runs"][0]["results"][0]
    assert result["suppressions"][0]["kind"] == "external"
    assert "TICKET-9" in result["suppressions"][0]["justification"]


def test_html_shows_accepted_section(tmp_path):
    _write_repo(
        tmp_path,
        '[[accept]]\nalgorithm = "MD5"\nreason = "documented accepted risk"\n',
    )
    out = tmp_path / "rep"
    assert main(["scan", str(tmp_path), "--format", "html", "--out", str(out), "--quiet"]) == 0
    page = (out / "report.html").read_text(encoding="utf-8")
    assert "Accepted risks" in page
    assert "documented accepted risk" in page
