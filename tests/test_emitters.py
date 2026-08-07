"""Gate 4: emitters are schema-shaped, deterministic, consistent, and leak-free."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from lattice.core.engine import scan
from lattice.core.models import Priority
from lattice.detectors.registry import all_detectors
from lattice.emitters import cbom_emitter, html_emitter, sarif_emitter

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def cbom():
    return scan(FIXTURES, all_detectors())


def _rescan():
    return scan(FIXTURES, all_detectors())


def test_sarif_shape(cbom):
    doc = json.loads(sarif_emitter.emit(cbom))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "Lattice"
    assert driver["rules"], "driver must declare rules"
    rule_ids = {r["id"] for r in driver["rules"]}
    assert len(run["results"]) == len(cbom.findings)
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
        assert result["level"] in ("error", "warning", "note", "none")
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"]
        assert location["region"]["startLine"] >= 1
    # a P0 finding must surface as error
    p0 = [r for r in run["results"] if r["properties"]["priority"] == "P0"]
    assert p0 and all(r["level"] == "error" for r in p0)


def test_sarif_fully_deterministic(cbom):
    assert sarif_emitter.emit(cbom) == sarif_emitter.emit(_rescan())


def test_cbom_deterministic_modulo_timestamp(cbom):
    second = _rescan()
    a = cbom_emitter.emit(cbom).replace(cbom.generated_at, "T")
    b = cbom_emitter.emit(second).replace(second.generated_at, "T")
    assert a == b


def test_html_deterministic_modulo_timestamp(cbom):
    second = _rescan()
    a = html_emitter.emit(cbom).replace(cbom.generated_at, "T")
    b = html_emitter.emit(second).replace(second.generated_at, "T")
    assert a == b


def test_html_self_contained_no_external_requests(cbom):
    page = html_emitter.emit(cbom)
    for marker in ("http://", "https://", "src=", "@import", "url("):
        assert marker not in page, f"external reference marker {marker!r} found"
    assert page.startswith("<!DOCTYPE html>")
    assert "<style>" in page  # CSS is inline


def test_html_surfaces_score_confidence_and_limitations(cbom):
    page = html_emitter.emit(cbom)
    assert "Post-quantum readiness score" in page
    assert "severity-weighted share of findings" in page  # formula is explained
    assert "harvest-now-decrypt-later" in page
    assert "limitations" in page.lower()
    assert "confidence" in page.lower()


def test_counts_consistent_across_all_three_formats(cbom):
    p0_count = cbom.priority_counts()[Priority.P0]
    cbom_doc = json.loads(cbom_emitter.emit(cbom))
    cbom_p0 = sum(
        1
        for c in cbom_doc["components"]
        for p in c.get("properties", [])
        if p["name"] == "lattice:priority" and p["value"] == "P0"
    )
    sarif_doc = json.loads(sarif_emitter.emit(cbom))
    sarif_p0 = sum(
        1 for r in sarif_doc["runs"][0]["results"] if r["properties"]["priority"] == "P0"
    )
    page = html_emitter.emit(cbom)
    assert cbom_p0 == p0_count
    assert sarif_p0 == p0_count
    # the HTML P0 card shows the same number
    assert re.search(rf">{p0_count}</div><div class=\"lbl\">P0", page)


def test_no_key_material_in_any_output(cbom):
    """The fake key body from the fixture must never reach any report."""
    key_fragment = "RkFLRSBLRVkg"
    ssh_fragment = "AAAAC3NzaC1lZDI1NTE5"
    for output in (
        cbom_emitter.emit(cbom),
        sarif_emitter.emit(cbom),
        html_emitter.emit(cbom),
    ):
        assert key_fragment not in output
        assert ssh_fragment not in output


def test_html_escapes_content():
    cbom = scan(FIXTURES / "python", all_detectors())
    object.__setattr__(cbom.findings[0].asset, "snippet", "<script>alert(1)</script>")
    page = html_emitter.emit(cbom)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
