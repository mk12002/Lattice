"""CBOM drift detection (lattice diff) and policy-pack evaluation."""

from __future__ import annotations

import json
from pathlib import Path

from lattice.cli import main
from lattice.core.diff import diff, render_text
from lattice.core.engine import scan
from lattice.core.models import Priority
from lattice.core.policy import CNSA2
from lattice.detectors.registry import all_detectors
from lattice.emitters import cbom_emitter

FIXTURES = Path(__file__).parent / "fixtures"

BROKEN_PY = "import hashlib\nhashlib.md5(b'x')\n"
SAFE_PY = (
    "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
    "aes = AESGCM(AESGCM.generate_key(bit_length=256))\n"
)


def _emit_cbom(tmp_path: Path, name: str, sources: dict[str, str]) -> Path:
    repo = tmp_path / name
    repo.mkdir()
    for filename, source in sources.items():
        (repo / filename).write_text(source, encoding="utf-8")
    cbom = scan(repo, all_detectors())
    out = tmp_path / f"{name}.json"
    out.write_text(cbom_emitter.emit(cbom), encoding="utf-8")
    return out


def test_diff_reports_new_and_resolved(tmp_path):
    baseline = _emit_cbom(tmp_path, "baseline", {"app.py": SAFE_PY})
    current = _emit_cbom(tmp_path, "current", {"app.py": SAFE_PY, "new.py": BROKEN_PY})
    result = diff(baseline, current)
    assert result.resolved == []
    new_algorithms = {key[0] for key, _ in result.new}
    assert "MD5" in new_algorithms
    assert result.new_at_or_above(Priority.P0) == 1
    text = render_text(result)
    assert "+ [P0] MD5" in text
    assert "readiness score:" in text


def test_diff_identical_cboms_report_no_drift(tmp_path):
    a = _emit_cbom(tmp_path, "a", {"app.py": SAFE_PY})
    b = _emit_cbom(tmp_path, "b", {"app.py": SAFE_PY})
    result = diff(a, b)
    assert result.new == [] and result.resolved == []
    assert "no cryptographic drift" in render_text(result)


def test_diff_cli_gate(tmp_path):
    baseline = _emit_cbom(tmp_path, "base", {"app.py": SAFE_PY})
    current = _emit_cbom(tmp_path, "cur", {"app.py": SAFE_PY, "bad.py": BROKEN_PY})
    assert main(["diff", str(baseline), str(current)]) == 0  # report only
    assert main(["diff", str(baseline), str(current), "--fail-on-new", "P0"]) == 1
    assert main(["diff", str(current), str(baseline), "--fail-on-new", "P0"]) == 0
    assert main(["diff", str(tmp_path / "missing.json"), str(current)]) == 2


def test_diff_rejects_non_cbom_json(tmp_path):
    bogus = tmp_path / "bogus.json"
    bogus.write_text('{"hello": "world"}', encoding="utf-8")
    other = _emit_cbom(tmp_path, "ok", {"app.py": SAFE_PY})
    assert main(["diff", str(bogus), str(other)]) == 2


def test_cnsa2_policy_flags_non_suite_algorithms(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "mixed.py").write_text(BROKEN_PY + SAFE_PY, encoding="utf-8")
    cbom = scan(repo, all_detectors())
    violations = CNSA2.evaluate(cbom.sorted_findings())
    names = {v.finding.asset.algorithm for v in violations}
    assert "MD5" in names
    assert "AES-256" not in names  # in the suite


def test_cnsa2_policy_ignores_inventory_and_accepted(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("pycrypto==2.6.1\n", encoding="utf-8")
    (repo / "legacy.py").write_text(BROKEN_PY, encoding="utf-8")
    (repo / "lattice.toml").write_text(
        '[[accept]]\nalgorithm = "MD5"\nreason = "accepted for policy test"\n',
        encoding="utf-8",
    )
    cbom = scan(repo, all_detectors())
    violations = CNSA2.evaluate(cbom.sorted_findings())
    assert violations == []  # library inventory + accepted finding both out of scope


def test_policy_cli_exit_code(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "bad.py").write_text(BROKEN_PY, encoding="utf-8")
    out = tmp_path / "rep"
    code = main(
        ["scan", str(repo), "--format", "cbom", "--out", str(out), "--policy", "cnsa2", "--quiet"]
    )
    assert code == 1

    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "good.py").write_text(SAFE_PY, encoding="utf-8")
    code = main(
        ["scan", str(clean), "--format", "cbom", "--out", str(out), "--policy", "cnsa2", "--quiet"]
    )
    assert code == 0


def test_scan_output_remains_deterministic_with_new_features(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(BROKEN_PY + SAFE_PY, encoding="utf-8")
    (repo / "lattice.toml").write_text(
        '[[accept]]\nalgorithm = "MD5"\nreason = "determinism check"\n', encoding="utf-8"
    )
    first = scan(repo, all_detectors())
    second = scan(repo, all_detectors())
    a = cbom_emitter.emit(first).replace(first.generated_at, "T")
    b = cbom_emitter.emit(second).replace(second.generated_at, "T")
    assert a == b


def test_chacha20_is_outside_cnsa2_but_compliant_generally(tmp_path):
    """CHACHA20 is quantum-safe (priority none) yet not in the CNSA 2.0 suite —
    the policy layer is orthogonal to the severity model, by design."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305\n"
        "c = ChaCha20Poly1305(ChaCha20Poly1305.generate_key())\n",
        encoding="utf-8",
    )
    cbom = scan(repo, all_detectors())
    assert cbom.findings[0].assessment.priority == Priority.NONE
    violations = CNSA2.evaluate(cbom.sorted_findings())
    assert {v.finding.asset.algorithm for v in violations} == {"CHACHA20"}


def test_diff_render_is_deterministic(tmp_path):
    baseline = _emit_cbom(tmp_path, "d1", {"app.py": SAFE_PY})
    current = _emit_cbom(tmp_path, "d2", {"app.py": BROKEN_PY + SAFE_PY})
    assert render_text(diff(baseline, current)) == render_text(diff(baseline, current))


def test_cbom_top_level_accepted_count(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(BROKEN_PY, encoding="utf-8")
    (repo / "lattice.toml").write_text(
        '[[accept]]\nalgorithm = "MD5"\nreason = "count check"\n', encoding="utf-8"
    )
    cbom = scan(repo, all_detectors())
    doc = json.loads(cbom_emitter.emit(cbom))
    props = {p["name"]: p["value"] for p in doc["properties"]}
    assert props["lattice:accepted"] == "1"
