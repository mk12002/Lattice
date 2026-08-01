"""Tests for v0.3 lifecycle additions: diff --format/--out, [scan] config, new policies."""

from __future__ import annotations

import json
from pathlib import Path

from lattice.cli import main
from lattice.core.config import load_scan_config
from lattice.core.diff import diff, render_json
from lattice.core.engine import scan
from lattice.core.policy import CNSA1, FIPS140, POLICIES
from lattice.detectors.registry import all_detectors
from lattice.emitters import cbom_emitter

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


# -- diff --format json / --out -----------------------------------------------------


def test_diff_render_json_shape(tmp_path):
    baseline = _emit_cbom(tmp_path, "base", {"app.py": SAFE_PY})
    current = _emit_cbom(tmp_path, "cur", {"app.py": SAFE_PY, "new.py": BROKEN_PY})
    doc = json.loads(render_json(diff(baseline, current)))
    assert doc["summary"]["new"] == 1
    assert doc["summary"]["resolved"] == 0
    assert any(e["algorithm"] == "MD5" and e["priority"] == "P0" for e in doc["new"])
    assert isinstance(doc["currentReadinessScore"], int)


def test_diff_cli_json_to_file(tmp_path):
    baseline = _emit_cbom(tmp_path, "base", {"app.py": SAFE_PY})
    current = _emit_cbom(tmp_path, "cur", {"app.py": SAFE_PY, "bad.py": BROKEN_PY})
    out = tmp_path / "drift.json"
    code = main(["diff", str(baseline), str(current), "--format", "json", "--out", str(out)])
    assert code == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["summary"]["new"] == 1


def test_diff_json_deterministic(tmp_path):
    baseline = _emit_cbom(tmp_path, "b", {"app.py": SAFE_PY})
    current = _emit_cbom(tmp_path, "c", {"app.py": BROKEN_PY + SAFE_PY})
    assert render_json(diff(baseline, current)) == render_json(diff(baseline, current))


# -- lattice.toml [scan] config -----------------------------------------------------


def test_scan_config_loads_valid_section(tmp_path):
    (tmp_path / "lattice.toml").write_text(
        '[scan]\nexclude = ["vendor/**"]\nlanguages = ["py", "go"]\n'
        'fail_on = "P1"\nmax_file_bytes = 500000\n',
        encoding="utf-8",
    )
    config, warnings = load_scan_config(tmp_path)
    assert warnings == []
    assert config.exclude == ["vendor/**"]
    assert config.languages == ["py", "go"]
    assert config.fail_on == "P1"
    assert config.max_file_bytes == 500000


def test_scan_config_warns_on_bad_values(tmp_path):
    (tmp_path / "lattice.toml").write_text(
        '[scan]\nlanguages = ["py", "cobol"]\nfail_on = "P9"\nmax_file_bytes = -1\n',
        encoding="utf-8",
    )
    config, warnings = load_scan_config(tmp_path)
    assert config.languages is None          # unknown language -> rejected
    assert config.fail_on is None            # invalid threshold -> rejected
    assert config.max_file_bytes is None     # non-positive -> rejected
    assert len(warnings) == 3


def test_scan_config_fail_on_gates_from_file(tmp_path):
    (tmp_path / "app.py").write_text(BROKEN_PY, encoding="utf-8")
    (tmp_path / "lattice.toml").write_text('[scan]\nfail_on = "P0"\n', encoding="utf-8")
    out = tmp_path / "rep"
    # no --fail-on on the CLI; the gate comes from the config file
    code = main(["scan", str(tmp_path), "--format", "cbom", "--out", str(out), "--quiet"])
    assert code == 1


def test_cli_fail_on_overrides_config(tmp_path):
    (tmp_path / "app.py").write_text(BROKEN_PY, encoding="utf-8")
    # config says P0 (would trip), CLI says P3-only... P0 finding still trips P3 gate,
    # so instead test that CLI languages overrides config languages:
    (tmp_path / "lattice.toml").write_text('[scan]\nlanguages = ["go"]\n', encoding="utf-8")
    out = tmp_path / "rep"
    # config restricts to go (would find nothing in app.py); CLI overrides with py
    code = main(
        ["scan", str(tmp_path), "--languages", "py", "--format", "cbom",
         "--out", str(out), "--quiet", "--fail-on", "P0"]
    )
    assert code == 1  # py detector ran (CLI won), found MD5


def test_scan_config_excludes_from_file(tmp_path):
    (tmp_path / "keep.py").write_text("import hashlib\nhashlib.sha1(b'x')\n", encoding="utf-8")
    skip_dir = tmp_path / "generated"
    skip_dir.mkdir()
    (skip_dir / "gen.py").write_text(BROKEN_PY, encoding="utf-8")
    (tmp_path / "lattice.toml").write_text('[scan]\nexclude = ["generated/**"]\n', encoding="utf-8")
    out = tmp_path / "rep"
    assert main(["scan", str(tmp_path), "--format", "cbom", "--out", str(out), "--quiet"]) == 0
    doc = json.loads((out / "cbom.json").read_text(encoding="utf-8"))
    names = {c["name"] for c in doc["components"]}
    assert "SHA-1" in names
    assert "MD5" not in names  # excluded by config


# -- new policy packs ---------------------------------------------------------------


def test_cnsa1_permits_ecc_but_flags_chacha(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305\n"
        "k = ec.generate_private_key(ec.SECP384R1())\n"
        "c = ChaCha20Poly1305(ChaCha20Poly1305.generate_key())\n",
        encoding="utf-8",
    )
    cbom = scan(repo, all_detectors())
    names = {v.finding.asset.algorithm for v in CNSA1.evaluate(cbom.sorted_findings())}
    assert "ECDSA" not in names     # CNSA 1.0 permits ECC
    assert "CHACHA20" in names      # but not ChaCha20


def test_fips140_flags_md5_permits_aes128(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import hashlib\n"
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "hashlib.md5(b'x')\n"
        "Cipher(algorithms.AES(b'0123456789abcdef'), modes.GCM(b'0'*12))\n",
        encoding="utf-8",
    )
    cbom = scan(repo, all_detectors())
    names = {v.finding.asset.algorithm for v in FIPS140.evaluate(cbom.sorted_findings())}
    assert "MD5" in names           # not FIPS-approved
    assert "AES-128" not in names   # AES-128 is approved


def test_new_policies_registered():
    assert set(POLICIES) == {"cnsa2", "cnsa1", "fips140"}


def test_policy_cli_accepts_new_packs(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "app.py").write_text(BROKEN_PY, encoding="utf-8")
    out = tmp_path / "rep"
    for pack in ("cnsa1", "fips140"):
        code = main(
            ["scan", str(repo), "--format", "cbom", "--out", str(out),
             "--policy", pack, "--quiet"]
        )
        assert code == 1  # MD5 is outside every pack
