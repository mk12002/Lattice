# Lattice

**Crypto-agility and post-quantum-readiness scanner.** Lattice statically analyzes a codebase,
produces a Cryptographic Bill of Materials (CBOM), grades every cryptographic usage for quantum
vulnerability and classical weakness, and emits a prioritized migration roadmap toward the NIST
post-quantum standards.

![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)
![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![Runtime deps: 0](https://img.shields.io/badge/runtime%20deps-0-2d7a46)
![Tests](https://img.shields.io/badge/tests-171-2d7a46)
![Security: Bandit](https://img.shields.io/badge/security-bandit%20clean-2d7a46)
![Languages: 12](https://img.shields.io/badge/detectors-12%20languages-8fb4d9)

*New here? Start with the plain-language walkthrough:
[docs/PROJECT_EXPLAINED.md](docs/PROJECT_EXPLAINED.md).*

<p align="center">
  <img src="docs/images/terminal-scan.svg" alt="lattice scan run: 15 findings, P0=5, readiness 56/100, fail-on P0 exits 1" width="760">
</p>

![How a scan works](docs/images/lattice-architecture.svg)

**The post-quantum threat in three sentences.** Adversaries can record encrypted traffic today
and decrypt it once a cryptographically relevant quantum computer exists — *harvest now, decrypt
later*. Shor's algorithm breaks RSA, Diffie-Hellman, and all elliptic-curve cryptography
outright, while Grover's algorithm halves the effective strength of symmetric keys and hashes.
NIST has standardized the replacements — **ML-KEM (FIPS 203)** for key establishment and
**ML-DSA (FIPS 204)** / **SLH-DSA (FIPS 205)** for signatures — and migrating to them starts
with knowing what cryptography you actually have.

## What Lattice does

- **Builds a CBOM** — a CycloneDX-style inventory of every cryptographic asset it can find:
  algorithms in code, certificates and keys on disk, TLS configuration, crypto libraries in
  dependency manifests.
- **Grades each asset twice** — quantum status (Shor-broken / Grover-weakened / safe) and
  classical status (broken / deprecated / secure), then combines them into a migration priority
  (P0–P3) with a one-line justification.
- **Emits three formats** — CBOM JSON for compliance tooling, a self-contained HTML report for
  humans, and SARIF 2.1.0 for CI code-scanning UIs.
- **Gates merges** — `--fail-on P0` exits non-zero when critical findings exist.

Detectors: **Python** (AST-based), **Java/Kotlin/Scala** (JCA strings),
**JavaScript/TypeScript** (node:crypto, WebCrypto), **Go** (import map),
**C/C++** (OpenSSL/mbedTLS/libsodium), **Rust** (RustCrypto/openssl/ring),
**C#/.NET** (System.Security.Cryptography), **Ruby** (OpenSSL + gems),
**PHP** (openssl_*/hash/Sodium), **Swift** (CryptoKit/CommonCrypto),
**config & key material** (PEM/certs/keystores/TLS configs), **dependency manifests**
(requirements.txt, package.json, pom.xml, go.mod, Cargo.toml, and more).

Beyond scanning, Lattice is built for the *lifecycle* of a migration:

- **Accepted risks** (`lattice.toml`): suppress a finding *with a mandatory reason and
  optional expiry* — it stays in the CBOM and the HTML report, marked, but stops tripping CI.
  SARIF output carries standard `suppressions`, so code-scanning UIs handle it natively.
- **Drift detection** (`lattice diff old.json new.json --fail-on-new P0`): because output is
  deterministic, two CBOMs diff meaningfully — CI can block a PR that *introduces* weak
  crypto without failing on pre-existing findings.
- **Policy packs** (`--policy cnsa2|cnsa1|fips140`): evaluate findings against a named
  compliance suite (CNSA 2.0, the pre-quantum CNSA 1.0, or an illustrative FIPS-140
  approved-algorithm set), orthogonally to the severity model.
- **Config in the repo** (`lattice.toml` `[scan]`): set default `exclude`, `languages`,
  `fail_on`, and `max_file_bytes` so CI jobs don't re-pass the same flags.

Lattice is **defensive and offline**: it reads files locally, writes reports locally, makes no
network calls, never attempts to break cryptography, and never writes key material into a
report. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Install

Requires Python 3.11+. Zero runtime dependencies (standard library only — every third-party
package is a supply-chain liability in a security tool). Lattice is not yet published to PyPI,
so install from source:

```bash
git clone https://github.com/mk12002/Lattice && cd Lattice
pip install .        # from the checkout
# or, for development:
pip install -e ".[dev]"
```

> If the `lattice` command isn't found after install, the console-script directory isn't on
> your `PATH`. Either add it, or run the tool as a module — `python -m lattice <args>` is
> equivalent to `lattice <args>`.

## Quickstart

```bash
lattice scan .                         # HTML report to ./lattice-report/report.html
lattice scan . --format all --out out  # CBOM + HTML + SARIF
lattice scan . --fail-on P0            # non-zero exit if anything critical exists
lattice rules list                     # print the full algorithm knowledge base
```

### What a scan looks like

Running Lattice over its own test fixtures:

```text
$ lattice scan tests/fixtures/python --format all --out report --fail-on P0
wrote report/cbom.json
wrote report/report.html
wrote report/findings.sarif
scanned 3 files (0 skipped): 4 findings
priorities: P0=2  P1=0  P2=0  P3=0  none=2
readiness score: 50/100
fail-on gate: 2 finding(s) at or above P0
$ echo $?
1
```

The two P0s: an `hashlib.md5(...)` call (classically broken today) and an RSA-2048 key
generation (quantum-broken **and** harvest-now-decrypt-later exposed — remediation:
ML-KEM per FIPS 203). The two compliant findings are AES-256-GCM and ChaCha20-Poly1305.
Every finding carries its file, line, matched snippet, confidence, and justification.

### The HTML report

A single self-contained file (works offline, no CDN), with a CISO-readable executive summary,
priority cards, the harvest-now-decrypt-later headline, and a full prioritized findings table.
It renders in both light and dark themes:

| Light | Dark |
|:---:|:---:|
| [![Lattice HTML report, light theme](docs/images/report-light.png)](docs/images/report-light.png) | [![Lattice HTML report, dark theme](docs/images/report-dark.png)](docs/images/report-dark.png) |

*(Screenshots are the top band of a scan over a small demo repo — score, priority breakdown,
HNDL exposure, and the start of the findings table.)*

## CLI reference

```text
lattice scan <path>
    --format {cbom,html,sarif,all}   default: html
    --out DIR                        default: ./lattice-report
    --fail-on {P0,P1,P2,P3}          exit 1 if findings at/above threshold exist
    --exclude GLOB                   repeatable
    --languages LIST                 py,java,js,go,c,rust,csharp,ruby,php,swift
                                     (config+deps always on)
    --policy {cnsa2,cnsa1,fips140}   also gate on a compliance profile
    --max-file-bytes N               per-file size cap (default 1000000)
    --quiet
lattice diff <baseline.json> <current.json>
    [--fail-on-new {P0,P1,P2,P3}]    exit 1 if NEW findings at/above threshold
    [--format {text,json}]           default: text
    [--out FILE]                     write drift report to FILE instead of stdout
lattice rules list
lattice version
```

Scan defaults can also live in a `lattice.toml` `[scan]` table
(`exclude`, `languages`, `fail_on`, `max_file_bytes`); CLI flags override it. The same file
holds accepted-risk entries.

Defaults: respects the scan root's `.gitignore`, skips vendored trees (`node_modules`,
`vendor`, `.venv`, `target`, `dist`, `build`, …), skips binaries, caps file size. A malformed
file never crashes a scan — it is skipped with a warning in the summary.

## Use Lattice in your CI

```yaml
- name: Block quantum-vulnerable and broken crypto
  run: |
    pip install git+https://github.com/mk12002/Lattice   # not yet on PyPI
    lattice scan . --format sarif --out lattice-report --fail-on P0
- uses: github/codeql-action/upload-sarif@v3   # optional: surface in code scanning
  if: always()
  with:
    sarif_file: lattice-report/findings.sarif
```

A turnkey workflow (with a drift-gate option) is in
[docs/examples/github-actions-sarif.yml](docs/examples/github-actions-sarif.yml); a pre-commit
hook is in [docs/examples/.pre-commit-config.yaml](docs/examples/.pre-commit-config.yaml).

## Architecture

Four stages — **walk → detect → assess → emit** — with a strict dependency rule: `detectors`
and `emitters` depend on `core`; `core` depends only on `rules`; `core` never imports a detector
or emitter. That keeps the two things that change most — languages and cryptographic knowledge —
isolated to one file each, so adding a language or algorithm is a local change.

![How a scan works](docs/images/lattice-architecture.svg)

```
src/lattice/
├── core/        models · severity (scoring) · walker · engine · diff · policy · suppress · config
├── rules/       algorithms.py — the cryptographic knowledge base (pure data + lookup)
├── detectors/   base + registry + one module per language, config, dependencies
├── emitters/    cbom (CycloneDX) · sarif · html
└── cli.py       argparse CLI (scan / diff / rules / version)
```

A deeper walkthrough is in [docs/PROJECT_EXPLAINED.md](docs/PROJECT_EXPLAINED.md).

## Python API

Everything the CLI does is available as a library — `scan()` returns a pure `CBOM` value (no
I/O, no exit code), which you can inspect or feed to an emitter:

```python
from pathlib import Path
from lattice.core.engine import scan
from lattice.core.severity import readiness_score
from lattice.detectors.registry import all_detectors
from lattice.emitters import cbom_emitter

cbom = scan(Path("myrepo"), all_detectors())
print(readiness_score(cbom.findings), "/100")
for f in cbom.sorted_findings():
    print(f.assessment.priority.value, f.asset.algorithm, f.asset.file_path, f.asset.line_number)

Path("cbom.json").write_text(cbom_emitter.emit(cbom))   # CycloneDX CBOM
```

Runnable examples are in [examples/](examples/).

## How scoring works (transparently)

Two orthogonal grades per asset, from a reviewed knowledge base
(`src/lattice/rules/algorithms.py` — inspect it with `lattice rules list`):

| Condition | Priority |
|---|---|
| Classically broken today (MD5, SHA-1, DES, RC4) or broken usage (ECB) | **P0** |
| Quantum-broken **with** HNDL exposure (RSA/DH/ECDH key establishment) | **P0** |
| Quantum-broken signatures (ECDSA, EdDSA, DSA, RSA-as-signature) | **P1** |
| Deprecated (3DES, Blowfish, TLS 1.0/1.1) or Grover-weakened ciphers/KDFs (AES-128, PBKDF2) | **P2** |
| Grover-weakened hashes, usable today (SHA-256) | **P3** |
| Quantum-resistant and classically secure (AES-256-GCM, ChaCha20, ML-KEM, SHA-3…) | none |

Precedence: broken-today outranks broken-later; HNDL raises quantum-broken key establishment
to P0 because captured ciphertext keeps its value, while a recorded signature mostly cannot be
retro-forged. The HNDL rule is a *heuristic about usage families* — it cannot see what data a
specific call protects.

The **readiness score** shown in reports is `100 × (1 − severity-weighted share of findings)`
with weights P0=1.0, P1=0.6, P2=0.3, P3=0.1. It summarizes the composition of what Lattice
could see; it is not a probability of compromise.

## Benchmarks

Numbers from real runs (see [docs/ACCURACY_NOTES.md](docs/ACCURACY_NOTES.md) for methodology
and hand-verification). These are honest measurements, not marketing figures.

| Target | Result |
|---|---|
| CPython standard library (~5,800 files) | scanned in ~72 s, 173 findings, zero crashes |
| `FiloSottile/age` (Go) | 30 findings, readiness 62/100 — correctly finds ChaCha20-Poly1305 on quantum-broken X25519 |
| `paramiko` (Python SSH) | 43 findings, readiness 54/100 — ECDH/ECDSA/RSA, SHA-1 host hashing, MD5 fingerprints |
| `auth0/node-jsonwebtoken` (JS) | 25 findings, readiness 26/100 — RSA ×11, ECDSA ×7 |
| Java detector, 6,000 crypto calls in one file | linear-time (regression-tested < 5 s) |

Determinism: two scans of the same tree produce byte-identical output modulo one timestamp
(regression-tested). Runtime memory is bounded by a per-file size cap.

## Extending Lattice

Adding a language is one class implementing `lattice.detectors.base.Detector`
(`applies_to` + `detect`), one fixture directory, and one test. Adding an algorithm is one
entry in the knowledge base plus its synonyms and a truth-table row. Both are walked through in
[CONTRIBUTING.md](CONTRIBUTING.md). For how Lattice compares to CBOMkit, Semgrep,
CodeQL, and TLS scanners, see [docs/COMPARISON.md](docs/COMPARISON.md).

## Roadmap

Versioned, demand-driven; the full ranked list (with what's blocked and why) is in
[docs/GAPS.md](docs/GAPS.md).

- **Now (v0.4.x):** src-layout package, 12 languages, `lattice.toml [scan]` config,
  CNSA 2.0 / CNSA 1.0 / FIPS-140 policy packs, JSON drift output, MkDocs site.
- **Next:** publish to PyPI (blocked on a maintainer action); deeper WebCrypto/Scala coverage;
  more policy packs (BSI TR-02102, PCI-style).
- **Later:** dataflow from "algorithm used" to "algorithm protects *this* data class" — the
  leap from inventory to per-usage risk.

## Limitations (read this before trusting a report)

- **Static analysis misses dynamically selected algorithms.** `hashlib.new(user_config)`,
  runtime key sizes, and algorithm agility layers are invisible. Absence of findings is not
  evidence of absence of crypto.
- **Regex detectors have false positives.** Java, JavaScript, C/C++, and config detection are
  pattern-based; matches in dead code, comments-adjacent strings, or test suites are reported
  at the file:line where they occur. Every finding carries an honest confidence level
  (`high`/`medium`/`low`) — low-confidence findings deserve manual verification.
- **A CBOM is an inventory, not a proof of correct usage.** AES-256-GCM with a reused nonce is
  compliant in this report and broken in practice. Lattice grades *what* is used, not *how
  well*.
- **Scanning crypto libraries flags their own internals.** A repo that implements or tests TLS
  will legitimately match SSLv3/TLS 1.0 constants (see
  [docs/ACCURACY_NOTES.md](docs/ACCURACY_NOTES.md) for the CPython-stdlib audit); use
  `--exclude` for test trees when that is noise.
- **Key sizes are often undeterminable.** AES with a runtime key is reported conservatively as
  bare `AES` (treated as <256-bit) with a note saying why.
- **Dependency findings prove presence, not use.** Manifests map to inventory components with
  priority *none* and the note "usage not confirmed by a call site".
- **`.gitignore` support is a subset** (literal names, `*` globs, directory patterns from the
  scan root; no negations, no nested files).

A full, ranked account of open gaps and roadmap items is in [docs/GAPS.md](docs/GAPS.md).

## Security

Lattice reads potentially hostile source trees, so its own hardening matters. It makes **no
network calls**, executes nothing (files are parsed, never imported), skips symlinks so a
planted link can't exfiltrate files from outside the scan root, caps per-file size, and never
writes key material into a report. The code is scanned with **Bandit** (SAST) and **pip-audit**
in CI, and the untrusted-input surfaces (symlinks, malformed CBOMs, pathological files, the DER
parser) have dedicated regression tests in `tests/test_security.py`. Full policy, threat model,
and how to report a vulnerability: [SECURITY.md](SECURITY.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Contributing

Contributions are welcome — adding a language detector or a policy pack is a bounded, one-file
change. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
Changelog: [CHANGELOG.md](CHANGELOG.md).

## Citation

If you use Lattice in research or tooling, please cite it via [CITATION.cff](CITATION.cff)
(GitHub renders a "Cite this repository" button), or:

> Lattice contributors. *Lattice: a crypto-agility and post-quantum-readiness scanner.*
> https://github.com/mk12002/Lattice

## License

Apache-2.0 — see [LICENSE](LICENSE). The patent grant matters for security tooling adopted
inside companies.
