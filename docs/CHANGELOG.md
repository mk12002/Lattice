# Changelog

## v0.2.1 — 2026-07-19 (security hardening)

- **Symlinks are no longer followed.** A file symlink planted in a scanned tree could
  previously be read (and redacted fragments quoted) even if it pointed outside the scan
  root; such files are now skipped with a warning. Directory symlinks were already excluded.
- **`lattice diff` hardened against hostile CBOMs.** The loader now totalizes over
  malformed-but-valid JSON (non-list `components`, non-dict entries, wrong-typed `evidence`)
  instead of raising, so a crafted file can't crash the drift gate.
- **Quadratic line-counting removed.** Whole-document regex detectors use a new O(log n)
  `LineIndex` (bisect over precomputed newline offsets) instead of counting newlines per
  match — a file crafted with thousands of matches stays linear.
- **CLI validation**: `--max-file-bytes` must be positive (a negative value silently skipped
  every file).
- **SECURITY.md** with the threat model, hardening table, and disclosure policy; **Bandit**
  (SAST) and **pip-audit** added to CI and the `dev` extras; B105 skipped project-wide with a
  documented rationale (algorithm-name literals are not secrets).
- New `tests/test_security.py` (symlink exfiltration, malformed-CBOM fuzzing, linear-time
  Java detection, CLI validation, end-to-end secret-leak checks).
- README: status badges, real HTML-report screenshots (light + dark), and a styled terminal
  SVG; `docs/PROJECT_EXPLAINED.md` gains a report screenshot.
- 153 tests (151 pass, 2 Windows-skipped); ruff, mypy, and Bandit all clean.

## v0.2.0 — 2026-07-14

- **Rust detector**: RustCrypto crates, the `openssl` crate (`Cipher::aes_128_ecb`,
  `Rsa::generate`), and `ring` tokens — the first CBOM scanner coverage for Rust that we
  know of among open-source tools.
- **C#/.NET detector**: `System.Security.Cryptography` factories, AEAD types,
  `Rfc2898DeriveBytes`, file-level `CipherMode` binding, BouncyCastle.NET awareness.
- **Accepted risks** (`lattice.toml`): suppress findings with a mandatory reason and
  optional expiry. Accepted findings stay in all reports, are excluded from the score and
  gates, and surface as standard SARIF `suppressions`.
- **`lattice diff`**: compare two CBOMs and report cryptographic drift;
  `--fail-on-new P0` blocks PRs that introduce weak crypto without failing on
  pre-existing findings.
- **Policy packs**: `--policy cnsa2` evaluates findings against the CNSA 2.0 algorithm
  suite (orthogonal to the severity model; caveats stated in output).
- **HTML report**: dark-mode support (token-based palette via `prefers-color-scheme`),
  accepted-risks section.
- Knowledge base: SSL-2.0 and RC2 entries; fixed SSLv2 being reported as SSL-3.0.
- Fixes: `createSign('sha256')` no longer grades a digest as a signature; Apache
  `SSLProtocol +TLSv1` enable-tokens are now detected.
- 138 tests, ruff + mypy clean.

## v0.1.0 — 2026-07-14

Initial release.

- Cryptographic knowledge base: 40+ canonical algorithms with quantum status (Shor/Grover),
  classical status, and NIST PQC migration targets (FIPS 203/204/205); 100+ synonyms.
- Detectors: Python (AST), Java/Kotlin (JCA), JavaScript/TypeScript (node:crypto + WebCrypto),
  Go (import map), C/C++ (OpenSSL/mbedTLS/libsodium), config & key material (PEM/X.509
  signature OIDs/SSH keys/keystores/nginx-Apache-OpenSSL TLS directives), dependency
  manifests (pip, npm, Maven, Gradle, Go modules, Cargo).
- Scoring: P0–P3 migration priorities with harvest-now-decrypt-later weighting, per-finding
  justifications, transparent 0–100 readiness score.
- Emitters: CycloneDX-style CBOM JSON, self-contained HTML report, SARIF 2.1.0. All
  deterministic modulo one timestamp.
- CLI: `scan` (with `--fail-on` CI gate, `--exclude`, `--languages`), `rules list`, `version`.
- 113 tests including a scoring truth table, per-detector known-answer fixtures, determinism
  and secret-leak guards, and DER/config fuzzing.
