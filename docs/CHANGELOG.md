# Changelog

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
