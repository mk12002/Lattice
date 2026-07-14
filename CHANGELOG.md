# Changelog

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
