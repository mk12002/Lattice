# LATTICE — One-Shot Build Specification

*Paste this entire document into Fable 5 as a single build task. It is written to be executed end-to-end in one sustained agentic run: read it fully, plan once, then build the whole tool. Do not ask for confirmation between components — build the complete system, then report.*

---

## MISSION

Build **Lattice**, a production-quality, open-source **crypto-agility and post-quantum-readiness scanner**. Lattice statically analyzes a target codebase, produces a complete **Cryptographic Bill of Materials (CBOM)**, grades every cryptographic usage for quantum vulnerability and classical weakness, and emits a prioritized migration roadmap toward the NIST post-quantum standards.

The deliverable is a working command-line tool with a clean plugin architecture, a real detection rule set, three output emitters (CBOM JSON, HTML report, SARIF), a test suite with fixtures, CI configuration, and complete documentation. It must run on any machine with the target runtime installed and require no network access to operate.

---

## NON-NEGOTIABLE CONSTRAINTS

1. **No fabricated security data.** Do not invent CVE numbers, CVSS scores, vendor advisories, or statistics. Detection rules encode *cryptographic facts* (e.g., "RSA is broken by Shor's algorithm", "MD5 is collision-broken") which are legitimate. Anything requiring a citation you cannot ground must be omitted, not invented. Where a rule's rationale references a standard, reference it by name only (e.g., "NIST FIPS 203"), never with fabricated section numbers.
2. **Detection over guessing.** Every finding must trace to a concrete matched pattern in a real file at a real line. No heuristic "this project probably uses crypto" findings. If it isn't matched, it isn't reported.
3. **Defensive tool only.** Lattice identifies and helps remediate weak cryptography. It must never generate exploit code, never attempt to break cryptography, and never exfiltrate scanned source. It reads files locally and writes reports locally. Nothing else.
4. **No false confidence.** Every finding carries a `confidence` field (high/medium/low). Regex-based matches in dynamic languages are inherently uncertain — mark them honestly. An HTML report that overstates certainty is a defect.
5. **Deterministic.** Same input → identical output (stable ordering, no timestamps inside the CBOM body except a single top-level `generatedAt`). This makes output diffable in CI.

---

## TARGET LANGUAGE & STACK

Build Lattice in **Python 3.11+** (broad reach, excellent for static analysis, trivial for others to install and extend). Use only well-established libraries; keep the dependency list minimal. Package it properly (`pyproject.toml`, console entry point `lattice`). No heavyweight frameworks.

---

## ARCHITECTURE

Enforce a clean separation so the tool is extensible without touching the core. Design deep modules with narrow interfaces.

```
lattice/
  core/
    models.py          # Finding, CryptoAsset, CBOM dataclasses; the shared spine
    severity.py        # Quantum-vulnerability + classical-weakness scoring model
    engine.py          # Orchestrates: walk files -> run detectors -> collect assets
    walker.py          # File discovery, language routing, .gitignore respect, size caps
  detectors/
    base.py            # Detector ABC: given file content, yield CryptoAssets
    python_det.py      # AST-aware where possible, regex fallback
    java_det.py
    javascript_det.py
    go_det.py
    c_cpp_det.py
    config_det.py      # TLS configs, OpenSSL configs, certs, .pem/.key material
    dependency_det.py  # crypto libraries in requirements/pom/package.json/go.mod
  rules/
    algorithms.py      # The knowledge base: algorithm -> {family, quantum_status, classical_status, pqc_replacement}
  emitters/
    cbom_emitter.py    # CycloneDX-style CBOM JSON
    html_emitter.py    # Self-contained exec report (inline CSS, no external assets)
    sarif_emitter.py   # SARIF 2.1.0 for CI / code scanning
  cli.py               # argparse entry point
tests/
  fixtures/            # Small real code samples per language, each with known crypto
  test_*.py
```

**Dependency direction:** `detectors` and `emitters` depend on `core`; `core` depends on nothing internal. `rules/algorithms.py` is pure data + lookup, depended on by detectors and severity. Never let core import a detector or emitter.

---

## THE CRYPTOGRAPHIC KNOWLEDGE BASE (`rules/algorithms.py`)

This is the heart of the tool. Build a structured table keyed by canonical algorithm name. Each entry carries:

- `family`: symmetric-cipher / asymmetric-cipher / signature / key-exchange / hash / kdf / mac / rng
- `quantum_status`: one of
  - `broken` — Shor's algorithm defeats it (RSA, DSA, DH, ECDSA, ECDH, ElGamal, ECC generally)
  - `weakened` — Grover's algorithm halves effective strength; needs larger parameters (AES-128 → weakened, AES-256 → acceptable; SHA-256 → weakened-but-usable)
  - `safe` — believed quantum-resistant (ML-KEM, ML-DSA, SLH-DSA, and symmetric ciphers at ≥256-bit)
  - `n/a`
- `classical_status`: secure / deprecated / broken (MD5 broken, SHA-1 broken, DES broken, RC4 broken, 3DES deprecated, ECB-mode broken-usage)
- `pqc_replacement`: the migration target where applicable — key exchange → **ML-KEM (FIPS 203)**; signatures → **ML-DSA (FIPS 204)** or **SLH-DSA (FIPS 205)**; symmetric → increase to 256-bit; hash → move to SHA-384/SHA-512 or SHA-3
- `notes`: short factual rationale, no citations invented

Cover, at minimum: RSA, DSA, DH, ECDH, ECDSA, EdDSA/Ed25519, ElGamal, AES (128/192/256 + mode awareness: ECB/CBC/GCM/CTR), 3DES, DES, RC4, ChaCha20/ChaCha20-Poly1305, Blowfish, MD5, SHA-1, SHA-2 family, SHA-3, BLAKE2/3, HMAC, PBKDF2, bcrypt, scrypt, Argon2, and the PQC set (ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA/SPHINCS+, Falcon). Include common library-specific aliases as lookup synonyms (e.g., `Rijndael` → AES, `secp256r1`/`prime256v1` → ECDSA-P256).

---

## DETECTION STRATEGY (per detector)

- **Python:** parse with the `ast` module; resolve imports of `cryptography`, `pycryptodome`, `hashlib`, `ssl`, `hmac`; match constructor/function calls to algorithms; fall back to regex only for string-configured algorithms. AST matches → `high` confidence; regex → `medium`/`low`.
- **Java:** regex/token scan for `Cipher.getInstance("...")`, `MessageDigest.getInstance`, `KeyPairGenerator.getInstance`, `Signature.getInstance`, JCA algorithm strings, BouncyCastle usage. Parse the algorithm string (e.g., `"AES/ECB/PKCS5Padding"` → AES + ECB mode → flag ECB).
- **JavaScript/TypeScript:** match `crypto.createCipheriv`, `createHash`, `createSign`, subtle-crypto `algorithm` params, and library imports (node:crypto, forge, jsrsasign).
- **Go:** match imports under `crypto/*` and `golang.org/x/crypto/*`; map package to algorithm.
- **C/C++:** match OpenSSL/libcrypto/mbedTLS/libsodium API calls and EVP algorithm identifiers.
- **Config/material:** detect `.pem`, `.key`, `.crt`, `.p12`; parse certificate/TLS config to extract signature & key-exchange algorithms and key sizes; flag TLS < 1.2, weak cipher suites, and detect (but never store or print) apparent private-key material — report only location and type.
- **Dependencies:** parse `requirements.txt`, `pom.xml`, `package.json`, `go.mod`, `Cargo.toml` for known crypto libraries; note them as CBOM components even if no direct call is matched.

Extract, per asset: algorithm, parameters (key size, curve, mode) where determinable, file path, line number, surrounding snippet (redacted of any secret material), confidence.

---

## SCORING MODEL (`core/severity.py`)

Compute two orthogonal grades per asset, then a combined priority:

1. **Quantum risk:** `broken` → Critical, `weakened` → Medium, `safe`/`n/a` → None.
2. **Classical risk:** `broken` → Critical, `deprecated` → High, `secure` → None.
3. **Harvest-Now-Decrypt-Later (HNDL) multiplier:** raise priority when a quantum-`broken` asset protects *data in transit or long-lived data at rest* (heuristic: key-exchange and asymmetric-encryption families score higher HNDL than ephemeral signing, because captured ciphertext is decryptable later while signatures mostly are not). Document the heuristic honestly as a heuristic.

Combined **migration priority** = deterministic function of the above → P0/P1/P2/P3, with a one-line justification string attached to each finding.

---

## OUTPUT EMITTERS

1. **CBOM JSON** (`--format cbom`): follow the **CycloneDX** structure with a `components` array of `cryptographic-asset` type entries, each carrying algorithm properties, and a `vulnerabilities`/`assessment` section for quantum & classical status. Deterministic ordering. This is the machine-readable compliance artifact.
2. **HTML report** (`--format html`): a single self-contained file (inline CSS, no external fetches, no CDN). Executive summary at top: total assets, count by priority, the headline HNDL exposure, and a "readiness score" (0–100, transparently computed and explained). Then a prioritized table, then per-language breakdown, then the full findings list with file:line and remediation guidance ("replace RSA-2048 key exchange with ML-KEM per FIPS 203"). Design it to be readable by a CISO, not just an engineer. No fabricated benchmark numbers anywhere.
3. **SARIF 2.1.0** (`--format sarif`): each finding as a result with rule id, level, location (physical: file + region), and message. This lets Lattice run in CI and surface findings in code-scanning UIs.

CLI supports `--format all` and an `--fail-on <priority>` gate (exit non-zero if findings at/above the threshold exist) so teams can block merges.

---

## CLI CONTRACT

```
lattice scan <path> [--format cbom|html|sarif|all] [--out DIR]
                    [--fail-on P0|P1|P2|P3] [--exclude GLOB]...
                    [--languages py,java,js,go,c] [--quiet]
lattice rules list          # print the algorithm knowledge base as a table
lattice version
```

Sensible defaults: scan current dir, emit HTML to `./lattice-report/`, respect `.gitignore`, cap individual file size, skip binaries and vendored dependency trees by default.

---

## TESTING (build this, don't skip it)

- For **each language**, create a small fixture file under `tests/fixtures/` containing *known* crypto usage (a broken one, a quantum-vulnerable one, a safe one) and assert the detector finds exactly those, with correct classification and confidence.
- Unit-test the scoring model against a truth table of (algorithm → expected priority).
- Test each emitter produces schema-valid, deterministic output (run twice, assert byte-identical modulo the single top-level timestamp).
- Include one "clean" fixture with only quantum-safe crypto and assert a high readiness score.
- Target meaningful coverage of `core/` and `rules/`; these are the correctness-critical modules.

---

## DOCUMENTATION

- `README.md`: what it is, the PQC threat in three sentences (harvest-now-decrypt-later, Shor, the NIST standards), install, quickstart, sample output screenshot-in-words, extension guide (how to add a detector or a rule), and an explicit **Limitations** section (static analysis misses dynamically-selected algorithms; regex detectors have false positives; a CBOM is an inventory, not a proof of correct usage). State limits plainly — do not oversell.
- `CONTRIBUTING.md`: how to add a language detector against the `base.Detector` interface.
- Inline docstrings on every public function; the rule table commented with rationale.
- MIT or Apache-2.0 license file.

---

## BUILD ORDER (execute in one run, in this sequence)

1. Scaffold package + `pyproject.toml` + entry point.
2. `core/models.py` and `rules/algorithms.py` — the spine and the knowledge base first; everything else references them.
3. `core/severity.py` + its truth-table test.
4. `detectors/base.py`, then the Python detector (AST) end-to-end with its fixture test — prove the full pipeline on one language before fanning out.
5. Remaining detectors, each with a fixture test.
6. The three emitters, each with a determinism test.
7. `core/walker.py`, `core/engine.py`, `cli.py` — wire it together.
8. CI config (GitHub Actions: install, lint, test, run Lattice on its own fixtures).
9. README + docs.
10. Final self-check against the acceptance criteria below; report results honestly, including anything not fully met.

---

## ACCEPTANCE CRITERIA (verify before declaring done)

- [ ] `pip install -e .` then `lattice scan tests/fixtures` runs clean and produces all three output formats.
- [ ] Every fixture's known crypto is detected with correct quantum/classical classification and honest confidence.
- [ ] CBOM output is valid CycloneDX-style JSON and deterministic across runs.
- [ ] HTML report renders standalone (open with no network) and is CISO-readable.
- [ ] SARIF validates against the 2.1.0 schema shape and locates findings at file:line.
- [ ] `--fail-on P0` returns non-zero when a P0 finding exists, zero otherwise.
- [ ] No fabricated CVEs, scores, or statistics anywhere in code, rules, or docs.
- [ ] No exploit generation, no network calls, no secret material written to any output.
- [ ] Test suite passes; core and rules meaningfully covered.
- [ ] README Limitations section is present and honest.

Build the complete system now. When finished, output a short manifest of what was created, the acceptance-criteria results (marking any gaps truthfully rather than claiming false completion), and the exact commands to install and run it.
