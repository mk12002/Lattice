# LATTICE — Detailed Phased Execution Plan

*A complete, phase-by-phase build plan for the Lattice crypto-agility & post-quantum-readiness scanner. Every phase has objectives, concrete tasks, deliverables, an acceptance gate, and its risks. Appendices carry the hard technical detail (algorithm table, detection patterns, scoring math, output schemas, test matrix, CI). Do not advance past a phase until its gate passes.*

---

## 0. How To Use This Plan

**Dual execution modes.** This plan works two ways:
- **Fable staged runs** — hand Fable one phase at a time (Phases 1–8 map to self-contained build tasks). Higher control, easier review, catches drift early. Recommended for the first build.
- **Fable one-shot** — hand it `LATTICE_BUILD_SPEC.md` and let it build Phases 1–8 in a single run. Faster; review the whole output against the gates afterward.

Either way, **you** own the phase gates. A gate is a hard stop: the listed criteria must be demonstrably true before the next phase starts. A failed gate sends you back inside the current phase, never forward.

**The spine-first discipline.** Phases 1–2 build the load-bearing core (data models + cryptographic knowledge base) and prove the entire pipeline on a single language before any fan-out. Everything after is addition, not invention. If the spine is wrong, nothing downstream can be right — so the spine gets disproportionate care.

**Estimates are ranges, not promises.** Times assume one focused engineer already fluent in Python. Fable-assisted, collapse them hard — but the *review* time is yours and doesn't compress. Treat estimates as relative effort signals.

---

## Guiding Principles (apply in every phase)

1. **Correctness before cleverness.** A scanner that misclassifies crypto is worse than useless — it creates false assurance. Accuracy of the knowledge base and scoring is the top priority; performance and polish come after.
2. **Every finding is traceable** to a matched pattern at a real file:line. No inferred or probabilistic "this project uses crypto" findings.
3. **Honest confidence, honest limits.** AST match = high; regex in a dynamic language = medium/low. The tool and its docs state what it cannot see.
4. **No fabricated security data — ever.** Cryptographic facts (RSA↔Shor, MD5 broken) are legitimate knowledge. Invented CVEs, CVSS scores, vendor advisories, or statistics are not. Omit what you can't ground.
5. **Deterministic output.** Same input → byte-identical output (modulo one top-level timestamp). This is what makes Lattice usable in CI diffs.
6. **Defensive only.** Reads locally, writes reports locally, no network, no exploit generation, never emits secret material.

---

## Phase 0 — Foundations & Decisions

**Objective:** lock every decision that would be expensive to reverse later, and stand up an empty-but-correct project skeleton. No detection logic yet.

**Tasks**
- Create the repository; choose and add the license (**Apache-2.0** recommended — patent grant matters for a security tool adopted by companies).
- Initialize `pyproject.toml` with project metadata, Python `>=3.11`, and the console entry point `lattice = "lattice.cli:main"`.
- Lock the dependency philosophy: **standard library first.** Permit only a minimal, justified set (e.g., `rich` for CLI tables is optional; a SARIF/JSON schema validator is dev-only). Every third-party dep is a supply-chain liability in a security tool — justify each in the README.
- Decide the canonical algorithm naming scheme (uppercase canonical name + a synonym map). This choice propagates everywhere; settle it now. (See Appendix A.)
- Create the full directory skeleton (empty modules with docstrings) matching the architecture in the build spec.
- Set up dev tooling: formatter (`black`), linter (`ruff`), type checker (`mypy`), test runner (`pytest`), coverage.
- Write a one-paragraph `VISION.md`: what Lattice is, who it's for (security engineers, platform teams, CISOs facing PQC-migration mandates), and the explicit **non-goals** (not a CSPM, not a SAST-for-injection tool, not a crypto-correctness prover).

**Deliverables:** installable empty package (`pip install -e .` succeeds; `lattice version` prints), locked decisions, tooling configured.

**Gate 0:** `pip install -e .` works; `lattice version` runs; `pytest` runs (zero tests, zero failures); linter/type-checker pass on the skeleton; license and VISION committed.

**Risks:** over-choosing dependencies now (mitigate: default to stdlib); bikeshedding the naming scheme (mitigate: decide, record in Appendix A, move on).

---

## Phase 1 — The Spine: Core Models, Knowledge Base, Scoring

**Objective:** build the three files everything else depends on, fully tested, with zero detectors or emitters yet. This is the highest-care phase.

**Tasks**

*1a. `core/models.py`* — define the shared data structures as typed, immutable-where-possible dataclasses:
- `CryptoAsset`: canonical_algorithm, family, parameters (key_size, curve, mode — all optional), file_path, line_number, snippet (redacted), detector_name, confidence (enum: HIGH/MEDIUM/LOW).
- `Assessment`: quantum_status, classical_status, hndl_relevant (bool), migration_priority (enum P0–P3), pqc_replacement, justification (str).
- `Finding`: a `CryptoAsset` + its `Assessment`.
- `CBOM`: metadata (tool version, single generatedAt) + ordered list of `Finding` + summary counts.
- Define stable sort keys on `Finding` (priority, then path, then line) so output ordering is deterministic.

*1b. `rules/algorithms.py`* — the cryptographic knowledge base (see **Appendix A** for the required entries). Pure data + a `lookup(name) -> AlgorithmInfo | None` that resolves synonyms. Each entry: family, quantum_status, classical_status, pqc_replacement, notes. This file encodes the tool's entire cryptographic judgment — review it against a second source before locking.

*1c. `core/severity.py`* — the scoring model (see **Appendix C** for the truth table it must satisfy):
- `quantum_risk(info)`, `classical_risk(info)`, `hndl_relevant(family)` → the HNDL heuristic.
- `migration_priority(asset, info) -> (priority, justification)` — deterministic function combining the above.
- The `readiness_score(findings) -> int 0..100` used in the report, with a transparent, documented formula (not a black box).

**Deliverables:** three spine files + their tests.

**Tests (must exist to pass the gate):**
- `algorithms.py`: assert lookup resolves every canonical name and every synonym; assert no entry has contradictory fields (e.g., quantum_status `safe` with a pqc_replacement set).
- `severity.py`: assert the full truth table in Appendix C — every (algorithm → expected priority) pair.
- `models.py`: assert sort determinism (shuffle a list of findings, sort, assert stable order).

**Gate 1:** truth-table test passes 100%; knowledge base reviewed against an independent reference for correctness; determinism test passes. **No detector or emitter code exists yet** — resist the urge.

**Risks:** subtle crypto errors in the table (mitigate: independent review, this is the one place a mistake is unacceptable); over-engineering the scoring (mitigate: the truth table is the spec — satisfy it simply).

---

## Phase 2 — Walking Skeleton: One Language, End-to-End

**Objective:** prove the *entire* pipeline — discover file → detect → assess → emit — on **Python only**, with a minimal CBOM emitter. This is the riskiest integration; do it on one language before building five more detectors against an unproven pipeline.

**Tasks**
- `detectors/base.py`: the `Detector` ABC — `applies_to(path) -> bool` and `detect(path, content) -> Iterable[CryptoAsset]`.
- `detectors/python_det.py`: AST-based. Parse with `ast`; walk for imports of `cryptography`, `hashlib`, `hmac`, `ssl`, `pycryptodome`; match calls to algorithms; extract key size / mode / curve where present in the call. Regex fallback for string-configured algorithms, marked lower confidence. (See **Appendix B**.)
- `core/walker.py` (minimal): recurse a path, yield files, respect `.gitignore`, skip binaries, apply a per-file size cap.
- `core/engine.py` (minimal): walker → route to applicable detectors → collect assets → run severity → assemble `CBOM`.
- `emitters/cbom_emitter.py` (minimal but schema-correct): emit CycloneDX-style CBOM JSON (see **Appendix D**).
- `cli.py` (minimal): `lattice scan <path> --format cbom`.
- Fixture: `tests/fixtures/python/` with three files — one broken (MD5), one quantum-vulnerable (RSA key-gen), one safe (AES-256-GCM) — each with a known-answer comment.

**Deliverables:** a runnable tool that scans the Python fixture and emits a correct CBOM.

**Gate 2 (the critical gate):** `lattice scan tests/fixtures/python --format cbom` finds exactly the three known assets, classifies each correctly (MD5→classical-broken/P-high; RSA→quantum-broken + HNDL→P0; AES-256-GCM→safe/none), at correct confidence, and the CBOM is valid and deterministic across two runs. If this gate passes, the architecture is proven and fan-out is safe.

**Risks:** AST edge cases (aliased imports, `from x import y as z`) — the fixture must include these; pipeline coupling discovered late — that's exactly why this phase exists.

---

## Phase 3 — Detector Fan-Out

**Objective:** add the remaining detectors against the now-proven pipeline. Each is independent; build and test one at a time.

**Tasks (one sub-cycle each — build detector, add fixture, test, gate-check):**
- `java_det.py`: regex/token scan for `Cipher.getInstance`, `MessageDigest.getInstance`, `KeyPairGenerator/Signature.getInstance`, JCA strings; **parse transformation strings** like `"AES/ECB/PKCS5Padding"` → AES + ECB mode → flag ECB as broken-usage. BouncyCastle awareness.
- `javascript_det.py`: `crypto.createCipheriv/createHash/createSign`, WebCrypto `subtle` algorithm params, `forge`/`jsrsasign` imports. Handle TS too.
- `go_det.py`: imports under `crypto/*` and `golang.org/x/crypto/*` → map package to algorithm.
- `c_cpp_det.py`: OpenSSL/libcrypto EVP identifiers, mbedTLS, libsodium calls.
- `config_det.py`: `.pem/.key/.crt/.p12` detection; parse certs/TLS config for signature + key-exchange algorithm and key size; flag TLS < 1.2 and weak cipher suites; **detect but never store or print** apparent private-key material — report location and type only.
- `dependency_det.py`: parse `requirements.txt`, `pom.xml`, `package.json`, `go.mod`, `Cargo.toml` for known crypto libraries; register as CBOM components even without a matched call.

Each detector ships with a `tests/fixtures/<lang>/` set (broken / quantum-vulnerable / safe) and a test asserting exact detections + classifications + confidence.

**Deliverables:** six additional detectors, each fixture-tested.

**Gate 3:** every detector passes its fixture test; running Lattice across the whole `tests/fixtures/` tree yields the complete known-answer set with no missed known assets and no classification errors. False positives are acceptable *if* correctly marked low-confidence; false negatives on the fixtures are not.

**Risks:** regex false positives in dynamic languages (mitigate: confidence marking + a documented FP philosophy); config parsing brittleness (mitigate: keep it conservative — report only what parses cleanly).

---

## Phase 4 — Emitters: HTML + SARIF, and CBOM Hardening

**Objective:** complete the three output formats to production quality.

**Tasks**
- `html_emitter.py` (see **Appendix E**): a single self-contained file — inline CSS, **no external fetch, no CDN**. Sections: executive summary (total assets, counts by priority, headline HNDL exposure, readiness score with its formula explained), prioritized findings table, per-language breakdown, full findings list with file:line + remediation guidance ("replace RSA-2048 key exchange with ML-KEM per FIPS 203"). CISO-readable. Zero fabricated numbers.
- `sarif_emitter.py`: SARIF 2.1.0 — tool driver with rules, results with level + physical location (file + region), message. Validates against the SARIF schema shape.
- Harden `cbom_emitter.py`: full CycloneDX cryptographic-asset component properties, assessment section, deterministic ordering.
- `--format all` writes all three; `--out DIR` controls destination.

**Deliverables:** three complete emitters.

**Gate 4:** HTML opens and renders with the network disabled and reads well to a non-engineer; SARIF validates and locates findings at file:line; CBOM is valid CycloneDX-style and deterministic; `--format all` produces all three consistently (same findings, same counts across formats).

**Risks:** HTML report overstating certainty (mitigate: surface confidence in the table, caveat low-confidence findings visibly); SARIF schema drift (mitigate: validate in a test).

---

## Phase 5 — Orchestration, CLI, and CI Gating

**Objective:** finish the CLI contract and make Lattice CI-ready.

**Tasks (full CLI in Appendix F):**
- `lattice scan` full flag set: `--format`, `--out`, `--fail-on P0|P1|P2|P3`, `--exclude GLOB` (repeatable), `--languages`, `--quiet`.
- `--fail-on`: exit non-zero when any finding at/above the threshold exists — the merge-blocking gate.
- `lattice rules list`: print the knowledge base as a table (transparency + a selling point).
- Defaults: scan cwd, HTML to `./lattice-report/`, respect `.gitignore`, skip vendored trees (`node_modules`, `vendor`, `.venv`, `target`, `dist`), file-size cap, binary skip.
- Robust error handling: unreadable file → warn and continue, never crash a whole scan on one bad file; unparseable source → fall back to regex, mark low confidence.
- Performance pass: ensure a mid-size repo scans in reasonable time; the walker, not detection, is usually the bottleneck — profile before optimizing.

**Deliverables:** complete, robust CLI.

**Gate 5:** `--fail-on P0` returns non-zero with a P0 present and zero without; `--exclude` and `--languages` filter correctly; a deliberately malformed file produces a warning, not a crash; `lattice rules list` prints the full table.

**Risks:** silent scan failures (mitigate: explicit warn-and-continue with a summary of skipped files); scope creep into full SAST (mitigate: the non-goals in VISION.md are the fence).

---

## Phase 6 — Testing, Hardening, Determinism

**Objective:** raise confidence from "passes fixtures" to "trustworthy on real code."

**Tasks**
- Coverage: meaningfully cover `core/` and `rules/` (the correctness-critical modules); reasonable coverage elsewhere.
- Determinism test: scan twice, assert byte-identical output modulo the single timestamp — for all three formats.
- Edge-case fixtures: empty file, huge file (hits the cap), binary masquerading as text, deeply nested dirs, symlink loops, non-UTF-8 encoding, a file with **both** safe and broken crypto, a "clean" repo (only quantum-safe crypto → high readiness score).
- False-positive tuning pass: run Lattice on 3–5 **real** public repositories; manually audit a sample of findings; adjust regex breadth and confidence levels based on real behavior. Record the FP characteristics honestly in the docs.
- Fuzz the config/cert parser with malformed inputs — it must degrade gracefully.

**Deliverables:** hardened tool + expanded test suite + a short internal "accuracy notes" record from the real-repo audit.

**Gate 6:** full suite green; determinism holds across all formats; real-repo runs complete without crashes; the clean-repo fixture scores high and the vulnerable fixtures score low, as expected.

**Risks:** over-tuning to the specific test repos (mitigate: audit variety, keep the knowledge base as the source of truth, not per-repo hacks).

---

## Phase 7 — Packaging & CI/CD

**Objective:** make it trivially installable and self-verifying (Appendix H).

**Tasks**
- Finalize `pyproject.toml` for build/distribution; verify a clean install in a fresh virtualenv.
- GitHub Actions workflow: matrix over Python versions → install → `ruff` → `mypy` → `pytest` with coverage → **run Lattice on its own fixtures** and assert expected exit codes (dogfooding).
- Add a release workflow (tag → build → optionally publish to PyPI). PyPI is optional for v1; a tagged GitHub release with install-from-source instructions is enough to start.
- Add a `lattice`-as-a-CI-step example (a snippet others can copy to gate their own repos).

**Deliverables:** green CI, reproducible install, release process.

**Gate 7:** CI passes on a clean checkout; fresh-venv install works; a tagged release is produced; the "use Lattice in your CI" snippet works when copy-pasted.

**Risks:** environment-specific install bugs (mitigate: the fresh-venv test); CI that doesn't actually run the tool (mitigate: the dogfooding step is mandatory).

---

## Phase 8 — Documentation

**Objective:** documentation good enough that a stranger adopts it and a contributor extends it without asking you.

**Tasks**
- `README.md`: the PQC threat in three sentences (harvest-now-decrypt-later; Shor breaks RSA/ECC; NIST FIPS 203/204/205 are the replacements); install; quickstart; a real sample-output walkthrough; the extension pointer; and an explicit, honest **Limitations** section (static analysis misses runtime-selected algorithms; regex detectors have false positives; a CBOM is an inventory, not a proof of correct usage; dynamic languages are harder than compiled ones).
- `CONTRIBUTING.md`: how to add a language detector against `base.Detector`, how to add an algorithm to the knowledge base, how to add a fixture. Make the detector interface the extension seam.
- Inline docstrings on every public function; the algorithm table commented with per-entry rationale.
- A short `THREAT_MODEL.md` for Lattice itself (it reads source and secrets locations — document what it does and doesn't do with that data; reaffirm no-network, no-secret-emission).

**Deliverables:** complete docs.

**Gate 8:** a person who has never seen the project can install, run, and interpret a report using only the README; a contributor can add a trivial detector using only CONTRIBUTING.md; Limitations is present and unflinching.

**Risks:** overselling in the README (mitigate: the Limitations section is load-bearing — write it first, honestly).

---

## Phase 9 — Launch & Proof-of-Work

**Objective:** convert the tool into public credibility — the real point of building it.

**Tasks**
- Run Lattice on several well-known public repos; capture clean, honest results (redact anything sensitive; report responsibly if you find something genuinely serious — coordinate disclosure, never publish an exploit).
- Write a launch post (LinkedIn + a longer blog/GitHub README section): the PQC-migration problem, what a CBOM is, what Lattice does, a real sample report, and — critically — its honest limitations. Proof-of-work over proclamation. Lead with the problem and the artifact, not adjectives.
- Ship a tagged v0.1.0 release with a crisp changelog.
- Optional: a 90-second demo (asciinema/GIF) of a scan producing a report.
- Invite contribution: good first issues (add a detector for language X, add algorithm Y).

**Deliverables:** public release + launch content + demo.

**Gate 9:** repo is public, installable, documented; the launch post links a reproducible run; at least one "good first issue" is filed.

**Risks:** irresponsible disclosure if you find real weaknesses in a scanned public project (mitigate: coordinated disclosure, no exploit publication — this is a hard rule); overclaiming novelty (mitigate: acknowledge prior art like existing CBOM tooling honestly — position on usability/PQC-focus, not on being first).

---

## Phase 10 — Post-Launch Roadmap (optional, demand-driven)

Pursue only what real usage justifies:
- **Git-history HNDL analysis:** flag long-lived data paths — the highest-value HNDL signal.
- **More languages:** Rust, C#, PHP, Ruby (each a clean `Detector` addition).
- **Deeper dataflow:** move from "algorithm is used" to "algorithm protects *this* data class" — the leap from inventory to risk.
- **Policy packs:** encode CNSA 2.0 / sector-specific migration deadlines as pass/fail policies.
- **VEX-style suppression:** let teams accept-and-annotate specific findings so CI stays green intentionally.
- **IDE/pre-commit hooks:** shift-left the scan.

Each roadmap item = its own mini-cycle (spine already exists; add a detector or a policy, fixture-test, gate, ship).

---

## Master Risk Register

| Risk | Phase | Severity | Mitigation |
|---|---|---|---|
| Cryptographic misclassification in the knowledge base | 1 | Critical | Independent review before Gate 1; the table is the one place errors are unacceptable |
| Pipeline coupling discovered after fan-out | 2 | High | Walking skeleton proves integration on one language first |
| Regex false positives eroding trust | 3,6 | Medium | Confidence marking + real-repo tuning + documented FP philosophy |
| Secret material leaking into reports | 3,4 | Critical | Detect-location-only rule; never store/print key bytes; test for it |
| HTML report overstating certainty | 4,8 | Medium | Surface confidence; caveat low-confidence findings; honest Limitations |
| Scope creep into general SAST | 5 | Medium | VISION.md non-goals as the fence |
| Irresponsible disclosure at launch | 9 | High | Coordinated disclosure; never publish exploits |
| Overclaiming vs existing CBOM tools | 9 | Low | Acknowledge prior art; position on PQC focus + usability |

---

## Master Definition of Done (v1)

- [ ] Clean-venv `pip install` → `lattice scan <repo>` produces CBOM + HTML + SARIF.
- [ ] All six language detectors + config + dependency detectors pass their fixture tests.
- [ ] Knowledge base independently reviewed; scoring truth table 100% green.
- [ ] Output deterministic across runs in all three formats.
- [ ] `--fail-on` gates correctly; malformed input never crashes a scan.
- [ ] No fabricated CVEs/scores/stats anywhere; no network calls; no secret material emitted.
- [ ] CI green and dogfoods Lattice on its own fixtures.
- [ ] README (with honest Limitations), CONTRIBUTING, THREAT_MODEL complete.
- [ ] Public tagged release + launch post linking a reproducible run.

---

# Appendix A — Cryptographic Knowledge Base (required entries)

Each row: **canonical name** — family — quantum_status — classical_status — pqc_replacement. Synonyms in parentheses resolve to the canonical name.

**Asymmetric / key-exchange / signatures (quantum-BROKEN — Shor):**
- RSA (rsaEncryption, PKCS1) — asymmetric-cipher/signature — broken — secure(classically, at ≥2048) — ML-KEM for encryption, ML-DSA for signatures
- DH / Diffie-Hellman — key-exchange — broken — secure — ML-KEM
- ECDH (X25519, X448, ECDH-P256) — key-exchange — broken — secure — ML-KEM
- ECDSA (secp256r1, prime256v1, secp384r1, P-256/P-384) — signature — broken — secure — ML-DSA / SLH-DSA
- EdDSA (Ed25519, Ed448) — signature — broken — secure — ML-DSA / SLH-DSA
- DSA — signature — broken — deprecated — ML-DSA
- ElGamal — asymmetric-cipher — broken — deprecated — ML-KEM

**Post-quantum (SAFE — the migration targets):**
- ML-KEM (Kyber, Kyber512/768/1024, FIPS 203) — key-exchange — safe — secure — (is the target)
- ML-DSA (Dilithium, FIPS 204) — signature — safe — secure — (is the target)
- SLH-DSA (SPHINCS+, FIPS 205) — signature — safe — secure — (is the target)
- Falcon — signature — safe — secure — (standardization ongoing; note as such)

**Symmetric ciphers (Grover — WEAKENED at small sizes):**
- AES-256 — symmetric-cipher — safe — secure — (increase not needed)
- AES-128 / AES-192 — symmetric-cipher — weakened — secure — move to AES-256
- ChaCha20 / ChaCha20-Poly1305 — symmetric-cipher — safe(256-bit) — secure — —
- 3DES (TripleDES, DESede) — symmetric-cipher — weakened — deprecated — AES-256
- DES — symmetric-cipher — weakened — broken — AES-256
- RC4 (ARC4) — symmetric-cipher — n/a — broken — AES-256-GCM
- Blowfish — symmetric-cipher — weakened — deprecated — AES-256

**Mode-of-operation flags (usage-level, not algorithms):**
- ECB (any cipher) — flag as **broken-usage** regardless of cipher — recommend GCM/CTR/CBC-with-MAC
- CBC without authentication — flag as weak-usage — recommend AEAD (GCM/ChaCha20-Poly1305)

**Hashes (Grover — WEAKENED; collisions — BROKEN):**
- SHA-256 / SHA-384 / SHA-512 — hash — weakened(safe in practice; SHA-384+ preferred post-quantum) — secure — SHA-384+/SHA-3
- SHA-1 — hash — n/a — broken — SHA-256+
- MD5 — hash — n/a — broken — SHA-256+
- SHA-3 family / SHAKE — hash — safe — secure — —
- BLAKE2 / BLAKE3 — hash — safe — secure — —

**KDF / password hashing / MAC:**
- Argon2 (argon2id) — kdf — safe — secure — —
- scrypt — kdf — safe — secure — —
- bcrypt — kdf — safe — secure(with adequate cost) — —
- PBKDF2 — kdf — weakened — secure(with high iterations) — increase iterations / Argon2
- HMAC — mac — safe(depends on hash) — secure — —

*Consistency rule to test: an entry with quantum_status `safe` and classical_status `secure` must not carry a pqc_replacement (it is already a target).*

---

# Appendix B — Detection Pattern Cheat-Sheet

**Python (AST — high confidence):** import resolution for `cryptography.hazmat`, `Crypto` (pycryptodome), `hashlib`, `hmac`, `ssl`. Match: `hashlib.md5(`, `hashlib.new("md5")`, `rsa.generate_private_key(`, `ec.generate_private_key(ec.SECP256R1())`, `Cipher(algorithms.AES(...), modes.ECB())`, `serialization.load_pem_private_key`. Extract key_size / curve / mode from call arguments. Regex fallback (medium/low) for algorithm names inside strings.

**Java (regex/token — medium):** `Cipher.getInstance("AES/ECB/PKCS5Padding")` → parse the transformation into algorithm+mode+padding; `MessageDigest.getInstance("MD5")`; `KeyPairGenerator.getInstance("RSA")`; `Signature.getInstance("SHA256withECDSA")`; BouncyCastle `org.bouncycastle.*` imports.

**JavaScript/TS (regex — medium):** `crypto.createHash("sha1")`, `crypto.createCipheriv("aes-128-ecb", ...)` → parse the `aes-128-ecb` triple; WebCrypto `subtle.encrypt({name:"RSA-OAEP"}, ...)`; `forge.*`, `jsrsasign` imports.

**Go (import-map — high):** `crypto/md5`, `crypto/rsa`, `crypto/ecdsa`, `crypto/aes` + mode from `cipher.NewCBCEncrypter`/`NewGCM`; `golang.org/x/crypto/...`.

**C/C++ (regex — medium):** OpenSSL `EVP_sha1`, `EVP_aes_128_ecb`, `RSA_generate_key`, `EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)`; mbedTLS `mbedtls_*`; libsodium `crypto_*`.

**Config/material (parse — medium):** `.pem/.key/.crt/.p12` by header/extension; X.509 signature algorithm + public-key algorithm + key size; TLS config min-version and cipher-suite lists. Private-key material → record path + type only; **never** read/store/print the key bytes.

**Dependencies (parse — high for presence, low for usage):** map known crypto libraries in manifests to CBOM components; mark as "present, usage not confirmed by call-site."

---

# Appendix C — Scoring Truth Table (severity.py must satisfy)

| Algorithm / usage | quantum | classical | HNDL? | Priority | Rationale |
|---|---|---|---|---|---|
| RSA key exchange / encryption | broken | secure | yes | **P0** | Captured ciphertext decryptable post-quantum |
| ECDH / DH key exchange | broken | secure | yes | **P0** | Same HNDL exposure |
| ECDSA / EdDSA signature | broken | secure | no | **P1** | Breaks post-quantum but no HNDL capture value |
| RSA/DSA signature | broken | deprecated(DSA)/secure(RSA) | no | **P1** | Migrate before quantum, lower urgency than HNDL |
| MD5 / SHA-1 | n/a | broken | — | **P0** | Broken *today*, independent of quantum |
| DES / RC4 | weakened/n-a | broken | — | **P0** | Broken today |
| AES-ECB (any) | — | broken-usage | — | **P0** | Structural weakness today |
| 3DES / Blowfish | weakened | deprecated | — | **P2** | Deprecated; plan migration |
| AES-128 | weakened | secure | — | **P2** | Grover-weakened; move to 256 |
| PBKDF2 (low iterations) | weakened | secure* | — | **P2** | Strengthen params |
| AES-256-GCM / ChaCha20-Poly1305 | safe | secure | — | **None** | Compliant |
| ML-KEM / ML-DSA / SLH-DSA | safe | secure | — | **None** | Already a target |
| SHA-256 | weakened | secure | — | **P3** | Usable; prefer SHA-384+ long-term |

*Priority precedence when both apply: classical-broken outranks quantum-broken (broken today > broken later); HNDL raises a quantum-broken asset to P0.*

---

# Appendix D — CBOM JSON Skeleton (CycloneDX-style)

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "timestamp": "<single generatedAt>",
    "tools": [{ "name": "Lattice", "version": "<v>" }]
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "RSA",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "pke",
          "parameterSetIdentifier": "2048",
          "classicalSecurityLevel": 112,
          "nistQuantumSecurityLevel": 0
        }
      },
      "evidence": { "occurrences": [{ "location": "src/auth.py", "line": 42 }] },
      "properties": [
        { "name": "lattice:quantumStatus", "value": "broken" },
        { "name": "lattice:classicalStatus", "value": "secure" },
        { "name": "lattice:hndl", "value": "true" },
        { "name": "lattice:priority", "value": "P0" },
        { "name": "lattice:confidence", "value": "high" },
        { "name": "lattice:pqcReplacement", "value": "ML-KEM (FIPS 203)" }
      ]
    }
  ],
  "properties": [
    { "name": "lattice:readinessScore", "value": "62" },
    { "name": "lattice:summary", "value": "P0=3 P1=5 P2=2 P3=1 none=14" }
  ]
}
```

Ordering: components sorted by (priority, path, line). Only `metadata.timestamp` varies between runs.

---

# Appendix E — HTML Report Structure

1. **Header:** target path, scan time, Lattice version.
2. **Executive summary band:** readiness score (0–100, big) with a one-line explanation of the formula; counts by priority (P0–P3 + compliant); headline sentence ("N quantum-vulnerable key-exchange usages create harvest-now-decrypt-later exposure").
3. **Priority table:** each finding — algorithm, file:line, quantum status, classical status, confidence, priority, remediation. Low-confidence rows visibly marked.
4. **Per-language breakdown:** asset counts and worst-priority per language.
5. **Full findings:** grouped by priority, each with the redacted snippet and a concrete remediation string referencing the PQC target by standard name.
6. **Methodology & limitations footer:** how scoring works, what static analysis misses. No fabricated numbers anywhere; every count derives from actual findings.

Single file, inline CSS, no external requests.

---

# Appendix F — CLI Reference

```
lattice scan <path>
    --format {cbom,html,sarif,all}   default: html
    --out DIR                        default: ./lattice-report
    --fail-on {P0,P1,P2,P3}          exit nonzero if findings >= threshold
    --exclude GLOB                   repeatable
    --languages LIST                 e.g. py,java,js,go,c
    --quiet
lattice rules list                   print the knowledge base table
lattice version
```
Default excludes: `node_modules`, `vendor`, `.venv`, `venv`, `target`, `dist`, `build`, `.git`. Respects `.gitignore`. Per-file size cap (configurable). Unreadable/unparseable files → warn, fall back to regex, mark low confidence, continue.

---

# Appendix G — Test Matrix

| Suite | Asserts |
|---|---|
| Knowledge base | every canonical + synonym resolves; no contradictory entries |
| Scoring | full Appendix C truth table |
| Models | deterministic sort under shuffle |
| Per-language detector (×7) | exact known assets, classification, confidence on fixtures |
| Emitters (×3) | schema validity + byte-determinism across two runs |
| Engine/walker | .gitignore respected, excludes applied, size cap enforced, binaries skipped |
| Edge cases | empty/huge/binary/non-UTF-8/nested/symlink-loop/mixed-crypto/clean-repo |
| CLI | `--fail-on` exit codes; `--exclude`/`--languages` filtering; malformed-input resilience |
| Dogfood (CI) | Lattice scans its own fixtures with expected exit code |

---

# Appendix H — GitHub Actions (shape)

```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix: { python: ["3.11", "3.12"] }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "${{ matrix.python }}" }
      - run: pip install -e ".[dev]"
      - run: ruff check .
      - run: mypy lattice
      - run: pytest --cov=lattice --cov-report=term-missing
      - run: lattice scan tests/fixtures --format all --out /tmp/rep --fail-on P0 || test $? -eq 1
```

The final step **dogfoods** Lattice: it must detect the fixtures' P0 findings and exit non-zero, proving the gate works end-to-end in CI.

---

*Build the spine with disproportionate care, prove the pipeline on one language, then fan out. Every phase gate is a real stop. The knowledge base is the product; everything else is delivery.*
