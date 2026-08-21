# Tool paper outline (honest framing)

> **Read this first.** Lattice's contribution is *engineering*, not a novel detection
> science, and it has real prior art (IBM/PQCA CBOMkit). So the right academic vehicle is
> a **tool / experience / systematization paper** at a workshop — *not* a novelty claim at
> a top-tier venue, and *not* a repost of a blog to arXiv. Reviewers reward honest
> positioning and reproducibility; they punish overclaiming. If you only have energy for
> one paper across your projects, an adversarial-benchmark project (e.g. an ML-malware
> scanner) is the stronger novelty candidate; Lattice's ceiling is a solid tool paper.
> This outline is optional — the DOI'd release + docs site may be sufficient.

## Suggested title

*Lattice: A Zero-Dependency, Prioritized Cryptographic Bill of Materials Generator for
Multi-Language Codebases*

## Target venues (workshop / tool track)

- IEEE S&P / USENIX / ACM CCS **poster or workshop** tracks
- SCORED (Software Supply Chain) or a PQC-migration workshop
- Journal alternative: a tool report (e.g. *SoftwareX*) — fits a well-engineered artifact

## Abstract (draft skeleton)

Post-quantum migration begins with an inventory, yet cryptography is scattered across
code, configuration, certificates, and dependencies in many languages. We present Lattice,
an open-source scanner that produces a CycloneDX-style Cryptographic Bill of Materials,
grades each usage on two axes (Shor-broken vs. Grover-weakened; classically broken vs.
secure), and combines them with a harvest-now-decrypt-later heuristic into P0–P3 migration
priorities. Lattice covers 12 languages plus configuration and dependency manifests with
zero runtime dependencies, deterministic output, and a CI-native lifecycle (merge gate,
CBOM drift diff, compliance policy packs). We report its detection approach, honest
confidence model, and measurements on real repositories, and position it against prior
CBOM tooling.

## Section plan

1. **Introduction** — the PQC migration problem; "you can't migrate what you can't find";
   contributions (engineering, honestly scoped).
2. **Background** — HNDL threat; Shor vs. Grover; NIST FIPS 203/204/205; CBOM/SBOM;
   CycloneDX.
3. **Related work / prior art** — CBOMkit (PQCA/IBM), Semgrep/CodeQL crypto rules, TLS
   scanners. *Explicitly credit prior art; state what is and isn't novel.*
4. **Design** — pipeline (walk → detect → assess → emit); dependency-direction rule; the
   four constraints (determinism, stdlib-only, honest confidence, no-secret-emission).
5. **Detection methodology** — AST (Python), import-map (Go), regex (others); the
   confidence hierarchy tied to technique; a hand-written defensive DER parser.
6. **Scoring model** — the truth-table decision procedure; usage-context override
   (key-exchange vs. signature); mode-aware grading (ECB); transparent readiness score.
7. **Lifecycle** — accepted-risk file, CBOM drift diff, policy packs (CNSA 2.0/1.0,
   FIPS-140).
8. **Evaluation** — real-repo runs (age, paramiko, node-jsonwebtoken, CPython stdlib);
   determinism; linear-time behavior; the `benchmarks/` harness for reproducibility.
9. **Honest limitations & biases** — static-analysis blind spots; regex false positives;
   documented conservative biases (bare-RSA→P0). *A candid limitations section is a
   strength in a tool paper.*
10. **Responsible use** — defensive-only; coordinated disclosure; never emits secrets.
11. **Conclusion & availability** — DOI'd release, Apache-2.0, reproducible.

## Artifact-evaluation checklist (most of it already exists)

- [x] Public source, permissive license (Apache-2.0)
- [x] Deterministic, reproducible output (tested)
- [x] Benchmark harness (`benchmarks/run.py`)
- [x] Documented methodology (`docs/`)
- [ ] DOI'd release (see `docs/ZENODO.md`)
- [ ] Camera-ready manuscript (this outline → full draft)

*What NOT to do:* do not paste a blog into arXiv; do not claim to be the first CBOM tool;
do not report benchmark numbers you can't reproduce with the harness.
