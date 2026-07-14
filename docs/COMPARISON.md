# How Lattice compares to existing tools

Honest positioning, not marketing. Lattice has real prior art — the CBOM concept itself
comes from IBM's work now stewarded by the Post-Quantum Cryptography Alliance — and it also
has real differences. Claims below are grounded in each project's public documentation as of
July 2026; none of these tools were benchmarked head-to-head (CBOMkit requires SonarQube +
service infrastructure we did not replicate).

## The landscape

| | **Lattice** | **CBOMkit / sonar-cryptography** (PQCA, ex-IBM) | **Semgrep / CodeQL crypto rules** | **testssl.sh / sslyze** |
|---|---|---|---|---|
| What it is | Standalone CLI CBOM scanner + prioritizer | SonarQube plugin + repo-scanning service + container scanner (cbomkit-theia) | General SAST engines with community crypto rules | Network-side TLS endpoint scanners |
| Languages | Python (AST), Java, JS/TS, Go, C/C++, Rust, C#, configs/PEM/X.509, 6 manifest formats | Java and Python source (plugin); container filesystems (theia) | Many languages, rule-dependent depth | None (network protocol only) |
| Infrastructure needed | `pip install`, zero runtime deps, offline | SonarQube server; service variant adds a database + frontend | CLI (Semgrep) / CodeQL DB build | CLI |
| Output | CycloneDX-style CBOM + self-contained HTML + SARIF, deterministic | CycloneDX CBOM with precise locations | SARIF/JSON findings (no CBOM inventory) | Text/JSON endpoint reports |
| PQC judgment | P0–P3 migration priorities with HNDL weighting + per-finding justification | Whitelist-based quantum-safe compliance check (compliant / not) | None built in (rules flag patterns, no PQC model) | Flags weak protocol/cipher config |
| Migration lifecycle | Accepted-risk file with mandatory reasons + expiry; CBOM drift diff gate; CNSA 2.0 policy pack | Compliance service; no acceptance/drift workflow documented | Semgrep has generic ignore comments | N/A |
| Honesty features | Per-finding confidence, "inventory ≠ proof" framing, conservative-bias docs | Location evidence | Rule-dependent | Protocol-level facts |

## Where Lattice is genuinely different

1. **Prioritization instead of a binary verdict.** A whitelist check answers "is this
   quantum-safe: yes/no." A migration team needs *ordering*: harvest-now-decrypt-later
   key exchange before signatures, broken-today before broken-later. Lattice's P0–P3 +
   HNDL model is the scheduling input, with the reasoning attached to every finding.
2. **Zero infrastructure.** No server, no database, no language-analysis backend — one
   `pip install`, stdlib-only, runs offline. The cost of *starting* a crypto inventory
   drops to one command.
3. **Determinism as a product feature.** Byte-identical output (modulo one timestamp)
   makes CBOMs diffable, which is what makes `lattice diff --fail-on-new P0` possible:
   block PRs that introduce weak crypto without failing on pre-existing debt.
4. **The acceptance workflow.** Real codebases have MD5-as-cache-key. A suppression that
   deletes the finding corrupts the inventory; Lattice acceptances require a reason,
   support expiry, stay visible in every report, and emit standard SARIF suppressions.
5. **Breadth per unit of setup.** Rust and C# coverage in particular — the incumbent CBOM
   scanner covers Java and Python source.

## Where the alternatives are stronger — use them when this matters

- **sonar-cryptography's Java/Python analysis is deeper** than Lattice's regex-based Java
  detector: it resolves more API surface with a real language backend. If you live in
  SonarQube and only need Java/Python, it is the more precise choice.
- **cbomkit-theia scans container images**; Lattice scans source trees. Different layer —
  they compose.
- **CodeQL/Semgrep** can express *usage-correctness* queries (nonce reuse, static IVs)
  that are outside Lattice's inventory scope by design.
- **testssl.sh/sslyze** see the *negotiated* TLS reality of a live endpoint, which no
  static scanner can.

A serious PQC program would plausibly use Lattice for the fast, prioritized, CI-gated
source inventory and layer the others where their depth applies.

*Sources: [github.com/cbomkit/cbomkit](https://github.com/cbomkit/cbomkit),
[github.com/cbomkit/sonar-cryptography](https://github.com/cbomkit/sonar-cryptography),
[PQCA CBOMkit announcement](https://pqca.org/blog/2025/pqca-announces-cbomkit-advanced-tools-for-generating-and-analyzing-cryptographic-bills-of-materials/),
[IBM Research on CBOMkit](https://research.ibm.com/blog/quantum-safe-cbomkit).*
