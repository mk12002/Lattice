# Ecosystem & Community

Where Lattice sits in the post-quantum / software-supply-chain landscape, and the
communities where engagement is most credible. Lattice openly acknowledges prior art;
positioning it honestly among these efforts is more valuable than claiming novelty.

## Standards Lattice already speaks

- **CycloneDX (OWASP)** — Lattice emits a CycloneDX-style CBOM (the `cryptographic-asset`
  component type). CycloneDX is an OWASP flagship project, so this is the most natural
  community: the output format, its evolution, and CBOM tooling are all on-theme.
  Engagement: <https://cyclonedx.org/> · CBOM: <https://cyclonedx.org/capabilities/cbom/>.
- **NIST FIPS 203 / 204 / 205** — the migration targets in the knowledge base
  (`lattice rules list`). Lattice references them by name only, never with invented
  section numbers.
- **NIST SP 1800-38 (NCCoE) — Migration to Post-Quantum Cryptography** — the practical
  program a Lattice CBOM feeds into (discover → prioritize → migrate).

## Communities where a contribution is credible

Retarget the generic "publish another blog / OWASP GenAI" advice: for a *cryptography*
tool, the high-signal communities are the PQC and CBOM ones, not the LLM-security ones.

| Community | Why it fits Lattice | How to engage |
|---|---|---|
| **OWASP CycloneDX** | Lattice produces its CBOM format | Issues/discussions on the spec; feedback on the crypto-asset schema; a CBOM-tooling entry |
| **Post-Quantum Cryptography Alliance (PQCA, Linux Foundation)** | Stewards **CBOMkit** — Lattice's honest prior art (see [COMPARISON.md](COMPARISON.md)) | Compare/contrast constructively; contribute test cases, language coverage, or accuracy findings |
| **NIST NCCoE PQC Migration project** | Real-world migration guidance a CBOM supports | Follow the practice guides; frame Lattice as a discovery-phase tool |
| **OWASP AI/GenAI** | *Only* if Lattice grows an AI-BOM angle | Not the current fit — noted for honesty |

## Honest positioning (the elevator version)

Lattice is **not** the first CBOM tool — IBM's work, now under the PQCA as CBOMkit, came
first. Lattice's distinct contribution is *engineering*: zero-dependency, offline, 12
languages, **prioritized** output (P0–P3 with harvest-now-decrypt-later weighting) rather
than a binary compliant/not verdict, and a CI-native lifecycle (fail-on gate, CBOM drift
diff, policy packs). A serious program could use several tools; Lattice's edge is the
fast, prioritized, gate-able source inventory. The full comparison — including where the
alternatives are stronger — is in [COMPARISON.md](COMPARISON.md).

## Responsible disclosure at scale

If a Lattice scan of a public project surfaces something genuinely serious, follow
coordinated disclosure — report privately, never publish an exploit, and give maintainers
time to fix. Lattice is a defensive tool; it detects and helps remediate, and never
generates exploit code. See [SECURITY.md](https://github.com/mk12002/Lattice/blob/main/SECURITY.md) and
[THREAT_MODEL.md](THREAT_MODEL.md).
