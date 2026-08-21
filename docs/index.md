# Lattice

**Crypto-agility and post-quantum-readiness scanner.** Lattice statically analyzes a codebase,
produces a CycloneDX-style **Cryptographic Bill of Materials (CBOM)**, grades every
cryptographic usage for quantum vulnerability and classical weakness, and emits a prioritized
migration roadmap toward the NIST post-quantum standards (FIPS 203/204/205).

- **12 languages** + config/key material + dependency manifests
- **Zero runtime dependencies**, offline, deterministic output
- **CI-native**: `--fail-on` gate, CBOM drift diff, SARIF for code scanning, policy packs

![How a scan works](images/lattice-architecture.svg)

## Install

Lattice is not yet on PyPI; install from source:

```bash
git clone https://github.com/mk12002/Lattice && cd Lattice
pip install .
```

## Quick start

```bash
lattice scan .                         # HTML report to ./lattice-report/report.html
lattice scan . --format all --fail-on P0
lattice rules list                     # the full algorithm knowledge base
```

## See it

- **[Live sample report](sample-report.html)** — a real Lattice HTML report (light + dark, self-contained).
- **[Terminal demo](demo.cast)** — an asciinema recording of a scan (`asciinema play`).
- **[Benchmarks](https://github.com/mk12002/Lattice/tree/main/benchmarks)** — reproducible measurements.

## Where to next

- **[Explained simply](PROJECT_EXPLAINED.md)** — a ten-minute, no-prerequisites walkthrough.
- **[Command & config reference](reference.md)** — every flag, exit code, and `lattice.toml` option.
- **[Comparison to other tools](COMPARISON.md)** — honest positioning vs. CBOMkit, Semgrep, TLS scanners.
- **[Accuracy & benchmarks](ACCURACY_NOTES.md)** — real-repo audits and measurements.
- **[Threat model](THREAT_MODEL.md)** — what Lattice does with the sensitive files it reads.
- **[Gaps & roadmap](GAPS.md)** — an honest, ranked account of what's next.

Source, changelog, and contributing guide: <https://github.com/mk12002/Lattice>.
