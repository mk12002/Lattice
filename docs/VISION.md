# Vision

**Lattice** is a crypto-agility and post-quantum-readiness scanner. It statically analyzes a
codebase, produces a Cryptographic Bill of Materials (CBOM), grades every cryptographic usage for
quantum vulnerability (Shor/Grover exposure) and classical weakness (broken or deprecated
primitives), and emits a prioritized migration roadmap toward the NIST post-quantum standards
(ML-KEM / FIPS 203, ML-DSA / FIPS 204, SLH-DSA / FIPS 205). It is built for security engineers,
platform teams, and CISOs facing post-quantum migration mandates who need an honest inventory
before they can plan a migration.

**Non-goals.** Lattice is *not* a CSPM, *not* a general SAST tool (it does not hunt injection or
memory-safety bugs), and *not* a crypto-correctness prover — a CBOM is an inventory of what
cryptography is present, not a proof that it is used correctly. Lattice never generates exploit
code, never attempts to break cryptography, makes no network calls, and never emits secret
material. It reads files locally and writes reports locally. Nothing else.
