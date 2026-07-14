# Threat model — for Lattice itself

Lattice is a security tool that reads source trees, which routinely contain the most sensitive
files in an organization (private keys, credentials, proprietary code). This document states
what Lattice does with that access, and what it will never do.

## What Lattice does

- **Reads files** under the path you point it at, subject to excludes, `.gitignore`, a
  per-file size cap, and a binary sniff. File contents are held in memory only for the
  duration of a single file's detection pass.
- **Writes reports** (CBOM JSON / HTML / SARIF) to the local output directory you choose.
- **Nothing else.** There is no network code anywhere in the package: no telemetry, no update
  check, no rule download, no upload. Determinism is a design requirement precisely so output
  can be diffed and audited.

## Handling of secret material

- **Private keys / keystores:** detection is header- and extension-based. The key *body* is
  never base64-decoded, parsed, stored, or echoed. Reports carry location and type only
  (`server.key:1 — RSA private key`). This is covered by tests
  (`test_config_private_key_location_only_never_contents`,
  `test_no_key_material_in_any_output`).
- **Certificates and public keys:** these are public material; Lattice base64-decodes them and
  runs a minimal DER walk that extracts algorithm OIDs only. Anything that does not parse
  cleanly is reported as presence-only.
- **Snippets:** every snippet passes through a redaction filter that masks runs of ≥24
  base64/hex-like characters and drops PEM lines entirely. Losing context is always preferred
  over leaking a token.

## What Lattice will never contain

- Exploit generation or proof-of-concept attack code of any kind.
- Code that attempts to break, brute-force, or downgrade cryptography.
- Network I/O.
- Fabricated security data: no invented CVEs, CVSS scores, vendor advisories, or statistics.
  The knowledge base encodes established cryptographic facts and references standards by name.

## Residual risks for users

- **Report files are themselves sensitive.** A CBOM tells an attacker where your weak crypto
  lives. Treat `lattice-report/` like an internal audit artifact: don't publish it, don't
  commit it (the default output directory is in `.gitignore`).
- **Scan output includes file paths and one-line snippets.** The redaction filter is
  conservative but pattern-based; review reports before sharing them outside the team that
  owns the code.
- **A malicious repository cannot execute code via Lattice** (files are parsed, never
  imported or executed), but pathological inputs are still parsed — the walker's size cap and
  the defensive parsers (fuzz-tested) bound the blast radius to CPU time.
