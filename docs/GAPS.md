# Known Gaps and Roadmap

An honest, living account of what Lattice does *not* yet do well, in the same spirit as the
Limitations section of the README — a security tool's credibility rests on naming its own
gaps. Split into: (1) gaps already fixed in this pass, (2) real gaps still open, ranked, and
(3) inherent limitations that are not "gaps" but permanent properties of the approach.

## 1. Fixed in the latest maintenance pass

- **Placeholder repository URLs.** `pyproject.toml` and the SARIF `informationUri` pointed at a
  non-existent `github.com/lattice-scanner/lattice`; the SARIF one shipped in every report.
  Now `github.com/mk12002/Lattice`, with `Repository`/`Issues` URLs added.
- **`python -m lattice` didn't work.** Only `python -m lattice.cli` did. Added
  `lattice/__main__.py` so the natural module invocation works — important because the
  console script isn't always on `PATH`.
- **Misleading install instructions.** README said `pip install lattice-scanner`, but the
  package is not on PyPI, so that command fails. Now install-from-source / `git+https`, with a
  PATH/`python -m` note.
- **Doc drift.** Test-count claims disagreed (138 vs 153). Reconciled to the real count.
- **Broken image links.** README and `PROJECT_EXPLAINED.md` embedded `marketing/assets/*.svg`,
  but `marketing/` was removed; the diagrams now live in `docs/images/` so the core docs no
  longer depend on the marketing tree.

## 2. Open gaps (ranked by value)

### High value
- **Not published to PyPI.** Adoption friction: users must install from source. A tagged
  release + PyPI publish (the release workflow scaffolds this) would make `pip install lattice`
  real. Requires claiming a package name and setting up trusted publishing.
- **`lattice diff` has no machine-readable / file output.** It prints text to stdout only.
  A `--format json` and/or `--out` would let CI systems and dashboards consume drift
  results the way they consume the CBOM/SARIF. Bounded, additive change (Chapter 26 shape).
- **Scan defaults can't be configured in a file.** `--exclude`/`--languages` live only on the
  CLI; `lattice.toml` holds only acceptances. Teams re-pass the same flags in every CI job.
  Extending `lattice.toml` with an optional `[scan]` section (excludes, languages, size cap,
  default fail-on) would remove that friction — and it composes with the existing loader.

### Medium value
- **Kotlin/Scala coverage is nominal.** `java_det` claims `.kt/.kts/.scala` but only matches
  JCA call shapes; idiomatic Kotlin (e.g., `kotlinx` crypto, extension-function wrappers) and
  Scala libraries aren't specifically handled, and there's no Kotlin/Scala fixture or test.
  Either add real fixtures+patterns or narrow the claimed extensions honestly.
- **WebCrypto/subtle depth in JS.** The JS detector handles common `subtle` algorithm-object
  shapes but not all (e.g., algorithms passed as pre-built variables, deriveKey chains).
  MEDIUM-confidence gaps; more patterns + fixtures would help.
- **Policy family scope is global.** `_POLICY_FAMILIES` is shared across all policies; a policy
  governing only a subset of families can't express that. Make it per-`Policy` when a second
  pack needs it (Chapter 27 notes this).
- **No incremental/cached scanning.** Every run is a full scan. Fine for repo-sized trees;
  a very large monorepo would benefit from path/mtime caching. Add only if demand appears.

### Lower value / nice-to-have
- **More policy packs.** Only CNSA 2.0 ships. CNSA 1.0, FIPS-140 approved-algorithms, BSI
  TR-02102, PCI-style baselines are each one `Policy` instance + a test (Chapter 27 workshop).
- **More languages.** PHP, Ruby, Swift, Elixir — each a Chapter-20 exercise.
- **Pre-commit / IDE hooks.** A shift-left integration (a `pre-commit` hook config) would catch
  weak crypto before CI. Small, high-usability addition.
- **CI SARIF upload example is illustrative.** The README snippet shows the shape; a committed,
  end-to-end GitHub Actions example that uploads SARIF to code scanning would be more turnkey.

## 3. Inherent limitations (by design, not gaps to "fix")

These follow from the approach and are documented in the README Limitations section and
Chapter 31 of the handbook. Listed here so they aren't mistaken for open work:

- **Static analysis can't see runtime-selected algorithms or runtime parameters.** Absence of
  findings is not absence of crypto. Deeper dataflow (a large, per-language project) is the only
  real mitigation and remains a research-grade roadmap item.
- **A CBOM is an inventory, not a proof of correct usage.** It won't catch a reused GCM nonce.
- **Regex detectors (Java/JS/C/Rust/C#) are MEDIUM confidence** and have false positives, marked
  honestly. Real parsers are mostly blocked by the stdlib-only constraint.
- **Deliberate conservative biases** (bare-RSA→P0, unknown-size-AES→weakened, file-level mode
  binding) are intentional over-warnings, documented — not to be "fixed" by weakening them.
- **`.gitignore` support is a subset** (no negations/nested files); fails safe by over-scanning.
- **CycloneDX output is "CycloneDX-style"** — faithful to the structure, not validated against
  the full schema; ungroundable fields (e.g. `classicalSecurityLevel`) are omitted, not guessed.

---

*Maintainers: when you close an open gap, move it to section 1 with a one-line note, and when
you introduce a new limitation, add it to section 3. Keeping this file honest is part of the
tool's culture.*
