# Known Gaps and Roadmap

An honest, living account of what Lattice does *not* yet do well, in the same spirit as the
Limitations section of the README — a security tool's credibility rests on naming its own
gaps. Split into: (1) gaps already fixed, (2) real gaps still open, ranked, and (3) inherent
limitations that are not "gaps" but permanent properties of the approach.

## 1. Fixed

**Maintenance / gap-audit pass:**
- **Placeholder repository URLs** in `pyproject.toml` and the SARIF `informationUri` (the
  latter shipped in every report) → `github.com/mk12002/Lattice`, plus `Repository`/`Issues`.
- **`python -m lattice`** now works (added `lattice/__main__.py`) — the console script isn't
  always on `PATH`.
- **Install instructions** no longer reference a nonexistent PyPI package; install-from-source
  / `git+https`, with a PATH/`python -m` note.
- **Doc drift** in test counts reconciled to the real count.
- **Broken image links** — diagrams relocated `marketing/assets/*.svg` → `docs/images/` so the
  core docs no longer depend on the removed marketing tree.

**v0.3.0 coverage + lifecycle pass (the "cover all gaps" work):**
- **`lattice diff` machine-readable output** — `--format {text,json}` and `--out FILE`, so
  CI/dashboards can consume drift the way they consume the CBOM/SARIF.
- **Scan defaults in `lattice.toml`** — an optional `[scan]` table (`exclude`, `languages`,
  `fail_on`, `max_file_bytes`); CLI flags override the file, the file overrides built-ins.
- **New policy packs** — CNSA 1.0 (pre-quantum; caveats it is not quantum-safe) and an
  illustrative FIPS-140 approved-algorithm pack. Policy family scope is now per-`Policy`.
- **Three new language detectors** — Ruby, PHP, Swift (each with a known-answer fixture and
  test), taking coverage to 12 languages + config + dependencies.
- **Kotlin coverage made real** — a Kotlin fixture + test proving the JCA detector handles it.
- **Integrations** — `.pre-commit-hooks.yaml` (id `lattice-scan`) plus example
  `docs/examples/.pre-commit-config.yaml` and a turnkey `docs/examples/github-actions-sarif.yml`.

## 2. Open gaps (ranked by value)

### High value
- **Not published to PyPI.** Users must install from source. **Blocked on a maintainer
  action** the tool can't perform itself: claim a package name and configure trusted
  publishing, then tag a release (the `release.yml` workflow builds and attaches artifacts).
  Packaging is release-ready — `python -m build` produces a valid wheel + sdist and the
  `pyproject` metadata/URLs are correct.

### Medium value
- **WebCrypto/subtle depth in JS.** Common `subtle` algorithm-object shapes are handled, but
  not all (algorithms passed as pre-built variables, `deriveKey` chains). MEDIUM-confidence
  gaps; more patterns + fixtures would help.
- **Scala coverage is nominal.** The JCA detector claims `.scala`; Kotlin now has a fixture and
  works, but Scala (and Scala-native crypto libraries) still lack a fixture/patterns. Add a
  fixture or narrow the claim.
- **Ruby/PHP/Swift are regex-based (MEDIUM)** like the other non-Python/Go detectors — they
  cover the common OpenSSL/CryptoKit/Sodium shapes but not every framework wrapper. Extend
  patterns + fixtures as real-world usage surfaces.
- **No incremental/cached scanning.** Every run is a full scan. Fine for repo-sized trees; a
  very large monorepo would benefit from path/mtime caching. Add only if demand appears.

### Lower value / nice-to-have
- **More policy packs.** BSI TR-02102, PCI-style, sector-specific baselines — each one
  `Policy` instance + a test (Chapter 27 workshop).
- **More languages.** Elixir, Dart, and others — each a Chapter-20 exercise.
- **IDE integration.** A pre-commit hook now ships; an editor plugin would shift-left further.

## 3. Inherent limitations (by design, not gaps to "fix")

These follow from the approach and are documented in the README Limitations section and
Chapter 31 of the handbook. Listed here so they aren't mistaken for open work:

- **Static analysis can't see runtime-selected algorithms or runtime parameters.** Absence of
  findings is not absence of crypto. Deeper dataflow (a large, per-language project) is the only
  real mitigation and remains a research-grade roadmap item.
- **A CBOM is an inventory, not a proof of correct usage.** It won't catch a reused GCM nonce.
- **Regex detectors (Java/JS/C/Rust/C#/Ruby/PHP/Swift) are MEDIUM confidence** and have false
  positives, marked honestly. Real parsers are mostly blocked by the stdlib-only constraint.
- **Deliberate conservative biases** (bare-RSA→P0, unknown-size-AES→weakened, file-level mode
  binding) are intentional over-warnings, documented — not to be "fixed" by weakening them.
- **`.gitignore` support is a subset** (no negations/nested files); fails safe by over-scanning.
- **CycloneDX output is "CycloneDX-style"** — faithful to the structure, not validated against
  the full schema; ungroundable fields (e.g. `classicalSecurityLevel`) are omitted, not guessed.
- **Policy packs check algorithm *names*, not parameter sets or usage correctness** — every pack
  says so in its caveat; "no violations" is not a compliance certification.

---

*Maintainers: when you close an open gap, move it to section 1 with a one-line note, and when
you introduce a new limitation, add it to section 3. Keeping this file honest is part of the
tool's culture.*
