# Accuracy notes — real-repository audit (v0.1.0)

Record of the Phase 6 false-positive tuning pass required by the execution
plan. These are observations from real runs, not benchmarks; no detection
rates are claimed because no ground-truth corpus exists for these targets.

## Targets

1. **CPython 3.11 standard library** (`Lib/`, ~5,800 files, scanned in ~72 s
   on one Windows machine — treat as an order of magnitude, not a benchmark).
2. **The Lattice repository itself** (dogfood run; 54 files).

Both runs completed without crashes or skipped-file errors.

## Observations (stdlib run: 173 findings — 58 P0, 17 P1, 49 P2, 8 P3, 41 compliant)

**True positives verified by hand (sample):**
- `poplib.py` — MD5 (the APOP protocol genuinely uses MD5).
- `antigravity.py` — MD5 (geohash implementation).
- `test/certdata/*.pem` — RSA keys and SHA-1-signed test certificates,
  correctly extracted from real PEM/DER material.

**False-positive characteristics found (and kept, deliberately):**
- Scanning a codebase that *implements or tests* TLS (like the stdlib's
  `ssl` module and its test suite) flags the protocol constants it defines
  and exercises (30× SSL-3.0, 30× TLS-1.0 findings, mostly in `test/`).
  These are real matches of real constants, but "this repo tests SSLv3"
  is different from "this service enables SSLv3". Lattice cannot tell the
  difference statically; the findings stay, honestly located, and the
  reader decides. Excluding test trees with `--exclude "test/*"` is the
  practical mitigation.
- `UNKNOWN` key-material findings (14×) are presence-only reports for
  certs/keys that did not parse cleanly — by design they carry no risk
  grade.

**Confidence distribution:** 171/173 high, 2 low. The stdlib is
Python + PEM, which are the two highest-confidence detectors (AST and
DER parse). Regex-heavy targets (Java/JS/C) will skew lower; their
fixtures encode the expected confidence levels.

**Not tuned:** no per-repo suppressions were added. The knowledge base
remains the single source of truth; the only tuning outcome of this audit
was confirming that directive-anchored config matching (rather than
free-text matching) keeps config false positives near zero.
