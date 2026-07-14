# Accuracy notes — real-repository audits

## v0.2.0 audit (2026-07-14): three public repositories

Depth-1 clones of three deliberately different public projects, scanned with all
detectors, sample of P0/P1 findings hand-verified against each project's known design.

| Repo | Findings | Score | What Lattice saw | Hand-check verdict |
|---|---|---|---|---|
| `paramiko/paramiko` (Python SSH) | 43 (13 P0) | 54 | ECDSA/ECDH/RSA/AES kex+hostkeys, SHA-1 in host hashing, MD5 fingerprints, bcrypt KDF | All spot-checked matches real (e.g. `kex_curve25519.py:30` X25519 keygen, `config.py:449` sha1) |
| `FiloSottile/age` (Go encryption) | 30 (9 P0) | 62 | ChaCha20-Poly1305 ×8, X25519 ×5, scrypt, HMAC — exactly age's published design; RSA from ssh-rsa recipient support | Matches the project's documented cryptography precisely; the RSA private key in `.github/workflows/certs` reported location-only, body not read |
| `auth0/node-jsonwebtoken` (JS JWT) | 25 (12 P0) | 26 | RSA ×11 / ECDSA ×7 (RS256/ES256), SHA-1-signed test certificates via the DER parser | Real matches; note below on signature-usage conservatism |

**Known conservative behaviors observed (kept deliberately, documented):**

1. **Signature-context blindness in JS**: `generateKeyPair('rsa')` in a JWT library is
   signature usage (P1-appropriate), but the call site alone cannot prove that, so RSA
   defaults to key-establishment scoring (P0, HNDL). Java's `Signature.getInstance` and
   certificates *do* pin signature usage; bare keygen does not.
2. **Hash-usage blindness**: paramiko's `sha1()` in known-hosts hashing is an HMAC-SHA1
   construction (collision resistance not load-bearing), still reported P0 as
   collision-broken SHA-1. Static analysis cannot see the construction; the justification
   string states exactly which property is broken so a reviewer can triage.
3. **Test material counts**: certificates and keys under `test/` directories are real
   findings at real locations; use `--exclude "test/*"` or a `lattice.toml` acceptance
   when they are noise.

No crashes, no unreadable-file failures, deterministic output across repeat runs on all
three repos.

---

# v0.1.0 audit — CPython standard library

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
