# Benchmarks

Reproducible measurements for Lattice. The harness ([`run.py`](run.py)) is stdlib-only
and prints a Markdown table of files scanned, findings, priority breakdown, readiness
score, and wall-clock time.

## Reproduce

```bash
pip install -e .

# offline, deterministic — scans the bundled fixtures
python benchmarks/run.py

# scan your own tree(s)
python benchmarks/run.py /path/to/repo

# clone & scan the public repos audited in docs/ACCURACY_NOTES.md (needs git + network)
python benchmarks/run.py --clone age paramiko node-jsonwebtoken
```

## Recorded results

From real runs (methodology and hand-verification in
[../docs/ACCURACY_NOTES.md](../docs/ACCURACY_NOTES.md)). Numbers are honest measurements,
not marketing figures; timings are order-of-magnitude and machine-dependent.

| Target | Findings | Readiness | Notes |
|---|---|---|---|
| CPython standard library (~5,800 files) | 173 | — | ~72 s, zero crashes |
| `FiloSottile/age` (Go) | 30 | 62/100 | ChaCha20-Poly1305 on quantum-broken X25519 |
| `paramiko` (Python SSH) | 43 | 54/100 | ECDH/ECDSA/RSA, SHA-1 host hashing, MD5 fingerprints |
| `auth0/node-jsonwebtoken` (JS) | 25 | 26/100 | RSA ×11, ECDSA ×7 |
| bundled `tests/fixtures` | 69 | 44/100 | 12-language corpus, ~0.02 s |

## Properties the harness demonstrates

- **Determinism** — two runs on the same tree produce byte-identical CBOMs modulo one
  timestamp (also enforced by `tests/test_emitters.py`).
- **Bounded resource use** — a per-file size cap bounds memory; whole-document regex
  detectors are linear via `LineIndex` (`tests/test_security.py` asserts a 6,000-match
  file stays under 5 s).
- **No crashes on hostile input** — the DER/config parsers are fuzzed
  (`tests/test_hardening.py`); the walker skips symlinks and binaries.

> These are *inventory* measurements — how much and how severe the detectable cryptography
> is. Lattice is not an adversarial-ML detector, so there is no ground-truth
> true/false-positive dataset here; the honest accuracy discussion (including conservative
> biases) is in `docs/ACCURACY_NOTES.md`.
