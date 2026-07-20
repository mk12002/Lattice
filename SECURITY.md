# Security Policy

Lattice is a defensive security tool that reads potentially untrusted source trees. Its own
security posture therefore matters as much as its findings. This document states the threat
model, the hardening measures in place, how the code is audited, and how to report a
vulnerability.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub's **Report a vulnerability**
button (Security tab → Advisories) rather than a public issue. Include reproduction steps and
the affected version. We aim to acknowledge within 72 hours and to ship a fix or mitigation
before any public disclosure. Coordinated disclosure is welcomed and credited.

## Threat model (summary)

Full detail in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). In short, Lattice:

- **reads files locally and writes reports locally — nothing else.** There is no network
  code anywhere in the package: no telemetry, no update check, no rule download.
- **parses hostile input by design.** A scanned repository may be attacker-controlled, so
  every file-facing code path must degrade — never crash the whole scan, hang, or exfiltrate
  data — on malformed, pathological, or malicious input.
- **must never emit secret material.** Private-key bodies are detected by header only and
  never decoded, stored, or echoed.

## Hardening measures

| Surface | Risk | Mitigation | Regression test |
|---|---|---|---|
| Symlinks in a scanned tree | A planted symlink could point outside the scan root (another tenant's key, `/etc/shadow`) and be read into a report | File symlinks are skipped; directory symlinks are not followed (`os.walk(followlinks=False)`) | `test_security.py::test_symlinked_file_is_not_followed` |
| `lattice diff` on a crafted CBOM | Malformed-but-valid JSON (non-list `components`, non-dict entries) could crash the tool | Defensive loader treats any non-list/non-dict as empty; totalizes the parse | `test_security.py::test_diff_survives_malformed_cbom` |
| Detector regexes on huge/crafted files | Quadratic line-counting or catastrophic backtracking (ReDoS) → CPU DoS | Per-file **size cap** (1 MB default) bounds all input; whole-document regex matching uses an O(log n) `LineIndex` instead of per-match newline counting; detector regexes use anchored, per-line, negated-character-class patterns (no nested quantifiers) | `test_security.py::test_java_detector_scales_linearly_on_many_matches` |
| Private-key material | Key bytes leaking into any output format | Header-only detection; snippet redaction of long base64/hex runs; PEM bodies dropped | `test_security.py::test_private_key_bytes_never_reach_any_output`, `test_emitters.py::test_no_key_material_in_any_output` |
| X.509 / DER parsing | A malformed certificate crashing the parser (DoS) | Bounded, defensive DER walker (no third-party ASN.1 lib); fuzzed with thousands of garbage inputs | `test_hardening.py::test_der_walkers_never_raise_on_garbage` |
| Binary / non-UTF-8 / oversized files | Memory blow-up or garbage findings | Size cap before read; null-byte binary sniff; `errors="replace"` decoding | `test_hardening.py` (size cap, binary, non-UTF-8) |
| CLI arguments | Confusing/undefined behavior from bad input (`--max-file-bytes -1`) | Explicit validation with a clear error and exit code 2 | `test_security.py::test_cli_rejects_non_positive_max_file_bytes` |
| Untrusted repo cannot execute code | Files are **parsed, never imported or executed** | Python detector uses `ast.parse` (no `eval`/`exec`/`import`); all others are pure text/regex | — |

## Supply chain

- **Zero runtime dependencies.** Lattice runs on the Python standard library only. Every
  third-party package is a supply-chain liability in a security tool, so the runtime
  dependency list is empty by policy (enforced in `pyproject.toml`).
- Development and CI tooling (pytest, ruff, mypy, bandit, pip-audit) is isolated under the
  `dev` optional-dependency group and never ships in the runtime package.

## How the code is audited

Run locally (all part of `pip install -e ".[dev]"`):

```bash
bandit -c pyproject.toml -r lattice     # static security analysis (SAST)
pip-audit                               # known-CVE check on dependencies
pytest tests/test_security.py           # the regression tests above
ruff check . && mypy lattice            # lint + types
```

CI runs Bandit and pip-audit on every push and pull request (see
`.github/workflows/ci.yml`).

**Note on Bandit B105.** Bandit's `hardcoded_password_string` check flags algorithm-name
string literals like `"DES"` that a cryptography-analysis tool compares constantly. Lattice
handles no credentials, tokens, or passwords anywhere (no network, no authentication), so
B105 can have no true positive here; it is skipped project-wide with that justification in
`pyproject.toml` (`[tool.bandit]`). No other Bandit checks are disabled.

## What Lattice will never do

Restating the hard rules from the threat model, because they are security guarantees:

- No network I/O of any kind.
- No exploit generation, and no attempt to break, brute-force, or downgrade cryptography.
- No fabricated security data (invented CVEs, CVSS scores, or advisories).
- No secret material written to any output.
