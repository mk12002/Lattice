# Building a Security Scanner That Never Lies: Determinism, Honest Confidence, and the Tests That Keep It That Way

> **Playbook meta** — Angle: "Building X the right way" · Audience: engineers (security + backend), tool builders · Target length: ~2,000 words · Primary keyword: *deterministic security scanner* · Slug: `building-a-security-scanner-that-never-lies`

---

The fastest way to kill a security tool is not a missed vulnerability. It's a confident wrong answer. One fabricated CVE, one "critical" that turns out to be a comment, one key byte leaked into a report — and the tool moves from "runs in CI" to "uninstalled, with prejudice."

I built [Lattice](REPO_URL_PLACEHOLDER), an open-source crypto-inventory scanner, with that failure mode as the primary design constraint. This post is about the engineering that keeps a scanner honest: deterministic output, confidence as a first-class field, secret-safety as a test invariant, and suppressions that can't hide anything. All of it generalizes to any analysis tool you might build.

> **TL;DR**
> - **Determinism is a feature, not hygiene**: byte-identical output (modulo one timestamp) is what turns reports into CI gates and makes `diff` meaningful.
> - **Confidence must be data, not vibes**: every finding carries `high/medium/low` derived from *how* it was matched (AST vs regex vs token).
> - **Secret-safety needs a test, not a policy**: assert that key bytes appear in zero output formats, forever.
> - **A truth table is the best spec**: the scoring model is defined by ~30 (input → expected priority) rows that the code must satisfy, not the other way around.

## Rule 1: Same input, byte-identical output

Most scanners treat output stability as an accident. Findings arrive in filesystem order (different on every OS), dicts serialize in insertion order (different across refactors), timestamps sprinkle everywhere. The result: you can't diff two reports, so you can't answer the only question CI cares about — *"did this PR make things worse?"*

Lattice pins all of it:

- Findings sort by a canonical key: `(priority, path, line, algorithm)`.
- The directory walker sorts every listing; discovery order can't leak into output.
- Exactly **one** timestamp exists, at the top level. A test scans twice and asserts the outputs are byte-identical after normalizing that single field — for all three formats (CBOM JSON, HTML, SARIF).

What that buys you is a new *verb*:

```bash
lattice diff baseline/cbom.json current/cbom.json --fail-on-new P0
```

Drift detection keys findings by `(algorithm, file, priority)` — deliberately **excluding line numbers**, so moving code around doesn't read as cryptographic churn. New key = new debt = red build. Pre-existing debt passes. Teams adopt gates that don't punish them for history.

```mermaid
flowchart LR
    subgraph CI["Pull request pipeline"]
      A[checkout main] --> B[lattice scan - baseline CBOM]
      C[checkout PR branch] --> D[lattice scan - current CBOM]
      B --> E{lattice diff --fail-on-new P0}
      D --> E
      E -- new P0 introduced --> F[build fails with the exact finding]
      E -- no new debt --> G[build passes - legacy debt untouched]
    end
```

Hot take: **a security report you can't diff is a PDF, not a control.** If your scanner's output changes shape run-to-run, it will never gate anything.

## Rule 2: Confidence is derived from mechanism, never asserted

Here's the uncomfortable truth about multi-language static analysis: your evidence quality varies wildly, and pretending otherwise is lying.

- Python: Lattice parses a real **AST**, resolves aliased imports (`import hashlib as hl` doesn't fool it), even infers AES key sizes from `os.urandom(32)` flowing into a constructor. Mechanism: parse. Confidence: **high**.
- Go: an unused import won't compile, so `import "crypto/md5"` is near-proof of use. Confidence: **high**.
- Java/JS/C/C++/Rust/C#: string and token matching on distinctive patterns (`Cipher.getInstance("AES/ECB/...")`). Real signal, weaker proof. Confidence: **medium**.
- A file that wouldn't parse, scanned for bare tokens as a last resort: **low** — and the HTML report badges it visibly so nobody acts on it blindly.

The rule: **confidence is a function of the match mechanism**, assigned by the code path that produced the finding — never a knob, never an average. When someone audits a finding and asks "how sure are you?", the answer was computed, not vibed.

The same honesty applies to the *scoring* layer. Lattice's readiness score prints its own formula next to the number in every report — `100 × (1 − severity-weighted share of findings)` — because a score whose formula is secret is a marketing asset, not a metric.

[SCREENSHOT: HTML report showing a low-confidence badge on a finding and the score formula text under the big number]

## Rule 3: The scoring model is a truth table, and the truth table is the spec

Crypto risk scoring invites endless cleverness. I refused all of it. The entire severity model is specified by a table of roughly thirty rows:

| Input | Expected |
|---|---|
| RSA used for key establishment | **P0** (Shor-broken + harvest-now-decrypt-later) |
| ECDSA signature | **P1** (Shor-broken, but recorded signatures mostly can't be retro-forged) |
| MD5, SHA-1, DES, RC4, any-cipher-in-ECB | **P0** (broken *today*; quantum irrelevant) |
| 3DES, Blowfish, AES-128, PBKDF2 | **P2** (deprecated / Grover-weakened) |
| SHA-256 | **P3** (fine today, prefer larger post-quantum margins) |
| AES-256-GCM, ChaCha20, ML-KEM, ML-DSA | **none** (compliant) |

The test file *is* this table (`tests/test_severity.py`), and the implementation is a ~40-line decision procedure that satisfies it. When a security reviewer disagrees with a judgment, we argue about **one row**, change it, and the code follows. Precedence rules are explicit: broken-today beats broken-later; HNDL promotes quantum-broken key establishment to P0.

The subtle part is *usage context*. RSA's priority depends on what it's doing — key transport (P0) vs signing (P1). Where the call site proves usage (Java's `Signature.getInstance("SHA256withRSA")`, a certificate's signature field), Lattice pins it. Where it can't (a bare keygen call), it scores conservatively and the docs say so. The blind spot is documented in the repo (`docs/ACCURACY_NOTES.md`) with real examples from scanning paramiko and node-jsonwebtoken — because **a scanner's known biases belong in its documentation, not in a postmortem**.

## Rule 4: Secret-safety is an invariant with a regression test

A crypto scanner reads the most sensitive files in any company: private keys. The design rule is absolute — *detect by header, never read the body*:

- `-----BEGIN RSA PRIVATE KEY-----` → report "RSA private key at path:line". The base64 body is never decoded.
- Certificates and public keys *are* parsed (they're public material) via a ~60-line defensive DER walker that extracts only algorithm OIDs — and that walker is **fuzzed** in the test suite with thousands of garbage inputs, because a parser that crashes on a malformed cert is a denial-of-service against your own CI.
- Every snippet passes a redaction filter that masks long base64/hex runs before storage.

And then the part I'd actually defend in a design review: the test suite plants a fake key in the fixtures and asserts its bytes appear in **none** of the three output formats. Policies decay; invariants with regression tests don't.

```mermaid
sequenceDiagram
    participant W as Walker
    participant D as Config detector
    participant R as Reports
    W->>D: file content (server.key)
    D->>D: match PEM header only
    Note over D: body never decoded<br/>snippet = "[body not read]"
    D->>R: finding: RSA private key, path:line
    R-->>R: test asserts key bytes ∉ CBOM ∪ HTML ∪ SARIF
```

## Rule 5: Suppression that can't become a cover-up

Every scanner eventually meets the legitimate exception — MD5 as a cache key, a keystore in test fixtures. Most tools offer a mute button, and mute buttons rot into cover-ups.

Lattice's version is an **acceptance file** with three enforced properties:

```toml
[[accept]]
algorithm = "MD5"
path = "legacy/cache/**"
reason = "non-security cache key; removal tracked in TICKET-123"   # mandatory
expires = 2027-01-01                                               # optional, enforced
```

1. **No reason, no acceptance** — the entry is rejected with a warning.
2. **The finding never disappears** — it stays in the CBOM, the HTML (in its own "Accepted risks" section), and SARIF (as a standard `suppressions` object), marked and explained. It only leaves the *gate* and the *score*.
3. **Expiry re-activates it** — time-boxed risk acceptance, the way risk registers actually work.

## The walking-skeleton lesson (what I'd tell anyone building an analysis tool)

Process note that mattered more than any single feature: before writing six detectors, I built **one language end-to-end** — Python detector → scoring → CBOM emitter → CLI — and gated on it finding exactly three known assets in a fixture with correct classifications. Only after that pipeline was proven did detectors fan out, each with its own known-answer fixture ("this file contains exactly: one broken, one quantum-vulnerable, one safe usage").

Known-answer fixtures are the highest-leverage test pattern for scanners: false negatives on fixtures are never acceptable; false positives are acceptable only if honestly marked low-confidence. That single rule shaped every detector.

## Key takeaways

- **Pin your output order and count your timestamps** — determinism is what upgrades reports into gates.
- **Compute confidence from the match mechanism** and show it; never let a regex hit cosplay as proof.
- **Spec judgment as a truth table** and make the test file the spec.
- **Turn "we never leak secrets" into a failing-test invariant**, not a code-review hope.
- **Fuzz every parser that touches untrusted files** — your scanner runs on hostile input by definition.
- **Design suppression as visible, reasoned, expiring acceptance** — inventory must survive convenience.

## Further reading

- [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) — including the `suppressions` mechanism Lattice emits.
- [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/) — the inventory format.
- [Reproducible Builds](https://reproducible-builds.org/) — the broader determinism movement this borrows its philosophy from.
- [Growing Object-Oriented Software (walking skeleton)](http://www.growing-object-oriented-software.com/) — origin of the build-one-slice-end-to-end discipline.
- [Lattice source + accuracy notes](REPO_URL_PLACEHOLDER) — every claim in this post is a test or a doc in the repo.

---

*Personal-voice checkpoints: (1) add the real story of a bug the gates caught (e.g. the SSLv2-labeled-as-SSLv3 mislabel found in self-review); (2) sharpen one hot take of your own — candidate: "If your SAST vendor can't show you a determinism test, their 'trend dashboards' are decorative."*
