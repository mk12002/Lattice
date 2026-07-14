# Lattice — 12-Day X/Twitter Launch Plan

Twelve days of threads, written in full and ready to paste. Rules applied throughout (per
the playbook): no `1/12` numbering, ≤280 characters per tweet, max 1 emoji per tweet, each
tweet self-contained, hottest take late in the thread, link at the end.

**Daily rhythm:** post the thread at **8:30–9:30 PM IST** (morning US East / afternoon
Europe — the security-Twitter overlap window). Pin Day 1's thread for the whole campaign.
Reply to every substantive comment within 12 hours — the algorithm rewards it and so do
people. `[ATTACH: …]` notes mark what image/GIF to add; create them per the posting guide.

Replace `REPO_URL` with the GitHub link everywhere. If a day slips, shift the calendar —
never post two threads in one day.

---

## Day 1 (launch) — "I built a thing"

> Your encrypted traffic can be stolen today and decrypted in 10 years. The attack has a name: harvest now, decrypt later. I built an open-source scanner that tells you exactly which of your crypto falls first. 🧵

> Lattice scans a codebase and builds a CBOM — a Cryptographic Bill of Materials. Every algorithm, key file, TLS config, and crypto dependency, each with file:line evidence. Like an SBOM, but for the crypto itself.
> [ATTACH: terminal GIF of `lattice scan` running and printing the summary]

> Every finding gets graded twice: quantum risk (does Shor's algorithm kill it?) and classical risk (is it broken today, like MD5?). Then one migration priority, P0 to P3, with the reasoning attached.

> The key idea: not all quantum-broken crypto is equal. RSA key exchange = P0, because recorded traffic decrypts later. ECDSA signatures = P1, because you mostly can't retro-forge a signature. Broken-today (MD5, ECB) outranks everything.

> It covers Python (real AST), Java, JS/TS, Go, C/C++, Rust, C#, PEM/X.509 files, TLS configs, and 6 dependency manifest formats. pip install, zero runtime dependencies, fully offline. No server, no database.

> Output: CycloneDX-style CBOM JSON, a self-contained HTML report a CISO can read, and SARIF for GitHub code scanning. Deterministic — same input, byte-identical output. That's what makes it CI-gateable.
> [ATTACH: screenshot of the HTML report executive summary]

> I tested it on real projects. age (Filippo Sottile's encryption tool) scored 62/100 — ChaCha20 is quantum-fine, but X25519 key exchange is exactly the harvest-now-decrypt-later shape. Even excellent modern crypto is pre-quantum crypto.

> Apache-2.0, tests green, honest limitations documented (static analysis can't see runtime-selected algorithms — and the README says so). Repo: REPO_URL

**Same day:** LinkedIn version of this thread (see posting guide §4).

---

## Day 2 — HNDL explainer (non-technical reach day)

> A thief steals locked boxes he cannot open. He's not stupid. He's read the locksmith journals and knows a new drill is coming. That's "harvest now, decrypt later" — and it's happening to encrypted data right now. 🧵

> Quantum computers will break the math behind RSA and elliptic curves (Shor's algorithm). Not today. Maybe not this decade. But encrypted traffic recorded today just... waits.

> So the question isn't "when do quantum computers arrive?" It's "which of my data still matters when they do?" Health records, legal files, source code, state secrets — 25-year shelf lives. Those boxes are already in the warehouse.

> NIST finished the replacement locks in August 2024: ML-KEM (FIPS 203) for key exchange, ML-DSA (FIPS 204) for signatures. The math is done. The hard part is finding every place your systems use the old math.

> Historical base rate: the SHA-1 and DES migrations each took 10-15 years. The US government's own targets for dropping classical public-key crypto cluster around 2030-2035. The migration clock and the quantum clock are racing.

> Step one is embarrassingly concrete: an inventory. You cannot migrate what you haven't listed. That's what a CBOM is — and generating one is now a one-command job.
> [ATTACH: the priority-flow diagram from blog 1, rendered at mermaid.live]

> One question to ask your team tomorrow: "If I asked for our cryptographic inventory, how long would it take?" A shrug means the project hasn't started. Full explainer + free scanner: REPO_URL

---

## Day 3 — the scoring model deep-dive

> Every PQC vendor says "start migrating." Almost nobody says where to start. Here's the entire prioritization model my scanner uses, in one thread — steal it even if you never run the tool. 🧵

> Rule 1: broken-today beats broken-someday. MD5, SHA-1, DES, RC4, anything in ECB mode — P0, no quantum computer required. If your inventory has these, quantum is not your first problem.

> Rule 2: quantum-broken + recordable = P0. RSA/DH/ECDH key exchange protects traffic an adversary can capture NOW and decrypt LATER. The breach already happened; it just hasn't been read yet.

> Rule 3: quantum-broken signatures = P1, not P0. A recorded ECDSA signature mostly can't be retro-forged. Still must migrate before quantum arrives — but after the key exchange.

> Rule 4: Grover-weakened = P2/P3. AES-128 and SHA-256 aren't broken; their margins halve. AES-256 and SHA-384 restore them. Plan it, don't panic about it.

> The whole model is a ~30-row truth table and the test suite IS the table. When someone disagrees with a judgment, we argue about one row. Specs you can argue about beat cleverness you can't.
> [ATTACH: screenshot of the truth-table test code]

> Hot take: a risk score whose formula is secret is marketing, not measurement. Lattice prints its formula next to the number in every report. Repo: REPO_URL

---

## Day 4 — determinism + the diff gate

> The most useful feature in my crypto scanner isn't detection. It's that two scans of the same code produce byte-identical output. Sounds boring. It changes everything. 🧵

> Non-deterministic reports can't be compared. Deterministic ones can — which means a CBOM becomes diffable, which means CI can answer the only question it actually has: did THIS PR make our crypto worse?

> lattice diff baseline.json current.json --fail-on-new P0
> Fails only when a PR introduces new weak crypto. Ten years of legacy debt? Build stays green. One new MD5? Red, with the exact file.
> [ATTACH: terminal screenshot of a diff failing with "+ [P0] MD5 in new.py"]

> Getting there: canonical sort key on every finding, sorted directory walking, exactly ONE timestamp in the whole document. A test scans twice and asserts byte-equality across all three output formats.

> Drift keys are (algorithm, file, priority) — deliberately no line numbers. Moving code around isn't cryptographic change. Design your identity keys around what you want to detect, not what's easy.

> Hot take: a security report you can't diff is a PDF, not a control. Repo: REPO_URL

---

## Day 5 — real-world scan results

> I pointed my crypto scanner at three well-known open-source projects. The results say more about the post-quantum problem than any whitepaper. 🧵

> age — the most thoughtfully designed modern encryption tool — scored 62/100. ChaCha20-Poly1305: quantum-fine. But it keys on X25519 exchange: Shor-broken, harvest-now-decrypt-later shaped. Excellent crypto, pre-quantum crypto.

> paramiko (Python SSH): 43 findings. ECDH+ECDSA+RSA key exchange and host keys, SHA-1 in known-hosts hashing, MD5 fingerprints. SSH is a beautifully preserved museum of 2005 cryptography that the whole industry stands on.

> node-jsonwebtoken: readiness 26/100. RSA ×11, ECDSA ×7 — every RS256/ES256 token. JWTs are quantum-broken signatures all the way down. (P1 tier, luckily: signatures, not key exchange.)

> Honest part: the scanner over-scores some of these. A bare `generateKeyPair('rsa')` can't prove it's signature-only usage, so it scores conservatively. That bias is documented in the repo with these exact examples, not hidden.
> [ATTACH: bar chart of the three repos' priority distributions]

> Every finding above is a real match at a real file:line — you can reproduce all three scans in about two minutes. Commands in the repo: REPO_URL

---

## Day 6 — the secret-safety thread

> My scanner reads the most dangerous files in any company: private keys. Here's the engineering that guarantees it never leaks one — including the test I'd least like to see deleted. 🧵

> Rule: detect by header, never read the body. `-----BEGIN RSA PRIVATE KEY-----` produces "RSA private key at path:line". The base64 body is never decoded. The snippet literally says "[body not read]".

> Certificates ARE parsed — they're public material. A 60-line defensive DER walker extracts only the signature-algorithm OID. It's fuzzed with thousands of garbage inputs in CI, because a parser that crashes on a weird cert is a DoS on your own pipeline.

> Every snippet passes a redaction filter first: long base64/hex runs get masked. Losing a little context always beats leaking one token into a report that gets emailed around.

> And the invariant: the test suite plants a fake key in the fixtures and asserts its bytes appear in ZERO output formats — CBOM, HTML, SARIF. Policies decay. Tests don't.
> [ATTACH: screenshot of test_no_key_material_in_any_output]

> If you build anything that reads repos: write that test on day one. Repo: REPO_URL

---

## Day 7 — rest day / engagement day

No thread. Instead:

- Quote-repost the best reply from Days 1–6 with a substantive addition.
- Post one standalone poll: **"Does your org have a cryptographic inventory (CBOM)?"** — options: "Yes, maintained", "Someone has a spreadsheet", "No", "What's a CBOM". Polls travel; the results seed Day 12's thread.
- Reply to everyone you owe replies to.

---

## Day 8 — suppressions done right

> Every scanner meets a legitimate exception: MD5 as a cache key, test fixtures full of dummy keys. Most tools offer a mute button. Mute buttons rot into cover-ups. Here's the alternative I shipped. 🧵

> In Lattice, you don't suppress a finding — you ACCEPT it, in a file called lattice.toml, and the acceptance requires a reason. No reason, no acceptance; the entry is rejected with a warning.

> [ATTACH: screenshot of a lattice.toml accept block with algorithm/path/reason/expires]

> Accepted findings leave the CI gate and the readiness score — but never the reports. They appear in their own "Accepted risks" section, marked, with the reason as the audit trail. An inventory that hides things isn't an inventory.

> Acceptances can expire. `expires = 2027-01-01` and the finding comes back by itself. That's how real risk registers work — time-boxed, not forever.

> In SARIF output they become standard `suppressions` objects, so GitHub code scanning handles them natively. No custom UI, no vendor lock.

> Hot take: every "ignore" comment in every SAST tool should require a reason and an expiry. The ones that don't are institutionalizing silent risk. Repo: REPO_URL

---

## Day 9 — how detection works (for the tool builders)

> Nine languages, one honesty rule: confidence is computed from HOW the match happened, never asserted. A tour of what a crypto detector actually looks like inside. 🧵

> Python gets a real AST walk. Aliased imports (`import hashlib as hl`) can't hide. It even infers AES key size when `os.urandom(32)` flows into a constructor — 32 bytes = AES-256, marked high confidence.

> Go is the fun one: unused imports don't compile. So `import "crypto/md5"` is near-proof of use. Import-map detection, high confidence, ~100 lines total.

> Java/JS/C/C++/Rust/C# run scoped token matching — `Cipher.getInstance("AES/ECB/PKCS5Padding")` gets parsed into AES + ECB and the ECB flags as broken usage. Real signal, weaker proof: medium confidence, badged as such.

> Files that won't parse fall back to bare token scanning at LOW confidence, visibly flagged "verify manually". The report never lets a token match cosplay as proof.

> The contract for every detector: yield a finding only for a concrete matched pattern at a real line. No "this project probably uses crypto" heuristics. If it isn't matched, it isn't reported.

> Adding language #10 is one class (two methods), one fixture, one test. Contributions welcome — Ruby and PHP are wide open: REPO_URL

---

## Day 10 — the CNSA 2.0 / policy angle

> "Are we compliant?" and "are we secure?" are different questions. My scanner answers them with two separate layers — and keeping them separate was the design decision I'm most confident about. 🧵

> Layer 1 (severity): is this crypto broken, and how urgently? MD5 = P0. That's physics and math; it doesn't care about your industry.

> Layer 2 (policy): is this algorithm in your required set? `--policy cnsa2` checks findings against NSA's CNSA 2.0 suite — AES-256, SHA-384/512, ML-KEM, ML-DSA. Violations exit 1.

> The layers disagree, and that's correct: ChaCha20-Poly1305 is quantum-safe (severity: compliant) but not in CNSA 2.0 (policy: violation). Secure ≠ compliant. A tool that merges those concepts lies in one direction or the other.

> Honesty caveat, printed in the output itself: static analysis can't verify parameter sets (ML-KEM-768 vs -1024). An empty violation list means "algorithms are in the suite," not "you're certified."

> CNSA 2.0 requires national-security systems to complete the PQC transition by 2033. If you sell into that world, the clock has a date on it. Repo: REPO_URL

---

## Day 11 — the build story (process thread)

> I built a 9-language security scanner with 138 tests, and the highest-leverage decision was refusing to write detector #2 before detector #1 worked end-to-end. The walking-skeleton method, applied. 🧵

> Phase 1 wasn't detection. It was the spine: data models, a knowledge base of ~45 algorithms, and a scoring truth table. The knowledge base IS the product; everything else is delivery.

> Then ONE language — Python — end to end: detect → score → emit → CLI, gated on a fixture with three known assets classified exactly right. Only after that gate passed did detectors fan out.

> Every detector since ships with a known-answer fixture: a file containing exactly one broken, one quantum-vulnerable, one safe usage. False negatives on fixtures: never acceptable. False positives: only if marked low-confidence.

> The gates caught real bugs before users could: SSLv2 mislabeled as SSLv3, a JS digest graded as a signature (P2 instead of P3), Apache's `+TLSv1` enable-syntax being skipped. Self-review with fixtures beats hope.

> Then I pointed it at CPython's entire stdlib: ~5,800 files, 72 seconds, 173 findings, zero crashes — and hand-verified samples (yes, poplib really still has MD5; it's the APOP protocol).

> The full phased plan, gate criteria, and accuracy audits are all in the repo docs. Build in public includes the process: REPO_URL

---

## Day 12 — campaign close + poll results + ask

> A week and a half ago I released Lattice, an open-source post-quantum readiness scanner. Closing the launch with the numbers, the poll results, and one ask. 🧵

> [Fill in: stars/forks/installs, best issue or PR received, most-read blog post. Real numbers only — small honest numbers beat inflated ones.]

> Poll results from Day 7: [X]% of you don't have a cryptographic inventory. That matches every conversation I've had. The gap between "PQC is coming" awareness and "we have a list" reality is the entire problem.

> What I learned shipping this: [fill in 2-3 genuine lessons — e.g. "the accepted-risks feature came from a reader comment", "Rust coverage was the most-requested addition"].

> Roadmap next: [pick from: Ruby/PHP detectors, git-history HNDL analysis, deeper parameter extraction, policy packs beyond CNSA 2.0]. Vote by opening an issue — the roadmap is demand-driven, genuinely.

> The ask: if you tried Lattice and it found something real, tell me (DM or issue) — accuracy reports are worth more than stars. If it's useful, a star helps others find it: REPO_URL

> Blogs from the campaign, if you missed them: harvest-now-decrypt-later explained, the scoring model, and building scanners that never lie. All linked from the repo README. Thanks for a great launch. 🙏

---

## Beyond day 12 (sustaining cadence)

- 1 thread/week: pick a single algorithm from `lattice rules list` and tell its story (MD5's fall, the 3DES Sweet32 saga, why ChaCha20 exists, Falcon vs ML-DSA).
- Reply-guy strategically: every viral "quantum will break encryption" post gets a calm, sourced reply linking the HNDL explainer.
- Re-run the Day 5 scans quarterly and post the drift — living proof the diff feature matters.
