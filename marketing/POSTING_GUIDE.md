# Lattice Content Kit — Posting Guide (how, when, where)

Everything in `marketing/` maps to the playbook's Phase 4–6. This file is the operational
checklist: exact platforms, order, timings, and asset-creation steps.

## 0. One-time prep (do before Day 1)

1. **Push the repo to GitHub public** and replace `REPO_URL_PLACEHOLDER` / `REPO_URL` in
   all three blogs and the Twitter plan. Tag `v0.2.0` so the release workflow builds
   artifacts.
2. **Pick the blog home**: Hashnode (recommended — custom domain, newsletter built in).
   Create the publication once; all three blogs go there first, and everywhere else points
   back via canonical URL.
3. **Generate the visuals** (see §2) into `marketing/assets/`.
4. **Set up accounts you'll cross-post from**: Dev.to, Medium (request to join the
   "InfoSec Write-ups" publication early — approval takes days), LinkedIn, X.

## 1. The calendar (blogs interleaved with the 12-day X plan)

| Day | X/Twitter (8:30–9:30 PM IST) | Blog / other |
|---|---|---|
| 1 | Launch thread | **Publish Blog 1** (launch post) on Hashnode in the morning; LinkedIn post same evening; **Show HN** next morning (§5) |
| 2 | HNDL explainer thread | Cross-post Blog 1 to Dev.to (canonical URL set) |
| 3 | Scoring-model thread | Submit Blog 1 to Medium "InfoSec Write-ups" |
| 4 | Determinism/diff thread | **Publish Blog 2** (HNDL explainer) on Hashnode; LinkedIn post for it |
| 5 | Real-world scans thread | Cross-post Blog 2 to Dev.to |
| 6 | Secret-safety thread | Reddit day (§5): r/crypto or r/netsec, following each sub's self-promo rules |
| 7 | Rest: poll + engagement | Answer every open comment across all platforms |
| 8 | Suppressions thread | **Publish Blog 3** (engineering deep-dive) on Hashnode; LinkedIn post |
| 9 | Detector-internals thread | Cross-post Blog 3 to Dev.to; submit to InfoSec Write-ups |
| 10 | CNSA 2.0 / policy thread | — |
| 11 | Build-story thread | Consider r/Python or r/rust (the Rust-detector angle) if Day 6 went well |
| 12 | Campaign close + poll results | Update README with "as featured" links; start weekly cadence |

**Why this order:** Blog 1 (the artifact) anchors everything; Blog 2 (broad explainer) lands
mid-campaign when non-technical followers have arrived; Blog 3 (deep engineering) lands
after credibility is established and feeds the tool-builder audience from Days 8–9.

## 2. Creating the visuals (playbook Phase 4)

Target 5–7 per blog. All placeholders in the blogs are marked `[SCREENSHOT: …]` or
`[VISUAL: …]`.

| Asset | How |
|---|---|
| Terminal GIF of `lattice scan` | Windows Terminal + `terminalizer` or OBS→CapCut crop. Scan `tests/fixtures` — it's fast and shows P0s. Keep under 15 s. |
| HTML report screenshots | Open `lattice-report/report.html`, screenshot the exec-summary band in **both** light and dark mode (the report supports both — it demos well). |
| Mermaid diagrams | Each blog's ```mermaid blocks render natively on Hashnode/Dev.to. For X and Medium, export PNGs at [mermaid.live](https://mermaid.live) (2x scale, transparent bg). |
| Priority bar chart (Day 5 / Blog 1) | Data is in `docs/ACCURACY_NOTES.md`. Simplest: a quick matplotlib script or Napkin.ai from the table. |
| Truth-table screenshot | `tests/test_severity.py` in your editor with a good theme, crop to the TRUTH_TABLE list. |
| lattice.toml screenshot | The accept block from Blog 3 §Rule 5 in an editor. |
| Hero/architecture diagram | Blueprint in `marketing/assets/lattice-architecture.svg` (committed); redraw in Excalidraw for the hand-drawn launch aesthetic if preferred. Playbook palette: services #89b4fa, data #a6e3a1, warnings #f9e2af, dark bg #1e1e2e. |
| Blog cover images | Canva, 1600×840, dark minimal, title + one accent. One per blog, reused as OG image. |

## 3. Publishing each blog (Phase 5–6 checklist)

Per blog, in order:

- [ ] Fill the **personal-voice checkpoints** at the bottom of the draft (non-negotiable; then delete the checkpoint block and the "Playbook meta" line)
- [ ] Verify every Further Reading link resolves
- [ ] Read-aloud pass; fix stumbles
- [ ] Replace `[SCREENSHOT]`/`[VISUAL]` placeholders with real assets
- [ ] Hashnode: paste markdown, upload cover, set slug + SEO description (each blog's meta line has the slug and keyword), publish
- [ ] Dev.to next day: same markdown, frontmatter `canonical_url:` → the Hashnode URL, tags: `security`, `cryptography`, `python`, `opensource`, `postquantum`
- [ ] Medium: import via URL (keeps canonical), submit to InfoSec Write-ups
- [ ] LinkedIn (same day as Hashnode publish, 10–11 AM IST): 150–200 words, hook + 4–6 `→` bullets, "Link in comments 👇", link as **first comment**; hashtags: #cybersecurity #cryptography #postquantum #opensource #appsec

## 4. LinkedIn adaptations

Each X thread compresses to one LinkedIn post: take the thread's first tweet as the hook,
three strongest tweets as `→` bullets, close with a question ("Does your org have a crypto
inventory?"). LinkedIn posts on Days 1, 4, and 8 only — LinkedIn punishes daily link posts;
three strong ones beat twelve.

## 5. Hacker News & Reddit (highest variance, highest ceiling)

- **Show HN** (Day 2 morning IST = Day 1 evening US): title exactly
  `Show HN: Lattice – open-source scanner that maps your code's post-quantum crypto debt`.
  Link to the **GitHub repo** (never the blog). Immediately add one first-person comment:
  what it does, the age/paramiko/jsonwebtoken numbers, the known limitations, and one
  question you genuinely want feedback on (e.g. the conservative RSA scoring). Stay online
  3 hours to answer. HN rewards humility + reproducible claims and destroys marketing tone.
- **Reddit**: r/crypto (Day 6; strictly technical framing — the DER walker, the scoring
  model), r/netsec (link post to Blog 3, only if it survived HN scrutiny), r/Python and
  r/rust later with the detector-internals angle. Read each sub's self-promotion rules
  first; comment on other posts before posting your own.

## 6. Metrics (fill weekly, playbook-style)

| Metric | Day 7 | Day 14 | Day 30 |
|---|---|---|---|
| GitHub stars / forks | | | |
| Hashnode views (per blog) | | | |
| Dev.to reactions | | | |
| X: best thread impressions | | | |
| LinkedIn impressions | | | |
| Issues/PRs from strangers | | | |

Double down on whichever angle (explainer vs engineering vs results) outperforms — the
sustaining cadence at the end of the Twitter plan has room for either.

## 7. Hard rules (from the playbook, enforced here)

- Never fabricate numbers, benchmarks, or incidents. Every stat in these drafts traces to
  the repo's own scans or a linked primary source. Keep it that way in edits.
- No filler phrases ("In today's rapidly evolving landscape…"). The drafts are clean;
  don't let editing reintroduce them.
- Personal voice is mandatory before publishing — the checkpoint blocks list exactly where.
- Answer comments. A launch is a conversation you started.
