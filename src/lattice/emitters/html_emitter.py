"""Self-contained HTML report emitter.

One file, inline CSS, zero external requests (no CDN, no fonts, no images).
Designed to be read by a CISO first and an engineer second: executive
summary up top, detail below. Renders in light and dark (token-based
palette switched by ``prefers-color-scheme``). Honesty rules enforced here:

- every number on the page derives from the findings list — nothing else;
- the readiness-score formula is printed next to the score;
- low-confidence findings are visibly badged;
- accepted risks stay on the page with their reasons — an inventory that
  hides things is not an inventory;
- the methodology/limitations footer states what static analysis cannot see.
"""

from __future__ import annotations

import html

from lattice.core.models import CBOM, Confidence, Finding, Priority
from lattice.core.severity import readiness_score

_PRIORITY_LABELS = {
    Priority.P0: "P0 · act now",
    Priority.P1: "P1 · migrate before quantum",
    Priority.P2: "P2 · plan migration",
    Priority.P3: "P3 · monitor",
    Priority.NONE: "Compliant / informational",
}

_PRIORITY_CLASS = {
    Priority.P0: "p0",
    Priority.P1: "p1",
    Priority.P2: "p2",
    Priority.P3: "p3",
    Priority.NONE: "ok",
}

_CSS = """
:root {
  color-scheme: light dark;
  --bg: #f4f5f7; --surface: #ffffff; --surface-2: #eceef2;
  --text: #1b1d22; --muted: #5b5e66; --border: #dcdee4; --line: #ebedf1;
  --accent: #24425f; --link: #1d4f8b;
  --p0: #b3261e; --p1: #b35c00; --p2: #8a6d00; --p3: #4a6fa5; --ok: #24704a;
  --badge-text: #ffffff; --snippet-bg: #f0f1f4;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #16181d; --surface: #1f2229; --surface-2: #262a33;
    --text: #e6e7ea; --muted: #9a9da6; --border: #33373f; --line: #2b2f37;
    --accent: #8fb4d9; --link: #7fb0e8;
    --p0: #e5675f; --p1: #e09b4a; --p2: #cbb04a; --p3: #7d9fc9; --ok: #5bab7f;
    --badge-text: #16181d; --snippet-bg: #14161b;
  }
}
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       margin: 0; background: var(--bg); color: var(--text); line-height: 1.55; }
.wrap { max-width: 1080px; margin: 0 auto; padding: 32px 24px 64px; }
header { border-bottom: 3px solid var(--accent); padding-bottom: 16px; margin-bottom: 28px; }
header h1 { margin: 0 0 4px; font-size: 27px; letter-spacing: 0.3px; text-wrap: balance; }
header .meta { color: var(--muted); font-size: 14px; }
h2 { font-size: 20px; margin: 40px 0 12px; border-bottom: 1px solid var(--border);
     padding-bottom: 6px; }
h3 { font-size: 16px; margin: 26px 0 8px; }
.cards { display: flex; flex-wrap: wrap; gap: 12px; margin: 16px 0; }
.card { flex: 1 1 140px; background: var(--surface); border: 1px solid var(--border);
        border-radius: 8px; padding: 14px 16px; }
.card .num { font-size: 30px; font-weight: 700; font-variant-numeric: tabular-nums; }
.card .lbl { font-size: 12.5px; color: var(--muted); }
.score { display: flex; gap: 24px; align-items: center; background: var(--surface);
         border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
.score .value { font-size: 56px; font-weight: 800; font-variant-numeric: tabular-nums; }
.score .explain { font-size: 13.5px; color: var(--muted); max-width: 640px; }
.headline { margin: 16px 0; padding: 14px 16px; background: var(--surface);
            border-left: 4px solid var(--p0); border-radius: 4px; font-size: 15px; }
.headline.ok { border-left-color: var(--ok); }
table { width: 100%; border-collapse: collapse; background: var(--surface);
        font-size: 13.5px; }
.tablewrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 8px; }
th { text-align: left; padding: 9px 12px; background: var(--surface-2); font-size: 12px;
     text-transform: uppercase; letter-spacing: 0.4px; color: var(--muted); }
td { padding: 9px 12px; border-top: 1px solid var(--line); vertical-align: top; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 10px;
         color: var(--badge-text); font-size: 11.5px; font-weight: 700;
         white-space: nowrap; }
.badge.p0 { background: var(--p0); } .badge.p1 { background: var(--p1); }
.badge.p2 { background: var(--p2); } .badge.p3 { background: var(--p3); }
.badge.ok { background: var(--ok); }
.num.p0 { color: var(--p0); } .num.p1 { color: var(--p1); }
.num.p2 { color: var(--p2); } .num.p3 { color: var(--p3); } .num.ok { color: var(--ok); }
.conf-low { background: color-mix(in srgb, var(--p1) 14%, var(--surface));
            color: var(--p1); border: 1px solid var(--p1); padding: 1px 7px;
            border-radius: 10px; font-size: 11px; white-space: nowrap; }
.conf-medium, .conf-high { color: var(--muted); font-size: 12px; }
code, .snippet { font-family: ui-monospace, Consolas, "Courier New", monospace;
                 font-size: 12.5px; }
.snippet { display: block; background: var(--snippet-bg); border-radius: 4px;
           padding: 6px 9px; margin-top: 6px; overflow-x: auto; white-space: pre;
           color: var(--muted); }
.finding { background: var(--surface); border: 1px solid var(--border);
           border-radius: 8px; padding: 14px 16px; margin: 10px 0; }
.finding .title { font-weight: 700; }
.finding .where { color: var(--muted); font-size: 13px; }
.finding .just { margin: 6px 0 0; font-size: 13.5px; }
.finding .fix { margin: 6px 0 0; font-size: 13.5px; color: var(--link); }
.finding.accepted { border-style: dashed; opacity: 0.9; }
.accept-tag { display: inline-block; border: 1px solid var(--ok); color: var(--ok);
              border-radius: 10px; padding: 1px 8px; font-size: 11.5px;
              font-weight: 700; white-space: nowrap; }
footer { margin-top: 48px; font-size: 13px; color: var(--muted);
         border-top: 1px solid var(--border); padding-top: 16px; }
footer ul { padding-left: 18px; }
@media (prefers-reduced-motion: no-preference) {
  .card, .finding { transition: border-color 120ms ease; }
}
"""


def _e(text: str) -> str:
    return html.escape(str(text), quote=True)


def _badge(priority: Priority) -> str:
    label = priority.value if priority != Priority.NONE else "ok"
    return f'<span class="badge {_PRIORITY_CLASS[priority]}">{_e(label)}</span>'


def _confidence(finding: Finding) -> str:
    c = finding.asset.confidence
    if c == Confidence.LOW:
        return '<span class="conf-low">low confidence</span>'
    return f'<span class="conf-{c.value}">{_e(c.value)}</span>'


def _location(finding: Finding) -> str:
    return f"{finding.asset.file_path}:{finding.asset.line_number}"


def _algorithm_label(finding: Finding) -> str:
    asset = finding.asset
    label = asset.algorithm
    if asset.mode:
        label += f" / {asset.mode}"
    if asset.key_size and str(asset.key_size) not in asset.algorithm:
        label += f" ({asset.key_size}-bit)"
    if asset.curve:
        label += f" ({asset.curve})"
    return label


def emit(cbom: CBOM) -> str:
    """Render the complete self-contained HTML report."""
    findings = cbom.sorted_findings()
    counts = cbom.priority_counts()
    score = readiness_score(findings)
    accepted = [f for f in findings if f.accepted_reason is not None]
    active = [f for f in findings if f.accepted_reason is None]
    hndl_count = sum(1 for f in active if f.assessment.hndl_relevant)
    low_conf = sum(1 for f in findings if f.asset.confidence == Confidence.LOW)
    actionable = [f for f in active if f.assessment.priority != Priority.NONE]

    parts: list[str] = []
    parts.append(
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>Lattice report — {_e(cbom.target)}</title>"
        f'<style>{_CSS}</style></head><body><div class="wrap">'
    )

    # -- header ---------------------------------------------------------------
    parts.append(
        "<header><h1>Lattice — Cryptographic Bill of Materials</h1>"
        f'<div class="meta">Target: <code>{_e(cbom.target)}</code> · '
        f"Generated: {_e(cbom.generated_at)} · Lattice v{_e(cbom.tool_version)} · "
        f"{cbom.stats.files_scanned} files scanned"
        + (f", {cbom.stats.files_skipped} skipped" if cbom.stats.files_skipped else "")
        + "</div></header>"
    )

    # -- executive summary -------------------------------------------------------
    parts.append("<h2>Executive summary</h2>")
    parts.append(
        f'<div class="score"><div class="value">{score}<span style="font-size:22px">/100</span></div>'
        '<div class="explain"><strong>Post-quantum readiness score.</strong> '
        "Computed as 100 × (1 − severity-weighted share of findings), weights "
        "P0=1.0, P1=0.6, P2=0.3, P3=0.1, compliant=0; findings accepted in "
        "lattice.toml are excluded. It measures the composition of the "
        "cryptography Lattice could see — it is not a probability of "
        "compromise, and it cannot account for code static analysis cannot see."
        "</div></div>"
    )
    parts.append('<div class="cards">')
    for priority in (Priority.P0, Priority.P1, Priority.P2, Priority.P3, Priority.NONE):
        parts.append(
            f'<div class="card"><div class="num {_PRIORITY_CLASS[priority]}">'
            f'{counts[priority]}</div><div class="lbl">{_e(_PRIORITY_LABELS[priority])}</div></div>'
        )
    parts.append("</div>")

    if hndl_count:
        parts.append(
            f'<div class="headline">{hndl_count} quantum-vulnerable key-establishment or '
            "asymmetric-encryption usage(s) create <strong>harvest-now-decrypt-later</strong> "
            "exposure: traffic captured today can be decrypted once a cryptographically "
            "relevant quantum computer exists. These are the P0 migration targets "
            "(ML-KEM, NIST FIPS 203).</div>"
        )
    else:
        parts.append(
            '<div class="headline ok">No harvest-now-decrypt-later exposure detected '
            "in the code Lattice could analyze.</div>"
        )
    if low_conf:
        parts.append(
            f"<p><em>{low_conf} finding(s) are marked <strong>low confidence</strong> "
            "(token-level matches). Verify them manually before acting.</em></p>"
        )
    if accepted:
        parts.append(
            f"<p><em>{len(accepted)} finding(s) are <strong>accepted risks</strong> "
            "(lattice.toml) — visible below with their reasons, excluded from the "
            "score and the CI gate.</em></p>"
        )

    # -- prioritized findings table -------------------------------------------------
    parts.append("<h2>Prioritized findings</h2>")
    if actionable:
        parts.append(
            '<div class="tablewrap"><table><thead><tr>'
            "<th>Priority</th><th>Algorithm</th><th>Location</th><th>Quantum</th>"
            "<th>Classical</th><th>Confidence</th><th>Remediation</th></tr></thead><tbody>"
        )
        for finding in actionable:
            remediation = finding.assessment.pqc_replacement or "-"
            parts.append(
                "<tr>"
                f"<td>{_badge(finding.assessment.priority)}</td>"
                f"<td><strong>{_e(_algorithm_label(finding))}</strong></td>"
                f"<td><code>{_e(_location(finding))}</code></td>"
                f"<td>{_e(finding.assessment.quantum_status.value)}</td>"
                f"<td>{_e(finding.assessment.classical_status.value)}</td>"
                f"<td>{_confidence(finding)}</td>"
                f"<td>{_e(remediation)}</td></tr>"
            )
        parts.append("</tbody></table></div>")
    else:
        parts.append(
            "<p>No actionable findings — everything detected is quantum-resistant "
            "and classically secure.</p>"
        )

    # -- per-detector breakdown ---------------------------------------------------
    parts.append("<h2>Breakdown by detector</h2>")
    by_detector: dict[str, list[Finding]] = {}
    for finding in findings:
        by_detector.setdefault(finding.asset.detector, []).append(finding)
    parts.append(
        '<div class="tablewrap"><table><thead><tr><th>Detector</th><th>Assets</th>'
        "<th>Worst priority</th></tr></thead><tbody>"
    )
    for detector in sorted(by_detector):
        group = by_detector[detector]
        worst = min(group, key=lambda f: f.assessment.priority.rank).assessment.priority
        parts.append(
            f"<tr><td>{_e(detector)}</td><td>{len(group)}</td><td>{_badge(worst)}</td></tr>"
        )
    parts.append("</tbody></table></div>")

    # -- full findings ---------------------------------------------------------------
    parts.append("<h2>All findings</h2>")
    for priority in (Priority.P0, Priority.P1, Priority.P2, Priority.P3, Priority.NONE):
        group = [f for f in active if f.assessment.priority == priority]
        if not group:
            continue
        parts.append(f"<h3>{_e(_PRIORITY_LABELS[priority])} ({len(group)})</h3>")
        for finding in group:
            parts.append(_finding_card(finding))

    if accepted:
        parts.append(f"<h2>Accepted risks ({len(accepted)})</h2>")
        parts.append(
            "<p>These findings matched an acceptance in <code>lattice.toml</code>. "
            "They remain part of the inventory; the acceptance reason is the audit "
            "trail.</p>"
        )
        for finding in accepted:
            parts.append(_finding_card(finding))

    # -- methodology & limitations ------------------------------------------------------
    parts.append(
        "<footer><strong>Methodology &amp; limitations.</strong>"
        "<ul>"
        "<li>Every finding traces to a concrete matched pattern at a real file and line; "
        "Lattice reports nothing it did not match.</li>"
        "<li>Priorities: classically broken crypto (MD5, SHA-1, DES, RC4, ECB usage) is P0 "
        "regardless of quantum risk; Shor-broken key establishment/asymmetric encryption is "
        "P0 via harvest-now-decrypt-later; Shor-broken signatures are P1; deprecated or "
        "Grover-weakened primitives are P2; usable-but-not-preferred hashes are P3.</li>"
        "<li>The HNDL rule is a heuristic about families of usage; it cannot see what data "
        "a given call actually protects.</li>"
        "<li>Static analysis cannot see dynamically selected algorithms, runtime key sizes, "
        "or dead code. Regex-based detectors (Java, JavaScript, C/C++, C#, Rust, configs) "
        "can produce false positives — confidence levels are marked per finding.</li>"
        "<li>A CBOM is an inventory, not a proof of correct usage. Correctly-chosen "
        "algorithms can still be used unsafely in ways this tool does not evaluate.</li>"
        "<li>Private-key material is reported by location and type only; key bytes are "
        "never read into this report.</li>"
        "</ul></footer>"
    )

    parts.append("</div></body></html>")
    return "".join(parts) + "\n"


def _finding_card(finding: Finding) -> str:
    asset = finding.asset
    accepted = finding.accepted_reason is not None
    pieces = [f'<div class="finding{" accepted" if accepted else ""}">']
    tag = '<span class="accept-tag">accepted</span> ' if accepted else ""
    pieces.append(
        f'<div class="title">{tag}{_badge(finding.assessment.priority)} '
        f"{_e(_algorithm_label(finding))} {_confidence(finding)}</div>"
    )
    pieces.append(
        f'<div class="where"><code>{_e(_location(finding))}</code> · '
        f"detector: {_e(asset.detector)}</div>"
    )
    pieces.append(f'<div class="just">{_e(finding.assessment.justification)}</div>')
    if finding.accepted_reason is not None:
        pieces.append(
            f'<div class="just"><strong>Accepted:</strong> {_e(finding.accepted_reason)}</div>'
        )
    if finding.assessment.pqc_replacement:
        pieces.append(
            f'<div class="fix">Remediation: {_e(finding.assessment.pqc_replacement)}</div>'
        )
    if asset.note:
        pieces.append(f'<div class="just"><em>{_e(asset.note)}</em></div>')
    if asset.snippet:
        pieces.append(f'<span class="snippet">{_e(asset.snippet)}</span>')
    pieces.append("</div>")
    return "".join(pieces)
