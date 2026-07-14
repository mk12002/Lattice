"""Self-contained HTML report emitter.

One file, inline CSS, zero external requests (no CDN, no fonts, no images).
Designed to be read by a CISO first and an engineer second: executive
summary up top, detail below. Honesty rules enforced here:

- every number on the page derives from the findings list — nothing else;
- the readiness-score formula is printed next to the score;
- low-confidence findings are visibly badged;
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

_PRIORITY_COLORS = {
    Priority.P0: "#b3261e",
    Priority.P1: "#c4620a",
    Priority.P2: "#9a7b00",
    Priority.P3: "#4a6fa5",
    Priority.NONE: "#2d7a46",
}

_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       margin: 0; background: #f6f7f9; color: #1c1d21; line-height: 1.5; }
.wrap { max-width: 1080px; margin: 0 auto; padding: 32px 24px 64px; }
header { border-bottom: 3px solid #1c1d21; padding-bottom: 16px; margin-bottom: 28px; }
header h1 { margin: 0 0 4px; font-size: 28px; letter-spacing: 0.5px; }
header .meta { color: #55575e; font-size: 14px; }
h2 { font-size: 20px; margin: 40px 0 12px; border-bottom: 1px solid #d7d9de; padding-bottom: 6px; }
.cards { display: flex; flex-wrap: wrap; gap: 12px; margin: 16px 0; }
.card { flex: 1 1 140px; background: #fff; border: 1px solid #e0e2e7; border-radius: 8px;
        padding: 14px 16px; }
.card .num { font-size: 30px; font-weight: 700; }
.card .lbl { font-size: 12.5px; color: #55575e; }
.score { display: flex; gap: 24px; align-items: center; background: #fff;
         border: 1px solid #e0e2e7; border-radius: 8px; padding: 20px; }
.score .value { font-size: 56px; font-weight: 800; }
.score .explain { font-size: 13.5px; color: #55575e; max-width: 640px; }
.headline { margin: 16px 0; padding: 14px 16px; background: #fff; border-left: 4px solid #b3261e;
            border-radius: 4px; font-size: 15px; }
.headline.ok { border-left-color: #2d7a46; }
table { width: 100%; border-collapse: collapse; background: #fff; font-size: 13.5px; }
.tablewrap { overflow-x: auto; border: 1px solid #e0e2e7; border-radius: 8px; }
th { text-align: left; padding: 9px 12px; background: #eef0f3; font-size: 12px;
     text-transform: uppercase; letter-spacing: 0.4px; color: #44464c; }
td { padding: 9px 12px; border-top: 1px solid #edeef2; vertical-align: top; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 10px; color: #fff;
         font-size: 11.5px; font-weight: 700; white-space: nowrap; }
.conf-low { background: #fdf3e7; color: #8a5a00; border: 1px solid #e8c98f;
            padding: 1px 7px; border-radius: 10px; font-size: 11px; white-space: nowrap; }
.conf-medium { color: #55575e; font-size: 12px; }
.conf-high { color: #55575e; font-size: 12px; }
code, .snippet { font-family: ui-monospace, Consolas, "Courier New", monospace; font-size: 12.5px; }
.snippet { display: block; background: #f2f3f6; border-radius: 4px; padding: 6px 9px;
           margin-top: 6px; overflow-x: auto; white-space: pre; color: #3c3e44; }
.finding { background: #fff; border: 1px solid #e0e2e7; border-radius: 8px;
           padding: 14px 16px; margin: 10px 0; }
.finding .title { font-weight: 700; }
.finding .where { color: #55575e; font-size: 13px; }
.finding .just { margin: 6px 0 0; font-size: 13.5px; }
.finding .fix { margin: 6px 0 0; font-size: 13.5px; color: #1d4f8b; }
footer { margin-top: 48px; font-size: 13px; color: #55575e; border-top: 1px solid #d7d9de;
         padding-top: 16px; }
footer ul { padding-left: 18px; }
"""


def _e(text: str) -> str:
    return html.escape(str(text), quote=True)


def _badge(priority: Priority) -> str:
    return (
        f'<span class="badge" style="background:{_PRIORITY_COLORS[priority]}">'
        f"{_e(priority.value if priority != Priority.NONE else 'ok')}</span>"
    )


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
    hndl_count = sum(1 for f in findings if f.assessment.hndl_relevant)
    low_conf = sum(1 for f in findings if f.asset.confidence == Confidence.LOW)
    actionable = [f for f in findings if f.assessment.priority != Priority.NONE]

    parts: list[str] = []
    parts.append(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>Lattice report — {_e(cbom.target)}</title>"
        f"<style>{_CSS}</style></head><body><div class=\"wrap\">"
    )

    # -- header ---------------------------------------------------------------
    parts.append(
        "<header><h1>Lattice — Cryptographic Bill of Materials</h1>"
        f"<div class=\"meta\">Target: <code>{_e(cbom.target)}</code> · "
        f"Generated: {_e(cbom.generated_at)} · Lattice v{_e(cbom.tool_version)} · "
        f"{cbom.stats.files_scanned} files scanned"
        + (f", {cbom.stats.files_skipped} skipped" if cbom.stats.files_skipped else "")
        + "</div></header>"
    )

    # -- executive summary -------------------------------------------------------
    parts.append("<h2>Executive summary</h2>")
    parts.append(
        f"<div class=\"score\"><div class=\"value\">{score}<span style=\"font-size:22px\">/100</span></div>"
        "<div class=\"explain\"><strong>Post-quantum readiness score.</strong> "
        "Computed as 100 × (1 − severity-weighted share of findings), weights "
        "P0=1.0, P1=0.6, P2=0.3, P3=0.1, compliant=0. It measures the composition "
        "of the cryptography Lattice could see — it is not a probability of "
        "compromise, and it cannot account for code static analysis cannot see."
        "</div></div>"
    )
    parts.append("<div class=\"cards\">")
    for priority in (Priority.P0, Priority.P1, Priority.P2, Priority.P3, Priority.NONE):
        parts.append(
            f"<div class=\"card\"><div class=\"num\" style=\"color:{_PRIORITY_COLORS[priority]}\">"
            f"{counts[priority]}</div><div class=\"lbl\">{_e(_PRIORITY_LABELS[priority])}</div></div>"
        )
    parts.append("</div>")

    if hndl_count:
        parts.append(
            f"<div class=\"headline\">{hndl_count} quantum-vulnerable key-establishment or "
            "asymmetric-encryption usage(s) create <strong>harvest-now-decrypt-later</strong> "
            "exposure: traffic captured today can be decrypted once a cryptographically "
            "relevant quantum computer exists. These are the P0 migration targets "
            "(ML-KEM, NIST FIPS 203).</div>"
        )
    else:
        parts.append(
            "<div class=\"headline ok\">No harvest-now-decrypt-later exposure detected "
            "in the code Lattice could analyze.</div>"
        )
    if low_conf:
        parts.append(
            f"<p><em>{low_conf} finding(s) are marked <strong>low confidence</strong> "
            "(token-level matches). Verify them manually before acting.</em></p>"
        )

    # -- prioritized findings table -------------------------------------------------
    parts.append("<h2>Prioritized findings</h2>")
    if actionable:
        parts.append(
            "<div class=\"tablewrap\"><table><thead><tr>"
            "<th>Priority</th><th>Algorithm</th><th>Location</th><th>Quantum</th>"
            "<th>Classical</th><th>Confidence</th><th>Remediation</th></tr></thead><tbody>"
        )
        for finding in actionable:
            remediation = finding.assessment.pqc_replacement or "—"
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
        parts.append("<p>No actionable findings — everything detected is quantum-resistant "
                     "and classically secure.</p>")

    # -- per-detector breakdown ---------------------------------------------------
    parts.append("<h2>Breakdown by detector</h2>")
    by_detector: dict[str, list[Finding]] = {}
    for finding in findings:
        by_detector.setdefault(finding.asset.detector, []).append(finding)
    parts.append(
        "<div class=\"tablewrap\"><table><thead><tr><th>Detector</th><th>Assets</th>"
        "<th>Worst priority</th></tr></thead><tbody>"
    )
    for detector in sorted(by_detector):
        group = by_detector[detector]
        worst = min(group, key=lambda f: f.assessment.priority.rank).assessment.priority
        parts.append(
            f"<tr><td>{_e(detector)}</td><td>{len(group)}</td>"
            f"<td>{_badge(worst)}</td></tr>"
        )
    parts.append("</tbody></table></div>")

    # -- full findings ---------------------------------------------------------------
    parts.append("<h2>All findings</h2>")
    for priority in (Priority.P0, Priority.P1, Priority.P2, Priority.P3, Priority.NONE):
        group = [f for f in findings if f.assessment.priority == priority]
        if not group:
            continue
        parts.append(f"<h3>{_e(_PRIORITY_LABELS[priority])} ({len(group)})</h3>")
        for finding in group:
            asset = finding.asset
            parts.append("<div class=\"finding\">")
            parts.append(
                f"<div class=\"title\">{_badge(priority)} {_e(_algorithm_label(finding))} "
                f"{_confidence(finding)}</div>"
            )
            parts.append(
                f"<div class=\"where\"><code>{_e(_location(finding))}</code> · "
                f"detector: {_e(asset.detector)}</div>"
            )
            parts.append(f"<div class=\"just\">{_e(finding.assessment.justification)}</div>")
            if finding.assessment.pqc_replacement:
                parts.append(
                    f"<div class=\"fix\">Remediation: {_e(finding.assessment.pqc_replacement)}</div>"
                )
            if asset.note:
                parts.append(f"<div class=\"just\"><em>{_e(asset.note)}</em></div>")
            if asset.snippet:
                parts.append(f"<span class=\"snippet\">{_e(asset.snippet)}</span>")
            parts.append("</div>")

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
        "or dead code. Regex-based detectors (Java, JavaScript, C/C++, configs) can produce "
        "false positives — confidence levels are marked per finding.</li>"
        "<li>A CBOM is an inventory, not a proof of correct usage. Correctly-chosen "
        "algorithms can still be used unsafely in ways this tool does not evaluate.</li>"
        "<li>Private-key material is reported by location and type only; key bytes are "
        "never read into this report.</li>"
        "</ul></footer>"
    )

    parts.append("</div></body></html>")
    return "".join(parts) + "\n"
