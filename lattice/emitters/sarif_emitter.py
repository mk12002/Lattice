"""SARIF 2.1.0 emitter for CI code-scanning integration.

Rule ids are ``LATTICE-<ALGORITHM>``; every result carries a physical
location (file + start line). Priorities map onto SARIF levels:
P0/P1 -> error, P2 -> warning, P3 -> note, compliant/informational -> none.
SARIF output contains no timestamp at all, so it is fully deterministic.
"""

from __future__ import annotations

import json

from lattice.core.models import CBOM, Finding, Priority
from lattice.rules.algorithms import lookup

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVELS: dict[Priority, str] = {
    Priority.P0: "error",
    Priority.P1: "error",
    Priority.P2: "warning",
    Priority.P3: "note",
    Priority.NONE: "none",
}


def _rule_id(finding: Finding) -> str:
    return "LATTICE-" + finding.asset.algorithm.upper().replace(" ", "-").replace("/", "-")


def _rule(finding: Finding) -> dict:
    info = lookup(finding.asset.algorithm)
    description = (
        info.notes
        if info
        else "Cryptographic component inventoried by Lattice (no knowledge-base judgment)."
    )
    rule: dict = {
        "id": _rule_id(finding),
        "name": finding.asset.algorithm,
        "shortDescription": {"text": f"Use of {finding.asset.algorithm}"},
        "fullDescription": {"text": description},
        "defaultConfiguration": {"level": _LEVELS[finding.assessment.priority]},
    }
    if finding.assessment.pqc_replacement:
        rule["help"] = {"text": f"Migration target: {finding.assessment.pqc_replacement}"}
    return rule


def _message(finding: Finding) -> str:
    parts = [finding.assessment.justification]
    if finding.assessment.pqc_replacement:
        parts.append(f"Replace with: {finding.assessment.pqc_replacement}.")
    parts.append(f"Confidence: {finding.asset.confidence.value}.")
    return " ".join(parts)


def _result(finding: Finding) -> dict:
    asset = finding.asset
    return {
        "ruleId": _rule_id(finding),
        "level": _LEVELS[finding.assessment.priority],
        "message": {"text": _message(finding)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": asset.file_path},
                    "region": {"startLine": max(asset.line_number, 1)},
                }
            }
        ],
        "properties": {
            "priority": finding.assessment.priority.value,
            "quantumStatus": finding.assessment.quantum_status.value,
            "classicalStatus": finding.assessment.classical_status.value,
            "hndl": finding.assessment.hndl_relevant,
            "confidence": asset.confidence.value,
            "detector": asset.detector,
        },
    }


def emit(cbom: CBOM) -> str:
    """Serialize the scan to a deterministic SARIF 2.1.0 document."""
    findings = cbom.sorted_findings()
    rules: dict[str, dict] = {}
    for finding in findings:
        rules.setdefault(_rule_id(finding), _rule(finding))
    document = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Lattice",
                        "version": cbom.tool_version,
                        "informationUri": "https://github.com/lattice-scanner/lattice",
                        "rules": [rules[k] for k in sorted(rules)],
                    }
                },
                "results": [_result(f) for f in findings],
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
