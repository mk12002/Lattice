"""CycloneDX-style CBOM JSON emitter.

Determinism contract: given the same findings, the emitted document is
byte-identical across runs except for the single ``metadata.timestamp``
field. Components are ordered by the canonical Finding sort key (priority,
path, line, algorithm) and all dicts are built in fixed insertion order.

Fields whose values Lattice cannot ground (e.g. ``classicalSecurityLevel``)
are omitted rather than guessed.
"""

from __future__ import annotations

import json

from lattice.core.models import CBOM, Family, Finding, Priority
from lattice.core.severity import readiness_score

#: family -> CycloneDX algorithmProperties.primitive
_PRIMITIVES: dict[Family, str] = {
    Family.SYMMETRIC_CIPHER: "block-cipher",
    Family.ASYMMETRIC_CIPHER: "pke",
    Family.SIGNATURE: "signature",
    Family.KEY_EXCHANGE: "key-agree",
    Family.HASH: "hash",
    Family.KDF: "kdf",
    Family.MAC: "mac",
    Family.RNG: "drbg",
    Family.PROTOCOL: "other",
    Family.KEY_MATERIAL: "other",
    Family.LIBRARY: "other",
}

#: algorithm-level primitive overrides where the family is too coarse
_PRIMITIVE_OVERRIDES = {
    "CHACHA20": "stream-cipher",
    "RC4": "stream-cipher",
    "ML-KEM": "kem",
}


def _primitive(finding: Finding) -> str:
    override = _PRIMITIVE_OVERRIDES.get(finding.asset.algorithm)
    if override:
        return override
    family = finding.asset.usage_family
    if family is None:
        from lattice.rules.algorithms import lookup

        info = lookup(finding.asset.algorithm)
        family = info.family if info else Family.LIBRARY
    return _PRIMITIVES[family]


def _parameter_set(finding: Finding) -> str | None:
    asset = finding.asset
    parts: list[str] = []
    if asset.key_size:
        parts.append(str(asset.key_size))
    if asset.curve:
        parts.append(asset.curve)
    if asset.mode:
        parts.append(asset.mode)
    return "/".join(parts) if parts else None


def _component(finding: Finding) -> dict:
    asset, assessment = finding.asset, finding.assessment
    if asset.usage_family == Family.LIBRARY:
        component: dict = {"type": "library", "name": asset.algorithm}
    else:
        algorithm_properties: dict = {"primitive": _primitive(finding)}
        parameter_set = _parameter_set(finding)
        if parameter_set:
            algorithm_properties["parameterSetIdentifier"] = parameter_set
        if asset.material == "certificate":
            asset_type = "certificate"
        elif asset.material is not None:
            asset_type = "related-crypto-material"
        elif asset.usage_family == Family.PROTOCOL:
            asset_type = "protocol"
        else:
            asset_type = "algorithm"
        component = {
            "type": "cryptographic-asset",
            "name": asset.algorithm,
            "cryptoProperties": {
                "assetType": asset_type,
                "algorithmProperties": algorithm_properties,
            },
        }
    component["evidence"] = {
        "occurrences": [{"location": asset.file_path, "line": asset.line_number}]
    }
    properties = [
        {"name": "lattice:quantumStatus", "value": assessment.quantum_status.value},
        {"name": "lattice:classicalStatus", "value": assessment.classical_status.value},
        {"name": "lattice:hndl", "value": "true" if assessment.hndl_relevant else "false"},
        {"name": "lattice:priority", "value": assessment.priority.value},
        {"name": "lattice:confidence", "value": asset.confidence.value},
        {"name": "lattice:justification", "value": assessment.justification},
        {"name": "lattice:detector", "value": asset.detector},
    ]
    if assessment.pqc_replacement:
        properties.append(
            {"name": "lattice:pqcReplacement", "value": assessment.pqc_replacement}
        )
    if asset.snippet:
        properties.append({"name": "lattice:snippet", "value": asset.snippet})
    if asset.note:
        properties.append({"name": "lattice:note", "value": asset.note})
    component["properties"] = properties
    return component


def emit(cbom: CBOM) -> str:
    """Serialize the CBOM to a deterministic CycloneDX-style JSON string."""
    findings = cbom.sorted_findings()
    counts = cbom.priority_counts()
    summary = " ".join(
        f"{p.value}={counts[p]}"
        for p in (Priority.P0, Priority.P1, Priority.P2, Priority.P3, Priority.NONE)
    )
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "timestamp": cbom.generated_at,
            "tools": [{"name": "Lattice", "version": cbom.tool_version}],
        },
        "components": [_component(f) for f in findings],
        "properties": [
            {"name": "lattice:readinessScore", "value": str(readiness_score(findings))},
            {"name": "lattice:summary", "value": summary},
            {"name": "lattice:filesScanned", "value": str(cbom.stats.files_scanned)},
            {"name": "lattice:filesSkipped", "value": str(cbom.stats.files_skipped)},
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
