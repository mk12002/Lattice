"""Policy packs: evaluate a scan against a named compliance profile.

v0.2 ships one profile, ``cnsa2`` — the NSA Commercial National Security
Algorithm Suite 2.0 (referenced by name; parameter-set requirements are
noted where static analysis cannot verify them). A policy violation is not
a new severity judgment: it says "this algorithm is not in the profile's
allowed set", nothing more.

Policies deliberately evaluate only algorithm findings in the primitive
families the profile actually specifies (ciphers, hashes, signatures, key
establishment). Library inventory, MACs/KDFs built on approved hashes, and
unparseable material are out of scope — flagging them would overclaim.
"""

from __future__ import annotations

from dataclasses import dataclass

from lattice.core.models import Family, Finding
from lattice.rules.algorithms import lookup

#: families a policy judges (effective family, i.e. usage context wins)
_POLICY_FAMILIES = frozenset(
    {
        Family.SYMMETRIC_CIPHER,
        Family.ASYMMETRIC_CIPHER,
        Family.SIGNATURE,
        Family.KEY_EXCHANGE,
        Family.HASH,
    }
)


@dataclass(frozen=True)
class PolicyViolation:
    """One finding that falls outside the policy's allowed algorithm set."""

    finding: Finding
    message: str


@dataclass(frozen=True)
class Policy:
    """A named allowlist profile."""

    name: str
    description: str
    allowed: frozenset[str]
    caveat: str

    def evaluate(self, findings: list[Finding]) -> list[PolicyViolation]:
        """Violations, in the findings' (already deterministic) order."""
        violations: list[PolicyViolation] = []
        for finding in findings:
            if finding.accepted_reason is not None:
                continue  # consciously accepted risks are gated by lattice.toml
            family = finding.asset.usage_family
            if family is None:
                info = lookup(finding.asset.algorithm)
                family = info.family if info else None
            if family not in _POLICY_FAMILIES:
                continue
            if finding.asset.algorithm in self.allowed:
                continue
            violations.append(
                PolicyViolation(
                    finding=finding,
                    message=(
                        f"{finding.asset.algorithm} at "
                        f"{finding.asset.file_path}:{finding.asset.line_number} "
                        f"is not in the {self.name} algorithm set"
                    ),
                )
            )
        return violations


#: CNSA 2.0 (NSA, for National Security Systems): AES-256, SHA-384/SHA-512,
#: ML-KEM (FIPS 203), ML-DSA (FIPS 204), and hash-based signatures. Lattice
#: cannot statically verify parameter sets (ML-KEM-1024 / ML-DSA-87), which
#: the caveat states in every policy report.
CNSA2 = Policy(
    name="CNSA 2.0",
    description=(
        "NSA Commercial National Security Algorithm Suite 2.0 allowed set: "
        "AES-256, SHA-384/SHA-512, ML-KEM, ML-DSA, and stateful/stateless "
        "hash-based signatures"
    ),
    allowed=frozenset(
        {"AES-256", "SHA-384", "SHA-512", "ML-KEM", "ML-DSA", "SLH-DSA"}
    ),
    caveat=(
        "Parameter sets (e.g. ML-KEM-1024, ML-DSA-87) and correct usage are "
        "not statically verifiable; an empty violation list means the "
        "detected algorithms are in the suite, not that the system is "
        "certified compliant."
    ),
)

POLICIES: dict[str, Policy] = {"cnsa2": CNSA2}
