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

#: default families a policy judges (effective family, i.e. usage context wins)
_DEFAULT_POLICY_FAMILIES = frozenset(
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
    """A named allowlist profile.

    ``families`` is the set of cryptographic families this profile actually
    governs; findings in other families are out of scope (flagging them would
    overclaim). It defaults to ciphers/asymmetric/signature/key-exchange/hash
    — a profile that governs only a subset can narrow it.
    """

    name: str
    description: str
    allowed: frozenset[str]
    caveat: str
    families: frozenset[Family] = _DEFAULT_POLICY_FAMILIES

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
            if family not in self.families:
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
    allowed=frozenset({"AES-256", "SHA-384", "SHA-512", "ML-KEM", "ML-DSA", "SLH-DSA"}),
    caveat=(
        "Parameter sets (e.g. ML-KEM-1024, ML-DSA-87) and correct usage are "
        "not statically verifiable; an empty violation list means the "
        "detected algorithms are in the suite, not that the system is "
        "certified compliant."
    ),
)

#: CNSA 1.0 — the pre-quantum NSA suite (still in force for many systems until
#: the CNSA 2.0 transition completes). Classical algorithms only: AES-256,
#: SHA-384, and ECC at P-384 / RSA-3072. Note this suite is *not* quantum-safe
#: by construction — it predates the PQC standards — so an all-CNSA-1.0 codebase
#: still carries harvest-now-decrypt-later exposure (which the severity model
#: flags independently). Parameter sets (P-384, RSA-3072) are not statically
#: verifiable.
CNSA1 = Policy(
    name="CNSA 1.0",
    description=(
        "NSA Commercial National Security Algorithm Suite 1.0 (pre-quantum): "
        "AES-256, SHA-384, ECDH/ECDSA at P-384, RSA-3072, DH-3072"
    ),
    allowed=frozenset({"AES-256", "SHA-384", "ECDH", "ECDSA", "RSA", "DH"}),
    caveat=(
        "CNSA 1.0 is pre-quantum: compliance here does NOT mean quantum-safe "
        "(the suite's ECC/RSA are Shor-broken — see the severity findings). "
        "Parameter sets (P-384, RSA-3072) and correct usage are not statically "
        "verifiable."
    ),
)

#: FIPS 140 approved algorithms (illustrative, not exhaustive): the primitives a
#: FIPS 140-validated module may use. Broader than CNSA — permits AES at all
#: sizes, the SHA-2/SHA-3 families, HMAC, and approved public-key/PQC schemes.
#: Governs ciphers/hashes/signatures/key-exchange *and* MACs.
FIPS140 = Policy(
    name="FIPS 140 (approved algorithms)",
    description=(
        "Illustrative FIPS 140 approved-algorithm allowlist: AES (128/192/256), "
        "SHA-2/SHA-3 families, HMAC, RSA/ECDSA/EdDSA/DSA, DH/ECDH, ML-KEM/ML-DSA/SLH-DSA. "
        "Excludes MD5, SHA-1, DES, RC4, 3DES, Blowfish, RC2."
    ),
    allowed=frozenset(
        {
            "AES",
            "AES-128",
            "AES-192",
            "AES-256",
            "SHA-256",
            "SHA-384",
            "SHA-512",
            "SHA-3",
            "HMAC",
            "RSA",
            "ECDSA",
            "EDDSA",
            "DSA",
            "DH",
            "ECDH",
            "ML-KEM",
            "ML-DSA",
            "SLH-DSA",
        }
    ),
    caveat=(
        "Illustrative allowlist of approved *algorithms* only — it is not a FIPS "
        "140 validation, which requires a certified module, approved modes, and "
        "correct usage that static analysis cannot verify. Approved algorithms "
        "like RSA/ECDSA are still Shor-broken (see severity findings)."
    ),
    families=frozenset(
        {
            Family.SYMMETRIC_CIPHER,
            Family.ASYMMETRIC_CIPHER,
            Family.SIGNATURE,
            Family.KEY_EXCHANGE,
            Family.HASH,
            Family.MAC,
        }
    ),
)

POLICIES: dict[str, Policy] = {"cnsa2": CNSA2, "cnsa1": CNSA1, "fips140": FIPS140}
