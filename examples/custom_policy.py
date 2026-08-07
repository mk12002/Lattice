"""Define and evaluate a custom compliance policy pack.

A policy is pure data: a name, an allowed set of canonical algorithm names, a
mandatory honesty caveat, and (optionally) the families it governs. This shows a
"modern baseline" pack that permits ChaCha20 (which CNSA 2.0 does not).

Run:  python examples/custom_policy.py [PATH]
"""

from __future__ import annotations

import sys
from pathlib import Path

from lattice.core.engine import scan
from lattice.core.policy import Policy
from lattice.detectors.registry import all_detectors

ORG_BASELINE = Policy(
    name="Org Modern Baseline",
    description="Permits AES-256, ChaCha20, SHA-2/3, EdDSA, Argon2, and the PQC set.",
    allowed=frozenset(
        {
            "AES-256",
            "CHACHA20",
            "SHA-256",
            "SHA-384",
            "SHA-512",
            "SHA-3",
            "EDDSA",
            "ARGON2",
            "ML-KEM",
            "ML-DSA",
            "SLH-DSA",
        }
    ),
    caveat=(
        "Permits classical EdDSA during migration; checks algorithm names only, "
        "not parameters or usage. Not a compliance certification."
    ),
)


def main() -> int:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tests/fixtures")
    cbom = scan(target, all_detectors())
    violations = ORG_BASELINE.evaluate(cbom.sorted_findings())

    if not violations:
        print(f"{ORG_BASELINE.name}: no detected algorithm outside the allowed set")
        print(f"  note: {ORG_BASELINE.caveat}")
        return 0
    print(f"{ORG_BASELINE.name}: {len(violations)} algorithm(s) outside the allowed set")
    for v in violations:
        print(f"  - {v.message}")
    print(f"  note: {ORG_BASELINE.caveat}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
