"""Lattice: crypto-agility and post-quantum-readiness scanner.

Lattice statically analyzes a codebase, produces a Cryptographic Bill of
Materials (CBOM), grades each cryptographic usage for quantum vulnerability
and classical weakness, and emits a prioritized migration roadmap toward the
NIST post-quantum standards (FIPS 203/204/205).
"""

import logging

__version__ = "0.4.0"

# Library best practice: attach a NullHandler so importing Lattice as a library
# never emits log output unless the caller configures logging (the CLI does this
# under --verbose). Keeps default behaviour silent and deterministic.
logging.getLogger(__name__).addHandler(logging.NullHandler())
