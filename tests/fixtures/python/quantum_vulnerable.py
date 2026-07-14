"""Fixture: quantum-vulnerable key generation.

Known answers (exactly one asset):
- RSA (key_size=2048) at the generate_private_key call -> quantum broken,
  HNDL-relevant, priority P0, confidence high. Aliased from-import included
  deliberately.
"""

from cryptography.hazmat.primitives.asymmetric import rsa as rsa_keys


def make_key():
    return rsa_keys.generate_private_key(  # KNOWN: RSA 2048, P0 (HNDL)
        public_exponent=65537,
        key_size=2048,
    )
