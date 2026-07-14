"""Fixture: quantum-safe symmetric crypto.

Known answers (exactly two assets):
- AES-256 in GCM mode at the AESGCM(key) call (key size inferred from
  generate_key(bit_length=256)) -> priority none, confidence high.
- CHACHA20 at the ChaCha20Poly1305(key) call -> priority none, confidence high.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def encrypt(data: bytes) -> bytes:
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)  # KNOWN: AES-256/GCM, compliant
    nonce = os.urandom(12)
    return nonce + aes.encrypt(nonce, data, None)


def stream_encrypt(data: bytes) -> bytes:
    key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(key)  # KNOWN: CHACHA20, compliant
    nonce = os.urandom(12)
    return nonce + chacha.encrypt(nonce, data, None)
