"""Rust detector: RustCrypto crates, the openssl crate, and ring.

Two signal sources, both regex (MEDIUM confidence — Rust tolerates unused
``use`` items with only a warning, unlike Go):

1. ``use`` declarations of algorithm-named crates (RustCrypto's naming is
   highly regular: ``md5``, ``sha1``, ``aes_gcm``, ``chacha20poly1305``, ...).
2. Distinctive call-site tokens from the ``openssl`` crate
   (``Cipher::aes_128_ecb``, ``MessageDigest::md5``, ``Rsa::generate``) and
   ``ring`` (``ring::aead::AES_256_GCM``, ``ring::signature::ED25519``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import PurePath

from lattice.core.models import Confidence, CryptoAsset, Family
from lattice.detectors.base import Detector, make_snippet

#: crate name (as it appears in `use crate::...`) -> (algorithm, family, mode, curve)
_USE_MAP: dict[str, tuple[str, Family | None, str | None, str | None]] = {
    "md5": ("MD5", Family.HASH, None, None),
    "md-5": ("MD5", Family.HASH, None, None),
    "sha1": ("SHA-1", Family.HASH, None, None),
    "sha2": ("SHA-256", Family.HASH, None, None),
    "sha3": ("SHA-3", Family.HASH, None, None),
    "blake2": ("BLAKE2", Family.HASH, None, None),
    "blake3": ("BLAKE3", Family.HASH, None, None),
    "aes_gcm": ("AES", None, "GCM", None),
    "aes_gcm_siv": ("AES", None, "GCM-SIV", None),
    "aes_siv": ("AES", None, "SIV", None),
    "chacha20poly1305": ("CHACHA20", None, None, None),
    "chacha20": ("CHACHA20", None, None, None),
    "rsa": ("RSA", None, None, None),
    "dsa": ("DSA", Family.SIGNATURE, None, None),
    "ed25519_dalek": ("EDDSA", Family.SIGNATURE, None, None),
    "ed25519": ("EDDSA", Family.SIGNATURE, None, None),
    "x25519_dalek": ("ECDH", Family.KEY_EXCHANGE, None, None),
    "p256": ("ECDSA", None, None, "P-256"),
    "p384": ("ECDSA", None, None, "P-384"),
    "k256": ("ECDSA", None, None, "secp256k1"),
    "argon2": ("ARGON2", Family.KDF, None, None),
    "bcrypt": ("BCRYPT", Family.KDF, None, None),
    "scrypt": ("SCRYPT", Family.KDF, None, None),
    "pbkdf2": ("PBKDF2", Family.KDF, None, None),
    "hmac": ("HMAC", Family.MAC, None, None),
    "des": ("DES", None, None, None),
    "rc4": ("RC4", None, None, None),
    "blowfish": ("BLOWFISH", None, None, None),
    "ml_kem": ("ML-KEM", Family.KEY_EXCHANGE, None, None),
    "ml_dsa": ("ML-DSA", Family.SIGNATURE, None, None),
    "pqcrypto_mlkem": ("ML-KEM", Family.KEY_EXCHANGE, None, None),
    "pqcrypto_mldsa": ("ML-DSA", Family.SIGNATURE, None, None),
}

_USE_LINE = re.compile(r"^\s*(?:pub\s+)?use\s+([A-Za-z_][A-Za-z0-9_]*)\b")

#: openssl-crate tokens
_OPENSSL_CIPHER = re.compile(r"\bCipher::(aes|aria|camellia)_(\d+)_([a-z0-9_]+)\b")
_OPENSSL_SIMPLE = {
    re.compile(r"\bCipher::des_ede3\w*\b"): ("3DES", None, None),
    re.compile(r"\bCipher::des_\w+\b"): ("DES", None, None),
    re.compile(r"\bCipher::rc4\b"): ("RC4", None, None),
    re.compile(r"\bCipher::chacha20\w*\b"): ("CHACHA20", None, None),
    re.compile(r"\bMessageDigest::md5\b"): ("MD5", Family.HASH, None),
    re.compile(r"\bMessageDigest::sha1\b"): ("SHA-1", Family.HASH, None),
    re.compile(r"\bMessageDigest::sha256\b"): ("SHA-256", Family.HASH, None),
    re.compile(r"\bMessageDigest::sha384\b"): ("SHA-384", Family.HASH, None),
    re.compile(r"\bMessageDigest::sha512\b"): ("SHA-512", Family.HASH, None),
}
_OPENSSL_RSA_GENERATE = re.compile(r"\bRsa::generate\s*\(\s*(\d+)?")
_OPENSSL_EC_CURVE = re.compile(r"\bNid::(X9_62_PRIME256V1|SECP256K1|SECP384R1|SECP521R1)\b")

#: ring tokens
_RING = {
    re.compile(r"\bdigest::SHA1\w*\b"): ("SHA-1", Family.HASH, None),
    re.compile(r"\bdigest::SHA256\b"): ("SHA-256", Family.HASH, None),
    re.compile(r"\bdigest::SHA384\b"): ("SHA-384", Family.HASH, None),
    re.compile(r"\bdigest::SHA512\b"): ("SHA-512", Family.HASH, None),
    re.compile(r"\baead::AES_128_GCM\b"): ("AES-128", None, "GCM"),
    re.compile(r"\baead::AES_256_GCM\b"): ("AES-256", None, "GCM"),
    re.compile(r"\baead::CHACHA20_POLY1305\b"): ("CHACHA20", None, None),
    re.compile(r"\bagreement::X25519\b"): ("ECDH", Family.KEY_EXCHANGE, None),
    re.compile(r"\bagreement::ECDH_P256\b"): ("ECDH", Family.KEY_EXCHANGE, None),
    re.compile(r"\bagreement::ECDH_P384\b"): ("ECDH", Family.KEY_EXCHANGE, None),
    re.compile(r"\bsignature::ED25519\b"): ("EDDSA", Family.SIGNATURE, None),
    re.compile(r"\bsignature::ECDSA_P256\w*\b"): ("ECDSA", Family.SIGNATURE, None),
    re.compile(r"\bsignature::ECDSA_P384\w*\b"): ("ECDSA", Family.SIGNATURE, None),
    re.compile(r"\bsignature::RSA_PKCS1\w*\b"): ("RSA", Family.SIGNATURE, None),
    re.compile(r"\bsignature::RSA_PSS\w*\b"): ("RSA", Family.SIGNATURE, None),
    re.compile(r"\bpbkdf2::PBKDF2\w*\b"): ("PBKDF2", Family.KDF, None),
}


class RustDetector(Detector):
    """Regex detector for Rust sources using RustCrypto, openssl, or ring."""

    name = "rust"

    def applies_to(self, path: PurePath) -> bool:
        return path.suffix == ".rs"

    def detect(self, path: PurePath, content: str) -> Iterable[CryptoAsset]:
        lines = content.splitlines()
        seen: set[tuple[int, str, str | None]] = set()

        def emit(
            line: int,
            algorithm: str,
            *,
            key_size: int | None = None,
            curve: str | None = None,
            mode: str | None = None,
            usage_family: Family | None = None,
            note: str = "",
        ) -> Iterator[CryptoAsset]:
            key = (line, algorithm, mode)
            if key in seen:
                return
            seen.add(key)
            yield CryptoAsset(
                algorithm=algorithm,
                file_path=str(path),
                line_number=line,
                detector=self.name,
                confidence=Confidence.MEDIUM,
                snippet=make_snippet(lines, line),
                key_size=key_size,
                curve=curve,
                mode=mode,
                usage_family=usage_family,
                note=note,
            )

        for i, line_text in enumerate(lines, start=1):
            use = _USE_LINE.match(line_text)
            if use:
                crate = use.group(1)
                mapped = _USE_MAP.get(crate)
                if mapped:
                    algorithm, family, mode, curve = mapped
                    yield from emit(
                        i,
                        algorithm,
                        mode=mode,
                        curve=curve,
                        usage_family=family,
                        note=f"crate '{crate}' in use declaration",
                    )

            for m in _OPENSSL_CIPHER.finditer(line_text):
                base, bits, mode = m.group(1), int(m.group(2)), m.group(3).upper()
                if base == "aes" and bits in (128, 192, 256):
                    yield from emit(i, f"AES-{bits}", key_size=bits, mode=mode)
                elif base == "aes":
                    yield from emit(i, "AES", mode=mode)

            for pattern, (algorithm, family, mode) in {**_OPENSSL_SIMPLE, **_RING}.items():
                if pattern.search(line_text):
                    yield from emit(i, algorithm, mode=mode, usage_family=family)

            rsa = _OPENSSL_RSA_GENERATE.search(line_text)
            if rsa:
                key_size = int(rsa.group(1)) if rsa.group(1) else None
                yield from emit(i, "RSA", key_size=key_size)

            curve_match = _OPENSSL_EC_CURVE.search(line_text)
            if curve_match:
                yield from emit(i, "ECDSA", curve=curve_match.group(1))
