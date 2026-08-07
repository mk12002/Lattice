"""C/C++ detector: OpenSSL/libcrypto EVP identifiers, mbedTLS, and libsodium.

Regex-based token matching (MEDIUM confidence): C call sites name their
algorithms in function identifiers (``EVP_aes_128_ecb``,
``mbedtls_sha1_starts``, ``crypto_sign_detached``), which regex reads
reliably; what it cannot see is dead code or macro indirection.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import PurePath

from lattice.core.models import Confidence, CryptoAsset, Family
from lattice.detectors.base import Detector, make_snippet

_EVP_CIPHER = re.compile(r"\bEVP_(aes|aria|camellia)_(\d+)_([a-z0-9]+)\b")
_EVP_SIMPLE = {
    re.compile(r"\bEVP_md5\b"): ("MD5", Family.HASH, None),
    re.compile(r"\bEVP_sha1\b"): ("SHA-1", Family.HASH, None),
    re.compile(r"\bEVP_sha224\b"): ("SHA-256", Family.HASH, None),
    re.compile(r"\bEVP_sha256\b"): ("SHA-256", Family.HASH, None),
    re.compile(r"\bEVP_sha384\b"): ("SHA-384", Family.HASH, None),
    re.compile(r"\bEVP_sha512\b"): ("SHA-512", Family.HASH, None),
    re.compile(r"\bEVP_sha3_\d+\b"): ("SHA-3", Family.HASH, None),
    re.compile(r"\bEVP_blake2[bs]\d*\b"): ("BLAKE2", Family.HASH, None),
    re.compile(r"\bEVP_chacha20_poly1305\b"): ("CHACHA20", None, None),
    re.compile(r"\bEVP_chacha20\b"): ("CHACHA20", None, None),
    re.compile(r"\bEVP_des_ede3?\w*\b"): ("3DES", None, None),
    re.compile(r"\bEVP_des_(?!ede)\w+\b"): ("DES", None, None),
    re.compile(r"\bEVP_rc4\w*\b"): ("RC4", None, None),
    re.compile(r"\bEVP_bf_\w+\b"): ("BLOWFISH", None, None),
}
_OPENSSL_LEGACY = {
    re.compile(r"\bMD5_(Init|Update|Final)\b"): ("MD5", Family.HASH),
    re.compile(r"\bSHA1_(Init|Update|Final)\b"): ("SHA-1", Family.HASH),
    re.compile(r"\bRSA_generate_key(_ex)?\b"): ("RSA", None),
    re.compile(r"\bEVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_RSA\b"): ("RSA", None),
    re.compile(r"\bEVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_EC\b"): ("ECDSA", None),
    re.compile(r"\bDSA_generate_(key|parameters\w*)\b"): ("DSA", Family.SIGNATURE),
    re.compile(r"\bDH_generate_(key|parameters\w*)\b"): ("DH", Family.KEY_EXCHANGE),
    re.compile(r"\bDES_\w*(ecb|cbc|encrypt)\w*\b"): ("DES", None),
    re.compile(r"\bRC4(_set_key)?\s*\("): ("RC4", None),
    re.compile(r"\bPKCS5_PBKDF2_HMAC\b"): ("PBKDF2", Family.KDF),
    re.compile(r"\bHMAC\s*\("): ("HMAC", Family.MAC),
    re.compile(r"\bX25519(_keygen)?\s*\("): ("ECDH", Family.KEY_EXCHANGE),
    re.compile(r"\bED25519_(sign|verify|keypair)\b"): ("EDDSA", Family.SIGNATURE),
}
_EC_CURVE = re.compile(r"\bEC_KEY_new_by_curve_name\s*\(\s*NID_(\w+)")
_MBEDTLS = {
    re.compile(r"\bmbedtls_md5\w*\b"): ("MD5", Family.HASH),
    re.compile(r"\bmbedtls_sha1\w*\b"): ("SHA-1", Family.HASH),
    re.compile(r"\bmbedtls_sha256\w*\b"): ("SHA-256", Family.HASH),
    re.compile(r"\bmbedtls_sha512\w*\b"): ("SHA-512", Family.HASH),
    re.compile(r"\bmbedtls_aes_\w+\b"): ("AES", None),
    re.compile(r"\bmbedtls_gcm_\w+\b"): ("AES", None),
    re.compile(r"\bmbedtls_des3\w*\b"): ("3DES", None),
    re.compile(r"\bmbedtls_des(?!3)\w*\b"): ("DES", None),
    re.compile(r"\bmbedtls_rsa_\w+\b"): ("RSA", None),
    re.compile(r"\bmbedtls_ecdsa_\w+\b"): ("ECDSA", Family.SIGNATURE),
    re.compile(r"\bmbedtls_ecdh_\w+\b"): ("ECDH", Family.KEY_EXCHANGE),
    re.compile(r"\bmbedtls_chacha(?:20|chapoly)\w*\b"): ("CHACHA20", None),
}
_LIBSODIUM = {
    re.compile(r"\bcrypto_box_\w+\b"): ("ECDH", Family.KEY_EXCHANGE),
    re.compile(r"\bcrypto_sign_\w+\b"): ("EDDSA", Family.SIGNATURE),
    re.compile(r"\bcrypto_aead_chacha20poly1305\w*\b"): ("CHACHA20", None),
    re.compile(r"\bcrypto_aead_xchacha20poly1305\w*\b"): ("CHACHA20", None),
    re.compile(r"\bcrypto_secretbox_\w+\b"): ("CHACHA20", None),
    re.compile(r"\bcrypto_aead_aes256gcm\w*\b"): ("AES-256", None),
    re.compile(r"\bcrypto_hash_sha256\w*\b"): ("SHA-256", Family.HASH),
    re.compile(r"\bcrypto_hash_sha512\w*\b"): ("SHA-512", Family.HASH),
    re.compile(r"\bcrypto_generichash\w*\b"): ("BLAKE2", Family.HASH),
    re.compile(r"\bcrypto_pwhash\w*\b"): ("ARGON2", Family.KDF),
    re.compile(r"\bcrypto_kx_\w+\b"): ("ECDH", Family.KEY_EXCHANGE),
}

#: libsodium notes where the mapped canonical name needs an honest caveat
_LIBSODIUM_NOTES = {
    "crypto_box_": "libsodium crypto_box (X25519 key exchange + XSalsa20-Poly1305)",
    "crypto_secretbox_": "libsodium secretbox (XSalsa20-Poly1305; mapped to the ChaCha20 family)",
}


class CCppDetector(Detector):
    """Regex detector for C/C++ sources using OpenSSL, mbedTLS, or libsodium."""

    name = "c_cpp"

    def applies_to(self, path: PurePath) -> bool:
        return path.suffix in (".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx")

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
            for m in _EVP_CIPHER.finditer(line_text):
                base, bits, mode = m.group(1), int(m.group(2)), m.group(3).upper()
                if base == "aes" and bits in (128, 192, 256):
                    yield from emit(i, f"AES-{bits}", key_size=bits, mode=mode)
                elif base == "aes":
                    yield from emit(i, "AES", mode=mode)
                # aria/camellia are outside the knowledge base; not reported

            for table in (_EVP_SIMPLE,):
                for pattern, (algorithm, family, mode) in table.items():
                    if pattern.search(line_text):
                        yield from emit(i, algorithm, mode=mode, usage_family=family)

            for pattern, (algorithm, family) in {**_OPENSSL_LEGACY, **_MBEDTLS}.items():
                if pattern.search(line_text):
                    yield from emit(i, algorithm, usage_family=family)

            curve_match = _EC_CURVE.search(line_text)
            if curve_match:
                yield from emit(i, "ECDSA", curve=curve_match.group(1))

            for pattern, (algorithm, family) in _LIBSODIUM.items():
                if pattern.search(line_text):
                    note = ""
                    for prefix, prefix_note in _LIBSODIUM_NOTES.items():
                        if prefix in pattern.pattern:
                            note = prefix_note
                    yield from emit(i, algorithm, usage_family=family, note=note)
