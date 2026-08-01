"""PHP detector: openssl_* functions, hash()/password_hash(), and Sodium.

PHP crypto is mostly free functions with the algorithm in a string argument:
``hash('sha256', ...)``, ``openssl_encrypt($d, 'aes-256-gcm', ...)``,
``openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA])``,
``password_hash($p, PASSWORD_BCRYPT)``, plus the ``sodium_*`` extension.
Regex-based (MEDIUM confidence).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import PurePath

from lattice.core.models import Confidence, CryptoAsset, Family
from lattice.detectors.base import Detector, LineIndex, make_snippet
from lattice.rules.algorithms import lookup

#: hash('algo', ...) / hash_init('algo') / hash_hmac('algo', ...)
_HASH = re.compile(r"\bhash(?:_init|_hmac|_pbkdf2)?\s*\(\s*['\"]([A-Za-z0-9_-]+)['\"]")
_HASH_HMAC = re.compile(r"\bhash_hmac\s*\(")
_PBKDF2 = re.compile(r"\bhash_pbkdf2\s*\(")
#: md5(...) / sha1(...) convenience functions
_MD5_FUNC = re.compile(r"(?<![A-Za-z0-9_])md5\s*\(")
_SHA1_FUNC = re.compile(r"(?<![A-Za-z0-9_])sha1\s*\(")
#: openssl_encrypt/decrypt($data, 'aes-256-gcm', ...)
_OPENSSL_CIPHER = re.compile(
    r"\bopenssl_(?:encrypt|decrypt)\s*\(\s*[^,]+,\s*['\"]([A-Za-z0-9-]+)['\"]"
)
#: openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA])
_PKEY_TYPE = re.compile(r"OPENSSL_KEYTYPE_(RSA|DSA|DH|EC)\b")
#: password_hash($pw, PASSWORD_BCRYPT|PASSWORD_ARGON2ID|PASSWORD_ARGON2I)
_PASSWORD_HASH = re.compile(r"\bPASSWORD_(BCRYPT|ARGON2ID|ARGON2I|ARGON2)\b")
#: sodium_crypto_* family
_SODIUM = {
    re.compile(r"\bsodium_crypto_sign\w*"): ("EDDSA", Family.SIGNATURE),
    re.compile(r"\bsodium_crypto_box\w*"): ("ECDH", Family.KEY_EXCHANGE),
    re.compile(r"\bsodium_crypto_kx\w*"): ("ECDH", Family.KEY_EXCHANGE),
    re.compile(r"\bsodium_crypto_aead_chacha20poly1305\w*"): ("CHACHA20", None),
    re.compile(r"\bsodium_crypto_aead_xchacha20poly1305\w*"): ("CHACHA20", None),
    re.compile(r"\bsodium_crypto_aead_aes256gcm\w*"): ("AES-256", None),
    re.compile(r"\bsodium_crypto_pwhash\w*"): ("ARGON2", Family.KDF),
    re.compile(r"\bsodium_crypto_generichash\w*"): ("BLAKE2", Family.HASH),
}

_PASSWORD_MAP = {
    "BCRYPT": "BCRYPT",
    "ARGON2ID": "ARGON2",
    "ARGON2I": "ARGON2",
    "ARGON2": "ARGON2",
}

_CIPHER_TRIPLE = re.compile(r"^(aes|aria|camellia)-(\d+)-([a-z0-9]+)$")
_CIPHER_FLAT = {
    "des-ede3-cbc": ("3DES", "CBC"),
    "des-ede3": ("3DES", None),
    "des-cbc": ("DES", "CBC"),
    "des": ("DES", None),
    "rc4": ("RC4", None),
    "rc4-40": ("RC4", None),
    "bf-cbc": ("BLOWFISH", "CBC"),
    "chacha20-poly1305": ("CHACHA20", None),
    "chacha20": ("CHACHA20", None),
}


class PHPDetector(Detector):
    """Regex detector for PHP sources using OpenSSL, hash(), and Sodium."""

    name = "php"

    def applies_to(self, path: PurePath) -> bool:
        return path.suffix in (".php", ".phtml", ".php3", ".php4", ".php5", ".phps")

    def detect(self, path: PurePath, content: str) -> Iterable[CryptoAsset]:
        lines = content.splitlines()
        index = LineIndex(content)
        seen: set[tuple[int, str, str | None]] = set()

        def emit(
            offset: int,
            algorithm: str,
            *,
            key_size: int | None = None,
            mode: str | None = None,
            usage_family: Family | None = None,
            note: str = "",
        ) -> Iterator[CryptoAsset]:
            line = index.line_of(offset)
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
                mode=mode,
                usage_family=usage_family,
                note=note,
            )

        for m in _HASH.finditer(content):
            # hash_hmac / hash_pbkdf2 name a digest; report the family accordingly
            call = content[max(0, m.start() - 5) : m.start() + 12]
            info = lookup(m.group(1))
            if info is None:
                continue
            if "pbkdf2" in call:
                yield from emit(m.start(), "PBKDF2", usage_family=Family.KDF)
            elif "hmac" in call:
                yield from emit(m.start(), "HMAC", usage_family=Family.MAC)
            yield from emit(m.start(), info.name, usage_family=Family.HASH)

        for m in _MD5_FUNC.finditer(content):
            yield from emit(m.start(), "MD5", usage_family=Family.HASH)
        for m in _SHA1_FUNC.finditer(content):
            yield from emit(m.start(), "SHA-1", usage_family=Family.HASH)

        for m in _OPENSSL_CIPHER.finditer(content):
            yield from self._cipher(emit, m.start(), m.group(1))

        for m in _PKEY_TYPE.finditer(content):
            kind = m.group(1)
            algorithm = {"RSA": "RSA", "DSA": "DSA", "DH": "DH", "EC": "ECDSA"}[kind]
            family = {"DH": Family.KEY_EXCHANGE}.get(kind)
            yield from emit(m.start(), algorithm, usage_family=family)

        for m in _PASSWORD_HASH.finditer(content):
            algorithm = _PASSWORD_MAP[m.group(1)]
            yield from emit(m.start(), algorithm, usage_family=Family.KDF)

        for pattern, (algorithm, family) in _SODIUM.items():
            for m in pattern.finditer(content):
                yield from emit(m.start(), algorithm, usage_family=family)

    def _cipher(self, emit, offset: int, spec: str) -> Iterator[CryptoAsset]:
        spec_l = spec.lower()
        triple = _CIPHER_TRIPLE.match(spec_l)
        if triple:
            base, bits, mode = triple.group(1), int(triple.group(2)), triple.group(3).upper()
            if base == "aes" and bits in (128, 192, 256):
                yield from emit(offset, f"AES-{bits}", key_size=bits, mode=mode)
            elif base == "aes":
                yield from emit(offset, "AES", mode=mode)
            return
        flat = _CIPHER_FLAT.get(spec_l)
        if flat:
            algorithm, mode = flat
            yield from emit(offset, algorithm, mode=mode)
