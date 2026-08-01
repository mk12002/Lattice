"""Ruby detector: OpenSSL stdlib and common crypto gems.

Ruby crypto goes through the ``openssl`` standard library
(``OpenSSL::Digest::MD5``, ``OpenSSL::Cipher.new('aes-256-gcm')``,
``OpenSSL::PKey::RSA.new(2048)``) plus gems like ``bcrypt`` and ``argon2``.
Regex-based (MEDIUM confidence): the algorithm is in a type name or a string
literal, which regex reads reliably. Cipher strings are OpenSSL triples
(``aes-256-gcm``), parsed like the JavaScript detector.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import PurePath

from lattice.core.models import Confidence, CryptoAsset, Family
from lattice.detectors.base import Detector, LineIndex, make_snippet
from lattice.rules.algorithms import lookup

#: OpenSSL::Digest::<NAME>  (MD5, SHA1, SHA256, ...)
_DIGEST = re.compile(r"OpenSSL::Digest::([A-Za-z0-9_]+)")
#: OpenSSL::HMAC
_HMAC = re.compile(r"\bOpenSSL::HMAC\b")
#: OpenSSL::PKey::<KIND>.new(<bits>?)   (RSA, DSA, EC)
_PKEY = re.compile(r"OpenSSL::PKey::(RSA|DSA|EC|DH)\b(?:\.new\s*\(?\s*(\d+)?)?")
#: OpenSSL::Cipher.new('aes-256-gcm')  or  OpenSSL::Cipher::AES.new(256, :GCM)
_CIPHER_STR = re.compile(r"OpenSSL::Cipher(?:\.new|\.new)?\s*\(\s*['\"]([a-zA-Z0-9-]+)['\"]")
#: gem require / call-site markers
_GEMS = {
    re.compile(r"\bBCrypt::Password\b|\brequire\s+['\"]bcrypt['\"]"): ("BCRYPT", Family.KDF),
    re.compile(r"\brequire\s+['\"]argon2['\"]|\bArgon2::"): ("ARGON2", Family.KDF),
    re.compile(r"\brequire\s+['\"]scrypt['\"]|\bSCrypt::"): ("SCRYPT", Family.KDF),
    re.compile(r"\bRbNaCl::"): ("EDDSA", Family.SIGNATURE),  # libsodium binding (signatures/box)
}

_CIPHER_TRIPLE = re.compile(r"^(aes|aria|camellia)-(\d+)-([a-z0-9]+)$")
_CIPHER_FLAT = {
    "des-ede3-cbc": ("3DES", "CBC"),
    "des-ede3": ("3DES", None),
    "des-cbc": ("DES", "CBC"),
    "des": ("DES", None),
    "rc4": ("RC4", None),
    "bf-cbc": ("BLOWFISH", "CBC"),
    "chacha20-poly1305": ("CHACHA20", None),
    "chacha20": ("CHACHA20", None),
}


class RubyDetector(Detector):
    """Regex detector for Ruby sources using OpenSSL and crypto gems."""

    name = "ruby"

    def applies_to(self, path: PurePath) -> bool:
        return path.suffix in (".rb", ".rake") or path.name in ("Rakefile", "Gemfile")

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

        for m in _DIGEST.finditer(content):
            info = lookup(m.group(1))
            if info is not None:
                yield from emit(m.start(), info.name, usage_family=Family.HASH)

        for m in _HMAC.finditer(content):
            yield from emit(m.start(), "HMAC", usage_family=Family.MAC)

        for m in _PKEY.finditer(content):
            kind = m.group(1)
            algorithm = {"RSA": "RSA", "DSA": "DSA", "EC": "ECDSA", "DH": "DH"}[kind]
            key_size = int(m.group(2)) if m.group(2) else None
            family = {"DH": Family.KEY_EXCHANGE}.get(kind)
            yield from emit(m.start(), algorithm, key_size=key_size, usage_family=family)

        for m in _CIPHER_STR.finditer(content):
            yield from self._cipher(emit, m.start(), m.group(1))

        for pattern, (algorithm, family) in _GEMS.items():
            match = pattern.search(content)
            if match:
                yield from emit(match.start(), algorithm, usage_family=family)

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
