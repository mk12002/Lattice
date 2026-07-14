"""JavaScript/TypeScript detector: node:crypto, WebCrypto, and crypto libraries.

Regex-based (MEDIUM confidence): JS is too dynamic for cheap AST certainty,
and algorithm choices live in string literals anyway. OpenSSL-style triples
(``aes-128-ecb``) from ``createCipheriv`` are parsed into algorithm + key
size + mode. Algorithm names built at runtime are invisible (documented
limitation).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import PurePath

from lattice.core.models import Confidence, CryptoAsset, Family
from lattice.detectors.base import Detector, make_snippet
from lattice.rules.algorithms import lookup

_CREATE_HASH = re.compile(r"\bcreate(?:Hash|Hmac)\s*\(\s*[\"']([A-Za-z0-9_-]+)[\"']")
_CREATE_CIPHER = re.compile(
    r"\bcreate(?:Cipheriv|Decipheriv|Cipher|Decipher)\s*\(\s*[\"']([A-Za-z0-9-]+)[\"']"
)
_CREATE_SIGN = re.compile(r"\bcreate(?:Sign|Verify)\s*\(\s*[\"']([A-Za-z0-9-]+)[\"']")
_GENERATE_KEYPAIR = re.compile(
    r"\bgenerateKeyPair(?:Sync)?\s*\(\s*[\"']([a-zA-Z0-9-]+)[\"']"
)
_MODULUS_LENGTH = re.compile(r"\bmodulusLength\s*:\s*(\d+)")
_NAMED_CURVE = re.compile(r"\bnamedCurve\s*:\s*[\"']([A-Za-z0-9-]+)[\"']")
_SUBTLE_NAME = re.compile(
    r"\bsubtle\s*\.\s*(?:encrypt|decrypt|sign|verify|generateKey|deriveKey|deriveBits|digest|importKey|wrapKey|unwrapKey)\b"
)
_ALGO_NAME_PROP = re.compile(r"\bname\s*:\s*[\"']([A-Za-z0-9-]+)[\"']")
_DIGEST_STRING = re.compile(r"[\"'](SHA-1|SHA-256|SHA-384|SHA-512)[\"']")
_PBKDF2_CALL = re.compile(r"\bpbkdf2(?:Sync)?\s*\(")
_SCRYPT_CALL = re.compile(r"\bscrypt(?:Sync)?\s*\(")
_IMPORT = re.compile(
    r"(?:require\s*\(\s*[\"']([^\"']+)[\"']\s*\)|from\s+[\"']([^\"']+)[\"'])"
)

#: OpenSSL cipher string -> (canonical, key bits, needs mode parse)
_CIPHER_TRIPLE = re.compile(r"^(aes|aria|camellia)-(\d+)-([a-z0-9]+)$")
_CIPHER_FLAT = {
    "des-ede3": ("3DES", None),
    "des-ede3-cbc": ("3DES", "CBC"),
    "des-ede-cbc": ("3DES", "CBC"),
    "des-cbc": ("DES", "CBC"),
    "des-ecb": ("DES", "ECB"),
    "des": ("DES", None),
    "rc4": ("RC4", None),
    "bf-cbc": ("BLOWFISH", "CBC"),
    "bf-ecb": ("BLOWFISH", "ECB"),
    "chacha20": ("CHACHA20", None),
    "chacha20-poly1305": ("CHACHA20", None),
}

#: package name -> canonical algorithm (None = inventory as a library)
_CRYPTO_PACKAGES: dict[str, str | None] = {
    "node-forge": None,
    "jsrsasign": None,
    "crypto-js": None,
    "elliptic": None,
    "tweetnacl": None,
    "libsodium-wrappers": None,
    "openpgp": None,
    "jose": None,
    "bcrypt": "BCRYPT",
    "bcryptjs": "BCRYPT",
    "argon2": "ARGON2",
    "scrypt-js": "SCRYPT",
    "md5": "MD5",
    "sha1": "SHA-1",
}

#: WebCrypto algorithm names -> (canonical, usage family, mode)
_WEBCRYPTO = {
    "rsa-oaep": ("RSA", Family.ASYMMETRIC_CIPHER, None),
    "rsassa-pkcs1-v1_5": ("RSA", Family.SIGNATURE, None),
    "rsa-pss": ("RSA", Family.SIGNATURE, None),
    "ecdsa": ("ECDSA", Family.SIGNATURE, None),
    "ecdh": ("ECDH", Family.KEY_EXCHANGE, None),
    "ed25519": ("EDDSA", Family.SIGNATURE, None),
    "x25519": ("ECDH", Family.KEY_EXCHANGE, None),
    "aes-gcm": ("AES", Family.SYMMETRIC_CIPHER, "GCM"),
    "aes-cbc": ("AES", Family.SYMMETRIC_CIPHER, "CBC"),
    "aes-ctr": ("AES", Family.SYMMETRIC_CIPHER, "CTR"),
    "aes-kw": ("AES", Family.SYMMETRIC_CIPHER, "KW"),
    "hmac": ("HMAC", Family.MAC, None),
    "sha-1": ("SHA-1", Family.HASH, None),
    "sha-256": ("SHA-256", Family.HASH, None),
    "sha-384": ("SHA-384", Family.HASH, None),
    "sha-512": ("SHA-512", Family.HASH, None),
}


class JavaScriptDetector(Detector):
    """Regex detector for JavaScript and TypeScript sources."""

    name = "javascript"

    def applies_to(self, path: PurePath) -> bool:
        return path.suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")

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
            confidence: Confidence = Confidence.MEDIUM,
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
                confidence=confidence,
                snippet=make_snippet(lines, line),
                key_size=key_size,
                curve=curve,
                mode=mode,
                usage_family=usage_family,
                note=note,
            )

        for i, line_text in enumerate(lines, start=1):
            for m in _CREATE_HASH.finditer(line_text):
                info = lookup(m.group(1))
                if info is not None:
                    yield from emit(i, info.name, usage_family=Family.HASH)

            for m in _CREATE_CIPHER.finditer(line_text):
                yield from self._cipher_assets(emit, i, m.group(1))

            for m in _CREATE_SIGN.finditer(line_text):
                spec = m.group(1)  # e.g. "RSA-SHA256", "sha256" (implies RSA context)
                base = spec.split("-")[0]
                info = lookup(base)
                if info is not None:
                    yield from emit(i, info.name, usage_family=Family.SIGNATURE)

            for m in _GENERATE_KEYPAIR.finditer(line_text):
                kind = m.group(1).lower()
                key_size = None
                curve = None
                mlen = _MODULUS_LENGTH.search(line_text)
                if mlen:
                    key_size = int(mlen.group(1))
                ncurve = _NAMED_CURVE.search(line_text)
                if ncurve:
                    curve = ncurve.group(1)
                mapped = {
                    "rsa": ("RSA", None),
                    "rsa-pss": ("RSA", Family.SIGNATURE),
                    "dsa": ("DSA", Family.SIGNATURE),
                    "ec": ("ECDSA", None),
                    "ed25519": ("EDDSA", Family.SIGNATURE),
                    "ed448": ("EDDSA", Family.SIGNATURE),
                    "x25519": ("ECDH", Family.KEY_EXCHANGE),
                    "x448": ("ECDH", Family.KEY_EXCHANGE),
                    "dh": ("DH", Family.KEY_EXCHANGE),
                }.get(kind)
                if mapped:
                    yield from emit(
                        i, mapped[0], key_size=key_size, curve=curve, usage_family=mapped[1]
                    )

            if _SUBTLE_NAME.search(line_text):
                for m in _ALGO_NAME_PROP.finditer(line_text):
                    entry = _WEBCRYPTO.get(m.group(1).lower())
                    if entry:
                        algorithm, family, mode = entry
                        yield from emit(i, algorithm, mode=mode, usage_family=family)
                for m in _DIGEST_STRING.finditer(line_text):
                    info = lookup(m.group(1))
                    if info is not None:
                        yield from emit(i, info.name, usage_family=Family.HASH)

            if _PBKDF2_CALL.search(line_text):
                yield from emit(i, "PBKDF2", usage_family=Family.KDF)
            if _SCRYPT_CALL.search(line_text):
                yield from emit(i, "SCRYPT", usage_family=Family.KDF)

            for m in _IMPORT.finditer(line_text):
                package = (m.group(1) or m.group(2) or "").split("/")[0]
                if package in _CRYPTO_PACKAGES:
                    algorithm = _CRYPTO_PACKAGES[package]
                    if algorithm:
                        yield from emit(
                            i, algorithm, note=f"imported package '{package}'"
                        )
                    else:
                        yield from emit(
                            i,
                            package,
                            usage_family=Family.LIBRARY,
                            confidence=Confidence.HIGH,
                            note="crypto library imported; usage not confirmed by call site",
                        )

    def _cipher_assets(self, emit, line: int, spec: str) -> Iterator[CryptoAsset]:
        spec_l = spec.lower()
        triple = _CIPHER_TRIPLE.match(spec_l)
        if triple:
            base, bits, mode = triple.group(1), int(triple.group(2)), triple.group(3).upper()
            if base == "aes" and bits in (128, 192, 256):
                yield from emit(line, f"AES-{bits}", key_size=bits, mode=mode)
            elif base == "aes":
                yield from emit(line, "AES", mode=mode)
            # aria/camellia are outside the knowledge base; not reported (no guessing)
            return
        flat = _CIPHER_FLAT.get(spec_l)
        if flat:
            algorithm, mode = flat
            yield from emit(line, algorithm, mode=mode)
            return
        info = lookup(spec_l)
        if info is not None:
            yield from emit(line, info.name)
