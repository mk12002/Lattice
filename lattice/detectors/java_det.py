"""Java detector: JCA/JCE algorithm strings and BouncyCastle awareness.

Java crypto is almost entirely selected through string parameters to
``getInstance`` factories, which regex reads reliably — matches on a string
literal are MEDIUM confidence (the call is real, but a string cannot prove
the surrounding context). Transformation strings like
``"AES/ECB/PKCS5Padding"`` are parsed into algorithm + mode so ECB usage is
flagged. Key sizes passed later via ``initialize(2048)`` are not bound to
the algorithm by this detector (documented limitation).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import PurePath

from lattice.core.models import Confidence, CryptoAsset, Family
from lattice.detectors.base import Detector, LineIndex, make_snippet
from lattice.rules.algorithms import lookup

#: JCA factory -> the usage family that call site pins
_FACTORIES: dict[str, Family | None] = {
    "Cipher": None,  # family comes from the algorithm itself
    "MessageDigest": Family.HASH,
    "KeyPairGenerator": None,
    "KeyGenerator": None,
    "Signature": Family.SIGNATURE,
    "KeyAgreement": Family.KEY_EXCHANGE,
    "Mac": Family.MAC,
    "SecretKeyFactory": None,
    "KeyFactory": None,
    "SSLContext": Family.PROTOCOL,
}

_GET_INSTANCE = re.compile(
    r"\b(" + "|".join(_FACTORIES) + r")\s*\.\s*getInstance\s*\(\s*\"([^\"]+)\""
)

_SIGNATURE_WITH = re.compile(r"^(?:(?P<hash>[A-Za-z0-9]+)with)?(?P<algorithm>.+)$", re.IGNORECASE)
_HMAC_NAME = re.compile(r"^Hmac(?P<hash>[A-Za-z0-9-]+)$", re.IGNORECASE)
_PBKDF2_NAME = re.compile(r"^PBKDF2With", re.IGNORECASE)
_BOUNCYCASTLE_IMPORT = re.compile(r"^\s*import\s+org\.bouncycastle\.", re.MULTILINE)

#: JCA algorithm-name spellings that need help before the synonym map
_JCA_ALIASES = {
    "aes_128": "AES-128",
    "aes_192": "AES-192",
    "aes_256": "AES-256",
    "diffiehellman": "DH",
    "ecies": "ECDH",
    "eddsa": "EDDSA",
    "rsassa-pss": "RSA",
    "arcfour": "RC4",
    "pbewithmd5anddes": "DES",  # legacy PBE: flags the weakest primitive it uses
}


class JavaDetector(Detector):
    """Regex/token detector for Java and Kotlin sources using the JCA."""

    name = "java"

    def applies_to(self, path: PurePath) -> bool:
        return path.suffix in (".java", ".kt", ".kts", ".scala")

    def detect(self, path: PurePath, content: str) -> Iterable[CryptoAsset]:
        lines = content.splitlines()
        index = LineIndex(content)
        seen: set[tuple[int, str, str | None]] = set()

        for match in _GET_INSTANCE.finditer(content):
            factory = match.group(1)
            spec = match.group(2)
            line = index.line_of(match.start())
            for asset in self._assets_for(path, factory, spec, line, lines):
                key = (asset.line_number, asset.algorithm, asset.mode)
                if key not in seen:
                    seen.add(key)
                    yield asset

        bc = _BOUNCYCASTLE_IMPORT.search(content)
        if bc:
            line = index.line_of(bc.start())
            yield CryptoAsset(
                algorithm="BouncyCastle",
                file_path=str(path),
                line_number=line,
                detector=self.name,
                confidence=Confidence.HIGH,
                snippet=make_snippet(lines, line),
                usage_family=Family.LIBRARY,
                note="crypto provider imported; specific algorithms appear as their own findings",
            )

    def _assets_for(
        self, path: PurePath, factory: str, spec: str, line: int, lines: list[str]
    ) -> Iterator[CryptoAsset]:
        usage = _FACTORIES[factory]
        snippet = make_snippet(lines, line)

        def asset(
            algorithm: str,
            mode: str | None = None,
            usage_family: Family | None = usage,
            note: str = "",
        ) -> CryptoAsset:
            return CryptoAsset(
                algorithm=algorithm,
                file_path=str(path),
                line_number=line,
                detector=self.name,
                confidence=Confidence.MEDIUM,
                snippet=snippet,
                mode=mode,
                usage_family=usage_family,
                note=note,
            )

        if factory == "SSLContext":
            info = lookup(spec)
            if info is not None:
                yield asset(info.name, usage_family=Family.PROTOCOL)
            return

        if factory == "Signature":
            m = _SIGNATURE_WITH.match(spec)
            algorithm = m.group("algorithm") if m else spec
            info = lookup(algorithm)
            if info is not None:
                yield asset(info.name, usage_family=Family.SIGNATURE)
            # a SHA-1/MD5 digest inside a signature spec is itself a finding
            digest = m.group("hash") if m else None
            digest_info = lookup(digest) if digest else None
            if digest_info is not None and digest_info.name in ("MD5", "SHA-1"):
                yield asset(
                    digest_info.name,
                    usage_family=Family.HASH,
                    note=f"digest inside signature spec {spec!r}",
                )
            return

        if factory == "Mac":
            m = _HMAC_NAME.match(spec)
            if m:
                yield asset("HMAC")
                digest_info = lookup(m.group("hash"))
                if digest_info is not None and digest_info.name in ("MD5", "SHA-1"):
                    yield asset(
                        digest_info.name,
                        usage_family=Family.HASH,
                        note=f"digest inside MAC spec {spec!r}",
                    )
            return

        if factory == "SecretKeyFactory" and _PBKDF2_NAME.match(spec):
            yield asset("PBKDF2", usage_family=Family.KDF)
            return

        # Cipher transformations ("AES/ECB/PKCS5Padding") and plain algorithm names
        parts = spec.split("/")
        base = parts[0].strip()
        mode = parts[1].strip().upper() if len(parts) > 1 else None
        canonical = _JCA_ALIASES.get(base.lower().replace("-", "_"))
        info = lookup(canonical) if canonical else lookup(base)
        if info is not None:
            yield asset(info.name, mode=mode)
