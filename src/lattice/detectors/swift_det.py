"""Swift detector: Apple CryptoKit and legacy CommonCrypto.

CryptoKit is a gift for detection: Apple namespaces weak algorithms under
``Insecure.`` (``Insecure.MD5``, ``Insecure.SHA1``) and separates ``.Signing``
from ``.KeyAgreement`` and names curves explicitly (``P256``, ``Curve25519``),
so the usage family is right there in the API path. Regex-based (MEDIUM
confidence): Swift ``import`` doesn't guarantee use the way Go's does.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import PurePath

from lattice.core.models import Confidence, CryptoAsset, Family
from lattice.detectors.base import Detector, LineIndex, make_snippet

#: pattern -> (algorithm, usage family, mode)
_CRYPTOKIT: dict[re.Pattern[str], tuple[str, Family | None, str | None]] = {
    re.compile(r"\bInsecure\.MD5\b"): ("MD5", Family.HASH, None),
    re.compile(r"\bInsecure\.SHA1\b"): ("SHA-1", Family.HASH, None),
    re.compile(r"\bSHA256\b"): ("SHA-256", Family.HASH, None),
    re.compile(r"\bSHA384\b"): ("SHA-384", Family.HASH, None),
    re.compile(r"\bSHA512\b"): ("SHA-512", Family.HASH, None),
    re.compile(r"\bHMAC<"): ("HMAC", Family.MAC, None),
    re.compile(r"\bAES\.GCM\b"): ("AES", None, "GCM"),
    re.compile(r"\bChaChaPoly\b"): ("CHACHA20", None, None),
    # curve + usage encoded in the API path
    re.compile(r"\bP256\.Signing\b"): ("ECDSA", Family.SIGNATURE, None),
    re.compile(r"\bP384\.Signing\b"): ("ECDSA", Family.SIGNATURE, None),
    re.compile(r"\bP521\.Signing\b"): ("ECDSA", Family.SIGNATURE, None),
    re.compile(r"\bP256\.KeyAgreement\b"): ("ECDH", Family.KEY_EXCHANGE, None),
    re.compile(r"\bP384\.KeyAgreement\b"): ("ECDH", Family.KEY_EXCHANGE, None),
    re.compile(r"\bP521\.KeyAgreement\b"): ("ECDH", Family.KEY_EXCHANGE, None),
    re.compile(r"\bCurve25519\.Signing\b"): ("EDDSA", Family.SIGNATURE, None),
    re.compile(r"\bCurve25519\.KeyAgreement\b"): ("ECDH", Family.KEY_EXCHANGE, None),
}

#: legacy CommonCrypto tokens
_COMMONCRYPTO: dict[re.Pattern[str], tuple[str, Family | None, str | None]] = {
    re.compile(r"\bCC_MD5\b|\bkCCHmacAlgMD5\b"): ("MD5", Family.HASH, None),
    re.compile(r"\bCC_SHA1\b|\bkCCHmacAlgSHA1\b"): ("SHA-1", Family.HASH, None),
    re.compile(r"\bCC_SHA256\b"): ("SHA-256", Family.HASH, None),
    re.compile(r"\bkCCAlgorithmAES\b|\bkCCAlgorithmAES128\b"): ("AES", None, None),
    re.compile(r"\bkCCAlgorithm3DES\b"): ("3DES", None, None),
    re.compile(r"\bkCCAlgorithmDES\b"): ("DES", None, None),
    re.compile(r"\bkCCAlgorithmRC4\b"): ("RC4", None, None),
    re.compile(r"\bkCCAlgorithmBlowfish\b"): ("BLOWFISH", None, None),
    re.compile(r"\bkCCOptionECBMode\b"): ("AES", None, "ECB"),
    re.compile(r"\bCCKeyDerivationPBKDF\b|\bkCCPBKDF2\b"): ("PBKDF2", Family.KDF, None),
}

#: swift-crypto / third-party PQC hints
_MISC = {
    re.compile(r"\bimport\s+CryptoKit\b"): None,  # marker only; algorithms matched above
}


class SwiftDetector(Detector):
    """Regex detector for Swift sources using CryptoKit or CommonCrypto."""

    name = "swift"

    def applies_to(self, path: PurePath) -> bool:
        return path.suffix == ".swift"

    def detect(self, path: PurePath, content: str) -> Iterable[CryptoAsset]:
        lines = content.splitlines()
        index = LineIndex(content)
        seen: set[tuple[int, str, str | None]] = set()

        def emit(
            offset: int,
            algorithm: str,
            *,
            mode: str | None = None,
            usage_family: Family | None = None,
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
                mode=mode,
                usage_family=usage_family,
            )

        for pattern, (algorithm, family, mode) in {**_CRYPTOKIT, **_COMMONCRYPTO}.items():
            for m in pattern.finditer(content):
                yield from emit(m.start(), algorithm, mode=mode, usage_family=family)
