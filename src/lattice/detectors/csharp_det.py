"""C#/.NET detector: System.Security.Cryptography and BouncyCastle.NET.

Regex-based (MEDIUM confidence). .NET names algorithms in type names
(``MD5.Create()``, ``new AesGcm(key)``, ``RSA.Create(2048)``), which regex
reads reliably. Cipher mode is a property assignment (``aes.Mode =
CipherMode.ECB``), so mode is attached file-level like the Go detector,
with an honest note that the binding is per-file, not per-instance.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import PurePath

from lattice.core.models import Confidence, CryptoAsset, Family
from lattice.detectors.base import Detector, make_snippet

#: type factories: Type.Create() / new TypeCryptoServiceProvider() / new TypeManaged()
_FACTORY = re.compile(
    r"\b(MD5|SHA1|SHA256|SHA384|SHA512|Aes|AesManaged|AesCryptoServiceProvider|"
    r"TripleDES|DES|RC2|RSA|DSA|ECDsa|ECDiffieHellman)"
    r"(?:CryptoServiceProvider|Managed|Cng)?\s*(?:\.\s*Create\s*\(|\()"
)
_NEW_TYPE = re.compile(
    r"\bnew\s+(MD5CryptoServiceProvider|SHA1Managed|SHA1CryptoServiceProvider|"
    r"SHA256Managed|SHA384Managed|SHA512Managed|AesManaged|AesCryptoServiceProvider|"
    r"TripleDESCryptoServiceProvider|DESCryptoServiceProvider|RC2CryptoServiceProvider|"
    r"RSACryptoServiceProvider|DSACryptoServiceProvider|AesGcm|AesCcm|ChaCha20Poly1305|"
    r"HMACMD5|HMACSHA1|HMACSHA256|HMACSHA384|HMACSHA512|Rfc2898DeriveBytes)\s*\(",
)
_RSA_CREATE_SIZE = re.compile(r"\bRSA\.Create\s*\(\s*(\d+)\s*\)")
_NEW_RSA_SIZE = re.compile(r"\bnew\s+RSACryptoServiceProvider\s*\(\s*(\d+)\s*\)")
_CIPHER_MODE = re.compile(r"\bCipherMode\.(ECB|CBC|CFB|OFB|CTS)\b")
_BOUNCY_IMPORT = re.compile(r"^\s*using\s+Org\.BouncyCastle\b", re.MULTILINE)

#: type-name prefix -> (canonical algorithm, usage family)
_TYPE_MAP: dict[str, tuple[str, Family | None]] = {
    "MD5": ("MD5", Family.HASH),
    "SHA1": ("SHA-1", Family.HASH),
    "SHA256": ("SHA-256", Family.HASH),
    "SHA384": ("SHA-384", Family.HASH),
    "SHA512": ("SHA-512", Family.HASH),
    "Aes": ("AES", None),
    "TripleDES": ("3DES", None),
    "DES": ("DES", None),
    "RC2": ("RC2", None),
    "RSA": ("RSA", None),
    "DSA": ("DSA", Family.SIGNATURE),
    "ECDsa": ("ECDSA", Family.SIGNATURE),
    "ECDiffieHellman": ("ECDH", Family.KEY_EXCHANGE),
    "AesGcm": ("AES", None),
    "AesCcm": ("AES", None),
    "ChaCha20Poly1305": ("CHACHA20", None),
    "HMACMD5": ("HMAC", Family.MAC),
    "HMACSHA1": ("HMAC", Family.MAC),
    "HMACSHA256": ("HMAC", Family.MAC),
    "HMACSHA384": ("HMAC", Family.MAC),
    "HMACSHA512": ("HMAC", Family.MAC),
    "Rfc2898DeriveBytes": ("PBKDF2", Family.KDF),
}

#: HMAC types whose digest is itself broken and worth co-reporting
_WEAK_HMAC_DIGEST = {"HMACMD5": "MD5", "HMACSHA1": "SHA-1"}

#: symmetric types that take the file-level CipherMode context
_MODE_SENSITIVE = {"AES", "3DES", "DES", "RC2"}
#: AEAD types where the mode is intrinsic, not from CipherMode
_INTRINSIC_MODE = {"AesGcm": "GCM", "AesCcm": "CCM"}


class CSharpDetector(Detector):
    """Regex detector for C# sources using System.Security.Cryptography."""

    name = "csharp"

    def applies_to(self, path: PurePath) -> bool:
        return path.suffix == ".cs"

    def detect(self, path: PurePath, content: str) -> Iterable[CryptoAsset]:
        lines = content.splitlines()
        seen: set[tuple[int, str, str | None]] = set()

        # file-level mode context (property assignment can't be bound per instance)
        mode_match = _CIPHER_MODE.search(content)
        file_mode = mode_match.group(1) if mode_match else None
        mode_note = (
            f"mode from CipherMode.{file_mode} reference in the same file" if file_mode else ""
        )

        def emit(
            line: int,
            type_name: str,
            *,
            key_size: int | None = None,
        ) -> Iterator[CryptoAsset]:
            mapped = _TYPE_MAP.get(type_name)
            if not mapped:
                return
            algorithm, family = mapped
            mode = None
            note = ""
            if type_name in _INTRINSIC_MODE:
                mode = _INTRINSIC_MODE[type_name]
            elif algorithm in _MODE_SENSITIVE and file_mode:
                mode = file_mode
                note = mode_note
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
                usage_family=family,
                note=note,
            )
            weak_digest = _WEAK_HMAC_DIGEST.get(type_name)
            if weak_digest:
                yield CryptoAsset(
                    algorithm=weak_digest,
                    file_path=str(path),
                    line_number=line,
                    detector=self.name,
                    confidence=Confidence.MEDIUM,
                    snippet=make_snippet(lines, line),
                    usage_family=Family.HASH,
                    note=f"digest inside {type_name}",
                )

        for i, line_text in enumerate(lines, start=1):
            rsa_size: int | None = None
            m = _RSA_CREATE_SIZE.search(line_text) or _NEW_RSA_SIZE.search(line_text)
            if m:
                rsa_size = int(m.group(1))

            for match in _FACTORY.finditer(line_text):
                type_name = match.group(1)
                yield from emit(i, type_name, key_size=rsa_size if type_name == "RSA" else None)

            for match in _NEW_TYPE.finditer(line_text):
                full = match.group(1)
                base = (
                    full.removesuffix("CryptoServiceProvider")
                    .removesuffix("Managed")
                    .removesuffix("Cng")
                )
                type_name = full if full in _TYPE_MAP else base
                yield from emit(
                    i,
                    type_name,
                    key_size=rsa_size if type_name == "RSA" else None,
                )

        bc = _BOUNCY_IMPORT.search(content)
        if bc:
            line = content.count("\n", 0, bc.start()) + 1
            yield CryptoAsset(
                algorithm="BouncyCastle.NET",
                file_path=str(path),
                line_number=line,
                detector=self.name,
                confidence=Confidence.HIGH,
                snippet=make_snippet(lines, line),
                usage_family=Family.LIBRARY,
                note="crypto provider imported; specific algorithms appear as their own findings",
            )
