"""Go detector: crypto/* and golang.org/x/crypto/* import mapping.

Go's compiler rejects unused imports, so an import of ``crypto/md5`` is a
near-certain sign of use — imports are HIGH confidence. Mode of operation
is attached from ``cipher.New*`` calls when present in the same file. AES
key sizes are runtime values (16/24/32-byte keys) and are not inferred
(documented limitation: bare ``AES`` is treated conservatively).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import PurePath

from lattice.core.models import Confidence, CryptoAsset, Family
from lattice.detectors.base import Detector, make_snippet

#: import path -> (canonical algorithm, usage family)
_IMPORT_MAP: dict[str, tuple[str, Family | None]] = {
    "crypto/md5": ("MD5", Family.HASH),
    "crypto/sha1": ("SHA-1", Family.HASH),
    "crypto/sha256": ("SHA-256", Family.HASH),
    "crypto/sha512": ("SHA-512", Family.HASH),
    "crypto/rsa": ("RSA", None),
    "crypto/dsa": ("DSA", Family.SIGNATURE),
    "crypto/ecdsa": ("ECDSA", Family.SIGNATURE),
    "crypto/ed25519": ("EDDSA", Family.SIGNATURE),
    "crypto/ecdh": ("ECDH", Family.KEY_EXCHANGE),
    "crypto/aes": ("AES", None),
    "crypto/des": ("DES", None),
    "crypto/rc4": ("RC4", None),
    "crypto/hmac": ("HMAC", Family.MAC),
    "golang.org/x/crypto/chacha20poly1305": ("CHACHA20", None),
    "golang.org/x/crypto/chacha20": ("CHACHA20", None),
    "golang.org/x/crypto/argon2": ("ARGON2", Family.KDF),
    "golang.org/x/crypto/bcrypt": ("BCRYPT", Family.KDF),
    "golang.org/x/crypto/scrypt": ("SCRYPT", Family.KDF),
    "golang.org/x/crypto/pbkdf2": ("PBKDF2", Family.KDF),
    "golang.org/x/crypto/blowfish": ("BLOWFISH", None),
    "golang.org/x/crypto/sha3": ("SHA-3", Family.HASH),
    "golang.org/x/crypto/curve25519": ("ECDH", Family.KEY_EXCHANGE),
    "golang.org/x/crypto/ed25519": ("EDDSA", Family.SIGNATURE),
    "golang.org/x/crypto/blake2b": ("BLAKE2", Family.HASH),
    "golang.org/x/crypto/blake2s": ("BLAKE2", Family.HASH),
    "golang.org/x/crypto/md4": ("MD5", Family.HASH),  # nearest broken-hash entry
}

_IMPORT_LINE = re.compile(r'^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"([^"]+)"')
_IMPORT_SINGLE = re.compile(r'^\s*import\s+(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"([^"]+)"')

#: cipher-mode constructors that refine an AES/DES import in the same file
_MODE_CALLS = {
    "cipher.NewGCM": "GCM",
    "cipher.NewCBCEncrypter": "CBC",
    "cipher.NewCBCDecrypter": "CBC",
    "cipher.NewCTR": "CTR",
    "cipher.NewCFBEncrypter": "CFB",
    "cipher.NewCFBDecrypter": "CFB",
    "cipher.NewOFB": "OFB",
}

_TRIPLE_DES = re.compile(r"\bdes\.NewTripleDESCipher\b")


class GoDetector(Detector):
    """Import-map detector for Go sources."""

    name = "go"

    def applies_to(self, path: PurePath) -> bool:
        return path.suffix == ".go"

    def detect(self, path: PurePath, content: str) -> Iterable[CryptoAsset]:
        lines = content.splitlines()
        imports: dict[str, int] = {}  # import path -> line number

        in_block = False
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("import ("):
                in_block = True
                continue
            if in_block:
                if stripped.startswith(")"):
                    in_block = False
                    continue
                m = _IMPORT_LINE.match(line)
                if m:
                    imports.setdefault(m.group(1), i)
            else:
                m = _IMPORT_SINGLE.match(line)
                if m:
                    imports.setdefault(m.group(1), i)

        # file-level mode context, applied to the block-cipher imports
        mode: str | None = None
        for call, call_mode in _MODE_CALLS.items():
            if call in content:
                mode = call_mode
                break

        triple_des = bool(_TRIPLE_DES.search(content))

        for import_path, line in sorted(imports.items(), key=lambda kv: kv[1]):
            mapped = _IMPORT_MAP.get(import_path)
            if not mapped:
                continue
            algorithm, family = mapped
            asset_mode = None
            note = ""
            if import_path in ("crypto/aes", "crypto/des"):
                asset_mode = mode
                if import_path == "crypto/aes":
                    note = "key size not determined (16/24/32-byte key chosen at runtime)"
                if import_path == "crypto/des" and triple_des:
                    algorithm = "3DES"
            yield CryptoAsset(
                algorithm=algorithm,
                file_path=str(path),
                line_number=line,
                detector=self.name,
                confidence=Confidence.HIGH,
                snippet=make_snippet(lines, line),
                mode=asset_mode,
                usage_family=family,
                note=note,
            )
