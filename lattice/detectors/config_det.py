"""Config & key-material detector: PEM/certs/keystores and TLS configuration.

Hard rules, tested explicitly:
- Private-key material is reported by *location and type only*. The key body
  is never decoded, stored, or echoed into any report.
- Certificates and public keys are public material; a minimal, defensive DER
  walk extracts only the algorithm OIDs. Anything that does not parse
  cleanly is reported as presence-only with algorithm UNKNOWN — never
  guessed.
- TLS config lines are matched against known directives (nginx, Apache,
  OpenSSL cnf); protocols below TLS 1.2 and weak cipher-suite tokens are
  flagged. Free-text mentions of "TLSv1" outside a directive are ignored.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable, Iterator
from pathlib import PurePath

from lattice.core.models import Confidence, CryptoAsset, Family
from lattice.detectors.base import Detector, make_snippet
from lattice.rules.algorithms import lookup

_KEY_EXTENSIONS = {".pem", ".key", ".crt", ".cer", ".csr", ".pub", ".p8"}
_BINARY_KEY_EXTENSIONS = {".p12", ".pfx", ".der", ".jks", ".keystore"}
_CONFIG_EXTENSIONS = {".conf", ".cnf", ".cfg", ".ini"}

_PEM_BEGIN = re.compile(r"^-----BEGIN ([A-Z0-9 ]+)-----\s*$")

#: PEM label fragments -> (algorithm or None, material kind)
_PRIVATE_KEY_LABELS = {
    "RSA PRIVATE KEY": "RSA",
    "EC PRIVATE KEY": "ECDSA",
    "DSA PRIVATE KEY": "DSA",
    "OPENSSH PRIVATE KEY": None,
    "ENCRYPTED PRIVATE KEY": None,
    "PRIVATE KEY": None,  # PKCS#8: algorithm is inside the (never-read) body
}

#: signature-algorithm OID -> (signature algorithm, weak digest to co-report or None)
_SIGNATURE_OIDS: dict[str, tuple[str, str | None]] = {
    "1.2.840.113549.1.1.4": ("RSA", "MD5"),
    "1.2.840.113549.1.1.5": ("RSA", "SHA-1"),
    "1.2.840.113549.1.1.11": ("RSA", None),
    "1.2.840.113549.1.1.12": ("RSA", None),
    "1.2.840.113549.1.1.13": ("RSA", None),
    "1.2.840.113549.1.1.10": ("RSA", None),  # RSASSA-PSS
    "1.2.840.10045.4.1": ("ECDSA", "SHA-1"),
    "1.2.840.10045.4.3.2": ("ECDSA", None),
    "1.2.840.10045.4.3.3": ("ECDSA", None),
    "1.2.840.10045.4.3.4": ("ECDSA", None),
    "1.2.840.10040.4.3": ("DSA", "SHA-1"),
    "1.3.101.112": ("EDDSA", None),
    "1.3.101.113": ("EDDSA", None),
}

#: SubjectPublicKeyInfo algorithm OID -> algorithm
_PUBLIC_KEY_OIDS = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "ECDSA",
    "1.2.840.10040.4.1": "DSA",
    "1.3.101.110": "ECDH",  # X25519
    "1.3.101.111": "ECDH",  # X448
    "1.3.101.112": "EDDSA",
    "1.3.101.113": "EDDSA",
}

_NGINX_PROTOCOLS = re.compile(r"^\s*ssl_protocols\s+([^;#]+)", re.IGNORECASE)
_NGINX_CIPHERS = re.compile(r"^\s*ssl_ciphers\s+['\"]?([^;#'\"]+)", re.IGNORECASE)
_APACHE_PROTOCOL = re.compile(r"^\s*SSLProtocol\s+(.+)$", re.IGNORECASE)
_APACHE_CIPHERS = re.compile(r"^\s*SSLCipherSuite\s+['\"]?([^#'\"]+)", re.IGNORECASE)
_OPENSSL_MINPROTO = re.compile(r"^\s*MinProtocol\s*=\s*(\S+)", re.IGNORECASE)
_OPENSSL_CIPHERSTRING = re.compile(r"^\s*CipherString\s*=\s*(\S+)", re.IGNORECASE)

_WEAK_SUITE_TOKENS = {
    "RC4": "RC4",
    "3DES": "3DES",
    "DES-CBC3": "3DES",
    "DES": "DES",
    "MD5": "MD5",
}


class ConfigDetector(Detector):
    """Detector for certificates, key files, keystores, and TLS configuration."""

    name = "config"
    accepts_binary = True

    def applies_to(self, path: PurePath) -> bool:
        suffix = path.suffix.lower()
        if suffix in _KEY_EXTENSIONS | _BINARY_KEY_EXTENSIONS | _CONFIG_EXTENSIONS:
            return True
        return path.name.lower() in ("openssl.cnf", "nginx.conf", "ssl.conf", "tls.conf")

    def detect(self, path: PurePath, content: str) -> Iterable[CryptoAsset]:
        suffix = path.suffix.lower()
        if not content:
            if suffix in _BINARY_KEY_EXTENSIONS:
                yield CryptoAsset(
                    algorithm="UNKNOWN",
                    file_path=str(path),
                    line_number=1,
                    detector=self.name,
                    confidence=Confidence.HIGH,
                    snippet="",
                    usage_family=Family.KEY_MATERIAL,
                    material="keystore",
                    note=f"binary key/keystore file ({suffix}); contents not read",
                )
            return
        lines = content.splitlines()
        yield from self._scan_pem_blocks(path, lines)
        yield from self._scan_ssh_keys(path, lines)
        yield from self._scan_tls_config(path, lines)

    # -- SSH public keys ----------------------------------------------------------

    _SSH_KEY_TYPES = {
        "ssh-rsa": "RSA",
        "ssh-dss": "DSA",
        "ssh-ed25519": "EDDSA",
        "ecdsa-sha2-nistp256": "ECDSA",
        "ecdsa-sha2-nistp384": "ECDSA",
        "ecdsa-sha2-nistp521": "ECDSA",
    }

    def _scan_ssh_keys(self, path: PurePath, lines: list[str]) -> Iterator[CryptoAsset]:
        for i, line_text in enumerate(lines, start=1):
            key_type = line_text.strip().split(" ", 1)[0]
            algorithm = self._SSH_KEY_TYPES.get(key_type)
            if algorithm:
                yield CryptoAsset(
                    algorithm=algorithm,
                    file_path=str(path),
                    line_number=i,
                    detector=self.name,
                    confidence=Confidence.HIGH,
                    snippet=f"{key_type} [key material not shown]",
                    usage_family=Family.SIGNATURE,
                    material="public-key",
                    note="SSH public key (host/user authentication is signature usage)",
                )

    # -- PEM material -----------------------------------------------------------

    def _scan_pem_blocks(self, path: PurePath, lines: list[str]) -> Iterator[CryptoAsset]:
        i = 0
        while i < len(lines):
            m = _PEM_BEGIN.match(lines[i].strip())
            if not m:
                i += 1
                continue
            label = m.group(1)
            start_line = i + 1  # 1-based
            body, end = self._pem_body(lines, i + 1, label)
            if label in _PRIVATE_KEY_LABELS:
                algorithm = _PRIVATE_KEY_LABELS[label] or "UNKNOWN"
                yield CryptoAsset(
                    algorithm=algorithm,
                    file_path=str(path),
                    line_number=start_line,
                    detector=self.name,
                    confidence=Confidence.HIGH,
                    snippet=f"-----BEGIN {label}----- [body not read]",
                    usage_family=None if _PRIVATE_KEY_LABELS[label] else Family.KEY_MATERIAL,
                    material="private-key",
                    note=(
                        "private-key material: location and type reported only; "
                        "key usage is unknown, scored conservatively"
                    ),
                )
            elif label == "CERTIFICATE":
                yield from self._certificate_assets(path, start_line, body)
            elif label == "PUBLIC KEY":
                yield from self._public_key_assets(path, start_line, body)
            i = end
        return

    @staticmethod
    def _pem_body(lines: list[str], start: int, label: str) -> tuple[str, int]:
        """Collect the base64 body until the matching END line (or EOF)."""
        body: list[str] = []
        i = start
        while i < len(lines):
            if lines[i].strip() == f"-----END {label}-----":
                return "".join(body), i + 1
            body.append(lines[i].strip())
            i += 1
        return "".join(body), i

    def _certificate_assets(
        self, path: PurePath, line: int, body: str
    ) -> Iterator[CryptoAsset]:
        oid = _certificate_signature_oid(_decode_b64(body))
        mapped = _SIGNATURE_OIDS.get(oid or "")
        if mapped is None:
            yield CryptoAsset(
                algorithm="UNKNOWN",
                file_path=str(path),
                line_number=line,
                detector=self.name,
                confidence=Confidence.LOW,
                snippet="-----BEGIN CERTIFICATE-----",
                usage_family=Family.KEY_MATERIAL,
                material="certificate",
                note="certificate did not parse cleanly; presence reported only",
            )
            return
        algorithm, weak_digest = mapped
        yield CryptoAsset(
            algorithm=algorithm,
            file_path=str(path),
            line_number=line,
            detector=self.name,
            confidence=Confidence.HIGH,
            snippet="-----BEGIN CERTIFICATE-----",
            usage_family=Family.SIGNATURE,
            material="certificate",
            note=f"certificate signature algorithm (OID {oid})",
        )
        if weak_digest:
            yield CryptoAsset(
                algorithm=weak_digest,
                file_path=str(path),
                line_number=line,
                detector=self.name,
                confidence=Confidence.HIGH,
                snippet="-----BEGIN CERTIFICATE-----",
                usage_family=Family.HASH,
                material="certificate",
                note=f"weak digest in certificate signature (OID {oid})",
            )

    def _public_key_assets(
        self, path: PurePath, line: int, body: str
    ) -> Iterator[CryptoAsset]:
        oid = _spki_algorithm_oid(_decode_b64(body))
        algorithm = _PUBLIC_KEY_OIDS.get(oid or "")
        yield CryptoAsset(
            algorithm=algorithm or "UNKNOWN",
            file_path=str(path),
            line_number=line,
            detector=self.name,
            confidence=Confidence.HIGH if algorithm else Confidence.LOW,
            snippet="-----BEGIN PUBLIC KEY-----",
            usage_family=None if algorithm else Family.KEY_MATERIAL,
            material="public-key",
            note=(
                f"public key algorithm (OID {oid})"
                if algorithm
                else "public key did not parse cleanly; presence reported only"
            ),
        )

    # -- TLS configuration --------------------------------------------------------

    def _scan_tls_config(self, path: PurePath, lines: list[str]) -> Iterator[CryptoAsset]:
        for i, line_text in enumerate(lines, start=1):
            protocols: list[str] = []
            for pattern in (_NGINX_PROTOCOLS, _APACHE_PROTOCOL, _OPENSSL_MINPROTO):
                m = pattern.match(line_text)
                if m:
                    for token in m.group(1).split():
                        if token.startswith(("-", "!")):
                            continue  # Apache exclusion syntax: protocol disabled
                        token = token.removeprefix("+")  # "+TLSv1" enables it
                        if token.lower() == "all":
                            continue
                        protocols.append(token)
            for token in protocols:
                info = lookup(token)
                if info is not None and info.family == Family.PROTOCOL:
                    yield CryptoAsset(
                        algorithm=info.name,
                        file_path=str(path),
                        line_number=i,
                        detector=self.name,
                        confidence=Confidence.MEDIUM,
                        snippet=make_snippet(lines, i),
                        usage_family=Family.PROTOCOL,
                        note="TLS protocol version enabled in configuration",
                    )
            for pattern in (_NGINX_CIPHERS, _APACHE_CIPHERS, _OPENSSL_CIPHERSTRING):
                m = pattern.match(line_text)
                if not m:
                    continue
                suite = m.group(1).upper()
                for token, algorithm in _WEAK_SUITE_TOKENS.items():
                    if token in suite and f"!{token}" not in suite:
                        # "DES" is a cipher-suite algorithm name here, not a secret.
                        if token == "DES" and ("3DES" in suite or "DES-CBC3" in suite):
                            continue
                        yield CryptoAsset(
                            algorithm=algorithm,
                            file_path=str(path),
                            line_number=i,
                            detector=self.name,
                            confidence=Confidence.MEDIUM,
                            snippet=make_snippet(lines, i),
                            note=f"cipher-suite configuration contains {token}",
                        )


# -- minimal defensive DER walking (certificates/public keys are public data) --


def _decode_b64(body: str) -> bytes | None:
    try:
        return base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        return None


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int] | None:
    """Read one DER TLV; returns (tag, value, next_offset) or None on any problem."""
    if offset + 2 > len(data):
        return None
    tag = data[offset]
    length_byte = data[offset + 1]
    offset += 2
    if length_byte < 0x80:
        length = length_byte
    else:
        n = length_byte & 0x7F
        if n == 0 or n > 4 or offset + n > len(data):
            return None
        length = int.from_bytes(data[offset : offset + n], "big")
        offset += n
    if offset + length > len(data):
        return None
    return tag, data[offset : offset + length], offset + length


def _decode_oid(value: bytes) -> str | None:
    if not value:
        return None
    parts = [value[0] // 40, value[0] % 40]
    acc = 0
    for byte in value[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(acc)
            acc = 0
    if acc:  # truncated multi-byte component
        return None
    return ".".join(str(p) for p in parts)


def _certificate_signature_oid(der: bytes | None) -> str | None:
    """Extract signatureAlgorithm OID from Certificate ::= SEQ{tbs, sigAlg, sig}."""
    if not der:
        return None
    outer = _read_tlv(der, 0)
    if outer is None or outer[0] != 0x30:
        return None
    body = outer[1]
    tbs = _read_tlv(body, 0)
    if tbs is None:
        return None
    sig_alg = _read_tlv(body, tbs[2])
    if sig_alg is None or sig_alg[0] != 0x30:
        return None
    oid_tlv = _read_tlv(sig_alg[1], 0)
    if oid_tlv is None or oid_tlv[0] != 0x06:
        return None
    return _decode_oid(oid_tlv[1])


def _spki_algorithm_oid(der: bytes | None) -> str | None:
    """Extract algorithm OID from SubjectPublicKeyInfo ::= SEQ{SEQ{OID,...}, BITSTRING}."""
    if not der:
        return None
    outer = _read_tlv(der, 0)
    if outer is None or outer[0] != 0x30:
        return None
    alg_seq = _read_tlv(outer[1], 0)
    if alg_seq is None or alg_seq[0] != 0x30:
        return None
    oid_tlv = _read_tlv(alg_seq[1], 0)
    if oid_tlv is None or oid_tlv[0] != 0x06:
        return None
    return _decode_oid(oid_tlv[1])
