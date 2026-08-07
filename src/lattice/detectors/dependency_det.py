"""Dependency detector: crypto libraries declared in package manifests.

Manifest entries become CBOM *inventory* components (priority: none) with
the honest note "usage not confirmed by a call site" — a declared library
proves presence, not use. Confidence is HIGH for presence itself. Special
knowledge (an unmaintained library, a post-quantum library) is carried in
the note, never as an invented vulnerability.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable, Iterator
from pathlib import PurePath

from lattice.core.models import Confidence, CryptoAsset, Family
from lattice.detectors.base import Detector, make_snippet

_PYTHON_LIBS = {
    "cryptography": "",
    "pycryptodome": "",
    "pycryptodomex": "",
    "pycrypto": "unmaintained since 2014; migrate to pycryptodome or cryptography",
    "bcrypt": "",
    "argon2-cffi": "",
    "pynacl": "",
    "m2crypto": "",
    "pyopenssl": "",
    "paramiko": "",
    "pyjwt": "",
    "jwcrypto": "",
    "oscrypto": "",
    "hkdf": "",
}

_JS_LIBS = {
    "node-forge": "",
    "jsrsasign": "",
    "crypto-js": "",
    "elliptic": "",
    "tweetnacl": "",
    "libsodium-wrappers": "",
    "openpgp": "",
    "jose": "",
    "bcrypt": "",
    "bcryptjs": "",
    "argon2": "",
    "sshpk": "",
    "md5": "package implements MD5 (classically broken)",
    "sha1": "package implements SHA-1 (classically broken)",
}

_JAVA_ARTIFACT_PREFIXES = {
    "bcprov": "BouncyCastle provider",
    "bcpkix": "BouncyCastle PKIX",
    "bctls": "BouncyCastle TLS",
    "tink": "Google Tink",
    "jasypt": "Jasypt",
    "conscrypt": "Conscrypt",
}

_GO_MODULES = {
    "golang.org/x/crypto": "",
    "github.com/cloudflare/circl": "includes post-quantum algorithms",
    "filippo.io/age": "",
    "github.com/ProtonMail/go-crypto": "",
}

_RUST_CRATES = {
    "ring": "",
    "rustls": "",
    "openssl": "",
    "sodiumoxide": "",
    "rust-crypto": "unmaintained; migrate to RustCrypto crates",
    "sha1": "crate implements SHA-1 (classically broken)",
    "sha2": "",
    "sha3": "",
    "md-5": "crate implements MD5 (classically broken)",
    "md5": "crate implements MD5 (classically broken)",
    "rsa": "",
    "ed25519-dalek": "",
    "x25519-dalek": "",
    "aes": "",
    "aes-gcm": "",
    "chacha20poly1305": "",
    "argon2": "",
    "bcrypt": "",
    "scrypt": "",
    "pbkdf2": "",
    "blake2": "",
    "blake3": "",
    "pqcrypto": "post-quantum library",
    "ml-kem": "post-quantum library",
    "ml-dsa": "post-quantum library",
}


class DependencyDetector(Detector):
    """Parses dependency manifests for known cryptographic libraries."""

    name = "dependency"

    def applies_to(self, path: PurePath) -> bool:
        name = path.name.lower()
        return (name.startswith("requirements") and name.endswith(".txt")) or name in (
            "package.json",
            "pom.xml",
            "go.mod",
            "cargo.toml",
            "pyproject.toml",
            "build.gradle",
            "build.gradle.kts",
            "pipfile",
        )

    def detect(self, path: PurePath, content: str) -> Iterable[CryptoAsset]:
        name = path.name.lower()
        lines = content.splitlines()
        if name.startswith("requirements") or name == "pipfile":
            yield from self._match_lines(path, lines, _PYTHON_LIBS, _requirement_name)
        elif name == "pyproject.toml":
            yield from self._pyproject(path, content, lines)
        elif name == "package.json":
            yield from self._package_json(path, content, lines)
        elif name == "pom.xml":
            yield from self._pom(path, lines)
        elif name == "go.mod":
            yield from self._go_mod(path, lines)
        elif name == "cargo.toml":
            yield from self._cargo(path, content, lines)
        elif name.startswith("build.gradle"):
            yield from self._gradle(path, lines)

    # -- emission helper ---------------------------------------------------------

    def _library(
        self, path: PurePath, line: int, lines: list[str], library: str, extra_note: str
    ) -> CryptoAsset:
        note = "declared dependency; usage not confirmed by a call site"
        if extra_note:
            note += f" ({extra_note})"
        return CryptoAsset(
            algorithm=library,
            file_path=str(path),
            line_number=line,
            detector=self.name,
            confidence=Confidence.HIGH,
            snippet=make_snippet(lines, line),
            usage_family=Family.LIBRARY,
            note=note,
        )

    def _match_lines(
        self,
        path: PurePath,
        lines: list[str],
        table: dict[str, str],
        extract,
    ) -> Iterator[CryptoAsset]:
        seen: set[str] = set()
        for i, line in enumerate(lines, start=1):
            candidate = extract(line)
            if candidate and candidate in table and candidate not in seen:
                seen.add(candidate)
                yield self._library(path, i, lines, candidate, table[candidate])

    # -- per-manifest parsers -----------------------------------------------------

    def _pyproject(self, path: PurePath, content: str, lines: list[str]) -> Iterator[CryptoAsset]:
        try:
            doc = tomllib.loads(content)
        except tomllib.TOMLDecodeError:
            return
        deps: list[str] = list(doc.get("project", {}).get("dependencies", []))
        for extras in doc.get("project", {}).get("optional-dependencies", {}).values():
            deps.extend(extras)
        seen: set[str] = set()
        for dep in deps:
            library = _requirement_name(dep)
            if library in _PYTHON_LIBS and library not in seen:
                seen.add(library)
                line = _find_line(lines, library)
                yield self._library(path, line, lines, library, _PYTHON_LIBS[library])

    def _package_json(
        self, path: PurePath, content: str, lines: list[str]
    ) -> Iterator[CryptoAsset]:
        try:
            doc = json.loads(content)
        except json.JSONDecodeError:
            return
        seen: set[str] = set()
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for library in doc.get(section, {}) or {}:
                if library in _JS_LIBS and library not in seen:
                    seen.add(library)
                    line = _find_line(lines, f'"{library}"')
                    yield self._library(path, line, lines, library, _JS_LIBS[library])

    def _pom(self, path: PurePath, lines: list[str]) -> Iterator[CryptoAsset]:
        seen: set[str] = set()
        for i, line in enumerate(lines, start=1):
            m = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", line)
            if not m:
                continue
            artifact = m.group(1)
            for prefix, label in _JAVA_ARTIFACT_PREFIXES.items():
                if artifact.startswith(prefix) and artifact not in seen:
                    seen.add(artifact)
                    yield self._library(path, i, lines, artifact, label)

    def _go_mod(self, path: PurePath, lines: list[str]) -> Iterator[CryptoAsset]:
        seen: set[str] = set()
        for i, line in enumerate(lines, start=1):
            stripped = line.strip().removeprefix("require ").strip()
            module = stripped.split()[0] if stripped.split() else ""
            for known, label in _GO_MODULES.items():
                if module == known and known not in seen:
                    seen.add(known)
                    yield self._library(path, i, lines, known, label)

    def _cargo(self, path: PurePath, content: str, lines: list[str]) -> Iterator[CryptoAsset]:
        try:
            doc = tomllib.loads(content)
        except tomllib.TOMLDecodeError:
            return
        seen: set[str] = set()
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for library in doc.get(section, {}) or {}:
                if library in _RUST_CRATES and library not in seen:
                    seen.add(library)
                    line = _find_line(lines, library)
                    yield self._library(path, line, lines, library, _RUST_CRATES[library])

    def _gradle(self, path: PurePath, lines: list[str]) -> Iterator[CryptoAsset]:
        seen: set[str] = set()
        for i, line in enumerate(lines, start=1):
            m = re.search(r"['\"]org\.bouncycastle:([A-Za-z0-9._-]+):", line)
            if m and m.group(1) not in seen:
                seen.add(m.group(1))
                yield self._library(path, i, lines, m.group(1), "BouncyCastle")
            m = re.search(r"['\"]com\.google\.crypto\.tink:([A-Za-z0-9._-]+):", line)
            if m and m.group(1) not in seen:
                seen.add(m.group(1))
                yield self._library(path, i, lines, m.group(1), "Google Tink")


def _requirement_name(line: str) -> str:
    """Package name from a requirements/PEP 508 line (lowercased, extras stripped)."""
    line = line.strip()
    if not line or line.startswith(("#", "-")):
        return ""
    return re.split(r"[=<>!~\[; @]", line, maxsplit=1)[0].lower()


def _find_line(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines, start=1):
        if needle in line:
            return i
    return 1
