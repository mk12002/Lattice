"""Detector interface plus shared helpers (snippet redaction, regex fallback).

A detector turns file content into ``CryptoAsset`` instances. Detectors never
assess severity (that is ``core.severity``'s job) and never read files
themselves (the walker hands them content) — this keeps them trivially
testable and keeps I/O in one place.
"""

from __future__ import annotations

import bisect
import re
from abc import ABC, abstractmethod
from collections.abc import Iterable
from pathlib import PurePath

from lattice.core.models import Confidence, CryptoAsset

#: Runs of >=24 base64/hex-ish characters are replaced before a snippet is
#: stored: they may be embedded keys, tokens, or other secret material.
_SECRET_RUN = re.compile(r"[A-Za-z0-9+/=_\-]{24,}")
_PEM_LINE = re.compile(r"-----(BEGIN|END)[^-]*-----")

_MAX_SNIPPET = 160


def redact(text: str) -> str:
    """Redact potential secret material from a snippet.

    Conservative by design: any long base64/hex-looking run is masked, and
    PEM body lines are dropped entirely. Losing a little context is always
    preferable to leaking a key byte into a report.
    """
    if _PEM_LINE.search(text):
        return "[PEM material redacted]"
    return _SECRET_RUN.sub("[redacted]", text)


def make_snippet(lines: list[str], line_number: int) -> str:
    """Return the redacted, truncated source line for a 1-based line number."""
    if not 1 <= line_number <= len(lines):
        return ""
    snippet = redact(lines[line_number - 1].strip())
    if len(snippet) > _MAX_SNIPPET:
        snippet = snippet[: _MAX_SNIPPET - 1] + "…"
    return snippet


class LineIndex:
    """Map string offsets to 1-based line numbers in O(log n) per lookup.

    Regex detectors that match on the whole document and need each match's
    line would otherwise call ``content.count("\\n", 0, offset)`` per match —
    O(matches x length), quadratic on a hostile file crafted to contain many
    matches. Precomputing newline offsets once and binary-searching keeps a
    scan linear regardless of how adversarial the input is.
    """

    __slots__ = ("_newlines",)

    def __init__(self, content: str) -> None:
        self._newlines = [i for i, ch in enumerate(content) if ch == "\n"]

    def line_of(self, offset: int) -> int:
        return bisect.bisect_right(self._newlines, offset - 1) + 1


class Detector(ABC):
    """One source of CryptoAssets. Subclass and register with the engine.

    Contract: ``detect`` must only yield assets that trace to a concrete
    matched pattern at a real line — no speculative findings — and must
    never raise on malformed input (degrade to lower-confidence matching
    or yield nothing instead).
    """

    #: short stable identifier, used in reports and SARIF rule ids
    name: str = "base"

    @abstractmethod
    def applies_to(self, path: PurePath) -> bool:
        """Whether this detector wants to see the file at ``path``."""

    @abstractmethod
    def detect(self, path: PurePath, content: str) -> Iterable[CryptoAsset]:
        """Yield every crypto asset matched in ``content``."""


#: Algorithm keywords for the last-resort regex scan. Word-ish boundaries;
#: only names distinctive enough to be meaningful as bare tokens.
_FALLBACK_TOKENS: dict[str, str] = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha-1": "SHA-1",
    "3des": "3DES",
    "des-ede3": "3DES",
    "blowfish": "BLOWFISH",
    "rc4": "RC4",
    "arcfour": "RC4",
    "chacha20": "CHACHA20",
    "ed25519": "EDDSA",
    "x25519": "ECDH",
    "secp256r1": "ECDSA",
    "prime256v1": "ECDSA",
    "secp384r1": "ECDSA",
    "kyber": "ML-KEM",
    "ml-kem": "ML-KEM",
    "dilithium": "ML-DSA",
    "ml-dsa": "ML-DSA",
    "sphincs": "SLH-DSA",
    "pbkdf2": "PBKDF2",
    "bcrypt": "BCRYPT",
    "scrypt": "SCRYPT",
    "argon2": "ARGON2",
}

_FALLBACK_RE = re.compile(
    r"(?<![A-Za-z0-9])("
    + "|".join(re.escape(t) for t in sorted(_FALLBACK_TOKENS, key=len, reverse=True))
    + r")(?![A-Za-z0-9])",
    re.IGNORECASE,
)


def regex_fallback_scan(path: PurePath, content: str, detector_name: str) -> Iterable[CryptoAsset]:
    """Last-resort scan for unparseable files: bare algorithm tokens, LOW confidence.

    Used when a language detector cannot parse a file it applies to. Every
    hit is honestly marked LOW — a token match proves nothing about usage.
    """
    lines = content.splitlines()
    seen: set[tuple[int, str]] = set()
    for i, line in enumerate(lines, start=1):
        for m in _FALLBACK_RE.finditer(line):
            algorithm = _FALLBACK_TOKENS[m.group(1).lower()]
            if (i, algorithm) in seen:
                continue
            seen.add((i, algorithm))
            yield CryptoAsset(
                algorithm=algorithm,
                file_path=str(path),
                line_number=i,
                detector=detector_name,
                confidence=Confidence.LOW,
                snippet=make_snippet(lines, i),
                note="token match in unparsed file",
            )
