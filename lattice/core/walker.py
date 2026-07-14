"""File discovery: recursion, excludes, .gitignore subset, binary and size guards.

The walker is the only component that touches the filesystem. It yields
``(path, content)`` pairs; binary files are yielded with ``content=None`` so
that binary-aware detectors (key material, keystores) can still report their
*presence* without anyone reading key bytes into a report.

.gitignore support is an honest subset: literal names, ``*`` globs, and
directory patterns from the scan root's .gitignore. Negations (``!``) and
nested .gitignore files are not implemented (documented limitation).
"""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator
from pathlib import Path

from lattice.core.models import ScanStats

#: vendored/build trees that are never the scan target's own code
DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".venv",
        "venv",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "__pycache__",
        "node_modules",
        "vendor",
        "third_party",
        "target",
        "dist",
        "build",
        "site-packages",
        ".eggs",
    }
)

DEFAULT_MAX_FILE_BYTES = 1_000_000


class Walker:
    """Walks a directory tree (or single file) applying all skip rules."""

    def __init__(
        self,
        root: Path,
        exclude: tuple[str, ...] = (),
        max_bytes: int = DEFAULT_MAX_FILE_BYTES,
        respect_gitignore: bool = True,
    ) -> None:
        self.root = root
        self.exclude = tuple(exclude)
        self.max_bytes = max_bytes
        self.stats = ScanStats()
        self._gitignore: list[str] = []
        if respect_gitignore and root.is_dir():
            self._gitignore = _load_gitignore(root / ".gitignore")

    def walk(self) -> Iterator[tuple[Path, str | None]]:
        """Yield (path, text content) pairs; content is None for binary files."""
        if self.root.is_file():
            item = self._load(self.root)
            if item is not None:
                yield self.root, (None if item == _BINARY else item)
            return
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = sorted(
                d
                for d in dirnames
                if d not in DEFAULT_EXCLUDED_DIRS
                and not self._excluded(Path(dirpath, d), is_dir=True)
            )
            for filename in sorted(filenames):
                path = Path(dirpath, filename)
                if self._excluded(path, is_dir=False):
                    self._skip(path, "excluded")
                    continue
                content = self._load(path)
                if content is not None:
                    yield path, (None if content == _BINARY else content)

    # -- skip rules -----------------------------------------------------------

    def _excluded(self, path: Path, is_dir: bool) -> bool:
        rel = path.relative_to(self.root).as_posix()
        candidates = (rel, path.name, rel + "/" if is_dir else rel)
        for pattern in self.exclude:
            if any(fnmatch.fnmatch(c, pattern) for c in candidates):
                return True
        for pattern in self._gitignore:
            if pattern.endswith("/"):
                if is_dir and fnmatch.fnmatch(rel + "/", pattern + "*"):
                    return True
                if fnmatch.fnmatch(rel, pattern.rstrip("/") + "/*"):
                    return True
            elif fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(path.name, pattern):
                return True
        return False

    def _skip(self, path: Path, reason: str) -> None:
        self.stats.files_skipped += 1
        if len(self.stats.skipped_reasons) < 200:  # keep the report bounded
            self.stats.skipped_reasons.append(f"{path}: {reason}")

    # -- loading ----------------------------------------------------------------

    def _load(self, path: Path) -> str | None:
        """Read a file defensively. Returns text, the binary sentinel, or None."""
        try:
            size = path.stat().st_size
            if size > self.max_bytes:
                self._skip(path, f"exceeds size cap ({size} bytes)")
                return None
            raw = path.read_bytes()
        except OSError as exc:
            self._skip(path, f"unreadable ({exc.__class__.__name__})")
            return None
        if b"\x00" in raw[:4096]:
            return _BINARY
        return raw.decode("utf-8", errors="replace")


#: sentinel: file exists and is within limits, but is binary
_BINARY = "\x00__lattice_binary__"


def _load_gitignore(path: Path) -> list[str]:
    """Parse the root .gitignore into fnmatch-able patterns (subset; see module doc)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    patterns: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue  # negations are unsupported; skipping is the safe direction
        patterns.append(line.lstrip("/"))
    return patterns
