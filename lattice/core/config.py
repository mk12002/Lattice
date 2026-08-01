"""Optional scan defaults from ``lattice.toml``'s ``[scan]`` table.

Teams re-pass the same ``--exclude``/``--languages``/``--fail-on`` flags in
every CI job. A ``[scan]`` table in the project's ``lattice.toml`` (the same
file that holds acceptances, see ``suppress.py``) lets those defaults live in
the repo instead. Explicit CLI flags always win over the file; the file wins
over the built-in defaults.

.. code-block:: toml

    [scan]
    exclude = ["build/**", "vendor/**"]     # extra globs to skip
    languages = ["py", "go", "rust"]        # restrict language detectors
    fail_on = "P0"                          # default gate threshold
    max_file_bytes = 2000000                # per-file size cap

Malformed values are ignored with a warning, never applied silently — the
same fail-safe posture as the acceptance loader.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from lattice.core.suppress import ACCEPT_FILENAME

_VALID_LANGUAGES = frozenset(
    {"py", "java", "js", "go", "c", "rust", "csharp", "ruby", "php", "swift", "config", "deps"}
)
_VALID_FAIL_ON = frozenset({"P0", "P1", "P2", "P3"})


@dataclass
class ScanConfig:
    """Scan defaults parsed from ``[scan]`` (all optional)."""

    exclude: list[str] = field(default_factory=list)
    languages: list[str] | None = None
    fail_on: str | None = None
    max_file_bytes: int | None = None


def load_scan_config(root: Path) -> tuple[ScanConfig, list[str]]:
    """Load the ``[scan]`` table from ``<root>/lattice.toml``.

    Returns ``(config, warnings)``. A missing file or missing ``[scan]``
    table yields an empty config with no warnings.
    """
    path = root / ACCEPT_FILENAME
    if not path.is_file():
        return ScanConfig(), []
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        return ScanConfig(), [f"{ACCEPT_FILENAME}: unreadable ({exc}); [scan] defaults ignored"]

    section = doc.get("scan")
    if section is None:
        return ScanConfig(), []
    warnings: list[str] = []
    if not isinstance(section, dict):
        return ScanConfig(), [f"{ACCEPT_FILENAME}: [scan] must be a table; ignored"]

    config = ScanConfig()

    exclude = section.get("exclude")
    if exclude is not None:
        if isinstance(exclude, list) and all(isinstance(x, str) for x in exclude):
            config.exclude = exclude
        else:
            warnings.append(f"{ACCEPT_FILENAME}: [scan] exclude must be a list of strings; ignored")

    languages = section.get("languages")
    if languages is not None:
        if isinstance(languages, list) and all(isinstance(x, str) for x in languages):
            unknown = [x for x in languages if x not in _VALID_LANGUAGES]
            if unknown:
                warnings.append(
                    f"{ACCEPT_FILENAME}: [scan] languages has unknown value(s) "
                    f"{', '.join(unknown)}; ignored"
                )
            else:
                config.languages = languages
        else:
            warnings.append(f"{ACCEPT_FILENAME}: [scan] languages must be a list of strings; ignored")

    fail_on = section.get("fail_on")
    if fail_on is not None:
        if isinstance(fail_on, str) and fail_on in _VALID_FAIL_ON:
            config.fail_on = fail_on
        else:
            warnings.append(f"{ACCEPT_FILENAME}: [scan] fail_on must be one of P0-P3; ignored")

    max_bytes = section.get("max_file_bytes")
    if max_bytes is not None:
        if isinstance(max_bytes, int) and not isinstance(max_bytes, bool) and max_bytes > 0:
            config.max_file_bytes = max_bytes
        else:
            warnings.append(f"{ACCEPT_FILENAME}: [scan] max_file_bytes must be a positive integer; ignored")

    return config, warnings
