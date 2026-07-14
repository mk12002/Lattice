"""Accepted-risk suppressions: the ``lattice.toml`` acceptance file.

Teams sometimes need CI to stay green while a known finding is tracked —
an MD5 used as a non-security cache key, a legacy service scheduled for
decommission. Silencing the scanner entirely destroys the inventory, so
Lattice supports *acceptances* instead: the finding stays in every report,
visibly marked, but stops tripping the --fail-on gate and stops counting
against the readiness score.

File format (``lattice.toml`` at the scan root):

.. code-block:: toml

    [[accept]]
    algorithm = "MD5"                  # required: canonical name or synonym
    path = "legacy/**"                 # optional: glob on the reported path
    reason = "cache key, not security; tracked in TICKET-123"  # required
    expires = "2027-01-01"             # optional: ISO date; ignored after

Every acceptance must carry a reason — an unexplained suppression is a
lie the next reader can't audit. Expired or malformed entries are ignored
with a warning so they never silently keep suppressing.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import tomllib
from dataclasses import dataclass
from pathlib import Path

from lattice.core.models import Finding
from lattice.rules.algorithms import lookup

ACCEPT_FILENAME = "lattice.toml"


@dataclass(frozen=True)
class Acceptance:
    """One accepted-risk rule from lattice.toml."""

    algorithm: str  # canonicalized
    path_glob: str
    reason: str
    expires: dt.date | None

    def matches(self, finding: Finding) -> bool:
        if finding.asset.algorithm.upper() != self.algorithm:
            return False
        path = finding.asset.file_path
        return fnmatch.fnmatch(path, self.path_glob) or fnmatch.fnmatch(
            path, self.path_glob.rstrip("/") + "/*"
        )


def load_acceptances(
    root: Path, today: dt.date | None = None
) -> tuple[list[Acceptance], list[str]]:
    """Load acceptances from ``<root>/lattice.toml``.

    Returns (valid acceptances, human-readable warnings). Malformed or
    expired entries become warnings, never silent suppressions.
    """
    today = today or dt.date.today()
    path = root / ACCEPT_FILENAME
    if not path.is_file():
        return [], []
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        return [], [f"{ACCEPT_FILENAME}: unreadable ({exc}); no findings accepted"]

    acceptances: list[Acceptance] = []
    warnings: list[str] = []
    entries = doc.get("accept", [])
    if not isinstance(entries, list):
        return [], [f"{ACCEPT_FILENAME}: [[accept]] must be an array of tables"]
    for i, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            warnings.append(f"{ACCEPT_FILENAME}: accept #{i} is not a table; ignored")
            continue
        raw_algorithm = str(entry.get("algorithm", "")).strip()
        reason = str(entry.get("reason", "")).strip()
        if not raw_algorithm:
            warnings.append(f"{ACCEPT_FILENAME}: accept #{i} has no algorithm; ignored")
            continue
        if not reason:
            warnings.append(
                f"{ACCEPT_FILENAME}: accept #{i} ({raw_algorithm}) has no reason; "
                "ignored — every acceptance must be auditable"
            )
            continue
        info = lookup(raw_algorithm)
        algorithm = info.name if info else raw_algorithm.upper()
        expires: dt.date | None = None
        raw_expires = entry.get("expires")
        if raw_expires is not None:
            expires = _parse_date(raw_expires)
            if expires is None:
                warnings.append(
                    f"{ACCEPT_FILENAME}: accept #{i} ({raw_algorithm}) has invalid "
                    f"expires {raw_expires!r}; ignored"
                )
                continue
            if expires < today:
                warnings.append(
                    f"{ACCEPT_FILENAME}: acceptance of {algorithm} expired "
                    f"{expires.isoformat()}; finding is active again"
                )
                continue
        acceptances.append(
            Acceptance(
                algorithm=algorithm,
                path_glob=str(entry.get("path", "*")),
                reason=reason,
                expires=expires,
            )
        )
    return acceptances, warnings


def _parse_date(value: object) -> dt.date | None:
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            return None
    return None


def apply_acceptances(
    findings: list[Finding], acceptances: list[Acceptance]
) -> list[Finding]:
    """Return findings with matching ones marked accepted (order preserved)."""
    if not acceptances:
        return findings
    import dataclasses

    result: list[Finding] = []
    for finding in findings:
        reason = next(
            (a.reason for a in acceptances if a.matches(finding)), None
        )
        if reason is not None and finding.accepted_reason is None:
            finding = dataclasses.replace(finding, accepted_reason=reason)
        result.append(finding)
    return result
