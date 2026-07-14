"""Fixture: classically broken hash usage.

Known answers (exactly one asset):
- MD5 at the hl.md5(...) call -> classical broken, priority P0, confidence high.
  The aliased import must not defeat detection.
"""

import hashlib as hl


def checksum(data: bytes) -> str:
    return hl.md5(data).hexdigest()  # KNOWN: MD5, P0
