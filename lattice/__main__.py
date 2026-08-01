"""Enable ``python -m lattice`` as an alias for the console script.

Runs the same entry point as the ``lattice`` command, so the tool works even
when the console script's install directory is not on PATH.
"""

from __future__ import annotations

import sys

from lattice.cli import main

if __name__ == "__main__":
    sys.exit(main())
