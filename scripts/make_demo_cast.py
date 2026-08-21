#!/usr/bin/env python3
"""Generate docs/demo.cast: an asciinema v2 recording of a real `lattice scan`.

The output is captured from an actual scan, so the recording is authentic (not
mocked). Regenerate after CLI changes:  python scripts/make_demo_cast.py

View it with asciinema (`asciinema play docs/demo.cast`), upload it to
asciinema.org, or embed it with asciinema-player.
"""

from __future__ import annotations

import json

# subprocess runs the project's own CLI (via sys.executable) with a fixed arg list.
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path

ESC = chr(27)
GREEN = f"{ESC}[32m"
RED = f"{ESC}[31m"
GREY = f"{ESC}[90m"
RESET = f"{ESC}[0m"
CRLF = "\r\n"


def build_events(output_lines: list[str]) -> list[list]:
    events: list[list] = []
    t = 0.0

    def emit(text: str, dt: float) -> None:
        nonlocal t
        t += dt
        events.append([round(t, 3), "o", text])

    prompt = f"{GREEN}${RESET} "
    emit(prompt, 0.5)
    for ch in "lattice scan . --format all --fail-on P0":
        emit(ch, 0.035)
    emit(CRLF, 0.3)
    for line in output_lines:
        emit(line + CRLF, 0.18)
    emit(CRLF + prompt, 0.6)
    for ch in "echo $?":
        emit(ch, 0.035)
    emit(CRLF, 0.3)
    emit(f"{RED}1{RESET}  {GREY}# CI blocks the merge: a P0 finding is present{RESET}{CRLF}", 0.3)
    emit(CRLF + prompt, 0.4)
    return events


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory() as tmp:
        # Fixed arg list; sys.executable is an absolute interpreter path.
        cmd = [
            sys.executable, "-m", "lattice", "scan",
            str(root / "tests" / "fixtures" / "python"),
            "--format", "all", "--out", tmp, "--fail-on", "P0",
        ]  # fmt: skip
        proc = subprocess.run(cmd, capture_output=True, text=True)  # nosec B603
    output_lines = proc.stdout.splitlines()

    header = {
        "version": 2,
        "width": 92,
        "height": 20,
        "timestamp": 0,
        "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
        "title": "lattice scan",
    }
    cast_path = root / "docs" / "demo.cast"
    with cast_path.open("w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(header) + "\n")
        for event in build_events(output_lines):
            f.write(json.dumps(event) + "\n")
    print(f"wrote {cast_path} ({len(output_lines)} output lines; scan exit {proc.returncode})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
