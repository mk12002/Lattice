# Examples

Runnable examples for using Lattice from the command line and as a Python library.
Install Lattice first (`pip install -e .` from the repo root), then run any script.

| File | Shows |
|---|---|
| [`python_api.py`](python_api.py) | Scan a directory programmatically and inspect findings without the CLI |
| [`scan_and_gate.py`](scan_and_gate.py) | Scan, emit all three report formats, and compute a pass/fail like `--fail-on P0` |
| [`custom_policy.py`](custom_policy.py) | Define and evaluate a custom compliance policy pack |
| [`ci_diff.sh`](ci_diff.sh) | The drift-gate workflow: block PRs that *introduce* new P0 crypto |

Config/CI examples (copy into your own repo) live in [`../docs/examples/`](../docs/examples/):
a pre-commit hook config and a GitHub Actions SARIF-upload workflow.
