# Command & Configuration Reference

## `lattice scan <path>`

| Option | Values | Default | Meaning |
|---|---|---|---|
| `--format` | `cbom` \| `html` \| `sarif` \| `all` | `html` | which report(s) to emit |
| `--out DIR` | path | `lattice-report/` | output directory |
| `--fail-on` | `P0`–`P3` | (none) | exit 1 if any non-accepted finding is at/above this priority |
| `--exclude GLOB` | glob (repeatable) | (none) | extra paths to skip |
| `--languages LIST` | `py,java,js,go,c,rust,csharp,ruby,php,swift` | all | restrict language detectors (config + deps always run) |
| `--policy` | `cnsa2` \| `cnsa1` \| `fips140` | (none) | also gate on a compliance profile |
| `--max-file-bytes N` | positive int | 1000000 | per-file size cap |
| `--quiet` | flag | | suppress the stdout summary |
| `-v`, `--verbose` | flag | | emit diagnostic logging to stderr |

Output filenames in `--out`: `cbom.json`, `report.html`, `findings.sarif`.

## `lattice diff <baseline.json> <current.json>`

Compares two CBOM JSON files and reports cryptographic drift.

| Option | Values | Meaning |
|---|---|---|
| `--fail-on-new` | `P0`–`P3` | exit 1 if new findings at/above this priority appeared |
| `--format` | `text` \| `json` | drift output format (default: text) |
| `--out FILE` | path | write the drift report to a file instead of stdout |

## `lattice rules list` · `lattice version`

`rules list` prints the entire knowledge base as a table. `version` prints the tool version
(also embedded in every CBOM and SARIF report).

## Exit codes

| Code | Meaning |
|---|---|
| **0** | success; no gate tripped |
| **1** | a gate tripped: `--fail-on`, `--policy`, or `diff --fail-on-new` |
| **2** | usage error: path not found, unknown language, invalid argument, unreadable CBOM |

## `lattice.toml`

Placed at the **scan root**, this file holds two optional sections.

### `[[accept]]` — accepted-risk entries

Matching findings stay in every report (marked, with the reason) but leave the `--fail-on`
gate and the readiness score.

```toml
[[accept]]
algorithm = "MD5"                                  # required (canonical name or synonym)
path = "legacy/cache/**"                            # optional glob (default "*")
reason = "content-addressing hash, not security; TICKET-123"   # required
expires = 2027-01-01                                # optional; after it, the finding is active again
```

A missing `reason` rejects the entry (with a warning); an expired entry re-activates the
finding; a malformed file accepts nothing (fails safe).

### `[scan]` — scan defaults

CLI flags override these; these override the built-in defaults.

```toml
[scan]
exclude = ["build/**", "vendor/**"]
languages = ["py", "go", "rust"]
fail_on = "P0"
max_file_bytes = 2000000
```

## CI patterns

```bash
# strict: fail if any P0 exists
lattice scan . --fail-on P0

# drift: fail only on NEW P0 (adoptable mid-migration)
lattice scan main-checkout --format cbom --out base
lattice scan . --format cbom --out cur
lattice diff base/cbom.json cur/cbom.json --fail-on-new P0

# compliance tracking
lattice scan . --policy cnsa2
```
