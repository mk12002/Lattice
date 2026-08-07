# Releasing Lattice

The release pipeline is automated, but the **first PyPI publish requires one-time
maintainer setup** that no automation can do for you (it needs your PyPI account). This
document is the exact checklist.

## Versioning

Lattice uses semantic-ish versioning. The version lives in **two places that must match**:
`pyproject.toml` (`version = "..."`) and `src/lattice/__init__.py` (`__version__`). `lattice
version`, the CBOM `metadata.tools`, and the SARIF driver all read the latter, so a release
must bump both and update `CHANGELOG.md`.

## Cutting a release (routine)

```bash
# 1. bump version in pyproject.toml AND src/lattice/__init__.py, and update CHANGELOG.md
# 2. verify locally
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy src/lattice && pytest
python -m build && twine check dist/*      # packaging is valid

# 3. tag and push — this triggers .github/workflows/release.yml
git tag v0.4.0
git push origin v0.4.0
```

The `release` workflow then: runs the test gate, builds the sdist+wheel, `twine check`s them,
creates a GitHub Release with generated notes and the artifacts attached, and (if PyPI is set
up, below) publishes to PyPI.

## One-time PyPI setup (maintainer action — cannot be automated here)

Lattice is **not yet on PyPI**. To enable `pip install`:

1. **Pick the distribution name.** `lattice` is taken on PyPI; `pyproject.toml` currently uses
   `lattice-scanner`. Confirm availability at `https://pypi.org/project/<name>/` and adjust
   `[project].name` if needed. (The *import* name stays `lattice`.)
2. **Create the project on PyPI** — either upload once manually with an API token, or create a
   "pending" Trusted Publisher (recommended, no long-lived token):
   - PyPI → your account → *Publishing* → *Add a pending publisher*
   - Owner: `mk12002`, Repository: `Lattice`, Workflow: `release.yml`, Environment: `pypi`
3. **Create the `pypi` GitHub Environment** in repo Settings → Environments (the `pypi` job in
   `release.yml` targets it). Optionally add required reviewers as a release approval gate.
4. **Tag a release** (routine steps above). The `pypi` job publishes via OIDC trusted
   publishing — no secrets stored in the repo.

### Verifying on TestPyPI first (optional but recommended)

```bash
python -m build
twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple lattice-scanner
lattice version
```

## Fresh-environment install check (every release)

Editable installs hide packaging bugs. Before announcing a release, verify a clean install:

```bash
python -m venv /tmp/fresh && /tmp/fresh/bin/pip install dist/lattice_scanner-*.whl
/tmp/fresh/bin/lattice version
/tmp/fresh/bin/lattice scan <somewhere> --format cbom --out /tmp/r
```

## Docs site

Pushing docs changes to `main` triggers `.github/workflows/docs.yml`, which builds the MkDocs
site and deploys to GitHub Pages — **once you enable Pages** (Settings → Pages → Source:
"GitHub Actions").
