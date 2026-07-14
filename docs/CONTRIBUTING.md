# Contributing to Lattice

The two intended extension seams are **detectors** (new languages/artifact types) and the
**knowledge base** (new algorithms). Everything else — scoring, models, emitters — should
rarely need to change.

## Setup

```bash
pip install -e ".[dev]"
pytest            # everything must be green before and after your change
ruff check .
mypy lattice
```

## Adding a language detector

1. **Create `lattice/detectors/<lang>_det.py`** implementing the ABC in
   [`lattice/detectors/base.py`](../lattice/detectors/base.py):

   ```python
   from collections.abc import Iterable
   from pathlib import PurePath

   from lattice.core.models import Confidence, CryptoAsset
   from lattice.detectors.base import Detector, make_snippet

   class RubyDetector(Detector):
       name = "ruby"

       def applies_to(self, path: PurePath) -> bool:
           return path.suffix == ".rb"

       def detect(self, path: PurePath, content: str) -> Iterable[CryptoAsset]:
           ...  # yield CryptoAsset for every concrete match
   ```

   Contract (enforced by review):
   - Yield an asset **only** for a concretely matched pattern at a real line. No "this file
     probably uses crypto" findings.
   - Resolve raw names through `lattice.rules.algorithms.lookup()`; pass the canonical name
     into the asset. Unknown names: don't guess — skip, or inventory with an honest note.
   - Set `confidence` honestly: parsed/AST match → `HIGH`; regex on a string literal →
     `MEDIUM`; bare token scan → `LOW`.
   - Never raise on malformed input — degrade (see `regex_fallback_scan`) or yield nothing.
   - Use `make_snippet()` for snippets; it truncates and redacts potential secret material.
     Never put file contents into `note`.
   - Set `usage_family` when the call site pins usage (a `Signature.getInstance` RSA is
     signature usage, which changes its HNDL scoring). Leave it `None` to use the
     knowledge-base default.

2. **Register it** in `lattice/detectors/registry.py` (`LANGUAGE_MAP`).

3. **Add a fixture** under `tests/fixtures/<lang>/` containing at minimum: one classically
   broken usage, one quantum-vulnerable usage, one safe usage — each with a `KNOWN:` comment
   stating the expected algorithm and priority. Keep comments free of tokens your own regexes
   match (or your known-answer comment becomes a finding).

4. **Add a test** in `tests/test_detectors.py` asserting the *exact* detection set —
   algorithms, modes, priorities, confidence — and extend the Gate-3 whole-tree known-answer
   set. False negatives on fixtures are never acceptable; false positives are acceptable only
   if marked low-confidence.

## Adding an algorithm to the knowledge base

1. Add the entry in `lattice/rules/algorithms.py` with `family`, `quantum_status`,
   `classical_status`, `pqc_replacement`, and factual `notes`. Ground every claim in
   well-established cryptography; reference standards by name only (e.g. "NIST FIPS 203"),
   never with section numbers you haven't verified. **No CVE numbers, no CVSS scores, no
   statistics.**
2. Add synonyms to `SYNONYMS` (library spellings, curve names, OID-ish aliases).
3. Add a row to the truth table in `tests/test_severity.py` for the expected priority, and a
   spot-check in `tests/test_algorithms.py` if the synonyms are non-obvious.
4. Consistency rules (already tested): quantum-safe + classically-secure entries must have no
   `pqc_replacement`; anything broken/deprecated/quantum-broken must name its replacement.

## Adding a fixture edge case

Walker and robustness edge cases live in `tests/test_hardening.py` and are generated into
`tmp_path` at test time rather than committed, except where a real on-disk artifact is the
point (like the synthetic certificate in `tests/fixtures/config/`). Never commit real key
material — fixtures use clearly fake base64 (`"FAKE KEY - NOT A REAL KEY"`).

## Ground rules

- Determinism is a product feature: same input → byte-identical output modulo the single
  top-level timestamp. If your change breaks the determinism tests, the change is wrong.
- `core` never imports a detector or an emitter. Detectors and emitters depend on `core`;
  `rules` depends on nothing internal but `core.models`.
- The README **Limitations** section must stay truthful — if your change adds a blind spot,
  document it there in the same PR.
