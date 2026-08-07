<!-- Thanks for contributing to Lattice. Keep the four constraints in mind:
     determinism, stdlib-only runtime deps, honest confidence, never emit secrets. -->

## What this changes

<!-- One or two sentences. Link any issue with "Closes #123". -->

## Type

- [ ] New language detector
- [ ] New policy pack / algorithm
- [ ] Bug fix
- [ ] Docs / examples
- [ ] Other

## Checklist

- [ ] `pytest` passes (new behavior has a test; a new detector has a known-answer fixture)
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `mypy src/lattice` passes
- [ ] No new **runtime** dependency (dev-only deps go in the `dev` extra)
- [ ] Determinism preserved (no unsorted set iteration into output, no stray timestamps)
- [ ] If this adds a knowledge-base entry: grounded in a named standard, no invented CVEs,
      truth-table row added
- [ ] If this adds a blind spot or bias: documented in the README Limitations / `docs/GAPS.md`
