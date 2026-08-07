#!/usr/bin/env bash
# Drift gate: fail only when a change *introduces* new P0 crypto, without
# failing on the pre-existing backlog. The adoptable gate mid-migration.
#
# Usage:  examples/ci_diff.sh <baseline-ref> [current-ref]
# Example: examples/ci_diff.sh origin/main HEAD
set -euo pipefail

BASELINE_REF="${1:-origin/main}"
CURRENT_REF="${2:-HEAD}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 1. baseline CBOM (from the baseline ref, via a throwaway worktree)
git worktree add --quiet "$WORK/base" "$BASELINE_REF"
lattice scan "$WORK/base" --format cbom --out "$WORK/base-report" --quiet
git worktree remove --force "$WORK/base"

# 2. current CBOM (working tree at the current ref)
lattice scan . --format cbom --out "$WORK/cur-report" --quiet

# 3. gate on *new* P0 findings only
lattice diff "$WORK/base-report/cbom.json" "$WORK/cur-report/cbom.json" --fail-on-new P0
