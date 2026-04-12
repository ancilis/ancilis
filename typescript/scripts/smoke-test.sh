#!/usr/bin/env bash
# smoke-test.sh — install the packed tarball and verify it works end-to-end.
# Usage:
#   smoke-test.sh <path-to-tarball>       # test a pre-built tarball
#   smoke-test.sh                         # pack from cwd then test
#
# Delegates to the project-root node smoke script, so all assertions stay
# in one place (scripts/ts_package_smoke.mjs).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SMOKE_SCRIPT="$REPO_ROOT/scripts/ts_package_smoke.mjs"

if [[ ! -f "$SMOKE_SCRIPT" ]]; then
  echo "ERROR: smoke script not found at $SMOKE_SCRIPT" >&2
  exit 1
fi

TARBALL="${1:-}"

if [[ -n "$TARBALL" ]]; then
  echo "Running smoke tests against: $TARBALL"
  node "$SMOKE_SCRIPT" "$TARBALL"
else
  echo "No tarball specified — packing from $REPO_ROOT"
  node "$SMOKE_SCRIPT"
fi
