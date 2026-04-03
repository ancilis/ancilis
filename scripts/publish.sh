#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python -m pip install --upgrade build twine
rm -rf dist
python -m build --sdist --wheel

shopt -s nullglob
artifacts=(dist/ancilis-*.whl dist/ancilis-*.tar.gz)
if [ "${#artifacts[@]}" -ne 2 ]; then
  printf 'Expected exactly one wheel and one sdist in dist/, found %d artifacts.\n' "${#artifacts[@]}" >&2
  printf '%s\n' "${artifacts[@]}" >&2
  exit 1
fi

twine check "${artifacts[@]}"
twine upload "${artifacts[@]}"
