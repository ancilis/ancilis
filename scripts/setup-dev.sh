#!/usr/bin/env bash
# Idempotent dev-environment setup: installs pre-commit + git hooks.
# Safe to re-run.
set -euo pipefail

if ! command -v pre-commit >/dev/null 2>&1; then
    echo "Installing pre-commit (user-local)..."
    if command -v pipx >/dev/null 2>&1; then
        pipx install pre-commit
    elif command -v pip3 >/dev/null 2>&1; then
        pip3 install --user pre-commit
    elif command -v pip >/dev/null 2>&1; then
        pip install --user pre-commit
    else
        echo "ERROR: no pip/pipx found. Install Python 3 first." >&2
        exit 1
    fi
fi

pre-commit install
pre-commit install --hook-type commit-msg

echo "Pre-commit hooks installed. They run automatically on every commit."
echo "First commit may be slow (downloading hook binaries); subsequent commits are fast."
