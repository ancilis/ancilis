#!/usr/bin/env bash
set -euo pipefail

echo "=== Ancilis Demo Setup ==="
cd "$(dirname "$0")/../.."
python3 -m venv .demo-venv
source .demo-venv/bin/activate
python -m pip install -e ".[dev]" --quiet
echo "Setup complete. Running demo..."
python examples/demo/run.py
