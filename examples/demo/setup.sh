#!/usr/bin/env bash
set -euo pipefail

echo "=== Ancilis Demo Setup ==="
cd "$(dirname "$0")/../.."
if [ ! -d ".demo-venv" ]; then
    python3 -m venv .demo-venv
fi
source .demo-venv/bin/activate
python -m pip install -e ".[dev]" --quiet
echo "Setup complete. Running demo..."
python examples/demo/run.py
