#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "Setting up Ancilis demo..."

if [ ! -d ".demo-venv" ]; then
    echo "  Creating virtual environment..."
    python3 -m venv .demo-venv
fi

source .demo-venv/bin/activate

echo "  Installing Ancilis..."
python -m pip install -e ".[dev]" --quiet 2>/dev/null

echo "  Ready."
echo ""
python examples/demo/run.py
