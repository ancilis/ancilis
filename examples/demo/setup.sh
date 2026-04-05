#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/../.."

# --- Pre-flight checks ---
# shellcheck source=preflight.sh
source "${SCRIPT_DIR}/preflight.sh"
check_python_version

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
