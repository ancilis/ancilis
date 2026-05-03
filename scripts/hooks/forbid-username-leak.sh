#!/usr/bin/env bash
# Refuse to commit content containing identifying usernames or host IDs.
set -euo pipefail

# Things that identify a specific dev environment.
forbidden=(
    'hellohelloalbus'
    'albuss-mac-mini'
    'tail8222f8'
    'MiniAlbus'
)

violations=()
for f in "$@"; do
    [ -f "$f" ] || continue
    for word in "${forbidden[@]}"; do
        if grep -In "$word" "$f" 2>/dev/null | head -3 >&2; then
            violations+=("$f: contains '$word'")
        fi
    done
done

if [ ${#violations[@]} -gt 0 ]; then
    echo "" >&2
    echo "ERROR: identifying username/host found in:" >&2
    printf '  %s\n' "${violations[@]}" >&2
    exit 1
fi
