#!/usr/bin/env bash
# Refuse to commit content with absolute dev paths or local references.
set -euo pipefail

# Patterns that should never appear in tracked source.
patterns=(
    '/Users/[a-zA-Z]'
    '/Volumes/[A-Z]'
    '/home/[a-z]'
    '/private/var/folders'
    '/Library/Caches/'
    '/opt/homebrew/'
    'file:///'
)

violations=()
for f in "$@"; do
    [ -f "$f" ] || continue
    for p in "${patterns[@]}"; do
        if grep -InE "$p" "$f" 2>/dev/null | head -3 >&2; then
            violations+=("$f: matches /$p/")
        fi
    done
done

if [ ${#violations[@]} -gt 0 ]; then
    echo "" >&2
    echo "ERROR: hardcoded local paths found in:" >&2
    printf '  %s\n' "${violations[@]}" >&2
    echo "" >&2
    echo "Use environment variables, config files, or relative paths." >&2
    echo "If a test fixture genuinely needs a path, place it under a" >&2
    echo "directory matched by the .pre-commit-config.yaml exclude." >&2
    exit 1
fi
