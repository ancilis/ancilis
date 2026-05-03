#!/usr/bin/env bash
# Refuse to commit agent/IDE local state files. These should be
# .gitignored, but this is the safety net.
#
# Compatible with bash 3.2 (macOS default) — no fall-through case syntax.
set -euo pipefail

violations=()
for f in "$@"; do
    case "$f" in
        .claude/settings.local.json| \
        .claude/projects/*| \
        .claude/sessions/*| \
        .claude/worktrees/*| \
        .codex/*| \
        .cursor/*| \
        .aider*| \
        .windsurf/*| \
        .continue/*| \
        .devin/*| \
        .zed/*| \
        .fleet/*| \
        .idea/*| \
        .vscode/settings.json| \
        .vscode/launch.json| \
        *.code-workspace| \
        .env.local| \
        .env.*.local)
            violations+=("$f")
            ;;
    esac
done

if [ ${#violations[@]} -gt 0 ]; then
    echo "ERROR: refusing to commit agent/IDE local state files:" >&2
    printf '  %s\n' "${violations[@]}" >&2
    echo "" >&2
    echo "These files contain local dev paths, session UUIDs, or tool" >&2
    echo "config that must not be tracked. Add them to .gitignore." >&2
    exit 1
fi
