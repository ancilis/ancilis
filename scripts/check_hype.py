#!/usr/bin/env python3
"""Hype lint (audit finding F12).

Guards buyer-facing surfaces (README + docs/, excluding internal
research/planning) against unsubstantiated marketing claims:

  1. Hard-banned absolutes that no shipped feature backs: "audit-grade",
     "regulator-grade"/"regulatory-grade", "tamper-proof", "court-admissible".
     These over-promise legal/regulatory standing the SDK does not provide.

  2. "tamper-evident" is allowed ONLY when the same document substantiates it
     with the mechanism that backs it ("hash chain", "SHA-256", or "HMAC").
     The evidence chain is a verifiable hash chain (see verify_chain), so the
     claim is fine when shown with its mechanism — but it must never appear as a
     bare buzzword. Substantiation is checked at document granularity: a doc that
     uses the term must explain the mechanism somewhere in the same document.

Scope: README + docs/ + shipped example docs (examples/**/*.md). Internal
research/planning docs are excluded.

Note: bare "compliance" is intentionally NOT banned — it is used honestly
throughout as "compliance monitoring", "compliance posture", and "compliance
overlays". The dishonest forms ("audit-grade", etc.) are what this guard blocks.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_EXCLUDE_SEGMENTS = {"research", "superpowers", ".venv", ".worktrees", "node_modules", "dist"}

_BANNED = [
    re.compile(r"audit-grade", re.I),
    re.compile(r"regulat(?:or|ory)-grade", re.I),
    re.compile(r"tamper-proof|tamperproof", re.I),
    re.compile(r"court-admissible", re.I),
]
_TAMPER_EVIDENT = re.compile(r"tamper-evident", re.I)
_SUBSTANTIATION = re.compile(r"hash[\s-]?chain|SHA-?256|HMAC", re.I)


def _doc_files() -> list[Path]:
    files = [ROOT / "README.md"]
    for pattern in ("docs/**/*.md", "docs/**/*.mdx", "examples/**/*.md"):
        files += [p for p in ROOT.glob(pattern) if not (_EXCLUDE_SEGMENTS & set(p.parts))]
    return sorted(set(files))


def main() -> int:
    errors: list[str] = []
    for doc in _doc_files():
        text = doc.read_text(encoding="utf-8")
        rel = doc.relative_to(ROOT)
        for rx in _BANNED:
            for m in rx.finditer(text):
                errors.append(f"{rel}: banned unsubstantiated term {m.group(0)!r}")
        if _TAMPER_EVIDENT.search(text) and not _SUBSTANTIATION.search(text):
            errors.append(
                f"{rel}: uses 'tamper-evident' without substantiating it in the same "
                f"document (mention the hash chain / SHA-256 / HMAC mechanism)."
            )

    if errors:
        print("Hype lint FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("Hype lint OK: no unsubstantiated marketing claims in buyer-facing docs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
