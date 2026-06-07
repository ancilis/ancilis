#!/usr/bin/env python3
"""Doc count lint (audit finding F8).

Fails the build when a rendered control/overlay count in user-facing docs drifts
from the catalog on disk (shared/controls/*.json, shared/overlays/*.json), and
forbids the historical stale values (26 controls, 19/21 overlays).

Counts are derived from disk so they stay correct as the catalog grows:
  - CONTROLS = number of shared/controls/*.json   (catalog total)
  - COMMON   = controls with "common": true       (default-active baseline)
  - OVERLAYS = number of shared/overlays/*.json    (overlay profiles)

Only canonical count phrasings are verified; illustrative runtime counts
("39 active", "6 controls" for a PCI sub-scope, "23 data classes", etc.) are
left alone. Internal/historical docs (docs/research/**, docs/superpowers/**)
are out of scope.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

control_files = sorted((ROOT / "shared" / "controls").glob("*.json"))
overlay_files = sorted((ROOT / "shared" / "overlays").glob("*.json"))
CONTROLS = len(control_files)
OVERLAYS = len(overlay_files)
COMMON = sum(1 for p in control_files if json.loads(p.read_text()).get("common", True))

_EXCLUDE_SEGMENTS = {"research", "superpowers", ".venv", ".worktrees", "node_modules", "dist"}


def _doc_files() -> list[Path]:
    files = [ROOT / "README.md"]
    for pattern in ("docs/**/*.md", "docs/**/*.mdx", "examples/**/README.md"):
        files += [
            p for p in ROOT.glob(pattern)
            if not (_EXCLUDE_SEGMENTS & set(p.parts))
        ]
    return sorted(set(files))


# Historical stale values that must never reappear in a count context.
# `scope`: "control" stale-count checks are skipped on overlay reference pages,
# which legitimately cite a control SUBSET count (e.g. SOC 2 maps "26 controls").
# The positive catalog/common/overlay-profile checks below still run everywhere.
_STALE = [
    (re.compile(r"\b26\s+(?:baseline|common|active|AKSI|control)", re.I), "stale '26' control count", "control"),
    (re.compile(r"\bAll\s+26\b"), "stale 'All 26' control count", "control"),
    (re.compile(r"\b(?:19|21)\s+overlay", re.I), "stale overlay count (19/21)", "overlay"),
]

# Canonical phrasings whose number must match disk.
_OVERLAY_PROFILES = re.compile(r"(\d+)\s+overlay profiles", re.I)
_COMMON_CONTROLS = re.compile(r"(\d+)\s+common\s+(?:AKSI[\w. ]*)?controls", re.I)
_CATALOG_CONTROLS = re.compile(r"(\d+)\s+AKSI v[\d.]+ controls", re.I)


def main(files: list[Path] | None = None) -> int:
    errors: list[str] = []
    for doc in (files if files is not None else _doc_files()):
        text = doc.read_text(encoding="utf-8")
        try:
            rel = doc.relative_to(ROOT)
        except ValueError:
            rel = doc
        is_overlay_page = "overlays" in doc.parts
        for rx, msg, scope in _STALE:
            # An overlay page legitimately cites how many controls IT maps; only
            # the overlay-count stale checks apply there, not control-count ones.
            if is_overlay_page and scope == "control":
                continue
            for m in rx.finditer(text):
                errors.append(f"{rel}: {msg}: {m.group(0)!r}")
        for m in _OVERLAY_PROFILES.finditer(text):
            if int(m.group(1)) != OVERLAYS:
                errors.append(f"{rel}: 'overlay profiles' count {m.group(1)} != {OVERLAYS} on disk")
        for m in _COMMON_CONTROLS.finditer(text):
            if int(m.group(1)) != COMMON:
                errors.append(f"{rel}: 'common controls' count {m.group(1)} != {COMMON} on disk")
        for m in _CATALOG_CONTROLS.finditer(text):
            if int(m.group(1)) not in (CONTROLS, COMMON):
                errors.append(
                    f"{rel}: 'AKSI controls' count {m.group(1)} not in "
                    f"{{{COMMON}, {CONTROLS}}} on disk"
                )

    if errors:
        print(f"Doc count lint FAILED (disk: {CONTROLS} controls, {COMMON} common, {OVERLAYS} overlays):")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"Doc count lint OK: {CONTROLS} controls, {COMMON} common, {OVERLAYS} overlays.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
