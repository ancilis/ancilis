/** Overlay ID helpers. */

export const OVERLAY_ID_ALIASES: Record<string, string> = {
  "nist-csf-2": "nist-csf",
};

export function normalizeOverlayId(overlayId: string): string {
  const trimmed = overlayId.trim();
  return OVERLAY_ID_ALIASES[trimmed.toLowerCase()] ?? trimmed;
}

export function normalizeOverlayIds(overlayIds: Iterable<string>): string[] {
  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const overlayId of overlayIds) {
    const canonical = normalizeOverlayId(overlayId);
    if (seen.has(canonical)) continue;
    normalized.push(canonical);
    seen.add(canonical);
  }
  return normalized;
}
