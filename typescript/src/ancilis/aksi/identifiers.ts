/** AKSI control identifier boundaries. */

export const AKSI_PREFIX = "AKSI-";
const AKSI_LEGACY_PREFIX = "AKSI_";

export function isPrefixed(controlId: string): boolean {
  return controlId.startsWith(AKSI_PREFIX) || controlId.startsWith(AKSI_LEGACY_PREFIX);
}

export const is_prefixed = isPrefixed;

export function unprefix(controlId: string): string {
  const normalized = controlId.startsWith(AKSI_LEGACY_PREFIX)
    ? `${AKSI_PREFIX}${controlId.slice(AKSI_LEGACY_PREFIX.length)}`
    : controlId;
  return normalized.startsWith(AKSI_PREFIX)
    ? normalized.slice(AKSI_PREFIX.length)
    : normalized;
}

export function prefix(controlId: string): string {
  return `${AKSI_PREFIX}${unprefix(controlId)}`;
}
