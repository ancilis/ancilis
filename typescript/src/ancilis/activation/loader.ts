/** Loads overlay profiles and certification profiles from shared JSON data files. */

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const SHARED_DIR = resolve(__filename, "..", "..", "..", "..", "..", "shared");
const OVERLAYS_DIR = join(SHARED_DIR, "overlays");
const CERTIFICATIONS_DIR = join(OVERLAYS_DIR, "certifications");
const CONTROLS_DIR = join(SHARED_DIR, "controls");
const CLASSIFICATIONS_FILE = join(SHARED_DIR, "classifications", "taxonomy.json");

export function loadOverlayProfiles(): Map<string, Record<string, unknown>> {
  const profiles = new Map<string, Record<string, unknown>>();
  const files = readdirSync(OVERLAYS_DIR).filter(f => f.endsWith(".json")).sort();
  for (const file of files) {
    const data = JSON.parse(readFileSync(join(OVERLAYS_DIR, file), "utf-8"));
    profiles.set(data.id, data);
  }
  return profiles;
}

export function loadCertificationProfile(certId: string): Record<string, unknown> | null {
  const path = join(CERTIFICATIONS_DIR, `${certId}.json`);
  if (!existsSync(path)) {
    return null;
  }
  const data = JSON.parse(readFileSync(path, "utf-8"));
  if (!("version" in data)) {
    return null;
  }
  return data;
}

export function loadCertificationProfiles(certIds: string[]): Map<string, Record<string, unknown>> {
  const profiles = new Map<string, Record<string, unknown>>();
  for (const cid of certIds) {
    const profile = loadCertificationProfile(cid);
    if (profile !== null) {
      profiles.set(cid, profile);
    }
  }
  return profiles;
}

export function loadControlDefinitions(): Map<string, Record<string, unknown>> {
  const controls = new Map<string, Record<string, unknown>>();
  const files = readdirSync(CONTROLS_DIR).filter(f => f.endsWith(".json")).sort();
  for (const file of files) {
    const data = JSON.parse(readFileSync(join(CONTROLS_DIR, file), "utf-8"));
    controls.set(data.id, data);
  }
  return controls;
}

export function loadTaxonomy(): Record<string, unknown> {
  return JSON.parse(readFileSync(CLASSIFICATIONS_FILE, "utf-8"));
}
