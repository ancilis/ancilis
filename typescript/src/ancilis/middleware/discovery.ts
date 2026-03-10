/** Auto-discovery: registers tools from MCP listTools into the ToolRegistry. */

import { createHash } from "node:crypto";
import type { ToolRegistry } from "../engine/registry.js";

export interface DriftEvent {
  toolName: string;
  oldHash: string | null;
  newHash: string;
}

export interface DiscoverableTool {
  name: string;
  description?: string | null;
}

export function registerToolsFromList(
  tools: DiscoverableTool[],
  registry: ToolRegistry,
): DriftEvent[] {
  const driftEvents: DriftEvent[] = [];

  for (const tool of tools) {
    const description = tool.description ?? "";
    const descHash = createHash("sha256").update(description).digest("hex");

    const existing = registry.lookup(tool.name);
    if (existing?.descriptionHash && existing.descriptionHash !== descHash) {
      driftEvents.push({
        toolName: tool.name,
        oldHash: existing.descriptionHash,
        newHash: descHash,
      });
    }

    registry.register({
      name: tool.name,
      descriptionHash: descHash,
      approved: true,
      approvedDate: new Date().toISOString(),
    });
  }

  return driftEvents;
}
