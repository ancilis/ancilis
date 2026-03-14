/** Auto-discovery: registers tools from MCP listTools into the ToolRegistry. */

import { createHash } from "node:crypto";
import { type ToolRegistry, ToolStatus } from "../engine/registry.js";

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
  preApproved: string[] = [],
): DriftEvent[] {
  const driftEvents: DriftEvent[] = [];
  const approvedSet = new Set(preApproved);

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

    // Don't downgrade an already-approved tool
    if (existing && existing.status === ToolStatus.APPROVED) {
      // Update hash only
      registry.register({
        ...existing,
        descriptionHash: descHash,
      });
    } else {
      const now = new Date().toISOString();
      registry.register({
        name: tool.name,
        descriptionHash: descHash,
        status: approvedSet.has(tool.name) ? ToolStatus.APPROVED : ToolStatus.OBSERVED,
        approvedBy: approvedSet.has(tool.name) ? "config" : null,
        firstSeen: existing?.firstSeen ?? now,
        statusChanged: now,
      });
    }
  }

  return driftEvents;
}
