/** Tool registry for provenance verification. */

export enum ToolStatus {
  OBSERVED = "observed",
  APPROVED = "approved",
  BLOCKED = "blocked",
}

export interface ToolEntry {
  name: string;
  version?: string | null;
  descriptionHash?: string | null;
  status: ToolStatus;
  approvedBy?: string | null;
  firstSeen: string;
  statusChanged: string;
}

export class ToolRegistry {
  private tools = new Map<string, ToolEntry>();

  register(entry: ToolEntry): void {
    this.tools.set(entry.name, entry);
  }

  lookup(name: string): ToolEntry | undefined {
    return this.tools.get(name);
  }

  isRegistered(name: string): boolean {
    return this.tools.has(name);
  }

  approve(name: string, approvedBy = "operator"): boolean {
    const entry = this.tools.get(name);
    if (!entry) return false;
    entry.status = ToolStatus.APPROVED;
    entry.approvedBy = approvedBy;
    entry.statusChanged = new Date().toISOString();
    return true;
  }

  getAll(): ToolEntry[] {
    return [...this.tools.values()];
  }
}
