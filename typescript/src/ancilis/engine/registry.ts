/** Tool registry for provenance verification. */

export interface ToolEntry {
  name: string;
  version?: string | null;
  descriptionHash?: string | null;
  approved: boolean;
  approvedDate: string;
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
}
