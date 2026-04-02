/** Tool-name matching helpers shared by producers and scope evaluation. */

export function matchesToolList(toolName: string, toolList: string[]): boolean {
  if (toolList.includes(toolName)) {
    return true;
  }

  const separator = toolName.indexOf(":");
  if (separator !== -1) {
    const bareName = toolName.slice(separator + 1);
    if (bareName && toolList.includes(bareName)) {
      return true;
    }
  }

  return false;
}
