/** Producers — protocol-agnostic action producers for security evaluation. */

export { ProducerType } from "./protocol.js";
export type { ActionProducer } from "./protocol.js";

export { MCPActionProducer } from "./mcp.js";
export type { MCPInvocation } from "./mcp.js";

export { ToolActionProducer, BlockedActionError, wrapTool, tool, evaluateAndExecute } from "./tool.js";
export type {
  ToolInvocation,
  ToolExecutionResult,
  AnyFn,
  ToolWrapOptions,
  EvaluateAndExecuteOptions,
} from "./tool.js";

export { CLIActionProducer } from "./cli.js";
export type { CLIInvocation, CLIExecutionResult } from "./cli.js";

export { HTTPActionProducer } from "./http.js";
export type { HTTPRequest, HTTPObservation, HTTPExecutionResult } from "./http.js";
