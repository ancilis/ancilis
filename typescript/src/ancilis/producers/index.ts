/** Producers — protocol-agnostic action producers for security evaluation. */

export { ToolActionProducer, BlockedActionError } from "./tool.js";
export type { ToolInvocation, ToolExecutionResult, AnyFn } from "./tool.js";

export { CLIActionProducer } from "./cli.js";
export type { CLIInvocation, CLIExecutionResult } from "./cli.js";

export { HTTPActionProducer } from "./http.js";
export type { HTTPRequest, HTTPObservation, HTTPExecutionResult } from "./http.js";
