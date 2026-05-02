import * as z from "zod/v4";

export const mcpModeSchema = z.enum(["audit", "enforce"]);
export const mcpDecisionSchema = z.enum(["ALLOW", "BLOCK", "FLAG"]);

export const checkPostureInputSchema = z.object({
  config_path: z.string().optional(),
  db_path: z.string().optional(),
  agent_id: z.string().optional(),
  session_id: z.string().optional(),
});

export const evaluateActionInputSchema = z.object({
  tool_name: z.string(),
  arguments: z.record(z.string(), z.unknown()).optional(),
  agent_id: z.string().optional(),
  session_id: z.string().optional(),
  source_type: z.string().optional(),
  config_path: z.string().optional(),
  db_path: z.string().optional(),
});

export const getEvidenceInputSchema = z.object({
  limit: z.number().int().min(1).max(100).optional(),
  session_id: z.string().optional(),
  tool_name: z.string().optional(),
  config_path: z.string().optional(),
  db_path: z.string().optional(),
});

export const reportInputSchema = z.object({
  config_path: z.string().optional(),
  db_path: z.string().optional(),
  agent_id: z.string().optional(),
  session_id: z.string().optional(),
  format: z.enum(["markdown", "json"]).default("markdown"),
});

export const listOverlaysInputSchema = z.object({
  config_path: z.string().optional(),
});

export const checkPostureOutputSchema = z.object({
  agent: z.object({
    name: z.string(),
    id: z.string().nullable(),
    owner: z.string().nullable(),
  }),
  mode: mcpModeSchema,
  posture: z.enum(["not_evaluated", "compliant", "non_compliant"]),
  summary: z.object({
    total_evaluations: z.number().int().nonnegative(),
    decisions: z.record(z.string(), z.number().int().nonnegative()),
    tools_evaluated: z.array(z.string()),
    control_pass_rates: z.record(z.string(), z.record(z.string(), z.number().int().nonnegative())),
  }),
  controls: z.array(z.object({
    control_id: z.string(),
    name: z.string(),
    enabled: z.boolean(),
    status: z.enum(["not_evaluated", "pass", "fail", "flag", "skip"]),
    pass: z.number().int().nonnegative(),
    fail: z.number().int().nonnegative(),
    flag: z.number().int().nonnegative(),
    skip: z.number().int().nonnegative(),
    error: z.number().int().nonnegative(),
  })),
  evidence: z.object({
    db_path: z.string(),
    chain_valid: z.boolean(),
    chain_errors: z.array(z.string()),
  }),
  warnings: z.array(z.string()),
});

export const evaluateActionOutputSchema = z.object({
  action_id: z.string(),
  evaluation_id: z.string(),
  timestamp: z.string(),
  decision: mcpDecisionSchema,
  decision_reason: z.string(),
  mode: mcpModeSchema,
  control_results: z.array(z.object({
    control_id: z.string(),
    control_name: z.string(),
    result: z.enum(["PASS", "FAIL", "FLAG", "SKIP", "ERROR"]),
    detail: z.string(),
    evidence_data: z.record(z.string(), z.unknown()),
    duration_ms: z.number().nonnegative(),
    display_name: z.string().optional(),
    display_detail: z.string().optional(),
    remediation_hint: z.string().optional(),
  })),
  active_overlays: z.array(z.string()),
  data_classifications: z.array(z.string()),
  detected_data_types: z.array(z.string()),
  would_store_evidence: z.literal(false),
});

export const evidenceRecordOutputSchema = z.object({
  record_id: z.string(),
  timestamp: z.string(),
  agent_id: z.string(),
  session_id: z.string().nullable(),
  source_type: z.string(),
  tool_name: z.string(),
  decision: mcpDecisionSchema,
  mode: mcpModeSchema,
  control_results: z.array(z.record(z.string(), z.unknown())),
  active_overlays: z.array(z.string()),
  data_classifications: z.array(z.string()),
  active_certifications: z.array(z.string()),
  record_hash: z.string(),
  previous_hash: z.string().nullable(),
  output_summary: z.string().nullable(),
  total_duration_ms: z.number().nonnegative(),
});

export const getEvidenceOutputSchema = z.object({
  records: z.array(evidenceRecordOutputSchema),
  chain_valid: z.boolean(),
  chain_errors: z.array(z.string()),
});

export const reportMarkdownOutputSchema = z.object({
  report: z.string(),
  generated_at: z.string(),
  session_id: z.string().nullable(),
  posture: z.enum(["not_evaluated", "compliant", "non_compliant"]),
});

export const reportOutputSchema = reportMarkdownOutputSchema;

export const listOverlaysOutputSchema = z.object({
  overlays: z.array(z.object({
    name: z.string(),
    source: z.enum(["baseline", "certification_target", "data_classification", "manual"]),
    controls_activated: z.array(z.string()),
    controls_total: z.number().int().nonnegative(),
    coverage_pct: z.number().nonnegative(),
  })),
  active_certification_targets: z.array(z.string()),
  total_active_controls: z.number().int().nonnegative(),
});

export type CheckPostureInput = z.infer<typeof checkPostureInputSchema>;
export type CheckPostureOutput = z.infer<typeof checkPostureOutputSchema>;
export type EvaluateActionInput = z.infer<typeof evaluateActionInputSchema>;
export type EvaluateActionOutput = z.infer<typeof evaluateActionOutputSchema>;
export type GetEvidenceInput = z.infer<typeof getEvidenceInputSchema>;
export type GetEvidenceOutput = z.infer<typeof getEvidenceOutputSchema>;
export type EvidenceRecordOutput = z.infer<typeof evidenceRecordOutputSchema>;
export type ReportInput = z.infer<typeof reportInputSchema>;
export type ReportMarkdownOutput = z.infer<typeof reportMarkdownOutputSchema>;
export type ListOverlaysInput = z.infer<typeof listOverlaysInputSchema>;
export type ListOverlaysOutput = z.infer<typeof listOverlaysOutputSchema>;
export type ReportOutput = ReportMarkdownOutput | CheckPostureOutput;
