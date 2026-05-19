/** Evidence record model — immutable record of a control evaluation. */

export interface EvidenceRecord {
  recordId: string;
  evaluationId: string;
  timestamp: string;
  agentId: string;
  sourceType: string;
  toolName: string;
  decision: string;
  mode: string;
  controlResults: Array<Record<string, unknown>>;
  activeOverlays: string[];
  dataClassifications: string[];
  activeCertifications: string[];
  recordHash: string;
  previousHash: string;
  totalDurationMs: number;
  outputSummary?: string | null;
  sessionId?: string | null;
  tenantId?: string | null;
  detectedDataTypes?: string[];
  sdkVersion?: string | null;
  frameworkVersion?: string | null;
  classificationContext?: Record<string, unknown>;
}
