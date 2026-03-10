/** Pattern detection on tool call responses. */

import { scanForPatterns } from "../engine/patterns.js";
import type { PatternMatch } from "../engine/patterns.js";

export interface EncryptionFinding {
  findingType: "high_entropy" | "base64_block" | "jwt_token";
  detail: string;
}

export interface ScanResult {
  toolName: string;
  patterns: PatternMatch[];
  encryptionFindings: EncryptionFinding[];
  recommendations: string[];
}

const PATTERN_TO_DATA_TYPE: Record<string, string> = {
  ssn: "personal_info",
  credit_card: "credit_cards",
  email: "personal_info",
  phone: "personal_info",
  mrn: "health_records",
  api_key: "trade_secrets",
};

function shannonEntropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const c of s) {
    counts.set(c, (counts.get(c) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / s.length;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

function detectEncryption(text: string): EncryptionFinding[] {
  const findings: EncryptionFinding[] = [];

  // JWT detection
  const jwtPattern = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/;
  if (jwtPattern.test(text)) {
    findings.push({
      findingType: "jwt_token",
      detail: "JWT token detected — evidence of token-based authentication in use.",
    });
  }

  // High-entropy strings
  const tokens = text.split(/[\s,;:"'\[\]{}]+/);
  for (const token of tokens) {
    if (token.length > 20) {
      const entropy = shannonEntropy(token);
      if (entropy > 4.5) {
        findings.push({
          findingType: "high_entropy",
          detail: `High-entropy string detected (entropy=${entropy.toFixed(1)}) — possible encrypted or tokenized data.`,
        });
        break;
      }
    }
  }

  // Base64 blocks (skip if JWT already found)
  if (!jwtPattern.test(text)) {
    const b64Pattern = /[A-Za-z0-9+/]{40,}={0,2}/;
    if (b64Pattern.test(text)) {
      findings.push({
        findingType: "base64_block",
        detail: "Base64-encoded block detected — possible encrypted payload.",
      });
    }
  }

  return findings;
}

export function scanResponse(toolName: string, responseText: string): ScanResult {
  const result: ScanResult = {
    toolName,
    patterns: [],
    encryptionFindings: [],
    recommendations: [],
  };

  result.patterns = scanForPatterns(responseText);

  for (const match of result.patterns) {
    const dataType = PATTERN_TO_DATA_TYPE[match.patternType];
    if (dataType) {
      result.recommendations.push(
        `Detected ${match.patternType} patterns (${match.count} found) in responses ` +
        `from tool '${toolName}'. Consider adding '${dataType}' to your ` +
        `data_handling configuration.`
      );
    }
  }

  result.encryptionFindings = detectEncryption(responseText);

  return result;
}
