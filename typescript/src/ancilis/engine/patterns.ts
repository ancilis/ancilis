/** Sensitive data pattern definitions for PR-04 Data Exposure Prevention. */

export interface PatternMatch {
  patternType: string;
  count: number;
  redactedSample: string;
}

const SSN_PATTERN = /\b\d{3}-\d{2}-\d{4}\b/g;
const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const US_PHONE_PATTERN = /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
const CREDIT_CARD_PATTERN = /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,7}\b/g;
const API_KEY_PATTERN = /\b(?:sk|pk|api|key|token|secret|bearer)[-_]?[A-Za-z0-9]{20,}\b/gi;
const MRN_PATTERN = /\bMRN[-:\s]?\d{6,}\b/gi;

function luhnCheck(numberStr: string): boolean {
  const digits = numberStr.replace(/\D/g, "").split("").map(Number);
  if (digits.length < 13 || digits.length > 19) return false;
  let checksum = 0;
  const reversed = [...digits].reverse();
  for (let i = 0; i < reversed.length; i++) {
    let d = reversed[i]!;
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    checksum += d;
  }
  return checksum % 10 === 0;
}

function redactSsn(match: string): string {
  return `***-**-${match.slice(-4)}`;
}

function redactEmail(match: string): string {
  const parts = match.split("@");
  const local = parts[0] ?? "";
  const domain = parts[1] ?? "";
  return `${local[0] ?? ""}***@${domain}`;
}

function redactCard(match: string): string {
  const digits = match.replace(/\D/g, "");
  return `****-****-****-${digits.slice(-4)}`;
}

function redactPhone(match: string): string {
  const digits = match.replace(/\D/g, "");
  return `***-***-${digits.slice(-4)}`;
}

function redactApiKey(match: string): string {
  return `${match.slice(0, 4)}***`;
}

function redactMrn(match: string): string {
  const digits = match.replace(/\D/g, "");
  return `MRN-***${digits.slice(-3)}`;
}

export function scanForPatterns(text: string): PatternMatch[] {
  const results: PatternMatch[] = [];

  const ssnMatches = [...text.matchAll(SSN_PATTERN)];
  if (ssnMatches.length > 0) {
    results.push({ patternType: "ssn", count: ssnMatches.length, redactedSample: redactSsn(ssnMatches[0]![0]) });
  }

  const cardMatches = [...text.matchAll(CREDIT_CARD_PATTERN)];
  const luhnValid = cardMatches.filter(m => luhnCheck(m[0]));
  if (luhnValid.length > 0) {
    results.push({ patternType: "credit_card", count: luhnValid.length, redactedSample: redactCard(luhnValid[0]![0]) });
  }

  const emailMatches = [...text.matchAll(EMAIL_PATTERN)];
  if (emailMatches.length > 0) {
    results.push({ patternType: "email", count: emailMatches.length, redactedSample: redactEmail(emailMatches[0]![0]) });
  }

  const phoneMatches = [...text.matchAll(US_PHONE_PATTERN)];
  if (phoneMatches.length > 0) {
    results.push({ patternType: "phone", count: phoneMatches.length, redactedSample: redactPhone(phoneMatches[0]![0]) });
  }

  const apiKeyMatches = [...text.matchAll(API_KEY_PATTERN)];
  if (apiKeyMatches.length > 0) {
    results.push({ patternType: "api_key", count: apiKeyMatches.length, redactedSample: redactApiKey(apiKeyMatches[0]![0]) });
  }

  const mrnMatches = [...text.matchAll(MRN_PATTERN)];
  if (mrnMatches.length > 0) {
    results.push({ patternType: "mrn", count: mrnMatches.length, redactedSample: redactMrn(mrnMatches[0]![0]) });
  }

  return results;
}

export function scanParameters(params: Record<string, unknown>): PatternMatch[] {
  const text = JSON.stringify(params);
  return scanForPatterns(text);
}
