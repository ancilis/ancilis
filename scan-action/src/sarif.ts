import type { ScanResult, ControlResult } from "./scanner.js";

interface SarifRule {
  id: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  help?: { text: string; markdown?: string };
  properties?: { tags?: string[] };
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string; uriBaseId: string };
    region?: { startLine: number };
  };
}

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  kind?: "pass" | "open" | "notApplicable";
  message: { text: string };
  locations: SarifLocation[];
}

interface SarifInvocation {
  executionSuccessful: boolean;
  endTimeUtc: string;
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      semanticVersion: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
  invocations: SarifInvocation[];
}

export interface SarifOutput {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

function controlToRule(control: ControlResult): SarifRule {
  return {
    id: control.id,
    shortDescription: { text: control.name },
    fullDescription: {
      text: `Ancilis control ${control.id}: ${control.name}. Status: ${control.status}.`,
    },
    help: {
      text: `Control ${control.id} (${control.name}) evaluated ${control.evaluations} tool call(s).`,
      markdown: `**Control ${control.id}**: ${control.name}\n\n- Evaluations: ${control.evaluations}\n- Failures: ${control.failures}\n- Flags: ${control.flags}`,
    },
    properties: {
      tags: ["security", "ancilis", control.id.toLowerCase()],
    },
  };
}

function controlToResult(control: ControlResult): SarifResult {
  let level: "error" | "warning" | "note";
  let kind: "pass" | "open" | "notApplicable" | undefined;

  if (control.status === "fail") {
    level = "error";
    kind = undefined;
  } else if (control.status === "skip") {
    level = "note";
    kind = "notApplicable";
  } else if (control.status === "pending") {
    // Only SKIP results — no evaluator evidence yet; open, not passing.
    level = "note";
    kind = "open";
  } else {
    level = "note";
    kind = "pass";
  }

  const messageText =
    control.status === "fail"
      ? `Control ${control.id} (${control.name}) failed with ${control.failures} failure(s) in ${control.evaluations} evaluation(s).`
      : control.status === "skip"
      ? `Control ${control.id} (${control.name}) was skipped — no evaluations recorded.`
      : control.status === "pending"
      ? `Control ${control.id} (${control.name}) is pending — no evaluator evidence collected yet.`
      : `Control ${control.id} (${control.name}) passed ${control.evaluations} evaluation(s).`;

  const result: SarifResult = {
    ruleId: control.id,
    level,
    message: { text: messageText },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: ".", uriBaseId: "REPOROOT" },
        },
      },
    ],
  };

  if (kind !== undefined) {
    result.kind = kind;
  }

  return result;
}

export function convertToSarif(scan: ScanResult): SarifOutput {
  const rules = scan.controls.map(controlToRule);
  const results = scan.controls.map(controlToResult);

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Ancilis",
            version: scan.version,
            informationUri: "https://ancilis.ai",
            semanticVersion: scan.version,
            rules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: scan.posture === "compliant",
            endTimeUtc: scan.timestamp,
          },
        ],
      },
    ],
  };
}
