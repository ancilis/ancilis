#!/usr/bin/env python3
"""Generate SDK shared assets from the frozen AKSI v0.6 platform artifacts."""

from __future__ import annotations

import ast
import json
import os
import shutil
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
FROZEN_SOURCE_ENV = "AKSI_FROZEN_SRC"
FROZEN_SOURCE = Path(os.environ.get(FROZEN_SOURCE_ENV, "__AKSI_FROZEN_SRC_NOT_SET__")).expanduser()
GRAPH_PATH = FROZEN_SOURCE / "AKSI_GRAPH.json"
CONTROL_CATALOG_PATH = FROZEN_SOURCE / "platform/backend/app/engine/control_catalog.py"
CLASS_SCHEMA_PATH = FROZEN_SOURCE / "shared/classifications/schema/aksi_class.schema.json"
CONTROL_SCHEMA_PATH = FROZEN_SOURCE / "shared/classifications/schema/aksi_control.schema.json"
SARIF_MAPPING_PATH = FROZEN_SOURCE / "shared/mappings/sarif-aksi-controls.json"

SHARED_DIR = REPO_ROOT / "shared"
CONTROLS_DIR = SHARED_DIR / "controls"
TAXONOMY_PATH = SHARED_DIR / "classifications/taxonomy.json"
CONFIG_SCHEMA_PATH = SHARED_DIR / "schemas/config.schema.json"
EVALUATION_SCHEMA_PATH = SHARED_DIR / "schemas/evaluation-result.schema.json"
EVIDENCE_SCHEMA_PATH = SHARED_DIR / "schemas/evidence-record.schema.json"
ACTION_SCHEMA_PATH = SHARED_DIR / "schemas/action.schema.json"
SDK_SARIF_MAPPING_PATH = SHARED_DIR / "mappings/sarif-aksi-controls.json"
SDK_OSCAL_MAPPING_PATH = SHARED_DIR / "mappings/oscal-sp800-53.json"
CONTROLS_REFERENCE_PATH = REPO_ROOT / "docs/controls-reference.md"

FRAMEWORK_VERSION = "0.6"
FRAMEWORK_COMMIT = "aeda1839054090a8384f3d9d2700a656fab519a2"

FUNCTION_BY_DOMAIN = {
    "Govern": "GOVERN",
    "Identify": "IDENTIFY",
    "Protect": "PROTECT",
    "Detect": "DETECT",
    "Respond": "RESPOND",
    "Recover": "RECOVER",
    "Payment": "PAYMENT",
}

PLATFORM_TO_SDK_OVERLAY = {
    "eu_ai_act": "eu-ai-act",
    "fedramp_nist_800_53": "fedramp",
    "nist_ai_rmf": "nist-ai-rmf",
    "nist_csf": "nist-csf",
    "pci_dss": "pci-dss-v4",
}

TAXONOMY_NAMES = {
    "DC-PHI": "Protected Health Information",
    "DC-CHD": "Cardholder Data",
    "DC-SAD": "Sensitive Authentication Data",
    "DC-CUI": "Controlled Unclassified Information",
    "DC-FCI": "Federal Contract Information",
    "DC-MNPI": "Material Non-Public Information",
    "DC-PII": "Personally Identifiable Information",
    "DC-FIN": "Financial Services Data",
    "DC-NPI": "Nonpublic Personal Information",
    "DC-GOV": "Government System Data",
    "DC-AI": "AI System, Model, Prompt, and Training Data",
    "DC-GEN": "General Business Data",
    "DC-ITAR": "ITAR-Controlled Technical Data",
    "DC-CRIT": "Critical Infrastructure Data",
    "DC-MINOR": "Children's Data",
    "DC-BIO": "Biometric Data",
    "DC-LEGAL": "Legal Privileged Data",
    "DC-IP": "Intellectual Property and Trade Secrets",
    "DC-PAY": "Agent Payment Data",
    "DC-EDU": "Education Records",
    "DC-CJI": "Criminal Justice Information",
    "DC-EAR": "EAR-Controlled Dual-Use Technology",
    "DC-MEDDEV": "Medical Device Data",
}

TAXONOMY_DESCRIPTIONS = {
    "DC-PHI": "Health data and individually identifiable health information that activates healthcare privacy and security overlays.",
    "DC-CHD": "Payment cardholder data, including primary account numbers and cardholder account attributes.",
    "DC-SAD": "Sensitive payment authentication data such as card verification values, PIN data, and equivalent authentication material.",
    "DC-CUI": "Controlled Unclassified Information requiring safeguarding or dissemination controls.",
    "DC-FCI": "Non-public federal contract information provided by or generated for government contracts.",
    "DC-MNPI": "Material non-public information that could influence investment decisions.",
    "DC-PII": "Personal data that can identify or relate to a natural person.",
    "DC-FIN": "Financial account, transaction, institution, or financial-services operational data.",
    "DC-NPI": "Nonpublic personal information used by financial institutions and privacy programs.",
    "DC-GOV": "Government system, federal environment, or public-sector operational data.",
    "DC-AI": "AI model, prompt, training, evaluation, agent behavior, or system metadata.",
    "DC-GEN": "General business data without a more specific AKSI v0.6 classification.",
    "DC-ITAR": "Technical data or defense articles controlled under ITAR.",
    "DC-CRIT": "Operational or service data tied to critical infrastructure or essential services.",
    "DC-MINOR": "Personal data about children or minors.",
    "DC-BIO": "Biometric identifiers, measurements, templates, or authentication factors.",
    "DC-LEGAL": "Attorney-client privileged, work-product, or legal matter data.",
    "DC-IP": "Source code, trade secrets, proprietary designs, inventions, or confidential intellectual property.",
    "DC-PAY": "Agent payment instructions, payment credentials, settlement artifacts, and x402-style payment context.",
    "DC-EDU": "Student data and education records.",
    "DC-CJI": "Criminal justice information.",
    "DC-EAR": "Dual-use technology and export-controlled data governed by EAR.",
    "DC-MEDDEV": "Medical device, AI/ML device, and medical-device cybersecurity data.",
}

PATTERN_DETECTION = {
    "DC-CHD": {
        "enabled": True,
        "patterns": [
            {"type": "luhn_checksum", "description": "Luhn algorithm validation for card numbers"},
            {"type": "card_number_visa", "regex": "4[0-9]{12}(?:[0-9]{3})?", "description": "Visa card number format"},
            {"type": "card_number_mastercard", "regex": "5[1-5][0-9]{14}", "description": "Mastercard number format"},
            {"type": "card_number_amex", "regex": "3[47][0-9]{13}", "description": "American Express card number format"},
            {"type": "cvv", "regex": "[0-9]{3,4}", "description": "Card verification value, context-dependent"},
            {"type": "expiration_date", "regex": "(0[1-9]|1[0-2])/([0-9]{2}|[0-9]{4})", "description": "Card expiration date"},
        ],
    },
    "DC-SAD": {
        "enabled": True,
        "patterns": [
            {"type": "cvv", "regex": "[0-9]{3,4}", "description": "Card verification value, context-dependent"},
            {"type": "pin_block", "description": "PIN or PIN-block indicators, context-dependent"},
        ],
    },
    "DC-PII": {
        "enabled": True,
        "patterns": [
            {"type": "ssn", "regex": "[0-9]{3}-[0-9]{2}-[0-9]{4}", "description": "US Social Security Number"},
            {"type": "email", "regex": "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", "description": "Email address"},
            {"type": "phone", "regex": "\\+?1?[\\s.-]?\\(?[0-9]{3}\\)?[\\s.-]?[0-9]{3}[\\s.-]?[0-9]{4}", "description": "US phone number"},
            {"type": "passport", "regex": "[A-Z]{1,2}[0-9]{6,9}", "description": "Passport number format"},
            {"type": "name_address_cooccurrence", "description": "Name and address appearing together"},
        ],
    },
    "DC-FIN": {
        "enabled": True,
        "patterns": [
            {"type": "account_number", "regex": "[0-9]{8,17}", "description": "Bank account number, context-dependent"},
            {"type": "routing_number", "regex": "[0-9]{9}", "description": "ABA routing number"},
            {"type": "swift_bic", "regex": "[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?", "description": "SWIFT/BIC code"},
            {"type": "iban", "regex": "[A-Z]{2}[0-9]{2}[A-Z0-9]{4,30}", "description": "International bank account number"},
        ],
    },
    "DC-NPI": {
        "enabled": True,
        "patterns": [
            {"type": "account_number", "regex": "[0-9]{8,17}", "description": "Financial account number, context-dependent"},
            {"type": "tax_id", "regex": "[0-9]{2}-[0-9]{7}", "description": "US employer identification number"},
        ],
    },
    "DC-PHI": {
        "enabled": True,
        "patterns": [
            {"type": "icd10", "regex": "[A-Z][0-9]{2}(\\.[0-9]{1,4})?", "description": "ICD-10 diagnostic code"},
            {"type": "npi", "regex": "[0-9]{10}", "description": "National Provider Identifier"},
            {"type": "mrn", "regex": "MRN[\\s:-]?[0-9]+", "description": "Medical record number"},
            {"type": "clinical_terminology", "description": "Clinical terms, drug names, and procedure codes"},
        ],
    },
}

DEVELOPER_TYPE_MAPPING = {
    "health_records": ["DC-PHI", "DC-PII"],
    "patient_data": ["DC-PHI", "DC-PII"],
    "personal_info": ["DC-PII"],
    "credit_cards": ["DC-CHD"],
    "payment_cards": ["DC-CHD"],
    "sensitive_authentication_data": ["DC-SAD"],
    "card_security_codes": ["DC-SAD"],
    "financial_data": ["DC-FIN"],
    "financial_records": ["DC-FIN"],
    "nonpublic_personal_info": ["DC-NPI"],
    "npi": ["DC-NPI"],
    "controlled_unclassified": ["DC-CUI"],
    "government_cui": ["DC-GOV", "DC-CUI"],
    "government_documents": ["DC-GOV", "DC-CUI"],
    "government_system": ["DC-GOV"],
    "federal_cloud": ["DC-FCI", "DC-GOV"],
    "fedramp_system": ["DC-FCI", "DC-GOV"],
    "material_nonpublic": ["DC-MNPI"],
    "mnpi": ["DC-MNPI"],
    "federal_contract": ["DC-FCI"],
    "federal_contract_info": ["DC-FCI"],
    "general": ["DC-GEN"],
    "public_data": ["DC-GEN"],
    "childrens_data": ["DC-MINOR"],
    "biometric_data": ["DC-BIO"],
    "legal_data": ["DC-LEGAL"],
    "legal_privileged": ["DC-LEGAL"],
    "trade_secrets": ["DC-IP"],
    "export_controlled": ["DC-ITAR"],
    "dual_use_technology": ["DC-EAR"],
    "ear_controlled": ["DC-EAR"],
    "critical_infrastructure": ["DC-CRIT"],
    "ai_training_data": ["DC-AI"],
    "agent_payments": ["DC-PAY"],
    "payment_data": ["DC-PAY"],
    "education_records": ["DC-EDU"],
    "student_data": ["DC-EDU"],
    "criminal_justice_information": ["DC-CJI"],
    "cji": ["DC-CJI"],
    "medical_device_data": ["DC-MEDDEV"],
    "medical_device": ["DC-MEDDEV"],
}

SDK_TAXONOMY_OVERLAY_OVERRIDES = {
    # The platform graph is intentionally broad. The SDK taxonomy is the
    # activation contract: it only auto-enables overlays that are ready enough
    # for default developer workflows and keeps jurisdiction-specific overlays
    # opt-in unless the data class is a strong signal. See
    # docs/adr/0001-sdk-taxonomy-overlay-overrides.md.
    "DC-BIO": ["eu-ai-act"],
    "DC-CUI": ["cmmc-l2"],
    "DC-FCI": ["fedramp"],
    "DC-FIN": ["glba", "soc2"],
    "DC-GEN": [],
    "DC-GOV": ["cmmc-l2", "fedramp"],
    "DC-MNPI": ["securities-mnpi"],
    "DC-NPI": ["glba", "soc2"],
    "DC-PII": ["ccpa", "gdpr", "soc2"],
}

SDK_SARIF_MAPPING_OVERRIDES = [
    {
        "rule_id": "js/sql-injection",
        "control_id": "PR-08",
        "match": "exact",
        "description": "CodeQL JavaScript SQL injection findings map to input validation and sanitization.",
    },
    {
        "rule_id": "js/sql-*",
        "control_id": "PR-08",
        "match": "glob",
        "description": "CodeQL JavaScript SQL injection-family findings map to input validation and sanitization.",
    },
    {
        "rule_id": "js/xss",
        "control_id": "PR-08",
        "match": "exact",
        "description": "CodeQL JavaScript XSS findings map to input validation and sanitization.",
    },
    {
        "rule_id": "js/hardcoded-credentials",
        "control_id": "PR-04",
        "match": "exact",
        "description": "Hard-coded credential findings map to data exposure prevention.",
    },
    {
        "rule_id": "js/missing-rate-limiting",
        "control_id": "PR-02",
        "match": "exact",
        "description": "Missing rate limiting findings map to permission scope enforcement.",
    },
    {
        "rule_id": "cwe-798",
        "control_id": "PR-04",
        "match": "exact",
        "description": "Hard-coded credential findings map to data exposure prevention.",
    },
]


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")


def normalize_overlay_id(overlay_id: str) -> str:
    return PLATFORM_TO_SDK_OVERLAY.get(overlay_id, overlay_id)


def load_effort_levels() -> dict[str, str]:
    tree = ast.parse(CONTROL_CATALOG_PATH.read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "_CONTROL_SPECS":
                    specs = ast.literal_eval(node.value)
                    return {spec[0].removeprefix("AKSI-"): spec[4] for spec in specs}
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "_CONTROL_SPECS"
        ):
            specs = ast.literal_eval(node.value)
            return {spec[0].removeprefix("AKSI-"): spec[4] for spec in specs}
    raise RuntimeError("_CONTROL_SPECS not found in frozen control catalog")


def display_name(title: str) -> str:
    return title.replace("&", "and")


def remediation_hint(control_id: str, title: str) -> str:
    return (
        f"Collect or attach AKSI v0.6 evidence for {control_id} ({title}) from one "
        "of the configured evidence sources, or record an explicit exception with owner and expiry."
    )


def generate_controls() -> list[str]:
    graph = read_json(GRAPH_PATH)
    effort_levels = load_effort_levels()
    control_ids = list(read_json(CONTROL_SCHEMA_PATH)["enum"])

    for control_id in control_ids:
        source = graph["controls"][control_id]
        product_id = source["product_control_id"]
        title = source["title"]
        common = bool(source["common"])
        generated = {
            "id": control_id,
            "product_control_id": product_id,
            "framework_version": FRAMEWORK_VERSION,
            "framework_source_commit": FRAMEWORK_COMMIT,
            "name": title,
            "function": FUNCTION_BY_DOMAIN[source["domain"]],
            "csf_mapping": "",
            "description": source["description"],
            "effort_level": effort_levels[control_id],
            "common": common,
            "trigger_classifications": source["trigger_classifications"],
            "trigger_certification_targets": source["trigger_certification_targets"],
            "evidence_sources": source["evidence_sources"],
            "evidence_keywords": source["evidence_keywords"],
            "overlays": [normalize_overlay_id(overlay) for overlay in source["overlays"]],
            "support_level": "runtime_evaluator" if control_id in RUNTIME_EVALUATOR_CONTROL_IDS else "attestation",
            "default_enabled": common,
            "baseline": common,
            "security_outcome": {
                "pass": f"Current evidence supports AKSI v0.6 {control_id}: {title}.",
                "fail": f"Required evidence for AKSI v0.6 {control_id}: {title} is missing, stale, or contradictory.",
            },
            "evidence_fields": source["evidence_keywords"],
            "regulatory_mappings": {},
            "display_name": display_name(title),
            "display_detail": source["description"],
            "remediation_hint_template": remediation_hint(control_id, title),
        }
        write_json(CONTROLS_DIR / f"{control_id.lower()}.json", generated)

    return control_ids


RUNTIME_EVALUATOR_CONTROL_IDS = {
    "DE-01",
    "DE-02",
    "DE-04",
    "GOV-02",
    "PR-01",
    "PR-02",
    "PR-03",
    "PR-04",
    "PR-05",
    "PR-06",
    "PR-07",
    "PR-08",
}

OSCAL_SP80053_MAPPINGS = {
    "DE-01": ["SI-4", "CA-7"],
    "DE-02": ["CM-3", "CM-6"],
    "DE-03": ["CA-2", "CA-7"],
    "DE-04": ["AU-9", "SI-7"],
    "DE-05": ["CA-7", "RA-5", "SI-4"],
    "DE-06": ["CA-2", "RA-5", "SA-11"],
    "GOV-01": ["PL-2", "PM-1"],
    "GOV-02": ["PM-2", "RA-2"],
    "GOV-03": ["RA-3", "RA-5"],
    "GOV-04": ["AC-25", "PL-4"],
    "GOV-05": ["PL-2", "PT-1", "PT-3"],
    "GOV-06": ["CA-7", "PL-2", "PM-4"],
    "GOV-07": ["AC-22", "PT-2", "PT-3"],
    "ID-01": ["PM-5", "CM-8"],
    "ID-02": ["CM-8", "SA-9"],
    "ID-03": ["RA-2", "RA-3"],
    "ID-04": ["SA-12", "SR-3"],
    "ID-05": ["RA-3", "RA-7"],
    "PAY-01": ["AC-3", "AC-6", "IA-2"],
    "PAY-02": ["AU-6", "AU-10", "AU-12"],
    "PR-01": ["AC-2", "IA-2", "IA-5"],
    "PR-02": ["AC-3", "AC-6"],
    "PR-03": ["SA-12", "SI-7"],
    "PR-04": ["SC-28", "SC-8"],
    "PR-05": ["AU-2", "AU-12"],
    "PR-06": ["CM-2", "CM-6", "SI-7"],
    "PR-07": ["SC-8", "SC-13"],
    "PR-08": ["SI-10"],
    "PR-09": ["CM-7", "SC-7", "SI-10"],
    "PR-10": ["AC-4", "SC-28", "SI-7"],
    "PR-11": ["MP-6", "PT-6", "SI-12"],
    "PR-12": ["IA-5", "SC-12", "SC-13"],
    "RC-01": ["CP-10", "IR-4"],
    "RC-02": ["IR-4", "IR-5"],
    "RC-03": ["CP-4", "CP-10"],
    "RS-01": ["IR-4", "SI-4"],
    "RS-02": ["IR-4", "IR-6"],
    "RS-03": ["AU-6", "IR-5"],
    "RS-04": ["AC-4", "IR-4", "SC-7"],
    "RS-05": ["IR-6", "IR-8"],
    "RS-06": ["RA-5", "SA-11", "SI-2"],
}


def pattern_detection_for(code: str) -> dict[str, Any]:
    if code in PATTERN_DETECTION:
        return PATTERN_DETECTION[code]
    return {
        "enabled": False,
        "note": "Requires declared classification or domain-specific detector evidence.",
    }


def generate_taxonomy() -> list[str]:
    graph = read_json(GRAPH_PATH)
    class_codes = list(read_json(CLASS_SCHEMA_PATH)["enum"])

    classifications = []
    for code in class_codes:
        overlays = SDK_TAXONOMY_OVERLAY_OVERRIDES.get(
            code,
            [
                normalize_overlay_id(overlay)
                for overlay in graph["dc_codes"].get(code, {}).get("overlays", [])
            ],
        )
        classifications.append(
            {
                "code": code,
                "name": TAXONOMY_NAMES[code],
                "description": TAXONOMY_DESCRIPTIONS[code],
                "overlays": overlays,
                "overlay_status": "active" if overlays else "roadmap",
                "pattern_detection": pattern_detection_for(code),
            }
        )

    taxonomy = {
        "version": FRAMEWORK_VERSION,
        "framework_source_commit": FRAMEWORK_COMMIT,
        "classifications": classifications,
        "developer_type_mapping": DEVELOPER_TYPE_MAPPING,
        "control_detection_signals": {
            "DC-Code-Execution": "PR-09",
            "DC-External-API": "ID-02 or PR-03",
            "DC-Credentials": "PR-04",
        },
    }
    write_json(TAXONOMY_PATH, taxonomy)
    return class_codes


def update_config_schema(control_ids: list[str]) -> None:
    schema = read_json(CONFIG_SCHEMA_PATH)
    controls = schema["properties"]["security"]["properties"]["controls"]
    controls["patternProperties"] = {
        "^(GOV-0[1-7]|ID-0[1-5]|PR-(0[1-9]|1[0-2])|DE-0[1-6]|RS-0[1-6]|RC-0[1-3]|PAY-0[1-2])$": {
            "type": "object",
            "properties": {
                "enabled": {
                    "type": "boolean",
                    "default": True,
                }
            },
            "additionalProperties": False,
        }
    }
    schema["properties"]["my_agent_handles"]["items"]["enum"] = sorted(DEVELOPER_TYPE_MAPPING)
    schema["properties"]["certification_targets"]["description"] = (
        "Certification standards or extension targets to activate. Examples: ['aiuc-1'], ['AGENT_PAYMENTS'], ['X402']."
    )
    schema.setdefault("$defs", {})["aksi_control_id"] = {"type": "string", "enum": control_ids}
    write_json(CONFIG_SCHEMA_PATH, schema)


def allow_flag_result(schema: dict[str, Any]) -> None:
    control_result = schema["properties"]["control_results"]["items"]["properties"]["result"]
    values = control_result.setdefault("enum", [])
    if "FLAG" not in values:
        values.insert(2, "FLAG")


def add_framework_version(schema: dict[str, Any]) -> None:
    properties = schema.setdefault("properties", {})
    properties.setdefault(
        "framework_version",
        {
            "type": ["string", "null"],
            "default": FRAMEWORK_VERSION,
            "description": "AKSI framework version used to produce this record.",
        },
    )


def update_result_schemas() -> None:
    evaluation_schema = read_json(EVALUATION_SCHEMA_PATH)
    allow_flag_result(evaluation_schema)
    add_framework_version(evaluation_schema)
    write_json(EVALUATION_SCHEMA_PATH, evaluation_schema)

    evidence_schema = read_json(EVIDENCE_SCHEMA_PATH)
    allow_flag_result(evidence_schema)
    add_framework_version(evidence_schema)
    write_json(EVIDENCE_SCHEMA_PATH, evidence_schema)

    action_schema = read_json(ACTION_SCHEMA_PATH)
    add_framework_version(action_schema)
    write_json(ACTION_SCHEMA_PATH, action_schema)


def copy_platform_mappings() -> None:
    data = read_json(SARIF_MAPPING_PATH)
    mappings = data.setdefault("mappings", [])
    override_ids = {entry["rule_id"] for entry in SDK_SARIF_MAPPING_OVERRIDES}
    mappings[:] = [entry for entry in mappings if entry.get("rule_id") not in override_ids]
    mappings.extend(SDK_SARIF_MAPPING_OVERRIDES)
    write_json(SDK_SARIF_MAPPING_PATH, data)


def generate_oscal_mapping(control_ids: list[str]) -> None:
    missing = sorted(set(control_ids) - set(OSCAL_SP80053_MAPPINGS))
    if missing:
        raise SystemExit(f"OSCAL SP 800-53 mapping missing controls: {', '.join(missing)}")
    mapping = {
        "_version": "1.1.0",
        "framework": "NIST SP 800-53 Rev 5",
        "oscal_version": "1.1.2",
        "catalog_href": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
        "mappings": {control_id: OSCAL_SP80053_MAPPINGS[control_id] for control_id in control_ids},
    }
    write_json(SDK_OSCAL_MAPPING_PATH, mapping)


def generate_controls_reference() -> None:
    controls = []
    for path in sorted(CONTROLS_DIR.glob("*.json")):
        controls.append(read_json(path))

    lines = [
        "# AKSI Controls Reference",
        "",
        "Ancilis evaluates agent actions against AKSI Framework v0.6.",
        "",
        "- 41 controls are defined in the shared catalog.",
        "- 39 common controls are enabled for every governed agent.",
        "- `PAY-01` and `PAY-02` are extension controls activated by `DC-PAY`, `AGENT_PAYMENTS`, or `X402`.",
        "- `support_level: runtime_evaluator` means the SDK has deterministic evaluator code today. `support_level: attestation` means the control is catalog-backed and expects imported or attached evidence.",
        "",
        "## Control Table",
        "",
        "| Control | Domain | Name | Default | Support | Evidence sources |",
        "|---------|--------|------|---------|---------|------------------|",
    ]

    for control in controls:
        default = "common" if control["common"] else "extension"
        sources = ", ".join(control["evidence_sources"])
        lines.append(
            "| {id} | {function} | {name} | {default} | {support} | {sources} |".format(
                id=control["id"],
                function=control["function"],
                name=control["name"].replace("|", "\\|"),
                default=default,
                support=control["support_level"],
                sources=sources,
            )
        )

    lines.extend(
        [
            "",
            "## Extension Activation",
            "",
            "| Control | Activates when |",
            "|---------|----------------|",
        ]
    )
    for control in controls:
        if control["common"]:
            continue
        triggers = []
        triggers.extend(control.get("trigger_classifications", []))
        triggers.extend(control.get("trigger_certification_targets", []))
        lines.append(f"| {control['id']} | {', '.join(triggers)} |")

    lines.extend(
        [
            "",
            "## Detailed Definitions",
            "",
        ]
    )
    for control in controls:
        lines.extend(
            [
                f"### {control['id']} - {control['name']}",
                "",
                control["description"],
                "",
                f"- Function: `{control['function']}`",
                f"- Effort level: `{control['effort_level']}`",
                f"- Support level: `{control['support_level']}`",
                f"- Product ID: `{control['product_control_id']}`",
                f"- Evidence keywords: {', '.join(control['evidence_keywords'])}",
                "",
            ]
        )

    CONTROLS_REFERENCE_PATH.write_text("\n".join(lines))


def main() -> None:
    if FROZEN_SOURCE_ENV not in os.environ:
        raise SystemExit(
            "AKSI_FROZEN_SRC must point to the frozen AKSI v0.6 artifact checkout "
            "before running scripts/generate_aksi_v06_assets.py."
        )

    missing = [
        path
        for path in (
            GRAPH_PATH,
            CONTROL_CATALOG_PATH,
            CLASS_SCHEMA_PATH,
            CONTROL_SCHEMA_PATH,
            SARIF_MAPPING_PATH,
        )
        if not path.exists()
    ]
    if missing:
        formatted = "\n".join(str(path) for path in missing)
        raise SystemExit(f"Missing frozen AKSI v0.6 artifacts:\n{formatted}")

    control_ids = generate_controls()
    generate_taxonomy()
    update_config_schema(control_ids)
    update_result_schemas()
    copy_platform_mappings()
    generate_oscal_mapping(control_ids)
    generate_controls_reference()
    print(f"Generated {len(control_ids)} controls and taxonomy at {TAXONOMY_PATH}")


if __name__ == "__main__":
    main()
