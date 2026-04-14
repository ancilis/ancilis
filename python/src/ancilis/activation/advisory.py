"""Classification advisory and certification upgrade advisory."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ancilis.activation.loader import load_overlay_profiles, load_taxonomy
from ancilis.overlays import normalize_overlay_ids


@dataclass
class ClassificationRecommendation:
    detected_pattern: str
    suggested_config_field: str
    suggested_value: str
    projected_overlays: list[str]
    projected_controls: list[str]
    detection_count: int
    confidence: str  # "high" | "medium" | "low"
    severity: str  # "info" | "warning" | "alert"
    example_config: str


@dataclass
class CertificationUpgradeAdvisory:
    certification_id: str
    message: str
    suggested_config_addition: dict[str, Any]
    aiuc1_domains_strengthened: list[str]
    severity: str = "info"


# Map pattern types (from Unit 3) to data handling terms
PATTERN_TO_DATA_TYPE: dict[str, str] = {
    "ssn": "personal_info",
    "credit_card": "credit_cards",
    "email": "personal_info",
    "phone": "personal_info",
    "api_key": "trade_secrets",
    "mrn": "health_records",
}

PATTERN_SEVERITY: dict[str, str] = {
    "ssn": "alert",
    "credit_card": "alert",
    "mrn": "alert",
    "api_key": "warning",
    "email": "info",
    "phone": "info",
}

# AIUC-1 domain mapping for upgrade advisories
DATA_TYPE_TO_AIUC1_DOMAIN: dict[str, list[str]] = {
    "health_records": ["A"],
    "personal_info": ["A"],
    "credit_cards": ["A"],
    "financial_records": ["A"],
    "ai_training_data": ["D"],
    "biometric_data": ["A", "D"],
}


@dataclass
class PatternDetection:
    pattern_type: str
    count: int


class ClassificationAdvisory:
    """Generates classification recommendations from pattern detections."""

    def __init__(self) -> None:
        self._taxonomy = load_taxonomy()
        self._overlay_profiles = load_overlay_profiles()

    def generate(
        self,
        pattern_detections: list[PatternDetection],
        active_my_agent_handles: list[str] | None = None,
        active_certifications: list[str] | None = None,
    ) -> tuple[list[ClassificationRecommendation], list[CertificationUpgradeAdvisory]]:
        """Generate recommendations for detected patterns not covered by config.

        Returns (recommendations, upgrade_advisories).
        Never auto-activates — returns data only.
        """
        current = set(active_my_agent_handles or [])
        recommendations: list[ClassificationRecommendation] = []
        upgrade_advisories: list[CertificationUpgradeAdvisory] = []

        # Aggregate detections by suggested data type
        type_detections: dict[str, int] = {}
        type_patterns: dict[str, list[str]] = {}
        for detection in pattern_detections:
            data_type = PATTERN_TO_DATA_TYPE.get(detection.pattern_type)
            if data_type and data_type not in current:
                type_detections[data_type] = type_detections.get(data_type, 0) + detection.count
                type_patterns.setdefault(data_type, []).append(detection.pattern_type)

        # Generate recommendations
        for data_type, count in type_detections.items():
            patterns = type_patterns[data_type]
            projected_overlays = self._project_overlays(data_type)
            projected_controls = self._project_controls(projected_overlays)

            # Determine severity from strictest pattern
            severity = max(
                (PATTERN_SEVERITY.get(p, "info") for p in patterns),
                key=lambda s: {"info": 0, "warning": 1, "alert": 2}[s],
            )

            confidence = "high" if count >= 5 else "medium" if count >= 2 else "low"

            example = f"my_agent_handles:\n  - {data_type}"

            recommendations.append(ClassificationRecommendation(
                detected_pattern=patterns[0],
                suggested_config_field="my_agent_handles",
                suggested_value=data_type,
                projected_overlays=projected_overlays,
                projected_controls=projected_controls,
                detection_count=count,
                confidence=confidence,
                severity=severity,
                example_config=example,
            ))

        # Generate certification upgrade advisories
        if active_certifications and "aiuc-1" in active_certifications:
            for rec in recommendations:
                domains = DATA_TYPE_TO_AIUC1_DOMAIN.get(rec.suggested_value, [])
                if domains:
                    msg = (
                        f"{rec.suggested_value} patterns detected in tool calls. "
                        f"Adding 'my_agent_handles: [{rec.suggested_value}]' would activate "
                        f"{', '.join(rec.projected_overlays)} controls and strengthen your "
                        f"AIUC-1 posture under domain {', '.join(domains)}."
                    )
                    upgrade_advisories.append(CertificationUpgradeAdvisory(
                        certification_id="aiuc-1",
                        message=msg,
                        suggested_config_addition={"my_agent_handles": [rec.suggested_value]},
                        aiuc1_domains_strengthened=domains,
                        severity="info",
                    ))

        return recommendations, upgrade_advisories

    def _project_overlays(self, data_type: str) -> list[str]:
        """Project which overlays would activate for a given data type."""
        type_mapping = self._taxonomy.get("developer_type_mapping", {})
        dc_codes = type_mapping.get(data_type, [])

        classification_lookup: dict[str, list[str]] = {}
        for entry in self._taxonomy.get("classifications", []):
            classification_lookup[entry["code"]] = normalize_overlay_ids(
                entry.get("overlays", [])
            )

        overlays: list[str] = []
        for dc_code in dc_codes:
            for oid in classification_lookup.get(dc_code, []):
                if oid in self._overlay_profiles and oid not in overlays:
                    overlays.append(oid)
        return overlays

    def _project_controls(self, overlay_ids: list[str]) -> list[str]:
        """Project additional controls that would activate from overlays."""
        controls: set[str] = set()
        for oid in overlay_ids:
            profile = self._overlay_profiles.get(oid, {})
            for cid in profile.get("control_adjustments", {}):
                controls.add(cid)
        return sorted(controls)
