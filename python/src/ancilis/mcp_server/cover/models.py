"""Shared models for Ancilis Cover MCP tools."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CoverSignal(BaseModel):
    """Evidence behind a deterministic Cover recommendation."""

    source: str
    value: str
    rule_id: str
    confidence: str
    recommendation: str | None = None
    path: str | None = None


class ProjectInspection(BaseModel):
    """Detected local project shape and likely Ancilis integration path."""

    root: str
    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    ancilis_present: bool = False
    config_path: str | None = None
    recommended_producers: list[str] = Field(default_factory=list)
    signals: list[CoverSignal] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0


class ProjectClassification(BaseModel):
    """Deterministic data and overlay recommendations for a project."""

    my_agent_handles: list[str] = Field(default_factory=list)
    data_classifications: list[str] = Field(default_factory=list)
    active_overlays: list[str] = Field(default_factory=list)
    certification_targets: list[str] = Field(default_factory=list)
    confidence: str = "low"
    signals: list[CoverSignal] = Field(default_factory=list)
    review_items: list[CoverSignal] = Field(default_factory=list)


class SetupRecommendation(BaseModel):
    """Concrete read-only setup guidance for adding Ancilis."""

    install_commands: list[str] = Field(default_factory=list)
    config_yaml: str
    integration_summary: str
    integration_snippets: dict[str, str] = Field(default_factory=dict)
    validation_commands: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)


class CodeFinding(BaseModel):
    """A deterministic code review finding."""

    severity: str
    category: str
    message: str
    path: str | None = None
    sample: str | None = None
    producer: str | None = None


class SkippedFile(BaseModel):
    """A file skipped by code review with a structured reason."""

    path: str
    reason: str
    detail: str = ""


class CodeReviewResult(BaseModel):
    """Bounded deterministic review of explicit files or snippets."""

    findings: list[CodeFinding] = Field(default_factory=list)
    producer_recommendations: list[str] = Field(default_factory=list)
    suggested_config_changes: list[str] = Field(default_factory=list)
    reviewed_files: list[str] = Field(default_factory=list)
    skipped_files: list[SkippedFile] = Field(default_factory=list)


class NormalizationSignal(BaseModel):
    """A deterministic mapping from user language to an Ancilis target."""

    source: str
    phrase: str
    mapped_to: str
    target_type: str
    confidence: str


class GapReviewItem(BaseModel):
    """A low-confidence or unsupported target phrase requiring user review."""

    source: str
    value: str
    reason: str


class GapTarget(BaseModel):
    """Normalized target state for a gap assessment."""

    my_agent_handles: list[str] = Field(default_factory=list)
    active_overlays: list[str] = Field(default_factory=list)
    certification_targets: list[str] = Field(default_factory=list)


class ConfigGap(BaseModel):
    """Delta between requested target and current Ancilis config."""

    missing_my_agent_handles: list[str] = Field(default_factory=list)
    present_my_agent_handles: list[str] = Field(default_factory=list)
    missing_overlays: list[str] = Field(default_factory=list)
    present_overlays: list[str] = Field(default_factory=list)
    missing_certification_targets: list[str] = Field(default_factory=list)
    present_certification_targets: list[str] = Field(default_factory=list)


class InstrumentationGap(BaseModel):
    """Producer instrumentation recommendations for the requested target."""

    recommended_producers: list[str] = Field(default_factory=list)
    present_producers: list[str] = Field(default_factory=list)
    missing_producers: list[str] = Field(default_factory=list)
    review_items: list[GapReviewItem] = Field(default_factory=list)


class EvidenceGap(BaseModel):
    """Evidence coverage for requested overlays and certifications."""

    session_id: str | None = None
    requested_overlays: list[str] = Field(default_factory=list)
    controls_total: int = 0
    controls_with_evidence: int = 0
    missing_controls: list[str] = Field(default_factory=list)
    evidenced_controls: list[str] = Field(default_factory=list)


class GapAssessmentResult(BaseModel):
    """Structured deterministic gap assessment response."""

    mode: str
    target: GapTarget
    normalization_signals: list[NormalizationSignal] = Field(default_factory=list)
    review_items: list[GapReviewItem] = Field(default_factory=list)
    project: dict[str, object] = Field(default_factory=dict)
    config_gap: ConfigGap
    instrumentation_gap: InstrumentationGap
    evidence_gap: EvidenceGap
    next_steps: list[str] = Field(default_factory=list)
    confidence: str = "low"
    assumptions: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
