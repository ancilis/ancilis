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
