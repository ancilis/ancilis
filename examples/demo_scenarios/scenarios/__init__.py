"""Scenario definitions for the acquirer-demo evidence generator."""

from __future__ import annotations

from .code_review import scenario as code_review
from .data_pipeline import scenario as data_pipeline
from .hr_onboarding import scenario as hr_onboarding
from .patient_intake import scenario as patient_intake
from .payment_processor import scenario as payment_processor

__all__ = [
    "code_review",
    "data_pipeline",
    "hr_onboarding",
    "patient_intake",
    "payment_processor",
]
