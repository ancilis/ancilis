"""Activation resolver (Unit 5)."""

from ancilis.activation.advisory import (
    CertificationUpgradeAdvisory,
    ClassificationAdvisory,
    ClassificationRecommendation,
    PatternDetection,
)
from ancilis.activation.loader import load_certification_profile, load_certification_profiles
from ancilis.activation.resolver import ActivationResolver, ActivationSpec

__all__ = [
    "ActivationResolver",
    "ActivationSpec",
    "CertificationUpgradeAdvisory",
    "ClassificationAdvisory",
    "ClassificationRecommendation",
    "PatternDetection",
    "load_certification_profile",
    "load_certification_profiles",
]
