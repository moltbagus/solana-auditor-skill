#!/usr/bin/env python3
"""
fix_models.py — Dataclasses for the fix suggestion engine.

Single Responsibility: Define all output schemas (FixSuggestion, RemediationBlock,
FixSuggestionsOutput). Reason to change: Schema/format changes.

Usage:
    from fix_models import FixSuggestion, RemediationBlock
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class FixSuggestion:
    """Fix suggestion for a single finding."""

    finding_id: str
    severity: str
    rule_id: str
    file: str
    line: int
    before_code: str
    after_code: str
    explanation: str
    references: list[str]
    # New fields for v2.0
    confidence_score: float = 0.0
    fix_tier: str = "C"
    fix_type: str = "validation_check"
    poker_risk: str = "MEDIUM"
    estimated_effort_minutes: int = 10
    cvss_before: float = 0.0
    cvss_after: float = 0.0
    cvss_reduction: float = 0.0
    test_template: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return asdict(self)


@dataclass
class RemediationBlock:
    """Remediation block for findings.json."""

    fix_tier: str
    confidence_score: float
    fix_type: str
    patch: dict[str, Any]
    cvss_after: dict[str, Any]
    poker_risk: str
    estimated_effort_minutes: int
    status: str = "pending"
    applied_at: Optional[str] = None
    applied_by: Optional[str] = None
    verification: dict[str, Any] = field(default_factory=lambda: {
        "anchor_test": None,
        "anchor_build_pass": False,
        "formal_verified": False,
        "regression_pass": False,
        "verified_at": None,
    })
    history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return asdict(self)


@dataclass
class FixSuggestionsOutput:
    """Output structure for fix_suggestions.json."""

    generated_at: str
    program_id: str
    version: str
    total_findings: int
    suggestions: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return asdict(self)
