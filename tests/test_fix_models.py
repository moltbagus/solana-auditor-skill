"""Tests for fix_models.py — dataclass definitions.

Verifies FixSuggestion, RemediationBlock, and FixSuggestionsOutput
dataclasses: construction, defaults, to_dict(), and edge cases.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from fix_models import FixSuggestion, FixSuggestionsOutput, RemediationBlock  # noqa: E402


# ---------------------------------------------------------------------------
# FixSuggestion
# ---------------------------------------------------------------------------

class TestFixSuggestion:
    def test_minimal_construction(self) -> None:
        """Required fields only."""
        s = FixSuggestion(
            finding_id="SUGGEST-TEST-01",
            severity="HIGH",
            rule_id="Rule 8",
            file="programs/test/src/lib.rs",
            line=42,
            before_code="// old",
            after_code="// new",
            explanation="Fix it",
            references=[],
        )
        assert s.finding_id == "SUGGEST-TEST-01"
        assert s.severity == "HIGH"
        assert s.confidence_score == 0.0  # default

    def test_full_construction(self) -> None:
        """All fields provided."""
        s = FixSuggestion(
            finding_id="SUGGEST-VULN-01",
            severity="CRITICAL",
            rule_id="Rule 8",
            file="src/lib.rs",
            line=10,
            before_code="// unsafe",
            after_code="// safe",
            explanation="Added signer check",
            references=["https://cwe.mitre.org/data/definitions/306.html"],
            confidence_score=0.95,
            fix_tier="A",
            fix_type="validation_check",
            poker_risk="LOW",
            estimated_effort_minutes=5,
            cvss_before=9.8,
            cvss_after=2.5,
            cvss_reduction=7.3,
            test_template="#[test]\nfn test() {}",
        )
        assert s.fix_tier == "A"
        assert s.cvss_before == 9.8
        assert s.cvss_reduction == 7.3

    def test_to_dict_returns_dict(self) -> None:
        s = FixSuggestion(
            finding_id="SUGGEST-VULN-01",
            severity="HIGH",
            rule_id="Rule 6",
            file="f.rs",
            line=5,
            before_code="a + b",
            after_code="a.checked_add(b)?",
            explanation="Checked math",
            references=[],
        )
        d = s.to_dict()
        assert isinstance(d, dict)
        assert d["finding_id"] == "SUGGEST-VULN-01"
        assert d["severity"] == "HIGH"
        assert d["confidence_score"] == 0.0
        assert d["cvss_reduction"] == 0.0

    def test_to_dict_serializable(self) -> None:
        """to_dict() output must be JSON-serializable."""
        import json
        s = FixSuggestion(
            finding_id="SUGGEST-TEST",
            severity="MEDIUM",
            rule_id="Rule 3",
            file="f.rs",
            line=1,
            before_code="old",
            after_code="new",
            explanation="bump fix",
            references=["https://example.com"],
        )
        dumped = json.dumps(s.to_dict())
        assert isinstance(dumped, str)

    def test_empty_references(self) -> None:
        s = FixSuggestion(
            finding_id="SUGGEST-TEST",
            severity="LOW",
            rule_id="Rule 0",
            file="f.rs",
            line=0,
            before_code="",
            after_code="",
            explanation="",
            references=[],
        )
        assert s.references == []

    def test_type_hints_match(self) -> None:
        s = FixSuggestion(
            finding_id="ID", severity="LOW", rule_id="R",
            file="f", line=0, before_code="", after_code="",
            explanation="", references=[],
        )
        assert isinstance(s.finding_id, str)
        assert isinstance(s.line, int)
        assert isinstance(s.confidence_score, float)
        assert isinstance(s.references, list)

    def test_cvss_reduction_negative(self) -> None:
        """cvss_reduction can be 0 or negative if fix doesn't reduce score."""
        s = FixSuggestion(
            finding_id="ID", severity="LOW", rule_id="R",
            file="f", line=0, before_code="", after_code="",
            explanation="", references=[], cvss_reduction=-0.5,
        )
        assert s.cvss_reduction == -0.5


# ---------------------------------------------------------------------------
# RemediationBlock
# ---------------------------------------------------------------------------

class TestRemediationBlock:
    def test_minimal_construction(self) -> None:
        rb = RemediationBlock(
            fix_tier="B",
            confidence_score=0.80,
            fix_type="validation_check",
            patch={"file": "src/lib.rs", "diff": "--- a\n+++ b"},
            cvss_after={"score": 3.1, "vector": "CVSS:3.1/..."},
            poker_risk="LOW",
            estimated_effort_minutes=10,
        )
        assert rb.fix_tier == "B"
        assert rb.status == "pending"
        assert rb.applied_at is None

    def test_to_dict_returns_dict(self) -> None:
        rb = RemediationBlock(
            fix_tier="A", confidence_score=0.95, fix_type="arithmetic_safety",
            patch={"f": "diff..."}, cvss_after={"score": 0.0},
            poker_risk="LOW", estimated_effort_minutes=2,
        )
        d = rb.to_dict()
        assert isinstance(d, dict)
        assert d["fix_tier"] == "A"
        assert d["status"] == "pending"

    def test_verification_defaults(self) -> None:
        rb = RemediationBlock(
            fix_tier="C", confidence_score=0.40, fix_type="architectural_refactor",
            patch={}, cvss_after={}, poker_risk="HIGH",
            estimated_effort_minutes=60,
        )
        assert rb.verification["anchor_test"] is None
        assert rb.verification["anchor_build_pass"] is False
        assert rb.verification["formal_verified"] is False
        assert rb.verification["regression_pass"] is False

    def test_history_appends(self) -> None:
        rb = RemediationBlock(
            fix_tier="A", confidence_score=0.9, fix_type="validation_check",
            patch={}, cvss_after={}, poker_risk="LOW",
            estimated_effort_minutes=5,
        )
        rb.history.append({"action": "applied", "at": "2025-01-01"})
        assert len(rb.history) == 1


# ---------------------------------------------------------------------------
# FixSuggestionsOutput
# ---------------------------------------------------------------------------

class TestFixSuggestionsOutput:
    def test_minimal_construction(self) -> None:
        output = FixSuggestionsOutput(
            generated_at="2025-01-01T00:00:00",
            program_id="test_program_id",
            version="1.0.0",
            total_findings=0,
            suggestions=[],
        )
        assert output.total_findings == 0
        assert len(output.suggestions) == 0

    def test_to_dict_returns_dict(self) -> None:
        output = FixSuggestionsOutput(
            generated_at="2025-01-01T00:00:00",
            program_id="test_program_id",
            version="1.0.0",
            total_findings=2,
            suggestions=[{"finding_id": "F1"}, {"finding_id": "F2"}],
        )
        d = output.to_dict()
        assert d["total_findings"] == 2
        assert len(d["suggestions"]) == 2
        assert d["program_id"] == "test_program_id"

    def test_to_dict_serializable(self) -> None:
        import json
        output = FixSuggestionsOutput(
            generated_at="2025-06-01T00:00:00Z",
            program_id="p1",
            version="2.0.0",
            total_findings=1,
            suggestions=[{"id": "S1"}],
        )
        dumped = json.dumps(output.to_dict())
        assert "2025-06-01" in dumped
        assert "S1" in dumped


# ---------------------------------------------------------------------------
# Integration: Full round-trip
# ---------------------------------------------------------------------------

class TestModelRoundTrip:
    def test_suggestion_inside_output(self) -> None:
        """FixSuggestion -> to_dict -> FixSuggestionsOutput -> to_dict."""
        s = FixSuggestion(
            finding_id="SUGGEST-VULN-01",
            severity="CRITICAL",
            rule_id="Rule 8",
            file="f.rs",
            line=42,
            before_code="",
            after_code="",
            explanation="",
            references=[],
        )
        output = FixSuggestionsOutput(
            generated_at="now",
            program_id="test",
            version="2.0.0",
            total_findings=1,
            suggestions=[s.to_dict()],
        )
        d = output.to_dict()
        assert d["suggestions"][0]["finding_id"] == "SUGGEST-VULN-01"
        assert d["suggestions"][0]["severity"] == "CRITICAL"
