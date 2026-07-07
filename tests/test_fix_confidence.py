"""Tests for fix_confidence.py — scoring, tiers, CVSS, and formatting.

Verifies confidence computation, tier determination, CVSS estimation,
test template generation, and tier-specific output formatting.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from fix_confidence import (  # noqa: E402  # noqa: E402
    compute_confidence,
    determine_tier,
    estimate_cvss_after,
    format_tier_a_notification,
    format_tier_b_prompt,
    format_tier_c_guidance,
    generate_test_template,
    get_effort_minutes,
    get_fix_type,
    get_poker_risk,
)
from fix_models import FixSuggestion  # noqa: E402


# ---------------------------------------------------------------------------
# compute_confidence
# ---------------------------------------------------------------------------

class TestComputeConfidence:
    def test_known_rule_with_pattern_match(self) -> None:
        """Rule 8 has base 0.98, pattern_match=True -> 0.98."""
        score = compute_confidence("Rule 8", True)
        assert score == 0.98

    def test_known_rule_without_pattern_match(self) -> None:
        """Rule 8 * 0.85 = 0.98 * 0.85 = 0.833 -> 0.83"""
        score = compute_confidence("Rule 8", False)
        assert score == pytest.approx(0.83, abs=0.01)

    def test_unknown_rule(self) -> None:
        score = compute_confidence("Rule 99", True)
        assert score == 0.70  # default base rate

    def test_high_confidence_rules(self) -> None:
        """Rules 6, 8, 18 should all be >= 0.95 with pattern match."""
        for rid in ("Rule 6", "Rule 8", "Rule 18"):
            assert compute_confidence(rid, True) >= 0.95

    def test_low_confidence_rule(self) -> None:
        """Rule 26 (flash loan) has the lowest base rate."""
        assert compute_confidence("Rule 26", True) == 0.60

    def test_score_type(self) -> None:
        score = compute_confidence("Rule 8", True)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0


# ---------------------------------------------------------------------------
# determine_tier
# ---------------------------------------------------------------------------

class TestDetermineTier:
    def test_high_confidence_low_risk_is_tier_a(self) -> None:
        assert determine_tier(0.95, "LOW") == "A"

    def test_medium_confidence_low_risk_is_tier_b(self) -> None:
        assert determine_tier(0.75, "LOW") == "B"

    def test_low_confidence_is_tier_c(self) -> None:
        assert determine_tier(0.50, "LOW") == "C"

    def test_high_risk_always_tier_c(self) -> None:
        for conf in (0.95, 0.75, 0.50):
            assert determine_tier(conf, "HIGH") == "C"

    def test_critical_risk_always_tier_c(self) -> None:
        assert determine_tier(0.99, "CRITICAL") == "C"

    def test_boundary_tier_a(self) -> None:
        assert determine_tier(0.90, "LOW") == "A"

    def test_boundary_tier_b(self) -> None:
        assert determine_tier(0.60, "LOW") == "B"
        assert determine_tier(0.89, "LOW") == "B"

    def test_boundary_tier_c(self) -> None:
        assert determine_tier(0.59, "LOW") == "C"

    def test_edge_case_zero_confidence(self) -> None:
        assert determine_tier(0.0, "LOW") == "C"


# ---------------------------------------------------------------------------
# estimate_cvss_after
# ---------------------------------------------------------------------------

class TestEstimateCvssAfter:
    def test_full_fix_rule(self) -> None:
        """Rule 8: 75% reduction floor at 1.0."""
        after, vec = estimate_cvss_after(9.8, "Rule 8")
        assert after == pytest.approx(7.4, abs=0.1)  # 9.8 - (9.8 * 0.25) = 7.35
        assert "AV:N" in vec

    def test_partial_fix_rule(self) -> None:
        """Rule 14: 85% of original, floor at 1.0."""
        after, vec = estimate_cvss_after(7.5, "Rule 14")
        expected = max(1.0, round(7.5 - (7.5 * 0.15), 1))
        assert after == expected

    def test_architectural_rule(self) -> None:
        """Rule 26: 90% of original."""
        after, _ = estimate_cvss_after(5.0, "Rule 26")
        assert after == max(1.0, round(5.0 - (5.0 * 0.10), 1))

    def test_default_reduction(self) -> None:
        """Unknown rule uses 20% reduction."""
        after, _ = estimate_cvss_after(10.0, "Rule 0")
        assert after == max(1.0, round(10.0 - (10.0 * 0.20), 1))

    def test_floor_at_one(self) -> None:
        """CVSS after should never be below 1.0."""
        after, _ = estimate_cvss_after(1.0, "Rule 6")
        assert after >= 1.0

    def test_return_type(self) -> None:
        after, vec = estimate_cvss_after(9.8, "Rule 8")
        assert isinstance(after, float)
        assert isinstance(vec, str)


# ---------------------------------------------------------------------------
# get_fix_type, get_poker_risk, get_effort_minutes
# ---------------------------------------------------------------------------

class TestFixMetadata:
    def test_known_fix_type(self) -> None:
        assert get_fix_type("Rule 8") == "validation_check"

    def test_unknown_fix_type(self) -> None:
        assert get_fix_type("Rule 99") == "validation_check"  # default

    def test_known_poker_risk(self) -> None:
        assert get_poker_risk("Rule 8") == "LOW"

    def test_high_poker_risk(self) -> None:
        assert get_poker_risk("Rule 26") == "HIGH"

    def test_unknown_poker_risk(self) -> None:
        assert get_poker_risk("Rule 99") == "MEDIUM"

    def test_known_effort(self) -> None:
        assert get_effort_minutes("Rule 8") == 5

    def test_high_effort(self) -> None:
        assert get_effort_minutes("Rule 16") == 60

    def test_unknown_effort(self) -> None:
        assert get_effort_minutes("Rule 99") == 10  # default


# ---------------------------------------------------------------------------
# generate_test_template
# ---------------------------------------------------------------------------

class TestGenerateTestTemplate:
    def test_rule_8_template(self) -> None:
        tpl = generate_test_template("Rule 8", "CRIT-01")
        assert "requires_signer" in tpl

    def test_rule_6_template(self) -> None:
        tpl = generate_test_template("Rule 6", "HIGH-01")
        assert "overflow" in tpl

    def test_rule_14_template(self) -> None:
        tpl = generate_test_template("Rule 14", "MED-01")
        assert "reentrancy" in tpl.lower()

    def test_unknown_rule_template(self) -> None:
        tpl = generate_test_template("Rule 99", "UNKNOWN-001")
        assert "fix_verification" in tpl

    def test_finding_id_in_template(self) -> None:
        tpl = generate_test_template("Rule 8", "VULN-01")
        assert "vuln_01" in tpl.lower() or "vuln-01" in tpl.lower()


# ---------------------------------------------------------------------------
# format_tier_a_notification
# ---------------------------------------------------------------------------

class TestFormatTierA:
    @pytest.fixture
    def suggestion(self) -> FixSuggestion:
        return FixSuggestion(
            finding_id="SUGGEST-VULN-01",
            severity="CRITICAL",
            rule_id="Rule 8",
            file="programs/vault/src/lib.rs",
            line=42,
            before_code="old_code",
            after_code="new_code",
            explanation="Added signer check",
            references=[],
            confidence_score=0.98,
            fix_tier="A",
            fix_type="validation_check",
        )

    def test_contains_finding_id(self, suggestion: FixSuggestion) -> None:
        msg = format_tier_a_notification(suggestion)
        assert "SUGGEST-VULN-01" in msg

    def test_contains_tier_label(self, suggestion: FixSuggestion) -> None:
        msg = format_tier_a_notification(suggestion)
        assert "Tier A" in msg

    def test_contains_cvss(self, suggestion: FixSuggestion) -> None:
        msg = format_tier_a_notification(suggestion)
        assert "CVSS" in msg


# ---------------------------------------------------------------------------
# format_tier_b_prompt
# ---------------------------------------------------------------------------

class TestFormatTierB:
    @pytest.fixture
    def suggestion(self) -> FixSuggestion:
        return FixSuggestion(
            finding_id="SUGGEST-HIGH-01",
            severity="HIGH",
            rule_id="Rule 6",
            file="programs/vault/src/lib.rs",
            line=88,
            before_code="a + b",
            after_code="a.checked_add(b)?",
            explanation="Checked math",
            references=[],
            confidence_score=0.80,
            fix_tier="B",
            fix_type="arithmetic_safety",
            estimated_effort_minutes=2,
            poker_risk="LOW",
        )

    def test_contains_before_code(self, suggestion: FixSuggestion) -> None:
        msg = format_tier_b_prompt(suggestion)
        assert "BEFORE" in msg or "a + b" in msg

    def test_contains_apply_edit_reject(self, suggestion: FixSuggestion) -> None:
        msg = format_tier_b_prompt(suggestion)
        assert "[APPLY]" in msg
        assert "[EDIT]" in msg
        assert "[REJECT]" in msg

    def test_contains_confidence_and_cvss(self, suggestion: FixSuggestion) -> None:
        msg = format_tier_b_prompt(suggestion)
        assert "80%" in msg or "0.80" in msg


# ---------------------------------------------------------------------------
# format_tier_c_guidance
# ---------------------------------------------------------------------------

class TestFormatTierC:
    @pytest.fixture
    def suggestion(self) -> FixSuggestion:
        return FixSuggestion(
            finding_id="SUGGEST-ARCH-01",
            severity="HIGH",
            rule_id="Rule 16",
            file="programs/vault/src/lib.rs",
            line=200,
            before_code="old",
            after_code="new",
            explanation="Architectural refactor needed for discriminator collision",
            references=[],
            confidence_score=0.40,
            fix_tier="C",
            fix_type="architectural_refactor",
            poker_risk="HIGH",
            estimated_effort_minutes=60,
        )

    def test_contains_tier_label(self, suggestion: FixSuggestion) -> None:
        msg = format_tier_c_guidance(suggestion)
        assert "Tier C" in msg

    def test_contains_manual_fix_label(self, suggestion: FixSuggestion) -> None:
        msg = format_tier_c_guidance(suggestion)
        assert "Manual" in msg

    def test_contains_remediation_reference(self, suggestion: FixSuggestion) -> None:
        msg = format_tier_c_guidance(suggestion)
        assert "06-remediation" in msg

    def test_contains_cvss_estimate(self, suggestion: FixSuggestion) -> None:
        msg = format_tier_c_guidance(suggestion)
        assert "CVSS" in msg
