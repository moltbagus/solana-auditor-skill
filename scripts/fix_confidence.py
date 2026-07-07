#!/usr/bin/env python3
"""
fix_confidence.py — Confidence scoring, tier determination, and CVSS estimation.

Single Responsibility: Compute confidence scores, fix tiers, CVSS post-fix estimates,
and format tier-specific notifications. Reason to change: Scoring model changes.

Usage:
    from fix_confidence import compute_confidence, determine_tier, format_tier_b_prompt
"""

from fix_constants import (
    FIX_TYPES,
    RULE_BASE_RATES,
    RULE_EFFORT_MINUTES,
    RULE_POKER_RISK,
    TIER_A_THRESHOLD,
    TIER_B_THRESHOLD,
)
from fix_models import FixSuggestion


def compute_confidence(rule_id: str, pattern_match: bool = True) -> float:
    """
    Compute confidence score using prediction-market model.

    Args:
        rule_id: Rule identifier (e.g., "Rule 8")
        pattern_match: Whether the finding exactly matches a known fix pattern

    Returns:
        Confidence score between 0.0 and 1.0
    """
    base_rate = RULE_BASE_RATES.get(rule_id, 0.70)
    pattern_bonus = 1.0 if pattern_match else 0.85
    return round(base_rate * pattern_bonus, 2)


def determine_tier(confidence: float, poker_risk: str) -> str:
    """
    Determine fix tier based on confidence and poker risk.

    Args:
        confidence: Confidence score
        poker_risk: Risk of the fix introducing new bugs

    Returns:
        Tier string (A, B, or C)
    """
    if poker_risk in ("HIGH", "CRITICAL"):
        return "C"
    if confidence >= TIER_A_THRESHOLD:
        return "A"
    if confidence >= TIER_B_THRESHOLD:
        return "B"
    return "C"


def estimate_cvss_after(cvss_before: float, rule_id: str) -> tuple[float, str]:
    """
    Estimate post-fix CVSS score based on rule type.

    Args:
        cvss_before: Pre-fix CVSS score
        rule_id: Rule identifier

    Returns:
        Tuple of (estimated_cvss_after, estimated_vector)
    """
    full_fix_rules = {"Rule 8", "Rule 18", "Rule 6"}
    partial_fix_rules = {"Rule 3", "Rule 7", "Rule 14", "Rule 15"}
    architectural_rules = {"Rule 26", "Rule 13", "Rule 9"}

    if rule_id in full_fix_rules:
        reduction = cvss_before * 0.25
    elif rule_id in partial_fix_rules:
        reduction = cvss_before * 0.15
    elif rule_id in architectural_rules:
        reduction = cvss_before * 0.10
    else:
        reduction = cvss_before * 0.20

    cvss_after = max(1.0, round(cvss_before - reduction, 1))
    if rule_id == "Rule 8":
        vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    else:
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    return cvss_after, vector


def get_fix_type(rule_id: str) -> str:
    """Get fix type for a rule."""
    return FIX_TYPES.get(rule_id, "validation_check")


def get_poker_risk(rule_id: str) -> str:
    """Get poker risk for a rule."""
    return RULE_POKER_RISK.get(rule_id, "MEDIUM")


def get_effort_minutes(rule_id: str) -> int:
    """Get estimated effort in minutes for a rule."""
    return RULE_EFFORT_MINUTES.get(rule_id, 10)


def generate_test_template(rule_id: str, finding_id: str) -> str:
    """Generate a verification test template for a rule."""
    templates: dict[str, str] = {
        "Rule 8": (
            f"#[test]\n"
            f"fn test_{finding_id.lower()}_requires_signer() {{\n"
            f"    // Attempt privileged action without admin signer should fail\n"
            f"    // Attempt with admin signer should succeed\n"
            f"}}"
        ),
        "Rule 6": (
            f"#[test]\n"
            f"fn test_{finding_id.lower()}_overflow_protection() {{\n"
            f"    // Overflow amounts should return ArithmeticOverflow error\n"
            f"}}"
        ),
        "Rule 14": (
            f"#[test]\n"
            f"fn test_{finding_id.lower()}_reentrancy_guard() {{\n"
            f"    // Reentrant callback should fail with ReentrancyDetected\n"
            f"}}"
        ),
        "Rule 15": (
            f"#[test]\n"
            f"fn test_{finding_id.lower()}_remaining_accounts_validation() {{\n"
            f"    // Invalid remaining accounts should fail validation\n"
            f"}}"
        ),
    }
    return templates.get(
        rule_id,
        (
            f"#[test]\n"
            f"fn test_{finding_id.lower()}_fix_verification() {{\n"
            f"    // Verify the fix for Rule {rule_id}\n"
            f"    // Add specific assertions based on the vulnerability\n"
            f"}}"
        ),
    )


def format_tier_a_notification(suggestion: FixSuggestion) -> str:
    """Format Tier A auto-fix notification."""
    return (
        f"\n[Tier A Auto-Fix] Applied {suggestion.finding_id} fix to {suggestion.file}\n"
        f"  Added fix for Rule {suggestion.rule_id}\n"
        f"  Confidence: {suggestion.confidence_score:.0%} | "
        f"CVSS reduction: {suggestion.cvss_before} -> {suggestion.cvss_after}\n"
    )


def format_tier_b_prompt(suggestion: FixSuggestion) -> str:
    """Format Tier B confirmation prompt."""
    before_lines = suggestion.before_code.strip().split("\n")[:5]
    after_lines = suggestion.after_code.strip().split("\n")[:5]

    output = [
        f"\n[Tier B Assisted Fix] Fix suggestion for {suggestion.finding_id}",
        "",
        "  BEFORE:",
    ]
    for line in before_lines:
        output.append(f"    {line}")
    output.append("")
    output.append("  AFTER:")
    for line in after_lines:
        output.append(f"    {line}")
    output.append("")
    output.append(
        f"  Confidence: {suggestion.confidence_score:.0%} | "
        f"CVSS reduction: {suggestion.cvss_before} -> {suggestion.cvss_after}"
    )
    output.append(
        f"  Estimated effort: {suggestion.estimated_effort_minutes} min | "
        f"Poker risk: {suggestion.poker_risk}"
    )
    output.append("")
    output.append("  [APPLY] [EDIT] [REJECT]")

    return "\n".join(output)


def format_tier_c_guidance(suggestion: FixSuggestion) -> str:
    """Format Tier C manual guidance."""
    return (
        f"\n[Tier C Manual Fix] {suggestion.finding_id} requires architectural review\n"
        f"\n"
        f"  Root cause: {suggestion.explanation[:100]}...\n"
        f"\n"
        f"  This finding requires manual remediation due to:\n"
        f"  - Low confidence score: {suggestion.confidence_score:.0%}\n"
        f"  - Poker risk: {suggestion.poker_risk}\n"
        f"\n"
        f"  Recommended approach:\n"
        f"    1. Review skill/06-remediation.md, Rule {suggestion.rule_id}\n"
        f"    2. Design fix with architecture review\n"
        f"    3. Implement with full test coverage\n"
        f"    4. Verify with formal methods if available\n"
        f"\n"
        f"  CVSS reduction after fix: {suggestion.cvss_before} -> {suggestion.cvss_after} "
        f"(estimated)\n"
        f"  Estimated effort: {suggestion.estimated_effort_minutes} min\n"
        f"\n"
        f"  Reference: skill/06-remediation.md\n"
    )
