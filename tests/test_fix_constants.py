"""Tests for fix_constants.py — rule metadata tables.

Verifies that all 26 rules have complete, well-typed entries across
every metadata table.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from fix_constants import (  # noqa: E402
    FIX_TYPES,
    RULES_COUNT,
    RULE_BASE_RATES,
    RULE_CWE_REFS,
    RULE_DOC_REFS,
    RULE_EFFORT_MINUTES,
    RULE_EXPLOIT_CLASS,
    RULE_NAMES,
    RULE_POKER_RISK,
    SCRIPT_VERSION,
    TIER_A_THRESHOLD,
    TIER_B_THRESHOLD,
    TIER_C_THRESHOLD,
)

_ALL_RULES = {f"Rule {i}" for i in range(1, 27)}


# ---------------------------------------------------------------------------
# Version & Count
# ---------------------------------------------------------------------------

class TestVersion:
    def test_script_version_format(self) -> None:
        assert isinstance(SCRIPT_VERSION, str)
        parts = SCRIPT_VERSION.split(".")
        assert len(parts) == 3
        for p in parts:
            assert p.isdigit(), f"Version part {p!r} is not numeric"

    def test_rules_count_matches_actual(self) -> None:
        assert RULES_COUNT == 26
        assert len(RULE_NAMES) == RULES_COUNT


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

class TestThresholds:
    def test_tiers_are_ordered(self) -> None:
        assert 0.0 <= TIER_C_THRESHOLD < TIER_B_THRESHOLD < TIER_A_THRESHOLD <= 1.0

    def test_tier_a_threshold(self) -> None:
        assert TIER_A_THRESHOLD == 0.90

    def test_tier_b_threshold(self) -> None:
        assert TIER_B_THRESHOLD == 0.60

    def test_tier_c_threshold(self) -> None:
        assert TIER_C_THRESHOLD == 0.00


# ---------------------------------------------------------------------------
# RULE_NAMES — every rule has a name
# ---------------------------------------------------------------------------

class TestRuleNames:
    def test_all_rules_have_names(self) -> None:
        missing = _ALL_RULES - set(RULE_NAMES.keys())
        assert not missing, f"Rules missing names: {sorted(missing)}"

    def test_no_extra_names(self) -> None:
        extra = set(RULE_NAMES.keys()) - _ALL_RULES
        assert not extra, f"Extra rules in names: {sorted(extra)}"

    @pytest.mark.parametrize("rule_id", sorted(_ALL_RULES))
    def test_rule_name_format(self, rule_id: str) -> None:
        name = RULE_NAMES[rule_id]
        assert isinstance(name, str) and len(name) > 5
        assert name[0].isalpha(), f"{rule_id}: first char '{name[0]}' is not a letter"

    def test_all_names_unique(self) -> None:
        assert len(set(RULE_NAMES.values())) == len(RULE_NAMES)


# ---------------------------------------------------------------------------
# RULE_BASE_RATES — every rule has a rate in [0, 1]
# ---------------------------------------------------------------------------

class TestRuleBaseRates:
    def test_all_rules_have_rates(self) -> None:
        missing = _ALL_RULES - set(RULE_BASE_RATES.keys())
        assert not missing, f"Rules missing rates: {sorted(missing)}"

    @pytest.mark.parametrize("rule_id", sorted(_ALL_RULES))
    def test_rate_in_range(self, rule_id: str) -> None:
        rate = RULE_BASE_RATES[rule_id]
        assert 0.0 <= rate <= 1.0, f"{rule_id}: rate {rate} out of [0, 1]"

    def test_minimum_rate_floor(self) -> None:
        """Lowest rule base rate should be at least 0.60."""
        assert min(RULE_BASE_RATES.values()) >= 0.60

    def test_critical_rules_have_high_base_rate(self) -> None:
        """Rule 6, 8, 18 — highest confidence, should be >= 0.95."""
        for rid in ("Rule 6", "Rule 8", "Rule 18"):
            assert RULE_BASE_RATES[rid] >= 0.95, f"{rid} base rate too low"


# ---------------------------------------------------------------------------
# FIX_TYPES — optional, but entries must be valid
# ---------------------------------------------------------------------------

class TestFixTypes:
    def test_known_fix_types(self) -> None:
        valid_types = {"constraint_addition", "pda_canonicalization",
                       "arithmetic_safety", "architectural_refactor",
                       "validation_check", "state_guard"}
        for rid, ftype in FIX_TYPES.items():
            assert ftype in valid_types, f"{rid}: unknown fix type {ftype!r}"


# ---------------------------------------------------------------------------
# RULE_POKER_RISK
# ---------------------------------------------------------------------------

class TestPokerRisk:
    def test_all_rules_have_risk(self) -> None:
        missing = _ALL_RULES - set(RULE_POKER_RISK.keys())
        # Rule 1 (entry point) does not have an explicit poker risk
        expected_missing = {"Rule 1"}
        actual_missing = missing - expected_missing
        assert not actual_missing, f"Rules missing poker risk: {sorted(actual_missing)}"

    @pytest.mark.parametrize("rule_id", sorted(RULE_POKER_RISK.keys()))
    def test_risk_in_valid_set(self, rule_id: str) -> None:
        risk = RULE_POKER_RISK[rule_id]
        assert risk in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


# ---------------------------------------------------------------------------
# RULE_EFFORT_MINUTES
# ---------------------------------------------------------------------------

class TestEffort:
    def test_all_rules_have_effort(self) -> None:
        missing = _ALL_RULES - set(RULE_EFFORT_MINUTES.keys())
        expected_missing = {"Rule 1"}
        actual_missing = missing - expected_missing
        assert not actual_missing, f"Rules missing effort: {sorted(actual_missing)}"

    @pytest.mark.parametrize("rule_id", sorted(RULE_EFFORT_MINUTES.keys()))
    def test_effort_positive(self, rule_id: str) -> None:
        assert RULE_EFFORT_MINUTES[rule_id] > 0

    def test_max_effort(self) -> None:
        """Rule 16 (discriminator) and Rule 26 (flash loan) require most effort."""
        assert RULE_EFFORT_MINUTES["Rule 16"] == 60
        assert RULE_EFFORT_MINUTES["Rule 26"] == 60


# ---------------------------------------------------------------------------
# RULE_CWE_REFS — optional, but entries must be valid URLs
# ---------------------------------------------------------------------------

class TestCweRefs:
    def test_cwe_urls_have_expected_format(self) -> None:
        for rid, refs in RULE_CWE_REFS.items():
            for ref in refs:
                assert "cwe.mitre.org" in ref, f"{rid}: CWE ref not mitre: {ref}"

    def test_critical_rules_have_cwe_refs(self) -> None:
        """Rules 6, 8, 14, 15, 18 should all have CWE references."""
        for rid in ("Rule 6", "Rule 8", "Rule 14", "Rule 15", "Rule 18"):
            assert rid in RULE_CWE_REFS, f"{rid} missing CWE references"


# ---------------------------------------------------------------------------
# RULE_DOC_REFS — optional, but entries must be valid
# ---------------------------------------------------------------------------

class TestDocRefs:
    def test_doc_urls_have_valid_scheme(self) -> None:
        for rid, refs in RULE_DOC_REFS.items():
            for ref in refs:
                assert ref.startswith("http"), f"{rid}: doc ref not http: {ref}"


# ---------------------------------------------------------------------------
# RULE_EXPLOIT_CLASS
# ---------------------------------------------------------------------------

class TestExploitClass:
    def test_all_rules_have_exploit_class(self) -> None:
        missing = _ALL_RULES - set(RULE_EXPLOIT_CLASS.keys())
        assert not missing, f"Rules missing exploit class: {sorted(missing)}"

    @pytest.mark.parametrize("rule_id", sorted(_ALL_RULES))
    def test_exploit_class_valid(self, rule_id: str) -> None:
        cls = RULE_EXPLOIT_CLASS[rule_id]
        valid = {"config", "state-manipulation", "privilege-escalation", "arith",
                 "oracle-manipulation", "reentrancy"}
        assert cls in valid, f"{rule_id}: unknown exploit class {cls!r}"
