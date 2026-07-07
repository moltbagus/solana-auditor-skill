"""Tests for fix_regression.py — regression test generation.

Verifies that VULN-specific generators produce correct Rust test code
and that the fallback generic generator works for unknown findings.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from fix_models import FixSuggestion  # noqa: E402
from fix_regression import (  # noqa: E402
    generate_regression_test,
    write_regression_tests,
)

# ---------------------------------------------------------------------------
# Helper to build a FixSuggestion for testing
# ---------------------------------------------------------------------------


def _make_suggestion(
    finding_id: str = "VULN-01",
    rule_id: str = "Rule 8",
    fix_tier: str = "A",
) -> FixSuggestion:
    return FixSuggestion(
        finding_id=f"SUGGEST-{finding_id}",
        severity="CRITICAL" if "01" in finding_id else "HIGH",
        rule_id=rule_id,
        file="programs/vault/src/lib.rs",
        line=42,
        before_code="// old code",
        after_code="// new code",
        explanation="Test fix",
        references=[],
        fix_tier=fix_tier,
    )


def _make_finding(finding_id: str, severity: str = "CRITICAL") -> dict:
    return {
        "id": finding_id,
        "severity": severity,
        "rule_caught": "Rule 8 — Signer Verification",
        "title": f"Test finding {finding_id}",
        "description": f"A test finding for {finding_id}",
        "location": {"file": "programs/vault/src/lib.rs", "line": 42, "function": "test_fn"},
    }


# ---------------------------------------------------------------------------
# VULN-specific generators
# ---------------------------------------------------------------------------

class TestKnownVulnGenerators:
    @pytest.mark.parametrize("vuln_id", [
        "VULN-01", "VULN-02", "VULN-03", "VULN-04", "VULN-05", "VULN-06",
        "VULN-07", "VULN-09",
    ])
    def test_known_vuln_produces_code(self, vuln_id: str) -> None:
        """Each known VULN pattern should produce usable Rust test code."""
        finding = _make_finding(vuln_id)
        suggestion = _make_suggestion(vuln_id)
        code = generate_regression_test(finding, suggestion)
        assert code, f"{vuln_id}: generated empty code"
        assert "fn test_" in code or "// REGRESSION TEST" in code

    def test_vuln_01_has_admin_withdraw(self) -> None:
        """VULN-01 is missing signer check on admin_withdraw."""
        code = generate_regression_test(
            _make_finding("VULN-01"),
            _make_suggestion("VULN-01"),
        )
        assert "admin_withdraw" in code

    def test_vuln_05_has_overflow_check(self) -> None:
        """VULN-05 is arithmetic overflow."""
        code = generate_regression_test(
            _make_finding("VULN-05", "HIGH"),
            _make_suggestion("VULN-05", "Rule 6"),
        )
        assert "overflow" in code.lower()

    def test_vuln_04_has_drain_vault(self) -> None:
        """VULN-04 is lamport drain."""
        code = generate_regression_test(
            _make_finding("VULN-04"),
            _make_suggestion("VULN-04", "Rule 7"),
        )
        assert "drain_vault" in code

    def test_vuln_06_has_reinit_blocked(self) -> None:
        """VULN-06 is reinit attack."""
        code = generate_regression_test(
            _make_finding("VULN-06", "HIGH"),
            _make_suggestion("VULN-06", "Rule 11"),
        )
        assert "reinit" in code.lower()

    def test_vuln_09_has_cpi_error(self) -> None:
        """VULN-09 is CPI return value discarded."""
        code = generate_regression_test(
            _make_finding("VULN-09", "HIGH"),
            _make_suggestion("VULN-09", "Rule 4"),
        )
        assert "cpi" in code.lower()


# ---------------------------------------------------------------------------
# Generic / fallback generator
# ---------------------------------------------------------------------------

class TestGenericGenerator:
    def test_unknown_vuln_returns_generic(self) -> None:
        """Unmapped VULN IDs should get the generic fallback."""
        finding = _make_finding("VULN-99")
        suggestion = _make_suggestion("VULN-99", "Rule 0")
        code = generate_regression_test(finding, suggestion)
        assert "TODO" in code or "Generic" in code

    def test_generic_contains_rule_id(self) -> None:
        finding = _make_finding("VULN-XX")
        suggestion = _make_suggestion("VULN-XX", "Rule 5")
        code = generate_regression_test(finding, suggestion)
        assert "Rule 5" in code

    def test_generic_contains_finding_id(self) -> None:
        finding = _make_finding("CUSTOM-01")
        suggestion = _make_suggestion("CUSTOM-01", "Rule 8")
        code = generate_regression_test(finding, suggestion)
        assert "CUSTOM-01" in code

    def test_generic_complies_with_anchor_test_format(self) -> None:
        """Should use tokio::test and valid Rust syntax."""
        finding = _make_finding("GENERIC-01")
        suggestion = _make_suggestion("GENERIC-01", "Rule 8")
        code = generate_regression_test(finding, suggestion)
        assert "#[tokio::test]" in code or "#[test]" in code
        assert "async fn test_" in code


# ---------------------------------------------------------------------------
# write_regression_tests
# ---------------------------------------------------------------------------

class TestWriteRegressionTests:
    def test_writes_files(self, tmp_path: Path) -> None:
        findings = [
            _make_finding("VULN-01"),
            _make_finding("VULN-05", "HIGH"),
        ]
        suggestions = [
            _make_suggestion("VULN-01", "Rule 8"),
            _make_suggestion("VULN-05", "Rule 6"),
        ]
        written = write_regression_tests(findings, suggestions, tmp_path)
        assert len(written) >= 2  # individual + combined runner

    def test_written_files_exist(self, tmp_path: Path) -> None:
        findings = [_make_finding("VULN-01")]
        suggestions = [_make_suggestion("VULN-01", "Rule 8")]
        written = write_regression_tests(findings, suggestions, tmp_path)
        for path in written:
            assert path.exists(), f"File not written: {path}"

    def test_generates_combined_runner(self, tmp_path: Path) -> None:
        findings = [_make_finding("VULN-01")]
        suggestions = [_make_suggestion("VULN-01", "Rule 8")]
        write_regression_tests(findings, suggestions, tmp_path)
        combined = tmp_path / "test_all_regressions.rs"
        assert combined.exists()
        assert "COMBINED REGRESSION TEST RUNNER" in combined.read_text()

    def test_empty_findings_no_error(self, tmp_path: Path) -> None:
        written = write_regression_tests([], [], tmp_path)
        # Should at least write the combined runner
        assert len(written) == 1

    def test_output_includes_test_code(self, tmp_path: Path) -> None:
        findings = [_make_finding("VULN-01")]
        suggestions = [_make_suggestion("VULN-01", "Rule 8")]
        written = write_regression_tests(findings, suggestions, tmp_path)
        content = written[0].read_text()
        assert "REGRESSION TEST" in content
        assert "fn test_" in content

    def test_output_directory_created(self, tmp_path: Path) -> None:
        nested = tmp_path / "nested" / "regression"
        findings = [_make_finding("VULN-01")]
        suggestions = [_make_suggestion("VULN-01", "Rule 8")]
        write_regression_tests(findings, suggestions, nested)
        assert nested.exists()
        assert nested.is_dir()
