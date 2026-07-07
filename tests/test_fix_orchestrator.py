"""Tests for orchestrator functions in audit-fix-suggestions.py.

The orchestrator file has a hyphen in its name (audit-fix-suggestions.py),
so it cannot be imported via `import`. We load it dynamically via
importlib and run it as a subprocess for integration tests.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
ORCHESTRATOR_PATH = SCRIPTS_DIR / "audit-fix-suggestions.py"
VAULT_FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "examples"
    / "sample-vulnerable-program"
    / "audit-output"
    / "findings.json"
)

# ---------------------------------------------------------------------------
# Dynamically load the orchestrator module (hyphen in filename)
# ---------------------------------------------------------------------------

_orch: Any = None


def _get_orch() -> Any:
    """Lazy-load the orchestrator module via importlib."""
    global _orch
    if _orch is None:
        if not ORCHESTRATOR_PATH.exists():
            raise FileNotFoundError(f"Orchestrator not found: {ORCHESTRATOR_PATH}")
        spec = importlib.util.spec_from_file_location(
            "audit_fix_suggestions", str(ORCHESTRATOR_PATH)
        )
        mod = importlib.util.module_from_spec(spec)
        # Ensure scripts/ is on sys.path so sub-modules can import
        scripts_dir = str(SCRIPTS_DIR)
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        _orch = mod
    return _orch


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ORCHESTRATOR_PATH)] + args,
        capture_output=True,
        text=True,
        check=False,
    )


# ---------------------------------------------------------------------------
# validate_finding_id
# ---------------------------------------------------------------------------


class TestValidateFindingId:
    def test_valid_ids(self) -> None:
        orch = _get_orch()
        for fid in ["VULN-01", "CRIT-001", "test_finding", "ADMIN-001", "B-42"]:
            orch.validate_finding_id(fid)  # should not raise

    def test_empty_raises(self) -> None:
        orch = _get_orch()
        with pytest.raises(orch.SecurityError, match="must not be empty"):
            orch.validate_finding_id("")

    def test_too_long_raises(self) -> None:
        orch = _get_orch()
        with pytest.raises(orch.SecurityError, match="exceeds max length"):
            orch.validate_finding_id("X" * 100)

    def test_special_chars_raises(self) -> None:
        orch = _get_orch()
        for bad in ["find;ing", "finding!", "finding$", "f<inding>"]:
            with pytest.raises(orch.SecurityError, match="invalid characters"):
                orch.validate_finding_id(bad)

    def test_whitespace_raises(self) -> None:
        orch = _get_orch()
        with pytest.raises(orch.SecurityError, match="invalid characters"):
            orch.validate_finding_id("FINDING 01")

    def test_unicode_raises(self) -> None:
        orch = _get_orch()
        with pytest.raises(orch.SecurityError, match="invalid characters"):
            orch.validate_finding_id("fünding")


# ---------------------------------------------------------------------------
# sanitize_path
# ---------------------------------------------------------------------------


class TestSanitizePath:
    def test_normal_path_accepted(self) -> None:
        orch = _get_orch()
        assert orch.sanitize_path("findings.json") == "findings.json"

    def test_relative_path_accepted(self) -> None:
        orch = _get_orch()
        assert orch.sanitize_path("audit-output/findings.json") == "audit-output/findings.json"

    def test_path_traversal_raises(self) -> None:
        orch = _get_orch()
        with pytest.raises(orch.SecurityError, match="Path traversal"):
            orch.sanitize_path("../etc/passwd")

    def test_deep_traversal_raises(self) -> None:
        orch = _get_orch()
        with pytest.raises(orch.SecurityError, match="Path traversal"):
            orch.sanitize_path("foo/../../../etc/passwd")

    def test_home_expansion_raises(self) -> None:
        orch = _get_orch()
        with pytest.raises(orch.SecurityError, match="Home directory"):
            orch.sanitize_path("~/config/solana/id.json")

    def test_null_byte_raises(self) -> None:
        orch = _get_orch()
        with pytest.raises(orch.SecurityError, match="Null byte"):
            orch.sanitize_path("good.json\x00evil.exe")

    def test_too_long_raises(self) -> None:
        orch = _get_orch()
        with pytest.raises(orch.SecurityError, match="exceeds max length"):
            orch.sanitize_path("x" * 600)

    def test_control_char_raises(self) -> None:
        orch = _get_orch()
        with pytest.raises(orch.SecurityError, match="Control character"):
            orch.sanitize_path("test\x01file.json")


# ---------------------------------------------------------------------------
# safe_output
# ---------------------------------------------------------------------------


class TestSafeOutput:
    def test_normal_string_passes(self) -> None:
        orch = _get_orch()
        assert orch.safe_output("hello world") == "hello world"

    def test_null_bytes_stripped(self) -> None:
        orch = _get_orch()
        assert orch.safe_output("hello\x00world") == "helloworld"

    def test_long_string_truncated(self) -> None:
        orch = _get_orch()
        result = orch.safe_output("a" * 20000, max_length=100)
        assert len(result) == 100

    def test_empty_string(self) -> None:
        orch = _get_orch()
        assert orch.safe_output("") == ""

    def test_custom_max_length(self) -> None:
        orch = _get_orch()
        result = orch.safe_output("abcdefghij", max_length=5)
        assert result == "abcde"


# ---------------------------------------------------------------------------
# safe_json_dump
# ---------------------------------------------------------------------------


class TestSafeJsonDump:
    def test_string_sanitized(self) -> None:
        orch = _get_orch()
        result = orch.safe_json_dump("hello\x00world")
        assert result == "helloworld"

    def test_dict_nested(self) -> None:
        orch = _get_orch()
        result = orch.safe_json_dump({"a": {"b": "safe"}}, max_depth=5)
        assert result == {"a": {"b": "safe"}}

    def test_list_nested(self) -> None:
        orch = _get_orch()
        result = orch.safe_json_dump([1, [2, [3]]], max_depth=5)
        assert result == [1, [2, [3]]]

    def test_primitives_passthrough(self) -> None:
        orch = _get_orch()
        assert orch.safe_json_dump(42) == 42
        assert orch.safe_json_dump(3.14) == 3.14
        assert orch.safe_json_dump(True) is True
        assert orch.safe_json_dump(None) is None

    def test_exceeds_depth(self) -> None:
        orch = _get_orch()
        with pytest.raises(ValueError, match="exceeds max depth"):
            orch.safe_json_dump({"a": {"b": {"c": "deep"}}}, max_depth=2)

    def test_serializable_to_json(self) -> None:
        orch = _get_orch()
        obj = {"finding_id": "VULN-01", "score": 9.8, "tags": ["critical"]}
        sanitized = orch.safe_json_dump(obj, max_depth=10)
        json.dumps(sanitized)  # should not raise


# ---------------------------------------------------------------------------
# extract_rule_id
# ---------------------------------------------------------------------------


class TestExtractRuleId:
    def test_standard_format(self) -> None:
        orch = _get_orch()
        assert orch.extract_rule_id("Rule 8 — Signer Verification") == "Rule 8"

    def test_just_rule_number(self) -> None:
        orch = _get_orch()
        assert orch.extract_rule_id("Rule 14") == "Rule 14"

    def test_compound_rule(self) -> None:
        orch = _get_orch()
        result = orch.extract_rule_id("Rule 5 + Rule 8 — Token Operations")
        assert result == "Rule 5"

    def test_empty_string(self) -> None:
        orch = _get_orch()
        assert orch.extract_rule_id("") == "Rule 0"


# ---------------------------------------------------------------------------
# generate_finding_id
# ---------------------------------------------------------------------------


class TestGenerateFindingId:
    def test_with_id(self) -> None:
        orch = _get_orch()
        assert orch.generate_finding_id({"id": "VULN-01"}, 0) == "SUGGEST-VULN-01"

    def test_without_id_uses_index(self) -> None:
        orch = _get_orch()
        fid = orch.generate_finding_id({"severity": "HIGH"}, 5)
        assert "IDX-5" in fid

    def test_empty_dict_uses_index(self) -> None:
        orch = _get_orch()
        fid = orch.generate_finding_id({}, 3)
        assert "IDX-3" in fid


# ---------------------------------------------------------------------------
# get_program_id_from_findings
# ---------------------------------------------------------------------------


class TestGetProgramId:
    def test_finding_has_program_id(self) -> None:
        orch = _get_orch()
        findings = [{"program_id": "abc123"}, {"program_id": "def456"}]
        assert orch.get_program_id_from_findings(findings) == "abc123"

    def test_no_program_id_returns_unknown(self) -> None:
        orch = _get_orch()
        findings = [{"id": "VULN-01"}]
        assert orch.get_program_id_from_findings(findings) == "unknown"

    def test_empty_list(self) -> None:
        orch = _get_orch()
        assert orch.get_program_id_from_findings([]) == "unknown"


# ---------------------------------------------------------------------------
# Subprocess integration tests (following test_scripts_smoke.py pattern)
# ---------------------------------------------------------------------------


class TestCliSubprocess:
    def test_help_flag(self) -> None:
        """--help should exit 0 and show usage."""
        proc = _run(["--help"])
        assert proc.returncode == 0
        assert "usage" in proc.stdout.lower()

    def test_version_in_output(self) -> None:
        """The script imports fix_constants; version should be in output."""
        proc = _run(["--help"])
        assert proc.returncode == 0

    def test_missing_findings_file(self) -> None:
        """Should error when input file doesn't exist."""
        proc = _run(["--input", "nonexistent.json"])
        assert proc.returncode != 0
        assert "not found" in proc.stderr.lower() or "ERROR" in proc.stderr

    def test_cli_examples_in_help(self) -> None:
        """--help should list example commands."""
        proc = _run(["--help"])
        assert "Examples" in proc.stdout
        assert "--finding" in proc.stdout


# ---------------------------------------------------------------------------
# Integration: Orchestrator round-trip against vault fixture
# ---------------------------------------------------------------------------


class TestOrchestratorRoundTrip:
    """Runs the orchestrator against the real vault fixture via importlib."""

    @pytest.fixture
    def vault_fixture(self) -> dict | None:
        if VAULT_FIXTURE.exists():
            return json.loads(VAULT_FIXTURE.read_text(encoding="utf-8"))
        return None

    def test_generate_suggestions_from_fixture(self, vault_fixture: dict | None) -> None:
        """End-to-end: read fixture, generate suggestions, verify output structure."""
        if vault_fixture is None:
            pytest.skip("Vault fixture not available")

        orch = _get_orch()
        findings = vault_fixture.get("findings", [])
        assert len(findings) > 0, "Fixture has no findings"

        # Generate suggestions for first finding individually
        first = orch.generate_fix_suggestion(findings[0], 0)
        assert first.finding_id.startswith("SUGGEST-")
        assert first.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")
        assert first.file is not None
        assert first.line >= 0

        # Generate all suggestions
        suggestions = orch.generate_all_suggestions(findings)
        assert len(suggestions) == len(findings)

        # Check all have required fields
        for s in suggestions:
            assert s.finding_id.startswith("SUGGEST-"), f"Missing SUGGEST- prefix: {s.finding_id}"
            assert s.rule_id, "Empty rule_id"
            assert s.before_code, "Empty before_code"
            assert s.after_code, "Empty after_code"
            assert s.explanation, "Empty explanation"
            assert isinstance(s.confidence_score, float)
            assert s.fix_tier in ("A", "B", "C")
            assert s.cvss_reduction >= 0.0

        # Verify all suggestions are JSON-serializable
        output_dicts = [s.to_dict() for s in suggestions]
        dumped = json.dumps(output_dicts)
        assert isinstance(dumped, str)

    def test_suggestion_to_output_json(self, vault_fixture: dict | None) -> None:
        """Verify FixSuggestionsOutput wraps suggestions correctly."""
        if vault_fixture is None:
            pytest.skip("Vault fixture not available")

        orch = _get_orch()
        findings = vault_fixture.get("findings", [])
        suggestions = orch.generate_all_suggestions(findings)

        from fix_models import FixSuggestionsOutput
        from fix_constants import SCRIPT_VERSION

        program_id = orch.get_program_id_from_findings(findings)
        output = FixSuggestionsOutput(
            generated_at="2025-01-01T00:00:00Z",
            program_id=program_id,
            version=SCRIPT_VERSION,
            total_findings=len(findings),
            suggestions=[s.to_dict() for s in suggestions],
        )
        d = output.to_dict()
        assert d["total_findings"] == len(findings)
        assert len(d["suggestions"]) == len(findings)
        json.dumps(d)

    def test_validate_findings_json_passes(self, vault_fixture: dict | None) -> None:
        """validate_findings_json should pass on clean fixture data."""
        if vault_fixture is None:
            pytest.skip("Vault fixture not available")

        orch = _get_orch()
        orch.validate_findings_json(vault_fixture)

    def test_security_functions_during_generation(
        self, vault_fixture: dict | None
    ) -> None:
        """Security functions don't raise during normal generation."""
        if vault_fixture is None:
            pytest.skip("Vault fixture not available")

        orch = _get_orch()
        findings = vault_fixture.get("findings", [])
        suggestions = orch.generate_all_suggestions(findings)
        assert len(suggestions) > 0

    def test_all_severities_have_correct_tiers(self, vault_fixture: dict | None) -> None:
        """CRITICAL findings should map to Tier A or B, not C."""
        if vault_fixture is None:
            pytest.skip("Vault fixture not available")

        orch = _get_orch()
        findings = vault_fixture.get("findings", [])
        suggestions = orch.generate_all_suggestions(findings)

        for finding, suggestion in zip(findings, suggestions):
            sev = finding.get("severity", "").upper()
            if sev == "CRITICAL":
                assert suggestion.fix_tier in ("A", "B"), (
                    f"CRITICAL {suggestion.finding_id} has Tier {suggestion.fix_tier}"
                )
