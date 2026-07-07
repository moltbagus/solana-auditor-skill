"""Tests for sarif_core.py — shared SARIF 2.1.0 generation module."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from sarif_core import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    SARIF_VERSION,
    SARIF_SCHEMA,
    build_location,
    build_sarif_log,
    build_sarif_results,
    build_sarif_rules,
    findings_to_sarif,
    load_findings,
    severity_to_level,
)

# ---------------------------------------------------------------------------
# Sample finding helpers
# ---------------------------------------------------------------------------


def _finding(
    finding_id: str = "VULN-01",
    severity: str = "CRITICAL",
    file: str = "programs/vault/src/lib.rs",
    line: int = 42,
    cwe: str = "CWE-306",
    rule_caught: str = "Rule 8 — Signer Verification",
) -> dict:
    return {
        "id": finding_id,
        "severity": severity,
        "title": f"Finding {finding_id}",
        "description": f"Description for {finding_id}",
        "impact": f"Impact of {finding_id}",
        "recommendation": f"Recommendation for {finding_id}",
        "cwe": cwe,
        "rule_caught": rule_caught,
        "cvss": 9.8,
        "location": {"file": file, "line": line, "function": "admin_withdraw"},
        "status": "Open",
        "poc_status": "pending",
    }


# ---------------------------------------------------------------------------
# severity_to_level
# ---------------------------------------------------------------------------


class TestSeverityToLevel:
    def test_critical(self) -> None:
        assert severity_to_level("CRITICAL") == "error"

    def test_high(self) -> None:
        assert severity_to_level("HIGH") == "error"

    def test_medium(self) -> None:
        assert severity_to_level("MEDIUM") == "warning"

    def test_low(self) -> None:
        assert severity_to_level("LOW") == "note"

    def test_info(self) -> None:
        assert severity_to_level("INFO") == "note"

    def test_case_insensitive(self) -> None:
        assert severity_to_level("critical") == "error"

    def test_unknown_severity(self) -> None:
        assert severity_to_level("UNKNOWN") == "warning"

    def test_empty_string(self) -> None:
        assert severity_to_level("") == "warning"


# ---------------------------------------------------------------------------
# build_location
# ---------------------------------------------------------------------------


class TestBuildLocation:
    def test_basic_location(self) -> None:
        finding = _finding()
        loc = build_location(finding)
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "programs/vault/src/lib.rs"
        assert loc["physicalLocation"]["region"]["startLine"] == 42

    def test_no_location(self) -> None:
        loc = build_location({})
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "unknown"
        assert "region" not in loc["physicalLocation"]

    def test_location_without_line(self) -> None:
        finding = _finding(line=None)
        loc = build_location(finding)
        assert "region" not in loc["physicalLocation"]

    def test_location_with_endline(self) -> None:
        finding = _finding()
        finding["location"]["endLine"] = 50
        loc = build_location(finding)
        assert loc["physicalLocation"]["region"]["endLine"] == 50

    def test_location_with_snippet(self) -> None:
        finding = _finding()
        finding["location"]["snippet"] = "pub fn test()"
        loc = build_location(finding)
        assert loc["physicalLocation"]["region"]["snippet"]["text"] == "pub fn test()"


# ---------------------------------------------------------------------------
# build_sarif_results
# ---------------------------------------------------------------------------


class TestBuildSarifResults:
    def test_single_finding(self) -> None:
        results = build_sarif_results([_finding()])
        assert len(results) == 1
        assert results[0]["ruleId"] == "SHIBA-VULN-01"
        assert results[0]["level"] == "error"

    def test_multiple_findings(self) -> None:
        results = build_sarif_results([_finding("VULN-01"), _finding("VULN-02", "MEDIUM")])
        assert len(results) == 2
        assert results[0]["ruleId"] == "SHIBA-VULN-01"
        assert results[1]["ruleId"] == "SHIBA-VULN-02"

    def test_properties_included(self) -> None:
        results = build_sarif_results([_finding()])
        props = results[0]["properties"]
        assert props["severity"] == "CRITICAL"
        assert props["cvss"] == 9.8
        assert props["cwe"] == "CWE-306"
        assert props["status"] == "Open"
        assert props["poc_status"] == "pending"

    def test_level_mapping(self) -> None:
        for sev, expected in [("CRITICAL", "error"), ("MEDIUM", "warning"), ("INFO", "note")]:
            results = build_sarif_results([_finding(severity=sev)])
            assert results[0]["level"] == expected, f"{sev} -> {expected}"

    def test_message_uses_description(self) -> None:
        results = build_sarif_results([_finding()])
        assert "Description for VULN-01" in results[0]["message"]["text"]

    def test_custom_rule_id_prefix(self) -> None:
        results = build_sarif_results([_finding()], rule_id_prefix="")
        assert results[0]["ruleId"] == "VULN-01"

    def test_finding_without_location(self) -> None:
        f = _finding()
        f["location"] = {}
        results = build_sarif_results([f])
        # Location with uri="unknown" should still be present for SARIF validity
        locs = results[0].get("locations", [])
        assert len(locs) == 1
        assert locs[0]["physicalLocation"]["artifactLocation"]["uri"] == "unknown"


# ---------------------------------------------------------------------------
# build_sarif_rules
# ---------------------------------------------------------------------------


class TestBuildSarifRules:
    def test_dedup_by_id(self) -> None:
        rules = build_sarif_rules([_finding("VULN-01"), _finding("VULN-01")])
        assert len(rules) == 1

    def test_multiple_rules(self) -> None:
        rules = build_sarif_rules([_finding("VULN-01"), _finding("VULN-02")])
        assert len(rules) == 2

    def test_rule_tags(self) -> None:
        rules = build_sarif_rules([_finding()])
        tags = rules[0]["properties"]["tags"]
        assert "security" in tags
        assert "solana" in tags
        assert "critical" in tags
        assert "cwe-306" in tags

    def test_rule_security_severity(self) -> None:
        rules = build_sarif_rules([_finding()])
        assert rules[0]["properties"]["security-severity"] == "9.8"

    def test_rule_default_configuration(self) -> None:
        rules = build_sarif_rules([_finding(severity="MEDIUM")])
        assert rules[0]["defaultConfiguration"]["level"] == "warning"

    def test_rule_name_format(self) -> None:
        rules = build_sarif_rules([_finding()])
        assert rules[0]["name"] == "Finding-VULN-01"

    def test_rule_full_description(self) -> None:
        rules = build_sarif_rules([_finding()])
        assert "Description for VULN-01" in rules[0]["fullDescription"]["text"]
        assert "Impact of VULN-01" in rules[0]["fullDescription"]["text"]


# ---------------------------------------------------------------------------
# build_sarif_log
# ---------------------------------------------------------------------------


class TestBuildSarifLog:
    def test_structure(self) -> None:
        sarif = build_sarif_log([_finding()])
        assert sarif["version"] == SARIF_VERSION
        assert sarif["$schema"] == SARIF_SCHEMA
        assert len(sarif["runs"]) == 1

    def test_tool_driver(self) -> None:
        sarif = build_sarif_log([_finding()])
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == TOOL_NAME
        assert driver["version"] == TOOL_VERSION

    def test_contains_rules_and_results(self) -> None:
        sarif = build_sarif_log([_finding("VULN-01"), _finding("VULN-02")])
        run = sarif["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) == 2
        assert len(run["results"]) == 2

    def test_empty_findings(self) -> None:
        sarif = build_sarif_log([])
        assert len(sarif["runs"][0]["results"]) == 0

    def test_column_kind(self) -> None:
        sarif = build_sarif_log([_finding()])
        assert sarif["runs"][0]["columnKind"] == "utf16CodeUnits"

    def test_custom_organization(self) -> None:
        sarif = build_sarif_log([_finding()], organization="Test Org")
        assert sarif["runs"][0]["tool"]["driver"]["organization"] == "Test Org"


# ---------------------------------------------------------------------------
# findings_to_sarif (backward compat entry point)
# ---------------------------------------------------------------------------


class TestFindingsToSarif:
    def test_returns_dict(self) -> None:
        result = findings_to_sarif([_finding()])
        assert isinstance(result, dict)

    def test_serializable(self) -> None:
        result = findings_to_sarif([_finding()])
        dumped = json.dumps(result)
        assert isinstance(dumped, str)


# ---------------------------------------------------------------------------
# load_findings
# ---------------------------------------------------------------------------


class TestLoadFindings:
    def test_list_format(self, tmp_path: Path) -> None:
        p = tmp_path / "list.json"
        p.write_text('[{"id": "VULN-01"}]')
        assert load_findings(p) == [{"id": "VULN-01"}]

    def test_dict_format(self, tmp_path: Path) -> None:
        p = tmp_path / "dict.json"
        p.write_text('{"findings": [{"id": "VULN-01"}]}')
        assert load_findings(p) == [{"id": "VULN-01"}]

    def test_missing_file(self, tmp_path: Path) -> None:
        assert load_findings(tmp_path / "nonexistent.json") == []

    def test_invalid_json(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("not json")
        assert load_findings(p) == []

    def test_empty_findings_key(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.json"
        p.write_text('{"findings": []}')
        assert load_findings(p) == []

    def test_unknown_format(self, tmp_path: Path) -> None:
        p = tmp_path / "str.json"
        p.write_text('"string"')
        assert load_findings(p) == []


# ---------------------------------------------------------------------------
# Integration: Real vault fixture
# ---------------------------------------------------------------------------


class TestSarifIntegration:
    @pytest.fixture
    def vault_fixture_path(self) -> Path:
        return (
            Path(__file__).resolve().parent.parent
            / "examples"
            / "sample-vulnerable-program"
            / "audit-output"
            / "findings.json"
        )

    def test_vault_fixture_produces_valid_sarif(self, vault_fixture_path: Path) -> None:
        if not vault_fixture_path.exists():
            pytest.skip("Vault fixture not available")
        findings = load_findings(vault_fixture_path)
        assert len(findings) > 0
        sarif = findings_to_sarif(findings)
        json.dumps(sarif)  # must be serializable
        assert len(sarif["runs"][0]["results"]) == len(findings)

    def test_vault_fixture_rules_deduped(self, vault_fixture_path: Path) -> None:
        if not vault_fixture_path.exists():
            pytest.skip("Vault fixture not available")
        findings = load_findings(vault_fixture_path)
        sarif = findings_to_sarif(findings)
        rule_count = len(sarif["runs"][0]["tool"]["driver"]["rules"])
        finding_count = len(findings)
        assert rule_count == finding_count  # all unique IDs

    def test_vault_fixture_all_severities_mapped(self, vault_fixture_path: Path) -> None:
        if not vault_fixture_path.exists():
            pytest.skip("Vault fixture not available")
        findings = load_findings(vault_fixture_path)
        sarif = findings_to_sarif(findings)
        valid_levels = {"error", "warning", "note"}
        for result in sarif["runs"][0]["results"]:
            assert result["level"] in valid_levels
