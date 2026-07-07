#!/usr/bin/env python3
"""
sarif_core.py — Shared SARIF 2.1.0 generation for the fix suggestion engine.

Single Responsibility: Convert findings.json data into SARIF 2.1.0 format.
Reason to change: SARIF schema changes or new property fields.

Usage:
    from sarif_core import findings_to_sarif, load_findings
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "SARIF_VERSION",
    "SARIF_SCHEMA",
    "severity_to_level",
    "build_location",
    "build_sarif_results",
    "build_sarif_rules",
    "build_sarif_log",
    "findings_to_sarif",
    "load_findings",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOOL_NAME: str = "solana-auditor-skill"
TOOL_VERSION: str = "2.0.0"
SARIF_VERSION: str = "2.1.0"
SARIF_SCHEMA: str = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


def severity_to_level(severity: str) -> str:
    """Map finding severity to SARIF result level."""
    mapping: dict[str, str] = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    return mapping.get(severity.upper(), "warning")


# ---------------------------------------------------------------------------
# Location builder
# ---------------------------------------------------------------------------


def build_location(finding: dict[str, Any]) -> dict[str, Any]:
    """Build a SARIF physicalLocation block from a finding's location dict.

    Includes:
    - artifactLocation (uri + optional uriBaseId)
    - region (startLine, optional endLine, snippet)
    """
    loc = finding.get("location", {})
    file_path: str = loc.get("file", "")

    # physical location
    artifact: dict[str, Any] = {
        "uri": file_path or "unknown",
        "uriBaseId": "%SRCROOT%",
    }
    result: dict[str, Any] = {"physicalLocation": {"artifactLocation": artifact}}

    # region
    region: dict[str, Any] = {}
    if loc.get("line"):
        region["startLine"] = loc["line"]
    if loc.get("endLine"):
        region["endLine"] = loc["endLine"]
    if loc.get("snippet"):
        region["snippet"] = {"text": loc["snippet"]}
    if region:
        result["physicalLocation"]["region"] = region

    return result


# ---------------------------------------------------------------------------
# SARIF results builder
# ---------------------------------------------------------------------------


def build_sarif_results(
    findings: list[dict[str, Any]],
    rule_id_prefix: str = "SHIBA-",
) -> list[dict[str, Any]]:
    """Build SARIF results list from findings.

    Args:
        findings: List of finding dicts from findings.json
        rule_id_prefix: Prefix for rule IDs (e.g. "SHIBA-" or "")

    Returns:
        List of SARIF result objects
    """
    results: list[dict[str, Any]] = []

    for finding in findings:
        severity: str = finding.get("severity", "MEDIUM")
        title: str = finding.get("title", "Untitled")
        description: str = finding.get("description", "")
        impact: str = finding.get("impact", "")
        recommendation: str = finding.get("recommendation", "")
        finding_id: str = finding.get("id", "UNKNOWN")

        result: dict[str, Any] = {
            "ruleId": f"{rule_id_prefix}{finding_id}",
            "level": severity_to_level(severity),
            "message": {"text": description or title},
            "properties": {
                "severity": severity,
                "cvss": finding.get("cvss"),
                "cwe": finding.get("cwe"),
                "rule_caught": finding.get("rule_caught"),
                "status": finding.get("status", "Open"),
                "poc_status": finding.get("poc_status", "pending"),
                "impact": impact,
                "recommendation": recommendation,
            },
        }

        # Add location
        location = build_location(finding)
        if location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri"):
            result["locations"] = [location]

        results.append(result)

    return results


# ---------------------------------------------------------------------------
# SARIF rules builder
# ---------------------------------------------------------------------------


def build_sarif_rules(
    findings: list[dict[str, Any]],
    rule_id_prefix: str = "SHIBA-",
) -> list[dict[str, Any]]:
    """Build SARIF tool driver rules from findings.

    Args:
        findings: List of finding dicts
        rule_id_prefix: Prefix for rule IDs

    Returns:
        List of SARIF rule objects
    """
    rules: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for finding in findings:
        finding_id: str = finding.get("id", "")
        if not finding_id or finding_id in seen_ids:
            continue
        seen_ids.add(finding_id)

        severity: str = finding.get("severity", "MEDIUM")
        title: str = finding.get("title", "Untitled")
        description: str = finding.get("description", "")
        impact: str = finding.get("impact", "")
        recommendation: str = finding.get("recommendation", "")

        # Full description = description + impact + recommendation
        full_desc_parts: list[str] = [description, impact, recommendation]
        full_desc: str = "\n\n".join(p for p in full_desc_parts if p)

        tags: list[str] = [
            "security",
            "solana",
            severity.lower(),
        ]
        cwe: str = finding.get("cwe", "")
        if cwe:
            tags.append(cwe.lower())
        rule_caught: str = finding.get("rule_caught", "")
        if rule_caught:
            tags.append(rule_caught.lower().replace(" ", "-"))

        rule: dict[str, Any] = {
            "id": f"{rule_id_prefix}{finding_id}",
            "name": title.replace(" ", "-"),
            "shortDescription": {"text": title},
            "fullDescription": {"text": full_desc or title},
            "defaultConfiguration": {"level": severity_to_level(severity)},
            "properties": {
                "tags": tags,
                "precision": "high",
                "security-severity": str(finding.get("cvss", "0.0")),
            },
        }
        rules.append(rule)

    return rules


# ---------------------------------------------------------------------------
# Full SARIF log builder
# ---------------------------------------------------------------------------


def build_sarif_log(
    findings: list[dict[str, Any]],
    rule_id_prefix: str = "SHIBA-",
    organization: str = "Solana Auditor Shiba",
    information_uri: str = "https://github.com/moltbagus/solana-auditor-skill",
) -> dict[str, Any]:
    """Build a complete SARIF 2.1.0 log document from findings.

    Merges the best features of both original exporters:
    - Rich tag arrays from findings-to-sarif.py
    - SHIBA- prefix from findings-to-sarif.py
    - Proper region/line handling from export-sarif.py
    - Full properties (impact, recommendation, poc_status) from findings-to-sarif.py

    Args:
        findings: List of finding dicts
        rule_id_prefix: Prefix for rule IDs (default "SHIBA-")
        organization: Tool organization name
        information_uri: Tool information URI

    Returns:
        Complete SARIF 2.1.0 document as a dict
    """
    rules: list[dict[str, Any]] = build_sarif_rules(findings, rule_id_prefix)
    results: list[dict[str, Any]] = build_sarif_results(findings, rule_id_prefix)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": information_uri,
                "organization": organization,
                "rules": rules,
            }
        },
        "results": results,
        "columnKind": "utf16CodeUnits",
    }

    sarif: dict[str, Any] = {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [run],
    }

    return sarif


# ---------------------------------------------------------------------------
# Compatibility: Single-call function matching findings-to-sarif.py generate_sarif_log
# ---------------------------------------------------------------------------


def findings_to_sarif(
    findings: list[dict[str, Any]],
    rule_id_prefix: str = "SHIBA-",
) -> dict[str, Any]:
    """Convert findings list to SARIF 2.1.0 format.

    Simple entry point for backward compatibility.
    Delegates to build_sarif_log.
    """
    return build_sarif_log(findings, rule_id_prefix)


# ---------------------------------------------------------------------------
# File I/O helpers
# ---------------------------------------------------------------------------


def load_findings(input_path: Path) -> list[dict[str, Any]]:
    """Load and normalize findings from a JSON file.

    Supports both list-of-findings and {'findings': [...]} formats.
    Returns empty list on parse failure.
    """
    try:
        with open(input_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, FileNotFoundError):
        return []

    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("findings", [])
    return []
