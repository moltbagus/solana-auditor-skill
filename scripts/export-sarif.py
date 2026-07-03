#!/usr/bin/env python3
"""SARIF 2.1.0 exporter for solana-auditor-skill findings.

Reads findings.json and emits SARIF format suitable for GitHub Code Scanning.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Union

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME = "solana-auditor-skill"
TOOL_VERSION = "1.3.0"
DEFAULT_FINDINGS_PATH = "examples/sample-vulnerable-program/audit-output/findings.json"
SARIF_PREFIX = "CVSS:3.1/"
UNKNOWN_ID = "UNKNOWN"
UNKNOWN_TITLE = "Untitled finding"
INFO_SEVERITY = "INFO"
OPEN_STATUS = "Open"
KIND_NOT_YET_DETERMINED = "notYetDetermined"
HIGH_PRECISION = "high"
PERCENT_SRCROOT = "%SRCROOT%"


def severity_to_level(severity: str) -> str:
    """Map finding severity to SARIF result level."""
    mapping: Dict[str, str] = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    return mapping.get(severity.upper(), "note")


def build_sarif(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build SARIF 2.1.0 document from findings list."""
    results: List[Dict[str, Any]] = []

    for finding in findings:
        location = finding.get("location", {})
        file_path = location.get("file", "")
        line = location.get("line")

        # Build physical location
        physical_location: Dict[str, Any] = {
            "artifactLocation": {
                "uri": file_path,
                "uriBaseId": PERCENT_SRCROOT,
            }
        }
        if line:
            physical_location["region"] = {
                "startLine": line,
                "startColumn": 1,
            }

        result: Dict[str, Any] = {
            "id": finding.get("id", UNKNOWN_ID),
            "shortDescription": {
                "text": finding.get("title", UNKNOWN_TITLE),
            },
            "fullDescription": {
                "text": finding.get("description", ""),
            },
            "level": severity_to_level(finding.get("severity", INFO_SEVERITY)),
            "properties": {
                "severity": finding.get("severity", INFO_SEVERITY),
                "cvss": finding.get("cvss"),
                "cvss_vector": finding.get("cvss_vector"),
                "cwe": finding.get("cwe"),
                "function": location.get("function"),
                "rule_caught": finding.get("rule_caught"),
                "status": finding.get("status", OPEN_STATUS),
            },
        }

        # Add location with proper SARIF structure
        if file_path:
            result["locations"] = [{"physicalLocation": physical_location}]

        # Add helpful message rule for remediation
        if finding.get("recommendation"):
            result["message"] = {
                "text": finding.get("recommendation", ""),
            }
            result["kind"] = KIND_NOT_YET_DETERMINED

        results.append(result)

    sarif: Dict[str, Any] = {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": "https://github.com/solana-auditor-skill",
                        "rules": build_rules(findings),
                    }
                },
                "results": results,
            }
        ],
    }

    return sarif


def build_rules(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build SARIF tool driver rules from findings."""
    rules: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()

    for finding in findings:
        fid = finding.get("id")
        if fid and fid not in seen_ids:
            seen_ids.add(fid)
            rule: Dict[str, Any] = {
                "id": fid,
                "name": finding.get("cwe", "Unknown"),
                "shortDescription": {
                    "text": finding.get("title", UNKNOWN_TITLE),
                },
                "fullDescription": {
                    "text": finding.get("description", ""),
                },
                "defaultConfiguration": {
                    "level": severity_to_level(finding.get("severity", INFO_SEVERITY)),
                },
                "properties": {
                    "tags": [finding.get("severity", INFO_SEVERITY).lower()],
                    "precision": HIGH_PRECISION,
                },
            }
            rules.append(rule)

    return rules


def load_findings(path: Union[str, Path]) -> Dict[str, Any]:
    """Load findings from JSON file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Findings file not found: {path}")

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if "findings" not in data:
        raise ValueError("Invalid findings schema: missing 'findings' key")

    return data


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export findings.json to SARIF 2.1.0 format for GitHub Code Scanning"
    )
    parser.add_argument(
        "findings",
        nargs="?",
        help=f"Path to findings.json (default: {DEFAULT_FINDINGS_PATH})",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "--pretty",
        "-p",
        action="store_true",
        default=True,
        help="Pretty-print JSON output (default: true)",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="store_true",
        help="Show tool version",
    )

    args = parser.parse_args()

    if args.version:
        print(f"{TOOL_NAME} v{TOOL_VERSION}")
        return 0

    # Default path if not provided
    findings_path = args.findings
    if not findings_path:
        findings_path = DEFAULT_FINDINGS_PATH

    try:
        data = load_findings(findings_path)
        sarif = build_sarif(data["findings"])

        output = json.dumps(sarif, indent=2 if args.pretty else None)

        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"SARIF output written to: {args.output}", file=sys.stderr)
        else:
            print(output)

        return 0

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in findings file: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
