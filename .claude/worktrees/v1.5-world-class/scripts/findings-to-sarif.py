#!/usr/bin/env python3
"""
findings-to-sarif.py — Convert findings.json to SARIF 2.1.0

Usage:
    python scripts/findings-to-sarif.py [--input findings.json] [--output findings.sarif]
    python scripts/findings-to-sarif.py [--input findings.json] [--upload --repo owner/repo --pr 42]
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TOOL_NAME = "solana-auditor-shiba"
TOOL_VERSION = "1.6.0"


def severity_to_sarif_level(severity: str) -> str:
    """Map finding severity to SARIF result level."""
    mapping: dict[str, str] = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    return mapping.get(severity.upper(), "warning")


def build_location(finding: dict[str, Any]) -> dict[str, Any]:
    """Build SARIF physicalLocation block from finding location dict."""
    loc = finding.get("location", {})
    artifact: dict[str, Any] = {
        "uri": loc.get("file", "unknown"),
    }
    region: dict[str, Any] = {}
    if loc.get("line"):
        region["startLine"] = loc["line"]
    if loc.get("endLine"):
        region["endLine"] = loc["endLine"]
    if loc.get("snippet"):
        region["snippet"] = {"text": loc["snippet"]}

    result: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": artifact,
        }
    }
    if region:
        result["physicalLocation"]["region"] = region
    return result


def generate_sarif_log(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate SARIF 2.1.0 log from findings list."""
    results: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []

    for finding in findings:
        rule_id = f"SHIBA-{finding['id']}"
        severity = finding.get("severity", "MEDIUM")
        title = finding.get("title", "unknown")
        description = finding.get("description", "")
        impact = finding.get("impact", "")
        recommendation = finding.get("recommendation", "")

        # Full description is description + impact + recommendation
        full_desc_parts = [description, impact, recommendation]
        full_desc = "\n\n".join(p for p in full_desc_parts if p)

        rule: dict[str, Any] = {
            "id": rule_id,
            "name": title.replace(" ", "-"),
            "shortDescription": {"text": title},
            "fullDescription": {"text": full_desc or title},
            "defaultConfiguration": {"level": severity_to_sarif_level(severity)},
            "properties": {
                "tags": [
                    "security",
                    "solana",
                    severity.lower(),
                    finding.get("cwe", "").lower(),
                    finding.get("rule_caught", "").lower().replace(" ", "-"),
                ],
                "precision": "high",
                "security-severity": str(finding.get("cvss", "0.0")),
            },
        }
        rules.append(rule)

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": severity_to_sarif_level(severity),
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

        location = build_location(finding)
        if location:
            result["locations"] = [location]

        results.append(result)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": (
                    "https://github.com/moltbagus/solana-auditor-shiba-skill"
                ),
                "organization": "Solana Auditor Shiba",
                "rules": rules,
            }
        },
        "results": results,
        "columnKind": "utf16CodeUnits",
    }

    return {
        "version": "2.1.0",
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "runs": [run],
    }


def load_findings(input_path: Path) -> list[dict[str, Any]]:
    """Load and validate findings from JSON file."""
    try:
        with open(input_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        print(f"ERROR: {input_path} is not valid JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    if isinstance(data, list):
        findings = data
    elif isinstance(data, dict):
        findings = data.get("findings", [])
    else:
        print(
            f"ERROR: {input_path} root must be array or object with 'findings' key",
            file=sys.stderr,
        )
        sys.exit(1)

    if not findings:
        print(f"WARNING: No findings found in {input_path}", file=sys.stderr)

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert findings.json to SARIF 2.1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/findings-to-sarif.py --input findings.json
  python scripts/findings-to-sarif.py -i findings.json -o findings.sarif
  python scripts/findings-to-sarif.py --input audit-output/findings.json --output results.sarif
        """,
    )
    parser.add_argument(
        "--input",
        "-i",
        default="findings.json",
        help="Input findings JSON file (default: findings.json)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output SARIF file (default: write to stdout)",
    )
    parser.add_argument(
        "--pretty",
        "-p",
        action="store_true",
        help="Pretty-print JSON output (default: True)",
    )
    args = parser.parse_args()

    # Load findings
    findings_path = Path(args.input)
    if not findings_path.exists():
        print(f"ERROR: {args.input} not found", file=sys.stderr)
        sys.exit(1)

    findings = load_findings(findings_path)

    # Generate SARIF
    sarif = generate_sarif_log(findings)

    # Serialize
    output = json.dumps(
        sarif,
        indent=2 if args.pretty else None,
        ensure_ascii=False,
    )

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(output, encoding="utf-8")
        print(f"Written: {out_path} ({len(findings)} findings)")
    else:
        print(output)


if __name__ == "__main__":
    main()
