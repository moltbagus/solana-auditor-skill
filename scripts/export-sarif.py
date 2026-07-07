#!/usr/bin/env python3
"""
export-sarif.py — Export findings.json to SARIF 2.1.0 format.

Thin CLI wrapper around sarif_core. Supports both positional and
--input arguments.

Usage:
    python scripts/export-sarif.py <findings.json> [--output <file>]
    python scripts/export-sarif.py --input findings.json --output results.sarif
    python scripts/export-sarif.py --version
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from sarif_core import TOOL_NAME, TOOL_VERSION, findings_to_sarif, load_findings

DEFAULT_FINDINGS_PATH = "examples/sample-vulnerable-program/audit-output/findings.json"


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.version:
        print(f"{TOOL_NAME} v{TOOL_VERSION}")
        return 0

    # Determine input path
    findings_path: str = args.findings or args.input
    if not findings_path:
        findings_path = DEFAULT_FINDINGS_PATH

    input_path = Path(findings_path)
    if not input_path.exists():
        print(f"Error: findings file not found: {findings_path}", file=sys.stderr)
        return 1

    findings = load_findings(input_path)
    if not findings:
        print(f"Warning: No findings found in {findings_path}", file=sys.stderr)

    sarif = findings_to_sarif(findings, rule_id_prefix="")
    output = json.dumps(sarif, indent=2 if args.pretty else None, ensure_ascii=False)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Written: {args.output} ({len(findings)} findings)", file=sys.stderr)
    else:
        print(output)

    return 0


def _build_parser():
    import argparse

    parser = argparse.ArgumentParser(
        description="Export findings.json to SARIF 2.1.0 format for GitHub Code Scanning",
    )
    parser.add_argument(
        "findings",
        nargs="?",
        help="Path to findings.json (positional, optional)",
    )
    parser.add_argument(
        "--input", "-i",
        help="Path to findings.json (alternative to positional)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "--pretty", "-p",
        action="store_true", default=True,
        help="Pretty-print JSON",
    )
    parser.add_argument(
        "--version", "-v",
        action="store_true",
        help="Show tool version",
    )
    return parser


if __name__ == "__main__":
    sys.exit(main())
