#!/usr/bin/env python3
"""
findings-to-sarif.py — Convert findings.json to SARIF 2.1.0.

Thin CLI wrapper around sarif_core, preserving the original CLI contract
(--input, --output, --pretty) for workflow compatibility.

Usage:
    python scripts/findings-to-sarif.py --input findings.json
    python scripts/findings-to-sarif.py -i findings.json -o findings.sarif
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from sarif_core import findings_to_sarif, load_findings


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    # Load findings
    findings_path = Path(args.input)
    if not findings_path.exists():
        print(f"ERROR: {args.input} not found", file=sys.stderr)
        sys.exit(1)

    findings = load_findings(findings_path)
    if not findings:
        print(f"WARNING: No findings found in {args.input}", file=sys.stderr)

    # Generate SARIF
    sarif = findings_to_sarif(findings)

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


def _build_parser():
    import argparse

    parser = argparse.ArgumentParser(
        description="Convert findings.json to SARIF 2.1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scripts/findings-to-sarif.py --input findings.json\n"
            "  python scripts/findings-to-sarif.py -i findings.json -o findings.sarif\n"
            "  python scripts/findings-to-sarif.py --input audit-output/findings.json "
            "--output results.sarif\n"
        ),
    )
    parser.add_argument("--input", "-i", default="findings.json", help="Input findings JSON file")
    parser.add_argument("--output", "-o", help="Output SARIF file (default: stdout)")
    parser.add_argument("--pretty", "-p", action="store_true", help="Pretty-print JSON output")
    return parser


if __name__ == "__main__":
    main()
