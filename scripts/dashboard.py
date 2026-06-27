#!/usr/bin/env python3
"""Audit findings dashboard generator.

Reads findings.json and renders a self-contained HTML report via Jinja2.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, TextIO

try:
    from jinja2 import Environment, FileSystemLoader, TemplateNotFound
except ImportError:
    sys.exit(
        "ERROR: jinja2 is required. Install it with:\n"
        "  pip install jinja2\n"
        "Or add it to requirements-dev.txt"
    )

SCRIPT_VERSION = "1.0.0"
TEMPLATE_NAME = "dashboard.html"
FINDINGS_KEY = "findings"
SUMMARY_KEY = "summary"

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def load_findings(source: TextIO | Path | str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse findings.json from a file-like object, Path, or raw string. Returns (findings, raw_data)."""
    try:
        if isinstance(source, Path):
            raw = json.loads(source.read_text(encoding="utf-8"))
        elif isinstance(source, str):
            raw = json.loads(source)
        else:
            raw = json.load(source)
    except json.JSONDecodeError as e:
        sys.exit(f"ERROR: Failed to parse JSON: {e}\n")
    except OSError as e:
        sys.exit(f"ERROR: Could not read input: {e}\n")

    if not isinstance(raw, dict):
        sys.exit("ERROR: JSON must be an object with a 'findings' key.\n")

    raw_findings = raw.get(FINDINGS_KEY, [])
    if not isinstance(raw_findings, list):
        sys.exit("ERROR: 'findings' must be a list.\n")

    return raw_findings, raw


def compute_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Derive CVSS stats and severity counts from findings list."""
    counts: dict[str, int] = {s: 0 for s in SEVERITY_LEVELS}
    for f in findings:
        sev = f.get("severity", "INFO")
        sev_upper = sev.upper()
        if sev_upper in counts:
            counts[sev_upper] += 1

    cvss_scores = [f["cvss"] for f in findings if isinstance(f.get("cvss"), (int, float))]
    cvss_total = sum(cvss_scores)
    cvss_avg = cvss_total / len(cvss_scores) if cvss_scores else 0.0
    cvss_worst = max(cvss_scores) if cvss_scores else 0.0

    return {
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "info": counts["INFO"],
        "total": len(findings),
        "cvss_total": round(cvss_total, 1),
        "cvss_avg": round(cvss_avg, 2),
        "cvss_worst": round(cvss_worst, 1),
    }


def compute_metadata(raw: dict[str, Any], input_path: str) -> dict[str, Any]:
    """Extract or derive metadata from the raw findings JSON."""
    summary_block = raw.get(SUMMARY_KEY, {}) or {}
    now = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "program_name": summary_block.get("program_name", "Unknown Program"),
        "repo": summary_block.get("repo", "N/A"),
        "audit_date": summary_block.get("audit_date", "N/A"),
        "skill_version": summary_block.get("skill_version", "N/A"),
        "generator": f"solana-auditor-skill dashboard v{SCRIPT_VERSION}",
        "file_path": input_path,
        "generated_at": now,
    }


def resolve_templates_dir() -> Path:
    """Locate the templates directory relative to this script."""
    script_dir = Path(__file__).parent.resolve()
    templates_dir = script_dir.parent / "templates"
    if templates_dir.is_dir():
        return templates_dir
    # Fallback: templates/ next to scripts/
    return script_dir / "templates"


def render(
    findings: list[dict[str, Any]],
    summary: dict[str, Any],
    metadata: dict[str, Any],
    templates_dir: Path,
) -> str:
    """Render the Jinja2 template and return the HTML string."""
    try:
        env = Environment(loader=FileSystemLoader(str(templates_dir)), autoescape=True)
    except Exception as e:
        sys.exit(f"ERROR: Could not load templates from {templates_dir}: {e}\n")

    try:
        template = env.get_template(TEMPLATE_NAME)
    except TemplateNotFound:
        sys.exit(f"ERROR: Template '{TEMPLATE_NAME}' not found in {templates_dir}\n")
    except Exception as e:
        sys.exit(f"ERROR: Failed to load template: {e}\n")

    return template.render(findings=findings, summary=summary, metadata=metadata)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate an HTML audit findings dashboard from findings.json.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 scripts/dashboard.py findings.json
  python3 scripts/dashboard.py findings.json report.html
  cat findings.json | python3 scripts/dashboard.py -
  cat findings.json | python3 scripts/dashboard.py - > report.html
""",
    )
    parser.add_argument(
        "findings",
        nargs="?",
        default=None,
        help="Path to findings.json (use '-' to read from stdin)",
    )
    parser.add_argument(
        "output",
        nargs="?",
        default=None,
        help=(
            "Output HTML path.\n"
            "  Default for files: <stem>.dashboard.html\n"
            "  Default for stdin: stdout (requires explicit '-' as input)"
        ),
    )
    parser.add_argument(
        "--templates",
        dest="templates_dir",
        metavar="DIR",
        help="Directory containing templates/dashboard.html (default: auto-detect)",
    )
    args = parser.parse_args()

    # Templates dir
    templates_dir: Path
    if args.templates_dir:
        templates_dir = Path(args.templates_dir).resolve()
    else:
        templates_dir = resolve_templates_dir()

    if not templates_dir.is_dir():
        sys.exit(f"ERROR: Templates directory not found: {templates_dir}\n")

    # Load findings
    input_arg = args.findings
    input_path_str: str

    if input_arg is None:
        sys.exit("ERROR: No input file specified. Pass a findings.json path or '-' for stdin.\n")
    elif input_arg == "-":
        raw_text = sys.stdin.read()
        if not raw_text.strip():
            sys.exit("ERROR: No input provided on stdin.\n")
        findings, raw_data = load_findings(raw_text)
        input_path_str = "<stdin>"
    else:
        input_path = Path(input_arg).resolve()
        if not input_path.is_file():
            sys.exit(f"ERROR: File not found: {input_path}\n")
        findings, raw_data = load_findings(input_path)
        input_path_str = str(input_path)

    # Derive summary and metadata
    summary = compute_summary(findings)
    metadata = compute_metadata(raw_data, input_path_str)

    # Resolve output
    stdout_mode = False
    if args.output:
        output_path = Path(args.output)
    elif input_arg and input_arg != "-":
        output_path = Path(input_arg).with_suffix(".dashboard.html")
    else:
        stdout_mode = True

    # Render
    html = render(findings, summary, metadata, templates_dir)

    if stdout_mode:
        sys.stdout.write(html)
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        print(f"Dashboard written to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()