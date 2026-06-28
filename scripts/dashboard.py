#!/usr/bin/env python3
"""Audit findings dashboard generator.

Reads one or two findings.json files and renders a self-contained HTML report
via Jinja2. When two files are given, shows a before/after comparison view.
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


def compute_comparison(
    before_findings: list[dict[str, Any]],
    after_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Diff two findings lists and return comparison stats + per-finding status."""
    # Build lookup by canonical id (strip leading C- if present)
    def norm_id(f: dict[str, Any]) -> str:
        return f.get("id", "").lstrip("C-")

    before_map: dict[str, dict[str, Any]] = {norm_id(f): f for f in before_findings}
    after_map: dict[str, dict[str, Any]] = {norm_id(f): f for f in after_findings}

    all_ids = set(before_map) | set(after_map)
    fixed_findings: list[dict[str, Any]] = []
    unchanged_findings: list[dict[str, Any]] = []
    new_findings: list[dict[str, Any]] = []

    for fid in sorted(all_ids, key=lambda x: (not x[0].isdigit(), x)):
        in_before = fid in before_map
        in_after = fid in after_map

        if in_before and in_after:
            unchanged_findings.append(after_map[fid])
        elif in_before:
            fixed_findings.append(before_map[fid])
        else:
            new_findings.append(after_map[fid])

    def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITY_LEVELS}
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            if sev in counts:
                counts[sev] += 1
        return counts

    def cvss_sum(findings: list[dict[str, Any]]) -> float:
        return round(sum(f["cvss"] for f in findings if isinstance(f.get("cvss"), (int, float))), 1)

    before_summary = compute_summary(before_findings)
    after_summary = compute_summary(after_findings)

    def delta(b: int, a: int) -> str:
        d = a - b
        return f"{'+' if d > 0 else ''}{d}"

    # Build status map: norm_id -> 'Fixed'|'Unchanged'|'New'
    fixed_ids = {norm_id(f) for f in fixed_findings}
    unchanged_ids = {norm_id(f) for f in unchanged_findings}
    new_ids = {norm_id(f) for f in new_findings}
    finding_status: dict[str, str] = {}
    for fid in fixed_ids:
        finding_status[fid] = "Fixed"
    for fid in unchanged_ids:
        finding_status[fid] = "Unchanged"
    for fid in new_ids:
        finding_status[fid] = "New"

    return {
        "before_summary": before_summary,
        "after_summary": after_summary,
        "severity_delta": {
            "critical": delta(before_summary["critical"], after_summary["critical"]),
            "high": delta(before_summary["high"], after_summary["high"]),
            "medium": delta(before_summary["medium"], after_summary["medium"]),
            "low": delta(before_summary["low"], after_summary["low"]),
            "info": delta(before_summary["info"], after_summary["info"]),
        },
        "cvss_delta": delta(before_summary["cvss_total"], after_summary["cvss_total"]),
        "before_total": before_summary["total"],
        "after_total": after_summary["total"],
        "fixed": fixed_findings,
        "fixed_counts": severity_counts(fixed_findings),
        "fixed_cvss": cvss_sum(fixed_findings),
        "unchanged": unchanged_findings,
        "unchanged_counts": severity_counts(unchanged_findings),
        "unchanged_cvss": cvss_sum(unchanged_findings),
        "new": new_findings,
        "new_counts": severity_counts(new_findings),
        "new_cvss": cvss_sum(new_findings),
        "finding_status": finding_status,
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
    comparison: dict[str, Any] | None = None,
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

    return template.render(
        findings=findings,
        summary=summary,
        metadata=metadata,
        comparison=comparison,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate an HTML audit findings dashboard from findings.json.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 scripts/dashboard.py findings.json
  python3 scripts/dashboard.py findings.json report.html
  python3 scripts/dashboard.py --compare before.json after.json
  python3 scripts/dashboard.py --compare before.json after.json comparison.html
""",
    )
    parser.add_argument(
        "before",
        nargs="?",
        default=None,
        help="Path to findings.json (before findings in compare mode)",
    )
    parser.add_argument(
        "after",
        nargs="?",
        default=None,
        help="Output HTML path in single-file mode; before findings in --compare mode",
    )
    parser.add_argument(
        "output",
        nargs="?",
        default=None,
        help="Output HTML path (single-file: second positional; compare: third positional)",
    )
    parser.add_argument(
        "--compare",
        dest="compare_mode",
        action="store_true",
        help="Enable comparison mode: args are before.json after.json [output.html]",
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

    # ── Comparison mode: --compare flag ──────────────────────────────────────
    if args.compare_mode:
        if not args.before or not args.after:
            sys.exit("ERROR: --compare requires two findings.json paths: before and after.\n")
        before_path = Path(args.before).resolve()
        after_path = Path(args.after).resolve()
        if not before_path.is_file():
            sys.exit(f"ERROR: Before file not found: {before_path}\n")
        if not after_path.is_file():
            sys.exit(f"ERROR: After file not found: {after_path}\n")

        before_findings, before_raw = load_findings(before_path)
        after_findings, after_raw = load_findings(after_path)

        comparison = compute_comparison(before_findings, after_findings)

        before_meta = compute_metadata(before_raw, str(before_path))
        after_meta = compute_metadata(after_raw, str(after_path))
        combined_meta = {
            "program_name": before_meta.get("program_name", "Unknown Program"),
            "repo": before_meta.get("repo", "N/A"),
            "before_audit_date": before_meta.get("audit_date", "N/A"),
            "after_audit_date": after_meta.get("audit_date", "N/A"),
            "generated_at": before_meta.get("generated_at", "N/A"),
            "generator": f"solana-auditor-skill dashboard v{SCRIPT_VERSION}",
            "file_path": f"{before_path} → {after_path}",
        }

        combined_findings = comparison["unchanged"] + comparison["new"]
        combined_summary = compute_summary(combined_findings)

        output_path = Path(args.output) if args.output else before_path.with_name("comparison.dashboard.html")
        html = render(combined_findings, combined_summary, combined_meta, templates_dir, comparison)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        print(f"Comparison dashboard written to {output_path}", file=sys.stderr)
        return

    # ── Single-file mode ────────────────────────────────────────────────────
    if args.before is None:
        sys.exit("ERROR: No input file specified. Pass a findings.json path.\n")

    input_path = Path(args.before).resolve()
    if not input_path.is_file():
        sys.exit(f"ERROR: File not found: {input_path}\n")
    findings, raw_data = load_findings(input_path)
    input_path_str = str(input_path)

    summary = compute_summary(findings)
    metadata = compute_metadata(raw_data, input_path_str)

    stdout_mode = False
    if args.after:
        # args.after is the output path in single-file mode
        output_path = Path(args.after).resolve()
    elif args.output:
        output_path = Path(args.output).resolve()
    elif args.before:
        output_path = input_path.with_suffix(".dashboard.html")

    html = render(findings, summary, metadata, templates_dir)

    if stdout_mode:
        sys.stdout.write(html)
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        print(f"Dashboard written to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()