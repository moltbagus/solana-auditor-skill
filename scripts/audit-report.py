#!/usr/bin/env python3
"""Standalone CLI to synthesize findings.json into AUDIT_REPORT.md and optionally an HTML dashboard.

Mirrors the /audit-report command contract:
  python3 scripts/audit-report.py <findings-json> [--output <dir>] [--html]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_VERSION = "1.0.0"
DEFAULT_FINDINGS = "examples/sample-vulnerable-program/audit-output/findings.json"
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_findings(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        sys.exit(f"ERROR: findings file not found: {p}\n")
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        sys.exit(f"ERROR: Invalid JSON in {p}: {e}\n")
    if "findings" not in raw:
        sys.exit("ERROR: findings.json must contain a 'findings' key.\n")
    return raw


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def severity_badge(sev: str) -> str:
    icons = {
        "CRITICAL": "![CRITICAL](https://img.shields.io/badge/-CRITICAL-red)",
        "HIGH":     "![HIGH](https://img.shields.io/badge/-HIGH-orange)",
        "MEDIUM":   "![MEDIUM](https://img.shields.io/badge/-MEDIUM-yellow)",
        "LOW":      "![LOW](https://img.shields.io/badge/-LOW-blue)",
        "INFO":     "![INFO](https://img.shields.io/badge/-INFO-lightgrey)",
    }
    return icons.get(sev.upper(), sev)


def render_report(findings: list[dict[str, Any]], raw: dict[str, Any], output_dir: Path) -> Path:
    summary = raw.get("summary", {}) or {}
    program = summary.get("program_name", "Unknown Program")
    repo = summary.get("repo", "N/A")
    audit_date = summary.get("audit_date", "N/A")
    skill_version = summary.get("skill_version", "N/A")

    # Severity counts
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev.upper() in counts:
            counts[sev.upper()] += 1

    total = len(findings)

    lines: list[str] = []
    W = lines.append

    W(f"# Security Audit Report\n")
    W(f"**Program:** {program}\n")
    W(f"**Repository:** {repo}\n")
    W(f"**Date:** {audit_date}\n")
    W(f"**Skill Version:** {skill_version}\n")
    W(f"**Generated:** {datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}\n")
    W("\n")

    W("## Executive Summary\n")
    crit = counts["CRITICAL"]
    high = counts["HIGH"]
    medium = counts["MEDIUM"]
    W(
        f"This audit identified **{total}** finding{'s' if total != 1 else ''} across "
        f"{len(SEVERITY_ORDER)} severity levels. "
        f"{crit} critical and {high} high severity issues require immediate attention."
        + (f" {medium} medium severity issues should be addressed in a timely manner." if medium else "")
        + "\n"
    )
    W("\n")

    W("## Severity Summary\n")
    W("| Severity | Count |")
    W("|----------|------:|")
    for s in SEVERITY_ORDER:
        if counts[s] > 0:
            W(f"| {severity_badge(s)} | {counts[s]} |")
    W(f"| **Total** | **{total}** |")
    W("\n")

    W("## Findings\n")
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO")
        title = f.get("title", "Untitled")
        fid = f.get("id", f"FIND-{i:03d}")
        cvss = f.get("cvss")
        cvss_vec = f.get("cvss_vector", "")
        cwe = f.get("cwe", "")
        loc = f.get("location", {})
        loc_file = loc.get("file", "N/A")
        loc_line = loc.get("line")
        loc_fn = loc.get("function", "")
        desc = f.get("description", "No description provided.")
        impact = f.get("impact", "Impact not assessed.")
        rec = f.get("recommendation", "No recommendation provided.")
        poc = f.get("poc_path")

        W(f"### {fid}: {title} {severity_badge(sev)}\n")
        W(f"- **Severity:** {sev}")
        if cvss is not None:
            W(f"  | **CVSS:** {cvss}" + (f" ({cvss_vec})" if cvss_vec else ""))
        if cwe:
            W(f"  | **CWE:** {cwe}")
        W(f"- **Location:** `{loc_file}`" + (f":{loc_line}" if loc_line else "") + (f" in `{loc_fn}`" if loc_fn else ""))
        if poc:
            W(f"- **PoC:** `examples/{poc}`")
        W("\n")
        W(f"**Description:** {desc}\n")
        W(f"\n**Impact:** {impact}\n")
        W(f"\n**Recommendation:** {rec}\n")
        W("\n---\n\n")

    W("## Patterns Reviewed, Not Exploited\n")
    W("The following patterns were analyzed and determined to not represent exploitable vulnerabilities under the current threat model:\n")
    W("- (None documented — add entries as findings are closed)\n")
    W("\n")

    W("## Out of Scope\n")
    W("The following areas were explicitly excluded from this audit:\n")
    scope = raw.get("out_of_scope", [])
    for item in scope:
        W(f"- {item}\n")
    if not scope:
        W("- (None — full program scope)\n")
    W("\n")

    W("## Disclaimer\n")
    W(
        "This report is a point-in-time security assessment. New attack vectors or changes to the "
        "program may introduce vulnerabilities not identified here. Findings should be re-evaluated "
        "after each significant code change."
    )
    W("\n\n")

    W("## Appendix: Tools & Methodology\n")
    W(f"- **Tool:** solana-auditor-skill v{skill_version}\n")
    W("- **Rules:** 26 path-scoped Solana Anchor security rules\n")
    W("- **Agents:** 6 specialized audit agents + cross-program agent\n")
    W("- **Framework:** Anchor v0.30+ on Solana v1.18+\n")
    W("\n")

    out_path = output_dir / "AUDIT_REPORT.md"
    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# HTML dashboard helper
# ---------------------------------------------------------------------------

def render_html(findings_path: Path, output_dir: Path) -> Path | None:
    dashboard_script = Path(__file__).parent / "dashboard.py"
    if not dashboard_script.is_file():
        print(f"WARN: dashboard.py not found at {dashboard_script} — skipping HTML", file=sys.stderr)
        return None

    out_path = output_dir / "dashboard.html"
    cmd = ["python3", str(dashboard_script), str(findings_path), str(out_path)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"WARN: dashboard.py failed:\n{result.stderr}", file=sys.stderr)
        return None
    return out_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Synthesize findings.json into AUDIT_REPORT.md and optionally an HTML dashboard.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 scripts/audit-report.py findings.json
  python3 scripts/audit-report.py findings.json --output ./output/
  python3 scripts/audit-report.py findings.json --html
  python3 scripts/audit-report.py findings.json --output ./output/ --html
""",
    )
    parser.add_argument(
        "findings",
        nargs="?",
        default=DEFAULT_FINDINGS,
        help=f"Path to findings.json (default: {DEFAULT_FINDINGS})",
    )
    parser.add_argument(
        "--output", "-o",
        dest="output_dir",
        default=None,
        help="Output directory (default: <findings-parent>/audit-output/)",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="Also generate an HTML dashboard via scripts/dashboard.py",
    )
    parser.add_argument(
        "--version", "-v",
        action="store_true",
        help="Show script version",
    )
    args = parser.parse_args()

    if args.version:
        print(f"audit-report.py v{SCRIPT_VERSION}")
        return 0

    findings_path = Path(args.findings)

    # Resolve output dir
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        output_dir = findings_path.parent

    output_dir.mkdir(parents=True, exist_ok=True)

    # Load
    raw = load_findings(findings_path)
    findings: list[dict[str, Any]] = raw.get("findings", [])

    # Sort by severity
    sev_order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda f: sev_order.get(f.get("severity", "INFO").upper(), 99))

    # Render markdown
    report_path = render_report(findings, raw, output_dir)
    print(f"Report written to: {report_path}", file=sys.stderr)

    # Render HTML if requested
    dashboard_path: Path | None = None
    if args.html:
        dashboard_path = render_html(findings_path, output_dir)
        if dashboard_path:
            print(f"Dashboard written to: {dashboard_path}", file=sys.stderr)
        else:
            print("HTML dashboard generation failed — continuing without it", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
