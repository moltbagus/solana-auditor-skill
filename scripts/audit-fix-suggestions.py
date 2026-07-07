#!/usr/bin/env python3
"""
audit-fix-suggestions.py — Fix suggestion engine CLI orchestrator.

Reads findings.json and generates inline fix suggestions for each finding type.
This module is the CLI entry point. All domain logic lives in sub-modules.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure scripts/ directory is on the path for module imports
_SCRIPTS_DIR = str(Path(__file__).resolve().parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from fix_constants import (  # noqa: E402
    RULE_CWE_REFS,
    RULE_DOC_REFS,
    RULE_NAMES,
    SCRIPT_VERSION,
)
from fix_confidence import (  # noqa: E402
    compute_confidence,
    determine_tier,
    estimate_cvss_after,
    format_tier_a_notification,
    format_tier_b_prompt,
    format_tier_c_guidance,
    generate_test_template,
    get_effort_minutes,
    get_fix_type,
    get_poker_risk,
)
from fix_exploit import generate_exploit_metadata, write_metadata_file  # noqa: E402
from fix_models import FixSuggestion, FixSuggestionsOutput  # noqa: E402
from fix_regression import write_regression_tests  # noqa: E402
from fix_templates import get_fix_template  # noqa: E402

# Security Hardening
FINDING_ID_PATTERN: str = r"^[a-zA-Z0-9_-]+$"
MAX_FINDING_ID_LENGTH: int = 64
MAX_FILE_PATH_LENGTH: int = 512


class SecurityError(Exception):
    """Raised when input validation fails for security reasons."""
    pass


def validate_finding_id(finding_id: str) -> None:
    """Validate a finding ID is safe for use in paths and queries."""
    if not finding_id:
        raise SecurityError("Finding ID must not be empty")
    if len(finding_id) > MAX_FINDING_ID_LENGTH:
        raise SecurityError(f"Finding ID exceeds max length of {MAX_FINDING_ID_LENGTH}")
    if not re.match(FINDING_ID_PATTERN, finding_id):
        raise SecurityError(f"Finding ID contains invalid characters: {finding_id!r}")


def sanitize_path(path: str, allow_absolute: bool = True) -> str:
    """Sanitize a file path against traversal and injection."""
    if len(path) > MAX_FILE_PATH_LENGTH:
        raise SecurityError(f"Path exceeds max length of {MAX_FILE_PATH_LENGTH}")
    if ".." in path:
        raise SecurityError(f"Path traversal detected: {path!r}")
    if path.startswith("~/") or path.startswith("~"):
        raise SecurityError(f"Home directory expansion detected: {path!r}")
    if "\x00" in path:
        raise SecurityError("Null byte detected in path")
    if any(ord(c) < 32 or ord(c) == 127 for c in path):
        raise SecurityError("Control character detected in path")
    return path


def safe_output(value: str, max_length: int = 10000) -> str:
    """Sanitize string output: cap length and strip nulls."""
    value = value.replace("\x00", "")
    if len(value) > max_length:
        value = value[:max_length]
    return value


def safe_json_dump(obj: Any, max_depth: int = 10) -> Any:
    """Recursively sanitize a Python object for JSON serialization."""
    if max_depth < 0:
        raise ValueError("JSON nesting exceeds max depth")
    if isinstance(obj, str):
        return safe_output(obj)
    if isinstance(obj, dict):
        return {safe_output(str(k)): safe_json_dump(v, max_depth - 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [safe_json_dump(item, max_depth - 1) for item in obj]
    if isinstance(obj, (int, float, bool)):
        return obj
    if obj is None:
        return None
    return safe_output(str(obj))


# Helper Functions
def extract_rule_id(rule_caught: str) -> str:
    """Extract the rule ID from a rule_caught string."""
    if not rule_caught:
        return "Rule 0"
    match = re.match(r"(Rule \d+)", rule_caught)
    if match:
        return match.group(1)
    for rule_id, rule_name in RULE_NAMES.items():
        if rule_name.lower() in rule_caught.lower():
            return rule_id
    return "Rule 0"


def generate_finding_id(finding: dict[str, Any], index: int) -> str:
    """Generate a suggestion ID for a finding."""
    finding_id = finding.get("id", f"IDX-{index}")
    return f"SUGGEST-{finding_id}"


def get_program_id_from_findings(findings: list[dict[str, Any]]) -> str:
    """Extract program ID from findings if available."""
    for finding in findings:
        if "program_id" in finding:
            return finding["program_id"]
    return "unknown"


def generate_fix_suggestion(finding: dict[str, Any], index: int) -> FixSuggestion:
    """Generate a fix suggestion for a single finding."""
    rule_id = extract_rule_id(finding.get("rule_caught", ""))
    template = get_fix_template(rule_id, finding.get("id", ""))
    location = finding.get("location", {})
    file_path = location.get("file", "unknown")
    line_num = location.get("line", 0)

    references: list[str] = []
    if rule_id in RULE_CWE_REFS:
        references.extend(RULE_CWE_REFS[rule_id])
    if rule_id in RULE_DOC_REFS:
        references.extend(RULE_DOC_REFS[rule_id])
    if finding.get("cwe"):
        cwe_clean = finding["cwe"].replace("CWE-", "")
        cwe_url = f"https://www.cwe.mitre.org/data/definitions/{cwe_clean}.html"
        if cwe_url not in references:
            references.insert(0, cwe_url)
    references.append("https://www.anchor-lang.com/docs/the-program")

    confidence = compute_confidence(rule_id, True)
    poker_risk = get_poker_risk(rule_id)
    tier = determine_tier(confidence, poker_risk)
    fix_type = get_fix_type(rule_id)
    effort = get_effort_minutes(rule_id)
    cvss_before = finding.get("cvss", 7.0)
    cvss_after, _ = estimate_cvss_after(cvss_before, rule_id)
    cvss_reduction = round(cvss_before - cvss_after, 1)
    test_template = generate_test_template(rule_id, finding.get("id", f"IDX-{index}"))

    return FixSuggestion(
        finding_id=generate_finding_id(finding, index),
        severity=finding.get("severity", "UNKNOWN"),
        rule_id=rule_id,
        file=file_path,
        line=line_num,
        before_code=template.before,
        after_code=template.after,
        explanation=template.explanation,
        references=references,
        confidence_score=confidence,
        fix_tier=tier,
        fix_type=fix_type,
        poker_risk=poker_risk,
        estimated_effort_minutes=effort,
        cvss_before=cvss_before,
        cvss_after=cvss_after,
        cvss_reduction=cvss_reduction,
        test_template=test_template,
    )


def generate_all_suggestions(findings: list[dict[str, Any]]) -> list[FixSuggestion]:
    """Generate fix suggestions for all findings."""
    suggestions: list[FixSuggestion] = []
    for idx, finding in enumerate(findings):
        try:
            suggestions.append(generate_fix_suggestion(finding, idx))
        except Exception as e:
            msg = f"Warning: suggestion failed at index {idx}: {e}"
            print(msg, file=sys.stderr)
    return suggestions


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


def validate_finding(finding: dict[str, Any]) -> None:
    """Validate a finding has required fields."""
    required_fields = ["id", "severity", "location", "rule_caught"]
    missing = [f for f in required_fields if f not in finding]
    if missing:
        raise ValidationError(f"Finding missing required fields: {missing}")
    location = finding.get("location", {})
    for loc_field in ["file", "line"]:
        if loc_field not in location:
            raise ValidationError(f"Finding location missing required field: {loc_field}")


def validate_findings_json(data: dict[str, Any]) -> None:
    """Validate the entire findings.json structure."""
    if "findings" not in data:
        raise ValidationError("Missing findings key in input JSON")
    findings = data["findings"]
    if not isinstance(findings, list):
        raise ValidationError("'findings' must be a list")
    for idx, finding in enumerate(findings):
        try:
            validate_finding(finding)
        except ValidationError as e:
            raise ValidationError(f"Finding at index {idx}: {e}") from e


# I/O Functions
def read_findings(input_path: Path) -> dict[str, Any]:
    """Read and validate findings from a JSON file."""
    if not input_path.exists():
        raise FileNotFoundError(f"Findings file not found: {input_path}")
    try:
        with open(input_path, encoding="utf-8") as fh:
            data: dict[str, Any] = json.load(fh)
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in findings file: {e.msg}", e.doc, e.pos) from e
    validate_findings_json(data)
    return data


def write_suggestions(output_path: Path, output_data: dict[str, Any]) -> None:
    """Write fix suggestions to a JSON file."""
    sanitized = safe_json_dump(output_data, max_depth=10)
    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(sanitized, fh, indent=2, ensure_ascii=False)
    except IOError as e:
        raise IOError(f"Failed to write output to {output_path}: {e}") from e


def _print_explanation(suggestion: FixSuggestion, finding: dict[str, Any]) -> None:
    """Print detailed explanation for a fix suggestion."""
    sep = "=" * 60
    print(f"\n{sep}")
    print(f"Finding: {suggestion.finding_id}")
    print(f"Severity: {suggestion.severity}")
    print(f"Rule: {suggestion.rule_id}")
    print(f"File: {suggestion.file}:{suggestion.line}")
    print(f"\nDescription: {finding.get('description', 'N/A')}")
    print(f"Impact: {finding.get('impact', 'N/A')}")
    print(f"CVSS: {suggestion.cvss_before} -> {suggestion.cvss_after} "
          f"(reduction: {suggestion.cvss_reduction})")
    print(f"Confidence: {suggestion.confidence_score:.0%} | Tier: {suggestion.fix_tier}")
    print(f"\nExplanation: {suggestion.explanation}")
    if suggestion.references:
        print("\nReferences:")
        for ref in suggestion.references:
            print(f"  - {ref}")
    print(f"\nBefore Code:\n{suggestion.before_code}")
    print(f"\nAfter Code:\n{suggestion.after_code}")
    print(f"\n{sep}\n")


# CLI Argument Parsing
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse and validate CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Generate fix suggestions from Solana audit findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scripts/audit-fix-suggestions.py\n"
            "  python scripts/audit-fix-suggestions.py --input findings.json\n"
            "    --output fix_suggestions.json\n"
            "  python scripts/audit-fix-suggestions.py --finding VULN-01\n"
            "  python scripts/audit-fix-suggestions.py --severity HIGH\n"
            "  python scripts/audit-fix-suggestions.py --finding VULN-01 --cvss-before-after\n"
            "  python scripts/audit-fix-suggestions.py --finding VULN-01 --explain\n"
            "  python scripts/audit-fix-suggestions.py --metadata\n"
            "  python scripts/audit-fix-suggestions.py --regression\n"
            "  python scripts/audit-fix-suggestions.py --report\n"
        ),
    )

    parser.add_argument("--input", "-i", default="findings.json",
                        help="Input findings JSON (default: findings.json)")
    parser.add_argument("--output", "-o", default="fix_suggestions.json",
                        help="Output fix suggestions JSON (default: fix_suggestions.json)")
    parser.add_argument("--finding", help="Generate suggestion for a single finding ID")
    parser.add_argument("--severity", action="append",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Filter findings by severity")
    parser.add_argument("--apply", action="store_true", help="Apply fix (Tier A auto-apply)")
    parser.add_argument("--cvss-before-after", action="store_true",
                        help="Show CVSS before/after comparison")
    parser.add_argument("--explain", action="store_true",
                        help="Print detailed explanation for finding(s)")
    parser.add_argument("--report", action="store_true", help="Print summary report")
    parser.add_argument("--metadata", action="store_true", help="Generate exploit metadata files")
    parser.add_argument("--regression", action="store_true", help="Generate regression test files")
    parser.add_argument("--metadata-dir", default="audit-output/exploit-metadata",
                        help="Directory for exploit metadata output")
    parser.add_argument("--regression-dir", default="tests/regression",
                        help="Directory for regression test output")

    args = parser.parse_args(argv)

    # Post-parse security validation
    try:
        args.input = sanitize_path(args.input)
        args.output = sanitize_path(args.output)
        if args.metadata_dir:
            args.metadata_dir = sanitize_path(args.metadata_dir)
        if args.regression_dir:
            args.regression_dir = sanitize_path(args.regression_dir)
        if args.finding:
            validate_finding_id(args.finding)
    except SecurityError as e:
        parser.error(str(e))

    return args


# Main Entry Point
def main() -> int:
    """Main entry point for the fix suggestion engine."""
    args = parse_args()

    try:
        findings_path = Path(args.input)
        if not findings_path.exists():
            print(f"ERROR: {args.input} not found", file=sys.stderr)
            return 1

        data = read_findings(findings_path)
        findings: list[dict[str, Any]] = data.get("findings", [])

        if not findings:
            print("WARNING: No findings found in input file", file=sys.stderr)
            return 0

        all_suggestions = generate_all_suggestions(findings)

        # --report: Print summary report
        if args.report:
            by_severity: dict[str, int] = {}
            by_tier: dict[str, int] = {}
            cvss_reductions: list[tuple[str, float, str]] = []
            for finding, suggestion in zip(findings, all_suggestions):
                sev = finding.get("severity", "UNKNOWN").upper()
                by_severity[sev] = by_severity.get(sev, 0) + 1
                by_tier[suggestion.fix_tier] = by_tier.get(suggestion.fix_tier, 0) + 1
                cvss_reductions.append((suggestion.finding_id, suggestion.cvss_reduction, sev))

            sep = "=" * 60
            print(f"\n{sep}")
            print("FIX SUGGESTION REPORT")
            print(f"{sep}")
            print(f"Total findings: {len(findings)}")
            print("\nSeverity Breakdown:")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if by_severity.get(sev, 0):
                    print(f"  {sev}: {by_severity[sev]}")
            print("\nFix Tier Breakdown:")
            for tier in ["A", "B", "C"]:
                if by_tier.get(tier, 0):
                    print(f"  Tier {tier}: {by_tier[tier]}")
            print("\nTop CVSS Reductions:")
            top = sorted(cvss_reductions, key=lambda x: x[1], reverse=True)[:5]
            for fid, reduction, sev in top:
                print(f"  {fid}: -{reduction} ({sev})")
            print(f"{sep}\n")
            return 0

        # --cvss-before-after
        if args.cvss_before_after and args.finding:
            fid = f"SUGGEST-{args.finding}"
            suggestion = next((s for s in all_suggestions if s.finding_id == fid), None)
            if not suggestion:
                print(f"Finding {args.finding} not found", file=sys.stderr)
                return 1
            print(f"\nCVSS Before/After for {args.finding}:")
            print(f"  Before: {suggestion.cvss_before}")
            print(f"  After:  {suggestion.cvss_after}")
            print(f"  Reduction: {suggestion.cvss_reduction}")
            print(f"  Fix Tier: {suggestion.fix_tier}")
            print(f"  Confidence: {suggestion.confidence_score:.0%}")
            return 0

        # --explain
        if args.explain:
            if args.finding:
                fid = f"SUGGEST-{args.finding}"
                suggestion = next((s for s in all_suggestions if s.finding_id == fid), None)
                finding = next((f for f in findings if f.get("id") == args.finding), None)
                if suggestion and finding:
                    _print_explanation(suggestion, finding)
                else:
                    print(f"Finding {args.finding} not found", file=sys.stderr)
                    return 1
            else:
                for suggestion, finding in zip(all_suggestions, findings):
                    _print_explanation(suggestion, finding)
            return 0

        # --metadata
        if args.metadata:
            metadata_dir = Path(args.metadata_dir)
            written: list[Path] = []
            for finding, suggestion in zip(findings, all_suggestions):
                metadata = generate_exploit_metadata(finding, suggestion)
                path = write_metadata_file(metadata_dir, finding.get("id", "unknown"), metadata)
                written.append(path)
            print(f"Wrote {len(written)} metadata files to {metadata_dir}/")
            return 0

        # --regression
        if args.regression:
            regression_dir = Path(args.regression_dir)
            reg_written = write_regression_tests(findings, all_suggestions, regression_dir)
            print(f"Wrote {len(reg_written)} regression tests to {regression_dir}/")
            print("\nTo run all regression tests:")
            print("  anchor test tests/regression/test_all_regressions.rs")
            print("  cargo test --manifest-path tests/regression/Cargo.toml")
            return 0

        # --finding
        if args.finding:
            fid = f"SUGGEST-{args.finding}"
            suggestion = next((s for s in all_suggestions if s.finding_id == fid), None)
            if not suggestion:
                template = get_fix_template("Rule 8", args.finding)
                suggestion = FixSuggestion(
                    finding_id=f"SUGGEST-{args.finding}", severity="UNKNOWN", rule_id="Rule 8",
                    file="unknown", line=0, before_code=template.before, after_code=template.after,
                    explanation=template.explanation, references=[],
                )

            if args.apply and suggestion.fix_tier == "A":
                print(format_tier_a_notification(suggestion))
            elif suggestion.fix_tier == "A":
                print(format_tier_a_notification(suggestion))
                print("  Use --apply to auto-apply this fix.")
            elif suggestion.fix_tier == "B":
                print(format_tier_b_prompt(suggestion))
            else:
                print(format_tier_c_guidance(suggestion))

            if suggestion.test_template:
                indented = suggestion.test_template.replace(chr(10), chr(10) + "    ")
                print("\n  Verification Test Template:")
                print(f"    {indented}")
            return 0

        # --severity
        if args.severity:
            severities = set(s.upper() for s in args.severity)
            filtered = [s for s in all_suggestions if s.severity.upper() in severities]
            print(f"Suggestions matching severity {', '.join(sorted(severities))}:")
            for s in filtered:
                print(f"  {s.finding_id} ({s.severity}, Tier {s.fix_tier})")
                print(f"    File: {s.file}:{s.line}")
                print(f"    Confidence: {s.confidence_score:.0%}")
                print(f"    CVSS: {s.cvss_before} -> {s.cvss_after}")
                print()
            return 0

        # Default: Generate full output file
        program_id = get_program_id_from_findings(findings)
        output_obj = FixSuggestionsOutput(
            generated_at=datetime.now(timezone.utc).isoformat(),
            program_id=program_id,
            version=SCRIPT_VERSION,
            total_findings=len(findings),
            suggestions=[s.to_dict() for s in all_suggestions],
        )

        output_path = Path(args.output)
        write_suggestions(output_path, output_obj.to_dict())
        print(f"Written: {output_path} ({len(all_suggestions)} suggestions)")

        tiers: dict[str, int] = {}
        for s in all_suggestions:
            tiers[s.fix_tier] = tiers.get(s.fix_tier, 0) + 1
        print(f"Tier A (auto-apply): {tiers.get('A', 0)}")
        print(f"Tier B (assisted):  {tiers.get('B', 0)}")
        print(f"Tier C (manual):    {tiers.get('C', 0)}")

        return 0

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        return 1
    except SecurityError as e:
        print(f"Security Error: {e}", file=sys.stderr)
        return 1
    except IOError as e:
        print(f"I/O Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
