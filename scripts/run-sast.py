#!/usr/bin/env python3
"""
run-sast.py -- Solana Auditor Skill SAST Engine

Loads security rule patterns from rules/sast-patterns.json (26 automated
patterns) and cross-references against rules/audit.rules (50 documentation
rules). Rules 27-50 (Token-2022 Transfer Hook, Pinocchio/Native, AI Agent
Safety) have no automated regex patterns and require manual review.

Usage:
    python scripts/run-sast.py <program_path> [--output findings.json]
    python scripts/run-sast.py --patterns  # Print loaded patterns
    python scripts/run-sast.py --stats     # Coverage stats

Environment:
    AUDIT_OUTPUT_DIR  -- directory for findings JSON
    AUDIT_RULES_PATH  -- path to rules/audit.rules
    AUDIT_PROGRAM_ID  -- program ID being audited

Exit codes:
    0 = audit complete (findings or clean)
    1 = no programs found
    2 = JSON write error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

# =============================================================================
# PATHS
# =============================================================================

SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent
DEFAULT_PATTERNS_PATH = PROJECT_ROOT / "rules" / "sast-patterns.json"
AUDIT_RULES_PATH = PROJECT_ROOT / "rules" / "audit.rules"

SCRIPT_VERSION = "2.0.0"

# =============================================================================
# DATA MODELS
# =============================================================================


@dataclass
class Rule:
    """A security rule with pattern and metadata."""
    rule_id: str
    severity: str
    cwe: str
    pattern: str
    pattern_type: str  # "regex" | "contains"
    file_glob: str
    description: str
    impact: str
    recommendation: str


@dataclass
class Finding:
    """A security finding from SAST analysis."""
    id: str
    rule_id: str
    severity: str
    cvss: float
    cvss_vector: str
    cwe: str
    title: str
    location: dict
    description: str
    impact: str
    recommendation: str
    poc_status: str
    status: str
    file: str
    line: int
    snippet: str


# CVSS 3.1 severity to score mapping
SEVERITY_SCORE: dict[str, tuple[float, str]] = {
    "CRITICAL": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "HIGH": (8.9, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "MEDIUM": (6.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "LOW": (3.3, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N"),
    "INFO": (0.1, "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:N/A:N"),
}


# =============================================================================
# PATTERN LOADING
# =============================================================================


def load_rules(patterns_path: Path | None = None) -> list[Rule]:
    """Load SAST rule patterns from JSON file.

    Falls back to the default rules/sast-patterns.json in the project root.
    """
    path = patterns_path or DEFAULT_PATTERNS_PATH

    if not path.exists():
        print(f"Error: patterns file not found: {path}", file=sys.stderr)
        print("       Run from project root or set --rules", file=sys.stderr)
        sys.exit(1)

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in {path}: {e}", file=sys.stderr)
        sys.exit(1)

    rules_data = data.get("rules", [])
    if not rules_data:
        print(f"Error: no rules found in {path}", file=sys.stderr)
        sys.exit(1)

    rules: list[Rule] = []
    for r in rules_data:
        rules.append(Rule(
            rule_id=r["rule_id"],
            severity=r["severity"],
            cwe=r["cwe"],
            pattern=r["pattern"],
            pattern_type=r["pattern_type"],
            file_glob=r["file_glob"],
            description=r["description"],
            impact=r["impact"],
            recommendation=r["recommendation"],
        ))

    return rules


def count_audit_rules() -> int:
    """Count rules defined in rules/audit.rules by counting '## Rule N:' headers."""
    if not AUDIT_RULES_PATH.exists():
        return 0
    content = AUDIT_RULES_PATH.read_text(errors="replace")
    matches = re.findall(r"^## Rule (\d+):", content, re.MULTILINE)
    return len(matches) if matches else 0


def print_stats(rules: list[Rule], audit_rules_count: int) -> None:
    """Print coverage statistics comparing loaded patterns vs audit.rules."""
    covered = len(rules)
    uncovered = audit_rules_count - covered if audit_rules_count > covered else 0
    covered_pct = (covered / audit_rules_count * 100) if audit_rules_count else 0

    print(f"Automated patterns loaded : {covered}")
    print(f"Manual rules in audit.rules: {audit_rules_count}")
    print(f"Coverage                 : {covered_pct:.0f}% ({covered}/{audit_rules_count})")
    if uncovered > 0:
        print(f"Rules requiring manual review: {uncovered}")
        print("  (Rules 27-50: Token-2022, Pinocchio, AI Agent safety)")
    print()

    # Count by severity
    sev_counts: dict[str, int] = {}
    for r in rules:
        sev_counts[r.severity] = sev_counts.get(r.severity, 0) + 1
    print("By severity:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        cnt = sev_counts.get(sev, 0)
        if cnt:
            print(f"  {sev:<10s} {cnt}")


# =============================================================================
# DETECTION ENGINE
# =============================================================================


def detect_in_file(filepath: Path, rules: list[Rule]) -> Iterator[tuple[Rule, re.Match, str]]:
    """Run all patterns against a single file, yield matches."""
    try:
        content = filepath.read_text(errors="replace")
    except OSError:
        return

    for rule in rules:
        if not filepath.match(rule.file_glob):
            continue
        try:
            flags = re.MULTILINE | re.DOTALL
            for match in re.finditer(rule.pattern, content, flags):
                yield rule, match, content
        except re.error:
            continue


def make_finding(rule: Rule, filepath: Path, match: re.Match, content: str) -> Finding:
    """Convert a rule match into a Finding."""
    line_num = content[:match.start()].count("\n") + 1
    score, vector = SEVERITY_SCORE.get(
        rule.severity.upper(),
        (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    )
    finding_id = f"SAST-{rule.rule_id}-{line_num}"
    snippet = match.group(0)
    if len(snippet) > 200:
        snippet = snippet[:200] + "..."

    return Finding(
        id=finding_id,
        rule_id=rule.rule_id,
        severity=rule.severity.upper(),
        cvss=score,
        cvss_vector=vector,
        cwe=rule.cwe,
        title=f"[{rule.rule_id}] {rule.description[:80]}",
        location={"file": str(filepath), "line": line_num},
        description=rule.description,
        impact=rule.impact,
        recommendation=rule.recommendation,
        poc_status="pending",
        status="Open",
        file=str(filepath),
        line=line_num,
        snippet=snippet,
    )


def run_audit(program_path: Path, rules: list[Rule]) -> list[Finding]:
    """Run full SAST audit against a program directory."""
    findings: list[Finding] = []

    for rs_file in program_path.rglob("**/*.rs"):
        parts = rs_file.parts
        if "target" in parts or "tests" in parts or ".git" in parts:
            continue
        for rule, match, content in detect_in_file(rs_file, rules):
            findings.append(make_finding(rule, rs_file, match, content))

    return findings


def severity_counts(findings: list[Finding]) -> dict:
    """Summarize findings by severity."""
    counts: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        "total": len(findings),
    }
    for f in findings:
        key = f.severity.lower()
        if key in counts:
            counts[key] += 1
    return counts


# =============================================================================
# CLI
# =============================================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Solana SAST engine — loads patterns from rules/sast-patterns.json",
    )
    parser.add_argument(
        "program",
        nargs="?",
        default="programs",
        help="Path to program source (default: programs/)",
    )
    parser.add_argument(
        "--output", "-o",
        default="findings.json",
        help="Output file for findings JSON",
    )
    parser.add_argument(
        "--rules",
        help="Path to sast-patterns.json (default: rules/sast-patterns.json)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print per-file findings",
    )
    parser.add_argument(
        "--patterns",
        action="store_true",
        help="Print loaded patterns and exit",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print coverage stats and exit",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print version and exit",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # --version
    if args.version:
        print(f"run-sast.py v{SCRIPT_VERSION}")
        return 0

    # Resolve patterns path
    patterns_path: Path | None = None
    if args.rules:
        patterns_path = Path(args.rules).resolve()
        if not patterns_path.exists():
            print(f"Error: --rules path not found: {patterns_path}", file=sys.stderr)
            return 1

    # Load rules
    rules = load_rules(patterns_path)
    audit_rules_count = count_audit_rules()

    # --patterns: print summary of loaded patterns
    if args.patterns:
        print(f"Loaded {len(rules)} SAST patterns from {DEFAULT_PATTERNS_PATH}")
        print()
        for r in rules:
            print(f"  [{r.severity:8s}] {r.rule_id}: {r.description}")
        print()
        if audit_rules_count:
            uncovered = audit_rules_count - len(rules)
            if uncovered > 0:
                print(f"Note: rules/audit.rules has {audit_rules_count} rules total "
                      f"({uncovered} require manual review)")
        return 0

    # --stats: coverage statistics
    if args.stats:
        print_stats(rules, audit_rules_count)
        return 0

    # Run audit
    program_path = Path(args.program)
    if not program_path.exists():
        print(f"Error: program path does not exist: {program_path}", file=sys.stderr)
        return 1

    files_to_scan = [
        p for p in program_path.rglob("**/*.rs")
        if "target" not in p.parts and "tests" not in p.parts and ".git" not in p.parts
    ]
    if not files_to_scan:
        print(f"Warning: no .rs files found in {program_path}", file=sys.stderr)
        return 1

    findings = run_audit(program_path, rules)
    counts = severity_counts(findings)

    # Append coverage stats to output metadata
    output: dict[str, Any] = {
        "findings": [asdict(f) for f in findings],
        "summary": counts,
        "audit_type": "SAST",
        "engine": "solana-auditor-skill/sast",
        "version": SCRIPT_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "program": str(program_path),
        "rules_run": len(rules),
        "audit_rules_total": audit_rules_count,
        "rules_requiring_manual_review": max(0, audit_rules_count - len(rules)),
        "files_scanned": len(files_to_scan),
    }

    try:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(output, indent=2))
    except OSError as e:
        print(f"Error writing output file {args.output}: {e}", file=sys.stderr)
        return 2
    print(
        "SAST complete: %d findings -- "
        "%d CRITICAL, %d HIGH, %d MEDIUM, %d LOW, %d INFO"
        % (counts['total'], counts['critical'], counts['high'],
           counts['medium'], counts['low'], counts['info'])
    )
    print(f"  Files scanned      : {len(files_to_scan)}")
    print(f"  Automated rules run: {len(rules)}")
    if audit_rules_count > len(rules):
        print(f"  Manual rules       : {audit_rules_count - len(rules)} "
              "(use audit.rules for manual review)")
    print(f"  Output             : {args.output}")

    if args.verbose:
        for f in findings:
            print(f"  [{f.severity:8s}] {f.id}  {f.file}:{f.line}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
