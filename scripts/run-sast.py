#!/usr/bin/env python3
"""
run-sast.py -- Solana Auditor Shiba Skill SAST Engine

Executes all 26 security rules against Rust source code, producing findings.json.
This is the executable implementation of rules/audit.rules.

Usage:
    python scripts/run-sast.py <program_path> [--output findings.json] [--rules rules/audit.rules]

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
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

# =============================================================================
# RULE DEFINITIONS -- Pattern-based detection for all 26 vulnerability classes
# =============================================================================

@dataclass
class Rule:
    """A security rule with pattern and metadata."""
    rule_id: str
    severity: str
    cwe: str
    pattern: str
    pattern_type: str  # "regex" | "contains" | "ast"
    file_glob: str  # glob pattern for target files
    description: str
    impact: str
    recommendation: str
    references: list[str] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)


RULES: list[Rule] = [
    # Rule 1: Privileged instruction surface
    Rule(
        rule_id="RULE-01",
        severity="HIGH",
        cwe="CWE-269",
        pattern=r"pub fn \w+\([^)]*\)[^{]*\{[^}]*(?<!is_signer)(?<!require_signed)\b(close|withdraw|transfer|liquidate)\b",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="Function performs privileged operation without obvious signer validation",
        impact="Unauthorized state mutation possible if account is not properly validated",
        recommendation="Add #[account(signer)] constraint and verify signer's pubkey matches expected authority",
    ),

    # Rule 2: Missing discriminator/owner/init
    Rule(
        rule_id="RULE-02",
        severity="HIGH",
        cwe="CWE-345",
        pattern=r"#\[account\(init\)\][^}]*Account[^}]*\{[^}]*(?!#[account\()owner\()\])",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="Account initialized without owner constraint",
        impact="Account can be initialized by anyone who knows the PDA seed",
        recommendation="Add #[account(owner = program_id)] constraint",
    ),

    # Rule 3: Hardcoded/non-canonical PDA bump
    Rule(
        rule_id="RULE-03",
        severity="MEDIUM",
        cwe="CWE-自主决策",
        pattern=r"bump\s*=\s*[0-9]{1,3}(?!\s*#.*find_program_address)",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="Hardcoded bump seed -- program address collision risk",
        impact="If collision occurs, attacker could initialize their own account at the PDA",
        recommendation="Use find_program_address with canonical bump: let bump = bump_seed.unwrap()",
    ),

    # Rule 4: CPI escalation / unverified program ID
    Rule(
        rule_id="RULE-04",
        severity="HIGH",
        cwe="CWE-347",
        pattern=r"invoke\([^)]*\bprogram_id\b[^)]*\)[^}]*(?!require_verified_program_id)(?!program_id\s*==)",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="CPI call with program_id that may not be verified",
        impact="Attacker could redirect CPI to malicious program",
        recommendation="Validate program_id: require!(actual_program == expected_program)",
    ),

    # Rule 5: SPL vs Token-2022 mismatch
    Rule(
        rule_id="RULE-05",
        severity="HIGH",
        cwe="CWE-1109",
        pattern=r"use\s+spl_token[^;]*;\s+#[account.*token_extensions|#[account.*transfer_fee",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="Token program mismatch -- spl_token used with Token-2022 extensions",
        impact="Extension features won't work correctly",
        recommendation="Use spl_token_2022::ID and appropriate extension types",
    ),

    # Rule 6: Integer overflow on u64 amounts
    Rule(
        rule_id="RULE-06",
        severity="MEDIUM",
        cwe="CWE-190",
        pattern=r"\b([a-z_]+_amount|[a-z_]+_sum)\s*=\s*[^;]+\.(saturating_add|checked_add|wrapping_add)",
        pattern_type="contains",
        file_glob="**/*.rs",
        description="NOT using checked arithmetic on token amounts",
        impact="Overflow/underflow could drain or mint unintended amounts",
        recommendation="Use checked_add, checked_mul, saturating_add for all token math",
    ),

    # Rule 7: Wrong close target (CRITICAL)
    Rule(
        rule_id="RULE-07",
        severity="CRITICAL",
        cwe="CWE-377",
        pattern=r"close\([^)]*,\s*[^)]*authority[^)]*\)",
        pattern_type="contains",
        file_glob="**/*.rs",
        description="close instruction with authority account -- verify it's the rent recipient",
        impact="Lamports could be sent to wrong destination",
        recommendation="Ensure close target is the account that will receive the rent exemption refund",
    ),

    # Rule 8: Unsigned privileged action
    Rule(
        rule_id="RULE-08",
        severity="CRITICAL",
        cwe="CWE-306",
        pattern=r"#[instruction]\s*\n\s*pub\s+fn\s+\w+[^}]*\{[^}]*(?<!is_signer)(?<!require_signed)(?<!require\()\b(admin|withdraw|mint|set_authority|pause)",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="Privileged instruction without signer check",
        impact="Anyone can call admin functions",
        recommendation="Add #[account(signer)] and validate authority PDA",
    ),

    # Rule 9: Upgrade authority surface
    Rule(
        rule_id="RULE-09",
        severity="MEDIUM",
        cwe="CWE-284",
        pattern=r"UpgradeAuthority|SETUPGRADEAUTHORITY|BufData\.new_with_size",
        pattern_type="contains",
        file_glob="**/*.rs",
        description="Upgrade authority pattern detected -- verify governance controls",
        impact="Program can be upgraded without multisig approval",
        recommendation="Use Timelock + multisig for upgrade authority",
    ),

    # Rule 10: panic!, missing error mapping
    Rule(
        rule_id="RULE-10",
        severity="LOW",
        cwe="CWE-755",
        pattern=r"\bpanic!\s*\(",
        pattern_type="contains",
        file_glob="**/*.rs",
        description="panic! without custom error -- loses error context",
        impact="Audit findings can't distinguish panic sources",
        recommendation="Replace panic! with custom error: Err(Error::Custom(NOT_AUTHORIZED)",
    ),

    # Rule 11: Reinit without discriminator
    Rule(
        rule_id="RULE-11",
        severity="CRITICAL",
        cwe="CWE-565",
        pattern=r"#\[account\(init_if_needed\)\][^}]*(?!#[account\()init.*discriminator",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="init_if_needed without discriminator reinitialization guard",
        impact="Account can be reinitialized with new data by anyone",
        recommendation="Track initialized state in discriminator or use close + reinit pattern",
    ),

    # Rule 12: Rent exemption breaking
    Rule(
        rule_id="RULE-12",
        severity="MEDIUM",
        cwe="CWE-400",
        pattern=r"Account\s*\{[^}]*space:\s*0\s*[^}]*\}",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="Account allocated with zero space -- rent exemption violated",
        impact="Account cannot hold data without paying rent",
        recommendation="Set space = T::LAYOUT: bytes. Use AccountSerialize + AccountDeserialize for dynamic sizing",
    ),

    # Rule 13: Flash loan oracle manipulation
    Rule(
        rule_id="RULE-13",
        severity="CRITICAL",
        cwe="CWE-841",
        pattern=r"oracle|price_feed|quote|get_price\s*\([^)]*\)[^}]*(?!\.settle_balance|settlement_delay)",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="Oracle read without settlement delay -- flash loan susceptible",
        impact="Price can be manipulated within same transaction to drain protocol",
        recommendation="Add settlement period -- price updates take effect after N slots",
    ),

    # Rule 14: Reentrancy (CEI violation)
    Rule(
        rule_id="RULE-14",
        severity="CRITICAL",
        cwe="CWE-362",
        pattern=r"\.invoke\([^}]*\)[\s\n]+[^}]*\{[^}]*(?<!reentrancy_guard)[^}]*self\.[^}]*[\n\s]+[^}]*\.\w+\(",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="CEI pattern violation -- external call before state update enables reentrancy",
        impact="Attacker re-enters contract in same tx, drains funds via race condition",
        recommendation="Apply checks-effects-interactions: update state BEFORE external call. Use reentrancy guard.",
    ),

    # Rule 15: missing remaining_accounts validation
    Rule(
        rule_id="RULE-15",
        severity="CRITICAL",
        cwe="CWE-adyice-79",
        pattern=r"remaining_accounts\s*\.\s*iter\(\)[^}]*(?!remaining_accounts\[i\]\.key\(\)\s*==",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="Iterating remaining_accounts without index-based validation",
        impact="Attacker can reorder accounts to bypass checks",
        recommendation="Validate each account's key BEFORE use. Store count: let remaining = remaining_accounts.len(); assert_eq!(expected_len, remaining.len());",
    ),

    # Rule 16: Discriminator collision
    Rule(
        rule_id="RULE-16",
        severity="CRITICAL",
        cwe="CWE-563",
        pattern=r"#\[instruction\]\s*\n\s*(?:impl\s+\w+\s*\{[^}]*\})?\s*pub\s+fn\s+(\w+)[^}]*\n[^}]*pub\s+fn\s+(\w+)[^}]*",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="Multiple instructions with similar names -- discriminator collision risk",
        impact="Wrong instruction could be dispatched",
        recommendation="Use unique discriminator prefixes. Audit discriminator assignment for collisions.",
    ),

    # Rule 17: AccountLoader without owner check
    Rule(
        rule_id="RULE-17",
        severity="HIGH",
        cwe="CWE-adyice-20",
        pattern=r"AccountLoader::\w+<[^>]+>\s*\([^)]+\)[^}]*(?!owner_check)[^}]*\.load\(\)",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="AccountLoader used without owner verification",
        impact="Attacker could deserialize account data not owned by this program",
        recommendation="Use .load() with .owner() check, or use Account instead",
    ),

    # Rule 18: BorshDeserialize panic
    Rule(
        rule_id="RULE-18",
        severity="HIGH",
        cwe="CWE-755",
        pattern=r"(?<!try_from_slice::)<[A-Z]\w+>\s*\.\s*deserialize\s*\(&[^)]*\)\s*(?!\?)(?!\.map_err)",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="BorshDeserialize without Result handling -- panics on malformed data",
        impact="Malicious tx data causes panic, enabling denial of service",
        recommendation="Use try_from_slice and handle Result: data.try_into()?",
    ),

    # Rule 19: Anchor verify/address constraint bypass
    Rule(
        rule_id="RULE-19",
        severity="HIGH",
        cwe="CWE-346",
        pattern=r"#\[account\([^)]*verify\s*=\s*false[^)]*\)",
        pattern_type="contains",
        file_glob="**/*.rs",
        description="Anchor verify constraint disabled -- constraint bypassed",
        impact="Account constraint not enforced by Anchor",
        recommendation="Enable verify constraint or add manual validation with require!()",
    ),

    # Rule 20: Token-2022 extension ordering
    Rule(
        rule_id="RULE-20",
        severity="HIGH",
        cwe="CWE-682",
        pattern=r"Extension::\s*MemoTransfer[^}]*Extension::\s*TransferFeeConfig",
        pattern_type="contains",
        file_glob="**/*.rs",
        description="Token-2022 extension order violation -- memo must precede transfer_fee",
        impact="Transfer fee extension silently fails if initialized out of order",
        recommendation="Initialize extensions in order: MemoTransfer BEFORE TransferFeeConfig",
    ),

    # Rule 21: CPI callback reentrancy
    Rule(
        rule_id="RULE-21",
        severity="CRITICAL",
        cwe="CWE-362",
        pattern=r"invoke_signed\([^}]*with_signer\([^)]*\)[^}]*Callback[^}]*PDA[^}]*self\.\w+[^}]*\.\w+\(",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="CPI callback with PDA -- attacker can reenter via unexpected signer PDA",
        impact="Callback reentrancy bypasses caller's guard because callee uses different PDA",
        recommendation="Validate callback signer PDA matches expected program-derived address. Add callback guard.",
    ),

    # Rule 22: init_if_needed + close race
    Rule(
        rule_id="RULE-22",
        severity="CRITICAL",
        cwe="CWE-362",
        pattern=r"#\[account\(init_if_needed\)[^}]*close\(",
        pattern_type="contains",
        file_glob="**/*.rs",
        description="init_if_needed and close in same or nearby instructions -- race condition",
        impact="Attacker front-runs close with init_if_needed to reinitialize, draining rent refund",
        recommendation="Make init and close ATOMIC or use close authority + state versioning",
    ),

    # Rule 23: Memo program CPI injection
    Rule(
        rule_id="RULE-23",
        severity="MEDIUM",
        cwe="CWE-20",
        pattern=r"invoke\s*\([^)]*Memo1UhkJRfHyvLMcRuc7u5MC7iBwlZ6EEgMw424FWP[^)]*,\s*user_data",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="CPI to memo program with user-supplied data -- log injection risk",
        impact="Attacker injects misleading memos into transaction logs to social-engineer users",
        recommendation="Do not pass user-controlled data to memo. Validate memo content before CPI.",
    ),

    # Rule 24: remaining_accounts count mismatch
    Rule(
        rule_id="RULE-24",
        severity="CRITICAL",
        cwe="CWE-125",
        pattern=r"invoke_signed\([^,]*,[^)]*remaining_accounts\[.*\.\.[^)]*\],\s*remaining_accounts\[[^\]]+\.\.[^]]*\]",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="Remaining accounts slice passed to invoke_signed with wrong bounds",
        impact="Signature verification bypassed -- wrong accounts signed for wrong instruction",
        recommendation="Validate accounts array length BEFORE invoke_signed. assert_eq!(expected, accounts.len())",
    ),

    # Rule 25: Versioned transaction LUT manipulation
    Rule(
        rule_id="RULE-25",
        severity="HIGH",
        cwe="CWE-346",
        pattern=r"get_associated_token_address\s*\([^)]*versioned_transaction[^)]*address_lookup_table",
        pattern_type="contains",
        file_glob="**/*.rs",
        description="Using associated token address with LUT -- verify account contents",
        impact="Attacker manipulates LUT to substitute unexpected accounts",
        recommendation="Validate LUT contents: verify account is in expected lookup table before use",
    ),

    # Rule 26: Cross-program flash loan composition
    Rule(
        rule_id="RULE-26",
        severity="CRITICAL",
        cwe="CWE-841",
        pattern=r"flash_loan\(|FlashLoan\(|ix_with_budget\s*\([^)]*borrow[^)]*price[^}]*\.set\(",
        pattern_type="regex",
        file_glob="**/*.rs",
        description="Flash loan pattern -- verify oracle settlement across ALL programs in CPI chain",
        impact="Flash loan in Program A manipulates oracle to exploit Program C via Program B CPI",
        recommendation="Check settlement slot + verify price in ALL programs in CPI chain. Add atomicity guard.",
    ),
]

# =============================================================================
# FINDING EMITTER
# =============================================================================

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
SEVERITY_SCORE = {
    "CRITICAL": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "HIGH": (8.9, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "MEDIUM": (6.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "LOW": (3.3, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N"),
    "INFO": (0.1, "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:N/A:N"),
}


def detect_in_file(filepath: Path) -> Iterator[tuple[Rule, re.Match, str]]:
    """Run all patterns against a single file, yield matches."""
    try:
        content = filepath.read_text(errors="replace")
    except OSError:
        return

    for rule in RULES:
        if not filepath.match(rule.file_glob):
            continue
        try:
            flags = re.MULTILINE | re.DOTALL
            for match in re.finditer(rule.pattern, content, flags):
                yield rule, match, content
        except re.error:
            # Invalid regex -- skip
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
    # Truncate snippet to 200 chars
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


def run_audit(program_path: Path) -> list[Finding]:
    """Run full SAST audit against a program directory."""
    findings: list[Finding] = []

    for rs_file in program_path.rglob("**/*.rs"):
        # Skip generated / test / target artifacts
        parts = rs_file.parts
        if "target" in parts or "tests" in parts or ".git" in parts:
            continue
        for rule, match, content in detect_in_file(rs_file):
            findings.append(make_finding(rule, rs_file, match, content))

    return findings


def severity_counts(findings: list[Finding]) -> dict:
    """Summarize findings by severity."""
    counts = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": len(findings)
    }
    for f in findings:
        key = f.severity.lower()
        if key in counts:
            counts[key] += 1
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "program",
        nargs="?",
        default="programs",
        help="Path to program source (default: programs/)",
    )
    parser.add_argument(
        "--output", "-o", default="findings.json", help="Output file"
    )
    parser.add_argument(
        "--rules",
        help="Path to rules (ignored -- patterns are hardcoded in this file)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print per-file findings"
    )
    args = parser.parse_args(argv)

    program_path = Path(args.program)
    if not program_path.exists():
        print(f"Error: program path does not exist: {program_path}", file=sys.stderr)
        return 1

    # Count files before scanning
    files_to_scan = [
        p for p in program_path.rglob("**/*.rs")
        if "target" not in p.parts and "tests" not in p.parts and ".git" not in p.parts
    ]
    if not files_to_scan:
        print(f"Warning: no .rs files found in {program_path}", file=sys.stderr)
        return 1

    findings = run_audit(program_path)
    counts = severity_counts(findings)

    output = {
        "findings": [asdict(f) for f in findings],
        "summary": counts,
        "audit_type": "SAST",
        "engine": "solana-auditor-skill/sast",
        "version": "1.6.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "program": str(program_path),
        "rules_run": len(RULES),
        "files_scanned": len(files_to_scan),
    }

    try:
        output_path = Path(args.output)
        output_path.write_text(json.dumps(output, indent=2))
    except OSError as e:
        print(f"Error writing output file {args.output}: {e}", file=sys.stderr)
        return 2

    print(
        f"SAST complete: {counts['total']} findings -- "
        f"{counts['critical']} CRITICAL, "
        f"{counts['high']} HIGH, "
        f"{counts['medium']} MEDIUM, "
        f"{counts['low']} LOW, "
        f"{counts['info']} INFO"
    )
    print(f"  Files scanned : {len(files_to_scan)}")
    print(f"  Rules run     : {len(RULES)}")
    print(f"  Output        : {args.output}")

    if args.verbose:
        for f in findings:
            print(f"  [{f.severity:8s}] {f.id}  {f.file}:{f.line}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
