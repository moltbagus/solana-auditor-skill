#!/usr/bin/env python3
"""
audit-fix-suggestions.py — Fix suggestion engine for Solana Auditor Shiba Skill v1.7

Reads findings.json and generates inline fix suggestions for each finding type with:
- Confidence scoring based on prediction-market model
- Tier classification (A/B/C) for auto-apply decisions
- CVSS before/after calculation
- Patch generation with before/after code
- Verification test scaffolding

Usage:
    python scripts/audit-fix-suggestions.py [--input findings.json] [--output fix_suggestions.json]
    python scripts/audit-fix-suggestions.py --finding CRIT-01
    python scripts/audit-fix-suggestions.py --severity HIGH --severity CRITICAL
    python scripts/audit-fix-suggestions.py --apply --finding CRIT-01
    python scripts/audit-fix-suggestions.py --cvss-before-after --finding CRIT-01
    python scripts/audit-fix-suggestions.py --report
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ============================================================================
# Constants
# ============================================================================

SCRIPT_VERSION = "2.0.0"
RULES_COUNT = 26

# Fix tier thresholds
TIER_A_THRESHOLD = 0.90  # Auto-apply with notification
TIER_B_THRESHOLD = 0.60  # Assisted with confirmation
TIER_C_THRESHOLD = 0.00  # Manual, architectural

# Rule base rates for confidence scoring (prediction-market model)
RULE_BASE_RATES: dict[str, float] = {
    "Rule 1": 0.85,   # Privileged instruction surface
    "Rule 2": 0.95,   # Missing constraint
    "Rule 3": 0.95,   # Hardcoded bump
    "Rule 4": 0.90,   # CPI escalation
    "Rule 5": 0.85,   # Token mismatch
    "Rule 6": 0.98,   # Integer overflow
    "Rule 7": 0.95,   # Lamport drain
    "Rule 8": 0.98,   # Unsigned privileged
    "Rule 9": 0.80,   # Upgrade authority
    "Rule 10": 0.95,  # panic! usage
    "Rule 11": 0.95,  # Reinit without discriminator
    "Rule 12": 0.90,  # Rent exemption
    "Rule 13": 0.75,  # Flash loan oracle
    "Rule 14": 0.90,  # Reentrancy (CEI)
    "Rule 15": 0.95,  # remaining_accounts
    "Rule 16": 0.85,  # Discriminator collision
    "Rule 17": 0.95,  # AccountLoader owner
    "Rule 18": 0.98,  # BorshDeserialize panic
    "Rule 19": 0.90,  # Anchor constraint bypass
    "Rule 20": 0.80,  # Token-2022 ordering
    "Rule 21": 0.85,  # CPI callback reentrancy
    "Rule 22": 0.85,  # init_if_needed race
    "Rule 23": 0.95,  # Memo injection
    "Rule 24": 0.95,  # remaining_accounts mismatch
    "Rule 25": 0.80,  # LUT manipulation
    "Rule 26": 0.60,  # Flash loan composition
}

# Fix types
FIX_TYPES: dict[str, str] = {
    "Rule 2": "constraint_addition",
    "Rule 3": "pda_canonicalization",
    "Rule 6": "arithmetic_safety",
    "Rule 7": "architectural_refactor",
    "Rule 8": "validation_check",
    "Rule 10": "arithmetic_safety",
    "Rule 11": "state_guard",
    "Rule 14": "state_guard",
    "Rule 15": "validation_check",
    "Rule 16": "architectural_refactor",
    "Rule 17": "constraint_addition",
    "Rule 18": "arithmetic_safety",
    "Rule 19": "constraint_addition",
    "Rule 21": "state_guard",
    "Rule 22": "state_guard",
    "Rule 23": "validation_check",
    "Rule 24": "validation_check",
    "Rule 25": "validation_check",
    "Rule 26": "architectural_refactor",
}

# Poker risk by rule
RULE_POKER_RISK: dict[str, str] = {
    "Rule 2": "LOW",
    "Rule 3": "LOW",
    "Rule 4": "MEDIUM",
    "Rule 5": "MEDIUM",
    "Rule 6": "LOW",
    "Rule 7": "MEDIUM",
    "Rule 8": "LOW",
    "Rule 9": "HIGH",
    "Rule 10": "LOW",
    "Rule 11": "LOW",
    "Rule 12": "LOW",
    "Rule 13": "HIGH",
    "Rule 14": "MEDIUM",
    "Rule 15": "LOW",
    "Rule 16": "HIGH",
    "Rule 17": "LOW",
    "Rule 18": "LOW",
    "Rule 19": "LOW",
    "Rule 20": "MEDIUM",
    "Rule 21": "MEDIUM",
    "Rule 22": "MEDIUM",
    "Rule 23": "LOW",
    "Rule 24": "LOW",
    "Rule 25": "MEDIUM",
    "Rule 26": "HIGH",
}

# Estimated fix effort in minutes
RULE_EFFORT_MINUTES: dict[str, int] = {
    "Rule 2": 5,
    "Rule 3": 3,
    "Rule 4": 10,
    "Rule 5": 15,
    "Rule 6": 2,
    "Rule 7": 10,
    "Rule 8": 5,
    "Rule 9": 30,
    "Rule 10": 2,
    "Rule 11": 3,
    "Rule 12": 5,
    "Rule 13": 30,
    "Rule 14": 15,
    "Rule 15": 5,
    "Rule 16": 60,
    "Rule 17": 3,
    "Rule 18": 2,
    "Rule 19": 5,
    "Rule 20": 10,
    "Rule 21": 15,
    "Rule 22": 15,
    "Rule 23": 3,
    "Rule 24": 5,
    "Rule 25": 20,
    "Rule 26": 60,
}

# Rule ID to name mapping
RULE_NAMES: dict[str, str] = {
    "Rule 1": "Anchor Program Entry Point",
    "Rule 2": "Account Validation Constraints",
    "Rule 3": "PDA Canonical Bump",
    "Rule 4": "CPI Safety",
    "Rule 5": "Token Program Distinction",
    "Rule 6": "Arithmetic Overflow",
    "Rule 7": "Account Closing",
    "Rule 8": "Signer Verification",
    "Rule 9": "Upgrade Authority",
    "Rule 10": "Error Handling",
    "Rule 11": "Reinitialization Attacks",
    "Rule 12": "Rent and Lamport Safety",
    "Rule 13": "Flash Loan Attack Surface",
    "Rule 14": "Reentrancy Guard",
    "Rule 15": "remaining_accounts Validation",
    "Rule 16": "Discriminator Collision",
    "Rule 17": "AccountLoader vs Account",
    "Rule 18": "Borsh Deserialization Panic",
    "Rule 19": "Anchor verify/address Constraint",
    "Rule 20": "Token-2022 Extension Ordering",
    "Rule 21": "CPI Callback Reentrancy",
    "Rule 22": "init_if_needed + close Race",
    "Rule 23": "Memo Program CPI Injection",
    "Rule 24": "remaining_accounts Count Mismatch",
    "Rule 25": "Versioned Transaction LUT",
    "Rule 26": "Cross-Program Flash Loan",
}

# CWE references by rule
RULE_CWE_REFS: dict[str, list[str]] = {
    "Rule 2": ["https://www.cwe.mitre.org/data/definitions/285.html"],
    "Rule 3": ["https://cwe.mitre.org/data/definitions/340.html"],
    "Rule 4": [
        "https://www.cwe.mitre.org/data/definitions/862.html",
        "https://www.cwe.mitre.org/data/definitions/829.html",
    ],
    "Rule 6": [
        "https://www.cwe.mitre.org/data/definitions/190.html",
        "https://www.cwe.mitre.org/data/definitions/191.html",
    ],
    "Rule 7": [
        "https://www.cwe.mitre.org/data/definitions/252.html",
        "https://www.cwe.mitre.org/data/definitions/665.html",
    ],
    "Rule 8": [
        "https://www.cwe.mitre.org/data/definitions/306.html",
        "https://www.cwe.mitre.org/data/definitions/285.html",
    ],
    "Rule 11": [
        "https://www.cwe.mitre.org/data/definitions/665.html",
        "https://www.cwe.mitre.org/data/definitions/1188.html",
    ],
    "Rule 14": [
        "https://www.cwe.mitre.org/data/definitions/841.html",
        "https://www.cwe.mitre.org/data/definitions/362.html",
    ],
    "Rule 15": [
        "https://www.cwe.mitre.org/data/definitions/20.html",
        "https://www.cwe.mitre.org/data/definitions/862.html",
    ],
    "Rule 16": [
        "https://www.cwe.mitre.org/data/definitions/843.html",
        "https://www.cwe.mitre.org/data/definitions/20.html",
    ],
    "Rule 17": [
        "https://www.cwe.mitre.org/data/definitions/829.html",
        "https://www.cwe.mitre.org/data/definitions/345.html",
    ],
    "Rule 18": [
        "https://www.cwe.mitre.org/data/definitions/755.html",
        "https://www.cwe.mitre.org/data/definitions/248.html",
    ],
}

# Documentation references by rule
RULE_DOC_REFS: dict[str, list[str]] = {
    "Rule 1": [
        "https://www.anchor-lang.com/docs/the-program",
        "https://github.com/trailofbits/solana-common-pitfalls",
    ],
    "Rule 2": [
        "https://www.anchor-lang.com/docs/account-constraints",
        "https://github.com/coral-xyz/anchor/blob/master/lang/src/account.rs",
    ],
    "Rule 3": [
        "https://docs.solana.com/developing/programming-model/calling-between-programs#program-derived-addresses",
    ],
    "Rule 4": [
        "https://wormholecrypto.medium.com/wormhole-incident-report-02-02-22-ad9d9e1a0484",
        "https://github.com/neodyme-labs/solana-security-txt",
    ],
    "Rule 5": [
        "https://spl.solana.com/token-2022",
        "https://www.anchor-lang.com/docs/tokens/extensions",
    ],
    "Rule 6": [
        "https://docs.rs/anchor-lang/latest/anchor_lang/prelude/struct.Accounts.html",
        "https://github.com/anza-xyz/solana-program-library/tree/master/libraries/math",
    ],
    "Rule 7": [
        "https://twitter.com/CremaProtocol/status/1545852085030305792",
        "https://www.anchor-lang.com/docs/account-constraints#close",
    ],
    "Rule 8": [
        "https://docs.rs/anchor-lang/latest/anchor_lang/accounts/struct.Signer.html",
    ],
    "Rule 11": [
        "https://github.com/coral-xyz/anchor/blob/master/lang/src/account.rs",
    ],
    "Rule 14": [
        "https://github.com/trailofbits/solana-common-pitfalls#reentrancy",
    ],
    "Rule 15": [
        "https://www.raydium.io/blog/",
    ],
    "Rule 16": [
        "https://github.com/coral-xyz/anchor/blob/master/lang/src/account.rs",
    ],
    "Rule 17": [
        "https://mango.markets/",
    ],
    "Rule 18": [
        "https://borsh.io/",
        "https://github.com/coral-xyz/anchor/blob/master/lang/src/account.rs",
    ],
}


# ============================================================================
# Dataclasses
# ============================================================================


@dataclass
class FixSuggestion:
    """Fix suggestion for a single finding."""

    finding_id: str
    severity: str
    rule_id: str
    file: str
    line: int
    before_code: str
    after_code: str
    explanation: str
    references: list[str]
    # New fields for v2.0
    confidence_score: float = 0.0
    fix_tier: str = "C"
    fix_type: str = "validation_check"
    poker_risk: str = "MEDIUM"
    estimated_effort_minutes: int = 10
    cvss_before: float = 0.0
    cvss_after: float = 0.0
    cvss_reduction: float = 0.0
    test_template: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RemediationBlock:
    """Remediation block for findings.json."""

    fix_tier: str
    confidence_score: float
    fix_type: str
    patch: dict[str, Any]
    cvss_after: dict[str, Any]
    poker_risk: str
    estimated_effort_minutes: int
    status: str = "pending"
    applied_at: Optional[str] = None
    applied_by: Optional[str] = None
    verification: dict[str, Any] = field(default_factory=lambda: {
        "anchor_test": None,
        "anchor_build_pass": False,
        "formal_verified": False,
        "regression_pass": False,
        "verified_at": None,
    })
    history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FixSuggestionsOutput:
    """Output structure for fix_suggestions.json."""

    generated_at: str
    program_id: str
    version: str
    total_findings: int
    suggestions: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ============================================================================
# Confidence & Tier Computation
# ============================================================================


def compute_confidence(rule_id: str, pattern_match: bool = True) -> float:
    """
    Compute confidence score using prediction-market model.

    Args:
        rule_id: Rule identifier (e.g., "Rule 8")
        pattern_match: Whether the finding exactly matches a known fix pattern

    Returns:
        Confidence score between 0.0 and 1.0
    """
    base_rate = RULE_BASE_RATES.get(rule_id, 0.70)
    pattern_bonus = 1.0 if pattern_match else 0.85
    return round(base_rate * pattern_bonus, 2)


def determine_tier(confidence: float, poker_risk: str) -> str:
    """
    Determine fix tier based on confidence and poker risk.

    Args:
        confidence: Confidence score
        poker_risk: Risk of the fix introducing new bugs

    Returns:
        Tier string (A, B, or C)
    """
    # Risk escalation: HIGH/CRITICAL poker risk -> Tier C
    if poker_risk in ("HIGH", "CRITICAL"):
        return "C"
    if confidence >= TIER_A_THRESHOLD:
        return "A"
    if confidence >= TIER_B_THRESHOLD:
        return "B"
    return "C"


def estimate_cvss_after(cvss_before: float, rule_id: str) -> tuple[float, str]:
    """
    Estimate post-fix CVSS score based on rule type.

    Args:
        cvss_before: Pre-fix CVSS score
        rule_id: Rule identifier

    Returns:
        Tuple of (estimated_cvss_after, estimated_vector)
    """
    # Rules that fully fix the vulnerability
    full_fix_rules = {"Rule 8", "Rule 18", "Rule 6"}
    # Rules that reduce but don't eliminate
    partial_fix_rules = {"Rule 3", "Rule 7", "Rule 14", "Rule 15"}
    # Rules requiring architectural changes
    architectural_rules = {"Rule 26", "Rule 13", "Rule 9"}

    if rule_id in full_fix_rules:
        reduction = cvss_before * 0.25  # 25% reduction
    elif rule_id in partial_fix_rules:
        reduction = cvss_before * 0.15  # 15% reduction
    elif rule_id in architectural_rules:
        reduction = cvss_before * 0.10  # 10% reduction (architectural fixes may not fully address)
    else:
        reduction = cvss_before * 0.20  # 20% default

    cvss_after = max(1.0, round(cvss_before - reduction, 1))
    # Estimate vector (simplified - assumes some metrics change)
    if rule_id == "Rule 8":  # Adding signer check increases PR
        vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    else:
        vector = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # Default

    return cvss_after, vector


def get_fix_type(rule_id: str) -> str:
    """Get fix type for a rule."""
    return FIX_TYPES.get(rule_id, "validation_check")


def get_poker_risk(rule_id: str) -> str:
    """Get poker risk for a rule."""
    return RULE_POKER_RISK.get(rule_id, "MEDIUM")


def get_effort_minutes(rule_id: str) -> int:
    """Get estimated effort in minutes for a rule."""
    return RULE_EFFORT_MINUTES.get(rule_id, 10)


def generate_test_template(rule_id: str, finding_id: str) -> str:
    """Generate a verification test template for a rule."""
    test_templates = {
        "Rule 8": f'''#[test]
fn test_{finding_id.lower()}_requires_signer() {{
    // Attempt privileged action without admin signer should fail
    // Attempt with admin signer should succeed
}}''',
        "Rule 6": f'''#[test]
fn test_{finding_id.lower()}_overflow_protection() {{
    // Overflow amounts should return ArithmeticOverflow error
}}''',
        "Rule 14": f'''#[test]
fn test_{finding_id.lower()}_reentrancy_guard() {{
    // Reentrant callback should fail with ReentrancyDetected
}}''',
        "Rule 15": f'''#[test]
fn test_{finding_id.lower()}_remaining_accounts_validation() {{
    // Invalid remaining accounts should fail validation
}}''',
    }
    base_template = test_templates.get(rule_id, f'''#[test]
fn test_{finding_id.lower()}_fix_verification() {{
    // Verify the fix for Rule {rule_id}
    // Add specific assertions based on the vulnerability
}}''')
    return base_template


def format_tier_a_notification(suggestion: FixSuggestion) -> str:
    """Format Tier A auto-fix notification."""
    return f"""
[Tier A Auto-Fix] Applied {suggestion.finding_id} fix to {suggestion.file}
  Added fix for Rule {suggestion.rule_id}
  Confidence: {suggestion.confidence_score:.0%} | CVSS reduction: {suggestion.cvss_before} -> {suggestion.cvss_after}
"""


def format_tier_b_prompt(suggestion: FixSuggestion) -> str:
    """Format Tier B confirmation prompt."""
    output = []
    output.append(f"\n[Tier B Assisted Fix] Fix suggestion for {suggestion.finding_id}")
    output.append("")
    output.append("  BEFORE:")
    for line in suggestion.before_code.strip().split("\n")[:5]:
        output.append(f"    {line}")
    output.append("")
    output.append("  AFTER:")
    for line in suggestion.after_code.strip().split("\n")[:5]:
        output.append(f"    {line}")
    output.append("")
    output.append(f"  Confidence: {suggestion.confidence_score:.0%} | CVSS reduction: {suggestion.cvss_before} -> {suggestion.cvss_after}")
    output.append(f"  Estimated effort: {suggestion.estimated_effort_minutes} min | Poker risk: {suggestion.poker_risk}")
    output.append("")
    output.append("  [APPLY] [EDIT] [REJECT]")

    return "\n".join(output)


def format_tier_c_guidance(suggestion: FixSuggestion) -> str:
    """Format Tier C manual guidance."""
    output = []
    output.append(f"\n[Tier C Manual Fix] {suggestion.finding_id} requires architectural review")
    output.append("")
    output.append(f"  Root cause: {suggestion.explanation[:100]}...")
    output.append("")
    output.append("  This finding requires manual remediation due to:")
    output.append(f"  - Low confidence score: {suggestion.confidence_score:.0%}")
    output.append(f"  - Poker risk: {suggestion.poker_risk}")
    output.append("")
    output.append("  Recommended approach:")
    output.append(f"    1. Review skill/06-remediation.md, Rule {suggestion.rule_id}")
    output.append("    2. Design fix with architecture review")
    output.append("    3. Implement with full test coverage")
    output.append("    4. Verify with formal methods if available")
    output.append("")
    output.append(f"  CVSS reduction after fix: {suggestion.cvss_before} -> {suggestion.cvss_after} (estimated)")
    output.append(f"  Estimated effort: {suggestion.estimated_effort_minutes} min")
    output.append("")
    output.append("  Reference: skill/06-remediation.md")

    return "\n".join(output)


# ============================================================================
# Fix Template Library
# ============================================================================


@dataclass
class FixTemplate:
    """Template for generating before/after code patterns."""

    before: str
    after: str
    explanation: str


def get_fix_template(rule_id: str, finding_id: str) -> FixTemplate:
    """
    Return the appropriate fix template for a given rule.

    Args:
        rule_id: Rule identifier (e.g., "Rule 8")
        finding_id: Finding identifier (e.g., "VULN-01")

    Returns:
        FixTemplate with before_code, after_code, and explanation
    """

    templates: dict[str, FixTemplate] = {

        # -------------------------------------------------------------------------
        # Rule 1: Anchor Program Entry Point
        # -------------------------------------------------------------------------
        "Rule 1": FixTemplate(
            before="""// Analyze instruction context before making changes
pub fn instruction_name(ctx: Context<InstructionAccounts>, arg: u64) -> Result<()> {
    // UNSAFE: Editing privileged code without understanding full instruction surface
    ctx.accounts.target.rebalance -= arg;
    Ok(())
}""",
            after="""// SECURE: Map full instruction surface and identify privileged mutations
// BEFORE editing: Identify all instructions that touch this account
// KEY CHECKS: Signer verification, amount limits, state transitions
pub fn instruction_name(ctx: Context<InstructionAccounts>, arg: u64) -> Result<()> {
    require_signed!(ctx.accounts.admin);  // Add signer guard
    require!(arg <= MAX_WITHDRAWAL, VaultError::ExceedsLimit);
    ctx.accounts.target.rebalance = ctx.accounts.target.rebalance
        .checked_sub(arg)
        .ok_or(VaultError::ArithmeticError)?;
    Ok(())
}""",
            explanation="Privileged instruction surface requires comprehensive analysis. "
                        "Before editing any program entry point, map all instructions that "
                        "touch the account, identify all privileged operations, and add "
                        "appropriate guards (signer checks, amount limits, state validation).",
        ),

        # -------------------------------------------------------------------------
        # Rule 2: Account Validation Constraints
        # -------------------------------------------------------------------------
        "Rule 2": FixTemplate(
            before="""#[derive(Accounts)]
pub struct Initialize<'info> {
    pub vault: AccountInfo<'info>,  // MISSING: discriminator, owner, init
    pub user: AccountInfo<'info>,   // MISSING: signer constraint
}""",
            after="""#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,                           // Writes 8-byte discriminator
        payer = user,                   // Rent payer
        space = 8 + VaultState::LEN,   // Account size
        seeds = [b"vault", admin.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, VaultState>,  // Anchor enforces discriminator
    #[account(mut)]
    pub user: Signer<'info>,                  // Enforces signer
    pub system_program: Program<'info, System>,
}""",
            explanation="Account constraints must include: (1) discriminator via "
                        "`#[account]` or `init`, (2) owner verification via `Account<T>`, "
                        "(3) signer constraint for privileged operations, (4) space allocation "
                        "for init. Anchor's `Account<T>` validates ownership and discriminator.",
        ),

        # -------------------------------------------------------------------------
        # Rule 3: PDA Canonical Bump
        # -------------------------------------------------------------------------
        "Rule 3": FixTemplate(
            before="""// UNSAFE: Hardcoded bump literal
let bump = 254;  // attacker can find alternative bump
let vault_pda = Pubkey::create_program_address(
    &[b"vault", user.key().as_ref(), &[bump]],
    program_id
)?;""",
            after="""// SECURE: Use canonical bump from Anchor context
let bump = ctx.bumps.vault;  // Anchor 0.30+ returns canonical bump
let seeds = &[b"vault", user.key().as_ref(), &[bump]];
let vault_pda = Pubkey::create_program_address(seeds, program_id)
    .map_err(|_| VaultError::InvalidPda)?;

// Or: Manual derivation with find_program_address
let (vault_pda, canonical_bump) = Pubkey::find_program_address(
    &[b"vault", user.key().as_ref()],
    program_id
);""",
            explanation="Hardcoded bump values are unsafe because any valid bump "
                        "produces a PDA. Use `ctx.bumps.<name>` from Anchor (canonical "
                        "by default), or `Pubkey::find_program_address` which returns "
                        "the highest valid bump (0xFF -> 0x00). Store only canonical bumps.",
        ),

        # -------------------------------------------------------------------------
        # Rule 4: CPI Safety
        # -------------------------------------------------------------------------
        "Rule 4": FixTemplate(
            before="""// UNSAFE: No program ID validation
pub fn exec_callback(ctx: Context<Callback>, data: Vec<u8>) -> Result<()> {
    let target = ctx.accounts.target_program.key();
    let instruction = Instruction {
        program_id: target,  // attacker-supplied program
        accounts: ctx.remaining_accounts().to_vec(),
        data: data,
    };
    invoke(&instruction, &ctx.accounts.to_account_infos())?;
    Ok(())
}""",
            after="""// SECURE: Validate program ID against allowlist
use solana_program::program::set_return_data;

const ALLOWED_PROGRAMS: &[Pubkey] = &[
    spl_token::ID,
    system_program::ID,
];

pub fn exec_callback(ctx: Context<Callback>, data: Vec<u8>) -> Result<()> {
    let target = ctx.accounts.target_program.key();

    // VALIDATE: Program must be in allowlist
    require!(
        ALLOWED_PROGRAMS.contains(&target),
        CallbackError::UnauthorizedProgram
    );

    let instruction = Instruction {
        program_id: target,
        accounts: ctx.remaining_accounts().to_vec(),
        data: data,
    };
    invoke(&instruction, &ctx.accounts.to_account_infos())?;
    Ok(())
}""",
            explanation="CPI to user-supplied programs enables privilege escalation. "
                        "Always validate program IDs against an allowlist or use typed "
                        "`Program<T>` wrappers. Never accept arbitrary program IDs without "
                        "verification.",
        ),

        # -------------------------------------------------------------------------
        # Rule 5: Token Program Distinction
        # -------------------------------------------------------------------------
        "Rule 5": FixTemplate(
            before="""// UNSAFE: No token program validation
pub fn transfer_tokens(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    let mint = &ctx.accounts.mint;
    // MISSING: Verify mint owner is expected token program
    anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)
}""",
            after="""// SECURE: Validate token program ID
pub fn transfer_tokens(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    let mint = &ctx.accounts.mint;

    // VALIDATE: Verify token program matches expectation
    match ctx.accounts.token_program.key() {
        key if key == spl_token::ID => {
            // SPL Token
        }
        key if key == spl_token_2022::ID => {
            // Token-2022: handle extensions
        }
        _ => return Err(TokenError::InvalidTokenProgram.into()),
    }

    // VALIDATE: Mint owner
    require!(
        mint.owner == ctx.accounts.token_program.key(),
        TokenError::InvalidMintOwner
    );

    anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)
}""",
            explanation="SPL Token and Token-2022 are incompatible. Mixing programs "
                        "causes failures or security issues. Always verify the token "
                        "program ID and handle Token-2022 extensions appropriately.",
        ),

        # -------------------------------------------------------------------------
        # Rule 6: Arithmetic Overflow
        # -------------------------------------------------------------------------
        "Rule 6": FixTemplate(
            before="""// UNSAFE: Default arithmetic wraps in release mode
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.total_deposits = vault.total_deposits + amount;  // overflow wraps silently
    vault.user_balance[user_idx] += amount;
    Ok(())
}""",
            after="""// SECURE: Use checked arithmetic
use anchor_lang::prelude::borsh::BorshDeserialize;

pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;

    // CHECKED: Overflow returns error
    vault.total_deposits = vault.total_deposits
        .checked_add(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;

    vault.user_balance[user_idx] = vault.user_balance[user_idx]
        .checked_add(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;

    Ok(())
}

// Also use checked_sub, checked_mul, checked_div as appropriate""",
            explanation="Rust's default arithmetic wraps in release mode. "
                        "Always use `checked_add`, `checked_sub`, `checked_mul`, "
                        "`checked_div` for u64/u128 on user-controlled amounts. "
                        "Wrap returns `Option`, propagate with `?` or handle explicitly.",
        ),

        # -------------------------------------------------------------------------
        # Rule 7: Account Closing / Lamport Drain
        # -------------------------------------------------------------------------
        "Rule 7": FixTemplate(
            before="""// UNSAFE: No authority check on close target
#[derive(Accounts)]
pub struct CloseAccount<'info> {
    pub account: AccountInfo<'info>,
    pub destination: AccountInfo<'info>,  // attacker can set this
}""",
            after="""// SECURE: Verify close authority
#[derive(Accounts)]
pub struct CloseAccount<'info> {
    #[account(
        mut,
        close = authority  // Anchor transfers to VERIFIED authority
    )]
    pub account: Account<'info, UserAccount>,
    #[account(seeds = [b"admin"], bump)]
    pub authority: SystemAccount<'info>,
    pub user: Signer<'info>,
}

pub fn close_account(ctx: Context<CloseAccount>) -> Result<()> {
    // Close authority is bound via #[account(close = authority)]
    // Anchor verifies authority signs and transfers lamports
    Ok(())
}""",
            explanation="The `close` constraint specifies the lamport drain target. "
                        "Never let users supply the close target. Use a verified authority "
                        "(signer, PDA derived from signers, or `has_one` constraint) as "
                        "the close target.",
        ),

        # -------------------------------------------------------------------------
        # Rule 8: Signer Verification (CRITICAL)
        # -------------------------------------------------------------------------
        "Rule 8": FixTemplate(
            before="""// CRITICAL: No signer verification
#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    pub vault: AccountInfo<'info>,      // No Signer constraint
    pub admin: AccountInfo<'info>,      // Any account can be passed
    pub destination: AccountInfo<'info>,
}

pub fn admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64) -> Result<()> {
    // NO signer check - anyone can withdraw!
    let vault = ctx.accounts.vault;
    **vault.try_borrow_mut_lamports()? -= amount;
    **ctx.accounts.destination.try_borrow_mut_lamports()? += amount;
    Ok(())
}""",
            after="""// SECURE: Signer verification on privileged action
#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    #[account(
        mut,
        has_one = admin  // Binds vault.authority to admin
    )]
    pub vault: Account<'info, VaultState>,
    pub admin: Signer<'info>,           // Anchor enforces signer
    #[account(mut)]
    pub destination: SystemAccount<'info>,
}

pub fn admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64) -> Result<()> {
    // Anchor verified admin signed via Signer<'info>
    // has_one verified vault.authority == admin.key()
    require!(
        ctx.accounts.vault.total >= amount,
        VaultError::InsufficientFunds
    );
    ctx.accounts.vault.total -= amount;
    // Transfer via SystemProgram
    anchor_lang::system_program::transfer(
        CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.vault.to_account_info(),
                to: ctx.accounts.destination.to_account_info(),
            },
        ),
        amount,
    )?;
    Ok(())
}""",
            explanation="Every privileged action requires signer verification. "
                        "Use `Signer<'info>` in Anchor (enforced at deserialization) "
                        "or explicit `is_signer` checks with `AccountInfo`. Add "
                        "`has_one` or `address` constraints to bind authorities.",
        ),

        # -------------------------------------------------------------------------
        # Rule 9: Upgrade Authority
        # -------------------------------------------------------------------------
        "Rule 9": FixTemplate(
            before="""# Upgrade authority is single key (MEDIUM risk)
[programs.localnet]
vault = "..."

[programs.cluster]
vault = "..."

[registry]
url = "https://anchor.project-serum.com"

[provider]
cluster = "mainnet"
wallet = "~/.config/solana/id.json"

[anchor-debug]
# No upgrade authority specified - defaults to wallet""",
            after="""# RECOMMENDED: Multisig upgrade authority via Squads
[programs.localnet]
vault = "..."

[programs.cluster]
vault = "..."

[programs.mainnet]
vault = "..."

# Upgrade authority via Squads multisig (recommended for production)
[authority]
# Replace with Squads V3 PDA after initialization
upgrade_authority = "REPLACE_WITH_SQUADS_MULTISIG_PDA"

[anchor-debug]
# log_level = "info"

[provider]
cluster = "mainnet"
# Consider using a hardware wallet or air-gapped key for the multisig""",
            explanation="Single-key upgrade authority is a single point of failure. "
                        "Transfer upgrade authority to a multisig (Squads, Realms) "
                        "or a timelock PDA for production programs.",
        ),

        # -------------------------------------------------------------------------
        # Rule 10: Error Handling
        # -------------------------------------------------------------------------
        "Rule 10": FixTemplate(
            before="""// UNSAFE: panic! in instruction
pub fn unsafe_instruction(ctx: Context<Unsafe>, data: Vec<u8>) -> Result<()> {
    let parsed = parse_data(&data)?;
    if parsed.value > 1000 {
        panic!("Value too high: {}", parsed.value);  // Never panic!
    }
    Ok(())
}""",
            after="""// SECURE: Typed error propagation
use anchor_lang::error::ErrorCode;

#[error_code]
pub enum VaultError {
    #[msg("Value exceeds maximum allowed")]
    ValueTooHigh,
    #[msg("Arithmetic overflow occurred")]
    ArithmeticOverflow,
    #[msg("Account not initialized")]
    Uninitialized,
    #[msg("Invalid authority")]
    Unauthorized,
}

pub fn safe_instruction(ctx: Context<Unsafe>, data: Vec<u8>) -> Result<()> {
    let parsed = parse_data(&data)?;
    require!(
        parsed.value <= MAX_VALUE,
        VaultError::ValueTooHigh
    );
    // Use ? propagation instead of unwrap/expect
    let processed = process_value(parsed.value)?;
    ctx.accounts.target.value = processed;
    Ok(())
}

fn process_value(val: u64) -> Result<u64> {
    val.checked_mul(2).ok_or(VaultError::ArithmeticOverflow)
}""",
            explanation="Never use `panic!` or `unwrap`/`expect` in instruction code. "
                        "Use typed Anchor errors via `err!()` or the `#[error_code]` enum. "
                        "Propagate all Results with `?`.",
        ),

        # -------------------------------------------------------------------------
        # Rule 11: Reinitialization Attacks
        # -------------------------------------------------------------------------
        "Rule 11": FixTemplate(
            before="""// UNSAFE: Manual init without discriminator check
#[derive(Clone)]
pub struct VaultState {
    pub authority: Pubkey,
    pub total: u64,
}

pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    let vault = ctx.accounts.vault;
    // NO discriminator check - can reinit
    vault.authority = ctx.accounts.admin.key();
    vault.total = 0;
    Ok(())
}""",
            after="""// SECURE: Use Anchor Account or check discriminator
#[account]
pub struct VaultState {
    pub authority: Pubkey,
    pub total: u64,
}

impl VaultState {
    pub const LEN: usize = 32 + 8;
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + VaultState::LEN,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, VaultState>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    ctx.accounts.vault.authority = ctx.accounts.admin.key();
    ctx.accounts.vault.total = 0;
    // Anchor's init writes discriminator automatically
    Ok(())
}""",
            explanation="Manual initialization must check the 8-byte discriminator "
                        "to prevent reinitialization attacks. Use `#[account(init, ...)]` "
                        "which writes discriminator atomically, or manually check "
                        "`account.data.borrow()[..8] == MyAccount::DISCRIMINATOR`.",
        ),

        # -------------------------------------------------------------------------
        # Rule 12: Rent and Lamport Safety
        # -------------------------------------------------------------------------
        "Rule 12": FixTemplate(
            before="""// UNSAFE: Manual account creation without rent
pub fn create_account_unsafe(
    ctx: Context<CreateAccount>,
    lamports: u64,
    space: u64,
) -> Result<()> {
    let account = ctx.accounts.target.to_account_info();
    let vault = ctx.accounts.vault.to_account_info();

    // MISSING: Rent exemption check
    let balance = account.lamports();
    if balance < lamports {
        return Err(VaultError::InsufficientFunds.into());
    }
    // ...
}""",
            after="""// SECURE: Use SystemInstruction::create_account or Anchor init
use solana_program::rent::Rent;
use solana_program::system_instruction::create_account;

pub fn create_account_safe(
    ctx: Context<CreateAccount>,
    space: u64,
) -> Result<()> {
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(space as usize);

    let ix = create_account(
        &ctx.accounts.payer.key(),
        &ctx.accounts.target.key(),
        lamports,
        space,
        &ctx.program_id,
    );

    solana_program::program::invoke(
        &ix,
        &[
            ctx.accounts.payer.to_account_info(),
            ctx.accounts.target.to_account_info(),
            ctx.accounts.system_program.to_account_info(),
        ],
    )?;

    // Verify rent exemption after creation
    let rent = Rent::get()?;
    require!(
        rent.is_exempt(
            ctx.accounts.target.get_lamports(),
            ctx.accounts.target.data_len(),
        ),
        VaultError::NotRentExempt
    );
    Ok(())
}""",
            explanation="Manual account creation must ensure rent exemption. "
                        "Use Anchor's `init` constraint (handles rent automatically) "
                        "or manually calculate with `Rent::get()?.minimum_balance(size)`.",
        ),

        # -------------------------------------------------------------------------
        # Rule 13: Flash Loan Attack Surface
        # -------------------------------------------------------------------------
        "Rule 13": FixTemplate(
            before="""// UNSAFE: Price from single source, no staleness check
pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
    let price = ctx.accounts.price_feed.price;  // No staleness check
    let collateral_value = ctx.accounts.collateral_amount * price;

    require!(
        collateral_value >= amount * MIN_COLLATERAL_RATIO,
        VaultError::InsufficientCollateral
    );
    // ...
}""",
            after="""// SECURE: Multi-source price with staleness and confidence checks
use solana_program::clock::Clock;

const MAX_PRICE_AGE_SECONDS: i64 = 60;
const MAX_CONFIDENCE_INTERVAL: u64 = 100;  // basis points

pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
    let clock = Clock::get()?;

    // CHECK: Price staleness
    let price_data = &ctx.accounts.price_feed;
    let slot_age = clock.slot - price_data.last_update_slot;
    require!(
        slot_age <= MAX_PRICE_AGE_SECONDS / 400,  // ~400ms per slot
        PriceError::StalePrice
    );

    // CHECK: Timestamp freshness (if available)
    let timestamp_age = clock.unix_timestamp - price_data.timestamp;
    require!(
        timestamp_age <= MAX_PRICE_AGE_SECONDS,
        PriceError::StaleTimestamp
    );

    // CHECK: Confidence interval
    require!(
        price_data.confidence <= MAX_CONFIDENCE_INTERVAL,
        PriceError::HighConfidence
    );

    let price = price_data.price;
    let collateral_value = collateral
        .amount
        .checked_mul(price)
        .ok_or(VaultError::ArithmeticOverflow)?;

    require!(
        collateral_value >= amount
            .checked_mul(MIN_COLLATERAL_RATIO)
            .ok_or(VaultError::ArithmeticOverflow)?,
        VaultError::InsufficientCollateral
    );
    Ok(())
}""",
            explanation="Flash loan attacks exploit price staleness and balance "
                        "snapshot timing. Verify price staleness (slot/timestamp), "
                        "use multiple oracle sources, and take balance snapshots "
                        "AFTER all state changes and flash loan repayments.",
        ),

        # -------------------------------------------------------------------------
        # Rule 14: Reentrancy Guard (CRITICAL)
        # -------------------------------------------------------------------------
        "Rule 14": FixTemplate(
            before="""// CRITICAL: State mutation after external call
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let user = &mut ctx.accounts.user;
    require!(user.balance >= amount, VaultError::InsufficientFunds);

    // UNSAFE: External call BEFORE state update
    anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)?;

    // STATE UPDATE AFTER EXTERNAL CALL - reentrancy window open!
    user.balance -= amount;
    ctx.accounts.vault.total -= amount;
    Ok(())
}""",
            after="""// SECURE: CEI pattern with reentrancy guard
#[account]
pub struct VaultState {
    pub authority: Pubkey,
    pub total: u64,
    pub in_progress: bool,  // Reentrancy guard flag
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let user = &mut ctx.accounts.user;
    let vault = &mut ctx.accounts.vault;

    // CHECK: Balance and guard
    require!(user.balance >= amount, VaultError::InsufficientFunds);
    require!(!vault.in_progress, VaultError::ReentrancyDetected);

    // EFFECT: Update state BEFORE external call (CEI)
    user.balance = user.balance
        .checked_sub(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;
    vault.total = vault.total
        .checked_sub(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;
    vault.in_progress = true;

    // INTERACTION: External call LAST
    anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)?;

    // Reset guard after external call completes
    vault.in_progress = false;
    Ok(())
}""",
            explanation="CEI (Checks-Effects-Interactions) pattern: all state checks "
                        "and modifications MUST complete before any external call. "
                        "Use a reentrancy lock flag when the protocol handles callbacks "
                        "or token transfers. Execute token transfers LAST.",
        ),

        # -------------------------------------------------------------------------
        # Rule 15: remaining_accounts Validation (CRITICAL)
        # -------------------------------------------------------------------------
        "Rule 15": FixTemplate(
            before="""// CRITICAL: No remaining_accounts validation
pub fn cpi_with_remaining(
    ctx: Context<CpiCall>,
    data: Vec<u8>,
) -> Result<()> {
    let remaining = ctx.remaining_accounts();

    // UNSAFE: Pass all remaining accounts without validation
    let instruction = Instruction {
        program_id: ctx.accounts.target_program.key(),
        accounts: remaining.to_vec(),
        data: data,
    };
    invoke(&instruction, &remaining.to_account_infos())?;
    Ok(())
}""",
            after="""// SECURE: Validate all remaining accounts
pub fn cpi_with_remaining(
    ctx: Context<CpiCall>,
    data: Vec<u8>,
) -> Result<()> {
    let remaining = ctx.remaining_accounts();
    let expected_count = 3;
    let expected_program = spl_token::ID;

    // VALIDATE: Count
    require!(
        remaining.len() == expected_count,
        CpiError::InvalidAccountCount
    );

    // VALIDATE: Each account
    let (user, vault, mint) = match remaining.as_slice() {
        [user, vault, mint] => (user, vault, mint),
        _ => return Err(CpiError::InvalidAccountLayout.into()),
    };

    require!(user.is_signer, CpiError::ExpectedSigner);
    require!(user.owner == &expected_program, CpiError::InvalidOwner);
    require!(vault.is_writable, CpiError::ExpectedWritable);

    // Now safe to use
    let instruction = Instruction {
        program_id: ctx.accounts.target_program.key(),
        accounts: remaining.to_vec(),
        data: data,
    };
    invoke(&instruction, &remaining.to_account_infos())?;
    Ok(())
}""",
            explanation="Missing remaining_accounts validation enables account "
                        "injection attacks. Always validate: (1) count matches expected, "
                        "(2) signer/writable flags, (3) owner/program, (4) account keys "
                        "if position-dependent.",
        ),

        # -------------------------------------------------------------------------
        # Rule 16: Discriminator Collision (CRITICAL)
        # -------------------------------------------------------------------------
        "Rule 16": FixTemplate(
            before="""// CRITICAL: Potential discriminator collision
#[derive(Accounts)]
pub struct VaultAccount<'info> {
    pub vault: Account<'info, VaultData>,
}

#[derive(Accounts)]
pub struct VaultAdmin<'info> {
    pub vault: Account<'info, VaultData>,  // COLLISION: "Vault" + "VaultAdmin"
    // Both generate "Vault\\0\\0\\0\\0\\0" discriminator!
}""",
            after="""// SECURE: Use unique struct names or manual discriminators
#[derive(Accounts)]
pub struct UserVault<'info> {
    #[account(seeds = [b"user_vault", user.key().as_ref()], bump)]
    pub vault: Account<'info, UserVaultData>,
}

#[derive(Accounts)]
pub struct AdminVault<'info> {
    #[account(seeds = [b"admin_vault"], bump)]
    pub vault: Account<'info, AdminVaultData>,
}

// If you must use similar names, use manual discriminator:
mod discriminator {
    pub const USER_VAULT: [u8; 8] = [0x55, 0x73, 0x65, 0x72, 0x5f, 0x76, 0x61, 0x75]; // "uservault"
    pub const ADMIN_VAULT: [u8; 8] = [0x61, 0x64, 0x6d, 0x69, 0x6e, 0x5f, 0x76, 0x61]; // "admin_va"
}

#[derive(Accounts)]
pub struct AdminVault<'info> {
    #[account(
        seeds = [b"admin_vault"],
        bump,
        // Manual discriminator for collision avoidance
    )]
    pub vault: AccountLoader<'info, AdminVaultData>,
}""",
            explanation="Anchor generates 8-byte discriminators from struct names "
                        "(case-insensitive, null-padded to 8 bytes). "
                        "'Vault' and 'VaultAdmin' both produce 'vault\\0\\0\\0\\0\\0'. "
                        "Use unique names or manual discriminators.",
        ),

        # -------------------------------------------------------------------------
        # Rule 17: AccountLoader vs Account
        # -------------------------------------------------------------------------
        "Rule 17": FixTemplate(
            before="""// HIGH RISK: AccountLoader without owner check
pub fn load_vault(ctx: Context<LoadVault>) -> Result<()> {
    let vault = ctx.accounts.vault.load_init()?;
    // NO owner check - vault could be from wrong program!
    ctx.accounts.user_balance = vault.balance;
    Ok(())
}""",
            after="""// SECURE: Use Account<T> or validate with AccountLoader
// OPTION 1: Use Account<T> (recommended)
#[derive(Accounts)]
pub struct LoadVault<'info> {
    pub vault: Account<'info, VaultState>,  // Anchor validates owner
}

pub fn load_vault_opt1(ctx: Context<LoadVault>) -> Result<()> {
    let vault = &ctx.accounts.vault;
    ctx.accounts.user_balance = vault.balance;
    Ok(())
}

// OPTION 2: AccountLoader with manual owner check
pub fn load_vault_opt2(ctx: Context<LoadVault>) -> Result<()> {
    let vault_info = ctx.accounts.vault.to_account_info();
    let vault = vault_info.try_borrow_data()?;
    let data = VaultState::try_from_slice(&vault)?;

    // MANUAL: Owner check required with AccountLoader
    require!(
        vault_info.owner == ctx.program_id,
        VaultError::InvalidOwner
    );

    ctx.accounts.user_balance = data.balance;
    Ok(())
}""",
            explanation="`Account<T>` validates owner automatically. "
                        "`AccountLoader<T>` and `UncheckedAccount<T>` do NOT. "
                        "When using these, YOU must verify `account_info.owner == expected_program_id`.",
        ),

        # -------------------------------------------------------------------------
        # Rule 18: Borsh Deserialization Panic
        # -------------------------------------------------------------------------
        "Rule 18": FixTemplate(
            before="""// UNSAFE: unwrap() on untrusted data
pub fn process_data(ctx: Context<Process>, data: Vec<u8>) -> Result<()> {
    let account = ctx.accounts.target.try_borrow_data()?;
    let parsed = MyStruct::try_from_slice(&account)
        .unwrap();  // PANIC on invalid data!
    // ...
}""",
            after="""// SECURE: Proper Result propagation
pub fn process_data(ctx: Context<Process>, data: Vec<u8>) -> Result<()> {
    let account = ctx.accounts.target.try_borrow_data()?;

    // SAFE: Propagate errors with ?
    let parsed = MyStruct::try_from_slice(&account)
        .map_err(|_| VaultError::DeserializationError)?;

    // Or use Anchor's Account<T> which handles this safely:
    // let account = Account::<MyStruct>::try_from(&ctx.accounts.target)?;
    // parsed = &account;

    ctx.accounts.result.value = parsed.value;
    Ok(())
}""",
            explanation="Account data is untrusted. Use `try_from_slice` and propagate "
                        "errors with `?`. Never `unwrap()` or `expect()` on data "
                        "from account. Anchor's `Account<T>` handles this safely.",
        ),

        # -------------------------------------------------------------------------
        # Rule 19: Anchor verify/address Constraint
        # -------------------------------------------------------------------------
        "Rule 19": FixTemplate(
            before="""// UNSAFE: address constraint without owner check
#[derive(Accounts)]
pub struct VerifyDeposit<'info> {
    #[account(address = expected_token_account)]
    pub token_account: Account<'info, TokenAccount>,
    // MISSING: owner check, mint verification
}""",
            after="""// SECURE: address constraint with additional validation
#[derive(Accounts)]
pub struct VerifyDeposit<'info> {
    #[account(
        address = expected_token_account,
        owner = token_program::ID  // Explicit owner check
    )]
    pub token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

pub fn verify_deposit(ctx: Context<VerifyDeposit>) -> Result<()> {
    // VALIDATE: Additional checks beyond constraint
    require!(
        ctx.accounts.token_account.mint == expected_mint,
        TokenError::InvalidMint
    );
    require!(
        ctx.accounts.token_account.delegate.is_none(),
        TokenError::FrozenDelegation
    );
    Ok(())
}""",
            explanation="`address` and `verify` constraints can be bypassed. "
                        "Always add redundant `owner` checks and validate additional "
                        "invariants (mint, state flags) in the instruction body.",
        ),

        # -------------------------------------------------------------------------
        # Rule 20: Token-2022 Extension Ordering
        # -------------------------------------------------------------------------
        "Rule 20": FixTemplate(
            before="""// UNSAFE: Wrong extension initialization order
pub fn init_token_v2(ctx: Context<InitTokenV2>) -> Result<()> {
    // WRONG: transfer_fee before memo
    initialize_transfer_fee_config(ctx.accounts.transfer_fee_ctx(), ...)?;
    initialize_memo(ctx.accounts.memo_ctx(), ...)?;  // Too late!
    Ok(())
}""",
            after="""// SECURE: Correct extension initialization order
pub fn init_token_v2(ctx: Context<InitTokenV2>) -> Result<()> {
    // STEP 1: Memo extension FIRST (required by transfer_fee)
    initialize_memo(ctx.accounts.memo_ctx(), ...)?;

    // STEP 2: Then transfer_fee (requires memo)
    initialize_transfer_fee_config(ctx.accounts.transfer_fee_ctx(), ...)?;

    // STEP 3: Other extensions in required order
    // ...

    Ok(())
}""",
            explanation="Token-2022 extensions have initialization prerequisites. "
                        "Memo extension must initialize before transfer_fee. "
                        "Consult SPL Token-2022 docs for correct extension ordering.",
        ),

        # -------------------------------------------------------------------------
        # Rule 21: CPI Callback Reentrancy
        # -------------------------------------------------------------------------
        "Rule 21": FixTemplate(
            before="""// UNSAFE: Reentrancy guard can be bypassed via callback
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    require!(!vault.in_use, VaultError::Reentrancy);
    vault.in_use = true;

    // CPI could callback via different PDA
    anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)?;

    vault.in_use = false;
    vault.amount -= amount;
    Ok(())
}""",
            after="""// SECURE: CEI pattern prevents callback reentrancy
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;

    // CHECK: Pre-condition
    require!(!vault.in_use, VaultError::Reentrancy);

    // EFFECT: Update ALL state BEFORE external call
    vault.in_use = true;
    vault.amount = vault.amount
        .checked_sub(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;

    // INTERACTION: External call LAST (CEI prevents callback reentrancy)
    anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)?;

    // Reset guard after external call
    vault.in_use = false;
    Ok(())
}""",
            explanation="CEI pattern prevents callback reentrancy because state "
                        "is finalized before the external call. A callback reentering "
                        "via a different PDA sees consistent state.",
        ),

        # -------------------------------------------------------------------------
        # Rule 22: init_if_needed + close Race
        # -------------------------------------------------------------------------
        "Rule 22": FixTemplate(
            before="""// UNSAFE: Race condition between init_if_needed and close
// Instruction 1: init_if_needed
#[derive(Accounts)]
pub struct InitUser<'info> {
    #[account(init_if_needed, space = 8 + User::LEN, payer = user, seeds = [...], bump)]
    pub user: Account<'info, User>,
    pub user: Signer<'info>,
}

// Instruction 2: close (separate instruction - race window!)
#[derive(Accounts)]
pub struct CloseUser<'info> {
    #[account(close = recipient)]
    pub user: Account<'info, User>,
}""",
            after="""// SECURE: Single atomic instruction for state transitions
#[derive(Accounts)]
pub struct TransitionUser<'info> {
    #[account(mut, seeds = [...], bump)]
    pub user: Account<'info, User>,
    pub admin: Signer<'info>,
}

pub fn transition_user(
    ctx: Context<TransitionUser>,
    new_status: UserStatus,
) -> Result<()> {
    let user = &mut ctx.accounts.user;
    require!(
        ctx.accounts.admin.key() == user.admin,
        VaultError::Unauthorized
    );

    match new_status {
        UserStatus::Active => {
            // Transition from inactive to active
            user.status = UserStatus::Active;
        }
        UserStatus::Closed => {
            // ATOMIC: Transfer lamports and close in single instruction
            let dest = ctx.accounts.destination.to_account_info();
            **dest.try_borrow_mut_lamports()? += user.to_account_info().lamports();
            **user.to_account_info().try_borrow_mut_lamports()? = 0;
            // No separate close instruction needed
        }
    }
    Ok(())
}""",
            explanation="init_if_needed + close on separate instructions creates a "
                        "race condition. Attacker can front-run close with reinit. "
                        "Use single atomic instructions for state transitions, "
                        "or protect with a common reentrancy lock.",
        ),

        # -------------------------------------------------------------------------
        # Rule 23: Memo Program CPI Injection
        # -------------------------------------------------------------------------
        "Rule 23": FixTemplate(
            before="""// UNSAFE: User-controlled memo in CPI
pub fn log_deposit(ctx: Context<LogDeposit>, memo: String) -> Result<()> {
    // ATTACK: User-supplied memo can forge confirmations
    invoke(
        &spl_memo::instruction::build(memo.as_bytes()),
        &[],
    )?;
    Ok(())
}""",
            after="""// SECURE: Program-controlled memo only
pub fn log_deposit(ctx: Context<LogDeposit>) -> Result<()> {
    // Program generates memo - not attacker-controllable
    let user_key = ctx.accounts.user.key();
    let memo = format!("DEP:{}", &user_key.to_string()[..8]);

    invoke(
        &spl_memo::instruction::build(memo.as_bytes()),
        &[],
    )?;
    Ok(())
}

// If user content is needed, hash it
pub fn log_deposit_with_hash(ctx: Context<LogDeposit>, amount: u64) -> Result<()> {
    use solana_program::hash::hash;
    use anchor_lang::prelude::Pubkey;

    let data_to_sign = ctx.accounts.user.key().to_string();
    let h = hash(data_to_sign.as_bytes());

    // Include hash in memo (verifiable off-chain)
    let memo = format!("DEP:{}:{}", amount, &h.to_string()[..8]);
    invoke(
        &spl_memo::instruction::build(memo.as_bytes()),
        &[],
    )?;
    Ok(())
}""",
            explanation="Memo program writes arbitrary bytes to logs. "
                        "Never include user-supplied content verbatim in memos. "
                        "Use program-controlled messages or hash user data.",
        ),

        # -------------------------------------------------------------------------
        # Rule 24: remaining_accounts Count Mismatch
        # -------------------------------------------------------------------------
        "Rule 24": FixTemplate(
            before="""// UNSAFE: No count validation in invoke_signed
pub fn inner_call(ctx: Context<InnerCall>, data: Vec<u8>) -> Result<()> {
    let remaining = ctx.remaining_accounts();

    // MISSING: Count validation
    let inner_accounts: Vec<AccountMeta> = remaining
        .iter()
        .map(|acc| AccountMeta::new(acc.key(), acc.is_signer))
        .collect();

    invoke_signed(
        &Instruction {
            program_id: ctx.accounts.target.key(),
            accounts: inner_accounts,
            data: data.clone(),
        },
        &remaining.to_account_infos(),
        &[&[b"vault", &[ctx.bumps.vault]]],
    )?;
    Ok(())
}""",
            after="""// SECURE: Validate remaining_accounts before use
const EXPECTED_ACCOUNTS: usize = 3;

pub fn inner_call(ctx: Context<InnerCall>, data: Vec<u8>) -> Result<()> {
    let remaining = ctx.remaining_accounts();

    // VALIDATE: Count
    require!(
        remaining.len() == EXPECTED_ACCOUNTS,
        InnerError::InvalidAccountCount
    );

    // VALIDATE: Signer requirement
    require!(
        remaining[0].is_signer,
        InnerError::ExpectedSigner
    );

    // VALIDATE: Owner
    require!(
        remaining[0].owner == &spl_token::ID,
        InnerError::InvalidOwner
    );

    // VALIDATE: Key if position-dependent
    require!(
        remaining[2].key() == ctx.accounts.expected.key(),
        InnerError::AccountMismatch
    );

    let inner_accounts: Vec<AccountMeta> = remaining
        .iter()
        .map(|acc| AccountMeta::new(acc.key(), acc.is_signer))
        .collect();

    invoke_signed(
        &Instruction {
            program_id: ctx.accounts.target.key(),
            accounts: inner_accounts,
            data: data.clone(),
        },
        &remaining.to_account_infos(),
        &[&[b"vault", &[ctx.bumps.vault]]],
    )?;
    Ok(())
}""",
            explanation="remaining_accounts count mismatches can cause wrong accounts "
                        "to be signed or validated. Always validate length, signer flags, "
                        "owner, and position-dependent keys before using remaining_accounts.",
        ),

        # -------------------------------------------------------------------------
        # Rule 25: Versioned Transaction LUT Manipulation
        # -------------------------------------------------------------------------
        "Rule 25": FixTemplate(
            before="""// UNSAFE: Trusts LUT address without validation
pub fn withdraw_vlut(ctx: Context<WithdrawVlut>, amount: u64) -> Result<()> {
    let user = ctx.accounts.user.clone();  // From LUT

    // NO validation - could be attacker's account at same address
    require!(
        user.amount >= amount,
        VlutError::InsufficientFunds
    );
    // ...
}""",
            after="""// SECURE: Validate every LUT-loaded account
pub fn withdraw_vlut(ctx: Context<WithdrawVlut>, amount: u64) -> Result<()> {
    let user_info = ctx.accounts.user.to_account_info();
    let user_data = user_info.try_borrow_data()?;

    // VALIDATE: Owner
    require!(
        user_info.owner == ctx.program_id,
        VlutError::InvalidOwner
    );

    // VALIDATE: Discriminator
    let account = UserAccount::try_from_slice(&user_data)
        .map_err(|_| VlutError::DeserializationError)?;

    // VALIDATE: State
    require!(
        account.amount >= amount,
        VlutError::InsufficientFunds
    );
    require!(
        account.status == AccountStatus::Active,
        VlutError::AccountInactive
    );
    Ok(())
}""",
            explanation="LUT-loaded accounts can be substituted with malicious accounts "
                        "at the same address. Always validate owner, discriminator, "
                        "and state of LUT-sourced accounts.",
        ),

        # -------------------------------------------------------------------------
        # Rule 26: Cross-Program Flash Loan Composition
        # -------------------------------------------------------------------------
        "Rule 26": FixTemplate(
            before="""// UNSAFE: Multi-program CPI without oracle protection
pub fn multi_hop(ctx: Context<MultiHop>, amount: u64) -> Result<()> {
    // Flash loan from Program A
    program_a::flash_loan(ctx.accounts.flash_ctx(), amount)?;

    // Program B reads price - can be manipulated by Program A
    let price = ctx.accounts.price_oracle.price;

    // Borrow against manipulated price
    program_b::borrow(ctx.accounts.borrow_ctx(), amount, price)?;
    Ok(())
}""",
            after="""// SECURE: Sequential execution with commit-reveal or external validation
pub fn borrow_with_commit(
    ctx: Context<BorrowCommit>,
    amount: u64,
    price_merkle_proof: Vec<u8>,
    price_slot: u64,
) -> Result<()> {
    let clock = Clock::get()?;
    let slot_age = clock.slot.saturating_sub(price_slot);

    // VALIDATE: Price from prior slot (not manipulable in same tx)
    require!(
        slot_age >= MIN_SLOT_SEPARATION,
        OracleError::PriceTooRecent
    );

    // VALIDATE: Merkle proof commits to price from prior slot
    verify_price_commitment(
        &ctx.accounts.price_oracle,
        &ctx.accounts.merkle_root,
        price_slot,
        &price_merkle_proof,
    )?;

    // NOW safe to use price
    let price = ctx.accounts.price_oracle.price;
    let collateral_needed = amount
        .checked_mul(price)
        .ok_or(VaultError::ArithmeticOverflow)?
        .checked_div(LAMPORTS_PER_SOL)
        .ok_or(VaultError::ArithmeticOverflow)?;

    require!(
        ctx.accounts.collateral.amount >= collateral_needed,
        VaultError::InsufficientCollateral
    );
    Ok(())
}""",
            explanation="Flash loans spanning multiple programs enable oracle "
                        "manipulation across program boundaries. Use commit-reveal "
                        "patterns, external validation, or slot-separated price "
                        "feeds that cannot be manipulated within a single transaction.",
        ),
    }

    # Return template for rule, or generate generic fallback
    if rule_id in templates:
        return templates[rule_id]

    # Fallback for unknown or non-matched rules
    return FixTemplate(
        before="// Review this code for security issues",
        after="// Apply security fixes based on rule requirements",
        explanation=f"Fix for {rule_id}. Refer to rules/audit.rules for detailed guidance.",
    )


# ============================================================================
# Finding Validation
# ============================================================================


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


def validate_finding(finding: dict[str, Any]) -> None:
    """
    Validate a finding has required fields.

    Args:
        finding: The finding dictionary to validate

    Raises:
        ValidationError: If required fields are missing
    """
    required_fields = ["id", "severity", "location", "rule_caught"]
    missing = [f for f in required_fields if f not in finding]
    if missing:
        raise ValidationError(f"Finding missing required fields: {missing}")

    # Validate location structure
    location = finding.get("location", {})
    location_fields = ["file", "line"]
    missing_loc = [f for f in location_fields if f not in location]
    if missing_loc:
        raise ValidationError(f"Finding location missing required fields: {missing_loc}")


def validate_findings_json(data: dict[str, Any]) -> None:
    """
    Validate the entire findings.json structure.

    Args:
        data: The parsed JSON data

    Raises:
        ValidationError: If schema is invalid
    """
    if "findings" not in data:
        raise ValidationError("Missing 'findings' key in input JSON")

    findings = data["findings"]
    if not isinstance(findings, list):
        raise ValidationError("'findings' must be a list")

    for idx, finding in enumerate(findings):
        try:
            validate_finding(finding)
        except ValidationError as e:
            raise ValidationError(f"Finding at index {idx}: {e}") from e


# ============================================================================
# Fix Suggestion Generator
# ============================================================================


def extract_rule_id(rule_caught: str) -> str:
    """
    Extract the rule ID from a rule_caught string.

    Args:
        rule_caught: String like "Rule 8 - Signer Verification"

    Returns:
        Rule ID like "Rule 8"
    """
    if not rule_caught:
        return "Rule 0"

    # Handle patterns like "Rule 8 - Signer Verification" or "Rule 8"
    import re
    match = re.match(r"(Rule \d+)", rule_caught)
    if match:
        return match.group(1)

    # Check for known rule names
    for rule_id, rule_name in RULE_NAMES.items():
        if rule_name.lower() in rule_caught.lower():
            return rule_id

    return "Rule 0"


def generate_finding_id(finding: dict[str, Any], index: int) -> str:
    """
    Generate a suggestion ID for a finding.

    Args:
        finding: The finding dictionary
        index: Index in the findings list

    Returns:
        Suggestion ID like "SUGGEST-VULN-01-1"
    """
    finding_id = finding.get("id", f"IDX-{index}")
    return f"SUGGEST-{finding_id}"


def get_program_id_from_findings(findings: list[dict[str, Any]]) -> str:
    """
    Extract program ID from findings if available.

    Args:
        findings: List of findings

    Returns:
        Program ID string or placeholder
    """
    # Look for program_id in any finding
    for finding in findings:
        if "program_id" in finding:
            return finding["program_id"]

    return "unknown"


def generate_fix_suggestion(
    finding: dict[str, Any],
    index: int,
) -> FixSuggestion:
    """
    Generate a fix suggestion for a single finding.

    Args:
        finding: The finding dictionary
        index: Index in findings list

    Returns:
        FixSuggestion dataclass instance with all v2.0 fields
    """
    rule_id = extract_rule_id(finding.get("rule_caught", ""))
    template = get_fix_template(rule_id, finding.get("id", ""))

    # Extract location info
    location = finding.get("location", {})
    file_path = location.get("file", "unknown")
    line_num = location.get("line", 0)

    # Get references for this rule
    references = []
    if rule_id in RULE_CWE_REFS:
        references.extend(RULE_CWE_REFS[rule_id])
    if rule_id in RULE_DOC_REFS:
        references.extend(RULE_DOC_REFS[rule_id])

    # Add finding-specific reference if present
    if finding.get("cwe"):
        cwe_url = f"https://www.cwe.mitre.org/data/definitions/{finding['cwe'].replace('CWE-', '')}.html"
        if cwe_url not in references:
            references.insert(0, cwe_url)

    # Add Anchor docs as general reference
    references.append("https://www.anchor-lang.com/docs/the-program")

    # Compute v2.0 fields
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
        # v2.0 fields
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


def generate_all_suggestions(
    findings: list[dict[str, Any]],
) -> list[FixSuggestion]:
    """
    Generate fix suggestions for all findings.

    Args:
        findings: List of finding dictionaries

    Returns:
        List of FixSuggestion instances
    """
    suggestions = []
    for idx, finding in enumerate(findings):
        try:
            suggestion = generate_fix_suggestion(finding, idx)
            suggestions.append(suggestion)
        except Exception as e:
            # Log error but continue processing
            print(f"Warning: Failed to generate suggestion for finding at index {idx}: {e}", file=sys.stderr)

    return suggestions


# ============================================================================
# CLI and I/O
# ============================================================================


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="Generate inline fix suggestions from findings.json (v2.0)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate all suggestions (default behavior)
  python scripts/audit-fix-suggestions.py

  # Specific finding
  python scripts/audit-fix-suggestions.py --finding CRIT-01

  # All HIGH/CRITICAL findings
  python scripts/audit-fix-suggestions.py --severity HIGH --severity CRITICAL

  # Show CVSS impact
  python scripts/audit-fix-suggestions.py --cvss-before-after --finding CRIT-01

  # Apply Tier A fix
  python scripts/audit-fix-suggestions.py --apply --finding CRIT-01

  # Generate remediation report
  python scripts/audit-fix-suggestions.py --report

  # With custom paths
  python scripts/audit-fix-suggestions.py --input audit-output/findings.json --output fix_suggestions.json
        """,
    )

    parser.add_argument(
        "--input", "-i",
        type=str,
        default="findings.json",
        help="Path to findings.json (default: findings.json)",
    )

    parser.add_argument(
        "--output", "-o",
        type=str,
        default="fix_suggestions.json",
        help="Path for output fix_suggestions.json (default: fix_suggestions.json)",
    )

    parser.add_argument(
        "--finding", "-f",
        type=str,
        help="Specific finding ID (e.g., CRIT-01)",
    )

    parser.add_argument(
        "--severity", "-s",
        action="append",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Filter by severity (can specify multiple)",
    )

    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply Tier A fix (with consent notification)",
    )

    parser.add_argument(
        "--cvss-before-after",
        action="store_true",
        help="Show CVSS before/after comparison",
    )

    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate full remediation status report",
    )

    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"%(prog)s {SCRIPT_VERSION}",
    )

    return parser.parse_args()


def read_findings(input_path: str) -> dict[str, Any]:
    """
    Read and parse findings.json.

    Args:
        input_path: Path to findings.json

    Returns:
        Parsed JSON data

    Raises:
        FileNotFoundError: If file does not exist
        json.JSONDecodeError: If JSON is invalid
    """
    path = Path(input_path)
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_suggestions(output_path: str, output_data: FixSuggestionsOutput) -> None:
    """
    Write fix suggestions to JSON file.

    Args:
        output_path: Path for output file
        output_data: FixSuggestionsOutput to write
    """
    path = Path(output_path)
    with path.open("w", encoding="utf-8") as f:
        json.dump(
            output_data.to_dict(),
            f,
            indent=2,
            ensure_ascii=False,
        )


def main() -> int:
    """
    Main entry point.

    Returns:
        Exit code (0 for success, 1 for error)
    """
    args = parse_args()

    try:
        # Read findings (skip for --report if no file exists)
        findings_data = {}
        findings = []
        suggestions = []

        if args.input and Path(args.input).exists():
            findings_data = read_findings(args.input)
            try:
                validate_findings_json(findings_data)
            except ValidationError as e:
                print(f"Validation error: {e}", file=sys.stderr)
                return 1
            findings = findings_data.get("findings", [])
            suggestions = generate_all_suggestions(findings)

        # Handle --report
        if args.report:
            print("\n=== REMEDIATION STATUS REPORT ===\n")
            if not findings:
                print("No findings loaded. Run an audit first.")
                return 0

            # Aggregate stats
            total = len(findings)
            open_findings = [f for f in findings if f.get("status") == "Open"]
            fixed_findings = [f for f in findings if f.get("status") == "Fixed"]
            pending_findings = [f for f in findings if f.get("remediation", {}).get("status") == "pending"]

            print(f"Total findings: {total}")
            print(f"Open: {len(open_findings)}")
            print(f"Fixed: {len(fixed_findings)}")
            print(f"Pending remediation: {len(pending_findings)}")

            # Breakdown by severity
            print("\nBy Severity:")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = len([f for f in findings if f.get("severity") == sev])
                print(f"  {sev}: {count}")

            # Breakdown by tier (from suggestions)
            print("\nBy Fix Tier:")
            for tier in ["A", "B", "C"]:
                count = len([s for s in suggestions if s.fix_tier == tier])
                print(f"  Tier {tier}: {count}")

            # CVSS summary
            print("\nCVSS Summary (Top 5 by severity):")
            for s in sorted(suggestions, key=lambda x: x.cvss_before, reverse=True)[:5]:
                print(f"  {s.finding_id}: {s.cvss_before} -> {s.cvss_after} (reduction: {s.cvss_reduction}) [{s.fix_tier}]")

            return 0

        # Handle --cvss-before-after
        if args.cvss_before_after and args.finding:
            if not suggestions:
                print(f"Finding {args.finding} not in findings.json.")
                return 1

            suggestion = next((s for s in suggestions if args.finding in s.finding_id), None)
            if not suggestion:
                print(f"Finding {args.finding} not found.")
                return 1

            print(f"\n=== CVSS Before/After for {args.finding} ===\n")
            print(f"  CVSS Before:  {suggestion.cvss_before}")
            print(f"  CVSS After:   {suggestion.cvss_after}")
            print(f"  Reduction:    {suggestion.cvss_reduction}")
            print(f"  Fix Tier:     {suggestion.fix_tier}")
            print(f"  Confidence:   {suggestion.confidence_score:.0%}")
            return 0

        # Handle --finding
        if args.finding:
            if not suggestions:
                # Generate a synthetic suggestion for the finding ID
                print(f"Finding {args.finding} not in findings.json.")
                print("Generating template suggestion...")
                rule_id = "Rule 8"  # Default to most common
                suggestion = FixSuggestion(
                    finding_id=args.finding,
                    severity="CRITICAL",
                    rule_id=rule_id,
                    file="programs/vault/src/lib.rs",
                    line=42,
                    before_code="// Missing signer check",
                    after_code="if !ctx.accounts.admin.is_signer {\n    return Err(ErrorCode::NotSigner.into());\n}",
                    explanation="Missing signer verification on privileged action",
                    references=[],
                    confidence_score=compute_confidence(rule_id),
                    fix_tier=determine_tier(compute_confidence(rule_id), get_poker_risk(rule_id)),
                    fix_type=get_fix_type(rule_id),
                    poker_risk=get_poker_risk(rule_id),
                    estimated_effort_minutes=get_effort_minutes(rule_id),
                    cvss_before=9.1,
                    cvss_after=7.5,
                    cvss_reduction=1.6,
                    test_template=generate_test_template(rule_id, args.finding),
                )
            else:
                suggestion = next((s for s in suggestions if args.finding in s.finding_id), None)
                if not suggestion:
                    print(f"Finding {args.finding} not found in suggestions.")
                    return 1

            # Display based on tier
            if suggestion.fix_tier == "A":
                print(format_tier_a_notification(suggestion))
                if args.apply:
                    print("[NOTICE] Tier A fix ready for application.")
                    print("  To apply manually, copy the AFTER code to the file.")
            elif suggestion.fix_tier == "B":
                print(format_tier_b_prompt(suggestion))
            else:
                print(format_tier_c_guidance(suggestion))

            # Show test template
            print("\n  VERIFICATION TEST:")
            print(f"    {suggestion.test_template}")

            return 0

        # Handle --severity filter
        if args.severity:
            if not suggestions:
                print("No findings loaded.")
                return 1

            filtered = [s for s in suggestions if s.severity in args.severity]
            print(f"\n=== Fix Suggestions for {', '.join(args.severity)} Findings ===\n")

            for suggestion in filtered:
                print(f"{suggestion.finding_id} | {suggestion.severity} | Rule {suggestion.rule_id}")
                print(f"  Confidence: {suggestion.confidence_score:.0%} | Tier: {suggestion.fix_tier} | CVSS: {suggestion.cvss_before} -> {suggestion.cvss_after}")
                print()

            print(f"Total: {len(filtered)} suggestions")
            return 0

        # Default: Generate all suggestions
        if not findings:
            print("No findings.json found. Run an audit first.")
            return 1

        # Get program ID
        program_id = get_program_id_from_findings(findings)

        # Build output
        output = FixSuggestionsOutput(
            generated_at=datetime.now(timezone.utc).isoformat(),
            program_id=program_id,
            version=SCRIPT_VERSION,
            total_findings=len(suggestions),
            suggestions=[s.to_dict() for s in suggestions],
        )

        # Write output
        write_suggestions(args.output, output)

        print(f"Generated {len(suggestions)} fix suggestions")
        print(f"Output written to: {args.output}")

        # Summary by tier
        tier_counts = {}
        for s in suggestions:
            tier_counts[s.fix_tier] = tier_counts.get(s.fix_tier, 0) + 1

        print("\nBy Tier:")
        for tier in ["A", "B", "C"]:
            count = tier_counts.get(tier, 0)
            if count > 0:
                print(f"  Tier {tier}: {count}")

        return 0

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in input file: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
