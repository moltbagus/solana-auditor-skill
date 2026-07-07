#!/usr/bin/env python3
"""
fix_constants.py — Rule metadata tables for the fix suggestion engine.

Single Responsibility: Store all rule metadata and configuration constants
for the fix suggestion pipeline. Reason to change: Rule set modifications.

Usage:
    from fix_constants import RULE_NAMES, RULE_BASE_RATES, ...
"""

from typing import Final

SCRIPT_VERSION: Final[str] = "2.0.0"
RULES_COUNT: Final[int] = 26

# Fix tier thresholds
TIER_A_THRESHOLD: Final[float] = 0.90  # Auto-apply with notification
TIER_B_THRESHOLD: Final[float] = 0.60  # Assisted with confirmation
TIER_C_THRESHOLD: Final[float] = 0.00  # Manual, architectural

# Rule base rates for confidence scoring (prediction-market model)
RULE_BASE_RATES: Final[dict[str, float]] = {
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
FIX_TYPES: Final[dict[str, str]] = {
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
RULE_POKER_RISK: Final[dict[str, str]] = {
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
RULE_EFFORT_MINUTES: Final[dict[str, int]] = {
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
RULE_NAMES: Final[dict[str, str]] = {
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
RULE_CWE_REFS: Final[dict[str, list[str]]] = {
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
RULE_DOC_REFS: Final[dict[str, list[str]]] = {
    "Rule 1": [
        "https://www.anchor-lang.com/docs/the-program",
        "https://github.com/trailofbits/solana-common-pitfalls",
    ],
    "Rule 2": [
        "https://www.anchor-lang.com/docs/account-constraints",
        "https://github.com/coral-xyz/anchor/blob/master/lang/src/account.rs",
    ],
    "Rule 3": [
        (
            "https://docs.solana.com/developing/programming-model/"
            "calling-between-programs#program-derived-addresses"
        ),
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

# Mapping from rule_id to exploit_class
RULE_EXPLOIT_CLASS: Final[dict[str, str]] = {
    "Rule 1": "config",
    "Rule 2": "state-manipulation",
    "Rule 3": "state-manipulation",
    "Rule 4": "privilege-escalation",
    "Rule 5": "config",
    "Rule 6": "arith",
    "Rule 7": "privilege-escalation",
    "Rule 8": "privilege-escalation",
    "Rule 9": "config",
    "Rule 10": "arith",
    "Rule 11": "state-manipulation",
    "Rule 12": "state-manipulation",
    "Rule 13": "oracle-manipulation",
    "Rule 14": "reentrancy",
    "Rule 15": "privilege-escalation",
    "Rule 16": "state-manipulation",
    "Rule 17": "privilege-escalation",
    "Rule 18": "arith",
    "Rule 19": "privilege-escalation",
    "Rule 20": "config",
    "Rule 21": "reentrancy",
    "Rule 22": "state-manipulation",
    "Rule 23": "privilege-escalation",
    "Rule 24": "privilege-escalation",
    "Rule 25": "privilege-escalation",
    "Rule 26": "oracle-manipulation",
}
