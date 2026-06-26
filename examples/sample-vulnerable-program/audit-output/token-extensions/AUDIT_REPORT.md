# Token Extensions — Audit Report

**Program**: token-extensions (Anchor 0.31.1 + spl-token-2022)
**Repo**: `examples/sample-vulnerable-program/`
**Audit Date**: 2026-06-24
**Auditor**: solana-auditor-skill skill v1.3.0
**Methodology**: 6-phase lifecycle — recon, static analysis, formal verification, triage, report, remediation
**Tools**: ripgrep pattern matching, manual review, Token-2022 extension analysis

---

## Executive Summary

The `token-extensions` program contains **6 security vulnerabilities** specific to Token-2022 (Token Extensions) patterns. The CRITICAL finding (VULN-14) allows an attacker to burn arbitrary tokens using an unverified permanent delegate — this is a total-value-at-risk vulnerability. The HIGH findings enable token program bypass, accounting drift, and non-transferable restriction bypass. The MEDIUM findings undermine close authority and metadata integrity.

This program is **NOT SAFE TO DEPLOY** in its current state. All findings should be remediated before any production use.

The most severe issue (VULN-14) allows any signer to act as a permanent delegate and burn tokens from any account because no extension data validation is performed.

---

## Scope

**Audited**:
- `programs/token-extensions/src/lib.rs` (1 file, ~180 lines, 6 instructions across 7 Accounts structs)
- `programs/token-extensions/Cargo.toml` (dependency analysis)

**Out of Scope**:
- Anchor.toml (shared with vault fixture)
- Formal verification (Token-2022 extension math)
- Runtime execution against test validator

---

## Severity Summary

| Severity | Count | IDs |
|----------|-------|-----|
| CRITICAL | 1     | VULN-14 |
| HIGH     | 3     | VULN-11, VULN-12, VULN-16 |
| MEDIUM   | 2     | VULN-13, VULN-15 |
| LOW      | 0     | — |
| INFO     | 0     | — |

All findings are caught by **Rule 5** (Token Operations — SPL vs Token-2022 Distinction) and **Rule 8** (Signer Verification).

---

## Findings

### VULN-14: Permanent delegate not verified — unauthorized burn — CRITICAL

- **CVSS**: 10.0 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H`)
- **CWE**: CWE-306 (Missing Authentication for Critical Function)
- **Location**: `programs/token-extensions/src/lib.rs:107` — `burn_with_unverified_delegate`
- **Rule caught**: Rule 5 + Rule 8 — Token Operations + Signer Verification

**Description**

The `burn_with_unverified_delegate` instruction accepts a `delegate: Signer` but performs zero validation that:
1. The mint has the `permanent_delegate` extension enabled
2. The delegate account matches the permanent delegate authority stored in the extension
3. The delegate is authorized to burn tokens from the specified token account

An attacker can supply their own pubkey as the delegate and burn tokens from any user's token account for this mint.

**Impact**

Complete token destruction. An attacker can burn arbitrary amounts of tokens from any holder's account. If this mint is used in a DeFi protocol (lending, AMM), burning held tokens can liquidate positions and drain pools.

**Recommendation**

Before accepting a delegate for permanent_delegate operations: (1) verify the mint has the `permanent_delegate` extension, (2) read the extension's authority field, (3) verify `require_keys_eq!(delegate.key(), permanent_delegate_authority)`, and (4) verify the token account is for the expected mint.

---

### VULN-11: Wrong token program — Token vs Token-2022 — HIGH

- **CVSS**: 8.1 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)
- **CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
- **Location**: `programs/token-extensions/src/lib.rs:37` — `transfer_no_2022_check`
- **Rule caught**: Rule 5 — Token Operations (SPL vs Token-2022 Distinction)

**Description**

Uses `anchor_spl::token::Token` instead of `anchor_spl::token_2022::Token2022` despite `spl-token-2022` in deps. Transfers bypass all Token-2022 extension enforcement.

**Impact**

Token-2022 extension bypass — transfer_fee not deducted, non-transferable tokens can move, metadata pointer rules ignored.

**Recommendation**

Replace with `anchor_spl::token_2022::Token2022` and corresponding transfer functions.

---

### VULN-12: Missing transfer_fee accounting on deposit — HIGH

- **CVSS**: 7.1 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`)
- **CWE**: CWE-1281 (Sequence of Processor Instructions Leads to Unexpected Behavior)
- **Location**: `programs/token-extensions/src/lib.rs:64` — `deposit_with_fee_mismatch`
- **Rule caught**: Rule 5 — Token Operations (Token-2022 extensions)

**Description**

Records full `amount` as deposited without deducting the transfer_fee. Actual tokens received are `amount - fee`. Accounting drifts over time.

**Impact**

Token theft via accounting drift. Users can withdraw more than they hold.

**Recommendation**

Calculate fee from `TransferFeeConfig` extension data before recording deposits.

---

### VULN-16: Non-transferable token bypass via wrapping — HIGH

- **CVSS**: 8.1 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`)
- **CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
- **Location**: `programs/token-extensions/src/lib.rs:149` — `wrap_non_transferable`
- **Rule caught**: Rule 5 — Token Operations (Token-2022 extensions)

**Description**

Deposits tokens into a vault without checking the `non_transferable` extension. Soulbound or identity tokens can be wrapped and then transferred.

**Impact**

Non-transferable restriction bypass — defeats regulatory compliance, identity verification, and tokenomics.

**Recommendation**

Read extension data and reject deposits if `non_transferable` extension is present.

---

### VULN-13: Mint close authority not verified — MEDIUM

- **CVSS**: 6.5 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`)
- **CWE**: CWE-285 (Improper Authorization)
- **Location**: `programs/token-extensions/src/lib.rs:85` — `close_mint_no_verify`
- **Rule caught**: Rule 5 — Token Operations (Token-2022 extensions)

**Description**

Accepts any signer as `close_authority` without verifying against the mint's `mint_close_authority` extension.

**Impact**

Unauthorized mint closure when supply reaches zero.

**Recommendation**

Verify signer against extension data before closing.

---

### VULN-15: Metadata pointer not verified — fake metadata injection — MEDIUM

- **CVSS**: 5.4 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`)
- **CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
- **Location**: `programs/token-extensions/src/lib.rs:131` — `read_metadata_unverified`
- **Rule caught**: Rule 5 — Token Operations (Token-2022 extensions)

**Description**

Accepts a `metadata_account` without verifying it against the mint's `metadata_pointer` extension. An attacker mint can point metadata to a fake account.

**Impact**

Metadata-based authorization bypass.

**Recommendation**

Verify metadata account matches the pointer value in the mint's extension data.

---

## Recommendations by Priority

1. **CRITICAL**: Fix VULN-14 — validate permanent delegate against extension data before burning
2. **HIGH**: Fix VULN-11 — switch to `anchor_spl::token_2022::Token2022` for all transfers
3. **HIGH**: Fix VULN-12 — pre-calculate transfer fees before recording deposits
4. **HIGH**: Fix VULN-16 — check for non_transferable extension before wrapping
5. **MEDIUM**: Fix VULN-13 — verify close authority against extension data
6. **MEDIUM**: Fix VULN-15 — verify metadata pointer before reading

---

## Token-2022 Extensions Reference

| Extension | VULN | Risk |
|-----------|------|------|
| `transfer_fee` | VULN-12 | Accounting drift when fee not deducted |
| `mint_close_authority` | VULN-13 | Unauthorized mint closure |
| `permanent_delegate` | VULN-14 | Unauthorized token burn/transfer |
| `metadata_pointer` | VULN-15 | Fake metadata injection |
| `non_transferable` | VULN-16 | Restriction bypass via wrapping |
