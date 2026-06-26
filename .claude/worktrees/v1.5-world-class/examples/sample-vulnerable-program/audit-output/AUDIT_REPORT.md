# Sample Vulnerable Vault — Audit Report

**Program**: vault (Anchor 0.31.1)
**Repo**: `examples/sample-vulnerable-program/`
**Audit Date**: 2026-06-22
**Auditor**: solana-auditor-shiba skill v1.0
**Methodology**: 6-phase lifecycle — recon, static analysis, formal verification, triage, report, remediation
**Tools**: ripgrep pattern matching, manual review

---

## Executive Summary

The `vault` program contains **6 security vulnerabilities** spanning CRITICAL, HIGH, and MEDIUM severities. The two CRITICAL findings (VULN-01, VULN-04) allow direct theft of program-controlled funds — a CRITICAL finding on its own would be sufficient to block deployment. The HIGH findings enable privilege escalation and account hijacking. The MEDIUM findings weaken deposit accounting and PDA derivation guarantees.

This program is **NOT SAFE TO DEPLOY** in its current state. All CRITICAL and HIGH findings must be remediated before any production use. The MEDIUM findings should be addressed in the same release cycle.

The most severe issue (VULN-01) allows any signer to drain the program vault via `admin_withdraw` because no `is_signer` check is performed on the admin account.

---

## Scope

**Audited**:
- `programs/vault/src/lib.rs` (1 file, 199 lines, 9 instructions across 5 Accounts structs)

**Out of Scope**:
- `Cargo.toml` dependency analysis (intentionally minimal)
- `Anchor.toml` (default config)
- Test suite (none present)
- IDL generation (`anchor build` not run — fixture only)

---

## Severity Summary

| Severity | Count | IDs |
|----------|-------|-----|
| CRITICAL | 2     | VULN-01, VULN-04 |
| HIGH     | 2     | VULN-03, VULN-05 |
| MEDIUM   | 6     | VULN-02, VULN-06, VULN-07, VULN-08, VULN-09, VULN-10 |
| LOW      | 0     | — |
| INFO     | 0     | — |

**Note**: VULN-02 through VULN-06 are caught by the 17 rules in `rules/audit.rules`. VULN-07 through VULN-10 are *non-rule-aligned* — they demonstrate that the audit methodology also surfaces bugs the rules don't explicitly cover, validating triage judgment.

---

## Findings

### VULN-01: Admin withdraw lacks signer verification — CRITICAL

- **CVSS**: 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **CWE**: CWE-306 (Missing Authentication for Critical Function)
- **Location**: `programs/vault/src/lib.rs:36` — `admin_withdraw`
- **Rule caught**: Rule 8 — Signer Verification

**Description**

The `admin_withdraw` instruction declares `admin: AccountInfo<'info>` in its `AdminWithdraw` accounts struct and performs no `is_signer` check on it. Anchor's `AccountInfo` type does NOT enforce signer verification — only `Signer<'info>` does. Any transaction can supply any pubkey as the `admin` field and the instruction will succeed.

**Impact**

Complete drain of the program vault. No authentication required — any transaction that supplies a destination account can withdraw arbitrary lamports up to the vault's balance.

**Recommendation**

Change `admin: AccountInfo<'info>` to `admin: Signer<'info>` in the `AdminWithdraw` struct. Anchor enforces signer verification at deserialization. Add `#[account(has_one = admin)]` on the vault account to bind the admin to the vault's stored authority.

---

### VULN-04: Lamport drain via unchecked transfer — CRITICAL

- **CVSS**: 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) — verified via [CVSS 3.1 calculator](https://www.first.org/cvss/calculator/3.1)
- **CWE**: CWE-285 (Improper Authorization)
- **Location**: `programs/vault/src/lib.rs:82` — `drain_vault`
- **Rule caught**: Rule 7 — Close Accounts

**Description**

The `DrainVault` struct uses plain `AccountInfo<'info>` for both `vault` and `destination` with no `Signer` constraint on authority and no `has_one` constraint binding the destination to a known recipient. The `drain_vault` function debits `vault` and credits `destination` with no validation. An attacker can pass their own address as the destination and drain all vault lamports up to the rent-exempt balance.

**Impact**

Lamport drain. Each call to `drain_vault` transfers up to the vault's full balance to an attacker-controlled destination. With no rate limit and no authority check, a single transaction empties the vault.

**Recommendation**

Add `authority: Signer<'info>` to the `DrainVault` struct, and `#[account(has_one = authority)]` on the vault field. Verify the destination is derived from authority (e.g., `#[account(address = vault.authority)]`) rather than accepting user-supplied input. Never perform raw lamport transfers without authority verification.

---

### VULN-03: Arbitrary CPI to user-supplied program — HIGH

- **CVSS**: 8.1 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)
- **CWE**: CWE-862 (Missing Authorization)
- **Location**: `programs/vault/src/lib.rs:60` — `exec_callback`
- **Rule caught**: Rule 4 — CPI Safety

**Description**

The `exec_callback` instruction accepts a `target_program: AccountInfo` with no allowlist validation and invokes it via `invoke(&ix, ...)`. An attacker can pass any program ID, including the System Program, Token Program, or a malicious program, and craft instruction data and account metas to perform unauthorized operations on accounts the caller has authority over.

**Impact**

Privilege escalation via arbitrary CPI. Attackers can exploit the program's instruction context to perform any signed operation the caller has authority for, including transfers, account closures, and authority changes.

**Recommendation**

Replace `target_program: AccountInfo<'info>` with `target_program: Program<'info, SomeKnownProgram>`. If a dynamic program is genuinely required (plug-in architecture), maintain an on-chain allowlist PDA and verify the target program key matches a registered entry.

---

### VULN-06: Manual init lacks 8-byte discriminator — reinit attack possible — MEDIUM

- **CVSS**: 6.5 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`)
- **CWE**: CWE-665 (Improper Initialization)
- **Location**: `programs/vault/src/lib.rs:145` — `VaultState` struct
- **Rule caught**: Rule 11 — Reinitialization Attacks

**Description**

The `VaultState` struct is declared with `#[derive(Clone)]` only, missing `#[account]`. Without `#[account]`, Anchor does not write the 8-byte discriminator on initialization and does not verify it on deserialization. The `Initialize` struct uses `AccountInfo` directly, so no implicit discriminator check occurs.

**Impact**

Reinitialization attack. An attacker who controls a vault account's key (e.g., previously held the account and had it refunded) can call `initialize` again and reset the vault's authority to a key they control. This hijacks the vault.

**Recommendation**

Add `#[account]` to the `VaultState` struct. Change `vault: AccountInfo<'info>` to `vault: Account<'info, VaultState>` (or use `#[account(init, ...)]` with proper constraints). Anchor's `Account<'info, T>` wrapper verifies the 8-byte discriminator on load, preventing reinit.

---

### VULN-02: Hardcoded bump literal in initialize — MEDIUM

- **CVSS**: 6.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **CWE**: CWE-330 (Use of Insufficiently Random Values)
- **Location**: `programs/vault/src/lib.rs:27` — `initialize`
- **Rule caught**: Rule 3 — PDA Canonical Bump

**Description**

The `initialize` instruction uses a hardcoded bump literal (254) rather than the canonical bump from `find_program_address` or `ctx.bumps.vault`. Storing a non-canonical bump allows an attacker who finds a different valid bump to derive a colliding PDA at the same address.

**Impact**

PDA collision potential. If the stored bump is not the canonical (highest valid) bump, an alternative seed/bump combination may produce a valid PDA at the same address, undermining the program's PDA-based access control.

**Recommendation**

Replace `let _hardcoded_bump: u8 = 254;` with `let bump = ctx.bumps.vault;` and store `ctx.bumps.vault` directly. Anchor 0.30+ canonicalizes bumps automatically. If deriving manually, use `Pubkey::find_program_address(seeds, program_id)` which returns the canonical bump.

---

### VULN-05: Unchecked arithmetic on user-supplied deposit amount — HIGH

- **CVSS**: 7.1 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`)
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **Location**: `programs/vault/src/lib.rs:47` — `user_deposit`
- **Rule caught**: Rule 6 — Arithmetic

**Description**

The `user_deposit` instruction computes `vault.total_deposits = vault.total_deposits + amount` using Rust's default `+` on `u64`. In release mode this wraps silently on overflow. An attacker can deposit an amount that wraps `total_deposits` to a small number, then withdraw against the wrapped balance.

**Impact**

Integer overflow on deposit accounting. The wrapped total no longer reflects actual deposits, enabling withdrawals up to the wrapped recorded balance.

**Recommendation**

Use `checked_add`: `vault.total_deposits = vault.total_deposits.checked_add(amount).ok_or(VaultError::Overflow)?;`. Add an `Overflow` variant to the `VaultError` enum. Apply the same pattern to any other `+`/`-`/`*` on user-controlled amounts.

---

### VULN-07: Integer division truncation in share calculation — MEDIUM

- **CVSS**: 5.4 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`)
- **CWE**: CWE-682 (Incorrect Calculation)
- **Location**: `programs/vault/src/lib.rs:95` — `calc_shares`
- **Rule caught**: (non-rule-aligned — demonstrates triage judgment)

**Description**

The `calc_shares` function computes `shares = deposit / divisor` using Rust's `/` operator, which truncates toward zero. If divisor exceeds deposit, the result is 0 and the user receives 0 shares for a non-zero deposit. The deposit is not refunded, so the user loses funds silently.

**Impact**

Indirect fund loss via share miscalculation. Users who pass small deposits get 0 shares and lose their deposit. Repeated attacks can drain a pool of misallocated shares.

**Recommendation**

Use `checked_div` and verify the result against a minimum threshold: `let shares = deposit.checked_div(divisor).ok_or(VaultError::DivisionByZero)?; require!(shares >= MIN_SHARES, VaultError::BelowMinimum);`. For tokens that support fractional units, ensure the divisor is always <= deposit or apply a refund for the remainder.

---

### VULN-08: Off-by-one in threshold check (>= vs >) — MEDIUM

- **CVSS**: 5.4 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`)
- **CWE**: CWE-697 (Incorrect Comparison)
- **Location**: `programs/vault/src/lib.rs:104` — `check_threshold`
- **Rule caught**: (non-rule-aligned — demonstrates triage judgment)

**Description**

The `check_threshold` function uses `>` instead of `>=`, allowing an attacker to bypass the threshold check by exactly hitting the threshold value. If the threshold is 1_000_000, an attacker passing value=1_000_000 passes the gate when the intent was for that to be rejected.

**Impact**

Threshold bypass. Logic that depends on the threshold (e.g., access control, fee tier, rate limit) can be evaded by choosing boundary values.

**Recommendation**

Use `>=` for inclusive thresholds or `>` for exclusive thresholds consistently. Add boundary tests that assert both the threshold value and threshold-1 are handled correctly. Document the intent of each comparison.

---

### VULN-09: CPI return value discarded (no ? propagation) — MEDIUM

- **CVSS**: 6.3 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L`)
- **CWE**: CWE-754 (Improper Check for Unusual or Exceptional Conditions)
- **Location**: `programs/vault/src/lib.rs:117` — `unchecked_cpi`
- **Rule caught**: (non-rule-aligned — Rule 4 covers CPI safety but not result handling)

**Description**

The `unchecked_cpi` function discards the result of `invoke()` via `let _ = ...`. If the CPI fails (program error, account not found, etc.), the outer transaction continues and returns Ok(()). State is left inconsistent: the caller thinks the CPI succeeded, but it didn't.

**Impact**

Silent failure of cross-program invocation. Off-chain monitoring cannot detect the failure because the transaction succeeded. State inconsistency between caller and callee can lead to loss of funds or stuck accounts.

**Recommendation**

Propagate CPI errors with `?`: `invoke(&ix, &[])?;`. Add error handling specific to the called program if needed. If silent failure is genuinely intended (rare), document why and emit an event for monitoring.

---

### VULN-10: Missing event emission for withdrawals — MEDIUM

- **CVSS**: 4.3 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`)
- **CWE**: CWE-778 (Insufficient Logging)
- **Location**: `programs/vault/src/lib.rs:131` — `silent_withdraw`
- **Rule caught**: (non-rule-aligned — best-practice gap, not a security rule)

**Description**

The `silent_withdraw` function performs a lamport transfer but emits no structured event. Off-chain indexers (security monitoring, accounting, front-end balance displays) cannot detect or react to withdrawals in real-time.

**Impact**

Audit trail gap. Security incidents cannot be detected by off-chain monitors; users see stale balances; accounting systems miss transactions. In a hack scenario, post-mortem analysis is impossible.

**Recommendation**

Define an event struct with `#[event]` and `emit!(WithdrawEvent { user, amount, timestamp });` on every state-changing instruction. Events are part of Anchor's standard observability pattern.

---

## Patterns Reviewed, Not Exploited

The following patterns were inspected and considered safe:

- `find_program_address` usage in VULN-02 mitigation discussion (would be canonical)
- `Signer<'info>` usage on `user` field of `UserDeposit` — correctly enforced
- `#[account(mut)]` on `vault` in `UserDeposit` — correctly applied
- AccountInfo `/// CHECK:` documentation comments on user-supplied accounts (acknowledged as out-of-scope protections, but flagged via VULN-03, VULN-04)

## Out of Scope

- Off-chain components (none present)
- Frontend wallet integration (none present)
- Token metadata content (no Token-2022 extensions in this program)
- Test suite (intentionally not provided — fixture only)
- `anchor build` / `anchor test` execution (not run — this is a code-review fixture, no Solana toolchain required to inspect)

## Disclaimer

This is a fixture program produced to demonstrate the solana-auditor-shiba skill. The findings are pre-written and intentionally authored to be caught by the rules in `rules/audit.rules`. The program is not intended for deployment. The findings.json and AUDIT_REPORT.md are the *expected output* of running `/audit` against this program.

## Appendix — Tools & Methodology

- **Pattern matching**: ripgrep with Solana-specific regex
- **Rule engine**: `rules/audit.rules` — 12 path-scoped rules
- **Methodology**: 6-phase audit lifecycle (`/audit` command)
- **Report schema**: per `commands/audit-report.md` §Required sections
- **No toolchain dependencies**: this audit was performed as a code review; `anchor build` and `anchor test` were not executed
