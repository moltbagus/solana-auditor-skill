# AMM/DEX Security Audit Report

## Simplified Constant-Product AMM Fixture

**Program IDs:**
- AMM Pool: `AMMpool7v8N9m2Xy3Ko4BpQ6rHzdLmN5StF8aGpLmN6PtQ`
- Swap: `SWAPpool9m2Xy3Ko4BpQ6rHzdLmN5StF8aGpLmN6PtQa`
- Oracle: `ORAcle7v8N9m2Xy3Ko4BpQ6rHzdLmN5StF8aGpLmN6PtQb`

**Target:** Anchor 0.31.1
**Auditor:** solana-auditor-skill
**Date:** 2026-06-28
**Version:** 1.0.0

---

## Executive Summary

This audit analyzed a simplified constant-product AMM (Automated Market Maker) fixture containing 14 intentional vulnerabilities across 3 programs (AMM, Swap, Oracle). The fixture is designed for educational and testing purposes within the solana-auditor-skill framework.

### Severity Breakdown

| Severity | Count | CVSS Range |
|----------|-------|------------|
| CRITICAL | 2 | 9.0 - 10.0 |
| HIGH | 7 | 7.0 - 8.9 |
| MEDIUM | 5 | 5.0 - 6.9 |
| LOW | 0 | 0.1 - 4.9 |

**Total Findings: 14**

---

## Finding Details

### VULN-01: Reentrancy on withdraw — CEI pattern violation

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **CVSS** | 9.8 |
| **CWE** | CWE-862 |
| **Rule** | Rule 14 — Reentrancy |
| **Location** | `programs/amm/src/lib.rs:52` |
| **Function** | `withdraw` |

**Description:**
The withdraw instruction transfers tokens BEFORE updating the pool's virtual_balance state. An attacker can re-enter the function via a callback during the token transfer, draining additional funds before the state update completes. The CEI (Checks-Effects-Interactions) pattern is violated.

**Impact:**
Complete drain of the AMM pool via reentrancy. The attacker can re-enter withdraw() multiple times before state is updated, extracting multiples of their deposited amount.

**Recommendation:**
Move state update BEFORE the token::transfer call. Add a reentrancy guard (e.g., a boolean flag on the pool account).

---

### VULN-02: Remaining accounts forwarded without validation in swap CPI

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS** | 8.6 |
| **CWE** | CWE-345 |
| **Rule** | Rule 15 — Remaining Accounts |
| **Location** | `programs/amm/src/lib.rs:77` |
| **Function** | `swap` |

**Description:**
The swap instruction accepts remaining_accounts and forwards them directly to the token program without validating that they are legitimate token accounts.

**Impact:**
Account injection attack. Attacker can manipulate the account list passed to the token program.

**Recommendation:**
Validate all accounts in remaining_accounts against expected types and owners. Use explicit account constraints instead of remaining_accounts.

---

### VULN-03: Flash loan composition — no flash loan protection

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **CVSS** | 9.1 |
| **CWE** | CWE-770 |
| **Rule** | Rule 26 — Flash Loans |
| **Location** | `programs/amm/src/lib.rs:94` |
| **Function** | `execute_arbitrage` |

**Description:**
The execute_arbitrage instruction accepts arbitrary amounts and adds them to the pool balance without any flash loan protection mechanism.

**Impact:**
Flash loan attack enabling unlimited arbitrage profit. The attacker can manipulate pool state arbitrarily within a single transaction.

**Recommendation:**
Implement flash loan protection: require that input amounts do not exceed the user's prior balance, track balance snapshots.

---

### VULN-04: Price oracle manipulation via stale data

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS** | 7.5 |
| **CWE** | CWE-1334 |
| **Rule** | Rule 13 — Price Oracles |
| **Location** | `programs/amm/src/lib.rs:112` |
| **Function** | `get_price` |

**Description:**
The get_price function reads the price_feed.value without checking if the last_update slot is recent.

**Impact:**
Oracle price manipulation. The attacker can read outdated prices to execute favorable trades.

**Recommendation:**
Add staleness check: read Clock::get() and verify clock.slot - price_feed.last_update < MAX_STALENESS_SLOTS.

---

### VULN-05: Arithmetic overflow in liquidity calculation

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS** | 7.1 |
| **CWE** | CWE-190 |
| **Rule** | Rule 6 — Arithmetic |
| **Location** | `programs/amm/src/lib.rs:127` |
| **Function** | `add_liquidity` |

**Description:**
The add_liquidity function computes total_liquidity = amount_a * amount_b using Rust's default * operator without checked_mul.

**Impact:**
Integer overflow corrupts liquidity accounting. The wrapped total_liquidity no longer reflects actual deposits.

**Recommendation:**
Use checked_mul: `amount_a.checked_mul(amount_b).ok_or(AmmError::Overflow)?`

---

### VULN-06: Arbitrary CPI via callback — no program allowlist

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS** | 8.1 |
| **CWE** | CWE-347 |
| **Rule** | Rule 4 — CPI Safety |
| **Location** | `programs/amm/src/lib.rs:143` |
| **Function** | `exec_swap_callback` |

**Description:**
The exec_swap_callback instruction accepts a user-supplied target_program and invokes it via invoke() with user-supplied data.

**Impact:**
Arbitrary code execution via CPI. The attacker can invoke any program using the AMM's authority.

**Recommendation:**
Replace AccountInfo with Program<'info, AllowedProgram> for known programs, or maintain an on-chain allowlist.

---

### VULN-07: Missing signer verification on pool admin

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS** | 7.2 |
| **CWE** | CWE-306 |
| **Rule** | Rule 8 — Signer Verification |
| **Location** | `programs/amm/src/lib.rs:156` |
| **Function** | `set_pool_fee` |

**Description:**
The set_pool_fee instruction takes admin as AccountInfo instead of Signer. No is_signer check exists.

**Impact:**
Unauthorized fee modification. Any user can call set_pool_fee with arbitrary fee values.

**Recommendation:**
Change `admin: AccountInfo` to `admin: Signer`. Add `has_one = authority` constraint.

---

### VULN-08: Manual init without discriminator check — reinit vulnerability

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **CVSS** | 6.5 |
| **CWE** | CWE-665 |
| **Rule** | Rule 40 — Manual Initialization |
| **Location** | `programs/swap/src/lib.rs:34` |
| **Function** | `init_pool` |

**Description:**
The init_pool instruction uses manual field assignment without Anchor's #[account] discriminator.

**Impact:**
Reinitialization attack. An attacker who controls a closed account's key can call init_pool again.

**Recommendation:**
Use `#[account(init, ...)]` or Account<'info, SwapPool>` which verifies the discriminator.

---

### VULN-09: Reentrancy via token callback

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS** | 7.5 |
| **CWE** | CWE-862 |
| **Rule** | Rule 14 — Reentrancy |
| **Location** | `programs/swap/src/lib.rs:47` |
| **Function** | `transfer_with_callback` |

**Description:**
The transfer_with_callback instruction executes a token transfer without a reentrancy guard.

**Impact:**
Reentrancy attack via token callback. The attacker can re-enter during the transfer.

**Recommendation:**
Add a reentrancy guard to the swap pool account. Follow CEI pattern strictly.

---

### VULN-10: Duplicate mutable account — double-spend vulnerability

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS** | 8.6 |
| **CWE** | CWE-733 |
| **Rule** | Rule 38 — Duplicate Accounts |
| **Location** | `programs/swap/src/lib.rs:65` |
| **Function** | `double_transfer` |

**Description:**
The double_transfer instruction accepts token_a and token_b as separate AccountInfo fields that may point to the same account.

**Impact:**
Double-spend via duplicate accounts. The attacker can pass the same account twice.

**Recommendation:**
Add account deduplication checks: verify `token_a.key() != token_b.key()` at function entry.

---

### VULN-11: Arithmetic underflow in fee calculation

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **CVSS** | 6.3 |
| **CWE** | CWE-190 |
| **Rule** | Rule 6 — Arithmetic |
| **Location** | `programs/swap/src/lib.rs:94` |
| **Function** | `calc_net_amount` |

**Description:**
The calc_net_amount function computes net = gross - fee without bounds checking on fee_bps.

**Impact:**
Integer underflow corrupts fee accounting. The wrapped net amount may be extremely large.

**Recommendation:**
Add bounds check: `require!(fee_bps <= 10000, SwapError::InvalidFeeBps)`. Use checked_sub.

---

### VULN-12: Sysvar spoofing — slot from instruction data

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **CVSS** | 6.5 |
| **CWE** | CWE-346 |
| **Rule** | Rule 36 — Sysvars |
| **Location** | `programs/oracle/src/lib.rs:30` |
| **Function** | `set_price` |

**Description:**
The set_price instruction accepts a slot parameter from instruction data rather than reading from the Clock sysvar.

**Impact:**
Oracle manipulation. The attacker can set any slot value to make prices appear fresh.

**Recommendation:**
Read the actual slot from `Clock::get()?` and store `clock.slot` as last_update.

---

### VULN-13: Unsafe deserialization without owner check

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **CVSS** | 5.9 |
| **CWE** | CWE-346 |
| **Rule** | Rule 39 — Account Ownership |
| **Location** | `programs/oracle/src/lib.rs:41` |
| **Function** | `read_data` |

**Description:**
The read_data instruction borrows data from an arbitrary account without verifying the account's owner.

**Impact:**
Unauthorized data access. Attacker can read arbitrary account data.

**Recommendation:**
Verify the account owner: `require!(data_account.owner == ctx.program_id, OracleError::InvalidOwner)`.

---

### VULN-14: Missing writable constraint on mutable account

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **CVSS** | 5.3 |
| **CWE** | CWE-20 |
| **Rule** | Rule 37 — Account Constraints |
| **Location** | `programs/oracle/src/lib.rs:53` |
| **Function** | `update_oracle` |

**Description:**
The update_oracle instruction mutates price_feed.value but does not mark the account as writable in the account constraints.

**Impact:**
Runtime failure with confusing error message.

**Recommendation:**
Add `#[account(mut)]` constraint to price_feed in UpdateOracle struct.

---

## Methodology Trace

See `methodology-trace.md` for per-vulnerability detection traces.

## Quick Scan Results

See `quick-scan-results.md` for pattern matching output.
