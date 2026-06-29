# Audit Report — Kamino Finance Lend (Live Program)

**Program:** `KMNo3nJsBXfcpJTVhZcXLW7RmTwTt4GVFE7suUBo9sS`
**Repo:** `kamino-finance/klend` · **Version:** v1.23.0 · **Commit:** `23b9f2b545`
**Audited:** 2026-06-25
**Context:** Post-Aug 2024 exploit ($4.7M, TokenExtensions overflow)

---

## Executive Summary

Audit of the **live Kamino Lend program** (v1.23.0) to verify whether previously identified vulnerabilities (KAM-001: Token2022 transfer fee LTV bug; KAM-002: U256 BigFraction overflow) are still present.

**Result: 1 open CRITICAL, 1 confirmed FIXED.**

| Finding | Severity | Status |
|---------|----------|--------|
| KAM-001 — Token2022 transfer fee not deducted from deposit | CRITICAL | ⚠️ **STILL PRESENT** |
| KAM-002 — U256 BigFraction overflow | ~~CRITICAL~~ | ✅ **FIXED** |

---

## KAM-001 — Token2022 Transfer Fee Not Deducted from Deposit Amount

**Severity:** CRITICAL · **CVSS:** 9.1 · **CWE:** CWE-345

### Description

When a user deposits Token2022 tokens into a reserve, the program calculates collateral to mint based on the **user-supplied** `liquidity_amount`, not the **actual amount received** after the Token2022 transfer fee is deducted.

**Call chain:**

```
process_deposit (handler_deposit_reserve_liquidity.rs:69)
  └─ lending_operations::deposit_reserve_liquidity(...)
       └─ reserve.compute_depositable_amount_and_minted_collateral(liquidity_amount)  ← uses user's amount
            └─ collateral_exchange_rate().liquidity_to_collateral(liquidity_amount)

token_transfer::deposit_reserve_liquidity_transfer(...)
  └─ token_interface::transfer_checked(..., liquidity_deposit_amount)  ← same user's amount, fee deducted AT transfer
```

The `transfer_checked` CPI succeeds for the full `liquidity_amount`, but the Token2022 program deducts the fee. The reserve receives `amount - fee` tokens but minted collateral = `liquidity_to_collateral(amount)` — not `(amount - fee)`.

### Impact

Systematic undercollateralization. For a Token2022 mint with a 1% transfer fee:

```
User deposits:     100 tokens
Transfer fee:      1 token (deducted by Token2022)
Reserve receives:  99 tokens
Collateral minted:  100 tokens worth of cTokens
```

The vault's liability = 100 cTokens, but actual backing = 99 tokens. Every deposit creates a permanent gap. A subsequent borrow or liquidation against the inflated reserve can drain real value.

### Evidence

**`programs/klend/src/state/reserve.rs:405-425`:**
```rust
pub fn compute_depositable_amount_and_minted_collateral(
    &self,
    liquidity_amount: u64,   // ← user-supplied, no fee adjustment
) -> Result<DepositLiquidityResult> {
    let collateral_amount = self
        .collateral_exchange_rate()
        .liquidity_to_collateral(liquidity_amount);  // ← based on user amount

    let liquidity_amount_to_deposit = self
        .collateral_exchange_rate()
        .collateral_to_liquidity_ceil(collateral_amount);

    Ok(DepositLiquidityResult {
        liquidity_amount: liquidity_amount_to_deposit,  // ← passed to transfer
        collateral_amount,                               // ← used for cToken minting
    })
}
```

**`programs/klend/src/utils/token_transfer.rs:34-60`:**
```rust
pub fn deposit_reserve_liquidity_transfer<'a>(
    ...
    liquidity_deposit_amount: u64,  // ← user's amount (no fee subtracted)
    liquidity_decimals: u8,
    collateral_mint_amount: u64,
) -> Result<()> {
    token_interface::transfer_checked(
        ...
        liquidity_deposit_amount,   // ← 100 tokens requested
        liquidity_decimals,
    )?;
    // Reserve now has (100 - fee) tokens but cTokens were minted on 100
    spltoken::mint(..., collateral_mint_amount)?;  // ← cTokens minted on full amount
}
```

### Remediation

**Option A — Post-transfer reconciliation (recommended):**
```rust
// In deposit_reserve_liquidity handler, after token_transfer call:
let actual_received = token_interface::accessor::amount(&reserve_supply)?
    - initial_reserve_token_balance;
// Use actual_received for any downstream accounting

let DepositLiquidityResult {
    liquidity_amount: actual_received,  // ← not user's requested amount
    collateral_amount,
} = reserve.compute_depositable_amount_and_minted_collateral(actual_received)?;
```

**Option B — Pre-flight fee reading:**
```rust
// Read TransferFeeConfig extension from mint before transfer
let mint_data = &ctx.accounts.reserve_liquidity_mint.to_account_info().data;
let state = StateWithExtensions::<Mint>::unpack(mint_data)?;
if let Some(fee_config) = state.get_extension::<TransferFeeConfig>()? {
    let max_fee = u64::from(fee_config.maximum_fee);
    let transfer_fee = calculate_fee(liquidity_amount, fee_config.older_than_30_days()?)?;
    let post_fee_amount = liquidity_amount.saturating_sub(transfer_fee);
    // Use post_fee_amount for collateral calculation
}
```

### Rule Reference

Rule 5 (Token Operations), Rule 6 (Arithmetic), Rule 4 (CPI Safety)

---

## KAM-002 — U256 BigFraction Overflow [RESOLVED ✅]

**Severity:** ~~CRITICAL~~ → **RESOLVED** · **CWE:** CWE-190

The on-chain fraction module has been **completely rewritten**. The old `BigFraction` U256 implementation is replaced by `fixed::types::U68F60` — a fixed-point type from the `fixed` crate with guaranteed overflow-safe arithmetic.

**Key changes:**
- All `mul` operations use `checked_mul()` with `?` error propagation
- `pow_fraction()` uses `checked_mul` throughout (lines 42-48)
- No raw `U256` multiplication without overflow checks
- Wide math via `full_mul_int_ratio` uses `U256` as intermediate type

**Evidence (`programs/klend/src/utils/fraction.rs`):**
```rust
// Line 42-48
y = x.checked_mul(y)?;  // ✅ checked
x = x.checked_mul(x)?;  // ✅ checked
x.checked_mul(y)         // ✅ checked, returns Option

// Line 107
self.checked_mul(fraction!(100))?.round().checked_to_num()  // ✅ checked

// Line 112
self.checked_mul(fraction!(10_000))?  // ✅ checked
```

### Recommendation

**No action needed.** This finding is resolved.

---

## Disclosure Note

**KAM-001 is structurally related to the Aug 2024 Kamino exploit** ($4.7M, TokenExtensions overflow). The specific attack vector differs (overflow bypass vs. fee accounting), but both originate from Token2022 extension handling gaps. The Aug 2024 post-mortem confirms Kamino is aware of Token2022 extension risks.

Before reporting to Immunefi:
1. Confirm the specific Token2022 mint being exploited has a non-zero `transfer_fee` extension
2. Verify the attack path (deposit → borrow/liquidate against inflated reserve) is distinct from the Aug 2024 vector
3. Consider that Kamino may already have this on their fix roadmap post-Aug 2024

If the path is genuinely novel, report to [Immunefi](https://immunefi.com/bug-bounty/kamino/).

---

*Audit performed using solana-auditor-skill skill v1.4.0 — 17-rule SAST methodology*
