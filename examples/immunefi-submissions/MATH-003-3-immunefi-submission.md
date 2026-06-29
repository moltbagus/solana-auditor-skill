# Immunefi Submission: MATH-003-3 — Divide-by-Zero Panic on Oracle Price == 0 in Liquidation Path

---

## Program

Kamino Finance — Smart Contract

---

## Vulnerability Type

Divide-by-Zero / Panic (CWE-369)

---

## Title

`liquidation_operations.rs` calls `liquidity.market_value()` without checking oracle staleness or zero-price, panicking on divide-by-zero when the oracle price is exactly zero and blocking all liquidations on that reserve

---

## Severity

**MEDIUM**

*Note: This is a DoS-only finding. No fund theft path exists. Panics are limited to one reserve's liquidation path. Downgraded from HIGH to MEDIUM.*

---

## Description

### Root Cause

In `programs/klend/src/state/liquidation_operations.rs:62`, `market_value()` is called without a prior zero-price guard:

```rust
let obligation_debt_for_liquidity_mv = liquidity.market_value();
```

If the oracle price for the liquidity token is exactly zero (delisted asset, stale feed, acute market condition), `market_value()` computes `price * quantity`. Zero price → zero market value.

The liquidation math divides by this value:
```rust
let max_liquidation_ratio = max_liquidatable_mv / obligation_debt_for_liquidity_mv; // divides by 0
```

`Fraction / Fraction` panics on zero denominator.

### Panic Path

1. Reserve has an oracle for price feed
2. Oracle price reaches exactly zero (extreme condition: delisted, acute crash, feed malfunction)
3. Any liquidation on that reserve calls `market_value()` → zero
4. Divide-by-zero panic → tx fails
5. All liquidations blocked → no resolution path

### Scope Limitation

- Only affects the specific reserve with zero oracle price
- All other reserves unaffected
- No fund theft path from the panic itself
- Attacker needs oracle manipulation (external dependency)

---

## Vulnerable Code

- `liquidation_operations.rs:60-65` — market value computation without zero-price guard
- Any caller of `liquidity.market_value()` on a reserve without oracle staleness validation

---

## Recommendation

```rust
if obligation_debt_for_liquidity_mv.is_zero() {
    // Return zero or maximum allowed liquidation — don't panic
    return Fraction::ZERO;
}
// OR: reserve oracle staleness check before entering liquidation logic
require!(
    !is_oracle_stale(reserve.price_feed, clock)?,
    LendingError::OracleStalePrice
);
```
