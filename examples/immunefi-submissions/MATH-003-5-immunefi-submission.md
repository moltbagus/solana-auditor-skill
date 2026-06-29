# Immunefi Submission: MATH-003-5 — `loan_to_value` Panics on Zero Collateral Without Caller Guard

---

## Program

Kamino Finance — Smart Contract

---

## Vulnerability Type

Divide-by-Zero / Panic on Zero Denominator (CWE-369)

---

## Title

`Obligation::{loan_to_value, no_bf_loan_to_value, unhealthy_loan_to_value}` perform unchecked plain division by `deposited_value_sf`, panicking when collateral reaches zero — DoS on all operations for the affected obligation

---

## Severity

**HIGH**

---

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — **7.5**

| Metric | Value | Rationale |
|--------|-------|-----------|
| AV | N | Exploitable via RPC — no local access needed |
| AC | L | Standard liquidation transaction; no special conditions |
| PR | N | No privileges needed — any liquidator can trigger path |
| UI | N | No victim interaction needed |
| S | U | Scope limited to this program |
| C | N | No data exposure |
| I | N | No data modification from this path |
| A | H | DoS on all borrows/liquidations for affected obligation |

---

## Description

### Root Cause

In `programs/klend/src/state/obligation.rs:226-240`, three LTV functions use plain `/` division with no zero-guard:

```rust
pub fn loan_to_value(&self) -> Fraction {
    Fraction::from_bits(self.borrow_factor_adjusted_debt_sf)
        / Fraction::from_bits(self.deposited_value_sf)
}

pub fn no_bf_loan_to_value(&self) -> Fraction {
    self.get_borrowed_assets_sf()
        / Fraction::from_bits(self.deposited_value_sf)
}

pub fn unhealthy_loan_to_value(&self) -> Fraction {
    self.get_borrowed_assets_sf()
        / Fraction::from_bits(self.deposited_value_sf)
}
```

`deposited_value_sf` is a u128. `Fraction / Fraction` uses the fixed-point `/` operator. When `deposited_value_sf == 0`, this panics. `Fraction` division panics on zero denominator, not an error return.

### Zero Collateral Path

An obligation reaches `deposited_value_sf == 0` through normal protocol operation:

1. Obligation has only 1 collateral asset type
2. Liquidation occurs: liquidator repays debt, receives ALL collateral
3. Collateral amount rounds down to 0 (dust amounts)
4. `Obligation.deposited_value_sf == 0`
5. Any tx that calls `loan_to_value()` (refresh, liquidation, borrow, deposit) panics

### DoS Scope

Multiple critical paths call LTV without checking `deposited_value_sf == 0` first:

| Caller | Function | Context |
|---------|----------|----------|
| Liquidation check | `check_liquidate_obligation` | Line 253: `loan_to_value()` called without guard |
| Liquidation | `liquidation_operations` | Lines 210, 474: `loan_to_value()` called |
| Obligation refresh | `refresh_obligation` | `no_bf_loan_to_value()` called |
| Multiple handlers | Obligation handlers | `loan_to_value()` called in obligation state evaluation |

The `Display` impl guards with `deposited_value_sf > 0`, but callers of the computation use the raw division directly.

### Impact

When an obligation's collateral rounds to zero through normal liquidation:
1. Next `liquidate` call panics on `loan_to_value()` → tx fails
2. Next `refresh_obligation` panics → tx fails
3. Next `borrow` panics → tx fails
4. Obligation is **permanently stuck** — no on-chain path to resolve it

Attack complexity: **zero.** This requires no attacker. Normal liquidation of a small position naturally creates this state.

---

## Proof of Concept

```rust
// Obligation with dust collateral
let obligation = Obligation {
    deposited_collateral_sf: 0,   // ALL collateral liquidated away
    borrowed_assets_sf: 100_000_000_000,  // debt remains
};

// liquidate() calls obligation.loan_to_value()
obligation.loan_to_value(); // PANIC: 0 / 0 denominator

// Resolution: none on-chain. Obligation stuck forever.
```

---

## Vulnerable Code

- `Obligation::loan_to_value` — `programs/klend/src/state/obligation.rs:226-228`
- `Obligation::no_bf_loan_to_value` — `obligation.rs:231-233`
- `Obligation::unhealthy_loan_to_value` — `obligation.rs:237-239`

---

## Recommendation

```rust
pub fn loan_to_value(&self) -> Fraction {
    if self.deposited_value_sf == 0 {
        return Fraction::MAX; // Maximum LTV = maximally unhealthy = immediately liquidatable
    }
    self.get_borrowed_assets_sf() / Fraction::from_bits(self.deposited_value_sf)
}

pub fn unhealthy_loan_to_value(&self) -> Fraction {
    if self.deposited_value_sf == 0 {
        return Fraction::MAX;
    }
    self.get_borrowed_assets_sf() / Fraction::from_bits(self.deposited_value_sf)
}
```

Alternative: `checked_div` returning `Result<Fraction, LendingError::ZeroCollateral`.
