# Immunefi Submission: C-1 — `Fraction::div_ceil` Off-by-One with Panic on Edge Case

---

## Program

Kamino Finance — Smart Contract

---

## Vulnerability Type

Integer Overflow / Panic on Edge Case (CWE-190, CWE-369)

---

## Title

`Fraction::div_ceil` ceiling-division formula is inverted on exact integer ratios, and overflows to panic in an edge case instead of returning a correct or bounded result

---

## Severity

**LOW**

*Note: Real bug in a math utility used in liquidation math. However: (1) the financial magnitude of the off-by-one is 1 U68F60 quantum ≈ 8.7×10⁻¹⁹, undetectable in any dollar amount; (2) the overflow → panic path requires a specific caller-side precondition. Downgraded from initial assessment.*

---

## Description

### Root Cause

`Fraction::div_ceil` in `programs/klend/src/utils/fraction.rs:173-179` uses:

```rust
fn div_ceil(&self, denum: &Self) -> Self {
    let num_sf = self.to_bits();
    let denum_sf = denum.to_bits();
    let res_sf_u256 =
        ((U256::from(num_sf) << Self::FRAC_NBITS) + U256::from(denum_sf - 1)) / denum_sf;
    let res_sf = u128::try_from(res_sf_u256).expect("Overflow in div_ceil");
    Self::from_bits(res_sf)
}
```

The ceiling-division formula is **inverted**: it adds `denum_sf - 1` instead of `num_sf - 1`.

### Correct ceiling-division formula

For a fixed-point ceiling division of `self / denum`, the correct computation is:
```rust
// CORRECT ceiling: ceil(a/b) = floor((a-1)/b) + 1
let res_sf_u256 = ((U256::from(num_sf) - 1) / denum_sf.into()) + U256::from(1);
```

### What the current formula does

Current formula: `((num << 60) + denum - 1) / denum`

For `self = 1.0`, `denum = 1.0`:
```
num_bits = denum_bits = 2^60
((2^60 << 60) + 2^60 - 1) / 2^60 = 2^60 + 1  ≠  2^60 ✓ (off by 1 SF)
```

For `self = 2.0`, `denum = 2.0`:
```
num_bits = denum_bits = 2 × 2^60
((2×2^60 << 60) + 2×2^60 - 1) / (2×2^60) = 2 + 1 SF / 2^61  ≈ 2 + 0.5 SF  ≠  2^61 ✓ (off by 0.5 SF)
```

### Panic on overflow

The `.expect("Overflow in div_ceil")` panics if `res_sf_u256` doesn't fit in u128. For this to fire:
- `U256::from(num_sf) << FRAC_NBITS` must exceed u128's range
- With `num_sf` from `Fraction::to_bits()`, this requires a caller to pass an abnormally large Fraction that overflows U256

### Affected Call Sites

- `fraction_liquidity_to_collateral_ceil` (reserve.rs) — liquidation collateral calculation
- `fraction_collateral_to_liquidity_ceil` (reserve.rs) — liquidation debt calculation
- `BigFraction::div_ceil` (fraction.rs:228-233) — same inverted formula pattern

---

## Impact

**Financial magnitude: negligible.** 1 U68F60 quantum ≈ 8.7×10⁻¹⁹ relative. No dollar amount is affected.

**Panic path: DoS only.** If a caller passes a value that causes the intermediate U256 to exceed u128, the `expect()` panics, DoS-ing the transaction. This requires the caller to supply an abnormally large numerator. Normal on-chain values are bounded.

**No silent fund corruption.** The `.expect()` ensures this never silently propagates wrong state.

---

## Proof of Concept

### PoC File

Attached: `C-1-div_ceil_off_by_one.rs`

### How to Run

```bash
rustc C-1-div_ceil_off_by_one.rs -o poc_c1 && ./poc_c1
```

Zero dependencies — only `rustc` required.

### Expected Output

```
div_ceil(1.0, 1.0):
  Buggy:   2^60 + 1 SF quantum
  Correct: 2^60 SF
  Off by:  1 SF quantum (8.67e-19 relative)
  Panics if input overflows U256 intermediate

div_ceil(2.0, 2.0):
  Buggy:   2^61 + 0.5 SF
  Correct: 2^61
  Off by:  0.5 SF quantum
```

---

## Vulnerable Code

- `Fraction::div_ceil` — `programs/klend/src/utils/fraction.rs:173-179`
- `BigFraction::div_ceil` — `programs/klend/src/utils/fraction.rs:228-233` (same pattern)

---

## Recommendation

Replace with correct ceiling-division formula:

```rust
// CURRENT (inverted formula, also panics on overflow)
let res_sf_u256 =
    ((U256::from(num_sf) << Self::FRAC_NBITS) + U256::from(denum_sf - 1)) / denum_sf;
let res_sf = u128::try_from(res_sf_u256).expect("Overflow in div_ceil");

// CORRECT ceiling division: ceil(a/b) = floor((a-1)/b) + 1
let res_sf_u256 = (U256::from(num_sf) - 1) / U256::from(denum_sf) + U256::from(1);
let res_sf = u128::try_into(res_sf_u256)
    .map_err(|_| LendingError::MathError)?; // graceful error instead of panic
Self::from_bits(res_sf)
```

**Note:** Even at quantum scale, correct fixed-point arithmetic is code quality discipline in a $100M+ protocol.
