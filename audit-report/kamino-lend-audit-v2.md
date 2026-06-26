# Kamino Lend v2 — Solana Program Security Audit

**Target:** `kamino-finance/klend` (master branch, 2026-06-25 snapshot)
**Scope:** Programs, handlers, state, utils, testing framework
**Methodology:** 5-agent parallel audit (KVLT, PERM, MATH, ADMIN, FLASH)
**Date:** 2026-06-26

---

## Executive Summary

**17 findings:** 2 CRITICAL · 6 HIGH · 6 MEDIUM · 3 LOW
**2 NOT FINDINGS** (KVLT-003, FLASH-003 — sound architecture)

The codebase is well-structured with solid fundamentals. The two CRITICAL issues are localized math bugs with clean, surgical fixes. The HIGH issues are concentrated in access control gaps (missing signer checks, cosmetic two-step patterns) and edge-case panics. No total-loss architecturally-bypassed vulnerabilities were found — the permissioning, flash-loan, and CPI callback systems are correctly implemented.

---

## Findings

### 🔴 CRITICAL

#### C-1: `Fraction::div_ceil` Off-by-One on Exact Divisions
**File:** `fraction.rs:136-143` | **CWE-682**

Every ceiling-divided amount is inflated by 1 U68F60 quantum (~8.67e-19). The formula `((num << 60) + den - 1) / den` adds `den-1` to a double-scaled numerator; on exact ratios (1.0/1.0) this returns `2^60 + 1` instead of `2^60`. Same bug in `BigFraction::div_ceil` and `full_mul_int_ratio_ceil`.

**Fix:** Replace with `((num << FRAC_NBITS) - 1) / den + 1`.

---

#### C-2: Unchecked u128 Overflow in Borrow Rate Curve
**File:** `borrow_rate_curve.rs:130-136` | **CWE-190**

`coef * slope_nom` with both in u128 (where `coef = 2^60` at 100% utilisation × U68F60 scaling × slope_nom up to 50000 bps) silently wraps. No `checked_mul`. Fractional BPS are discarded at line 293 via `to_bps().unwrap()`.

**Fix:** Cast intermediate product to U256. Fix fractional BPS handling.

---

### 🔴 HIGH

| ID | File | Issue |
|---|---|---|
| H-1 | `redeem_fees.rs` | Zero signer check — any tx triggers fee withdrawal via PDA-signed CPI |
| H-2 | `update_global_config*.rs` | Global admin sets pending_admin=self in 2 txs — cosmetic two-step |
| H-3 | `update_lending_market.rs` | Permissioning authority change — no timelock, no notification |
| H-4 | `liquidation_ops.rs:84-91` | Div-by-zero on zero oracle price in liquidation math |
| H-5 | `fraction.rs:206-211` | `BigFraction::mul` silent U256 wrapping — no guard |
| H-6 | `obligation.rs:228,233,239` | Three LTV functions panic on zero collateral |

---

### 🟡 MEDIUM

| ID | File | Issue |
|---|---|---|
| M-1 | `update_lending_market.rs` | Emergency council can enable borrow+liq-disable without owner |
| M-2 | `withdraw_protocol_fees.rs` | No signer check — any tx drains fees to fee_collector ATA |
| M-3 | `socialize_loss.rs` | Only lending_market_owner needed — no global_admin co-sig |
| M-4 | `liquidation_ops.rs:954-958` | Fee formula gives 4.762% not 5% — systematic leak |
| M-5 | `liquidation_ops.rs:75-80` | Sharp close-factor cliff at insolvency boundary |
| M-6 | `obligation.rs:271-305` | 1-SF gap between max_withdraw and unhealthy LTV |

---

### 🟢 LOW

| ID | File | Issue |
|---|---|---|
| L-1 | `update_reserve_config.rs` | Proposer authority configures reserves before lock |
| L-2 | `fraction.rs:188-192` | `BigFraction::from_num` overflow guard unreliable |

---

### ✅ NOT FINDINGS

| ID | Reason |
|---|---|
| KVLT-003 | KVault callback — Anchor-constrained to `CORRESPONDING_KAMINO_VAULT_PROGRAM_ID`. Amounts computed from on-chain state. Callback is one-way CPI with PDA-signed `invoke_signed`. Not exploitable. |
| FLASH-003 | Flash loans — reserve-level isolation from obligation health. CPI + stack-depth guard (`is_flash_forbidden_cpi_call`). Borrow/repay pairing enforced via instruction introspection. No manipulation vector. |

---

## Architecture Assessment

### What's done well

1. **Flash-loan isolation** — reserve-level accounting, no obligation-level coupling. Instruction-introspection for borrow/repay pairing is a sound Solana pattern.
2. **CPI callback guard** — `progress_callback_program` is Anchor-constrained, not caller-supplied. Vault account owner-validated at ticket creation.
3. **Permissioning framework** — three-tier model (market-level, reserve-level, `check_permissions_and_strip`). Consistent enforcement across deposit/borrow/liquidate handlers.
4. **Post-transfer balance checks** — vault balance and available liquidity verified after every token movement action.
5. **Per-reserve flash-loan disable** — `flash_loan_fee_sf == u64::MAX` circuit breaker.

### Key concerns

1. **Access control gaps** — `redeem_fees` and `withdraw_protocol_fee` have zero signer checks. Any transaction can trigger token transfers via PDA-signed CPI.
2. **Cosmetic two-step patterns** — `global_admin` → `pending_admin` → `apply` looks like secure transfer but has no guard against self-approval.
3. **Missing edge-case guards** — three LTV functions panic on zero collateral. Oracle price of zero causes div-by-zero panic in liquidation math. These are not attacker-trigger conditions — normal market paths.
4. **Silent arithmetic corruption** — `BigFraction::mul` wraps on overflow without any guard or panic. Borrow rate curve overflows silently. These are the most dangerous because they produce no error — just wrong values.
5. **Systematic rounding bias** — `div_ceil` off-by-one compounded by liquidation repay-ceil / collateral-floor asymmetry. Liquidators systematically lose.

---

## Severity Distribution

```
CRITICAL ████░░░░░░ 2  (11.8%)
HIGH     ██████████ 6  (35.3%)
MEDIUM   ██████████ 6  (35.3%)
LOW      █████░░░░░ 3  (17.6%)
```

---

## Root Cause Patterns

1. **No overflow protection on critical math** (C-2, H-5): `u128::mul` and `U256::mul` used without `checked_mul` in financial arithmetic. Fix: audit all `fraction.rs` operations for checked math.

2. **Zero-value edge cases not guarded** (H-4, H-6): `loan_to_value()` and `max_liquidatable_borrowed_amount()` use plain `/` with no zero-denominator path. Fix: add zero-value guards returning safe defaults.

3. **Missing signer validation on fee-collection instructions** (H-1, M-2): Both `redeem_fees` and `withdraw_protocol_fee` use PDA-signed token transfers with no caller signer constraint. Fix: require owner/admin co-signature.

4. **Circumventable two-step patterns** (H-2): The admin transfer pattern allows the same entity to set and apply in separate transactions. Fix: require both current and future admin signatures on the apply step.

5. **Systematic rounding errors** (C-1, H-6, M-4): Multiple rounding paths compound incorrectly. Fix: align rounding direction, fix `div_ceil` formula.
