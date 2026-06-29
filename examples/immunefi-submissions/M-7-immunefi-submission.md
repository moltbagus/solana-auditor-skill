# Immunefi Submission: M-7 — Liquidation Bonus Formula Computes 4.762% Instead of 5%

---

## Program

Kamino Finance — Smart Contract

---

## Vulnerability Type

Math / Formula Error (CWE-682)

---

## Title

`calculate_protocol_liquidation_fee` uses incorrect liquidation bonus formula, causing liquidators to systematically receive 4.762% bonus instead of the configured 5% — reducing liquidation incentive and potentially leaving insolvent positions un-liquidated

---

## Severity

**MEDIUM**

---

## CVSS

`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L` — **6.5 (MEDIUM)**

| Metric | Value | Rationale |
|--------|-------|-----------|
| AV | N | Exploitable via RPC — no local access needed |
| AC | L | Standard liquidation transaction; no special conditions |
| PR | N | No privileges needed — any liquidator can call liquidation |
| UI | N | No victim interaction needed |
| S | U | Scope limited to this program |
| C | N | No data exposure |
| I | L | Liquidators systematically underpaid; protocol loses incentive alignment |
| A | L | No fund loss but reduced liquidation incentive may delay healthy liquidations |

---

## Description

### Root Cause

In `programs/klend/src/state/liquidation_operations.rs:954-958`:

```rust
let bonus = amount_liquidated - (amount_liquidated / bonus_multiplier);
```

Where `bonus_multiplier = liquidation_bonus_rate + Fraction::ONE` (e.g., `1.05` for a 5% bonus rate).

This computes:
```
bonus = amount_liquidated × (1 - 1 / bonus_multiplier)
      = amount_liquidated × (1 - 1/1.05)
      = amount_liquidated × 0.047619
```

The correct formula for the liquidator bonus is:
```rust
let bonus = amount_liquidated * liquidation_bonus_rate;  // 0.05 × amount
```

### Confusion Clarified

The variable is named `bonus` because it IS the liquidator's bonus — the extra collateral the liquidator receives above their repayment. The protocol then takes a fraction of this as a fee:

```rust
let protocol_fee = bonus * protocol_liquidation_fee_pct;  // e.g., 20% of bonus
```

So the full chain is:
- Liquidator repays $X of debt
- Liquidator receives collateral worth $X + bonus (the incentive)
- Protocol takes `protocol_fee = bonus × protocol_liquidation_fee_pct`
- Liquidator nets `bonus - protocol_fee`

The formula bug means the liquidator's bonus is **4.762%** of `amount_liquidated` instead of **5.0%** — a 4.76% reduction in the liquidation incentive on every liquidation.

### Secondary Issue

`max(protocol_fee, 1)` at line 960 forces a minimum 1-lamport protocol fee even when `protocol_liquidation_fee_pct = 0`. This creates a dust leak on reserves with fee collection disabled.

### Impact

**Systematic liquidator incentive degradation.** For every liquidation:

| Configuration | Intended Bonus | Actual Bonus | Reduction |
|---|---|---|---|
| 5% bonus rate | 5.000% | 4.762% | −4.76% |
| 10% bonus rate | 10.000% | 9.091% | −9.09% |
| 15% bonus rate | 15.000% | 13.043% | −13.04% |

**Why this matters:**

1. Liquidators earn less per liquidation than the protocol intends
2. At scale, this creates a systematic subsidy gap — liquidators are mildly disincentivized relative to the intended economics
3. In competitive liquidation markets, the 4.76% reduction may discourage participation on small liquidations or thinly-profitable positions
4. Insufficient liquidation incentive can cause healthy positions to drift further into insolvency before being liquidated
5. The bug is **silent and systematic** — no transaction reverts, no alerts, the discrepancy is absorbed by the liquidator

**Numerical example:** At a 5% bonus rate on $1M in daily liquidations, liquidators collectively receive $2,381 less per day than intended ($50,000 expected vs $47,619 actual). At $100M daily volume: $238,100 systematic underpayment per day.

---

## Proof of Concept

### PoC File

Attached: `M-7-liquidation_bonus_formula.rs`

### How to Run

```bash
rustc M-7-liquidation_bonus_formula.rs -o poc_m7 && ./poc_m7
```

Zero dependencies — only `rustc` required.

### Expected Output

```
=== Liquidation Bonus Formula Bug ===
Bonus multiplier: 1.05 (5% configured rate)

  Intended formula: bonus = amount * 0.05
  Intended bonus:   $50,000.00 on $1,000,000 liquidation

  Buggy formula:    bonus = amount * (1 - 1/1.05)
  Buggy bonus:      $47,619.05 on $1,000,000 liquidation

  Leak per $1M:    $2,380.95
  Leak percentage:  4.76%
```

---

## Vulnerable Code

- `calculate_protocol_liquidation_fee` — `programs/klend/src/state/liquidation_operations.rs:954-958`

---

## Recommendation

```rust
// CURRENT (buggy): bonus = amount * (1 - 1/bonus_multiplier)
// CORRECT:         bonus = amount * liquidation_bonus_rate

let bonus = amount_liquidated * liquidation_bonus_rate;

// Then protocol fee:
let protocol_fee = bonus * protocol_liquidation_fee_pct;
let protocol_fee = std::cmp::max(protocol_fee, 1).unwrap_or(1); // apply min only if pct > 0
```

The `max(protocol_fee, 1)` guard should only be applied conditionally when `protocol_liquidation_fee_pct > 0`, not unconditionally.
