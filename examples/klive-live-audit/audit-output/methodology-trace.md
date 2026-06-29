# Methodology Trace — Kamino Finance Lend Live Audit

Per-finding traces showing which audit phase and rule detected each finding.

## Detection Phases

1. **Phase 1: Reconnaissance** — Source verification, constraint analysis
2. **Phase 2: Static Analysis** — SAST pattern matching
3. **Phase 1C: Economic Security** — Tokenomics and invariant analysis

---

## KAM-001: Token2022 transfer fee not deducted

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 1 | Rule 5 | Source verified: `deposit_reserve_liquidity_transfer` reads `liquidity_amount` not actual received amount |
| Phase 1C | — | Economic invariant violation: collateral mint > actual token received |

**Trace:** `transfer_checked` CPI → reserve receives `amount - fee` → collateral minted from full `amount` → undercollateralization

**Severity:** CRITICAL — systematic, grows over time, enables drain

---

## KAM-002: U256 BigFraction overflow [RESOLVED]

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 1 | Rule 6 | Source verified: `fraction.rs` rewritten, `U68F60` replaces `U256` |

**Trace:** `BigFraction` removed → `fixed::types::U68F60` with `checked_mul` throughout → overflow impossible

**Severity:** RESOLVED — no longer exploitable