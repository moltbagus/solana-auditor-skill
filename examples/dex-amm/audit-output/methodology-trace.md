# Methodology Trace — AMM/DEX Fixture

Per-vulnerability traces showing which audit phase and rule detected each finding.

## Detection Phases

1. **Phase 1: Static Analysis** — Pattern matching on source code
2. **Phase 2: Data Flow Analysis** — Taint tracking, input validation
3. **Phase 3: Semantic Analysis** — Contextual reasoning about program logic
4. **Phase 4: Interaction Testing** — CPI analysis, cross-program patterns

---

## VULN-01: Reentrancy on withdraw

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 1 | Rule 14 | Pattern match: `token::transfer` before state mutation |
| Phase 3 | — | CEI pattern violation identified via semantic analysis |
| Phase 4 | — | Callback injection vector confirmed |

**Trace:** `token::transfer` at line 52 → state update at line 62 → gap enables reentrancy

**Mitigation Verified:**
```rust
// CEI-compliant: Effects before Interactions
ctx.accounts.pool.virtual_balance = pool.virtual_balance.saturating_sub(amount);
token::transfer(ctx.accounts.token_transfer_ctx(), amount)?;
```

---

## VULN-02: Remaining accounts forwarded without validation

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 1 | Rule 15 | Pattern match: `ctx.remaining_accounts` passed to `invoke` |
| Phase 2 | — | Taint analysis: attacker-controlled account metas |
| Phase 3 | — | No allowlist validation found |

**Trace:** `remaining_accounts` → `invoke(&swap_ix, &ctx.remaining_accounts)` → no validation

**Mitigation Verified:**
```rust
// Validate all accounts against expected mint/program
for account in ctx.remaining_accounts.iter() {
    require!(account.owner == &token_program::ID, ErrorCode::InvalidAccount);
}
```

---

## VULN-03: Flash loan composition

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 1 | Rule 26 | Pattern match: arbitrary `Vec<u64>` amounts parameter |
| Phase 2 | — | No balance snapshot check |
| Phase 3 | — | No pre/post state validation |

**Trace:** `amounts: Vec<u64>` → `checked_add(amt)` → no flash loan protection

**Mitigation Verified:**
```rust
let pre_balance = ctx.accounts.pool.balance;
for amt in amounts {
    // validate amount against pre-balance
    require!(amt <= pre_balance, ErrorCode::InvalidAmount);
}
```

---

## VULN-04: Price oracle manipulation via stale data

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 1 | Rule 13 | Pattern match: `price_feed.value` read without Clock check |
| Phase 3 | — | No staleness validation found |

**Trace:** `ctx.accounts.price_feed.value` → no `Clock::get()` → stale price accepted

**Mitigation Verified:**
```rust
let clock = Clock::get()?;
let staleness = clock.slot.saturating_sub(price_feed.last_update);
require!(staleness <= MAX_STALENESS, OracleError::PriceStale);
```

---

## VULN-05: Arithmetic overflow in liquidity calculation

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 1 | Rule 6 | Pattern match: `amount_a * amount_b` without checked_mul |
| Phase 2 | — | Both operands are user-controlled |

**Trace:** `let total = amount_a * amount_b` → release mode overflow → silent wrap

**Mitigation Verified:**
```rust
let total = amount_a.checked_mul(amount_b).ok_or(AmmError::Overflow)?;
```

---

## VULN-06: Arbitrary CPI via callback

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 1 | Rule 4 | Pattern match: `invoke` with `target_program.key()` |
| Phase 2 | — | No program allowlist found |
| Phase 3 | — | User-controlled program_id and data |

**Trace:** `target_program: AccountInfo` → `invoke(&ix, &ctx.remaining_accounts)` → arbitrary CPI

**Mitigation Verified:**
```rust
// Use Program<AllowedProgram> instead of AccountInfo
pub target_program: Program<'info, Token>,
// Or maintain allowlist
require!(ALLOWED_PROGRAMS.contains(&target_program.key()), ErrorCode::UnauthorizedProgram);
```

---

## VULN-07: Missing signer on pool admin

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 1 | Rule 8 | Pattern match: `admin: AccountInfo` instead of `Signer` |
| Phase 3 | — | No `is_signer` check found |

**Trace:** `pub admin: AccountInfo<'info>` → no Signer constraint → anyone can call

**Mitigation Verified:**
```rust
pub admin: Signer<'info>,
#[account(has_one = authority)]
pub pool: Account<'info, AmmPool>,
```

---

## VULN-08: Manual init without discriminator check

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 1 | Rule 40 | Pattern match: manual field assignment in init function |
| Phase 3 | — | No `#[account]` init or discriminator verification |

**Trace:** `ctx.accounts.pool.virtual_balance = 0` → no discriminator written → reinit possible

**Mitigation Verified:**
```rust
#[account(init, payer = authority, space = 8 + AmmPool::INIT_SPACE)]
pub pool: Account<'info, AmmPool>,
// Or use Account<'info, AmmPool> which verifies discriminator
```

---

## VULN-09: Reentrancy via token callback

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 1 | Rule 14 | Pattern match: `token::transfer` without reentrancy guard |
| Phase 3 | — | No is_locked flag on pool |

**Trace:** `token::transfer` → state update after → reentrancy window open

**Mitigation Verified:**
```rust
require!(!pool.is_locked, AmmError::ReentrancyDetected);
pool.is_locked = true;
// ... transfer ...
pool.is_locked = false;
```

---

## VULN-10: Duplicate mutable account

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 1 | Rule 38 | Pattern match: multiple `AccountInfo` fields without dedup check |
| Phase 3 | — | Same account can be passed twice |

**Trace:** `token_a: AccountInfo` + `token_b: AccountInfo` → no dedup check → double-spend

**Mitigation Verified:**
```rust
require!(token_a.key() != token_b.key(), SwapError::DuplicateAccount);
```

---

## VULN-11: Arithmetic underflow in fee calculation

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 1 | Rule 6 | Pattern match: `gross - fee` without checked_sub |
| Phase 2 | — | fee_bps user-controlled, no upper bound check |

**Trace:** `let net = gross - fee` → fee_bps > 10000 → underflow → wrapped value

**Mitigation Verified:**
```rust
require!(fee_bps <= 10000, SwapError::InvalidFeeBps);
let net = gross.checked_sub(fee).ok_or(SwapError::Underflow)?;
```

---

## VULN-12: Sysvar spoofing

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 1 | Rule 36 | Pattern match: `slot: u64` parameter used instead of Clock |
| Phase 3 | — | User-controlled slot stored as last_update |

**Trace:** `slot: u64` from instruction → `ctx.accounts.price_feed.last_update = slot` → spoofed

**Mitigation Verified:**
```rust
let clock = Clock::get()?;
ctx.accounts.price_feed.last_update = clock.slot;
```

---

## VULN-13: Unsafe deserialization without owner check

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 1 | Rule 39 | Pattern match: `try_borrow_data()` without owner check |
| Phase 2 | — | No validation that data_account.owner == program_id |

**Trace:** `ctx.accounts.data_account.try_borrow_data()?` → any account data readable

**Mitigation Verified:**
```rust
require!(data_account.owner == ctx.program_id, OracleError::InvalidOwner);
```

---

## VULN-14: Missing writable constraint

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 1 | Rule 37 | Pattern match: account mutated but `#[account(mut)]` missing |
| Phase 3 | — | Anchor constraint validation gap |

**Trace:** `ctx.accounts.price_feed.value = new_price` → `#[account(mut)]` absent → runtime error

**Mitigation Verified:**
```rust
#[derive(Accounts)]
pub struct UpdateOracle<'info> {
    #[account(mut)]
    pub price_feed: Account<'info, PriceFeed>,
    pub updater: Signer<'info>,
}
```

---

## Summary

| Vulnerability | Primary Rule | Detection Phase |
|--------------|--------------|-----------------|
| VULN-01 | Rule 14 | Phase 1 |
| VULN-02 | Rule 15 | Phase 1 |
| VULN-03 | Rule 26 | Phase 1 |
| VULN-04 | Rule 13 | Phase 1 |
| VULN-05 | Rule 6 | Phase 1 |
| VULN-06 | Rule 4 | Phase 1 |
| VULN-07 | Rule 8 | Phase 1 |
| VULN-08 | Rule 40 | Phase 1 |
| VULN-09 | Rule 14 | Phase 1 |
| VULN-10 | Rule 38 | Phase 1 |
| VULN-11 | Rule 6 | Phase 1 |
| VULN-12 | Rule 36 | Phase 1 |
| VULN-13 | Rule 39 | Phase 1 |
| VULN-14 | Rule 37 | Phase 1 |
