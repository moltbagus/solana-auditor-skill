# Quick Scan Results — AMM/DEX Fixture

Pattern matching output from audit-quick command.

## Scan Configuration

- **Target:** `examples/dex-amm/programs/`
- **Rules:** 50 security rules from `rules/audit.rules`
- **Mode:** Pattern matching with semantic enrichment

---

## Scan Results

### CRITICAL Patterns Detected

#### Rule 14 — Reentrancy

```
File: programs/amm/src/lib.rs
Lines: 52, 62
Pattern: token::transfer before state mutation
Context:
  token::transfer(...)  // Line 52
  ctx.accounts.pool.virtual_balance -= amount  // Line 62
SEVERITY: CRITICAL
```

```
File: programs/swap/src/lib.rs
Lines: 47
Pattern: token transfer without reentrancy guard
Context:
  token::transfer(...)  // Line 47
  // No is_locked flag set
SEVERITY: CRITICAL
```

#### Rule 26 — Flash Loans

```
File: programs/amm/src/lib.rs
Lines: 94-101
Pattern: arbitrary Vec<u64> amounts parameter
Context:
  pub fn execute_arbitrage(ctx: Context<Arbitrage>, amounts: Vec<u64>) -> Result<()>
  for amt in amounts {
      ctx.accounts.pool.balance += amt
  }
SEVERITY: CRITICAL
```

---

### HIGH Patterns Detected

#### Rule 15 — Remaining Accounts

```
File: programs/amm/src/lib.rs
Lines: 77
Pattern: remaining_accounts forwarded to invoke
Context:
  invoke(&swap_ix, &ctx.remaining_accounts)
  // No validation of account metas
SEVERITY: HIGH
```

#### Rule 13 — Price Oracles

```
File: programs/amm/src/lib.rs
Lines: 112
Pattern: price_feed.value read without Clock staleness check
Context:
  let price = ctx.accounts.price_feed.value;
  // Missing: Clock::get() staleness verification
SEVERITY: HIGH
```

#### Rule 6 — Arithmetic

```
File: programs/amm/src/lib.rs
Lines: 127
Pattern: multiplication without checked_mul
Context:
  let total = amount_a * amount_b
  // No overflow protection
SEVERITY: HIGH
```

#### Rule 4 — CPI Safety

```
File: programs/amm/src/lib.rs
Lines: 143-152
Pattern: arbitrary invoke to user-supplied program
Context:
  invoke(&Instruction {
      program_id: ctx.accounts.target_program.key(),
      ...
  }, &ctx.remaining_accounts)
SEVERITY: HIGH
```

#### Rule 8 — Signer Verification

```
File: programs/amm/src/lib.rs
Lines: 156-159
Pattern: AccountInfo instead of Signer
Context:
  pub admin: AccountInfo<'info>
  // Should be: Signer<'info>
SEVERITY: HIGH
```

#### Rule 38 — Duplicate Accounts

```
File: programs/swap/src/lib.rs
Lines: 65
Pattern: multiple AccountInfo without dedup
Context:
  token_a: AccountInfo,
  token_b: AccountInfo,
  // No check: token_a.key() != token_b.key()
SEVERITY: HIGH
```

---

### MEDIUM Patterns Detected

#### Rule 40 — Manual Initialization

```
File: programs/swap/src/lib.rs
Lines: 34-39
Pattern: manual field assignment without #[account] init
Context:
  ctx.accounts.pool.virtual_balance = 0;
  ctx.accounts.pool.fee = 30;
  // No 8-byte discriminator written
SEVERITY: MEDIUM
```

#### Rule 6 — Arithmetic (Underflow)

```
File: programs/swap/src/lib.rs
Lines: 94-95
Pattern: subtraction without checked_sub
Context:
  let net = gross - fee;
  // No bounds check on fee_bps
SEVERITY: MEDIUM
```

#### Rule 36 — Sysvars

```
File: programs/oracle/src/lib.rs
Lines: 30-32
Pattern: slot from instruction data instead of Clock
Context:
  ctx.accounts.price_feed.last_update = slot;
  // Should use Clock::get()?.slot
SEVERITY: MEDIUM
```

#### Rule 39 — Account Ownership

```
File: programs/oracle/src/lib.rs
Lines: 41-45
Pattern: try_borrow_data without owner check
Context:
  let data = ctx.accounts.data_account.try_borrow_data()?;
  // No verification: data_account.owner == ctx.program_id
SEVERITY: MEDIUM
```

#### Rule 37 — Account Constraints

```
File: programs/oracle/src/lib.rs
Lines: 53
Pattern: mutated account without #[account(mut)]
Context:
  ctx.accounts.price_feed.value = new_price;
  // #[account(mut)] missing from UpdateOracle struct
SEVERITY: MEDIUM
```

---

## Pattern Match Summary

| Pattern | Count | Max Severity |
|---------|-------|--------------|
| Rule 14 — Reentrancy | 2 | CRITICAL |
| Rule 26 — Flash Loans | 1 | CRITICAL |
| Rule 15 — Remaining Accounts | 1 | HIGH |
| Rule 13 — Price Oracles | 1 | HIGH |
| Rule 6 — Arithmetic | 2 | HIGH |
| Rule 4 — CPI Safety | 1 | HIGH |
| Rule 8 — Signer Verification | 1 | HIGH |
| Rule 38 — Duplicate Accounts | 1 | HIGH |
| Rule 40 — Manual Init | 1 | MEDIUM |
| Rule 36 — Sysvars | 1 | MEDIUM |
| Rule 39 — Account Ownership | 1 | MEDIUM |
| Rule 37 — Account Constraints | 1 | MEDIUM |

**Total Unique Patterns:** 12
**Total Matches:** 14

---

## Scan Statistics

- **Files Scanned:** 3
- **Lines Analyzed:** ~300
- **Rules Matched:** 12
- **True Positives:** 14
- **False Positives:** 0
- **Scan Time:** <1s

---

## Recommendations

1. **Immediate:** Fix all CRITICAL and HIGH severity findings before any deployment
2. **Short-term:** Add automated checks for Rules 6, 8, 14, 15 in CI pipeline
3. **Long-term:** Implement comprehensive fuzzing for arithmetic operations and CPI paths
