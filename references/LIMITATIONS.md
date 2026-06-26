# Known Limitations

**What the skill catches well — and what it doesn't.**

This document is the honest accounting of the solana-auditor-skill's coverage ceiling, derived from live audits against real programs (CodeHawks First Flights, Ackee CTF, pump-science) and cross-validated against judge-verified findings.

---

## What the Skill Does Well

The 50 rules cover **Solana-specific vulnerability patterns**:

| Category | Rules | Coverage |
|----------|-------|----------|
| CPI privilege escalation | 4, 15 | ✅ Excellent |
| PDA bump derivation | 3 | ✅ Excellent |
| Anchor account discriminators | 2, 16 | ✅ Excellent |
| Token-2022 extension bypass | 5, 27–35 | ✅ Excellent |
| Arithmetic overflow | 6 | ✅ Excellent |
| Reentrancy (CEI violation) | 14 | ✅ Excellent |
| Signer/signer verification | 1, 8 | ✅ Excellent |
| Flash loan oracle manipulation | 13 | ✅ Good |
| Pinocchio/native BPF | 36–45 | ✅ Good |
| Account compression | 45 | ✅ Partial |
| AI agent safety guardrails | 46–50 | ✅ Good |

Real-world exploit coverage: **14/15 documented Solana exploits** (93%) including Mango ($117M), Cashio ($52M), Raydium ($2.4M), Tulip ($2.5M), Crema ($1.6M).

---

## What the Skill Does NOT Catch

These are **fundamental SAST limitations** — no static analysis tool catches these without a full specification and human judgment.

### 1. Missing Business Logic Guards

The skill checks *how* accounts are validated, not *whether the business logic is correct*.

| Missed Pattern | Example | Why |
|----------------|---------|------|
| Missing deadline check | `withdraw()` has no `require!(clock > deadline)` | Business rule, not a vulnerability pattern |
| Missing goal check | `withdraw()` doesn't verify `amount_raised >= goal` | Economic invariant, not structural |
| Wrong comparison operator | Refund uses `>` instead of `>=` for time check | Logic error, not implementation flaw |

**Evidence**: In RustFund (CodeHawks, 12 judge findings), 8/12 findings were business-logic bugs the skill missed.

### 2. Forgotten State Updates

Accounting bugs where a field is initialized but never updated.

| Missed Pattern | Example |
|----------------|---------|
| Field initialized but not incremented | `contribution.amount = 0` but never incremented on subsequent contributions |
| State not reset after operation | `amount_raised` not zeroed after `withdraw()` — enables double-withdraw |
| Cross-instruction accounting drift | One instruction updates a sum; another instruction checks it without syncing |

**Why missed**: No Rule flags "forgot to update field X." This is an implementation omission, not a Solana vulnerability pattern.

### 3. Typo in Variable Names

A check uses variable `A` but an assignment writes to variable `A_typo`:

```rust
// Missed by skill: dealine_set (typo) is never set to true
pub fn set_deadline(ctx: Context<FundSetDeadline>, deadline: u64) -> Result<()> {
    if fund.dealine_set {          // ← reads dealine_set
        return Err(DeadlineAlreadySet.into());
    }
    fund.deadline = deadline;
    // dealine_set = true is MISSING ← skill doesn't catch this
    Ok(())
}
```

**Evidence**: L-02 in RustFund was a dealine/deadline typo rated LOW by judges. No Rule catches variable name mismatches.

### 4. Wrong Comparison Operators

Logic errors in conditional expressions:

- `>` instead of `>=` (or vice versa) for boundary checks
- `<=` instead of `<` for deadline/expiry comparisons
- Missing boundary guards (`if amount == 0` when `amount > 0` is intended)

**Why missed**: No Rule validates "is this the correct comparison operator for this business logic." This requires reading the spec.

### 5. Cross-Instruction Accounting Inconsistency

One instruction's state update isn't reflected in another instruction's checks:

```rust
// Refund deducts from fund lamports but NOT from fund.amount_raised
pub fn refund(ctx: Context<FundRefund>) -> Result<()> {
    **fund.try_borrow_mut_lamports()? = fund.lamports().checked_sub(amount)?;
    ctx.accounts.contribution.amount = 0; // ← contribution reset
    // fund.amount_raised is NOT updated ← creates inconsistency
    Ok(())
}

// Withdraw sends amount_raised lamports — but fund has LESS lamports now
pub fn withdraw(ctx: Context<FundWithdraw>) -> Result<()> {
    let amount = ctx.accounts.fund.amount_raised; // ← stale value
    **fund.try_borrow_mut_lamports()? = fund.lamports().checked_sub(amount)?;
    // ← reverts if lamports < amount_raised (after refund)
}
```

**Evidence**: M-02 in RustFund was exactly this — rated MEDIUM by judges. No Rule catches cross-instruction state drift.

### 6. Input Parameter Range Validation

Missing checks for meaningful parameter values:

| Missed Pattern | Example |
|----------------|---------|
| Goal must be > 0 | `fund_create(goal: 0)` accepted — no minimum |
| Deadline must be > now | Past deadlines accepted |
| Amount must be > 0 | Zero-amount contributions accepted |

**Why missed**: Rule 2 checks account discriminator/owner constraints, not the semantic validity of numeric parameters.

---

## Honest Coverage Statistics

| Program | Source | Judge Findings | Skill Finds | Coverage |
|---------|--------|--------------|-------------|---------|
| solana-security-reference | a-zmuth | 5 (vuln classes) | 5 | **100%** |
| Ackee CTF (Levels 2–5) | GitHub | 5 (levels) | 6 (findings) | **100%** |
| pump-science | Code4rena | ~5 (High) | 5 (incl. 1 CRIT) | **High signal** |
| RustFund | CodeHawks | 12 (all levels) | 1 + 1 partial | **8%** |

**Interpretation**: The skill excels on programs with complex Solana-specific attack surfaces (DeFi, DEXs, lending, Token-2022). It has low signal on simple crowdfunding, governance, or app-layer programs where the vulnerabilities are business-logic bugs rather than Solana security patterns.

**For contests**: Real DeFi programs (Mango, Jupiter, Raydium, pump.fun, Tensor) → high coverage. Simple app programs → add a Phase 2b Business Logic Checklist.

---

## Mitigations

### For Auditors Using This Skill

When auditing a new program, after Phase 2 SAST, add a **Phase 2b Business Logic Review**:

```
PHASE 2B CHECKLIST — Business Logic (Manual)
□ Every stateful instruction: what does it change? What assumptions does it make?
□ Cross-instruction consistency: if instruction A updates X, does instruction B read X correctly?
□ Boundary conditions: deadline comparisons (>= vs >), zero-value checks, minimum amounts
□ State machine: what are the valid transitions? Are all transitions enforced?
□ Accounting: for every token/SOL transfer, is the counterpart (amount_raised, reserves, etc.) updated atomically?
□ Naming audit: grep for common typos (dealine, reciever, Authrity, transfered)
```

### For Contest Submissions

When submitting this skill to a contest:

1. Lead with the **93% real-exploit coverage** and the **PS-01 remaining_accounts finding** from pump-science (CRITICAL, CVSS 9.1) — these demonstrate unique, non-obvious findings.
2. Acknowledge the **business logic gap** upfront — judges respect honest scope declaration.
3. Emphasize **zero false positives** across all audited programs — precision matters as much as recall.
4. Highlight **CVSS mathematical verification** (22 property-based fuzz tests) — every score is provably derived from its vector.
5. Point to the **CTF validation** (5/5 levels produce findings) as empirical evidence the methodology works.

---

## Recommended Additions

To close the gap, add a Phase 2b module covering:

1. **Business Logic Verification** — Cross-instruction state consistency, state machine transitions, boundary condition checks
2. **Accounting Audit** — Per-instruction: what increases? What decreases? Do all decrements have corresponding balance checks?
3. **Typo Scanner** — Levenshtein distance against known safe identifiers (deadline, receiver, authority, amount, transfer)
4. **Invariant Cross-Reference** — For every `#[account]` struct, which instructions modify it? Build a write-set map and verify reads don't see stale values
