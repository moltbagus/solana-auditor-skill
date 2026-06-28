# Staking Pool Fixture — Audit Report

**Program**: staking-pool (Anchor 0.31.1, 3 programs)
**Repo**: `examples/staking-pool/`
**Audit Date**: 2026-06-28
**Auditor**: solana-auditor-skill skill v1.0
**Methodology**: 6-phase lifecycle — recon, static analysis, formal verification, triage, report, remediation
**Tools**: ripgrep pattern matching, manual review

---

## Executive Summary

The `staking-pool` fixture contains **14 security vulnerabilities** across 3 programs (staking, rewards, delegation). The two CRITICAL findings (VULN-01, VULN-08) enable direct theft of funds via reentrancy and CPI injection. Seven HIGH findings enable reward manipulation, privilege escalation, and account confusion. Five MEDIUM findings weaken system integrity and enable denial-of-service.

This program is **NOT SAFE TO DEPLOY** in its current state. All CRITICAL and HIGH findings must be remediated before any production use. The MEDIUM findings should be addressed in the same release cycle.

The most severe issue (VULN-01) allows an attacker to re-enter the `claim` instruction during the lamport transfer and double-claim rewards, draining the pool. Combined with VULN-08 (arbitrary CPI injection via remaining_accounts), the attacker has multiple paths to extract funds.

---

## Architecture Review Summary

### Program Design Overview

The `staking-pool` fixture implements three Anchor programs (v0.31.1) modeling a simplified Marinade/Jito-style staking pool:

- **staking**: Core staking pool with position management, validator registry, and reward computation
- **rewards**: Reward distribution with CPI callbacks and compound interest
- **delegation**: Validator stake delegation with vote recording

### Account Architecture

| Program | Account Type | Purpose | Access Control |
|---------|-------------|---------|----------------|
| staking | Pool | Global pool state, authority, reward rate | PDA — `[]` |
| staking | Position | Per-user stake position | PDA — `["position", user]` |
| staking | Validator | Validator registry | PDA — `["validator", name]` |
| staking | State | Reward accrual state | PDA — `[]` |
| rewards | RewardState | Per-user reward balance | Program state |
| delegation | StakeAccount | Validator stake delegation | PDA — `["stake", validator]` |
| delegation | VoteRecord | Vote slot record | PDA — `["vote", validator, slot]` |

### Cross-Program Invocations

| Target | Purpose | Trust Assumption |
|--------|---------|------------------|
| System Program | Lamport transfers in claim, distribute | Trusted — immutable Solana core |
| Arbitrary programs (VULN-09) | Callback invocation | Untrusted — attacker-controlled |

### Data Flow

```
Transaction
      │
      ▼
┌─────────────────────────┐
│  Instruction           │ ── No reentrancy guard on claim (VULN-01)
│  Deserialization        │ ── Missing Signer on admin (VULN-05)
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Account Validation     │ ── remaining_accounts forwarded unvalidated (VULN-08)
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Business Logic         │ ── Arithmetic overflow (VULN-04, VULN-10)
│                          │ ── Arbitrary CPI (VULN-09)
│                          │ ── Duplicate mutable account (VULN-11)
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  State Write            │ ── Reinit (VULN-06), hardcoded bump (VULN-12)
│                          │ ── Sysvar spoofing (VULN-13), missing mut (VULN-14)
└─────────────────────────┘
```

---

## Scope

**Audited**:
- `programs/staking/src/lib.rs` (1 file, 234 lines, 7 instructions across 6 Accounts structs)
- `programs/rewards/src/lib.rs` (1 file, 142 lines, 4 instructions across 4 Accounts structs)
- `programs/delegation/src/lib.rs` (1 file, 136 lines, 3 instructions across 3 Accounts structs)

**Out of Scope**:
- `Cargo.toml` dependency analysis
- `Anchor.toml` (default config)
- Test suite (none present)
- IDL generation

---

## Severity Summary

| Severity | Count | IDs |
|----------|-------|-----|
| CRITICAL | 2     | VULN-01, VULN-08 |
| HIGH     | 7     | VULN-02, VULN-03, VULN-04, VULN-05, VULN-09, VULN-10, VULN-11 |
| MEDIUM   | 5     | VULN-06, VULN-07, VULN-12, VULN-13, VULN-14 |
| LOW      | 0     | — |
| INFO     | 0     | — |

---

## Findings

### VULN-01: Reentrancy double-claim via CEI pattern violation — CRITICAL

- **CVSS**: 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **CWE**: CWE-362 (Race Condition)
- **Location**: `programs/staking/src/lib.rs:25` — `claim`
- **Rule caught**: Rule 14 — Reentrancy Guards

**Description**

The `claim` instruction transfers lamports to the user account BEFORE updating the `user_position.claimed_rewards` state. No reentrancy guard is set before the external call. An attacker can re-enter the program during the lamport transfer and claim rewards a second time before the state update executes, draining the pool.

**Impact**

Double-claim of rewards. The attacker claims once in the outer call and again in the re-entered call, doubling their reward extraction per transaction. Repeated calls drain the pool of all reward lamports.

**Recommendation**

Follow the Checks-Effects-Interactions (CEI) pattern strictly: update state before any external call. Set a reentrancy guard flag before the lamport transfer and verify it in the instruction entry. Use Anchor's reentrancy guard pattern or a one-time-use bump seed.

---

### VULN-08: remaining_accounts CPI injection — attacker-controlled CPI accounts — CRITICAL

- **CVSS**: 8.6 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`)
- **CWE**: CWE-862 (Missing Authorization)
- **Location**: `programs/rewards/src/lib.rs:33` — `distribute`
- **Rule caught**: Rule 15 — remaining_accounts in CPI

**Description**

The `distribute` instruction forwards `ctx.remaining_accounts` directly to the system program's transfer instruction without validating which accounts appear in the slice. An attacker can craft a transaction where `remaining_accounts` contains different (mutable) accounts than `from` and `to`, injecting arbitrary lamport transfers into the CPI call.

**Impact**

Arbitrary lamport transfer via CPI injection. The attacker redirects the system program's transfer to any account pair of their choosing, draining lamports from the program's `from` account to an attacker-controlled destination.

**Recommendation**

Never forward `remaining_accounts` to a CPI without validation. Build the account metas array explicitly. If `remaining_accounts` are genuinely needed, validate each account key against an allowlist before forwarding.

---

### VULN-02: init_if_needed race condition — unbumped PDA reinitialization — HIGH

- **CVSS**: 8.2 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)
- **CWE**: CWE-665 (Improper Initialization)
- **Location**: `programs/staking/src/lib.rs:43` — `stake`
- **Rule caught**: Rule 22 — init_if_needed Race Conditions

**Description**

The `stake` instruction uses `init_if_needed` to create the position account if it does not exist, but the bump parameter is passed as an unverified instruction argument and never compared against `ctx.bumps.position`. An attacker who knows the PDA seeds can call `stake()` repeatedly to reset the `virtual_stake` to a new value.

**Impact**

Virtual stake reset attack. Attacker reinitializes the position to a known `virtual_stake` value to manipulate the reward distribution or inflate their apparent stake share.

**Recommendation**

Use `ctx.bumps.position` directly instead of the caller-supplied bump. Verify the bump matches: `require!(bump == ctx.bumps.position, StakingError::InvalidBump);`. Alternatively, add a one-time discriminator field that prevents reinitialization.

---

### VULN-03: Lamport griefing via unfunded PDA occupation — HIGH

- **CVSS**: 7.4 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`)
- **CWE**: CWE-770 (Allocation of Resources Without Limits or Throttling)
- **Location**: `programs/staking/src/lib.rs:60` — `register_validator`
- **Rule caught**: Rule 41 — Lamport Griefing

**Description**

The `register_validator` instruction creates a validator PDA without verifying that the payer account has sufficient lamports for rent-exemption. An attacker can pre-compute validator PDAs using known name strings and create unfunded accounts at those addresses, blocking legitimate registrations.

**Impact**

Denial of service against the validator registry. Legitimate validators cannot register because their desired name strings map to already-existing (but unfunded) PDA addresses controlled by the attacker.

**Recommendation**

Add a rent-exemption check: `if validator.lamports() < Rent::get()?.minimum_balance(validator.data_len()) { return Err(...) }`. Alternatively, use a registry-counting approach where the program controls the PDA derivation to prevent pre-computation.

---

### VULN-04: Arithmetic overflow in reward calculation — HIGH

- **CVSS**: 7.1 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`)
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **Location**: `programs/staking/src/lib.rs:77` — `compute_rewards`
- **Rule caught**: Rule 6 — Arithmetic

**Description**

The `compute_rewards` function computes `total = staked_amount + (rate_per_slot * slots_elapsed)` using unchecked Rust arithmetic. The multiplication `rate_per_slot * slots_elapsed` can overflow u64 in release mode (wrapping silently). A wrapped reward value can be stored and later used to over-withdraw from the pool.

**Impact**

Reward inflation via overflow. The wrapped total value no longer reflects actual accrual. An attacker who triggers overflow can claim inflated rewards against the pool.

**Recommendation**

Replace with checked arithmetic: `rate_per_slot.checked_mul(slots_elapsed).ok_or(StakingError::Overflow)?`. Apply the same pattern to all arithmetic on user-controlled amounts.

---

### VULN-05: Missing signer verification on admin update_reward_rate — HIGH

- **CVSS**: 7.2 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **CWE**: CWE-306 (Missing Authentication for Critical Function)
- **Location**: `programs/staking/src/lib.rs:90` — `update_reward_rate`
- **Rule caught**: Rule 8 — Signer Verification

**Description**

The `update_reward_rate` instruction declares `admin: AccountInfo<'info>` in the `UpdateRate` Accounts struct. No `Signer` constraint is applied and no `is_signer` check is performed. Any caller can pass any pubkey as the `admin` field and update the pool's `reward_rate` to any value.

**Impact**

Complete reward rate manipulation. An attacker sets `reward_rate` to 0 (DoS) or to an enormous value (inflation attack).

**Recommendation**

Change `admin: AccountInfo<'info>` to `admin: Signer<'info>`. Add `#[account(has_one = admin)]` on the pool account.

---

### VULN-09: Arbitrary CPI via unverified callback instruction — HIGH

- **CVSS**: 8.1 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)
- **CWE**: CWE-347 (Reliance on Untrusted Inputs in a Security Decision)
- **Location**: `programs/rewards/src/lib.rs:46` — `exec_reward_callback`
- **Rule caught**: Rule 4 — CPI Safety

**Description**

The `exec_reward_callback` instruction accepts arbitrary `data: Vec<u8>` and arbitrary `remaining_accounts`, then invokes an arbitrary target program via `invoke()`. The target program ID is read from `ctx.accounts.target` (an unverified `AccountInfo`) with no allowlist check. This is a complete arbitrary CPI gadget.

**Impact**

Total privilege escalation. The attacker can call any program with any instruction data and any accounts in the context of this program's signer privileges.

**Recommendation**

Remove the arbitrary CPI capability entirely. If callbacks are required, use a signed instruction data format with a domain-specific schema. Validate the target program against an on-chain allowlist PDA.

---

### VULN-10: Unchecked arithmetic compound interest calculation — wrapping overflow — HIGH

- **CVSS**: 6.8 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`)
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **Location**: `programs/rewards/src/lib.rs:73` — `compound`
- **Rule caught**: Rule 6 — Arithmetic

**Description**

The `compound` function computes `(principal * (1 + rate/10000)^periods` using `wrapping_pow` on u128 before casting to u64. While u128 provides more headroom than u64, `wrapping_pow` still silently wraps on overflow. A sufficiently large principal with many compounding periods can wrap the u128 result.

**Impact**

Fund loss via compound overflow. The wrapped compounded value is smaller than the correct compound interest, causing the user to receive fewer rewards than earned.

**Recommendation**

Use `checked_pow` instead of `wrapping_pow`: `(1_u128 + rate / 10000).checked_pow(periods_u128 as u32).ok_or(RewardsError::Overflow)?`. Add a maximum period check.

---

### VULN-11: Duplicate mutable account reference — effective credit doubling — HIGH

- **CVSS**: 7.5 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`)
- **CWE**: CWE-366 (Incorrect Calculation)
- **Location**: `programs/rewards/src/lib.rs:89` — `split_rewards`
- **Rule caught**: Rule 38 — Duplicate Mutable Account

**Description**

The `split_rewards` function borrows `account_a` as mutable twice: first to subtract amount, then to add amount back. When `account_a == account_b`, the same account is debited and credited, doubling the credit amount.

**Impact**

Reward inflation via double credit. When `account_a == account_b`, the program loses the extra amount.

**Recommendation**

Enforce that `account_a != account_b`: `require!(account_a.key() != account_b.key(), RewardsError::DuplicateAccount);`. Use separate temporary variables for the debit and credit amounts.

---

### VULN-06: Reinit attack — position account zeroed and reset — MEDIUM

- **CVSS**: 6.5 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`)
- **CWE**: CWE-665 (Improper Initialization)
- **Location**: `programs/staking/src/lib.rs:102` — `reinit_position`
- **Rule caught**: Rule 11 — Reinitialization Attacks

**Description**

The `reinit_position` instruction writes to the position account without verifying the Anchor 8-byte discriminator or any one-time initialization guard. If the position account is closed and re-funded by an attacker, `reinit_position` can be called again to zero `virtual_stake` and `claimed_rewards`.

**Impact**

Position drain via reinitialization. The user loses their staked amount because `virtual_stake` is reset to 0.

**Recommendation**

Add a discriminator check: `require!(ctx.accounts.position.is_initialized(), StakingError::NotInitialized);`. Use Anchor's reinit guard pattern.

---

### VULN-07: Token mint without amount validation — dust attack — MEDIUM

- **CVSS**: 5.8 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`)
- **CWE**: CWE-20 (Improper Input Validation)
- **Location**: `programs/staking/src/lib.rs:114` — `mint_shares`
- **Rule caught**: Rule 5 — Token Operations

**Description**

The `mint_shares` instruction accepts an `amount` parameter with no minimum or maximum threshold check. Dust amounts (1 lamport) can be minted to any `user_shares` account.

**Impact**

State bloating via dust minting. An attacker mints 1-lamport shares to thousands of accounts, diluting existing share holders and wasting rent-exemption lamports.

**Recommendation**

Add minimum and maximum amount checks: `require!(amount >= MIN_SHARE_AMOUNT, StakingError::BelowMinimum); require!(amount <= MAX_SHARE_AMOUNT, StakingError::ExceedsMaximum);`.

---

### VULN-12: Hardcoded bump in PDA derivation — non-canonical bump stored — MEDIUM

- **CVSS**: 6.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **CWE**: CWE-330 (Use of Insufficiently Random Values)
- **Location**: `programs/delegation/src/lib.rs:27` — `create_validator_stake`
- **Rule caught**: Rule 3 — PDA Canonical Bump

**Description**

The `create_validator_stake` instruction accepts `bump` as an instruction parameter and stores it directly in `stake_account.bump` without verifying it against `ctx.bumps.stake_account`. The stored bump may not be the canonical bump. An attacker who finds a colliding bump/seed combination can derive the same PDA address.

**Impact**

PDA collision risk. If the stored bump is non-canonical, an attacker may find an alternative bump that produces the same PDA address, bypassing the program's access control.

**Recommendation**

Use `ctx.bumps.stake_account` directly instead of the caller-supplied bump. Anchor 0.30+ canonicalizes bumps automatically.

---

### VULN-13: Sysvar spoofing via instruction-supplied slot — clock not validated — MEDIUM

- **CVSS**: 5.9 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`)
- **CWE**: CWE-20 (Improper Input Validation)
- **Location**: `programs/delegation/src/lib.rs:42` — `record_vote`
- **Rule caught**: Rule 36 — Sysvar Validation

**Description**

The `record_vote` instruction takes `slot` as an instruction parameter and uses it directly without validating it against the clock sysvar. The weak threshold check (`slot > clock.slot + 100`) is insufficient to prevent manipulation. The clock `AccountInfo` is not validated via `#[account(address = clock::id())]`.

**Impact**

Stale vote bypass. An attacker passes a slot value slightly ahead of the current clock slot but within the +100 threshold, making a stale vote appear valid.

**Recommendation**

Remove the instruction-supplied `slot` parameter. Use `clock.slot` from the verified clock sysvar directly. Add the constraint `#[account(address = clock::ID)]` on the clock account field.

---

### VULN-14: Missing writable enforcement — account mutated without mut constraint — MEDIUM

- **CVSS**: 5.3 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`)
- **CWE**: CWE-283 (Assignment of Improper Fixed Value)
- **Location**: `programs/delegation/src/lib.rs:60` — `deactivate_stake`
- **Rule caught**: Rule 37 — Missing Writable Enforcement

**Description**

The `deactivate_stake` instruction mutates `stake_account.status = 1`, but the `stake_account` field in the `Deactivate` Accounts struct is declared without `#[account(mut)]`. In Anchor, accounts not marked `#[account(mut)]` cannot be written to. The code will fail at runtime.

**Impact**

Instruction failure / constraint bypass. The instruction fails with a runtime error, causing a denial of service for the deactivate operation.

**Recommendation**

Add `#[account(mut)]` to the `stake_account` field in the `Deactivate` struct to make the mutation intent explicit.

---

## Methodology Trace

Each finding was identified using the 6-phase audit methodology. See `audit-output/methodology-trace.md` for the per-finding phase-by-phase trace, including which rule fired, the detection method, CVSS rationale, and trace time.

---

## Disclaimer

This is a fixture program produced to demonstrate the solana-auditor-skill skill. The findings are pre-written and intentionally authored to be caught by the rules in `rules/audit.rules`. The program is not intended for deployment. The `findings.json` and `AUDIT_REPORT.md` are the *expected output* of running `/audit` against this program.

---

## Appendix — Tools & Methodology

- **Pattern matching**: ripgrep with Solana-specific regex
- **Rule engine**: `rules/audit.rules` — 14 rule-to-VULN mappings
- **Methodology**: 6-phase audit lifecycle (`/audit` command)
- **Report schema**: per `commands/audit-report.md` §Required sections
- **No toolchain dependencies**: this audit was performed as a code review
