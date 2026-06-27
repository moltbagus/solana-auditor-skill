# Phase 6: Remediation Guidance

**Goal**: Guide secure fix implementation and verify fixes don't introduce regressions.

---

## Exploit Simulation Framework

### Metadata Schema

Every PoC must be accompanied by a machine-readable metadata file (`<poc-id>-metadata.json`) that lives alongside the PoC markdown. This enables automated ingestion by dashboards, fix suggestion engines, and audit trackers.

```json
{
  "$schema": "https://solana-auditor-skill/schemas/exploit-metadata-v1.json",
  "poc_id": "VULN-01",
  "title": "Admin Signer Bypass Allows Full Vault Drain",
  "severity": "CRITICAL",
  "cvss": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cwe": ["CWE-306"],
  "rule_ids": ["Rule 8"],
  "exploit_class": "privilege-escalation",
  "attack_surface": {
    "entry_point": "admin_withdraw",
    "instruction_index": 2,
    "accounts_required": ["vault", "admin", "destination"],
    "cpi_calls": 0
  },
  "attacker_model": {
    "position": "none",
    "capital": "none",
    "privilege": "none"
  },
  "preconditions": [
    "Vault account exists with lamports > rent-exempt minimum",
    "Attacker can submit transactions to the program"
  ],
  "steps": [
    {"step": 1, "action": "Construct admin_withdraw instruction with attacker's pubkey as admin field", "tx_required": false},
    {"step": 2, "action": "Set destination to attacker-controlled account", "tx_required": false},
    {"step": 3, "action": "Set amount to vault.lamports - rent_exempt", "tx_required": true}
  ],
  "post_conditions": {
    "vault_balance": "0",
    "attacker_balance": "vault_initial + rent_exempt",
    "authority_unmodified": true
  },
  "impact": {
    "funds_at_risk_sol": "unbounded",
    "users_affected": "all depositors",
    "protocol_insolvency": true,
    "recovery_path": "none"
  },
  "remediation": {
    "fix_tier": "A",
    "confidence": 0.98,
    "cvss_after": 7.5,
    "files_to_modify": ["programs/vault/src/lib.rs"],
    "verification_test": "tests/poc-vuln-01-fixed.rs"
  },
  "poc_status": "verified",
  "poc_author": "solana-auditor-skill",
  "generated_at": "2026-01-15T10:30:00Z"
}
```

---

### PoC Walkthroughs

#### PoC 1: Admin Drain (`admin-drain-metadata.json`)

**Finding ID**: VULN-01
**Rule**: Rule 8 — Signer Verification
**Severity**: CRITICAL | **CVSS**: 9.8 | **CVSS Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Metadata Summary**:
| Field | Value |
|-------|-------|
| Exploit Class | `privilege-escalation` |
| Attacker Position | `none` (no privilege required) |
| Capital Required | `none` |
| CPI Calls | `0` |
| Fix Tier | `A` (mechanical signer constraint) |
| CVSS After Fix | `7.5` |

**Exploit Flow**:

```
Attacker (no privilege)
    │
    ▼
[1] Submit tx: admin_withdraw(
        admin    = attacker_wallet.pubkey(),   // ← NOT a signer
        vault    = vault_pda,
        dest     = attacker_wallet.pubkey(),
        amount   = vault.lamports - rent_exempt
    )
    │
    ▼
[2] Anchor deserializes AdminWithdraw:
    - vault: AccountInfo ← no ownership check
    - admin: AccountInfo ← no is_signer check
    - dest:  AccountInfo ← no validation
    │
    ▼
[3] Raw lamport transfer executes:
    vault.lamports -= amount
    dest.lamports  += amount
    │
    ▼
[4] Tx confirmed — vault drained
```

**Why It Works**: `AccountInfo` carries no signer semantics. Anchor's deserializer only checks that the account exists, not that it signed the transaction. The `admin` field is cosmetic — its pubkey is read but never verified.

**Preconditions**:
- Vault account exists on-chain with `lamports > rent_exempt_minimum`
- Attacker can submit transactions to the program (public instruction)

**Post-conditions**:
- `vault.lamports == rent_exempt_minimum`
- `attacker.lamports == attacker_initial + (vault_initial - rent_exempt_minimum)`
- `vault.authority` unchanged (no state modified except lamports)

**Verification**:
```rust
// Fixed: Signer<'info> enforces is_signer at deserialization
#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    #[account(mut, has_one = admin)]
    pub vault: Account<'info, VaultState>,
    pub admin: Signer<'info>,         // ← Anchor checks is_signer
    #[account(mut)]
    pub destination: SystemAccount<'info>,
}
```

> **Remediation Analysis**
>
> **Root cause**: The `admin` field in `AdminWithdraw` was declared as `AccountInfo<'info>` instead of `Signer<'info>`. Anchor's deserializer accepts any `AccountInfo` regardless of whether it signed the transaction. The raw lamport transfer then executes because no signer gate exists at any level.
>
> **Attack scenario**:
> 1. Attacker constructs a transaction invoking `admin_withdraw` with their own pubkey in the `admin` field
> 2. Transaction is signed only by the attacker's wallet (for the `payer` account), not by the vault authority
> 3. Anchor deserializes the instruction without verifying the admin field signed
> 4. Program executes `vault.lamports -= amount` and `dest.lamports += amount` unconditionally
> 5. Vault is drained; attacker receives lamports at their chosen destination
>
> **Business impact**: Total loss of vault funds. Unbounded SOL drain. All depositors lose funds. Protocol insolvency with no recovery path.
>
> **Regression test**:
> ```rust
> #[tokio::test]
> async fn test_admin_withdraw_requires_signer() {
>     let program = ProgramTest::bpf("vault", program_id).start_with_context().await;
>     let malicious_tx = Transaction::new_signed_with_payer(
>         &[instruction::admin_withdraw(
>             &program_id,
>             &context_accounts,  // admin = attacker pubkey, NOT a signer
>             vault.lamports - rent_exempt,
>         )],
>         Some(&payer.pubkey()),
>         &[&payer],  // Only payer signs — admin does NOT sign
>         recent_blockhash,
>     );
>     let result = program.rpc().process_transaction(&malicious_tx).await;
>     assert!(result.is_err());  // Must fail with NotSigner
> }
> ```
>
> **Tradeoffs**:
> - **Gas cost**: +600 CU (Signer deserialization overhead)
> - **Breaking changes**: Existing callers must sign with the admin key — non-breaking for correctly-designed integrations
> - **Complexity**: None — single type swap from `AccountInfo` to `Signer`
>
> **Compute unit impact**: ~+600 CU. Signer verification is a single sysvar check at deserialization.

---

#### PoC 2: Reinit Attack (`reinit-vuln-metadata.json`)

**Finding ID**: VULN-11 (mapped from VULN-06 in findings.json)
**Rule**: Rule 11 — Reinitialization Attacks
**Severity**: HIGH | **CVSS**: 7.5 | **CVSS Vector**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`

**Metadata Summary**:
| Field | Value |
|-------|-------|
| Exploit Class | `state-manipulation` |
| Attacker Position | `must hold vault account key` |
| Capital Required | `rent_exempt_minimum` |
| CPI Calls | `0` |
| Fix Tier | `A` (discriminator check) |
| CVSS After Fix | `4.0` |

**Exploit Flow**:

```
Attacker (holds vault account key)
    │
    ▼
[1] Call initialize() on vault account
    vault.authority = attacker_key
    vault.balance   = 0
    │
    ▼
[2] Deposit 100 tokens into protocol
    vault.balance = 100
    protocol.escrow += 100
    │
    ▼
[3] Account goes inactive (lamports refunded or closed)
    vault.lamports = 0
    │
    ▼
[4] Attacker re-funds account to rent_exempt
    vault.lamports = rent_exempt_minimum
    │
    ▼
[5] Call initialize() again
    // No discriminator check!
    vault.authority = NEW_ATTACKER_KEY  // ← overwrites
    vault.balance   = 0
    │
    ▼
[6] Call withdraw(100) — protocol sees vault.authority == attacker
    withdraw succeeds → attacker drains protocol
```

**Why It Works**: Without `#[account]` on `VaultState`, Anchor does not write or verify the 8-byte discriminator. An account with all-zero bytes is indistinguishable from a freshly-init'd account.

**Preconditions**:
- Attacker must control (own the private key for) a vault account's pubkey
- Vault account must have `lamports >= rent_exempt_minimum` (to be rent-exempt)
- Vault account's data must be zeroed or the attacker must be able to refund it

**Post-conditions**:
- `vault.authority` replaced with attacker's new key
- `vault.balance = 0` (resets accounting)
- Protocol's escrow unchanged (attacker has claim on 100 tokens)
- Attacker can call `withdraw()` as the new authority

**Verification**:
```rust
// Fixed: Anchor Account enforces discriminator
#[account]
pub struct VaultState {
    pub authority: Pubkey,
    pub balance: u64,
}

// Or manual check:
let data = vault.try_borrow_data()?;
require!(
    &data[..8] == VaultState::DISCRIMINATOR,
    ErrorCode::AlreadyInitialized
);
```

> **Remediation Analysis**
>
> **Root cause**: The `initialize` function wrote account fields without first checking the 8-byte Anchor discriminator. When an account is closed (lamports refunded to zero) and re-funded to rent-exemption minimum, it contains all-zero bytes — indistinguishable from a freshly-init'd account. Without the discriminator check, `initialize` will overwrite state on any zeroed account.
>
> **Attack scenario**:
> 1. Attacker acquires a vault account pubkey (e.g., via a predictable derivation or from on-chain data)
> 2. Attacker calls `initialize()` with their pubkey as authority — vault.authority = attacker, vault.balance = 0
> 3. Legitimate user deposits 100 tokens into the protocol, updating the escrow
> 4. Attacker triggers account closure (lamports -> 0) or waits for lamport refund
> 5. Attacker re-funds the account to rent_exempt_minimum
> 6. Attacker calls `initialize()` again — discriminator check absent, vault.authority = NEW_KEY, vault.balance = 0
> 7. Attacker calls `withdraw()` as the new authority — protocol sees attacker as owner, drain succeeds
>
> **Business impact**: Loss of escrowed user funds (100 tokens in example). Protocol insolvency for the affected vault. Requires manual intervention or governance action to recover.
>
> **Regression test**:
> ```rust
> #[tokio::test]
> async fn test_initialize_rejects_reinit() {
>     let program = ProgramTest::bpf("vault", program_id).start_with_context().await;
>     // First initialization
>     program.rpc().process_transaction(&init_tx).await.unwrap();
>     // Close the account (lamports = 0)
>     program.rpc().process_transaction(&close_tx).await.unwrap();
>     // Refund to rent-exempt
>     program.rpc().process_transaction(&refund_tx).await.unwrap();
>     // Attempt reinit — should FAIL
>     let result = program.rpc().process_transaction(&init_tx).await;
>     assert!(result.is_err());  // Must fail with AlreadyInitialized
> }
> ```
>
> **Tradeoffs**:
> - **Gas cost**: +400 CU (8-byte discriminator read and comparison)
> - **Breaking changes**: None — discriminator check is additive
> - **Complexity**: Low — single `require!` on discriminator bytes
>
> **Compute unit impact**: ~+400 CU. Discriminator check reads 8 bytes from account data and compares against constant.

---

#### PoC 3: Flash Loan Attack (`flash-loan-metadata.json`)

**Finding ID**: VULN-13
**Rule**: Rule 13 — Flash Loan Attack Surface
**Severity**: CRITICAL | **CVSS**: 9.0 | **CVSS Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Metadata Summary**:
| Field | Value |
|-------|-------|
| Exploit Class | `oracle-manipulation` |
| Attacker Position | `borrowed capital` |
| Capital Required | `flash_loan_fee` (repaid in same tx) |
| CPI Calls | `3+` (borrow, price_write, repay) |
| Fix Tier | `B` (oracle redesign) |
| CVSS After Fix | `5.5` |

**Exploit Flow**:

```
Slot N
    │
    ▼
[1] Attacker invokes flash_loan(amount=10_000_000 USDC)
    → Protocol lends 10M USDC to attacker (same-tx repayment required)
    │
    ▼
[2] Attacker invokes swap(USDC → MNGO, 10M USDC)
    → MNGO price spikes 1000% within this transaction
    │
    ▼
[3] Attacker invokes borrow(MNGO, collateral_value=10M USDC)
    → Oracle reads manipulated MNGO price from step [2]
    → Collateral ratio satisfied → borrow succeeds
    │
    ▼
[4] Attacker swaps borrowed MNGO → USDC at inflated price
    → Realizes 10M USDC profit
    │
    ▼
[5] Attacker repays flash loan + fees in same transaction
    → All state changes atomic: price spike + borrow happen together
    │
    ▼
[6] Post-tx: Protocol holds 10M USDC liability, MNGO collateral worth 1% of notional
```

**Why It Works**: Solana transactions are atomic — all instructions succeed or all fail. The price oracle is read at step [3] but written at step [2]. Because both happen in the same transaction, there is no external confirmation of the "real" price. The oracle is stale-within-a-block.

**Preconditions**:
- Protocol reads from a price oracle without slot-age or timestamp validation
- Flash loan available (Raydium, Solend, or similar)
- Liquidity exists to execute the swap at manipulated price

**Post-conditions**:
- Protocol: net -10M USDC (liability), collateral worth ~100K USDC
- Attacker: net +9.9M USDC (profit minus flash loan fees)
- Price oracle: corrupted for all other users until next update

**Verification**:
```rust
// Fixed: Staleness check + confidence threshold
const MAX_SLOT_AGE: u64 = 2;
const MAX_CONFIDENCE_BPS: u64 = 100;  // 1%

let clock = Clock::get()?;
let slot_age = clock.slot.saturating_sub(price_feed.last_update_slot);
require!(slot_age <= MAX_SLOT_AGE, PriceError::StalePrice);
require!(
    price_feed.confidence_bps <= MAX_CONFIDENCE_BPS,
    PriceError::HighConfidence
);
```

> **Remediation Analysis**
>
> **Root cause**: The price oracle is read and written within the same atomic transaction. Because Solana transactions are all-or-nothing, the manipulated price from step [2] (the attacker-controlled swap) is the live price at step [3] (the borrow). There is no external confirmation or slot-age gate that would invalidate the attacker-written price before it is consumed.
>
> **Attack scenario**:
> 1. Attacker identifies a protocol that reads a manipulable price feed (e.g., AMM spot price) without slot-age validation
> 2. Attacker takes a flash loan of 10M USDC (repayable within same transaction)
> 3. Attacker executes a swap that moves the price of the collateral token by 1000% within the transaction
> 4. Attacker immediately borrows against the inflated collateral value using the now-corrupted price feed
> 5. Attacker swaps the borrowed tokens back to USDC at the inflated price, realizing profit
> 6. Attacker repays flash loan + fees atomically — all state changes succeed or fail together
> 7. Post-tx: protocol holds MNGO collateral worth 1% of notional against a 10M USDC liability
>
> **Business impact**: Protocol insolvency of ~9.9M USDC (net loss). Secondary: price oracle corruption affects all protocol users until the next independent price update. Recovery requires governance intervention or insurance fund.
>
> **Regression test**:
> ```rust
> #[tokio::test]
> async fn test_flash_loan_reverts_price_manipulation() {
>     let program = ProgramTest::bpf("vault", program_id).start_with_context().await;
>     let clock = Clock::get().unwrap();
>     // Simulate same-slot price manipulation attempt
>     let price_before = get_price_feed(&program, "MNGO/USDC");
>     // Flash loan + swap + borrow within same slot
>     let exploit_tx = Transaction::new_signed_with_payer(
>         &[flash_loan_ix(), swap_ix(), borrow_ix()],
>         Some(&attacker.pubkey()),
>         &[&attacker],
>         recent_blockhash,
>     );
>     let result = program.rpc().process_transaction(&exploit_tx).await;
>     assert!(result.is_err());  // Must fail: slot_age = 0, exceeds MAX_SLOT_AGE
>     let price_after = get_price_feed(&program, "MNGO/USDC");
>     assert_eq!(price_before, price_after);  // Price unchanged
> }
> ```
>
> **Tradeoffs**:
> - **Gas cost**: +800 CU (Clock sysvar read + slot comparison + confidence check)
> - **Breaking changes**: Protocols relying on stale prices (>= 2 slots old) will see borrows revert — may affect legitimate use cases
> - **Complexity**: Medium — requires understanding of slot timing, Clock sysvar, and confidence intervals
>
> **Compute unit impact**: ~+800 CU. Clock sysvar deserialization (~200 CU) + arithmetic comparisons (~600 CU).

---

### Schema Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `poc_id` | string | Yes | Finding ID (e.g., `VULN-01`) |
| `title` | string | Yes | Human-readable title |
| `severity` | enum | Yes | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `cvss` | float | Yes | CVSS score 0.0–10.0 |
| `cvss_vector` | string | No | Full CVSS 3.1 vector string |
| `cwe` | string[] | No | CWE identifiers |
| `rule_ids` | string[] | Yes | Rule numbers caught (e.g., `["Rule 8"]`) |
| `exploit_class` | enum | Yes | `privilege-escalation`, `state-manipulation`, `oracle-manipulation`, `reentrancy`, `arith`, `config` |
| `attack_surface` | object | Yes | Technical attack surface details |
| `attacker_model` | object | Yes | Attacker capability requirements |
| `preconditions` | string[] | Yes | Conditions that must hold before exploit |
| `steps` | object[] | Yes | Ordered exploit steps |
| `post_conditions` | object | Yes | Expected state after exploit |
| `impact` | object | Yes | Impact quantification |
| `remediation` | object | Yes | Fix metadata |
| `poc_status` | enum | Yes | `pending`, `verified`, `failed`, `not-applicable` |
| `generated_at` | ISO8601 | Yes | Timestamp |

---



## Auto-Fix Tier Classification

Every vulnerability finding is classified into a fix tier that determines the remediation approach:

| Tier | Criteria | Auto-Apply | Example Fixes |
|------|----------|------------|---------------|
| **A** | Single file, mechanical change, no logic modification | Yes (with consent) | `is_signer` check, `checked_add`, `require!` guard |
| **B** | Multi-file, moderate complexity, may affect logic | No (manual review) | Reentrancy guard addition, discriminator rename |
| **C** | Architectural change, requires design review | Never | Oracle redesign, CPI chain restructure |

### Tier A Indicators (Auto-Applicable)
- Adding exactly one validation check
- Swapping `+` for `checked_add`
- Adding `require!` macro guard
- Changing `unwrap()` to `?`
- Adding `is_signer` verification
- Using canonical bump from `ctx.bumps`

### Tier B Indicators (Manual Review Required)
- Adding new state fields
- Modifying instruction signatures
- Changing account types (Account vs AccountLoader)
- Adding reentrancy locks
- Discriminator changes (requires migration)

### Tier C Indicators (Architectural)
- Oracle source changes
- CPI chain restructuring
- Token program version changes
- Multi-account transaction redesign

---

## Fix Suggestion Format

Every finding should include a structured fix suggestion:

```json
{
  "finding_id": "CRIT-01",
  "rule": 8,
  "title": "Missing signer check on admin withdrawal",
  "tier": "A",
  "confidence": 0.95,
  "fix_risk": "LOW",
  "files_to_modify": ["programs/vault/src/lib.rs"],
  "before_code": "pub fn admin_withdraw(ctx: Context<Admin>) -> Result<()> { ... }",
  "after_code": "pub fn admin_withdraw(ctx: Context<Admin>) -> Result<()> {\n    if !ctx.accounts.admin.is_signer {\n        return Err(ErrorCode::NotSigner.into());\n    }\n    ...\n}",
  "test_to_verify": "tests/admin_withdraw_test.ts",
  "cvss_before": 9.1,
  "cvss_after": 7.5,
  "cvss_reduction": 1.6
}
```

### Confidence Score Definition

| Score | Meaning | Criteria |
|-------|---------|----------|
| 0.9-1.0 | Near-certain | Exact pattern match, well-tested approach |
| 0.7-0.9 | High confidence | Similar patterns proven, minor variations |
| 0.5-0.7 | Moderate | Requires context verification |
| 0.3-0.5 | Experimental | Novel approach, needs review |

### Fix Risk Levels

| Level | Definition | Mitigation |
|-------|------------|------------|
| **LOW** | No breaking changes | Standard test coverage sufficient |
| **MEDIUM** | May affect error paths | Add edge case tests |
| **HIGH** | Could break valid usage | Manual review + integration tests |

---

## Rule-by-Rule Fix Templates

### Rule 1: Privileged Instruction Surface
**Tier: B** | **Confidence: 0.85**

```rust
// BEFORE: No privileged action surface audit
pub fn risky_action(ctx: Context<Risky>) -> Result<()> { ... }

// AFTER: Add privileged action surface documentation
/// # Privileged Actions
/// - `admin_upgrade`: Requires upgrade authority signer
/// - `emergency_pause`: Requires pause authority signer
/// - `fee_change`: Requires governance approval
pub fn risky_action(ctx: Context<Risky>) -> Result<()> { ... }
```

> **Remediation Analysis**
>
> **Root cause**: No privileged action surface audit was performed before modifying the instruction. Critical invariants (signer verification, amount limits, state transition validity) were assumed rather than verified. The developer edited code that touches authority-controlled state without mapping which instructions hold that authority and what preconditions must hold.
>
> **Attack scenario**:
> 1. Developer modifies `risky_action` to implement a new feature
> 2. Developer assumes the function is called only after proper authorization checks
> 3. In fact, `risky_action` is callable by any user who can craft the instruction data
> 4. Attacker calls `risky_action` with crafted parameters that drain or corrupt privileged state
> 5. Authorization checks that should have been added were never present in the original design
>
> **Business impact**: Exploitation of undocumented privileged operations. May range from fund drain (CRITICAL) to unauthorized state modification (HIGH). Disclosure risk: audit findings often reveal multiple undocumented privileged paths not caught by static analysis alone.
>
> **Regression test**:
> ```rust
> #[tokio::test]
> async fn test_risky_action_privileged_surface() {
>     // Verify all privileged paths are documented and guarded
>     let privileged_actions = [
>         ("admin_upgrade", UpgradeAuthority::signer_required),
>         ("emergency_pause", PauseAuthority::signer_required),
>         ("fee_change", GovernanceAuthority::signer_required),
>     ];
>     for (name, guard) in privileged_actions {
>         // Attempt without correct signer
>         let unsigned_tx = build_instruction(program_id, name, &[]);
>         let result = process_tx_without_signer(&unsigned_tx).await;
>         assert!(result.is_err(), "{} must require authority signer", name);
>         // Attempt with correct signer
>         let signed_tx = build_instruction(program_id, name, &[&authority]);
>         let result = process_tx_with_signer(&signed_tx, &[&authority]).await;
>         assert!(result.is_ok(), "{} must succeed with authority signer", name);
>     }
> }
> ```
>
> **Tradeoffs**:
> - **Gas cost**: Minimal (+50-100 CU for docstring parsing by tooling)
> - **Breaking changes**: None — documentation-only fix
> - **Complexity**: Low (documentation) to High (actual privilege audit may reveal missing guards requiring architectural changes)
>
> **Compute unit impact**: ~+50-100 CU. No runtime change; tooling adds this at analysis time.

---

### Rule 2: Missing Discriminator/Owner/Init
**Tier: A** | **Confidence: 0.95**

```rust
// BEFORE: Missing init constraints
#[derive(Accounts)]
pub struct InitUser<'info> {
    pub user: Account<'info, User>,
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

// AFTER: Full init constraints
#[derive(Accounts)]
pub struct InitUser<'info> {
    #[account(
        init,
        space = 8 + User::LEN,
        payer = payer,
        seeds = [b"user", payer.key().as_ref()],
        bump
    )]
    pub user: Account<'info, User>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

---

### Rule 3: Hardcoded/Non-Canonical PDA Bump
**Tier: A** | **Confidence: 0.95**

```rust
// BEFORE: Hardcoded bump
let seeds = &[b"vault", user.as_ref(), &[255]];
let vault_pda = Pubkey::create_program_address(seeds, program_id)?;

// AFTER: Canonical bump from Anchor
let vault_bump = *ctx.bumps.get("vault").unwrap();
let seeds = &[b"vault", user.as_ref(), &[vault_bump]];
let (vault_pda, _) = Pubkey::find_program_address(seeds, program_id);
```

---

### Rule 4: CPI Escalation / Unverified Program ID
**Tier: A** | **Confidence: 0.90**

```rust
// BEFORE: No program ID verification
invoke(
    &instruction,
    &[
        AccountMeta::new(program_id, false),  // attacker-controlled
        ...
    ],
)?;

// AFTER: Whitelist verification
let expected_program = SWAP_PROGRAM_ID;
require!(
    program_id == expected_program,
    ErrorCode::InvalidProgram
);
invoke(&instruction, &accounts)?;
```

---

### Rule 5: SPL vs Token-2022 Mismatch
**Tier: B** | **Confidence: 0.85**

```rust
// BEFORE: Assumes SPL Token
use anchor_spl::token::{Transfer, Token};

// AFTER: Token program detection
#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(
        token_program = token_program.key()
    )]
    pub token_program: AccountInfo<'info>,
}

pub fn transfer_tokens(ctx: Context<TransferTokens>, amount: u64) -> Result<()> {
    let token_program_key = ctx.accounts.token_program.key();
    if token_program_key == anchor_spl::token::ID {
        // Handle SPL Token
        anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)?;
    } else if token_program_key == anchor_spl::token_2022::ID {
        // Handle Token-2022
        anchor_spl::token_2022::transfer(ctx.accounts.transfer_ctx(), amount)?;
    } else {
        return Err(ErrorCode::InvalidTokenProgram.into());
    }
    Ok(())
}
```

---

### Rule 6: Integer Overflow on u64 Amounts
**Tier: A** | **Confidence: 0.98**

```rust
// BEFORE: Unsafe arithmetic
let new_amount = old_amount + deposit;
let new_supply = total_supply + mint_amount;

// AFTER: Checked arithmetic
let new_amount = old_amount.checked_add(deposit)
    .ok_or(ErrorCode::Overflow)?;
let new_supply = total_supply.checked_add(mint_amount)
    .ok_or(ErrorCode::Overflow)?;
```

---

### Rule 7: Lamport Drain via Wrong Close Target
**Tier: A** | **Confidence: 0.95**

```rust
// BEFORE: User-controlled close target
#[derive(Accounts)]
pub struct CloseVault<'info> {
    #[account(close = user)]  // WRONG: attacker controls target
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
}

// AFTER: Admin-controlled close target
#[derive(Accounts)]
pub struct CloseVault<'info> {
    #[account(close = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
```

---

### Rule 8: Unsigned Privileged Action
**Tier: A** | **Confidence: 0.98**

```rust
// BEFORE: No signer verification
pub fn admin_withdraw(ctx: Context<Admin>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.withdraw(ctx.accounts.recipient.key(), amount)?;
    Ok(())
}

// AFTER: Explicit signer check
pub fn admin_withdraw(ctx: Context<Admin>) -> Result<()> {
    if !ctx.accounts.admin.is_signer {
        return Err(ErrorCode::NotSigner.into());
    }
    let vault = &mut ctx.accounts.vault;
    vault.withdraw(ctx.accounts.admin.key(), amount)?;
    Ok(())
}

// ANCHOR WAY (preferred):
#[derive(Accounts)]
pub struct Admin<'info> {
    pub admin: Signer<'info>,  // Anchor enforces at deserialization
    pub vault: Account<'info, Vault>,
    pub system_program: Program<'info, System>,
}
```

---

### Rule 9: Upgrade Authority Surface
**Tier: B** | **Confidence: 0.80**

```markdown
# Recommended Actions for Upgrade Authority

## Option 1: Transfer to Multisig (Recommended)
```bash
# Using Squads multisig
solana program upgrade ./target/deploy/program.so <PROGRAM_ID> --multisig <MULTISIG_PUBKEY>
```

## Option 2: Transfer to Timelock PDA
```rust
// Set upgrade authority to a timelock contract
pub struct TimelockController {
    pub authority: Pubkey,
    pub delay: i64,  // seconds
    pub pending_authority: Option<Pubkey>,
}
```

## Option 3: Remove Upgrade Authority (Irreversible)
```bash
solana program set-upgrade-authority <PROGRAM_ID> --final
```
```

---

### Rule 10: panic! / Missing Error Mapping
**Tier: A** | **Confidence: 0.95**

```rust
// BEFORE: panic! usage
fn process_user_data(data: &[u8]) {
    let parsed = parse_data(data).unwrap(); // panics on invalid
}

// AFTER: Proper error handling
fn process_user_data(data: &[u8]) -> Result<UserData> {
    let parsed = parse_data(data)
        .ok_or(ErrorCode::InvalidDataFormat)?;
    Ok(parsed)
}
```

> **Remediation Analysis**
>
> **Root cause**: The code used `unwrap()` on `parse_data(data)` which returns `Option<UserData>`. When parsing fails (malformed data), `unwrap()` panics and aborts the entire transaction. On Solana, a panicking program consumes its compute budget without returning a useful error code, making debugging and error recovery impossible for off-chain systems.
>
> **Attack scenario**:
> 1. Attacker observes that `process_user_data` is called with attacker-controlled input
> 2. Attacker crafts a transaction with malformed instruction data
> 3. Program panics — transaction fails with no error message, lamports consumed
> 4. If `process_user_data` is on a critical path (e.g., inside a callback or during settlement), repeated DoS is possible
> 5. Unlike an error return, a panic cannot be distinguished from other failure modes (insufficient funds, invalid accounts) by indexers or monitoring systems
>
> **Business impact**: Denial of service to individual users who submit malformed data. Loss of lamports (failed tx fees) for affected users. In visibility terms: panics are indistinguishable from other failure modes in on-chain data, degrading monitoring and incident response. No fund loss unless panic occurs on a critical path (e.g., inside a reentrancy window).
>
> **Regression test**:
> ```rust
> #[test]
> fn test_parse_data_rejects_malformed_input() {
>     let malformed = &[0xFF, 0xFE, 0xFD, 0xFC];
>     let result = parse_data(malformed);
>     assert!(result.is_none(), "parse_data must return None for malformed input");
>     // Verify Result propagation works
>     fn wrapper(data: &[u8]) -> Result<UserData, ErrorCode> {
>         parse_data(data).ok_or(ErrorCode::InvalidDataFormat)
>     }
>     assert!(wrapper(malformed).is_err());
>     assert_eq!(wrapper(malformed).unwrap_err(), ErrorCode::InvalidDataFormat);
> }
> #[test]
> fn test_parse_data_accepts_valid_input() {
>     let valid = encode_valid_user_data();
>     let result = parse_data(&valid);
>     assert!(result.is_some(), "parse_data must succeed for valid input");
> }
> ```
>
> **Tradeoffs**:
> - **Gas cost**: Negligible (+0-50 CU — Option handling is branch-free on the happy path)
> - **Breaking changes**: None — error returns are strictly more permissive than panics
> - **Complexity**: None — single `ok_or()` call replaces `unwrap()`
>
> **Compute unit impact**: ~+0-50 CU. `ok_or()` is a no-op on `Some`, adds one branch on `None`.

---

### Rule 11: Reinit Without Discriminator
**Tier: A** | **Confidence: 0.95**

```rust
// BEFORE: Manual init without discriminator check
pub fn init_vault(ctx: Context<InitVault>) -> Result<()> {
    ctx.accounts.vault.authority = ctx.accounts.admin.key();
    Ok(())
}

// AFTER: Discriminator check before init
pub fn init_vault(ctx: Context<InitVault>) -> Result<()> {
    let vault = &ctx.accounts.vault;
    require!(
        vault.discriminator == [0u8; 8],
        ErrorCode::AlreadyInitialized
    );
    ctx.accounts.vault.authority = ctx.accounts.admin.key();
    Ok(())
}
```

---

### Rule 12: Rent Exemption Breaking
**Tier: A** | **Confidence: 0.90**

```rust
// BEFORE: Manual lamport transfer without rent check
pub fn fund_account(ctx: Context<Fund>) -> Result<()> {
    **ctx.accounts.target.try_borrow_mut_lamports()? += 1000;
    **ctx.accounts.source.try_borrow_mut_lamports()? -= 1000;
    Ok(())
}

// AFTER: Verify rent exemption after transfer
use solana_program::rent::Rent;
pub fn fund_account(ctx: Context<Fund>, amount: u64) -> Result<()> {
    let rent = Rent::get()?;
    **ctx.accounts.target.try_borrow_mut_lamports()? += amount;
    **ctx.accounts.source.try_borrow_mut_lamports()? -= amount;
    // Verify target is still rent-exempt
    require!(
        ctx.accounts.target.lamports() >= rent.minimum_balance(
            ctx.accounts.target.data_len()
        ),
        ErrorCode::RentExemptionBroken
    );
    Ok(())
}
```

---

### Rule 13: Flash Loan Oracle Manipulation
**Tier: B** | **Confidence: 0.75**

```rust
// BEFORE: No oracle staleness check
pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
    let price = ctx.accounts.price_feed.get_price()?;
    let collateral_value = (price as u128)
        .checked_mul(amount as u128)
        .ok_or(ErrorCode::Overflow)?;
    // ...
}

// AFTER: Staleness verification + confidence threshold
pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
    let price_data = ctx.accounts.price_feed.get_price()?;
    let clock = Clock::get()?;

    // Check staleness (max 60 seconds)
    let max_age: i64 = 60;
    require!(
        clock.unix_timestamp - price_data.timestamp <= max_age,
        ErrorCode::StalePrice
    );

    // Confidence threshold
    const MAX_CONFIDENCE: u64 = 1_000_000;
    require!(
        price_data.confidence <= MAX_CONFIDENCE,
        ErrorCode::HighPriceConfidence
    );

    let collateral_value = (price_data.price as u128)
        .checked_mul(amount as u128)
        .ok_or(ErrorCode::Overflow)?;
    // ...
}
```

---

### Rule 14: Reentrancy (CEI Violation)
**Tier: B** | **Confidence: 0.90**

```rust
// BEFORE: External call before state update
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    require!(ctx.accounts.user.balance >= amount, ErrorCode::InsufficientFunds);
    anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)?;
    ctx.accounts.user.balance -= amount;  // After external call!
    Ok(())
}

// AFTER: CEI pattern with reentrancy guard
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let user = &mut ctx.accounts.user;
    let vault = &mut ctx.accounts.vault;

    // CHECK: Verify balance + guard
    require!(user.balance >= amount, ErrorCode::InsufficientFunds);
    require!(!vault.withdraw_in_progress, ErrorCode::ReentrancyDetected);

    // EFFECT: Update state BEFORE external call
    user.balance = user.balance.checked_sub(amount).ok_or(ErrorCode::Overflow)?;
    vault.withdraw_in_progress = true;

    // INTERACTION: External call last
    anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)?;

    // Reset guard
    vault.withdraw_in_progress = false;

    Ok(())
}
```

---

### Rule 15: Missing remaining_accounts Validation
**Tier: A** | **Confidence: 0.95**

```rust
// BEFORE: No validation
let remaining = ctx.remaining_accounts();
let extra_account = &remaining[0];  // Unvalidated!

// AFTER: Full validation
let remaining = ctx.remaining_accounts();
require!(remaining.len() >= 1, ErrorCode::InsufficientAccounts);
let extra_account = &remaining[0];
require!(extra_account.is_writable, ErrorCode::AccountNotWritable);
require!(
    extra_account.owner == &token_program::ID,
    ErrorCode::InvalidOwner
);
```

---

### Rule 16: Discriminator Collision
**Tier: B** | **Confidence: 0.85**

```rust
// BEFORE: Collision-prone names
#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct VaultData { ... }  // "VaultData"
#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct Vault { ... }       // "Vault" - different!

// AFTER: Explicit unique discriminators
#[derive(AnchorSerialize, AnchorDeserialize)]
#[repr(transparent)]
pub struct VaultData {
    pub discriminator: [u8; 8],
    // ...
}

impl VaultData {
    pub const DISCRIMINATOR: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
}

#[derive(AnchorSerialize, AnchorDeserialize)]
#[repr(transparent)]
pub struct AdminVaultData {
    pub discriminator: [u8; 8],
    // ...
}

impl AdminVaultData {
    pub const DISCRIMINATOR: [u8; 8] = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
}
```

---

### Rule 17: AccountLoader Without Owner Check
**Tier: A** | **Confidence: 0.95**

```rust
// BEFORE: No owner check
let account = AccountLoader::<MyData>::try_from(&ctx.accounts.data)?;
account.load()?;

// AFTER: Owner verification
let account = AccountLoader::<MyData>::try_from(&ctx.accounts.data)?;
require!(
    ctx.accounts.data.owner == program_id,
    ErrorCode::InvalidAccountOwner
);
account.load()?;
```

---

### Rule 18: BorshDeserialize Panic
**Tier: A** | **Confidence: 0.98**

```rust
// BEFORE: unwrap on untrusted data
let data = account.data.borrow().try_from_slice::<T>(&[])?;
data.unwrap();  // PANIC on invalid

// AFTER: Proper result propagation
let data = account.data.borrow().try_from_slice::<T>(&[])?;
// Or use Anchor's safe Account<T>:
let safe_account = Account::<MyType>::try_from(&account_info)?;
```

---

### Rule 19: Anchor verify/address Constraint Bypass
**Tier: A** | **Confidence: 0.90**

```rust
// BEFORE: Only address constraint
#[derive(Accounts)]
pub struct VerifyToken<'info> {
    #[account(address = expected_token)]
    pub token: Account<'info, TokenAccount>,
}

// AFTER: Add redundant owner check
#[derive(Accounts)]
pub struct VerifyToken<'info> {
    #[account(
        address = expected_token,
        owner = token_program::ID
    )]
    pub token: Account<'info, TokenAccount>,
    pub token_program: Account<'info, Token>,
}

// Add verify predicate for complex checks
#[derive(Accounts)]
pub struct VerifyComplex<'info> {
    #[account(verify = is_valid_depositor)]
    pub depositor: Account<'info, DepositorData>,
}

fn is_valid_depositor(depositor: &DepositorData) -> Result<(), ProgramError> {
    require!(depositor.status == Status::Active, MyError::NotActive);
    require!(depositor.kyc_level >= KYCLevel::Verified, MyError::KycRequired);
    Ok(())
}
```

---

### Rule 20: Token-2022 Extension Ordering
**Tier: B** | **Confidence: 0.80**

```rust
// BEFORE: Wrong order (memo after transfer_fee)
initialize_transfer_fee_config(&ctx, &config)?;
initialize_memo_extension(&ctx)?;

// AFTER: Correct order (memo before transfer_fee)
initialize_memo_extension(&ctx)?;
initialize_transfer_fee_config(&ctx, &config)?;
```

---

### Rule 21: CPI Callback Reentrancy
**Tier: B** | **Confidence: 0.85**

```rust
// BEFORE: Single guard can be bypassed
let vault = &mut ctx.accounts.vault;
require!(!vault.in_use, ErrorCode::Reentrancy);
vault.in_use = true;
anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)?;
vault.in_use = false;  // Callback could use different PDA!

// AFTER: CEI + depth tracking
let vault = &mut ctx.accounts.vault;
let vault_pda = ctx.accounts.vault.key();
require!(!vault.in_use, ErrorCode::Reentrancy);
vault.in_use = true;

vault.amount = vault.amount.checked_sub(amount).ok_or(ErrorCode::Underflow)?;

anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)?;

vault.amount = vault.amount.checked_add(amount).ok_or(ErrorCode::Overflow)?;
vault.in_use = false;
```

---

### Rule 22: init_if_needed + close Race
**Tier: B** | **Confidence: 0.85**

```rust
// BEFORE: Separate instructions create race
// init instruction
#[derive(Accounts)]
pub struct InitUser<'info> {
    #[account(init_if_needed, ...)]
    pub user: Account<'info, User>,
}
// close instruction
#[derive(Accounts)]
pub struct CloseUser<'info> {
    #[account(close = authority)]
    pub user: Account<'info, User>,
}

// AFTER: Single atomic transition instruction
#[derive(Accounts)]
pub struct TransitionUser<'info> {
    #[account(mut, seeds = [...], bump)]
    pub user: Account<'info, User>,
    pub authority: Signer<'info>,
}

pub fn transition_user(ctx: Context<TransitionUser>, new_status: u8) -> Result<()> {
    let user = &mut ctx.accounts.user;
    require!(
        ctx.accounts.authority.key() == user.admin
            || ctx.accounts.authority.key() == user.owner,
        ErrorCode::Unauthorized
    );

    match new_status {
        STATUS_ACTIVE => {
            require!(user.is_closed, ErrorCode::InvalidTransition);
            user.is_closed = false;
        },
        STATUS_CLOSED => {
            // Atomic close: transfer lamports + set closed flag
            let dest_lamports = user.lamports();
            **user.lamports.try_borrow_mut_lamports()? = 0;
            **ctx.accounts.authority.lamports.try_borrow_mut_lamports()? += dest_lamports;
            user.is_closed = true;
        },
        _ => return Err(ErrorCode::InvalidStatus.into()),
    }
    Ok(())
}
```

---

### Rule 23: Memo Program CPI Injection
**Tier: A** | **Confidence: 0.95**

```rust
// BEFORE: User-controlled memo
let memo = format!("Deposit from {}", user.key());
invoke(
    &spl_memo::instruction::build(memo.as_bytes()),
    &[],
)?;

// AFTER: Program-controlled memo only
const DEPOSIT_MEMO: &[u8] = b"DepositConfirmed";
invoke(
    &spl_memo::instruction::build(DEPOSIT_MEMO),
    &[],
)?;

// OR: Sanitize and format program-controlled
let short_key = &user.key().to_string()[..8];
let memo = format!("DEP:{}", short_key);
let memo_bytes = memo.as_bytes();
require!(memo_bytes.len() <= 32, ErrorCode::MemoTooLong);
invoke(
    &spl_memo::instruction::build(memo_bytes),
    &[],
)?;
```

---

### Rule 24: remaining_accounts Count Mismatch
**Tier: A** | **Confidence: 0.95**

```rust
// BEFORE: Direct indexing
let remaining = ctx.remaining_accounts();
let inner_accounts = vec![
    AccountMeta::new(remaining[0].key(), remaining[0].is_signer),
    AccountMeta::new(remaining[1].key(), remaining[1].is_signer),
    AccountMeta::new(remaining[2].key(), remaining[2].is_signer),  // Missing from outer!
];

// AFTER: Validate count and properties first
let remaining = ctx.remaining_accounts();
let expected_count = 3;
require!(
    remaining.len() >= expected_count,
    ErrorCode::InsufficientAccounts
);

// Validate each account
for (i, account) in remaining.iter().enumerate() {
    if i < 2 {
        require!(account.is_signer, ErrorCode::ExpectedSigner);
    }
    require!(
        account.owner == &token_program::ID,
        ErrorError::InvalidOwner
    );
}

let inner_accounts: Vec<AccountMeta> = remaining[..expected_count]
    .iter()
    .map(|acc| AccountMeta::new(acc.key(), acc.is_signer))
    .collect();
```

---

### Rule 25: Versioned Transaction LUT Manipulation
**Tier: B** | **Confidence: 0.80**

```rust
// BEFORE: Trusts LUT address
pub fn withdraw_vlut(ctx: Context<WithdrawVlut>, amount: u64) -> Result<()> {
    let user = &ctx.accounts.user;  // From LUT
    require!(user.amount >= amount, ErrorCode::InsufficientFunds);
    // ...
}

// AFTER: Full account validation
pub fn withdraw_vlut(ctx: Context<WithdrawVlut>, amount: u64) -> Result<()> {
    let user_info = &ctx.accounts.user;

    // Validate owner (LUT cannot bypass)
    require!(user_info.owner == program_id, ErrorCode::InvalidOwner);

    // Validate discriminator
    let data = user_info.try_borrow_data()?;
    require!(
        &data[..8] == UserAccount::DISCRIMINATOR,
        ErrorCode::InvalidAccount
    );

    // Deserialize and validate state
    let user = UserAccount::try_from_slice(&data[8..])?;
    require!(user.amount >= amount, ErrorCode::InsufficientFunds);
    require!(user.active, ErrorCode::AccountNotActive);

    Ok(())
}
```

---

### Rule 26: Cross-Program Flash Loan Composition
**Tier: C** | **Confidence: 0.60**

```rust
// BEFORE: Trust oracle price without commit-reveal
pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
    let price = ctx.accounts.price_feed.get_price()?;
    // Price can be manipulated in same transaction via flash loan
    let borrow_value = calculate_borrow(price, amount)?;
    // ...
}

// AFTER: Commit-reveal or external price source
pub fn borrow_with_proof(
    ctx: Context<Borrow>,
    amount: u64,
    price_commitment: PriceCommitment,
    proof: Vec<u8>,
) -> Result<()> {
    // Verify commitment is from prior slot (not manipulable)
    let price_feed = &ctx.accounts.price_feed;
    let clock = Clock::get()?;

    // Commitment must be at least 2 slots old
    const MIN_SLOT_AGE: u64 = 2;
    require!(
        clock.slot - price_commitment.slot >= MIN_SLOT_AGE,
        ErrorCode::PriceTooRecent
    );

    // Verify merkle proof
    verify_price_commitment(
        &price_commitment,
        &ctx.accounts.merkle_root.key(),
        &proof,
    )?;

    let borrow_value = calculate_borrow(price_commitment.price, amount)?;
    require!(
        ctx.accounts.user.credit_limit >= borrow_value,
        ErrorCode::ExceededBorrowLimit
    );

    Ok(())
}
```

---

## Verification Protocol

```
1. PRE-FIX STATE
   - Record finding status, CVSS, affected files
   - Generate fix suggestion with audit-fix-suggestions.py
   - Determine tier classification

2. CONSENT GATE
   - Display fix preview to operator
   - Require explicit approval: "Type YES to apply"
   - For Tier A: auto-apply after consent
   - For Tier B/C: provide manual guidance

3. APPLY FIX
   - Tier A: scripts/audit-fix-suggestions.py --apply <finding-id>
   - Tier B: Provide code snippet for manual application
   - Tier C: Provide architectural guidance document

4. BUILD CHECK
   - anchor build 2>&1 | tail -20
   - Must succeed with no warnings

5. TEST RUN
   - scripts/fix-verification.sh <finding-id>
   - Runs finding-specific test
   - Verifies exploit now fails

6. REGRESSION CHECK
   - anchor test
   - All existing tests must pass

7. POST-FIX STATE
   - Update findings.json status: "Fixed"
   - Recalculate CVSS with cvss-before-after flag
   - Document verification in audit output
```

---

## CVSS Reduction Tracking Table

| Finding | Rule | CVSS Before | CVSS After | Reduction | Fix Tier |
|---------|------|-------------|------------|-----------|----------|
| CRIT-01 | 8 | 9.1 | 7.5 | 1.6 | A |
| CRIT-02 | 7 | 9.8 | 8.1 | 1.7 | A |
| HIGH-01 | 6 | 7.5 | 5.9 | 1.6 | A |
| HIGH-02 | 14 | 8.9 | 6.2 | 2.7 | B |
| MED-01 | 3 | 5.3 | 4.2 | 1.1 | A |
| LOW-01 | 10 | 2.8 | 1.8 | 1.0 | A |

### CVSS Recalculation Guidelines

When a fix addresses a vulnerability:
1. Re-evaluate each CVSS metric after the fix
2. Focus on metrics that change:
   - **Privileges Required (PR)**: Fixing signer check may increase PR
   - **Attack Vector (AV)**: Fixing remote exploit may change to Adjacent
   - **User Interaction (UI)**: Fixing may require additional UI
3. Always verify with `tests/severity_counts.py`

---

## Integration with audit-fix-suggestions.py

The fix suggestion engine (`scripts/audit-fix-suggestions.py`) provides:

```bash
# Get fix for specific finding
python scripts/audit-fix-suggestions.py --finding CRIT-01

# Generate fix for all HIGH/CRITICAL findings
python scripts/audit-fix-suggestions.py --severity HIGH --severity CRITICAL

# Apply Tier A fixes (with consent)
python scripts/audit-fix-suggestions.py --apply --finding CRIT-01

# Show CVSS impact
python scripts/audit-fix-suggestions.py --cvss-before-after --finding CRIT-01

# Generate remediation report
python scripts/audit-fix-suggestions.py --report
```

---

## Regression Testing

```bash
# After any fix, run in order:

# 1. Build verification
anchor build

# 2. Finding-specific test
anchor test --grep "admin_withdraw"

# 3. Formal verification (if available)
qed-solana verify --program target/deploy/PROGRAM.so --invariants tests/invariants/

# 4. Full test suite
anchor test

# 5. Integrity checks
bash tests/test-skill-integrity.sh

# 6. CVSS recalculation
python tests/severity_counts.py --verify
```

---

## Post-Fix Checklist

- [ ] Fix compiles without warnings
- [ ] All existing tests pass
- [ ] New test covers the finding scenario
- [ ] Exploit scenario now fails
- [ ] Formal verification passes on fixed code (if available)
- [ ] CVSS recalculated and documented
- [ ] Fix doesn't introduce new findings
- [ ] Finding marked as "Fixed" in findings.json
- [ ] Remediation documented in audit output

---

## Regression Test Patterns

Exploit-grade regression tests that fail on vulnerable code and pass on fixed code. Each test is grounded in actual Solana/Anchor mechanics.

---

### VULN-01 (CRITICAL): Missing Signer Check on Admin

**Finding**: `admin_withdraw` accepts `AccountInfo` instead of `Signer`, allowing anyone to drain the vault.

**Anchor Test**:

```rust
#[tokio::test]
async fn test_admin_withdraw_rejects_non_signer() {
    let program = ProgramTest::bpf("vault", program_id)
        .start_with_context()
        .await;

    let payer = program.payer();
    let (vault_pda, _vault_bump) = Pubkey::find_program_address(
        &[b"vault"],
        &program_id,
    );

    // Fund vault with lamports
    let vault_initial = 10_000_000_000u64;
    program.rpc().transfer(payer.pubkey(), vault_pda, vault_initial).await.unwrap();

    // Attacker key — NOT a signer for admin field
    let attacker = Keypair::new();

    let accounts = vec![
        AccountMeta::new(vault_pda, false),
        AccountMeta::new_readonly(attacker.pubkey(), false), // admin ← NOT signer
        AccountMeta::new(attacker.pubkey(), false),
    ];

    let ix = Instruction {
        program_id,
        accounts,
        data: vault::instruction::AdminWithdraw { amount: vault_initial }.data(),
    };

    // Only payer signs — admin field belongs to attacker but didn't sign
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );

    let result = program.rpc().process_transaction(&tx).await;

    // MUST fail — vulnerable code accepts; fixed code uses Signer<'info>
    assert!(result.is_err(), "VULN-01: Non-signer admin should be rejected");

    // Verify vault untouched
    let vault_balance = program.rpc().get_balance(vault_pda).await.unwrap();
    assert_eq!(vault_balance, vault_initial, "Vault drained — VULN-01 still exploitable");
}
```

**Mechanics**: `Signer<'info>` forces Anchor to verify `is_signer` at deserialization. Passing a non-signer key in the admin slot causes an immediate rejection before instruction code runs.

---

### VULN-04 (CRITICAL): Lamport Drain via Unchecked Transfer

**Finding**: `drain_vault` has no authority signer and no `has_one` constraint — attacker passes their own address as destination.

**Anchor Test**:

```rust
#[tokio::test]
async fn test_drain_vault_rejects_attacker_destination() {
    let program = ProgramTest::bpf("vault", program_id)
        .start_with_context()
        .await;

    let payer = program.purse();
    let (vault_pda, _) = Pubkey::find_program_address(&[b"vault"], &program_id);

    let vault_balance = 5_000_000_000u64;
    program.rpc().transfer(payer, vault_pda, vault_balance).await.unwrap();

    // Attacker-controlled destination
    let attacker_dest = Keypair::new();

    let accounts = vec![
        AccountMeta::new(vault_pda, false),
        AccountMeta::new(attacker_dest.pubkey(), false), // attacker-supplied
    ];

    let ix = Instruction {
        program_id,
        accounts,
        data: vault::instruction::DrainVault { amount: vault_balance }.data(),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer),
        &[&program.wallet()],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );

    let result = program.rpc().process_transaction(&tx).await;

    assert!(result.is_err(), "VULN-04: drain_vault to arbitrary dest should fail");

    let final_balance = program.rpc().get_balance(vault_pda).await.unwrap();
    assert_eq!(final_balance, vault_balance, "Vault was drained — VULN-04 still open");
}
```

**Mechanics**: Fixed code adds `authority: Signer<'info>` and `#[account(has_one = authority)]`. The `has_one` constraint verifies `vault.authority == authority.key()` before the instruction body runs.

---

### VULN-05 (HIGH): Arithmetic Overflow on User-Supplied Amount

**Finding**: `user_deposit` uses unchecked `+` on u64 — release mode wraps silently.

**Anchor Test**:

```rust
#[tokio::test]
async fn test_deposit_overflow_rejected() {
    let program = ProgramTest::bpf("vault", program_id)
        .start_with_context()
        .await;

    let payer = program.purse();
    let user = Keypair::new();
    let (vault_pda, _) = Pubkey::find_program_address(&[b"vault"], &program_id);

    program.rpc().transfer(payer, vault_pda, 2_000_000_000).await.unwrap();

    // u64::MAX will wrap on unchecked add
    let overflow_amount = u64::MAX;

    let accounts = vec![
        AccountMeta::new(vault_pda, false),
        AccountMeta::new_readonly(user.pubkey(), true),
    ];

    let ix = Instruction {
        program_id,
        accounts,
        data: vault::instruction::UserDeposit { amount: overflow_amount }.data(),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer),
        &[&user],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );

    let result = program.rpc().process_transaction(&tx).await;

    assert!(result.is_err(), "VULN-05: Overflow deposit should be rejected");
}

#[tokio::test]
async fn test_deposit_u64_max_edge_case() {
    // Exact edge: vault at u64::MAX - 1, deposit u64::MAX → overflow
    let program = ProgramTest::bpf("vault", program_id)
        .start_with_context()
        .await;

    let user = Keypair::new();
    let (vault_pda, _) = Pubkey::find_program_address(&[b"vault"], &program_id);

    program.rpc().transfer(program.purse(), vault_pda, u64::MAX - 1).await.unwrap();

    let accounts = vec![
        AccountMeta::new(vault_pda, false),
        AccountMeta::new_readonly(user.pubkey(), true),
    ];

    let ix = Instruction {
        program_id,
        accounts,
        data: vault::instruction::UserDeposit { amount: u64::MAX }.data(),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&program.purse()),
        &[&user],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );

    // Vulnerable: wraps silently (tx succeeds, balance corrupted)
    // Fixed: returns ArithmeticOverflow error
    let result = program.rpc().process_transaction(&tx).await;
    assert!(result.is_err(), "u64::MAX + (u64::MAX - 1) overflow — fix not applied");
}
```

**Mechanics**: `checked_add` returns `Option<u64>` — `None` on overflow. Fixed code propagates with `?` and maps to `VaultError::ArithmeticOverflow`.

---

### VULN-03 (HIGH): Arbitrary CPI to User-Supplied Program

**Finding**: `exec_callback` accepts any `program_id` and invokes it — privilege escalation via arbitrary CPI.

**Anchor Test**:

```rust
#[tokio::test]
async fn test_exec_callback_rejects_arbitrary_program() {
    let program = ProgramTest::bpf("vault", program_id)
        .start_with_context()
        .await;

    // System Program as stand-in for arbitrary program
    let malicious_program = system_program::ID;

    let attacker = Keypair::new();

    let accounts = vec![
        AccountMeta::new_readonly(malicious_program, false),
    ];

    let ix = Instruction {
        program_id,
        accounts,
        data: vault::instruction::ExecCallback {
            data: vec![1, 2, 3],
        }.data(),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&program.purse()),
        &[&attacker],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );

    let result = program.rpc().process_transaction(&tx).await;

    assert!(result.is_err(), "VULN-03: Arbitrary CPI should be rejected");
}
```

**Mechanics**: Fixed code uses `Program<'info, SomeKnownProgram>` which validates program ID, or maintains an on-chain allowlist PDA checked via `require!(allowlist.contains(&target), Error::UnauthorizedProgram)`.

---

### VULN-06 (MEDIUM): Reinit Attack via Missing Discriminator

**Finding**: `VaultState` missing `#[account]` — no 8-byte discriminator written or checked on deserialize.

**Anchor Test**:

```rust
#[tokio::test]
async fn test_reinit_attack_blocked() {
    let program = ProgramTest::bpf("vault", program_id)
        .start_with_context()
        .await;

    let payer = program.purse();
    let attacker = Keypair::new();

    let (vault_pda, _) = Pubkey::find_program_address(&[b"vault"], &program_id);

    // Fund to rent-exempt
    let rent = program.rpc().get_minimum_balance_for_rent_exemption(0).await.unwrap();
    program.rpc().transfer(payer, vault_pda, rent).await.unwrap();

    // First initialize (attacker is authority)
    let init_ix = vault::instruction::Initialize { authority: attacker.pubkey() };
    let init_tx = Transaction::new_signed_with_payer(
        &[init_ix],
        Some(&payer),
        &[&attacker],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );
    program.rpc().process_transaction(init_tx).await.unwrap();

    // Second initialize — reinit attack with stolen authority
    let stolen_authority = Keypair::new();
    let reinit_ix = vault::instruction::Initialize { authority: stolen_authority.pubkey() };
    let reinit_tx = Transaction::new_signed_with_payer(
        &[reinit_ix],
        Some(&payer),
        &[&attacker],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );

    let result = program.rpc().process_transaction(reinit_tx).await;

    // MUST fail — discriminator check prevents reinit
    assert!(result.is_err(), "VULN-06: Reinit attack should be blocked");
}
```

**Mechanics**: `#[account]` writes an 8-byte discriminator on `init`. `Account<'info, VaultState>` verifies discriminator on deserialize. Without it, a re-initialized account with zeroed data passes as uninitialized.

---

### VULN-07 (MEDIUM): Division Truncation Loses Funds

**Finding**: `calc_shares` uses `/` which truncates — small deposits get 0 shares but tokens are debited.

**Anchor Test**:

```rust
#[tokio::test]
async fn test_calc_shares_minimum_enforced() {
    let program = ProgramTest::bpf("vault", program_id)
        .start_with_context()
        .await;

    let user = Keypair::new();
    let (vault_pda, _) = Pubkey::find_program_address(&[b"vault"], &program_id);

    // divisor >> deposit — truncation gives 0 shares
    let deposit = 1u64;
    let divisor = u64::MAX;

    let accounts = vec![
        AccountMeta::new(vault_pda, false),
        AccountMeta::new(user.pubkey(), false),
    ];

    let ix = Instruction {
        program_id,
        accounts,
        data: vault::instruction::CalcShares { deposit, divisor }.data(),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&program.purse()),
        &[&user],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );

    // Vulnerable: returns 0 shares, tx succeeds
    // Fixed: returns BelowMinimum or DivisionByZero error
    let result = program.rpc().process_transaction(&tx).await;
    assert!(result.is_err(), "VULN-07: Zero shares from truncation should be rejected");
}
```

---

### VULN-09 (MEDIUM): CPI Return Value Discarded

**Finding**: `unchecked_cpi` uses `let _ = invoke(...)` — CPI failures are silent.

**Anchor Test**:

```rust
#[tokio::test]
async fn test_unchecked_cpi_error_propagates() {
    let program = ProgramTest::bpf("vault", program_id)
        .start_with_context()
        .await;

    let user = Keypair::new();

    // Non-existent program — CPI will fail
    let invalid_program = Pubkey::new_unique();

    let accounts = vec![
        AccountMeta::new_readonly(invalid_program, false),
    ];

    let ix = Instruction {
        program_id,
        accounts,
        data: vault::instruction::UncheckedCpi { data: vec![1, 2, 3] }.data(),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&program.purse()),
        &[&user],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );

    // Vulnerable: tx succeeds (CPI error discarded)
    // Fixed: tx fails (CPI error propagated via ?)
    let result = program.rpc().process_transaction(&tx).await;
    assert!(result.is_err(), "VULN-09: Failed CPI should propagate, not succeed silently");
}
```

---

## Test Execution Commands

```bash
# Run all regression tests
anchor test --grep "vuln" tests/regression/

# Run specific finding test
anchor test --grep "admin_withdraw_rejects_non_signer"

# Run with verbose output
RUST_LOG=debug anchor test -v

# Full regression suite (CI gate)
anchor test && python scripts/audit-fix-suggestions.py --regression
```

---

## Exploit PoC Verification

```rust
#[tokio::test]
async fn test_exploit_crit01_fixed() {
    // Arrange: Set up exploit conditions
    let program = ProgramTest::bpf("vault", program_id).start_with_context().await;

    // Create malicious instruction without signer
    let malicious_tx = Transaction::new_signed_with_payer(
        &[instruction::admin_withdraw(
            &program_id,
            &CONTEXT_ACCOUNTS,  // Missing admin signer
            1_000_000,
        )],
        Some(&payer.pubkey()),
        &[&payer],  // Only payer signs, NOT admin
        recent_blockhash,
    );

    // Act: Attempt the exploit
    let result = program.rpc().process_transaction(&malicious_tx).await;

    // Assert: Should fail with signer error
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TransportError::TransactionError(TransactionError::InstructionError(
            _,
            InstructionError::Custom(42)  // NotSigner error code
        ))
    ));
}
```

---

## Absolute Constraints

1. **Never auto-apply without consent**: Even Tier A requires explicit approval
2. **Never alter intended behavior**: Fixes must not break valid use cases
3. **Never skip verification**: Always run tests after fix
4. **Never hardcode secrets**: Use constants for program IDs
5. **Never skip CVSS recalculation**: Document severity change
