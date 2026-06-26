# Phase 6: Remediation Guidance

**Goal**: Guide secure fix implementation and verify fixes don't introduce regressions.

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
