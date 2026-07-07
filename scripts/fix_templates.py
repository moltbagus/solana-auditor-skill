#!/usr/bin/env python3
"""
fix_templates.py — FixTemplate dataclass and library of 26 fix patterns.

Single Responsibility: Store the FixTemplate dataclass and all before/after
code templates. Reason to change: Fix pattern changes or new rule templates.

Usage:
    from fix_templates import FixTemplate, get_fix_template
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FixTemplate:
    """Template for generating before/after code patterns."""

    before: str
    after: str
    explanation: str


def get_fix_template(rule_id: str, finding_id: str) -> FixTemplate:
    """
    Return the appropriate fix template for a given rule.

    Args:
        rule_id: Rule identifier (e.g., "Rule 8")
        finding_id: Finding identifier (e.g., "VULN-01")

    Returns:
        FixTemplate with before_code, after_code, and explanation
    """
    # -------------------------------------------------------------------------
    # Rule 1: Anchor Program Entry Point
    # -------------------------------------------------------------------------
    if rule_id == "Rule 1":
        return FixTemplate(
            before="""// Analyze instruction context before making changes
pub fn instruction_name(ctx: Context<InstructionAccounts>, arg: u64) -> Result<()> {
    // UNSAFE: Editing privileged code without understanding full instruction surface
    ctx.accounts.target.rebalance -= arg;
    Ok(())
}""",
            after="""// SECURE: Map full instruction surface and identify privileged mutations
// BEFORE editing: Identify all instructions that touch this account
// KEY CHECKS: Signer verification, amount limits, state transitions
pub fn instruction_name(ctx: Context<InstructionAccounts>, arg: u64) -> Result<()> {
    require_signed!(ctx.accounts.admin);  // Add signer guard
    require!(arg <= MAX_WITHDRAWAL, VaultError::ExceedsLimit);
    ctx.accounts.target.rebalance = ctx.accounts.target.rebalance
        .checked_sub(arg)
        .ok_or(VaultError::ArithmeticError)?;
    Ok(())
}""",
            explanation="Privileged instruction surface requires comprehensive analysis. "
                        "Before editing any program entry point, map all instructions that "
                        "touch the account, identify all privileged operations, and add "
                        "appropriate guards (signer checks, amount limits, state validation).",
        )

    # -------------------------------------------------------------------------
    # Rule 2: Account Validation Constraints
    # -------------------------------------------------------------------------
    if rule_id == "Rule 2":
        return FixTemplate(
            before="""#[derive(Accounts)]
pub struct Initialize<'info> {
    pub vault: AccountInfo<'info>,  // MISSING: discriminator, owner, init
    pub user: AccountInfo<'info>,   // MISSING: signer constraint
}""",
            after="""#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,                           // Writes 8-byte discriminator
        payer = user,                   // Rent payer
        space = 8 + VaultState::LEN,   // Account size
        seeds = [b"vault", admin.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, VaultState>,  // Anchor enforces discriminator
    #[account(mut)]
    pub user: Signer<'info>,                  // Enforces signer
    pub system_program: Program<'info, System>,
}""",
            explanation="Account constraints must include: (1) discriminator via "
                        "`#[account]` or `init`, (2) owner verification via `Account<T>`, "
                        "(3) signer constraint for privileged operations, (4) space allocation "
                        "for init. Anchor's `Account<T>` validates ownership and discriminator.",
        )

    # -------------------------------------------------------------------------
    # Rule 3: PDA Canonical Bump
    # -------------------------------------------------------------------------
    if rule_id == "Rule 3":
        return FixTemplate(
            before="""// UNSAFE: Hardcoded bump literal
let bump = 254;  // attacker can find alternative bump
let vault_pda = Pubkey::create_program_address(
    &[b"vault", user.key().as_ref(), &[bump]],
    program_id
)?;""",
            after="""// SECURE: Use canonical bump from Anchor context
let bump = ctx.bumps.vault;  // Anchor 0.30+ returns canonical bump
let seeds = &[b"vault", user.key().as_ref(), &[bump]];
let vault_pda = Pubkey::create_program_address(seeds, program_id)
    .map_err(|_| VaultError::InvalidPda)?;

// Or: Manual derivation with find_program_address
let (vault_pda, canonical_bump) = Pubkey::find_program_address(
    &[b"vault", user.key().as_ref()],
    program_id
);""",
            explanation="Hardcoded bump values are unsafe because any valid bump "
                        "produces a PDA. Use `ctx.bumps.<name>` from Anchor (canonical "
                        "by default), or `Pubkey::find_program_address` which returns "
                        "the highest valid bump (0xFF -> 0x00). Store only canonical bumps.",
        )

    # -------------------------------------------------------------------------
    # Rule 4: CPI Safety
    # -------------------------------------------------------------------------
    if rule_id == "Rule 4":
        return FixTemplate(
            before="""// UNSAFE: No program ID validation
pub fn exec_callback(ctx: Context<Callback>, data: Vec<u8>) -> Result<()> {
    let target = ctx.accounts.target_program.key();
    let instruction = Instruction {
        program_id: target,  // attacker-supplied program
        accounts: ctx.remaining_accounts().to_vec(),
        data: data,
    };
    invoke(&instruction, &ctx.accounts.to_account_infos())?;
    Ok(())
}""",
            after="""// SECURE: Validate program ID against allowlist
use solana_program::program::set_return_data;

const ALLOWED_PROGRAMS: &[Pubkey] = &[
    spl_token::ID,
    system_program::ID,
];

pub fn exec_callback(ctx: Context<Callback>, data: Vec<u8>) -> Result<()> {
    let target = ctx.accounts.target_program.key();

    // VALIDATE: Program must be in allowlist
    require!(
        ALLOWED_PROGRAMS.contains(&target),
        CallbackError::UnauthorizedProgram
    );

    let instruction = Instruction {
        program_id: target,
        accounts: ctx.remaining_accounts().to_vec(),
        data: data,
    };
    invoke(&instruction, &ctx.accounts.to_account_infos())?;
    Ok(())
}""",
            explanation="CPI to user-supplied programs enables privilege escalation. "
                        "Always validate program IDs against an allowlist or use typed "
                        "`Program<T>` wrappers. Never accept arbitrary program IDs without "
                        "verification.",
        )

    # -------------------------------------------------------------------------
    # Rule 5: Token Program Distinction
    # -------------------------------------------------------------------------
    if rule_id == "Rule 5":
        return FixTemplate(
            before="""// UNSAFE: No token program validation
pub fn transfer_tokens(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    let mint = &ctx.accounts.mint;
    // MISSING: Verify mint owner is expected token program
    anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)
}""",
            after="""// SECURE: Validate token program ID
pub fn transfer_tokens(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    let mint = &ctx.accounts.mint;

    // VALIDATE: Verify token program matches expectation
    match ctx.accounts.token_program.key() {
        key if key == spl_token::ID => {
            // SPL Token
        }
        key if key == spl_token_2022::ID => {
            // Token-2022: handle extensions
        }
        _ => return Err(TokenError::InvalidTokenProgram.into()),
    }

    // VALIDATE: Mint owner
    require!(
        mint.owner == ctx.accounts.token_program.key(),
        TokenError::InvalidMintOwner
    );

    anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)
}""",
            explanation="SPL Token and Token-2022 are incompatible. Mixing programs "
                        "causes failures or security issues. Always verify the token "
                        "program ID and handle Token-2022 extensions appropriately.",
        )

    # -------------------------------------------------------------------------
    # Rule 6: Arithmetic Overflow
    # -------------------------------------------------------------------------
    if rule_id == "Rule 6":
        return FixTemplate(
            before="""// UNSAFE: Default arithmetic wraps in release mode
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.total_deposits = vault.total_deposits + amount;  // overflow wraps silently
    vault.user_balance[user_idx] += amount;
    Ok(())
}""",
            after="""// SECURE: Use checked arithmetic
use anchor_lang::prelude::borsh::BorshDeserialize;

pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;

    // CHECKED: Overflow returns error
    vault.total_deposits = vault.total_deposits
        .checked_add(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;

    vault.user_balance[user_idx] = vault.user_balance[user_idx]
        .checked_add(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;

    Ok(())
}

// Also use checked_sub, checked_mul, checked_div as appropriate""",
            explanation="Rust's default arithmetic wraps in release mode. "
                        "Always use `checked_add`, `checked_sub`, `checked_mul`, "
                        "`checked_div` for u64/u128 on user-controlled amounts. "
                        "Wrap returns `Option`, propagate with `?` or handle explicitly.",
        )

    # -------------------------------------------------------------------------
    # Rule 7: Account Closing / Lamport Drain
    # -------------------------------------------------------------------------
    if rule_id == "Rule 7":
        return FixTemplate(
            before="""// UNSAFE: No authority check on close target
#[derive(Accounts)]
pub struct CloseAccount<'info> {
    pub account: AccountInfo<'info>,
    pub destination: AccountInfo<'info>,  // attacker can set this
}""",
            after="""// SECURE: Verify close authority
#[derive(Accounts)]
pub struct CloseAccount<'info> {
    #[account(
        mut,
        close = authority  // Anchor transfers to VERIFIED authority
    )]
    pub account: Account<'info, UserAccount>,
    #[account(seeds = [b"admin"], bump)]
    pub authority: SystemAccount<'info>,
    pub user: Signer<'info>,
}

pub fn close_account(ctx: Context<CloseAccount>) -> Result<()> {
    // Close authority is bound via #[account(close = authority)]
    // Anchor verifies authority signs and transfers lamports
    Ok(())
}""",
            explanation="The `close` constraint specifies the lamport drain target. "
                        "Never let users supply the close target. Use a verified authority "
                        "(signer, PDA derived from signers, or `has_one` constraint) as "
                        "the close target.",
        )

    # -------------------------------------------------------------------------
    # Rule 8: Signer Verification (CRITICAL)
    # -------------------------------------------------------------------------
    if rule_id == "Rule 8":
        return FixTemplate(
            before="""// CRITICAL: No signer verification
#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    pub vault: AccountInfo<'info>,      // No Signer constraint
    pub admin: AccountInfo<'info>,      // Any account can be passed
    pub destination: AccountInfo<'info>,
}

pub fn admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64) -> Result<()> {
    // NO signer check - anyone can withdraw!
    let vault = ctx.accounts.vault;
    **vault.try_borrow_mut_lamports()? -= amount;
    **ctx.accounts.destination.try_borrow_mut_lamports()? += amount;
    Ok(())
}""",
            after="""// SECURE: Signer verification on privileged action
#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    #[account(
        mut,
        has_one = admin  // Binds vault.authority to admin
    )]
    pub vault: Account<'info, VaultState>,
    pub admin: Signer<'info>,           // Anchor enforces signer
    #[account(mut)]
    pub destination: SystemAccount<'info>,
}

pub fn admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64) -> Result<()> {
    // Anchor verified admin signed via Signer<'info>
    // has_one verified vault.authority == admin.key()
    require!(
        ctx.accounts.vault.total >= amount,
        VaultError::InsufficientFunds
    );
    ctx.accounts.vault.total -= amount;
    // Transfer via SystemProgram
    anchor_lang::system_program::transfer(
        CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.vault.to_account_info(),
                to: ctx.accounts.destination.to_account_info(),
            },
        ),
        amount,
    )?;
    Ok(())
}""",
            explanation="Every privileged action requires signer verification. "
                        "Use `Signer<'info>` in Anchor (enforced at deserialization) "
                        "or explicit `is_signer` checks with `AccountInfo`. Add "
                        "`has_one` or `address` constraints to bind authorities.",
        )

    # -------------------------------------------------------------------------
    # Rule 9: Upgrade Authority
    # -------------------------------------------------------------------------
    if rule_id == "Rule 9":
        return FixTemplate(
            before="""# Upgrade authority is single key (MEDIUM risk)
[programs.localnet]
vault = "..."

[programs.cluster]
vault = "..."

[registry]
url = "https://anchor.project-serum.com"

[provider]
cluster = "mainnet"
wallet = "~/.config/solana/id.json"

[anchor-debug]
# No upgrade authority specified - defaults to wallet""",
            after="""# RECOMMENDED: Multisig upgrade authority via Squads
[programs.localnet]
vault = "..."

[programs.cluster]
vault = "..."

[programs.mainnet]
vault = "..."

# Upgrade authority via Squads multisig (recommended for production)
[authority]
# Replace with Squads V3 PDA after initialization
upgrade_authority = "REPLACE_WITH_SQUADS_MULTISIG_PDA"

[anchor-debug]
# log_level = "info"

[provider]
cluster = "mainnet"
# Consider using a hardware wallet or air-gapped key for the multisig""",
            explanation="Single-key upgrade authority is a single point of failure. "
                        "Transfer upgrade authority to a multisig (Squads, Realms) "
                        "or a timelock PDA for production programs.",
        )

    # -------------------------------------------------------------------------
    # Rule 10: Error Handling
    # -------------------------------------------------------------------------
    if rule_id == "Rule 10":
        return FixTemplate(
            before="""// UNSAFE: panic! in instruction
pub fn unsafe_instruction(ctx: Context<Unsafe>, data: Vec<u8>) -> Result<()> {
    let parsed = parse_data(&data)?;
    if parsed.value > 1000 {
        panic!("Value too high: {}", parsed.value);  // Never panic!
    }
    Ok(())
}""",
            after="""// SECURE: Typed error propagation
use anchor_lang::error::ErrorCode;

#[error_code]
pub enum VaultError {
    #[msg("Value exceeds maximum allowed")]
    ValueTooHigh,
    #[msg("Arithmetic overflow occurred")]
    ArithmeticOverflow,
    #[msg("Account not initialized")]
    Uninitialized,
    #[msg("Invalid authority")]
    Unauthorized,
}

pub fn safe_instruction(ctx: Context<Unsafe>, data: Vec<u8>) -> Result<()> {
    let parsed = parse_data(&data)?;
    require!(
        parsed.value <= MAX_VALUE,
        VaultError::ValueTooHigh
    );
    // Use ? propagation instead of unwrap/expect
    let processed = process_value(parsed.value)?;
    ctx.accounts.target.value = processed;
    Ok(())
}

fn process_value(val: u64) -> Result<u64> {
    val.checked_mul(2).ok_or(VaultError::ArithmeticOverflow)
}""",
            explanation="Never use `panic!` or `unwrap`/`expect` in instruction code. "
                        "Use typed Anchor errors via `err!()` or the `#[error_code]` enum. "
                        "Propagate all Results with `?`.",
        )

    # -------------------------------------------------------------------------
    # Rule 11: Reinitialization Attacks
    # -------------------------------------------------------------------------
    if rule_id == "Rule 11":
        return FixTemplate(
            before="""// UNSAFE: Manual init without discriminator check
#[derive(Clone)]
pub struct VaultState {
    pub authority: Pubkey,
    pub total: u64,
}

pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    let vault = ctx.accounts.vault;
    // NO discriminator check - can reinit
    vault.authority = ctx.accounts.admin.key();
    vault.total = 0;
    Ok(())
}""",
            after="""// SECURE: Use Anchor Account or check discriminator
#[account]
pub struct VaultState {
    pub authority: Pubkey,
    pub total: u64,
}

impl VaultState {
    pub const LEN: usize = 32 + 8;
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + VaultState::LEN,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, VaultState>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    ctx.accounts.vault.authority = ctx.accounts.admin.key();
    ctx.accounts.vault.total = 0;
    // Anchor's init writes discriminator automatically
    Ok(())
}""",
            explanation="Manual initialization must check the 8-byte discriminator "
                        "to prevent reinitialization attacks. Use `#[account(init, ...)]` "
                        "which writes discriminator atomically, or manually check "
                        "`account.data.borrow()[..8] == MyAccount::DISCRIMINATOR`.",
        )

    # -------------------------------------------------------------------------
    # Rule 12: Rent and Lamport Safety
    # -------------------------------------------------------------------------
    if rule_id == "Rule 12":
        return FixTemplate(
            before="""// UNSAFE: Manual account creation without rent
pub fn create_account_unsafe(
    ctx: Context<CreateAccount>,
    lamports: u64,
    space: u64,
) -> Result<()> {
    let account = ctx.accounts.target.to_account_info();
    let vault = ctx.accounts.vault.to_account_info();

    // MISSING: Rent exemption check
    let balance = account.lamports();
    if balance < lamports {
        return Err(VaultError::InsufficientFunds.into());
    }
    // ...
}""",
            after="""// SECURE: Use SystemInstruction::create_account or Anchor init
use solana_program::rent::Rent;
use solana_program::system_instruction::create_account;

pub fn create_account_safe(
    ctx: Context<CreateAccount>,
    space: u64,
) -> Result<()> {
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(space as usize);

    let ix = create_account(
        &ctx.accounts.payer.key(),
        &ctx.accounts.target.key(),
        lamports,
        space,
        &ctx.program_id,
    );

    solana_program::program::invoke(
        &ix,
        &[
            ctx.accounts.payer.to_account_info(),
            ctx.accounts.target.to_account_info(),
            ctx.accounts.system_program.to_account_info(),
        ],
    )?;

    // Verify rent exemption after creation
    let rent = Rent::get()?;
    require!(
        rent.is_exempt(
            ctx.accounts.target.get_lamports(),
            ctx.accounts.target.data_len(),
        ),
        VaultError::NotRentExempt
    );
    Ok(())
}""",
            explanation="Manual account creation must ensure rent exemption. "
                        "Use Anchor's `init` constraint (handles rent automatically) "
                        "or manually calculate with `Rent::get()?.minimum_balance(size)`.",
        )

    # -------------------------------------------------------------------------
    # Rule 13: Flash Loan Attack Surface
    # -------------------------------------------------------------------------
    if rule_id == "Rule 13":
        return FixTemplate(
            before="""// UNSAFE: Price from single source, no staleness check
pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
    let price = ctx.accounts.price_feed.price;  // No staleness check
    let collateral_value = ctx.accounts.collateral_amount * price;

    require!(
        collateral_value >= amount * MIN_COLLATERAL_RATIO,
        VaultError::InsufficientCollateral
    );
    // ...
}""",
            after="""// SECURE: Multi-source price with staleness and confidence checks
use solana_program::clock::Clock;

const MAX_PRICE_AGE_SECONDS: i64 = 60;
const MAX_CONFIDENCE_INTERVAL: u64 = 100;  // basis points

pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
    let clock = Clock::get()?;

    // CHECK: Price staleness
    let price_data = &ctx.accounts.price_feed;
    let slot_age = clock.slot - price_data.last_update_slot;
    require!(
        slot_age <= MAX_PRICE_AGE_SECONDS / 400,  // ~400ms per slot
        PriceError::StalePrice
    );

    // CHECK: Timestamp freshness (if available)
    let timestamp_age = clock.unix_timestamp - price_data.timestamp;
    require!(
        timestamp_age <= MAX_PRICE_AGE_SECONDS,
        PriceError::StaleTimestamp
    );

    // CHECK: Confidence interval
    require!(
        price_data.confidence <= MAX_CONFIDENCE_INTERVAL,
        PriceError::HighConfidence
    );

    let price = price_data.price;
    let collateral_value = collateral
        .amount
        .checked_mul(price)
        .ok_or(VaultError::ArithmeticOverflow)?;

    require!(
        collateral_value >= amount
            .checked_mul(MIN_COLLATERAL_RATIO)
            .ok_or(VaultError::ArithmeticOverflow)?,
        VaultError::InsufficientCollateral
    );
    Ok(())
}""",
            explanation="Flash loan attacks exploit price staleness and balance "
                        "snapshot timing. Verify price staleness (slot/timestamp), "
                        "use multiple oracle sources, and take balance snapshots "
                        "AFTER all state changes and flash loan repayments.",
        )

    # -------------------------------------------------------------------------
    # Rule 14: Reentrancy Guard (CRITICAL)
    # -------------------------------------------------------------------------
    if rule_id == "Rule 14":
        return FixTemplate(
            before="""// CRITICAL: State mutation after external call
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let user = &mut ctx.accounts.user;
    require!(user.balance >= amount, VaultError::InsufficientFunds);

    // UNSAFE: External call BEFORE state update
    anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)?;

    // STATE UPDATE AFTER EXTERNAL CALL - reentrancy window open!
    user.balance -= amount;
    ctx.accounts.vault.total -= amount;
    Ok(())
}""",
            after="""// SECURE: CEI pattern with reentrancy guard
#[account]
pub struct VaultState {
    pub authority: Pubkey,
    pub total: u64,
    pub in_progress: bool,  // Reentrancy guard flag
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let user = &mut ctx.accounts.user;
    let vault = &mut ctx.accounts.vault;

    // CHECK: Balance and guard
    require!(user.balance >= amount, VaultError::InsufficientFunds);
    require!(!vault.in_progress, VaultError::ReentrancyDetected);

    // EFFECT: Update state BEFORE external call (CEI)
    user.balance = user.balance
        .checked_sub(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;
    vault.total = vault.total
        .checked_sub(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;
    vault.in_progress = true;

    // INTERACTION: External call LAST
    anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)?;

    // Reset guard after external call completes
    vault.in_progress = false;
    Ok(())
}""",
            explanation="CEI (Checks-Effects-Interactions) pattern: all state checks "
                        "and modifications MUST complete before any external call. "
                        "Use a reentrancy lock flag when the protocol handles callbacks "
                        "or token transfers. Execute token transfers LAST.",
        )

    # -------------------------------------------------------------------------
    # Rule 15: remaining_accounts Validation (CRITICAL)
    # -------------------------------------------------------------------------
    if rule_id == "Rule 15":
        return FixTemplate(
            before="""// CRITICAL: No remaining_accounts validation
pub fn cpi_with_remaining(
    ctx: Context<CpiCall>,
    data: Vec<u8>,
) -> Result<()> {
    let remaining = ctx.remaining_accounts();

    // UNSAFE: Pass all remaining accounts without validation
    let instruction = Instruction {
        program_id: ctx.accounts.target_program.key(),
        accounts: remaining.to_vec(),
        data: data,
    };
    invoke(&instruction, &remaining.to_account_infos())?;
    Ok(())
}""",
            after="""// SECURE: Validate all remaining accounts
pub fn cpi_with_remaining(
    ctx: Context<CpiCall>,
    data: Vec<u8>,
) -> Result<()> {
    let remaining = ctx.remaining_accounts();
    let expected_count = 3;
    let expected_program = spl_token::ID;

    // VALIDATE: Count
    require!(
        remaining.len() == expected_count,
        CpiError::InvalidAccountCount
    );

    // VALIDATE: Each account
    let (user, vault, mint) = match remaining.as_slice() {
        [user, vault, mint] => (user, vault, mint),
        _ => return Err(CpiError::InvalidAccountLayout.into()),
    };

    require!(user.is_signer, CpiError::ExpectedSigner);
    require!(user.owner == &expected_program, CpiError::InvalidOwner);
    require!(vault.is_writable, CpiError::ExpectedWritable);

    // Now safe to use
    let instruction = Instruction {
        program_id: ctx.accounts.target_program.key(),
        accounts: remaining.to_vec(),
        data: data,
    };
    invoke(&instruction, &remaining.to_account_infos())?;
    Ok(())
}""",
            explanation="Missing remaining_accounts validation enables account "
                        "injection attacks. Always validate: (1) count matches expected, "
                        "(2) signer/writable flags, (3) owner/program, (4) account keys "
                        "if position-dependent.",
        )

    # -------------------------------------------------------------------------
    # Rule 16: Discriminator Collision (CRITICAL)
    # -------------------------------------------------------------------------
    if rule_id == "Rule 16":
        return FixTemplate(
            before="""// CRITICAL: Potential discriminator collision
#[derive(Accounts)]
pub struct VaultAccount<'info> {
    pub vault: Account<'info, VaultData>,
}

#[derive(Accounts)]
pub struct VaultAdmin<'info> {
    pub vault: Account<'info, VaultData>,  // COLLISION: "Vault" + "VaultAdmin"
    // Both generate "Vault\\\\0\\\\0\\\\0\\\\0\\\\0" discriminator!
}""",
            after="""// SECURE: Use unique struct names or manual discriminators
#[derive(Accounts)]
pub struct UserVault<'info> {
    #[account(seeds = [b"user_vault", user.key().as_ref()], bump)]
    pub vault: Account<'info, UserVaultData>,
}

#[derive(Accounts)]
pub struct AdminVault<'info> {
    #[account(seeds = [b"admin_vault"], bump)]
    pub vault: Account<'info, AdminVaultData>,
}

// If you must use similar names, use manual discriminator:
mod discriminator {
    pub const USER_VAULT: [u8; 8] = [0x55, 0x73, 0x65, 0x72, 0x5f, 0x76, 0x61, 0x75]; // "uservault"
    pub const ADMIN_VAULT: [u8; 8] = [0x61, 0x64, 0x6d, 0x69, 0x6e, 0x5f, 0x76, 0x61]; // "admin_va"
}

#[derive(Accounts)]
pub struct AdminVault<'info> {
    #[account(
        seeds = [b"admin_vault"],
        bump,
        // Manual discriminator for collision avoidance
    )]
    pub vault: AccountLoader<'info, AdminVaultData>,
}""",
            explanation="Anchor generates 8-byte discriminators from struct names "
                        "(case-insensitive, null-padded to 8 bytes). "
                        "'Vault' and 'VaultAdmin' both produce 'vault\\\\0\\\\0\\\\0\\\\0\\\\0'. "
                        "Use unique names or manual discriminators.",
        )

    # -------------------------------------------------------------------------
    # Rule 17: AccountLoader vs Account
    # -------------------------------------------------------------------------
    if rule_id == "Rule 17":
        return FixTemplate(
            before="""// HIGH RISK: AccountLoader without owner check
pub fn load_vault(ctx: Context<LoadVault>) -> Result<()> {
    let vault = ctx.accounts.vault.load_init()?;
    // NO owner check - vault could be from wrong program!
    ctx.accounts.user_balance = vault.balance;
    Ok(())
}""",
            after="""// SECURE: Use Account<T> or validate with AccountLoader
// OPTION 1: Use Account<T> (recommended)
#[derive(Accounts)]
pub struct LoadVault<'info> {
    pub vault: Account<'info, VaultState>,  // Anchor validates owner
}

pub fn load_vault_opt1(ctx: Context<LoadVault>) -> Result<()> {
    let vault = &ctx.accounts.vault;
    ctx.accounts.user_balance = vault.balance;
    Ok(())
}

// OPTION 2: AccountLoader with manual owner check
pub fn load_vault_opt2(ctx: Context<LoadVault>) -> Result<()> {
    let vault_info = ctx.accounts.vault.to_account_info();
    let vault = vault_info.try_borrow_data()?;
    let data = VaultState::try_from_slice(&vault)?;

    // MANUAL: Owner check required with AccountLoader
    require!(
        vault_info.owner == ctx.program_id,
        VaultError::InvalidOwner
    );

    ctx.accounts.user_balance = data.balance;
    Ok(())
}""",
            explanation="`Account<T>` validates owner automatically. "
                        "`AccountLoader<T>` and `UncheckedAccount<T>` do NOT. "
                        "AccountLoader does not verify owner; you must check it manually.",
        )

    # -------------------------------------------------------------------------
    # Rule 18: Borsh Deserialization Panic
    # -------------------------------------------------------------------------
    if rule_id == "Rule 18":
        return FixTemplate(
            before="""// UNSAFE: unwrap() on untrusted data
pub fn process_data(ctx: Context<Process>, data: Vec<u8>) -> Result<()> {
    let account = ctx.accounts.target.try_borrow_data()?;
    let parsed = MyStruct::try_from_slice(&account)
        .unwrap();  // PANIC on invalid data!
    // ...
}""",
            after="""// SECURE: Proper Result propagation
pub fn process_data(ctx: Context<Process>, data: Vec<u8>) -> Result<()> {
    let account = ctx.accounts.target.try_borrow_data()?;

    // SAFE: Propagate errors with ?
    let parsed = MyStruct::try_from_slice(&account)
        .map_err(|_| VaultError::DeserializationError)?;

    // Or use Anchor's Account<T> which handles this safely:
    // let account = Account::<MyStruct>::try_from(&ctx.accounts.target)?;
    // parsed = &account;

    ctx.accounts.result.value = parsed.value;
    Ok(())
}""",
            explanation="Account data is untrusted. Use `try_from_slice` and propagate "
                        "errors with `?`. Never `unwrap()` or `expect()` on data "
                        "from account. Anchor's `Account<T>` handles this safely.",
        )

    # -------------------------------------------------------------------------
    # Rule 19: Anchor verify/address Constraint
    # -------------------------------------------------------------------------
    if rule_id == "Rule 19":
        return FixTemplate(
            before="""// UNSAFE: address constraint without owner check
#[derive(Accounts)]
pub struct VerifyDeposit<'info> {
    #[account(address = expected_token_account)]
    pub token_account: Account<'info, TokenAccount>,
    // MISSING: owner check, mint verification
}""",
            after="""// SECURE: address constraint with additional validation
#[derive(Accounts)]
pub struct VerifyDeposit<'info> {
    #[account(
        address = expected_token_account,
        owner = token_program::ID  // Explicit owner check
    )]
    pub token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

pub fn verify_deposit(ctx: Context<VerifyDeposit>) -> Result<()> {
    // VALIDATE: Additional checks beyond constraint
    require!(
        ctx.accounts.token_account.mint == expected_mint,
        TokenError::InvalidMint
    );
    require!(
        ctx.accounts.token_account.delegate.is_none(),
        TokenError::FrozenDelegation
    );
    Ok(())
}""",
            explanation="`address` and `verify` constraints can be bypassed. "
                        "Always add redundant `owner` checks and validate additional "
                        "invariants (mint, state flags) in the instruction body.",
        )

    # -------------------------------------------------------------------------
    # Rule 20: Token-2022 Extension Ordering
    # -------------------------------------------------------------------------
    if rule_id == "Rule 20":
        return FixTemplate(
            before="""// UNSAFE: Wrong extension initialization order
pub fn init_token_v2(ctx: Context<InitTokenV2>) -> Result<()> {
    // WRONG: transfer_fee before memo
    initialize_transfer_fee_config(ctx.accounts.transfer_fee_ctx(), ...)?;
    initialize_memo(ctx.accounts.memo_ctx(), ...)?;  // Too late!
    Ok(())
}""",
            after="""// SECURE: Correct extension initialization order
pub fn init_token_v2(ctx: Context<InitTokenV2>) -> Result<()> {
    // STEP 1: Memo extension FIRST (required by transfer_fee)
    initialize_memo(ctx.accounts.memo_ctx(), ...)?;

    // STEP 2: Then transfer_fee (requires memo)
    initialize_transfer_fee_config(ctx.accounts.transfer_fee_ctx(), ...)?;

    // STEP 3: Other extensions in required order
    // ...

    Ok(())
}""",
            explanation="Token-2022 extensions have initialization prerequisites. "
                        "Memo extension must initialize before transfer_fee. "
                        "Consult SPL Token-2022 docs for correct extension ordering.",
        )

    # -------------------------------------------------------------------------
    # Rule 21: CPI Callback Reentrancy
    # -------------------------------------------------------------------------
    if rule_id == "Rule 21":
        return FixTemplate(
            before="""// UNSAFE: Reentrancy guard can be bypassed via callback
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    require!(!vault.in_use, VaultError::Reentrancy);
    vault.in_use = true;

    // CPI could callback via different PDA
    anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)?;

    vault.in_use = false;
    vault.amount -= amount;
    Ok(())
}""",
            after="""// SECURE: CEI pattern prevents callback reentrancy
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;

    // CHECK: Pre-condition
    require!(!vault.in_use, VaultError::Reentrancy);

    // EFFECT: Update ALL state BEFORE external call
    vault.in_use = true;
    vault.amount = vault.amount
        .checked_sub(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;

    // INTERACTION: External call LAST (CEI prevents callback reentrancy)
    anchor_spl::token::transfer(ctx.accounts.transfer_ctx(), amount)?;

    // Reset guard after external call
    vault.in_use = false;
    Ok(())
}""",
            explanation="CEI pattern prevents callback reentrancy because state "
                        "is finalized before the external call. A callback reentering "
                        "via a different PDA sees consistent state.",
        )

    # -------------------------------------------------------------------------
    # Rule 22: init_if_needed + close Race
    # -------------------------------------------------------------------------
    if rule_id == "Rule 22":
        return FixTemplate(
            before="""// UNSAFE: Race condition between init_if_needed and close
// Instruction 1: init_if_needed
#[derive(Accounts)]
pub struct InitUser<'info> {
    #[account(init_if_needed, space = 8 + User::LEN, payer = user, seeds = [...], bump)]
    pub user: Account<'info, User>,
    pub user: Signer<'info>,
}

// Instruction 2: close (separate instruction - race window!)
#[derive(Accounts)]
pub struct CloseUser<'info> {
    #[account(close = recipient)]
    pub user: Account<'info, User>,
}""",
            after="""// SECURE: Single atomic instruction for state transitions
#[derive(Accounts)]
pub struct TransitionUser<'info> {
    #[account(mut, seeds = [...], bump)]
    pub user: Account<'info, User>,
    pub admin: Signer<'info>,
}

pub fn transition_user(
    ctx: Context<TransitionUser>,
    new_status: UserStatus,
) -> Result<()> {
    let user = &mut ctx.accounts.user;
    require!(
        ctx.accounts.admin.key() == user.admin,
        VaultError::Unauthorized
    );

    match new_status {
        UserStatus::Active => {
            // Transition from inactive to active
            user.status = UserStatus::Active;
        }
        UserStatus::Closed => {
            // ATOMIC: Transfer lamports and close in single instruction
            let dest = ctx.accounts.destination.to_account_info();
            **dest.try_borrow_mut_lamports()? += user.to_account_info().lamports();
            **user.to_account_info().try_borrow_mut_lamports()? = 0;
            // No separate close instruction needed
        }
    }
    Ok(())
}""",
            explanation="init_if_needed + close on separate instructions creates a "
                        "race condition. Attacker can front-run close with reinit. "
                        "Use single atomic instructions for state transitions, "
                        "or protect with a common reentrancy lock.",
        )

    # -------------------------------------------------------------------------
    # Rule 23: Memo Program CPI Injection
    # -------------------------------------------------------------------------
    if rule_id == "Rule 23":
        return FixTemplate(
            before="""// UNSAFE: User-controlled memo in CPI
pub fn log_deposit(ctx: Context<LogDeposit>, memo: String) -> Result<()> {
    // ATTACK: User-supplied memo can forge confirmations
    invoke(
        &spl_memo::instruction::build(memo.as_bytes()),
        &[],
    )?;
    Ok(())
}""",
            after="""// SECURE: Program-controlled memo only
pub fn log_deposit(ctx: Context<LogDeposit>) -> Result<()> {
    // Program generates memo - not attacker-controllable
    let user_key = ctx.accounts.user.key();
    let memo = format!("DEP:{}", &user_key.to_string()[..8]);

    invoke(
        &spl_memo::instruction::build(memo.as_bytes()),
        &[],
    )?;
    Ok(())
}

// If user content is needed, hash it
pub fn log_deposit_with_hash(ctx: Context<LogDeposit>, amount: u64) -> Result<()> {
    use solana_program::hash::hash;
    use anchor_lang::prelude::Pubkey;

    let data_to_sign = ctx.accounts.user.key().to_string();
    let h = hash(data_to_sign.as_bytes());

    // Include hash in memo (verifiable off-chain)
    let memo = format!("DEP:{}:{}", amount, &h.to_string()[..8]);
    invoke(
        &spl_memo::instruction::build(memo.as_bytes()),
        &[],
    )?;
    Ok(())
}""",
            explanation="Memo program writes arbitrary bytes to logs. "
                        "Never include user-supplied content verbatim in memos. "
                        "Use program-controlled messages or hash user data.",
        )

    # -------------------------------------------------------------------------
    # Rule 24: remaining_accounts Count Mismatch
    # -------------------------------------------------------------------------
    if rule_id == "Rule 24":
        return FixTemplate(
            before="""// UNSAFE: No count validation in invoke_signed
pub fn inner_call(ctx: Context<InnerCall>, data: Vec<u8>) -> Result<()> {
    let remaining = ctx.remaining_accounts();

    // MISSING: Count validation
    let inner_accounts: Vec<AccountMeta> = remaining
        .iter()
        .map(|acc| AccountMeta::new(acc.key(), acc.is_signer))
        .collect();

    invoke_signed(
        &Instruction {
            program_id: ctx.accounts.target.key(),
            accounts: inner_accounts,
            data: data.clone(),
        },
        &remaining.to_account_infos(),
        &[&[b"vault", &[ctx.bumps.vault]]],
    )?;
    Ok(())
}""",
            after="""// SECURE: Validate remaining_accounts before use
const EXPECTED_ACCOUNTS: usize = 3;

pub fn inner_call(ctx: Context<InnerCall>, data: Vec<u8>) -> Result<()> {
    let remaining = ctx.remaining_accounts();

    // VALIDATE: Count
    require!(
        remaining.len() == EXPECTED_ACCOUNTS,
        InnerError::InvalidAccountCount
    );

    // VALIDATE: Signer requirement
    require!(
        remaining[0].is_signer,
        InnerError::ExpectedSigner
    );

    // VALIDATE: Owner
    require!(
        remaining[0].owner == &spl_token::ID,
        InnerError::InvalidOwner
    );

    // VALIDATE: Key if position-dependent
    require!(
        remaining[2].key() == ctx.accounts.expected.key(),
        InnerError::AccountMismatch
    );

    let inner_accounts: Vec<AccountMeta> = remaining
        .iter()
        .map(|acc| AccountMeta::new(acc.key(), acc.is_signer))
        .collect();

    invoke_signed(
        &Instruction {
            program_id: ctx.accounts.target.key(),
            accounts: inner_accounts,
            data: data.clone(),
        },
        &remaining.to_account_infos(),
        &[&[b"vault", &[ctx.bumps.vault]]],
    )?;
    Ok(())
}""",
            explanation="remaining_accounts count mismatches can cause wrong accounts "
                        "to be signed or validated. Always validate length, signer flags, "
                        "owner, and position-dependent keys before using remaining_accounts.",
        )

    # -------------------------------------------------------------------------
    # Rule 25: Versioned Transaction LUT Manipulation
    # -------------------------------------------------------------------------
    if rule_id == "Rule 25":
        return FixTemplate(
            before="""// UNSAFE: Trusts LUT address without validation
pub fn withdraw_vlut(ctx: Context<WithdrawVlut>, amount: u64) -> Result<()> {
    let user = ctx.accounts.user.clone();  // From LUT

    // NO validation - could be attacker's account at same address
    require!(
        user.amount >= amount,
        VlutError::InsufficientFunds
    );
    // ...
}""",
            after="""// SECURE: Validate every LUT-loaded account
pub fn withdraw_vlut(ctx: Context<WithdrawVlut>, amount: u64) -> Result<()> {
    let user_info = ctx.accounts.user.to_account_info();
    let user_data = user_info.try_borrow_data()?;

    // VALIDATE: Owner
    require!(
        user_info.owner == ctx.program_id,
        VlutError::InvalidOwner
    );

    // VALIDATE: Discriminator
    let account = UserAccount::try_from_slice(&user_data)
        .map_err(|_| VlutError::DeserializationError)?;

    // VALIDATE: State
    require!(
        account.amount >= amount,
        VlutError::InsufficientFunds
    );
    require!(
        account.status == AccountStatus::Active,
        VlutError::AccountInactive
    );
    Ok(())
}""",
            explanation="LUT-loaded accounts can be substituted with malicious accounts "
                        "at the same address. Always validate owner, discriminator, "
                        "and state of LUT-sourced accounts.",
        )

    # -------------------------------------------------------------------------
    # Rule 26: Cross-Program Flash Loan Composition
    # -------------------------------------------------------------------------
    if rule_id == "Rule 26":
        return FixTemplate(
            before="""// UNSAFE: Multi-program CPI without oracle protection
pub fn multi_hop(ctx: Context<MultiHop>, amount: u64) -> Result<()> {
    // Flash loan from Program A
    program_a::flash_loan(ctx.accounts.flash_ctx(), amount)?;

    // Program B reads price - can be manipulated by Program A
    let price = ctx.accounts.price_oracle.price;

    // Borrow against manipulated price
    program_b::borrow(ctx.accounts.borrow_ctx(), amount, price)?;
    Ok(())
}""",
            after="""// SECURE: Sequential execution with commit-reveal or external validation
pub fn borrow_with_commit(
    ctx: Context<BorrowCommit>,
    amount: u64,
    price_merkle_proof: Vec<u8>,
    price_slot: u64,
) -> Result<()> {
    let clock = Clock::get()?;
    let slot_age = clock.slot.saturating_sub(price_slot);

    // VALIDATE: Price from prior slot (not manipulable in same tx)
    require!(
        slot_age >= MIN_SLOT_SEPARATION,
        OracleError::PriceTooRecent
    );

    // VALIDATE: Merkle proof commits to price from prior slot
    verify_price_commitment(
        &ctx.accounts.price_oracle,
        &ctx.accounts.merkle_root,
        price_slot,
        &price_merkle_proof,
    )?;

    // NOW safe to use price
    let price = ctx.accounts.price_oracle.price;
    let collateral_needed = amount
        .checked_mul(price)
        .ok_or(VaultError::ArithmeticOverflow)?
        .checked_div(LAMPORTS_PER_SOL)
        .ok_or(VaultError::ArithmeticOverflow)?;

    require!(
        ctx.accounts.collateral.amount >= collateral_needed,
        VaultError::InsufficientCollateral
    );
    Ok(())
}""",
            explanation="Flash loans spanning multiple programs enable oracle "
                        "manipulation across program boundaries. Use commit-reveal "
                        "patterns, external validation, or slot-separated price "
                        "feeds that cannot be manipulated within a single transaction.",
        )

    # Fallback for unknown or non-matched rules
    return FixTemplate(
        before="// Review this code for security issues",
        after="// Apply security fixes based on rule requirements",
        explanation=f"Fix for {rule_id}. Refer to rules/audit.rules for detailed guidance.",
    )
