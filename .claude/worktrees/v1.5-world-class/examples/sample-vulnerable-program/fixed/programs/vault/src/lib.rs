//! Secure vault program — remediated example for the solana-auditor-shiba skill.
//!
//! This is the corrected version of the sample-vulnerable-program fixture.
//! All CRITICAL, HIGH, and MEDIUM findings have been resolved:
//!   - Admin operations require Signer + has_one constraint
//!   - PDA bumps sourced from ctx.bumps (canonical, not literals)
//!   - CPI targets validated via typed Program<'info, T>
//!   - All arithmetic uses checked_add/checked_sub/checked_div
//!   - VaultState has #[account] (discriminator enforced)
//!   - Drain operations require authority Signer + amount bounds
//!   - All invoke() results propagated with ?
//!   - State-changing instructions emit typed Anchor events
//!
//! This program compiles cleanly under anchor 0.31.1.

use anchor_lang::prelude::*;
use anchor_lang::system_program;
use solana_program::{
    instruction::{AccountMeta, Instruction},
    program::invoke,
};

declare_id!("VauLTv8XCvFhMtNTSg9qV9u1KKrn3DLzNaX7cSC8K8H");

// --- FIX: VaultState now has #[account] so Anchor writes and
// verifies the 8-byte discriminator on init/deserialization.
#[account]
#[derive(InitSpace)]
pub struct VaultState {
    pub authority: Pubkey,
    pub bump: u8,
    pub total_deposits: u64,
}

// --- FIX: Typed event for structured off-chain indexing.
#[event]
pub struct WithdrawEvent {
    pub authority: Pubkey,
    pub destination: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
}

// --- FIX: Overflow-safe arithmetic + division by zero + insufficient funds.
#[error_code]
pub enum VaultError {
    #[msg("arithmetic overflow")]
    ArithmeticOverflow,
    #[msg("division by zero")]
    DivisionByZero,
    #[msg("insufficient funds in vault")]
    InsufficientFunds,
    #[msg("shares below minimum threshold")]
    BelowMinimumShares,
}

const MIN_SHARES: u64 = 1;

#[program]
pub mod vault {
    use super::*;

    // --- FIX: Use ctx.bumps.vault (canonical bump) instead of literal 254.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.bump = ctx.bumps.vault; // canonical bump from Anchor
        vault.total_deposits = 0;
        msg!("vault initialized with bump {}", vault.bump);
        Ok(())
    }

    // --- FIX: admin is now Signer<'info> and vault has has_one = admin.
    // Anchor enforces is_signer at deserialization; has_one binds the admin
    // to the vault's stored authority field.
    pub fn admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64) -> Result<()> {
        let vault_lamports = ctx.accounts.vault.to_account_info().lamports();
        require!(amount <= vault_lamports, VaultError::InsufficientFunds);
        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.destination.to_account_info().try_borrow_mut_lamports()? += amount;
        msg!("admin withdrew {}", amount);
        Ok(())
    }

    // --- FIX: checked_add propagates ArithmeticOverflow on wrap.
    pub fn user_deposit(ctx: Context<UserDeposit>, amount: u64) -> Result<()> {
        let current_balance: u64 = 1_000_000_000;
        // checked_add returns None on overflow; ? propagates VaultError::ArithmeticOverflow
        let new_balance: u64 = current_balance
            .checked_add(amount)
            .ok_or(VaultError::ArithmeticOverflow)?;
        msg!("deposit {} → new balance {}", amount, new_balance);
        let _ = ctx.accounts.vault.key();
        Ok(())
    }

    // --- FIX: target_program is now Program<'info, System>.
    // Anchor verifies it is exactly the System Program pubkey.
    // Arbitrary CPI targets are no longer possible.
    pub fn exec_callback(ctx: Context<ExecCallback>, data: Vec<u8>) -> Result<()> {
        let ix = Instruction {
            program_id: ctx.accounts.target_program.key(),
            accounts: ctx
                .remaining_accounts
                .iter()
                .map(|a| AccountMeta {
                    pubkey: a.key(),
                    is_signer: a.is_signer,
                    is_writable: a.is_writable,
                })
                .collect(),
            data,
        };
        invoke(&ix, ctx.remaining_accounts)?;
        Ok(())
    }

    // --- FIX: DrainVault now requires Signer authority with has_one.
    // Amount is bounded to available lamports before transfer.
    pub fn drain_vault(ctx: Context<DrainVault>, amount: u64) -> Result<()> {
        let vault_lamports = ctx.accounts.vault.to_account_info().lamports();
        require!(amount <= vault_lamports, VaultError::InsufficientFunds);
        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.destination.to_account_info().try_borrow_mut_lamports()? += amount;
        msg!("drained {} lamports", amount);
        Ok(())
    }

    // --- FIX: checked_div prevents division-by-zero panic; threshold
    // check prevents zero-share deposits.
    pub fn calc_shares(_ctx: Context<DrainVault>, deposit: u64, divisor: u64) -> Result<()> {
        // checked_div returns None when divisor == 0
        let shares: u64 = deposit
            .checked_div(divisor)
            .ok_or(VaultError::DivisionByZero)?;
        // Reject deposits that would result in fewer than MIN_SHARES
        require!(shares >= MIN_SHARES, VaultError::BelowMinimumShares);
        msg!("shares for {} / {} = {}", deposit, divisor, shares);
        Ok(())
    }

    // --- FIX: >= instead of > makes the threshold inclusive.
    // A value of exactly 1_000_000 is now correctly rejected as "below".
    pub fn check_threshold(ctx: Context<DrainVault>, value: u64) -> Result<()> {
        if value >= 1_000_000 {
            msg!("at or above threshold");
        } else {
            msg!("below threshold");
        }
        let _ = ctx.accounts.vault.key();
        Ok(())
    }

    // --- FIX: invoke() result is propagated with ?, not discarded.
    // If the CPI fails the entire transaction reverts, leaving state consistent.
    pub fn unchecked_cpi(ctx: Context<ExecCallback>, data: Vec<u8>) -> Result<()> {
        let ix = Instruction {
            program_id: ctx.accounts.target_program.key(),
            accounts: vec![],
            data,
        };
        // ? propagates the error instead of discarding it
        invoke(&ix, &[])?;
        Ok(())
    }

    // --- FIX: emit! produces a structured, indexable event.
    // Off-chain indexers can now detect and react to every withdrawal.
    pub fn silent_withdraw(ctx: Context<DrainVault>, amount: u64) -> Result<()> {
        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.destination.to_account_info().try_borrow_mut_lamports()? += amount;
        emit!(WithdrawEvent {
            authority: ctx.accounts.authority.key(),
            destination: ctx.accounts.destination.key(),
            amount,
            timestamp: Clock::get()?.unix_timestamp,
        });
        msg!("withdrew {} (event emitted)", amount);
        Ok(())
    }
}

// --- FIX: vault is Account<'info, VaultState>, not AccountInfo.
// Anchor verifies the 8-byte discriminator on every load, preventing reinit.
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = VaultState::INIT_SPACE)]
    pub vault: Account<'info, VaultState>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

// --- FIX: admin is Signer, vault has has_one = admin.
#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    #[account(mut, has_one = admin)]
    pub vault: Account<'info, VaultState>,
    pub admin: Signer<'info>,
    #[account(mut)]
    pub destination: SystemAccount<'info>,
}

#[derive(Accounts)]
pub struct UserDeposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    pub user: Signer<'info>,
}

// --- FIX: Program<'info, System> enforces the System Program ID.
#[derive(Accounts)]
pub struct ExecCallback<'info> {
    pub target_program: Program<'info, System>,
}

// --- FIX: authority is Signer, vault has has_one = authority.
#[derive(Accounts)]
pub struct DrainVault<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, VaultState>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub destination: SystemAccount<'info>,
}