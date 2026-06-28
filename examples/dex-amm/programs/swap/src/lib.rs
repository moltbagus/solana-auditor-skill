//! Simplified swap program with intentional vulnerabilities.
//!
//! DO NOT DEPLOY. This is a documentation fixture for the
//! solana-auditor-skill skill. Each `// VULN-XX:` tag marks a bug that
//! a rule in `rules/audit.rules` is designed to catch. See
//! `audit-output/findings.json` for the expected findings when this
//! program is run through `/audit`.
//!
//! VULN-08: init without discriminator check (manual init vulnerability)
//! VULN-09: reentrancy via token callback
//! VULN-10: duplicate mutable account passed twice
//! VULN-11: arithmetic underflow in fee calculation

use anchor_lang::prelude::*;

declare_id!("SWAPpool9m2Xy3Ko4BpQ6rHzdLmN5StF8aGpLmN6PtQa");

// ============================================================================
// Account Structures
// ============================================================================

#[account]
#[derive(Default)]
pub struct SwapPool {
    pub virtual_balance: u64,
    pub fee: u64,  // basis points
    pub authority: Pubkey,
    pub bump: u8,
}

#[account]
#[derive(Default)]
pub struct SwapState {
    pub gross_amount: u64,
    pub net_amount: u64,
}

// ============================================================================
// Swap Program
// ============================================================================

#[program]
pub mod swap {
    use super::*;

    // VULN-08: init without discriminator check — Rule 40 (manual init vulnerability)
    // Pool initialized without Anchor's #[account] discriminator
    pub fn init_pool(ctx: Context<InitPool>) -> Result<()> {
        // VULN-08: manual field assignment without discriminator check
        // Should use #[account(init)] or verify 8-byte discriminator
        ctx.accounts.pool.virtual_balance = 0;
        ctx.accounts.pool.fee = 30; // basis points
        ctx.accounts.pool.authority = ctx.accounts.authority.key();
        ctx.accounts.pool.bump = ctx.bumps.pool;

        msg!("swap pool initialized manually (no discriminator check)");
        Ok(())
    }

    // VULN-09: reentrancy via token callback — Rule 14
    pub fn transfer_with_callback(ctx: Context<Transfer>) -> Result<()> {
        let seeds = &[b"swap".as_ref()];
        let signer = [&seeds[..]];

        // VULN-09: no reentrancy guard; callback could re-enter
        // Transfer executes — attacker can have callback re-enter during this
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.from.to_account_info(),
                    to: ctx.accounts.to.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
                &signer,
            ),
            ctx.accounts.amount,
        )?;

        // State updated after transfer — reentrancy window existed
        msg!("transferred {} with callback", ctx.accounts.amount);
        Ok(())
    }

    // VULN-10: duplicate mutable account passed twice — Rule 38
    pub fn double_transfer(ctx: Context<Double>, amount: u64) -> Result<()> {
        // VULN-10: same account appears twice in accounts; double-spend possible
        // Both ctx.accounts.token_a and ctx.accounts.token_b point to same account
        let seeds = &[b"swap".as_ref()];
        let signer = [&seeds[..]];

        // First transfer debits the account
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.token_a.to_account_info(),
                    to: ctx.accounts.recipient.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                &signer,
            ),
            amount,
        )?;

        // VULN-10: second transfer may succeed on the same account due to
        // duplicate account passed in instruction — double-spend vulnerability
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.token_b.to_account_info(),
                    to: ctx.accounts.recipient.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                &signer,
            ),
            amount,
        )?;

        msg!("double transfer executed: {} twice", amount);
        Ok(())
    }

    // VULN-11: arithmetic underflow in fee calculation — Rule 6
    pub fn calc_net_amount(ctx: Context<Calc>, gross: u64, fee_bps: u64) -> Result<()> {
        // VULN-11: fee_bps could exceed 10000, making fee > gross
        // Then gross - fee underflows on u64
        let fee = gross * fee_bps / 10000;
        // VULN-11: no checked_sub — underflow wraps silently
        let net = gross - fee;

        ctx.accounts.state.net_amount = net;
        msg!("gross: {}, fee: {}, net: {}", gross, fee, net);
        Ok(())
    }
}

// ============================================================================
// Account Structs
// ============================================================================

#[derive(Accounts)]
pub struct InitPool<'info> {
    #[account(mut)]
    pub pool: Account<'info, SwapPool>,
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub swap_pool: Account<'info, SwapPool>,
    /// CHECK: VULN-09 — no reentrancy guard on from/to/authority
    pub from: AccountInfo<'info>,
    /// CHECK: VULN-09
    pub to: AccountInfo<'info>,
    /// CHECK: VULN-09
    pub authority: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
    pub amount: u64,
}

#[derive(Accounts)]
pub struct Double<'info> {
    #[account(mut)]
    pub swap_pool: Account<'info, SwapPool>,
    /// CHECK: VULN-10 — token_a and token_b may be same account (duplicate)
    pub token_a: AccountInfo<'info>,
    /// CHECK: VULN-10 — may duplicate token_a
    pub token_b: AccountInfo<'info>,
    /// CHECK: VULN-10
    pub vault: AccountInfo<'info>,
    /// CHECK: VULN-10
    pub recipient: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Calc<'info> {
    #[account(mut)]
    pub state: Account<'info, SwapState>,
}

// ============================================================================
// Error Enum
// ============================================================================

#[error_code]
pub enum SwapError {
    #[msg("Insufficient balance")]
    InsufficientBalance,
    #[msg("Invalid fee basis points")]
    InvalidFeeBps,
    #[msg("Transfer failed")]
    TransferFailed,
    #[msg("Arithmetic error")]
    ArithmeticError,
}
