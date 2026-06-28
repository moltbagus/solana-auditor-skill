//! Simplified AMM pool program with intentional vulnerabilities.
//!
//! DO NOT DEPLOY. This is a documentation fixture for the
//! solana-auditor-skill skill. Each `// VULN-XX:` tag marks a bug that
//! a rule in `rules/audit.rules` is designed to catch. See
//! `audit-output/findings.json` for the expected findings when this
//! program is run through `/audit`.
//!
//! VULN-01: Reentrancy on withdraw (CEI pattern violation)
//! VULN-02: remaining_accounts not validated in swap CPI
//! VULN-03: Flash loan composition (cross-program flash loan)
//! VULN-04: Price oracle manipulation via stale data
//! VULN-05: Arithmetic overflow in liquidity calculation
//! VULN-06: Arbitrary CPI via callback
//! VULN-07: Missing signer on pool admin

use anchor_lang::prelude::*;
use solana_program::{
    instruction::{AccountMeta, Instruction},
    program::invoke,
};

declare_id!("AMMpool7v8N9m2Xy3Ko4BpQ6rHzdLmN5StF8aGpLmN6PtQ");

// ============================================================================
// Account Structures
// ============================================================================

#[account]
#[derive(Default)]
pub struct AmmPool {
    pub virtual_balance: u64,
    pub total_liquidity: u64,
    pub fee: u64,  // basis points
    pub authority: Pubkey,
    pub bump: u8,
}

#[account]
#[derive(Default)]
pub struct PriceFeed {
    pub value: u64,
    pub last_update: u64,
    pub authority: Pubkey,
}

#[account]
#[derive(Default)]
pub struct PoolState {
    pub balance: u64,
    pub locked: u64,
}

// ============================================================================
// AMM Program
// ============================================================================

#[program]
pub mod amm {
    use super::*;

    // VULN-01: Reentrancy on withdraw — Rule 14 (CEI pattern violation)
    // withdraw() transfers tokens BEFORE state update — attacker re-enters via callback
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // VULN-01: no reentrancy guard; state updated AFTER transfer
        // CEI pattern violated: Effects come before Interaction
        let seeds = &[b"pool".as_ref(), ctx.accounts.token_a.as_ref()];
        let signer = [&seeds[..]];

        // Transfer happens first — attacker can re-enter via callback
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx.accounts.recipient.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                &signer,
            ),
            amount,
        )?;

        // State updated too late — reentrancy window open during transfer
        ctx.accounts.pool.virtual_balance = ctx
            .accounts
            .pool
            .virtual_balance
            .saturating_sub(amount);

        msg!("withdrew {} from pool", amount);
        Ok(())
    }

    // VULN-02: remaining_accounts not validated in swap CPI — Rule 15
    // User passes extra accounts that get forwarded to token program without checks
    pub fn swap(ctx: Context<Swap>, amount_in: u64, min_amount_out: u64) -> Result<()> {
        // VULN-02: remaining_accounts forwarded directly to token program
        // No validation that these accounts are legitimate token accounts
        let swap_ix = Instruction {
            program_id: ctx.accounts.token_program.key(),
            accounts: ctx
                .remaining_accounts
                .iter()
                .map(|a| AccountMeta {
                    pubkey: a.key(),
                    is_signer: a.is_signer,
                    is_writable: a.is_writable,
                })
                .collect(),
            data: amount_in.to_le_bytes().to_vec(),
        };

        // VULN-02: all remaining_accounts forwarded blindly — injection possible
        invoke(&swap_ix, &ctx.remaining_accounts)?;

        msg!("swapped {} for at least {}", amount_in, min_amount_out);
        Ok(())
    }

    // VULN-03: Flash loan composition — Rule 26 (cross-program flash loan)
    // No flash loan protection; attacker borrows from another program and manipulates price
    pub fn execute_arbitrage(ctx: Context<Arbitrage>, amounts: Vec<u64>) -> Result<()> {
        // VULN-03: no flash loan detection; arbitrary amounts accepted
        // Attacker can supply amounts from a flash loan and manipulate pool state
        for amt in amounts {
            ctx.accounts.pool.balance = ctx
                .accounts
                .pool
                .balance
                .checked_add(amt)
                .unwrap();
        }

        // No check that amounts are from legitimate liquidity — could be flash-borrowed
        msg!(
            "executed arbitrage with {} steps, final balance: {}",
            amounts.len(),
            ctx.accounts.pool.balance
        );
        Ok(())
    }

    // VULN-04: Price oracle manipulation via stale data — Rule 13
    // Oracle price not checked for staleness; attacker manipulates before reading
    pub fn get_price(ctx: Context<OracleRead>) -> Result<u64> {
        // VULN-04: no staleness check on price_feed.last_update
        // Attacker can set stale price and read it before legitimate update
        let price = ctx.accounts.price_feed.value;

        // Missing: clock staleness check
        // Should verify: clock.slot - price_feed.last_update < MAX_STALENESS
        msg!("price: {} (no staleness verification)", price);
        Ok(price)
    }

    // VULN-05: Arithmetic overflow in liquidity calculation — Rule 6
    pub fn add_liquidity(ctx: Context<AddLiq>, amount_a: u64, amount_b: u64) -> Result<()> {
        // VULN-05: no checked_mul — overflow wraps silently in release mode
        let total = amount_a * amount_b;

        ctx.accounts.pool.total_liquidity = total;
        msg!(
            "added liquidity: {} * {} = {}",
            amount_a,
            amount_b,
            total
        );
        Ok(())
    }

    // VULN-06: Arbitrary CPI via callback — Rule 4
    pub fn exec_swap_callback(ctx: Context<Callback>, data: Vec<u8>) -> Result<()> {
        // VULN-06: user-supplied program invoked with user-supplied data
        // No allowlist check — attacker can invoke any program
        invoke(
            &Instruction {
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
                data: data.clone(),
            },
            &ctx.remaining_accounts,
        )?;

        msg!("executed callback to {:?}", ctx.accounts.target_program.key());
        Ok(())
    }

    // VULN-07: Missing signer on pool admin — Rule 8
    pub fn set_pool_fee(ctx: Context<SetFee>, new_fee: u64) -> Result<()> {
        // VULN-07: no signer check; anyone can call set_pool_fee
        // Should require: ctx.accounts.admin.is_signer or has_one constraint
        ctx.accounts.pool.fee = new_fee;
        msg!("pool fee updated to {} basis points", new_fee);
        Ok(())
    }
}

// ============================================================================
// Account Structs
// ============================================================================

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub pool: Account<'info, AmmPool>,
    #[account(mut)]
    pub vault: AccountInfo<'info>,
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    /// CHECK: VULN-01 — no signer verification, vault authority unchecked
    pub vault_authority: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
    pub token_a: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub pool: Account<'info, AmmPool>,
    /// CHECK: VULN-02 — remaining_accounts forwarded without validation
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Arbitrage<'info> {
    #[account(mut)]
    pub pool: Account<'info, PoolState>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct OracleRead<'info> {
    #[account(mut)]
    pub pool: Account<'info, AmmPool>,
    pub price_feed: Account<'info, PriceFeed>,
}

#[derive(Accounts)]
pub struct AddLiq<'info> {
    #[account(mut)]
    pub pool: Account<'info, AmmPool>,
    pub provider: Signer<'info>,
}

#[derive(Accounts)]
pub struct Callback<'info> {
    #[account(mut)]
    pub pool: Account<'info, AmmPool>,
    /// CHECK: VULN-06 — user-supplied program, no allowlist validation
    pub target_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct SetFee<'info> {
    #[account(mut)]
    pub pool: Account<'info, AmmPool>,
    /// CHECK: VULN-07 — should be Signer but is AccountInfo, no signer verification
    pub admin: AccountInfo<'info>,
}

// ============================================================================
// Error Enum
// ============================================================================

#[error_code]
pub enum AmmError {
    #[msg("Insufficient liquidity")]
    InsufficientLiquidity,
    #[msg("Slippage exceeded")]
    SlippageExceeded,
    #[msg("Invalid fee")]
    InvalidFee,
    #[msg("Overflow in calculation")]
    Overflow,
    #[msg("Price stale")]
    PriceStale,
}
