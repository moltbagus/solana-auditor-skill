//! Simplified price oracle program with intentional vulnerabilities.
//!
//! DO NOT DEPLOY. This is a documentation fixture for the
//! solana-auditor-skill skill. Each `// VULN-XX:` tag marks a bug that
//! a rule in `rules/audit.rules` is designed to catch. See
//! `audit-output/findings.json` for the expected findings when this
//! program is run through `/audit`.
//!
//! VULN-12: sysvar spoofing
//! VULN-13: unsafe deserialization without owner check
//! VULN-14: missing writable enforcement

use anchor_lang::prelude::*;

declare_id!("ORAcle7v8N9m2Xy3Ko4BpQ6rHzdLmN5StF8aGpLmN6PtQb");

// ============================================================================
// Account Structures
// ============================================================================

#[account]
#[derive(Default)]
pub struct PriceFeed {
    pub value: u64,
    pub last_update: u64,
    pub authority: Pubkey,
    pub bump: u8,
}

#[account]
#[derive(Default)]
pub struct OracleData {
    pub data: Vec<u8>,
    pub owner: Pubkey,
}

// ============================================================================
// Oracle Program
// ============================================================================

#[program]
pub mod oracle {
    use super::*;

    // VULN-12: sysvar spoofing — Rule 36
    pub fn set_price(ctx: Context<SetPrice>, price: u64, slot: u64) -> Result<()> {
        // VULN-12: slot from instruction data, not from Clock sysvar
        // Attacker can set arbitrary slot to bypass staleness checks elsewhere
        ctx.accounts.price_feed.value = price;
        ctx.accounts.price_feed.last_update = slot; // attacker-controlled slot

        // Missing: should read Clock::get() and verify slot from sysvar
        // let clock = Clock::get()?;
        // ctx.accounts.price_feed.last_update = clock.slot;

        msg!("price set to {} at slot {}", price, slot);
        Ok(())
    }

    // VULN-13: unsafe deserialization without owner check — Rule 39
    pub fn read_data(ctx: Context<ReadData>, offset: u32) -> Result<Vec<u8>> {
        let data = ctx.accounts.data_account.try_borrow_data()?;

        // VULN-13: no owner check; can read arbitrary account data
        // Should verify data_account.owner == expected_program_id
        let slice = data
            .get(offset as usize..)
            .ok_or(OracleError::OutOfBounds)?;

        msg!("read {} bytes from offset {}", slice.len(), offset);
        Ok(slice.to_vec())
    }

    // VULN-14: missing writable enforcement — Rule 37
    pub fn update_oracle(ctx: Context<UpdateOracle>, new_price: u64) -> Result<()> {
        // VULN-14: account not marked writable in constraints but mutated
        // Anchor will not catch this at compile time; runtime write will fail
        // but error message may be confusing
        ctx.accounts.price_feed.value = new_price;

        msg!("oracle updated to {}", new_price);
        Ok(())
    }
}

// ============================================================================
// Account Structs
// ============================================================================

#[derive(Accounts)]
pub struct SetPrice<'info> {
    #[account(mut)]
    pub price_feed: Account<'info, PriceFeed>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ReadData<'info> {
    /// CHECK: VULN-13 — no owner check on this account
    pub data_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct UpdateOracle<'info> {
    #[account(mut)]
    pub price_feed: Account<'info, PriceFeed>,
    pub updater: Signer<'info>,
}

// ============================================================================
// Error Enum
// ============================================================================

#[error_code]
pub enum OracleError {
    #[msg("Out of bounds read")]
    OutOfBounds,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Stale price")]
    StalePrice,
    #[msg("Invalid owner")]
    InvalidOwner,
}
