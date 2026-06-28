//! Delegation Program — validator stake delegation with PDA and sysvar vulnerabilities.
//!
//! DO NOT DEPLOY. This is a documentation fixture for the
//! solana-auditor-skill skill. Each `// VULN-XX:` tag marks a bug that
//! a rule in `rules/audit.rules` is designed to catch.

use anchor_lang::prelude::*;

declare_id!("DgtPv8XCvFhMtNTSg9qV9u1KKrn3DLzNaX7cSC8K8Hc");

#[program]
pub mod delegation {
    use super::*;

    // ------------------------------------------------------------------------
    // VULN-12: Hardcoded bump in PDA derivation — Rule 3
    // ------------------------------------------------------------------------
    pub fn create_validator_stake(
        ctx: Context<CreateStake>,
        bump: u8,
    ) -> Result<()> {
        // VULN-12: The bump is passed as a parameter and stored directly
        // without verification against ctx.bumps.stake_account. If the
        // stored bump is not canonical, an attacker can find a colliding
        // bump and derive the same PDA address, enabling unauthorized mutations.
        ctx.accounts.stake_account.voter = ctx.accounts.validator.key();
        ctx.accounts.stake_account.bump = bump; // <-- not verified
        Ok(())
    }

    // ------------------------------------------------------------------------
    // VULN-13: Sysvar spoofing via account data — Rule 36
    // ------------------------------------------------------------------------
    pub fn record_vote(ctx: Context<RecordVote>, slot: u64) -> Result<()> {
        let clock = Clock::get()?;
        // VULN-13: The slot is taken from instruction data, not from the
        // verified clock sysvar. An attacker can pass a future slot to
        // make the vote appear fresh. The check `slot > clock.slot + 100`
        // is a weak gate — a slightly-future slot still bypasses it.
        // Additionally, the clock sysvar itself could be spoofed if not
        // properly validated via #[account(address = clock::id())].
        if slot > clock.slot + 100 {
            return err!(DelegationError::StaleVote);
        }
        ctx.accounts.vote_record.slot = slot;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // VULN-14: Missing writable enforcement — Rule 37
    // ------------------------------------------------------------------------
    pub fn deactivate_stake(ctx: Context<Deactivate>) -> Result<()> {
        // VULN-14: The stake_account is not marked as mutable in the
        // Accounts struct, yet the code mutates it. In Anchor, accounts
        // not marked #[account(mut)] cannot be written to. This will
        // cause a runtime error, but the bug is that the constraint is
        // missing — a developer might add it later without realizing
        // the mutation is intentional, or the missing mut could be
        // exploited if the constraint system is bypassed.
        ctx.accounts.stake_account.status = 1; // 1 = deactivating
        Ok(())
    }
}

// ------------------------------------------------------------------------
// Account structs
// ------------------------------------------------------------------------

#[account]
pub struct StakeAccount {
    pub voter: Pubkey,
    pub validator: Pubkey,
    pub amount: u64,
    pub status: u8, // 0=active, 1=deactivating, 2=withdrawn
    pub bump: u8,
}

#[account]
pub struct VoteRecord {
    pub slot: u64,
    pub validator: Pubkey,
    pub timestamp: i64,
}

#[derive(Accounts)]
pub struct CreateStake<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + 32 + 32 + 8 + 1 + 1,
        seeds = [b"stake", validator.key().as_ref()],
        bump
    )]
    pub stake_account: Account<'info, StakeAccount>,
    /// CHECK: validator identity.
    pub validator: AccountInfo<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RecordVote<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + 8 + 32 + 8,
        seeds = [b"vote", validator.key().as_ref(), &slot.to_le_bytes()],
        bump
    )]
    pub vote_record: Account<'info, VoteRecord>,
    /// CHECK: validator identity.
    pub validator: AccountInfo<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
    /// CHECK: VULN-13 — clock sysvar could be spoofed; slot from instruction
    /// data is used instead of clock.slot.
    pub clock: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Deactivate<'info> {
    // VULN-14: stake_account is NOT marked #[account(mut)] but is mutated.
    // This is a constraint mismatch — the code will fail at runtime but
    // the missing mut constraint is the vulnerability.
    pub stake_account: Account<'info, StakeAccount>,
}

#[error_code]
pub enum DelegationError {
    #[msg("Vote slot is stale")]
    StaleVote,
    #[msg("Invalid stake status")]
    InvalidStatus,
}