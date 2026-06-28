//! Staking Pool Program — simplified Marinade/Jito-style staking pool.
//!
//! DO NOT DEPLOY. This is a documentation fixture for the
//! solana-auditor-skill skill. Each `// VULN-XX:` tag marks a bug that
//! a rule in `rules/audit.rules` is designed to catch. See
//! `audit-output/findings.json` for the expected findings when this
//! program is run through `/audit`.

use anchor_lang::prelude::*;

declare_id!("StkPv8XCvFhMtNTSg9qV9u1KKrn3DLzNaX7cSC8K8Ha");

#[program]
pub mod staking {
    use super::*;

    // ------------------------------------------------------------------------
    // VULN-01: Reentrancy on claim rewards — Rule 14 (CEI pattern violation)
    // ------------------------------------------------------------------------
    // claim() sends SOL to user BEFORE updating state. An attacker re-enters
    // the program during the external call to claim again for a double-claim.
    pub fn claim(ctx: Context<Claim>, amount: u64) -> Result<()> {
        // VULN-01: External call happens BEFORE state update.
        // No reentrancy guard (no flag set before external call).
        **ctx.accounts.user.to_account_info().try_borrow_mut_lamports()? += amount;
        **ctx.accounts.pool.to_account_info().try_borrow_mut_lamports()? -= amount;
        // State update happens TOO LATE — attacker can re-enter during the
        // lamport transfer above and claim again before this line executes.
        ctx.accounts.user_position.claimed_rewards += amount;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // VULN-02: init_if_needed race condition — Rule 22
    // ------------------------------------------------------------------------
    // Stake position created with init_if_needed but no one-time bump
    // enforcement. The position can be re-initialized by an attacker who
    // controls the PDA address.
    pub fn stake(ctx: Context<Stake>, amount: u64, bump: u8) -> Result<()> {
        // VULN-02: init_if_needed creates the account if missing, but there is
        // no bump constraint or unique discriminator. Attacker who controls
        // the PDA seed can call stake() multiple times to reset virtual_stake.
        ctx.accounts.position.virtual_stake = amount;
        // Bump is passed in but never verified against ctx.bumps.position.
        // No one-time-use guard — the same instruction can be called repeatedly.
        Ok(())
    }

    // ------------------------------------------------------------------------
    // VULN-03: Lamport griefing via unfunded PDA — Rule 41
    // ------------------------------------------------------------------------
    // Attacker creates unfunded PDAs to prevent legitimate account initialization.
    // If the program relies on finding a fresh PDA for a new user/position,
    // an attacker can pre-compute and occupy those PDAs at zero cost.
    pub fn register_validator(ctx: Context<Register>, name: String) -> Result<()> {
        // VULN-03: No rent-exempt check. The validator account is a PDA derived
        // from seeds but is not verified to be funded to rent-exemption before
        // being written to. An attacker can create many unfunded PDA accounts
        // that block legitimate registrations.
        ctx.accounts.validator.name = name;
        // Attacker can DoS the registry by creating unfunded validator PDAs.
        Ok(())
    }

    // ------------------------------------------------------------------------
    // VULN-04: Arithmetic overflow in reward calculation — Rule 6
    // ------------------------------------------------------------------------
    pub fn compute_rewards(
        ctx: Context<Compute>,
        staked_amount: u64,
        slots_elapsed: u64,
    ) -> Result<u64> {
        let rate_per_slot = 1_000_000_000u64 / 100_000_000u64; // ~10 lamports/slot
        // VULN-04: `staked_amount + (rate_per_slot * slots_elapsed)` uses
        // unchecked arithmetic. If slots_elapsed is large enough, the
        // multiplication overflows u64 in release mode (wraps silently).
        let total = staked_amount + (rate_per_slot * slots_elapsed);
        ctx.accounts.state.pending_rewards = total;
        Ok(total)
    }

    // ------------------------------------------------------------------------
    // VULN-05: Missing signer on admin operations — Rule 8
    // ------------------------------------------------------------------------
    pub fn update_reward_rate(ctx: Context<UpdateRate>, new_rate: u64) -> Result<()> {
        // VULN-05: No Signer constraint on admin field. The admin account is
        // declared as AccountInfo instead of Signer. Any caller can update
        // the pool's reward rate to any value, including 0 (denial of service)
        // or an enormous value (inflation attack).
        ctx.accounts.pool.reward_rate = new_rate;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // VULN-06: Reinit attack on stake position — Rule 11
    // ------------------------------------------------------------------------
    pub fn reinit_position(ctx: Context<Reinit>) -> Result<()> {
        // VULN-06: The position account is not protected by an Anchor
        // discriminator. If the account is closed and its lamports refunded,
        // it can be re-initialized to zero out virtual_stake and
        // claimed_rewards, draining the user's staked position.
        ctx.accounts.position.virtual_stake = 0;
        ctx.accounts.position.claimed_rewards = 0;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // VULN-07: Token transfer without amount validation — Rule 5
    // ------------------------------------------------------------------------
    pub fn mint_shares(ctx: Context<MintShares>, amount: u64) -> Result<()> {
        // VULN-07: No minimum amount check. Dust amounts (1 lamport) can be
        // minted to many accounts, bloating state and wasting rent-exemption
        // storage. Also no maximum to cap inflation.
        ctx.accounts.user_shares.mint_amount += amount;
        Ok(())
    }
}

// ------------------------------------------------------------------------
// Account structs
// ------------------------------------------------------------------------

#[account]
pub struct Pool {
    pub authority: Pubkey,
    pub reward_rate: u64,
    pub total_staked: u64,
    pub bump: u8,
}

#[account]
pub struct Position {
    pub owner: Pubkey,
    pub virtual_stake: u64,
    pub claimed_rewards: u64,
    pub bump: u8,
}

#[account]
pub struct Validator {
    pub name: String,
    pub total_delegated: u64,
    pub score: u64,
}

#[account]
pub struct State {
    pub pending_rewards: u64,
    pub last_update_slot: u64,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub user_position: Account<'info, Position>,
    #[account(mut)]
    pub user: Signer<'info>,
    /// CHECK: VULN-01 — lamports transferred without reentrancy guard.
    pub user_wallet: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Stake<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    #[account(
        init_if_needed,
        payer = user,
        space = 8 + Position::INIT_SPACE,
        seeds = [b"position", user.key().as_ref()],
        bump
    )]
    pub position: Account<'info, Position>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Register<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + 32 + 4 + 64 + 8 + 8, // discriminator + owner + name + delegated + score
        seeds = [b"validator", name.as_bytes()],
        bump
    )]
    pub validator: Account<'info, Validator>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
    /// CHECK: VULN-03 — no rent-exempt check; PDA can be created without funding.
    pub name: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Compute<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
}

#[derive(Accounts)]
pub struct UpdateRate<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    /// CHECK: VULN-05 — should be Signer but is unverified AccountInfo.
    pub admin: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Reinit<'info> {
    #[account(mut)]
    pub position: Account<'info, Position>,
}

#[derive(Accounts)]
pub struct MintShares<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub user_shares: Account<'info, Position>,
    #[account(mut)]
    pub user: Signer<'info>,
}

impl Position {
    pub const INIT_SPACE: usize = 32 + 8 + 8 + 1; // owner + virtual_stake + claimed_rewards + bump
}

impl State {
    pub const INIT_SPACE: usize = 8 + 8; // pending_rewards + last_update_slot
}