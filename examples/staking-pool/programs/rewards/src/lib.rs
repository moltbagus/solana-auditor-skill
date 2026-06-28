//! Rewards Distributor Program — simplified reward distribution with CPI vulnerabilities.
//!
//! DO NOT DEPLOY. This is a documentation fixture for the
//! solana-auditor-skill skill. Each `// VULN-XX:` tag marks a bug that
//! a rule in `rules/audit.rules` is designed to catch.

use anchor_lang::prelude::*;
use solana_program::{
    instruction::{AccountMeta, Instruction},
    program::invoke,
};

declare_id!("RwdPv8XCvFhMtNTSg9qV9u1KKrn3DLzNaX7cSC8K8Hb");

#[program]
pub mod rewards {
    use super::*;

    // ------------------------------------------------------------------------
    // VULN-08: remaining_accounts CPI injection — Rule 15
    // ------------------------------------------------------------------------
    pub fn distribute(ctx: Context<Distribute>, amounts: Vec<u64>) -> Result<()> {
        // VULN-08: remaining_accounts are forwarded to the system program
        // without validation. An attacker can craft a transaction where
        // remaining_accounts contains different accounts than expected,
        // injecting arbitrary transfers into the CPI call.
        let from = ctx.accounts.from.key();
        let to = ctx.accounts.to.key();
        let amount = amounts.get(0).copied().unwrap_or(0);

        invoke(
            &solana_program::system_instruction::transfer(&from, &to, amount),
            &ctx.remaining_accounts, // <-- attacker-controlled CPI accounts
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // VULN-09: Arbitrary CPI in callback — Rule 4
    // ------------------------------------------------------------------------
    pub fn exec_reward_callback(ctx: Context<RewardCallback>, data: Vec<u8>) -> Result<()> {
        // VULN-09: The callback instruction accepts arbitrary data and invokes
        // an arbitrary program with arbitrary accounts. This is a complete
        // arbitrary CPI gadget — attacker can call any program with any data
        // in the context of this program's signer privileges.
        invoke(
            &Instruction {
                program_id: ctx.accounts.target.key(),
                accounts: vec![AccountMeta::new(ctx.accounts.victim.key(), false)],
                data: data.clone(),
            },
            &ctx.remaining_accounts,
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // VULN-10: Unchecked arithmetic in compound calculation — Rule 6
    // ------------------------------------------------------------------------
    pub fn compound(
        ctx: Context<Compound>,
        principal: u64,
        rate_bps: u64,
        periods: u64,
    ) -> Result<u64> {
        let rate = rate_bps as u128;
        let periods_u128 = periods as u128;

        // VULN-10: The exponentiation (1 + rate / 10000)^periods can overflow
        // u128 before the final cast to u64. In release mode, wrapping occurs
        // silently. Even with checked arithmetic, the intermediate u128 can
        // overflow for large principal + high rate + many periods.
        let compounded = (principal as u128)
            * (1_u128 + rate / 10000).wrapping_pow(periods_u128 as u32);

        ctx.accounts.state.balance = compounded as u64;
        Ok(compounded as u64)
    }

    // ------------------------------------------------------------------------
    // VULN-11: Duplicate mutable account — Rule 38
    // ------------------------------------------------------------------------
    pub fn split_rewards(ctx: Context<Split>, amount: u64) -> Result<()> {
        // VULN-11: The same account (account_a) is passed as both the source
        // and implicitly as a destination. Anchor's ownership check will see
        // account_a twice in the mutable list — this is an ownership conflict.
        // The first borrow subtracts, the second borrow (same account) adds.
        // If account_a == account_b, the amount is effectively doubled credited.
        **ctx.accounts.account_a.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.account_a.try_borrow_mut_lamports()? += amount; // same account
        **ctx.accounts.account_b.try_borrow_mut_lamports()? += amount;
        Ok(())
    }
}

// ------------------------------------------------------------------------
// Account structs
// ------------------------------------------------------------------------

#[account]
pub struct RewardState {
    pub balance: u64,
    pub last_compound_slot: u64,
}

#[derive(Accounts)]
pub struct Distribute<'info> {
    #[account(mut)]
    pub from: AccountInfo<'info>,
    #[account(mut)]
    pub to: AccountInfo<'info>,
    /// CHECK: VULN-08 — remaining_accounts forwarded without validation.
    pub remaining_accounts: Vec<AccountInfo<'info>>,
}

#[derive(Accounts)]
pub struct RewardCallback<'info> {
    /// CHECK: VULN-09 — arbitrary program invoked.
    pub target: AccountInfo<'info>,
    /// CHECK: arbitrary account passed as victim.
    pub victim: AccountInfo<'info>,
    /// CHECK: VULN-09 — arbitrary remaining accounts forwarded to CPI.
    pub remaining_accounts: Vec<AccountInfo<'info>>,
}

#[derive(Accounts)]
pub struct Compound<'info> {
    #[account(mut)]
    pub state: Account<'info, RewardState>,
}

#[derive(Accounts)]
pub struct Split<'info> {
    #[account(mut)]
    pub account_a: AccountInfo<'info>,
    #[account(mut)]
    pub account_b: AccountInfo<'info>,
}

impl RewardState {
    pub const INIT_SPACE: usize = 8 + 8; // balance + last_compound_slot
}