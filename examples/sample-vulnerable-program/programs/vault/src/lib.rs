//! Sample Anchor program with intentional vulnerabilities.
//!
//! DO NOT DEPLOY. This is a documentation fixture for the
//! solana-auditor-skill skill. Each `// VULN-XX:` tag marks a bug that
//! a rule in `rules/audit.rules` is designed to catch. See
//! `audit-output/findings.json` for the expected findings when this
//! program is run through `/audit`.
//!
//! All bugs in this version are *runtime* / *logic-level* — the program
//! compiles cleanly under anchor 0.31.1 so reviewers can run `anchor build`
//! to verify the fixture is buildable.

use anchor_lang::prelude::*;
use solana_program::{
    instruction::{AccountMeta, Instruction},
    program::invoke,
};

declare_id!("VauLTv8XCvFhMtNTSg9qV9u1KKrn3DLzNaX7cSC8K8H");

#[program]
pub mod vault {
    use super::*;

    // VULN-02: hardcoded bump literal — Rule 3 (PDA canonical bump)
    // Real Anchor code uses ctx.bumps.vault or find_program_address.
    pub fn initialize(_ctx: Context<Initialize>) -> Result<()> {
        let _hardcoded_bump: u8 = 254;
        msg!("vault initialized with bump {}", _hardcoded_bump);
        Ok(())
    }

    // VULN-01: missing signer check on admin — Rule 8 (Signer verification)
    // The admin is taken as AccountInfo, not Signer; no is_signer check.
    // Anyone can call admin_withdraw and drain the vault.
    pub fn admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64) -> Result<()> {
        // No signer check on `admin` — anyone can call this.
        // No has_one constraint binding admin to a vault authority.
        // Direct lamport transfer with no validation.
        **ctx.accounts.vault.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.destination.try_borrow_mut_lamports()? += amount;
        Ok(())
    }

    // VULN-05: arithmetic without checked_add on user-supplied amount
    // — Rule 6 (Arithmetic overflow)
    pub fn user_deposit(ctx: Context<UserDeposit>, amount: u64) -> Result<()> {
        // VULN-05: unchecked_add on u64 wraps silently on overflow in release mode.
        // In a real program, `vault.balance` would be Account<'info, VaultState>.
        // Here we simulate the bug on a local to keep the fixture compile-clean.
        let current_balance: u64 = 1_000_000_000; // pretend vault balance
        let _new_balance: u64 = current_balance + amount; // <-- unchecked!
        msg!("deposit {} → new balance {} (overflow risk)", amount, _new_balance);
        let _ = ctx.accounts.vault.key();
        Ok(())
    }

    // VULN-03: arbitrary CPI to user-supplied program — Rule 4 (CPI safety)
    // No whitelist of allowed programs; user passes `target_program` directly.
    pub fn exec_callback(ctx: Context<ExecCallback>, data: Vec<u8>) -> Result<()> {
        let ix = Instruction {
            program_id: ctx.accounts.target_program.key(), // ← attacker-controlled
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

    // VULN-04: lamport drain via unchecked transfer — Rule 7 (Close accounts)
    // The function debits from vault and credits to a user-supplied destination
    // with no authority check. Anyone can drain the vault by passing their own
    // address as `destination` and amount = vault_balance.
    pub fn drain_vault(ctx: Context<DrainVault>, amount: u64) -> Result<()> {
        // VULN-04: no signer check on authority; no has_one constraint binding
        // destination to a known recipient. Anyone can call this.
        **ctx.accounts.vault.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.destination.try_borrow_mut_lamports()? += amount;
        Ok(())
    }

    // === Non-rule-aligned bugs (VULN-07..VULN-10) ===

    // VULN-07: integer division truncation — logic bug
    // `shares = deposit / divisor` truncates. If divisor > deposit, result is 0
    // and the user gets 0 shares but their deposit is still credited.
    pub fn calc_shares(_ctx: Context<DrainVault>, deposit: u64, divisor: u64) -> Result<()> {
        let _shares: u64 = deposit / divisor; // <-- truncates, no remainder check
        msg!("shares for {} / {} = {}", deposit, divisor, _shares);
        Ok(())
    }

    // VULN-08: wrong comparison direction — off-by-one in favor of attacker
    // `>` instead of `>=` lets the attacker bypass the threshold check by
    // exactly hitting the threshold value.
    pub fn check_threshold(ctx: Context<DrainVault>, value: u64) -> Result<()> {
        if value > 1_000_000 { // <-- should be >=
            msg!("above threshold");
        } else {
            msg!("at or below threshold");
        }
        let _ = ctx.accounts.vault.key();
        Ok(())
    }

    // VULN-09: unchecked return from CPI (no ? propagation) — silent failure
    // `let _ = invoke(...)` discards the result. If the CPI fails, the outer
    // transaction succeeds anyway, leaving state inconsistent.
    pub fn unchecked_cpi(ctx: Context<ExecCallback>, data: Vec<u8>) -> Result<()> {
        let ix = Instruction {
            program_id: ctx.accounts.target_program.key(),
            accounts: vec![],
            data,
        };
        let _ = invoke(&ix, &[]); // <-- result discarded, should use `?`
        Ok(())
    }

    // VULN-10: missing event emission — audit trail gap
    // Withdrawals should emit an event for off-chain indexing (security
    // monitoring, accounting). Without it, off-chain systems can't detect
    // anomalous activity and post-mortem analysis is impossible.
    pub fn silent_withdraw(ctx: Context<DrainVault>, amount: u64) -> Result<()> {
        **ctx.accounts.vault.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.destination.try_borrow_mut_lamports()? += amount;
        // No emit!(WithdrawEvent { ... }); — should emit event for indexers
        msg!("withdrew {}", amount); // msg! is not a structured event
        Ok(())
    }
}

// VULN-06: account struct missing #[account] attribute — Rule 11 (Reinit attacks)
// Without #[account], Anchor does not write the 8-byte discriminator on init,
// and Account<'info, VaultState> cannot be used to enforce it at deserialize.
// The Initialize struct uses AccountInfo, so there is no discriminator check
// at all — re-initialization is possible.
pub struct VaultState {
    pub authority: Pubkey,
    pub bump: u8,
    pub total_deposits: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    // VULN-06: should be `Account<'info, VaultState>` so the discriminator is verified.
    // Using AccountInfo bypasses the discriminator check, allowing reinit attacks.
    /// CHECK: VULN-06 — AccountInfo bypasses discriminator enforcement.
    #[account(mut)]
    pub vault: AccountInfo<'info>,
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    // VULN-01: should be `Account<'info, VaultState>` with `has_one = admin` constraint.
    // Using AccountInfo bypasses type safety AND the admin check below is missing.
    /// CHECK: VULN-01 — AccountInfo bypasses type safety.
    #[account(mut)]
    pub vault: AccountInfo<'info>,
    /// CHECK: VULN-01 — should be Signer but is unverified AccountInfo.
    pub admin: AccountInfo<'info>,
    /// CHECK: destination is unchecked.
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct UserDeposit<'info> {
    /// CHECK: vault balance is mutated unchecked (see VULN-05).
    #[account(mut)]
    pub vault: AccountInfo<'info>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct ExecCallback<'info> {
    /// CHECK: target program. VULN-03 — should be validated against an allowlist.
    pub target_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct DrainVault<'info> {
    /// CHECK: VULN-04 — vault is referenced raw without discriminator or has_one check.
    #[account(mut)]
    pub vault: AccountInfo<'info>,
    /// CHECK: VULN-04 — destination is whatever the caller passes. Should
    /// be derived from authority or be a known recipient PDA.
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}
