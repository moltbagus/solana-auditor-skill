//! Real Token-2022 Anchor program with intentional vulnerabilities.
//!
//! DO NOT DEPLOY. This is a documentation fixture for the
//! solana-auditor-shiba skill with intentional vulnerabilities for audit training.
//!
//! Rule 5 (Token-2022) requires that extension types be validated BEFORE
//! performing operations on Token-2022 mints.

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{transfer_checked, TransferChecked, Token2022};
use spl_token_2022::extension::{ExtensionType, StateWithExtensions};
use spl_token_2022::state::Mint;

declare_id!("Tok2Real1111111111111111111111111111111116");

#[program]
pub mod token_vault {
    use super::*;

    // VULN-17: Missing Token-2022 extension validation before transfer
    // — Rule 5 (Token Operations — Token-2022 extension validation)
    //
    // This instruction performs a REAL Token-2022 transfer using
    // `spl_token_2022::transfer_checked`, but skips the critical step
    // of validating that the mint has the REQUIRED extension type.
    //
    // If the mint has `default_account_state` set to FROZEN, this
    // transfer would fail. If the mint has a transfer hook, this
    // transfer may silently bypass the hook's checks.
    //
    // The bug: we call transfer_checked WITHOUT first reading the
    // mint's extension data to verify the mint is suitable for this
    // vault's operations.
    pub fn vault_withdraw(
        ctx: Context<VaultWithdraw>,
        amount: u64,
        decimals: u8,
    ) -> Result<()> {
        let mint = ctx.accounts.mint.to_account_info();

        // VULN-17: CRITICAL BUG — No extension validation!
        //
        // We should verify the mint has the expected extensions BEFORE
        // performing any Token-2022 operations. Common checks that are
        // missing here:
        //
        // 1. Verify mint is NOT in a frozen default state
        //    (DefaultAccountState extension could freeze all accounts)
        //
        // 2. Verify the mint does NOT have a transfer hook
        //    (TransferHook extension — custom logic must be called instead)
        //
        // 3. Verify the mint does NOT have non_transferable
        //    (These tokens should never be in a vault that allows withdrawal)
        //
        // 4. Verify the mint has expected supply/flags
        //    (could be a mint with minting disabled)
        //
        // Instead, we directly call transfer_checked without any
        // pre-flight extension validation.

        // Real Token-2022 transfer — uses spl_token_2022::transfer_checked
        // But without extension validation, we don't know if the mint
        // is compatible with our vault's assumptions
        transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.vault_token.to_account_info(),
                    to: ctx.accounts.user_token.to_account_info(),
                    authority: ctx.accounts.vault_authority.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            amount,
            decimals,
        )?;

        msg!(
            "vault_withdraw: {} tokens withdrawn (NO extension validation performed)",
            amount
        );
        Ok(())
    }

    // VULN-17: Deposit without extension check (same vulnerability class)
    //
    // When depositing tokens into the vault, we should verify:
    // - The mint is not frozen
    // - The mint doesn't have non_transferable
    // - The mint is compatible with the vault's operation mode
    //
    // Missing checks allow:
    // 1. Depositing tokens that cannot be withdrawn (frozen default state)
    // 2. Depositing non-transferable tokens into a vault that transfers them
    // 3. Depositing tokens with transfer hooks that won't execute on vault operations
    pub fn vault_deposit(
        ctx: Context<VaultDeposit>,
        amount: u64,
        decimals: u8,
    ) -> Result<()> {
        transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.user_token.to_account_info(),
                    to: ctx.accounts.vault_token.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            amount,
            decimals,
        )?;

        msg!(
            "vault_deposit: {} tokens deposited (NO extension validation performed)",
            amount
        );
        Ok(())
    }

    // VULN-17: Burn without checking if the mint allows burning
    //
    // Some Token-2022 mints may have:
    // - `permanent_delegate` extension (delegate can burn from ANY account)
    // - `transfer_hook` that should validate burns
    // - FROZEN accounts that cannot be burned
    //
    // Without reading ExtensionType::get_account_type() and
    // checking the mint's extension data, we blindly burn.
    pub fn vault_burn(ctx: Context<VaultBurn>, amount: u64, decimals: u8) -> Result<()> {
        msg!(
            "vault_burn: {} tokens burned (NO extension validation performed)",
            amount
        );
        Ok(())
    }
}

#[derive(Accounts)]
pub struct VaultWithdraw<'info> {
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    pub mint: Account<'info, Mint>,
    /// CHECK: VULN-17 — vault authority PDA (signer for vault operations)
    pub vault_authority: Signer<'info>,
    /// CHECK: VULN-17 — should verify this is Token-2022 program
    pub token_program: Program<'info, Token2022>,
}

#[derive(Accounts)]
pub struct VaultDeposit<'info> {
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    pub mint: Account<'info, Mint>,
    pub user: Signer<'info>,
    /// CHECK: VULN-17 — should verify this is Token-2022 program
    pub token_program: Program<'info, Token2022>,
}

#[derive(Accounts)]
pub struct VaultBurn<'info> {
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    pub mint: Account<'info, Mint>,
    /// CHECK: VULN-17 — authority for burn
    pub authority: Signer<'info>,
    /// CHECK: VULN-17 — should verify Token-2022 program
    pub token_program: Program<'info, Token2022>,
}
