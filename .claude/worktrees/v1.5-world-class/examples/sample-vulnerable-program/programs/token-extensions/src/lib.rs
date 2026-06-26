//! Sample Token-2022 Anchor program with intentional vulnerabilities.
//!
//! DO NOT DEPLOY. This is a documentation fixture for the
//! solana-auditor-shiba skill. Each `// VULN-XX:` tag marks a bug that
//! a rule in `rules/audit.rules` is designed to catch.
//!
//! This program demonstrates Token-2022 (Token Extensions) vulnerability
//! patterns — wrong token program, missing fee math, close authority
//! bypass, permanent delegate risk, and metadata pointer confusion.
//!
//! All bugs are *logic-level* / *code-review-visibile* — the program
//! compiles cleanly under anchor 0.31.1 with spl-token-2022 features,
//! so reviewers can run `anchor build` to verify the fixture.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("TokExB1oxTqN1S3R4NDoM7dD3F4uLtK8aT9eXaMpLeId");

// ============================================================
// Token-2022 vulnerability patterns
// ============================================================

#[program]
pub mod token_extensions {
    use super::*;

    // VULN-11: Wrong token program — uses `anchor_spl::token::Token`
    // instead of `anchor_spl::token_2022::Token2022`.
    // — Rule 5 (Token Operations — SPL vs Token-2022 Distinction)
    //
    // Cargo.toml declares spl-token-2022 as a dependency, but the
    // instruction uses the legacy Token program for CPI. Token-2022
    // mints have different extension state (transfer_fee, metadata,
    // etc.) that the legacy program won't enforce. Transfers may
    // bypass extension checks.
    pub fn transfer_no_2022_check(ctx: Context<TransferNo2022Check>, amount: u64) -> Result<()> {
        // Uses `anchor_spl::token::transfer` (Token program, not Token-2022)
        // Token-2022 extensions (transfer_fee, metadata_pointer) are NOT enforced
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.from.to_account_info(),
                    to: ctx.accounts.to.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount,
        )?;
        msg!("transfer_no_2022_check: {} transferred (Token program only)", amount);
        Ok(())
    }

    // VULN-12: Missing transfer_fee accounting — raw amount math
    // without pre-calculating the Token-2022 transfer fee.
    // — Rule 5 (Token Operations — Token-2022 extensions)
    //
    // When a mint has the transfer_fee extension enabled, the actual
    // amount delivered to the recipient is `amount - fee`, where
    // `fee = floor(amount * fee_rate)`. This function calculates
    // state updates using the raw input amount without deducting
    // the fee, causing accounting drift.
    pub fn deposit_with_fee_mismatch(ctx: Context<DepositWithFeeMismatch>, amount: u64) -> Result<()> {
        // VULN-12: Records `amount` as received, but Token-2022
        // transfer_fee means recipient only gets `amount - fee`.
        // Over time, internal accounting drifts from actual token state.
        let user = &mut ctx.accounts.user;
        user.deposited = user.deposited.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;
        // Should be: calculate fee via TransferFeeConfig extension,
        // then record `amount - fee` as the deposited amount.
        msg!("deposit_with_fee_mismatch: recorded {} (fee not deducted)", amount);
        Ok(())
    }

    // VULN-13: Missing mint_close_authority check — allows closing
    // a mint without verifying the close authority.
    // — Rule 5 (Token Operations — Token-2022 extensions)
    //
    // Token-2022 mints can have the `mint_close_authority` extension
    // that allows a designated authority to close the mint (if supply
    // is zero). This instruction closes the mint via CPI but never
    // verifies that the caller is the actual close authority stored
    // in the mint's extension data.
    pub fn close_mint_no_verify(ctx: Context<CloseMintNoVerify>) -> Result<()> {
        // VULN-13: No check that `close_authority` matches the
        // mint's `mint_close_authority` extension data.
        // Any signer can attempt to close the mint if supply is zero.
        let _ = &ctx.accounts.mint;
        let _ = &ctx.accounts.close_authority;
        // CPI to token program to close mint — would succeed
        // if supply is 0, even if caller isn't the real close authority.
        msg!("close_mint_no_verify: mint closed (authority NOT verified)");
        Ok(())
    }

    // VULN-14: Permanent delegate not verified — the instruction
    // accepts a `permanent_delegate` account but never checks that
    // the mint has the `permanent_delegate` extension enabled nor
    // that the delegate matches the extension's stored authority.
    // — Rule 5 + Rule 8 (Signer Verification)
    //
    // The permanent_delegate extension gives a designated address
    // the power to burn or transfer tokens from ANY account for
    // that mint. A caller can supply their own pubkey as the
    // delegate and drain user accounts.
    pub fn burn_with_unverified_delegate(ctx: Context<BurnWithUnverifiedDelegate>, amount: u64) -> Result<()> {
        // VULN-14: Uses `delegate` from accounts as if it's the
        // mint's permanent delegate, with no validation that:
        // 1. The mint has the permanent_delegate extension
        // 2. The delegate account matches the extension's authority
        // 3. The delegate is even authorized for this mint
        //
        // Accepts any caller-supplied delegate — attacker passes
        // their own pubkey and burns tokens from any account.
        let _ = &ctx.accounts.mint;
        let _ = &ctx.accounts.delegate;
        let _ = &ctx.accounts.token_account;
        msg!("burn_with_unverified_delegate: {} burned by unverified delegate", amount);
        Ok(())
    }

    // VULN-15: Metadata pointer not verified — reads metadata
    // from the location pointed to by the mint's metadata_pointer
    // extension, but doesn't verify the pointer is canonical or
    // that the metadata account is owned by the expected program.
    // — Rule 5 (Token Operations — Token-2022 extensions)
    //
    // The metadata_pointer extension can point to ANY account.
    // Without verification, an attacker can deploy a mint that
    // points metadata to a malicious account, tricking the
    // program into using fake metadata for authorization decisions.
    pub fn read_metadata_unverified(ctx: Context<ReadMetadataUnverified>) -> Result<()> {
        // VULN-15: Reads metadata pointer from mint extension data
        // but never verifies:
        // 1. The metadata account is owned by the Token Metadata program
        // 2. The metadata matches the mint's actual metadata
        // 3. The pointer wasn't redirected to a fake metadata account
        let _ = &ctx.accounts.mint;
        let _ = &ctx.accounts.metadata_account;
        msg!("read_metadata_unverified: metadata read without pointer verification");
        Ok(())
    }

    // VULN-16 (stretch): Non-transferable token bypass —
    // allows wrapping non-transferable tokens into a vault that
    // can then transfer them, stripping the non-transferable property.
    // — Rule 5 (Token Operations)
    pub fn wrap_non_transferable(ctx: Context<WrapNonTransferable>, amount: u64) -> Result<()> {
        // VULN-16: Does not check if the mint has the
        // `non_transferable` extension enabled. If the mint
        // is non-transferable, the user should not be able to
        // deposit it into a vault that allows withdrawals.
        let vault = &mut ctx.accounts.vault;
        vault.wrapped = vault.wrapped.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;
        msg!("wrap_non_transferable: wrapped {} tokens (non-transferable NOT checked)", amount);
        Ok(())
    }
}

// ============================================================
// Account structs
// ============================================================

#[derive(Accounts)]
pub struct TransferNo2022Check<'info> {
    /// CHECK: VULN-11 — uses Token program, should use Token-2022
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    /// CHECK: VULN-11 — recipient account
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
    /// CHECK: VULN-11 — should check this is Token-2022 program ID
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct DepositWithFeeMismatch<'info> {
    #[account(mut)]
    pub user: Account<'info, UserState>,
    /// CHECK: VULN-12 — mint with potential transfer_fee extension
    pub mint: Account<'info, Mint>,
}

#[derive(Accounts)]
pub struct CloseMintNoVerify<'info> {
    /// CHECK: VULN-13 — no validation that close_authority matches extension
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    /// CHECK: VULN-13 — should be verified against mint's close authority extension
    pub close_authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct BurnWithUnverifiedDelegate<'info> {
    /// CHECK: VULN-14 — no check for permanent_delegate extension
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    /// CHECK: VULN-14 — not verified as actual permanent delegate
    pub delegate: Signer<'info>,
    /// CHECK: VULN-14 — token account to burn from
    #[account(mut)]
    pub token_account: Account<'info, TokenAccount>,
}

#[derive(Accounts)]
pub struct ReadMetadataUnverified<'info> {
    /// CHECK: VULN-15 — mint with metadata_pointer extension
    pub mint: Account<'info, Mint>,
    /// CHECK: VULN-15 — metadata account not verified for ownership or pointer match
    /// CHECK: could point to fake metadata controlled by attacker
    pub metadata_account: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct WrapNonTransferable<'info> {
    /// CHECK: VULN-16 — no check for non_transferable extension on mint
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    /// CHECK: VULN-16 — mint could have non_transferable extension
    pub mint: Account<'info, Mint>,
    pub user: Signer<'info>,
}

// ============================================================
// State structs
// ============================================================

#[account]
pub struct UserState {
    pub deposited: u64,
    pub authority: Pubkey,
}

#[account]
pub struct VaultState {
    pub wrapped: u64,
    pub authority: Pubkey,
}
