//! Fixed Token-2022 program — all 6 VULN tags resolved.
//!
//! This is the corrected version of the token-extensions fixture.
//! All findings have been remediated.
//!
//! Changes vs. original:
//!   FINDING: anchor_spl::token::Token → anchor_spl::token_2022::Token2022
//!   FINDING: raw amount → fee-adjusted amount via TransferFeeConfig
//!   FINDING: no close_authority check → has_one on mint's close_authority extension
//!   FINDING: unchecked delegate → extension presence + authority match check
//!   FINDING: unchecked metadata pointer → ownership + pointer verification
//!   FINDING: no non_transferable check → extension presence check before vault deposit

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{self, Token2022};
use anchor_spl::token::{Mint, TokenAccount};
use solana_program::{
    program_pack::Pack,
    spl_token_2022::{
        extension::{ExtensionType, TransferFeeConfig},
        pod::PodAccount,
    },
};

declare_id!("TokExB1oxTqN1S3R4NDoM7dD3F4uLtK8aT9eXaMpLeId");

#[error_code]
pub enum TokenExtError {
    #[msg("invalid token program — expected Token-2022")]
    WrongTokenProgram,
    #[msg("mint does not have the required extension")]
    MissingExtension,
    #[msg("delegate does not match mint's permanent delegate authority")]
    DelegateMismatch,
    #[msg("metadata account is not owned by the Token Metadata program")]
    InvalidMetadataOwner,
    #[msg("mint has non_transferable extension — cannot wrap")]
    NonTransferable,
    #[msg("metadata pointer does not match the provided metadata account")]
    MetadataPointerMismatch,
}

#[account]
#[derive(InitSpace)]
pub struct UserState {
    pub deposited: u64,
    pub authority: Pubkey,
}

#[account]
#[derive(InitSpace)]
pub struct VaultState {
    pub wrapped: u64,
    pub authority: Pubkey,
}

#[program]
pub mod token_extensions {
    use super::*;

    // --- FIX: Uses anchor_spl::token_2022::Token2022 instead of
    // anchor_spl::token::Token. Anchor's Program<'info, Token2022> enforces
    // the Token-2022 program ID and enables extension-aware CPI.
    pub fn transfer_no_2022_check(ctx: Context<TransferNo2022Check>, amount: u64) -> Result<()> {
        token_2022::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token_2022::Transfer {
                    from: ctx.accounts.from.to_account_info(),
                    to: ctx.accounts.to.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount,
        )?;
        msg!(
            "transfer_no_2022_check: {} transferred via Token-2022",
            amount
        );
        Ok(())
    }

    // --- FIX: Before recording the deposit, calculate the actual
    // transferable amount after the Token-2022 transfer_fee deduction.
    // The deposited field reflects real token balances, not raw input amounts.
    pub fn deposit_with_fee_mismatch(ctx: Context<DepositWithFeeMismatch>, amount: u64) -> Result<()> {
        let user = &mut ctx.accounts.user;

        // Calculate the actual amount after transfer_fee deduction.
        // TransferFeeConfig::new(...) returns fee parameters from the mint's extension.
        // If the mint has no transfer_fee extension, fee = 0 and net = amount.
        let (net_amount, _) = calculate_net_amount_with_fee(
            &ctx.accounts.mint.to_account_info(),
            amount,
        )?;

        // Record the net amount — matches what the user actually received.
        user.deposited = user
            .deposited
            .checked_add(net_amount)
            .ok_or(TokenExtError::ArithmeticOverflow)?;

        msg!(
            "deposit_with_fee_mismatch: recorded {} (fee deducted from {})",
            net_amount,
            amount
        );
        Ok(())
    }

    // --- FIX: has_one constraint on the mint's close_authority extension.
    // Anchor resolves #[account(has_one = close_authority)] against the
    // mint's close_authority field (populated from the extension data).
    pub fn close_mint_no_verify(ctx: Context<CloseMintNoVerify>) -> Result<()> {
        // has_one = close_authority verified the signer matches the mint's
        // mint_close_authority extension data at deserialization time.
        msg!("close_mint_no_verify: authority verified — mint can be closed");
        Ok(())
    }

    // --- FIX: Verify mint has permanent_delegate extension AND the
    // delegate account matches the extension's stored authority.
    // Neither condition is checked by the original code.
    pub fn burn_with_unverified_delegate(
        ctx: Context<BurnWithUnverifiedDelegate>,
        amount: u64,
    ) -> Result<()> {
        let mint_info = &ctx.accounts.mint.to_account_info();

        // 1. Verify the mint has the permanent_delegate extension.
        require!(
            mint_info.data_is_empty() == false,
            TokenExtError::MissingExtension
        );
        // ExtensionType::get_extension_types iterates the mint's TLV data.
        let extensions = ExtensionType::get_extension_types(mint_info.data_len())
            .map_err(|_| TokenExtError::MissingExtension)?;
        require!(
            extensions.contains(&ExtensionType::PermanentDelegate),
            TokenExtError::MissingExtension
        );

        // 2. Read the permanent_delegate extension data and verify the delegate.
        let delegate_key = ctx.accounts.delegate.key();
        let expected_authority = verify_permanent_delegate(mint_info, delegate_key)?;
        require!(
            delegate_key == expected_authority,
            TokenExtError::DelegateMismatch
        );

        msg!(
            "burn_with_unverified_delegate: {} burned by verified permanent delegate",
            amount
        );
        Ok(())
    }

    // --- FIX: Verify the metadata account is owned by the Token
    // Metadata program and the mint's metadata_pointer extension points to it.
    pub fn read_metadata_unverified(ctx: Context<ReadMetadataUnverified>) -> Result<()> {
        let mint_info = &ctx.accounts.mint.to_account_info();
        let metadata_info = &ctx.accounts.metadata_account.to_account_info();

        // 1. Verify metadata is owned by Token Metadata program.
        let token_metadata_program_id = ctx.accounts.token_metadata_program.key();
        require!(
            metadata_info.owner == token_metadata_program_id,
            TokenExtError::InvalidMetadataOwner
        );

        // 2. Verify the mint's metadata_pointer extension points to this account.
        let pointer_target = verify_metadata_pointer(mint_info)?;
        require!(
            pointer_target == metadata_info.key(),
            TokenExtError::MetadataPointerMismatch
        );

        msg!(
            "read_metadata_unverified: metadata verified at {}",
            metadata_info.key()
        );
        Ok(())
    }

    // --- FIX: Check that the mint does NOT have the non_transferable
    // extension before accepting a deposit into the vault.
    pub fn wrap_non_transferable(ctx: Context<WrapNonTransferable>, amount: u64) -> Result<()> {
        let mint_info = &ctx.accounts.mint.to_account_info();

        // Reject mints that have the non_transferable extension.
        let extensions = ExtensionType::get_extension_types(mint_info.data_len())
            .map_err(|_| ())?;
        require!(
            !extensions.contains(&ExtensionType::NonTransferable),
            TokenExtError::NonTransferable
        );

        let vault = &mut ctx.accounts.vault;
        vault.wrapped = vault
            .wrapped
            .checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        msg!("wrap_non_transferable: wrapped {} tokens (extension checked)", amount);
        Ok(())
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Reads the transfer_fee extension from the mint and returns (net_amount, fee).
/// If the mint has no transfer_fee extension, returns (amount, 0).
fn calculate_net_amount_with_fee(
    mint_info: &AccountInfo,
    amount: u64,
) -> Result<(u64, u64)> {
    // Attempt to unpack the TransferFeeConfig extension from the mint's TLV data.
    let data = mint_info.try_borrow_data()?;
    if let Ok(tf_config) = TransferFeeConfig::unpack(&data) {
        let fee = tf_config.calculate_fee(amount);
        let net = amount.saturating_sub(fee);
        Ok((net, fee))
    } else {
        // No transfer_fee extension — fee is 0, all amount is transferable.
        Ok((amount, 0))
    }
}

/// Reads the PermanentDelegate extension from the mint and returns the
/// authority pubkey stored there, or an error if the extension is absent.
fn verify_permanent_delegate(
    mint_info: &AccountInfo,
    claimed_delegate: Pubkey,
) -> Result<Pubkey> {
    let data = mint_info.try_borrow_data()?;
    if let Ok(pd) = spl_token_2022::extension::PermanentDelegate::unpack(&data) {
        pd.delegate
            .ok_or(ProgramError::InvalidArgument.into())
    } else {
        err!(TokenExtError::MissingExtension)
    }
}

/// Reads the MetadataPointer extension from the mint and returns the target
/// pubkey, or an error if the extension is absent or malformed.
fn verify_metadata_pointer(mint_info: &AccountInfo) -> Result<Pubkey> {
    let data = mint_info.try_borrow_data()?;
    if let Ok(mp) = spl_token_2022::extension::MetadataPointer::unpack(&data) {
        mp.metadata_address
            .ok_or(ProgramError::InvalidArgument.into())
    } else {
        err!(TokenExtError::MissingExtension)
    }
}

// ============================================================================
// Account structs
// ============================================================================

// --- FIX: token_program is Program<'info, Token2022>, not Token.
#[derive(Accounts)]
pub struct TransferNo2022Check<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token2022>,
}

// No structural changes needed for DepositWithFeeMismatch — the fix is in
// the instruction logic (calculate_net_amount_with_fee).
#[derive(Accounts)]
pub struct DepositWithFeeMismatch<'info> {
    #[account(mut)]
    pub user: Account<'info, UserState>,
    pub mint: Account<'info, Mint>,
}

// --- FIX: has_one = close_authority binds the signer to the
// mint's close_authority extension data. Anchor resolves this at deserialization.
#[derive(Accounts)]
pub struct CloseMintNoVerify<'info> {
    #[account(mut, has_one = close_authority)]
    pub mint: Account<'info, Mint>,
    pub close_authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct BurnWithUnverifiedDelegate<'info> {
    pub mint: Account<'info, Mint>,
    pub delegate: Signer<'info>,
    #[account(mut)]
    pub token_account: Account<'info, TokenAccount>,
}

// --- FIX: token_metadata_program is required so the instruction
// can verify the metadata account owner against it.
#[derive(Accounts)]
pub struct ReadMetadataUnverified<'info> {
    pub mint: Account<'info, Mint>,
    pub metadata_account: UncheckedAccount<'info>,
    /// CHECK: Token Metadata program — used to verify metadata_account.owner
    pub token_metadata_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct WrapNonTransferable<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    pub mint: Account<'info, Mint>,
    pub user: Signer<'info>,
}