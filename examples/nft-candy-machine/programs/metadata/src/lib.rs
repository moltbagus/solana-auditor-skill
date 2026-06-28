use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::program::invoke;

declare_id!("Meta111111111111111111111111111111111111111");

#[derive(Accounts)]
pub struct CreateMetadata<'info> {
    #[account(mut)]
    pub mint: AccountInfo<'info>,
    #[account(mut)]
    pub metadata: AccountInfo<'info>,
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ReadMetadata<'info> {
    pub metadata_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct UpdateMetadata<'info> {
    #[account(mut)]
    pub metadata_account: AccountInfo<'info>,
    pub target_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct SetUpdateAuth<'info> {
    #[account(mut)]
    pub metadata_account: AccountInfo<'info>,
    pub authority: AccountInfo<'info>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct Metadata {
    pub name: String,
    pub symbol: String,
    pub uri: String,
    pub update_authority: Pubkey,
}

// VULN-11: Token-2022 transfer hook CPI routing — Rule 27
pub fn create_metadata(ctx: Context<CreateMetadata>, data: Vec<u8>) -> Result<()> {
    // VULN-11: CPI to token-2022 without verifying extra accounts
    invoke(
        &Instruction {
            program_id: ctx.accounts.token_program.key(),
            accounts: vec![
                AccountMeta::new(ctx.accounts.mint.key(), false),
                AccountMeta::new(ctx.accounts.metadata.key(), false),
            ],
            data: data.clone(),
        },
        &ctx.remaining_accounts,
    )?;
    Ok(())
}

// VULN-12: unsafe deserialization — Rule 39
pub fn read_metadata(ctx: Context<ReadMetadata>) -> Result<Vec<u8>> {
    let data = ctx.accounts.metadata_account.try_borrow_data()?;
    // VULN-12: no owner check; can deserialize arbitrary data
    let metadata = Metadata::try_from_slice(&data[8..])?;
    Ok(metadata.name.as_bytes().to_vec())
}

// VULN-13: arbitrary CPI in metadata update — Rule 4
pub fn update_metadata(ctx: Context<UpdateMetadata>, new_uri: String) -> Result<()> {
    // VULN-13: arbitrary CPI via remaining_accounts
    invoke(
        &Instruction {
            program_id: ctx.accounts.target_program.key(),
            accounts: vec![],
            data: new_uri.as_bytes().to_vec(),
        },
        &ctx.remaining_accounts,
    )?;
    Ok(())
}

// VULN-14: missing writable enforcement — Rule 37
pub fn set_update_authority(ctx: Context<SetUpdateAuth>, new_auth: Pubkey) -> Result<()> {
    // VULN-14: account not marked writable in constraints but mutated
    ctx.accounts.metadata_account.update_authority = new_auth;
    Ok(())
}