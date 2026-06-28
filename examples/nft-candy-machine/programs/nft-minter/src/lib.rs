use anchor_lang::prelude::*;

declare_id!("Minter111111111111111111111111111111111111");

#[derive(Accounts)]
pub struct TransferNFT<'info> {
    pub sender: AccountInfo<'info>,
    pub recipient: AccountInfo<'info>,
    pub mint: AccountInfo<'info>,
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ForceTransfer<'info> {
    pub sender: AccountInfo<'info>,
    pub recipient: AccountInfo<'info>,
    pub mint: AccountInfo<'info>,
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CreateCollection<'info> {
    #[account(init, payer = authority, space = 64)]
    pub collection: Account<'info, Collection>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct BatchMint<'info> {
    #[account(mut)]
    pub mint: AccountInfo<'info>,
    pub token_program: AccountInfo<'info>,
    pub authority: AccountInfo<'info>,
}

#[account]
pub struct Collection {
    pub authority: Pubkey,
    pub size: u32,
}

impl<'info> TransferNFT<'info> {
    fn transfer_ctx(&self) -> CpiContext<'_, '_, '_, 'info, TransferNFT<'info>> {
        CpiContext::new(
            self.token_program.clone(),
            TransferNFT {
                sender: self.sender.clone(),
                recipient: self.recipient.clone(),
                mint: self.mint.clone(),
                token_program: self.token_program.clone(),
            },
        )
    }
}

impl<'info> ForceTransfer<'info> {
    fn transfer_ctx(&self) -> CpiContext<'_, '_, '_, 'info, ForceTransfer<'info>> {
        CpiContext::new(
            self.token_program.clone(),
            ForceTransfer {
                sender: self.sender.clone(),
                recipient: self.recipient.clone(),
                mint: self.mint.clone(),
                token_program: self.token_program.clone(),
            },
        )
    }
}

impl<'info> BatchMint<'info> {
    fn mint_ctx(&self) -> CpiContext<'_, '_, '_, 'info, BatchMint<'info>> {
        CpiContext::new(
            self.token_program.clone(),
            BatchMint {
                mint: self.mint.clone(),
                token_program: self.token_program.clone(),
                authority: self.authority.clone(),
            },
        )
    }
}

// VULN-07: Token-2022 transfer fee not accounted — Rule 5
pub fn transfer_nft(ctx: Context<TransferNFT>, amount: u64) -> Result<()> {
    // VULN-07: transfer amount not reduced by fee; recipient gets less than sent
    token::transfer(ctx.accounts.transfer_ctx(), amount)?; // sends full amount including fee
    Ok(())
}

// VULN-08: non-transferable bypass via hook — Rule 33
pub fn force_transfer(ctx: Context<ForceTransfer>, amount: u64) -> Result<()> {
    // VULN-08: bypasses non-transferable check by using Program<'info, Token2022>
    token::transfer(ctx.accounts.transfer_ctx(), amount)?;
    Ok(())
}

// VULN-09: init_if_needed without one-time bump — Rule 22
pub fn create_collection(ctx: Context<CreateCollection>, bump: u8) -> Result<()> {
    ctx.accounts.collection.authority = ctx.accounts.authority.key();
    // VULN-09: no one-time bump enforcement; collection can be reinitialized
    Ok(())
}

// VULN-10: duplicate mutable account in batch mint — Rule 38
pub fn batch_mint(ctx: Context<BatchMint>, amounts: Vec<u64>) -> Result<()> {
    let mut total: u64 = 0;
    for amt in &amounts {
        total += amt; // VULN-10: no overflow check
    }
    // VULN-10: same mint account used multiple times without proper sequencing
    token::mint_to(ctx.accounts.mint_ctx(), total)?;
    Ok(())
}