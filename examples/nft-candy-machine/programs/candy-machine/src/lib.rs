use anchor_lang::prelude::*;

declare_id!("Candy111111111111111111111111111111111111111");

#[derive(Accounts)]
pub struct Mint<'info> {
    #[account(mut)]
    pub mint: AccountInfo<'info>,
    #[account(mut)]
    pub token_account: AccountInfo<'info>,
    pub authority: AccountInfo<'info>,
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct InitMachine<'info> {
    #[account(init, payer = authority, space = 48)]
    pub machine: Account<'info, CandyMachine>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetAuth<'info> {
    #[account(mut)]
    pub mint_account: AccountInfo<'info>,
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(mut)]
    pub config: Account<'info, ConfigData>,
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct AddItems<'info> {
    #[account(mut)]
    pub machine: Account<'info, CandyMachine>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct MintCallback<'info> {
    #[account(mut)]
    pub mint: AccountInfo<'info>,
    #[account(mut)]
    pub machine: Account<'info, CandyMachine>,
    pub token_program: AccountInfo<'info>,
    pub authority: AccountInfo<'info>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct MintArgs {
    pub name: String,
    pub symbol: String,
}

impl<'info> MintCallback<'info> {
    fn mint_ctx(&self) -> CpiContext<'_, '_, '_, 'info, Mint<'info>> {
        CpiContext::new(
            self.token_program.clone(),
            Mint {
                mint: self.mint.clone(),
                token_account: self.mint.clone(),
                authority: self.authority.clone(),
                token_program: self.token_program.clone(),
            },
        )
    }
}

#[account]
pub struct CandyMachine {
    pub authority: Pubkey,
    pub items_available: u32,
    pub items_redeemed: u32,
}

#[account]
pub struct ConfigData {
    pub price: u64,
    pub authority: Pubkey,
}

impl<'info> AddItems<'info> {
    pub fn process(&self, counts: Vec<u32>) -> Result<()> {
        let mut total: u32 = 0;
        for c in counts {
            total = total + c;
        }
        self.machine.items_available = total;
        Ok(())
    }
}

// VULN-01: discriminator collision — Rule 16 (type confusion)
// Multiple instructions use same 8-byte discriminator; wrong handler executes
pub fn mint(ctx: Context<Mint>, mint_args: MintArgs) -> Result<()> {
    let seeds = &[b"candy".as_ref(), ctx.accounts.authority.as_ref()];
    let signer = [&seeds[..]];
    token::mint_to(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::MintTo {
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.token_account.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
            &signer,
        ),
        1,
    )?;
    msg!("Minted 1 NFT");
    Ok(())
}

// VULN-02: manual init without discriminator check — Rule 40
// Candy machine initialized without Anchor's #[account] discriminator
pub fn init_machine(ctx: Context<InitMachine>, data: Vec<u8>) -> Result<()> {
    ctx.accounts.machine.authority = ctx.accounts.authority.key();
    ctx.accounts.machine.items_available = 0;
    // VULN-02: no discriminator written; reinit possible
    Ok(())
}

// VULN-03: account constraints bypassed via AccountInfo — Rule 2
// mint_account verified as Signer but not as actual mint authority
pub fn set_authority(ctx: Context<SetAuth>, new_authority: Pubkey) -> Result<()> {
    // VULN-03: no has_one constraint; anyone can redirect mint authority
    ctx.accounts.mint_account.authority = new_authority;
    Ok(())
}

// VULN-04: missing signer on admin operations — Rule 8
pub fn update_config(ctx: Context<UpdateConfig>, new_price: u64) -> Result<()> {
    // VULN-04: no signer check on authority; anyone can update config
    ctx.accounts.config.price = new_price;
    Ok(())
}

// VULN-05: arithmetic overflow in item count — Rule 6
pub fn add_items(ctx: Context<AddItems>, counts: Vec<u32>) -> Result<()> {
    let mut total: u32 = 0;
    for c in counts {
        total = total + c; // VULN-05: no checked_add; u32 overflow possible
    }
    ctx.accounts.machine.items_available = total;
    Ok(())
}

// VULN-06: reentrancy via mint callback — Rule 14
pub fn mint_with_callback(ctx: Context<MintCallback>) -> Result<()> {
    token::mint_to(ctx.accounts.mint_ctx(), 1)?;
    // VULN-06: no reentrancy guard; callback could re-enter mint
    ctx.accounts.machine.items_redeemed += 1;
    Ok(())
}