# Phase 2: Static Analysis

**Goal**: Find vulnerability classes in Anchor / sealevel code.

## Anchor Core Checks

### Account Discriminator
```rust
// VULN: Direct account creation without discriminator check
pub fn init_user(ctx: Context<InitUser>) -> Result<()> {
    let user = &mut ctx.accounts.user;
    user.authority = ctx.accounts.authority.key(); // ← MISSING discriminator
    Ok(())
}

// FIX: Use #[account(...)] with proper constraints
#[derive(Accounts)]
pub struct InitUser<'info> {
    #[account(mut)]
    pub user: Account<'info, User>,
    pub authority: Signer<'info>,
}

#[account]
pub struct User {
    pub authority: Pubkey,
    pub bump: u8,
}
```

### Missing `mut` Check
```rust
// VULN: Account not marked mut but modified
pub fn update(ctx: Context<Update>, data: u64) -> Result<()> {
    ctx.accounts.data.data = data; // Won't persist — anchor will reject
    Ok(())
}

// Check anchor constraints carefully
// init, mut, signer, owner, executable, writable — each is a gate
```

### Init Without Rent-Exempt
```rust
// VULN: init sets data without ensuring rent-exemption
#[derive(Accounts)]
pub struct CreatePool<'info> {
    #[account(init, space = Pool::LEN, payer = user)]
    pub pool: Account<'info, Pool>,
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

// FIX: Always verify rent-exemption on new accounts
// Anchor's init constraint handles this IF space is correct
```

### Reinitialization Attack
```rust
// VULN: No bump validation → reinit with wrong PDA
#[derive(Accounts)]
pub struct InitVault<'info> {
    #[account(seeds = [b"vault", user.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
}

// Must validate bump:
// FIX: 
let bump = *ctx.bumps.get("vault").unwrap();
vault.bump = bump;
// And use canonical bump for PDA derivation
```

## CPI Privilege Escalation

### Missing Signer Verification on CPI
```rust
// VULN: invoke without verifying signer
pub fn delegate(ctx: Context<Delegate>) -> Result<()> {
    let cx = Context::new(ctx.program_id, &ctx.accounts.delegate_ctx(), &[]);
    invoke(&ix, &cx.accounts.as_slice()) // ← delegate not verified as signer
    Ok(())
}

// FIX: Verify signer before invoke
require!(ctx.accounts.delegate.is_signer, ErrorCode::NotSigner);
```

### Missing Owner Check on CPI Target
```rust
// VULN: CPI to token account without owner check
invoke(
    &spl_token::instruction::transfer(
        token_program.key,
        source.key,
        dest.key,
        authority.key,
        &[],
        amount,
    )?,
    &accounts,
)?;
// If authority is not verified against the expected owner → stolen funds

// FIX: Verify owner before any token operation
require!(*ctx.accounts.token_account.owner == spl_token::id(), ErrorCode::WrongOwner);
```

### CPI With Dynamic Seeds
```rust
// VULN: invoke_signed with user-controlled seeds
invoke_signed(
    &ix,
    &accounts,
    &[&[b"user", user.key().as_ref(), user_nonce.to_le_bytes().as_ref()]]
)?;
// If user_nonce is derived from untrusted input → PDA collision

// FIX: Use canonical bump, verify bump before use
let bump = *ctx.bumps.get("vault").unwrap();
let authority_pda = Pubkey::find_program_address(
    &[b"vault", user.key().as_ref(), &[bump]],
    program_id,
).0;
```

## Integer Overflow / Underflow

### Amount Arithmetic
```rust
// VULN: No checked arithmetic
let new_amount = ctx.accounts.vault.amount + deposit_amount; // ← overflow possible

// FIX: Use checked math
let new_amount = ctx.accounts.vault.amount.checked_add(deposit_amount)
    .ok_or(ErrorCode::Overflow)?;

// Anchor 0.30+ uses checked math by default in Accounts struct
// But manual arithmetic in instruction handlers MUST use checked_* methods
```

### PDA Bump Overflow
```rust
// VULN: bump cast without bounds check
let bump = data.bump as u64;
let pda = Pubkey::create_program_address(&[&[bump]], program_id)?;

// FIX: Anchor bumps are always u8 — trust anchor's bump extraction
let bump = *ctx.bumps.get("pda").unwrap();
```

## Access Control

### Missing Owner Check
```rust
// VULN: Modifying account without owner verification
pub fn update_config(ctx: Context<UpdateConfig>, new_value: u64) -> Result<()> {
    ctx.accounts.config.data = new_value; // Anyone can update
    Ok(())
}

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    pub config: Account<'info, Config>,
}

// FIX: Add authority check
#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(mut, has_one = authority)]
    pub config: Account<'info, Config>,
    pub authority: Signer<'info>,
}
```

### Missing Signer Check
```rust
// VULN: Critical action without signer
pub fn withdraw_treasury(ctx: Context<WithdrawTreasury>) -> Result<()> {
    ctx.accounts.treasury.sub_lamports(LAMPORTS_PER_SOL * 10)?; // No signer check!
    ctx.accounts.destination.add_lamports(LAMPORTS_PER_SOL * 10)?;
    Ok(())
}

// FIX: Add signer constraint
pub struct WithdrawTreasury<'info> {
    #[account(mut, has_one = authority)]
    pub treasury: Account<'info, Treasury>,
    pub authority: Signer<'info>, // ← Required
    pub destination: Account<'info>,
}
```

## Token Extensions (2022)

### Metadata Pointer Not Verified
```rust
// VULN: Mint with metadata_pointer but no metadata validation
// Attack: Mint a fake token with same symbol as legitimate token
// Users could be tricked into signing for the wrong token

// CHECK: Verify metadata matches expected values
if mint.metadata_pointer.is_some() {
    let metadata = &ctx.accounts.metadata;
    require!(metadata.mint == mint.key(), ErrorCode::InvalidMetadata);
    require!(metadata.update_authority == expected_authority, ErrorCode::InvalidUpdateAuth);
}
```

### Mint Close Authority
```rust
// VULN: Mint close authority not checked before sensitive operations
// If mint close authority is set, mint can be closed at any time
// All token accounts become unusable

// CHECK:
if let Some(close_authority) = mint.mint_close_authority {
    require!(close_authority == expected_authority, ErrorCode::UnauthorizedClose);
}
```

### Confidential Transfer Fee
```rust
// VULN: settling confidential transfers without extracting fee
// The fee is embedded in the transfer and must be extracted by the receiver

// CHECK: When settling, verify fee accounts and amounts
```

## Sealevel Runtime

### Unsigned Transaction via `invoke`
```rust
// VULN: invoke without is_signer check
// Solana's invoke doesn't automatically verify signer on the calling instruction's accounts
// The program MUST check is_signer itself if required

// FIX:
msg!("Require signer");
if !ctx.accounts.authority.is_signer {
    return Err(ErrorCode::NotSigner.into());
}
```

### Non-writable Account Modification Attempt
```rust
// Anchor will reject writes to non-mut accounts at runtime
// But during CPI, a program can mark accounts as writable in the
// AccountMeta it constructs. This is a runtime constraint.

// CHECK: When processing CPI results, re-validate account states
// Don't trust account data from CPI'd programs
```

## Program Derived Addresses

### Seed Collision
```rust
// VULN: Hardcoded bump with find_program_address
let (pda, bump) = Pubkey::find_program_address(&[b"seed"], program_id);
// Then used directly — if another caller uses different bump, wrong PDA

// FIX: Always use canonical bump
let bump = bump_seed; // from find_program_address
// Verify bump is canonical before using
```

### User-Provided Seeds
```rust
// VULN: User controls seed derivation
let pda = Pubkey::create_program_address(
    &[b"vault", user.key().as_ref(), user_seed.as_bytes()],
    program_id,
)?;
// Attacker can find collision by varying user_seed

// FIX: Never derive PDAs from user-provided seeds without hashing
// Or use a fixed namespace + user key only
```

## Static Analysis Commands

```bash
# Anchor build (finds some issues)
anchor build 2>&1

# IDL generation (validates account constraints)
anchor build --output idl 2>&1

# sealevel constraints (via Anchor)
anchor check 2>&1

# Security-focused grep patterns
grep -rn "invoke\|invoke_signed\|create_program_address\|find_program_address" \
  --include="*.rs" src/

# Check for rawbors  (sealevel bypass)
grep -rn "unsafe\|unwrap()\|expect(" --include="*.rs" src/

# Check no panics in instruction handlers
grep -rn "panic!\|unreachable!\|todo!()" --include="*.rs" src/
```

## Next Phase
After static analysis → load `skill/03-formal-verification.md` for invariant proofs.