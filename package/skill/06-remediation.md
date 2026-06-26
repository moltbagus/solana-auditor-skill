# Phase 6: Remediation Guidance

**Goal**: Guide secure fix implementation and verify fixes don't introduce regressions.

## Fix Verification Workflow

```
1. Review the finding description
2. Understand root cause (not just symptom)
3. Implement fix
4. Run anchor build + tests
5. Run formal verification again
6. Check for regressions
7. Mark finding as resolved
```

## Common Fix Patterns

### Adding Signer Verification
```rust
// BEFORE (VULN):
pub fn admin_action(ctx: Context<Admin>) -> Result<()> {
    // No signer check
    Ok(())
}

// AFTER (FIXED):
pub fn admin_action(ctx: Context<Admin>) -> Result<()> {
    if !ctx.accounts.admin.is_signer {
        return Err(ErrorCode::NotSigner.into());
    }
    Ok(())
}

// ANCHOR WAY (better):
#[derive(Accounts)]
pub struct Admin<'info> {
    pub admin: Signer<'info>, // Anchor enforces signer at deserialization
}
```

### Adding Owner Check
```rust
// BEFORE:
let token_account = &ctx.accounts.user_token;

// AFTER (explicit check):
require!(
    token_account.owner == ctx.accounts.token_program.key(),
    ErrorCode::WrongTokenOwner
);

// ANCHOR WAY:
#[derive(Accounts)]
pub struct Transfer<'info> {
    pub from: Account<'info, TokenAccount>, // Anchor validates owner
    pub to: Account<'info, TokenAccount>,
}
```

### Overflow-Safe Arithmetic
```rust
// BEFORE:
let new_amount = old_amount + deposit;

// AFTER:
let new_amount = old_amount.checked_add(deposit)
    .ok_or(ErrorCode::Overflow)?;

// Or with custom error:
match old_amount.checked_add(deposit) {
    Some(v) => v,
    None => return Err(OverflowError.into()),
}
```

### Bump Canonicalization
```rust
// BEFORE (non-canonical bump):
let bump = ctx.bumps.get("vault").unwrap();
let seeds = &[b"vault", user.as_ref(), &[bump]];
let (pda, expected_bump) = Pubkey::find_program_address(seeds, program_id);

// AFTER (canonical bump):
let bump = *ctx.bumps.get("vault").unwrap();
let seeds = &[b"vault", user.as_ref(), &[bump]];
let (pda, _) = Pubkey::find_program_address(seeds, program_id);
// Canonical bump is always the one returned by find_program_address
// ctx.bumps already gives canonical bump from Anchor 0.30+
```

### Reinitialization Guard
```rust
#[derive(Accounts)]
pub struct InitVault<'info> {
    #[account(
        init,
        space = 8 + Vault::LEN,
        payer = user,
        seeds = [b"vault", user.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

// Add check in instruction body:
pub fn init_vault(ctx: Context<InitVault>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    require!(vault.bump == 0, ErrorCode::AlreadyInitialized); // or check is_empty()
    vault.bump = *ctx.bumps.get("vault").unwrap();
    vault.authority = ctx.accounts.user.key();
    Ok(())
}
```

## Regression Testing

```bash
# After any fix, run:
anchor build
anchor test

# Formal verification again
qed-solana verify --program target/deploy/PROGRAM.so --invariants tests/invariants/

# Specific regression test for the finding
anchor test --grep "admin_withdraw"
```

## Post-Fix Checklist

- [ ] Fix compiles without warnings
- [ ] All existing tests pass
- [ ] New test covers the finding scenario
- [ ] Formal verification passes on fixed code
- [ ] Fix doesn't introduce new findings
- [ ] Finding marked as "Fixed" in findings DB

## Exploit PoC Verification

```rust
#[tokio::test]
async fn test_exploit_poc_crit01_fixed() {
    // Arrange: Set up exploit conditions
    let program = ProgramTest::bpf("vault", program_id).start_with_context().await;
    
    // Act: Attempt the exploit
    let result = program.rpc.call_admin_withdraw_unsiged(
        malicious_instruction_data
    ).await;
    
    // Assert: Should fail now
    assert!(result.is_err());
    // Check error matches expected:
    assert!(matches!(result.unwrap_err(), anchor_lang::error::Error ...));
}
```
