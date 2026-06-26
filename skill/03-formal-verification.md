# Phase 3: Formal Verification

**Goal**: Prove or disprove security invariants using automated tools.

> **Note**: QED 2A requires `anchor` + `solana-test-validator` to be installed. In CI (GitHub Actions), formal verification is skipped gracefully. Run `anchor test` locally to exercise the verification patterns.

## Solana Formal Verification Tools

### QED 2A (Primary)
QED's automated verification tool for Solana programs:
- Website: https://qeda.app (or https://github.com/QEDGen/solana-qed)
- Proves invariants without manual Coq/Lean proofs
- Best for: Token programs, AMMs, staking programs

```bash
# Install QED 2A
cargo install qed-solana 2>/dev/null || \
  git clone https://github.com/QEDGen/solana-qed.git && cd solana-qed && cargo build --release

# Run verification
qed-solana verify --program target/deploy/PROGRAM.so --idl target/idl/PROGRAM.json
```

## Key Invariants to Verify

### 1. Token Conservation
```
total_supply = sum(all_token_accounts.balance)
vault.balance = sum(deposits) - sum(withdrawals)
No mint without corresponding deposit
```

### 2. Authorization
```
Only owner can transfer tokens
Only admin can update config
Upgrade authority is as expected
No privileged operation without signer
```

### 3. PDA Integrity
```
PDA derived from correct seeds
Canonical bump always used
No PDA collision possible
```

### 4. Arithmetic Safety
```
No overflow/underflow in amounts
Fee calculations always correct
Shares don't exceed underlying value
```

### 5. State Consistency
```
Account state transitions are valid
No invalid state reached from valid state
Initialization is idempotent (can't reinit)
```

## Formal Verification Workflow

### Step 1: Define Invariants as Test Cases

Anchor's test framework uses standard Rust test assertions. Define invariants as test functions that verify conditions:

```rust
// tests/invariants.rs
use anchor_lang::prelude::*;
use solana_program_test::*;

#[tokio::test]
async fn test_token_supply_conservation() {
    let mut program_test = ProgramTest::new(
        "my_program",
        my_program::ID,
        processor!(my_program::processor),
    );

    // Set up test context with known initial state
    let (mut banks_client, payer, _blockhash) = program_test.start().await;

    // Invoke the instruction under test
    my_program::instruction::deposit(&mut banks_client, &payer, amount)
        .await
        .unwrap();

    // Verify invariant: vault + user balances = original supply
    let vault = banks_client.get_account(vault_pubkey).await.unwrap().unwrap();
    let user = banks_client.get_account(user_pubkey).await.unwrap().unwrap();

    let vault_data = Vault::try_from(&vault.data[..]).unwrap();
    let user_data = UserAccount::try_from(&user.data[..]).unwrap();

    assert_eq!(
        vault_data.balance + user_data.balance,
        initial_supply,
        "Token supply must be conserved"
    );
}

#[tokio::test]
async fn test_authorization_enforced() {
    let mut program_test = ProgramTest::new(
        "my_program",
        my_program::ID,
        processor!(my_program::processor),
    );

    // Create non-signer authority
    let (mut banks_client, payer, _blockhash) = program_test.start().await;

    // Attempt unauthorized operation - must fail
    let result = my_program::instruction::admin_update(
        &mut banks_client,
        &non_signer_keypair.pubkey(),  // Not a signer
        new_value,
    ).await;

    assert!(result.is_err(), "Non-authorized call must be rejected");
}
```

### Step 2: Run Anchor Tests
```bash
anchor test 2>&1
# or for specific test file
anchor test tests/invariants.rs 2>&1
```

### Step 3: Run QED 2A
```bash
qed-solana verify \
  --program target/deploy/PROGRAM.so \
  --invariants tests/invariants/ \
  --timeout 300
```

### Step 4: Review Counterexamples
```bash
# If QED finds a counterexample:
# 1. Read the initial state
# 2. Read the violating instruction sequence
# 3. Map back to source code
# 4. Create a PoC exploit test
```

## Anchor Specific FV

### Discriminator Uniqueness
```rust
// Prove: No two account types share a discriminator
// QED check: 
//   - derive() on all #[account] structs
//   - verify no collision in first 8 bytes

// Manual check:
grep -rn "DISCRIMINATOR\|anchor_attribute" src/ | head -50
```

### Bump Canonicalization
```rust
// Prove: Using non-canonical bump is impossible
// Check: all PDA derivations use find_program_address (not create_program_address)
// And bump is stored, not passed as parameter
```

### CPI Bounds
```rust
// Prove: CPI'd program can't bypass instruction constraints
// Check: all invoke_signed calls use seeds derived from on-chain data
// Not from caller-provided untrusted data
```

## Writing FV Test Cases

```rust
#[tokio::test]
async fn test_no_overflow() {
    let program = ProgramTest::bpf("vault", 
        program_id).start_with_context().await;
    
    let ctx = program.context.clone();
    
    // Attempt deposit that would overflow
    let overflow_amount = u64::MAX - ctx.accounts.vault.amount + 1;
    let result = program.rpc.call_vault_deposit(overflow_amount).await;
    
    // Expect rejection
    assert!(result.is_err());
}

#[tokio::test]  
async fn test_signer_auth_required() {
    let program = ProgramTest::bpf("vault", 
        program_id).start_with_context().await;
    
    let mut ctx = program.context.clone();
    ctx.accounts.authority.is_signer = false; // Simulate non-signer
    
    let result = program.rpc.call_vault_withdraw(ctx, 100).await;
    
    // Expect rejection
    assert!(result.is_err());
}
```

## Fallback: Anchor Test Verification

Without QED 2A, run the built-in anchor test that demonstrates the invariant patterns:

```bash
cd examples/sample-vulnerable-program
anchor test
```

This exercises the QED-equivalent invariant checks via `anchor test` against the fixture.

## Next Phase
After formal verification → load `skill/04-findings-triage.md` to classify findings.
