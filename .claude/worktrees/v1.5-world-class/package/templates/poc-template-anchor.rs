//! PoC template — Type A: Anchor Rust test
//!
//! Usage:
//!   1. Copy this file: `cp templates/poc-template-anchor.rs tests/poc-<FINDING_ID>.rs`
//!   2. Replace FINDING_ID, FINDING_TITLE, and INSTRUCTION_NAME
//!   3. Fill in the malicious instruction construction
//!   4. Add to the example's test suite: `anchor test`
//!
//! IMPORTANT: PoCs are run against the *vulnerable* program to confirm
//! exploitability. They MUST be reviewed before execution. See
//! `commands/audit-poc.md` for the consent gate.

use anchor_lang::prelude::*;
use solana_program_test::{ProgramTest, tokio};
use solana_sdk::{signature::Keypair, signer::Signer, transaction::Transaction};

#[tokio::test]
async fn test_poc_FINDING_ID() {
    // Replace with the actual program ID from the audited target
    let program_id = Pubkey::new_unique();
    let program_test = ProgramTest::new(
        "TARGET_PROGRAM_NAME", // e.g., "vault"
        program_id,
        processor!(TARGET_PROGRAM_NAME::entry),
    );

    // Pre-state setup
    let attacker = Keypair::new();
    program_test.add_account(
        attacker.pubkey(),
        solana_sdk::account::Account {
            lamports: 10_000_000_000,
            ..Default::default()
        },
    );

    let mut context = program_test.start_with_context().await;

    // ============================================================
    // STEP 1: Set up the preconditions for the vulnerability
    // ============================================================
    // Example: fund the program, create victim accounts, mint tokens, etc.

    // ============================================================
    // STEP 2: Construct the malicious instruction
    // ============================================================
    // Replace with the actual instruction that triggers FINDING_TITLE
    let malicious_ix = TARGET_PROGRAM_NAME::instruction::INSTRUCTION_NAME(
        // ...malicious args...
    );

    // ============================================================
    // STEP 3: Submit the transaction
    // ============================================================
    let tx = Transaction::new_signed_with_payer(
        &[malicious_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );

    // ============================================================
    // STEP 4: Assert exploit succeeded
    // ============================================================
    let result = context.banks_client.process_transaction(tx).await;
    assert!(
        result.is_ok(),
        "FINDING_ID confirmed: <describe exploit outcome>"
    );

    // ============================================================
    // STEP 5: Verify post-state matches attacker's goal
    // ============================================================
    // Example: vault balance should be 0, attacker should have +N lamports, etc.
}
