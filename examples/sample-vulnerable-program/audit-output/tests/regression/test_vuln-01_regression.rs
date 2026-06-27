// REGRESSION TEST: VULN-01 (CRITICAL)
// Tests that admin_withdraw REJECTS calls where admin field is not a signer.
// Vulnerable code: admin is AccountInfo — no is_signer check.
// Fixed code: admin is Signer<'info> — Anchor enforces at deserialization.

#[tokio::test]
async fn test_vuln-01_rejects_non_signer() {
    let program = ProgramTest::bpf("vault", program_id)
        .start_with_context()
        .await;

    let payer = program.payer();
    let (vault_pda, _) = Pubkey::find_program_address(&[b"vault"], &program_id);

    // Fund vault
    let vault_initial = 10_000_000_000u64;
    program.rpc().transfer(payer.pubkey(), vault_pda, vault_initial).await.unwrap();

    // Attacker key — NOT a signer for the admin field
    let attacker = Keypair::new();

    let accounts = vec![
        AccountMeta::new(vault_pda, false),
        AccountMeta::new_readonly(attacker.pubkey(), false), // admin — NOT signer
        AccountMeta::new(attacker.pubkey(), false),          // destination
    ];

    let ix = Instruction {
        program_id,
        accounts,
        data: vault::instruction::AdminWithdraw { amount: vault_initial }.data(),
    };

    // Transaction signed by payer ONLY — admin field belongs to attacker
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],  // Only payer signs; attacker does NOT sign admin field
        program.rpc().get_latest_blockhash().await.unwrap(),
    );

    let result = program.rpc().process_transaction(&tx).await;

    // MUST fail — vulnerable code accepts; fixed code uses Signer<'info>
    assert!(
        result.is_err(),
        "0: Non-signer admin must be rejected (0 NOT FIXED)",
    );

    // Verify vault untouched
    let vault_balance = program.rpc().get_balance(vault_pda).await.unwrap();
    assert_eq!(
        vault_balance, vault_initial,
        "0: Vault was drained — 0 still exploitable",
    );
}
