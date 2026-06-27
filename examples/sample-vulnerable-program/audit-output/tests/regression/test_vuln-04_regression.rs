// REGRESSION TEST: VULN-04 (CRITICAL)
// Tests that drain_vault REJECTS calls where destination is attacker-controlled.
// Vulnerable code: no authority signer, no has_one constraint.
// Fixed code: authority: Signer<'info> + #[account(has_one = authority)].

#[tokio::test]
async fn test_vuln-04_rejects_attacker_destination() {
    let program = ProgramTest::bpf("vault", program_id)
        .start_with_context()
        .await;

    let payer = program.purse();
    let (vault_pda, _) = Pubkey::find_program_address(&[b"vault"], &program_id);

    let vault_balance = 5_000_000_000u64;
    program.rpc().transfer(payer, vault_pda, vault_balance).await.unwrap();

    // Attacker-controlled destination
    let attacker_dest = Keypair::new();

    let accounts = vec![
        AccountMeta::new(vault_pda, false),
        AccountMeta::new(attacker_dest.pubkey(), false), // attacker-supplied
    ];

    let ix = Instruction {
        program_id,
        accounts,
        data: vault::instruction::DrainVault { amount: vault_balance }.data(),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer),
        &[&program.wallet()],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );

    let result = program.rpc().process_transaction(&tx).await;

    assert!(
        result.is_err(),
        "0: drain_vault to arbitrary dest must be rejected (0 NOT FIXED)",
    );

    let final_balance = program.rpc().get_balance(vault_pda).await.unwrap();
    assert_eq!(
        final_balance, vault_balance,
        "0: Vault was drained — 0 still open",
    );
}
