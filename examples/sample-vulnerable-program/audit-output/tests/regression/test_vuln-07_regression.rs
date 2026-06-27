// REGRESSION TEST: VULN-07 (MEDIUM)
// Tests that calc_shares REJECTS zero-share results from truncation.
// Vulnerable code: `/` truncates, small deposits get 0 shares silently.
// Fixed code: checked_div + minimum share threshold enforcement.

#[tokio::test]
async fn test_vuln-07_minimum_share_enforced() {
    let program = ProgramTest::bpf("vault", program_id)
        .start_with_context()
        .await;

    let user = Keypair::new();
    let (vault_pda, _) = Pubkey::find_program_address(&[b"vault"], &program_id);

    // divisor >> deposit — truncation gives 0 shares
    let deposit = 1u64;
    let divisor = u64::MAX;

    let accounts = vec![
        AccountMeta::new(vault_pda, false),
        AccountMeta::new(user.pubkey(), false),
    ];

    let ix = Instruction {
        program_id,
        accounts,
        data: vault::instruction::CalcShares { deposit, divisor }.data(),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&program.purse()),
        &[&user],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );

    // Vulnerable: returns 0 shares, tx succeeds
    // Fixed: returns BelowMinimum or DivisionByZero error
    let result = program.rpc().process_transaction(&tx).await;
    assert!(
        result.is_err(),
        "0: Zero shares from truncation must be rejected (0 NOT FIXED)",
    );
}
