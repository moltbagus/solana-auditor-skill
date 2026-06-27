// REGRESSION TEST: VULN-09 (MEDIUM)
// Tests that failed CPI calls PROPAGATE error, not succeed silently.
// Vulnerable code: `let _ = invoke(...)` discards result.
// Fixed code: `invoke(...)` uses `?` to propagate errors.

#[tokio::test]
async fn test_vuln-09_cpi_error_propagates() {
    let program = ProgramTest::bpf("vault", program_id)
        .start_with_context()
        .await;

    let user = Keypair::new();

    // Non-existent program — CPI will fail
    let invalid_program = Pubkey::new_unique();

    let accounts = vec![
        AccountMeta::new_readonly(invalid_program, false),
    ];

    let ix = Instruction {
        program_id,
        accounts,
        data: vault::instruction::UncheckedCpi { data: vec![1, 2, 3] }.data(),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&program.purse()),
        &[&user],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );

    // Vulnerable: tx succeeds (CPI error discarded)
    // Fixed: tx fails (CPI error propagated via ?)
    let result = program.rpc().process_transaction(&tx).await;
    assert!(
        result.is_err(),
        "{fid}: Failed CPI must propagate error, not succeed silently (0 NOT FIXED)",
    );
}
