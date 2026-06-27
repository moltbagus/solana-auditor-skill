// REGRESSION TEST: VULN-03 (HIGH)
// Tests that exec_callback REJECTS calls to arbitrary programs.
// Vulnerable code: no program allowlist, user passes target_program directly.
// Fixed code: validates against allowlist or uses Program<'info, KnownProgram>.

#[tokio::test]
async fn test_vuln-03_rejects_arbitrary_program() {
    let program = ProgramTest::bpf("vault", program_id)
        .start_with_context()
        .await;

    // System Program as stand-in for arbitrary program
    let malicious_program = system_program::ID;

    let attacker = Keypair::new();

    let accounts = vec![
        AccountMeta::new_readonly(malicious_program, false),
    ];

    let ix = Instruction {
        program_id,
        accounts,
        data: vault::instruction::ExecCallback {
            data: vec![1, 2, 3],
        }.data(),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&program.purse()),
        &[&attacker],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );

    let result = program.rpc().process_transaction(&tx).await;

    assert!(
        result.is_err(),
        "{fid}: Arbitrary CPI must be rejected (0 NOT FIXED)",
    );
}
