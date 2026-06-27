// REGRESSION TEST: VULN-05 (HIGH)
// Tests that deposit REJECTS overflow amounts.
// Vulnerable code: unchecked `+` wraps silently in release mode.
// Fixed code: checked_add returns error on overflow.

#[tokio::test]
async fn test_vuln-05_overflow_rejected() {
    let program = ProgramTest::bpf("vault", program_id)
        .start_with_context()
        .await;

    let payer = program.purse();
    let user = Keypair::new();
    let (vault_pda, _) = Pubkey::find_program_address(&[b"vault"], &program_id);

    program.rpc().transfer(payer, vault_pda, 2_000_000_000).await.unwrap();

    // u64::MAX will wrap on unchecked add
    let overflow_amount = u64::MAX;

    let accounts = vec![
        AccountMeta::new(vault_pda, false),
        AccountMeta::new_readonly(user.pubkey(), true),
    ];

    let ix = Instruction {
        program_id,
        accounts,
        data: vault::instruction::UserDeposit { amount: overflow_amount }.data(),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer),
        &[&user],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );

    let result = program.rpc().process_transaction(&tx).await;

    assert!(
        result.is_err(),
        "0: Overflow deposit must be rejected (0 NOT FIXED)",
    );
}

#[tokio::test]
async fn test_vuln-05_u64_max_edge_case() {
    // Exact edge: vault at u64::MAX - 1, deposit u64::MAX → overflow
    let program = ProgramTest::bpf("vault", program_id)
        .start_with_context()
        .await;

    let user = Keypair::new();
    let (vault_pda, _) = Pubkey::find_program_address(&[b"vault"], &program_id);

    program.rpc().transfer(program.purse(), vault_pda, u64::MAX - 1).await.unwrap();

    let accounts = vec![
        AccountMeta::new(vault_pda, false),
        AccountMeta::new_readonly(user.pubkey(), true),
    ];

    let ix = Instruction {
        program_id,
        accounts,
        data: vault::instruction::UserDeposit { amount: u64::MAX }.data(),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&program.purse()),
        &[&user],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );

    // Vulnerable: wraps silently (tx succeeds, balance corrupted)
    // Fixed: returns ArithmeticOverflow error
    let result = program.rpc().process_transaction(&tx).await;
    assert!(
        result.is_err(),
        "0: u64::MAX + (u64::MAX - 1) must overflow — 0 fix not applied",
    );
}
