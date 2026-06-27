// REGRESSION TEST: VULN-06 (MEDIUM)
// Tests that initialize() REJECTS reinit on an already-initialized account.
// Vulnerable code: no #[account] on VaultState — no discriminator written/checked.
// Fixed code: #[account] + Account<'info, VaultState> enforces 8-byte discriminator.

#[tokio::test]
async fn test_vuln-06_reinit_blocked() {
    let program = ProgramTest::bpf("vault", program_id)
        .start_with_context()
        .await;

    let payer = program.purse();
    let attacker = Keypair::new();

    let (vault_pda, _) = Pubkey::find_program_address(&[b"vault"], &program_id);

    // Fund to rent-exempt
    let rent = program.rpc().get_minimum_balance_for_rent_exemption(0).await.unwrap();
    program.rpc().transfer(payer, vault_pda, rent).await.unwrap();

    // First initialize (attacker is authority)
    let init_ix = vault::instruction::Initialize { authority: attacker.pubkey() };
    let init_tx = Transaction::new_signed_with_payer(
        &[init_ix],
        Some(&payer),
        &[&attacker],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );
    program.rpc().process_transaction(init_tx).await.unwrap();

    // Second initialize — reinit attack with stolen authority
    let stolen_authority = Keypair::new();
    let reinit_ix = vault::instruction::Initialize { authority: stolen_authority.pubkey() };
    let reinit_tx = Transaction::new_signed_with_payer(
        &[reinit_ix],
        Some(&payer),
        &[&attacker],
        program.rpc().get_latest_blockhash().await.unwrap(),
    );

    let result = program.rpc().process_transaction(reinit_tx).await;

    // MUST fail — discriminator check prevents reinit
    assert!(
        result.is_err(),
        "{fid}: Reinit attack must be blocked (0 NOT FIXED)",
    );
}
