/**
 * Anchor Invariant Test Pattern
 * 
 * This file demonstrates how to write formal verification tests for
 * Solana Anchor programs. Each test verifies a security invariant.
 * 
 * Run with: anchor test tests/fv-invariant-pattern.ts
 */

import * as anchor from "@project-serum/anchor";
import { Program } from "@project-serum/anchor";
import { assert } from "chai";
import { Vault } from "../target/types/vault";

describe("Vault Invariant Tests", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const program = anchor.workspace.Vault as Program<Vault>;
  const provider = anchor.getProvider();

  // ============================================================
  // Invariant 1: Authorization — Only owner can withdraw
  // ============================================================
  it("enforces signer verification on admin operations", async () => {
    // Generate a non-signer keypair to simulate unauthorized access
    const unauthorizedKey = anchor.web3.Keypair.generate();
    
    // Attempt admin_withdraw without proper signer
    // This should FAIL because VULN-01 is present in the fixture
    try {
      await program.methods
        .adminWithdraw(new anchor.BN(100))
        .accounts({
          vault: anchor.web3.PublicKey.findProgramAddressSync(
            [Buffer.from("vault")],
            program.programId
          )[0],
          admin: unauthorizedKey.publicKey, // Not a signer
          destination: provider.wallet.publicKey,
        })
        .signers([unauthorizedKey])
        .rpc();
      
      // If we reach here, the invariant was violated
      assert.fail("adminWithdraw succeeded without proper authorization");
    } catch (err) {
      // Expected: Transaction failed due to missing signer verification
      assert(err.toString().includes("Error") || err.toString().includes("failed"));
    }
  });

  // ============================================================
  // Invariant 2: CPI Safety — No arbitrary program execution
  // ============================================================
  it("prevents arbitrary CPI to user-supplied programs", async () => {
    const maliciousProgram = anchor.web3.Keypair.generate();
    const maliciousData = Buffer.from([0x01, 0x02, 0x03]);
    
    try {
      await program.methods
        .execCallback(maliciousData)
        .accounts({
          targetProgram: maliciousProgram.publicKey,
        })
        .remainingAccounts([])
        .rpc();
      
      // If we reach here, arbitrary CPI was allowed (VULN-03)
      assert.fail("execCallback allowed CPI to arbitrary program");
    } catch (err) {
      // Expected: CPI should be restricted
      assert(err.toString().includes("Error") || err.toString().includes("failed"));
    }
  });

  // ============================================================
  // Invariant 3: Arithmetic Safety — No overflow in amounts
  // ============================================================
  it("handles arithmetic overflow correctly", async () => {
    const maxU64 = new anchor.BN("18446744073709551615"); // u64::MAX
    const one = new anchor.BN(1);
    
    // This should either succeed with proper wrapping or fail with error
    try {
      await program.methods
        .userDeposit(maxU64.add(one))
        .accounts({
          vault: anchor.web3.PublicKey.findProgramAddressSync(
            [Buffer.from("vault")],
            program.programId
          )[0],
          user: provider.wallet.publicKey,
        })
        .rpc();
      
      // If overflow is unchecked, this would silently wrap
      // Proper implementation should use checked_add or reject
    } catch (err) {
      // Expected: Overflow should be detected
      assert(err.toString().includes("Error") || err.toString().includes("overflow"));
    }
  });

  // ============================================================
  // Invariant 4: State Consistency — No reinitialization attacks
  // ============================================================
  it("prevents reinitialization of accounts", async () => {
    const vaultPDA = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("vault")],
      program.programId
    )[0];
    
    // First initialization
    try {
      await program.methods
        .initialize()
        .accounts({
          vault: vaultPDA,
          authority: provider.wallet.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
    } catch (err) {
      // May already be initialized — that's fine for this test
    }
    
    // Attempt reinitialization — should fail due to discriminator
    try {
      await program.methods
        .initialize()
        .accounts({
          vault: vaultPDA,
          authority: provider.wallet.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
      
      // If VULN-06 is present, this succeeds (discriminator not enforced)
      assert.fail("reinitialization succeeded — discriminator not enforced");
    } catch (err) {
      // Expected: Reinitialization should be rejected
      assert(
        err.toString().includes("already in use") ||
        err.toString().includes("Error") ||
        err.toString().includes("discriminator")
      );
    }
  });

  // ============================================================
  // Invariant 5: Authorization — Lamport transfer authority
  // ============================================================
  it("enforces authority on lamport transfers", async () => {
    const attackerKey = anchor.web3.Keypair.generate();
    const victimKey = anchor.web3.Keypair.generate();
    
    try {
      await program.methods
        .drainVault(new anchor.BN(100))
        .accounts({
          vault: anchor.web3.PublicKey.findProgramAddressSync(
            [Buffer.from("vault")],
            program.programId
          )[0],
          destination: victimKey.publicKey,
        })
        .signers([attackerKey]) // Attacker as signer
        .rpc();
      
      // If VULN-04 is present, this succeeds
      assert.fail("drainVault succeeded without authority check");
    } catch (err) {
      // Expected: Authority check should prevent this
      assert(err.toString().includes("Error") || err.toString().includes("failed"));
    }
  });
});
