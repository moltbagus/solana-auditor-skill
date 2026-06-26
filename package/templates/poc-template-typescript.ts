/**
 * PoC template — Type B: TypeScript script
 *
 * Usage:
 *   1. Copy this file: `cp templates/poc-template-typescript.ts poc/<FINDING_ID>.ts`
 *   2. Replace FINDING_ID, FINDING_TITLE, INSTRUCTION_NAME
 *   3. Fill in the malicious instruction construction
 *   4. Run with: `npx ts-node poc/<FINDING_ID>.ts`
 *
 * IMPORTANT: PoCs are run against the *vulnerable* program to confirm
 * exploitability. They MUST be reviewed before execution. See
 * `commands/audit-poc.md` for the consent gate.
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Keypair, PublicKey } from "@solana/web3.js";

// Configuration
const RPC_URL = process.env.RPC_URL ?? "http://127.0.0.1:8899";
const PROGRAM_ID_PLACEHOLDER = "YOUR_PROGRAM_ID_HERE";
const PROGRAM_ID = new PublicKey(PROGRAM_ID_PLACEHOLDER);

if (PROGRAM_ID.toBase58() === PROGRAM_ID_PLACEHOLDER) {
    throw new Error(
        "Replace PROGRAM_ID with the deployed program ID (base58). " +
        "PublicKey ctor would otherwise throw on the literal placeholder."
    );
}

async function main() {
    // ============================================================
    // STEP 1: Connect to cluster and load wallet
    // ============================================================
    const connection = new anchor.web3.Connection(RPC_URL, "confirmed");
    const wallet = anchor.Wallet.local();
    const provider = new anchor.AnchorProvider(connection, wallet, {
        commitment: "confirmed",
    });
    anchor.setProvider(provider);

    // @ts-expect-error — replace with the typed IDL after `anchor build`
    const program = new Program({}, provider) as Program;

    // ============================================================
    // STEP 2: Construct the malicious instruction
    // ============================================================
    // Replace with the actual instruction that triggers FINDING_TITLE
    const attacker = Keypair.generate();

    const maliciousIx = await program.methods
        .INSTRUCTION_NAME(
            // ...malicious args...
        )
        .accounts({
            // ...accounts...
        })
        .instruction();

    // ============================================================
    // STEP 3: Submit the transaction
    // ============================================================
    const tx = new anchor.web3.Transaction().add(maliciousIx);
    try {
        const signature = await anchor.web3.sendAndConfirm(
            provider.connection,
            tx,
            [wallet.payer],
        );
        console.log("FINDING_ID confirmed. Signature:", signature);
    } catch (err) {
        console.error("PoC failed:", err);
        process.exit(1);
    }
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
