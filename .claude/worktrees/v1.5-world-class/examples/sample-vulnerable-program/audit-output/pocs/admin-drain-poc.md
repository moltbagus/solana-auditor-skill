# PoC: VULN-01 - Admin Signer Bypass Allows Full Vault Drain

**Finding ID**: VULN-01
**Title**: Admin withdraw lacks signer verification — CRITICAL
**Severity**: CRITICAL
**CVSS**: 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
**CWE**: CWE-306 (Missing Authentication for Critical Function)
**Rule caught**: Rule 8 — Signer Verification

---

## Exploit Path

1. **Attacker obtains the vault program ID and its deployed address.** The `admin_withdraw` instruction is publicly callable — it accepts any transaction, not just ones signed by a legitimate admin key.

2. **Attacker constructs a transaction invoking `admin_withdraw`.** In the transaction's account list, the attacker supplies their own wallet address (or any arbitrary pubkey they control) as the `admin` field. Anchor does NOT enforce signer verification on `AccountInfo` — it only checks that the account exists on-chain. The `admin` field in the `AdminWithdraw` struct is declared as `AccountInfo<'info>`, which does not call `is_signer` under the hood.

3. **Attacker specifies any `destination` account** — their own wallet, a freshly generated address, or any account they control. The instruction accepts it without validation.

4. **Attacker sets `amount` equal to the vault's full lamport balance (minus rent-exempt reserve).** The `admin_withdraw` function subtracts from `vault.lamports` and adds to `destination.lamports` with no bounds check and no ownership verification.

5. **Transaction is submitted and confirmed.** Because the instruction logic performs no signer check, no `has_one` constraint, and no ownership validation, the raw lamport transfer succeeds. The vault is drained.

---

## Impact

**An attacker who compromises the admin key (or simply passes any pubkey in the admin slot) can drain the entire vault to any destination of their choosing.**

The vulnerability is especially dangerous because:
- No privileged position is required — the instruction is publicly callable.
- The "admin" field is cosmetic. It is read but never verified against any stored authority.
- A single transaction empties the vault completely. There is no timelock, no multisig gate, no rate limit.
- Even if the real admin key is not compromised, an off-path attacker can invoke the instruction with a bogus `admin` pubkey because the program never checks who signed the transaction.

Real-world consequence: users who deposited funds into the vault lose everything. There is no recovery path because lamports are transferred to an attacker-controlled account, and Solana does not support reversible transactions.

---

## Remediation

**Step 1 — Change `AccountInfo` to `Signer` on the admin field.**

```rust
// BEFORE (vulnerable)
#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    #[account(mut)]
    pub vault: AccountInfo<'info>,
    /// CHECK: VULN-01 — should be Signer but is unverified AccountInfo.
    pub admin: AccountInfo<'info>,   // ← accepts any pubkey
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

// AFTER (fixed)
#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    #[account(mut, has_one = admin)]   // ← Anchor verifies admin signed + matches stored authority
    pub vault: Account<'info, VaultState>,
    pub admin: Signer<'info>,           // ← Anchor enforces is_signer check
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}
```

**Step 2 — Add `has_one` constraint to bind the admin to the vault's stored authority.**

The `#[account(has_one = admin)]` constraint on the vault field instructs Anchor to verify that the vault's stored `authority` field equals the supplied `admin` pubkey. This prevents an attacker from passing a valid signer that is simply not the vault's authority.

**Step 3 — Derive the vault PDA using canonical bumps.**

Use `find_program_address` or `ctx.bumps.vault` to derive the vault PDA at runtime. This prevents collisions from non-canonical bumps (see VULN-02).

**Step 4 — Validate the destination.**

Either restrict the destination to a known recipient (e.g., a PDA derived from the admin key) or require the admin to cosign the transfer with a second approval instruction.

---

## Verification Checklist

- [ ] `admin: AccountInfo<'info>` replaced with `admin: Signer<'info>`
- [ ] `vault: AccountInfo<'info>` replaced with `vault: Account<'info, VaultState>`
- [ ] `#[account(has_one = admin)]` constraint added to `vault` field
- [ ] Vault `VaultState` struct has `#[account]` attribute (discriminator enforcement)
- [ ] `admin_withdraw` called with a non-admin signer fails with `SignerViolation` or `has_one` constraint error
- [ ] `admin_withdraw` called with the correct admin key succeeds
- [ ] Transaction that drains the vault using a bogus admin pubkey reverts
