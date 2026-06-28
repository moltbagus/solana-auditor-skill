# NFT Candy Machine — Security Audit Report

**Target**: `examples/nft-candy-machine/` (3 programs)
**Date**: 2026-06-29
**Severity Distribution**: Critical: 1 | High: 7 | Medium: 6 | Low: 0 | Info: 0
**Total Findings**: 14

---

## Executive Summary

This audit examined three Solana programs in the NFT candy machine fixture: `candy-machine` (6 functions), `nft-minter` (4 functions), and `metadata` (4 functions). The audit identified **14 security vulnerabilities** spanning 4 severity levels, with a concentration of high-severity issues in CPI safety, authorization, and initialization logic.

The most critical finding is **VULN-01**, a discriminator collision that enables type confusion at the instruction dispatch level, affecting the entire candy-machine program. Three programs exhibit missing or weak authorization controls (VULN-03, VULN-04, VULN-08), allowing unauthorized state modifications. Several findings involve improper cross-program invocation (CPI) patterns (VULN-06, VULN-11, VULN-13) that expose the programs to arbitrary code execution.

All 14 findings are classified as **Open** and require remediation before production deployment.

---

## Severity Table

| ID | Title | Severity | CVSS | CWE | Rule | Programs |
|----|-------|----------|------|-----|------|----------|
| VULN-01 | Discriminator collision — type confusion | CRITICAL | 9.8 | CWE-843 | 16 | candy-machine |
| VULN-02 | Manual init without discriminator | MEDIUM | 6.5 | CWE-665 | 40 | candy-machine |
| VULN-03 | Account constraints bypassed | HIGH | 8.6 | CWE-20 | 2 | candy-machine |
| VULN-04 | Missing signer on admin config update | HIGH | 7.2 | CWE-306 | 8 | candy-machine |
| VULN-05 | Arithmetic overflow in item count | MEDIUM | 6.8 | CWE-190 | 6 | candy-machine |
| VULN-06 | Reentrancy via mint callback | HIGH | 7.5 | CWE-362 | 14 | candy-machine |
| VULN-07 | Token-2022 transfer fee not accounted | MEDIUM | 6.3 | CWE-20 | 5 | nft-minter |
| VULN-08 | Non-transferable bypass via hook | HIGH | 7.8 | CWE-862 | 33 | nft-minter |
| VULN-09 | init_if_needed without one-time bump | HIGH | 8.2 | CWE-665 | 22 | nft-minter |
| VULN-10 | Duplicate mutable account in batch mint | MEDIUM | 6.5 | CWE-366 | 38 | nft-minter |
| VULN-11 | Token-2022 transfer hook CPI routing | HIGH | 7.5 | CWE-347 | 27 | metadata |
| VULN-12 | Unsafe deserialization without owner check | MEDIUM | 5.9 | CWE-345 | 39 | metadata |
| VULN-13 | Arbitrary CPI via remaining_accounts | HIGH | 8.1 | CWE-347 | 4 | metadata |
| VULN-14 | Missing writable enforcement | MEDIUM | 5.3 | CWE-283 | 37 | metadata |

---

## Finding Details

### VULN-01 — Discriminator Collision (Type Confusion)

**Severity**: CRITICAL | **CVSS**: 9.8 | **CWE**: CWE-843 | **Rule**: 16
**Location**: `programs/candy-machine/src/lib.rs:101` (`mint`)

**Description**: Multiple instructions in the candy-machine program use the same 8-byte Anchor discriminator. Anchor derives instruction discriminators from the first 8 bytes of the SHA256 hash of the function name. When two or more public functions share the same discriminator, the runtime dispatches to whichever handler appears first in the dispatch table.

**Impact**: Complete execution context confusion. An attacker can trigger unintended instruction handlers — including admin operations, minting, or configuration changes — by submitting a transaction with the colliding discriminator.

**Recommendation**: Audit all public function names for hash collisions using Anchor's IDL tooling. Rename colliding functions to unique names. Add a comprehensive test suite validating each instruction discriminator is unique.

**Line Reference**: `programs/candy-machine/src/lib.rs:101`

---

### VULN-02 — Manual Init Without Anchor Discriminator

**Severity**: MEDIUM | **CVSS**: 6.5 | **CWE**: CWE-665 | **Rule**: 40
**Location**: `programs/candy-machine/src/lib.rs:122` (`init_machine`)

**Description**: The init_machine instruction manually sets CandyMachine fields without writing the 8-byte Anchor discriminator. Since init_machine bypasses the `#[account]` init mechanism, no discriminator is stored.

**Impact**: Reinitialization of candy machine state. An attacker who acquires a closed account's key can reinitialize the machine, resetting items_available and items_redeemed to arbitrary values.

**Recommendation**: Use Anchor's `#[account(init, ...)]` constraint to trigger automatic discriminator writing. Remove the manual field assignment pattern entirely.

**Line Reference**: `programs/candy-machine/src/lib.rs:122`

---

### VULN-03 — Account Constraints Bypassed

**Severity**: HIGH | **CVSS**: 8.6 | **CWE**: CWE-20 | **Rule**: 2
**Location**: `programs/candy-machine/src/lib.rs:131` (`set_authority`)

**Description**: The set_authority instruction accepts mint_account as AccountInfo with no `has_one` constraint, no signer check, and assigns `mint_account.authority = new_authority` directly.

**Impact**: Unauthorized mint authority transfer. An attacker can redirect the mint authority to a key they control, enabling arbitrary token minting.

**Recommendation**: Add `#[account(has_one = authority)]` on mint_account and change `authority: AccountInfo` to `authority: Signer`. Anchor's constraint system will verify the signing authority matches the stored authority.

**Line Reference**: `programs/candy-machine/src/lib.rs:131`

---

### VULN-04 — Missing Signer on Admin Config Update

**Severity**: HIGH | **CVSS**: 7.2 | **CWE**: CWE-306 | **Rule**: 8
**Location**: `programs/candy-machine/src/lib.rs:138` (`update_config`)

**Description**: The update_config instruction accepts `authority` as AccountInfo instead of Signer and performs no is_signer check.

**Impact**: Unauthorized price manipulation. An attacker can set the price to 0 (free minting) or an extreme value, disrupting the sale mechanism.

**Recommendation**: Change `authority: AccountInfo` to `authority: Signer`. Add `#[account(has_one = authority, mut)]` on the config field.

**Line Reference**: `programs/candy-machine/src/lib.rs:138`

---

### VULN-05 — Arithmetic Overflow in Item Count

**Severity**: MEDIUM | **CVSS**: 6.8 | **CWE**: CWE-190 | **Rule**: 6
**Location**: `programs/candy-machine/src/lib.rs:146` (`add_items`)

**Description**: The add_items instruction sums counts using default `+` operator on u32, which wraps silently on overflow in Solana release mode.

**Impact**: Integer overflow corrupts the supply counter. A wrapped items_available value enables minting beyond the intended supply, breaking the core scarcity mechanism.

**Recommendation**: Use `checked_add` in the loop: `total = total.checked_add(c).ok_or(ErrorCode::Overflow)?;`. Replace all arithmetic on user-controlled amounts with checked operations.

**Line Reference**: `programs/candy-machine/src/lib.rs:146`

---

### VULN-06 — Reentrancy via Mint Callback

**Severity**: HIGH | **CVSS**: 7.5 | **CWE**: CWE-362 | **Rule**: 14
**Location**: `programs/candy-machine/src/lib.rs:155` (`mint_with_callback`)

**Description**: The mint_with_callback instruction performs `token::mint_to` via CPI and then increments `machine.items_redeemed`. No reentrancy guard exists between the CPI call and the state update.

**Impact**: Double-counting of mint redemptions. A re-entrant attacker can increment items_redeemed multiple times per actual mint, enabling minting more NFTs than configured supply.

**Recommendation**: Move all state updates before CPI calls. Alternatively, use a ReentrancyGuard account with check-and-set pattern.

**Line Reference**: `programs/candy-machine/src/lib.rs:155`

---

### VULN-07 — Token-2022 Transfer Fee Not Accounted

**Severity**: MEDIUM | **CVSS**: 6.3 | **CWE**: CWE-20 | **Rule**: 5
**Location**: `programs/nft-minter/src/lib.rs:86` (`transfer_nft`)

**Description**: The transfer_nft instruction calls `token::transfer` with the full amount parameter without accounting for Token-2022 transfer fees.

**Impact**: Fund loss for NFT recipients. When transferring Token-2022 tokens with fees, the recipient receives less than the sender specified.

**Recommendation**: Query the token's transfer fee configuration. Calculate the maximum fee before calling transfer. Use `transfer_checked` instead of `transfer`.

**Line Reference**: `programs/nft-minter/src/lib.rs:86`

---

### VULN-08 — Non-Transferable Bypass via Hook

**Severity**: HIGH | **CVSS**: 7.8 | **CWE**: CWE-862 | **Rule**: 33
**Location**: `programs/nft-minter/src/lib.rs:93` (`force_transfer`)

**Description**: The force_transfer instruction uses `Program<'info, Token2022>` to invoke the token program, bypassing the non-transferable extension's owner-invariant check.

**Impact**: Unauthorized transfer of non-transferable tokens. NFTs marked as non-transferable can be stolen, defeating the entire purpose of the non-transferable extension.

**Recommendation**: Remove force_transfer entirely. If a legitimate force-transfer use case exists, implement it with proper authorization checks and emit a ForceTransfer event.

**Line Reference**: `programs/nft-minter/src/lib.rs:93`

---

### VULN-09 — init_if_needed Without One-Time Bump

**Severity**: HIGH | **CVSS**: 8.2 | **CWE**: CWE-665 | **Rule**: 22
**Location**: `programs/nft-minter/src/lib.rs:100` (`create_collection`)

**Description**: The create_collection instruction accepts a bump parameter but does not enforce one-time use. The instruction can be called multiple times to reinitialize the Collection account.

**Impact**: Collection reinitialization. An attacker can change the authority to any key they control or reset the collection size to inflate apparent supply.

**Recommendation**: Store the bump in the Collection account. On subsequent calls, verify the existing bump matches the provided bump. Use Anchor's `init_if_needed` pattern with a bump constraint.

**Line Reference**: `programs/nft-minter/src/lib.rs:100`

---

### VULN-10 — Duplicate Mutable Account in Batch Mint

**Severity**: MEDIUM | **CVSS**: 6.5 | **CWE**: CWE-366 | **Rule**: 38
**Location**: `programs/nft-minter/src/lib.rs:107` (`batch_mint`)

**Description**: The batch_mint instruction uses the same mint AccountInfo for multiple operations within a single instruction execution. The total computation uses unchecked addition.

**Impact**: Potential state inconsistency between intended and actual mint totals. If the account state changes between sequential operations or the total overflows, the mint operation may not reflect the intended amount.

**Recommendation**: Use a single checked mint_to call with the precomputed total: `amounts.iter().try_fold(0u64, |acc, &a| acc.checked_add(a)).ok_or(ErrorCode::Overflow)?;`.

**Line Reference**: `programs/nft-minter/src/lib.rs:107`

---

### VULN-11 — Token-2022 Transfer Hook CPI Routing

**Severity**: HIGH | **CVSS**: 7.5 | **CWE**: CWE-347 | **Rule**: 27
**Location**: `programs/metadata/src/lib.rs:44` (`create_metadata`)

**Description**: The create_metadata instruction passes `ctx.remaining_accounts` directly to invoke without validating the accounts match the expected transfer hook extra accounts.

**Impact**: CPI routing failure or redirection. Missing extra accounts will cause the CPI to fail; an attacker could craft remaining_accounts to redirect to a different program.

**Recommendation**: Validate remaining_accounts against the token program's expected extra accounts before passing them to invoke. Query the transfer hook extension's required accounts from the mint metadata.

**Line Reference**: `programs/metadata/src/lib.rs:44`

---

### VULN-12 — Unsafe Deserialization Without Owner Check

**Severity**: MEDIUM | **CVSS**: 5.9 | **CWE**: CWE-345 | **Rule**: 39
**Location**: `programs/metadata/src/lib.rs:61` (`read_metadata`)

**Description**: The read_metadata instruction calls `Metadata::try_from_slice(&data[8..])` without verifying the account owner is the metadata program.

**Impact**: Type confusion via arbitrary deserialization. An attacker can pass any account with sufficient data and the bytes will be deserialized as Metadata, potentially leaking sensitive data.

**Recommendation**: Add an owner check: `require!(ctx.accounts.metadata_account.owner == &program_id, MetadataError::InvalidOwner);`. Use Anchor's `Account<'info, Metadata>` wrapper instead of raw `try_borrow_data`.

**Line Reference**: `programs/metadata/src/lib.rs:61`

---

### VULN-13 — Arbitrary CPI via remaining_accounts

**Severity**: HIGH | **CVSS**: 8.1 | **CWE**: CWE-347 | **Rule**: 4
**Location**: `programs/metadata/src/lib.rs:69` (`update_metadata`)

**Description**: The update_metadata instruction accepts `target_program: AccountInfo` with no allowlist validation and passes `ctx.remaining_accounts` directly to invoke.

**Impact**: Full arbitrary CPI execution. An attacker can invoke any program with attacker-controlled instruction data and accounts, enabling token transfers, account closures, and privilege escalation.

**Recommendation**: Remove the arbitrary CPI capability. Replace with a dedicated metadata update instruction that only modifies the metadata account's uri field directly. If a plugin architecture is needed, maintain an allowlist of approved program IDs.

**Line Reference**: `programs/metadata/src/lib.rs:69`

---

### VULN-14 — Missing Writable Enforcement

**Severity**: MEDIUM | **CVSS**: 5.3 | **CWE**: CWE-283 | **Rule**: 37
**Location**: `programs/metadata/src/lib.rs:83` (`set_update_authority`)

**Description**: The metadata_account field is mutated without verifying runtime writability. The `#[account(mut)]` constraint generates writable=true in AccountMeta for CPIs, but the account could be passed without the writable flag.

**Impact**: Failed instruction execution. The mutation will fail at runtime if the account is not genuinely writable, creating a confusing error path and potential for denial of service.

**Recommendation**: Add an explicit writability check: `if !ctx.accounts.metadata_account.is_writable { return Err(ProgramError::InvalidArgument.into()); }`.

**Line Reference**: `programs/metadata/src/lib.rs:83`

---

## Methodology Trace

| VULN | Phase 1 (Recon) | Phase 2 (Rule Scan) | Phase 3 (Deep Dive) |
|------|-----------------|---------------------|---------------------|
| VULN-01 | Discriminator analysis | Rule 16 (Type Confusion) | Instruction dispatch table review |
| VULN-02 | Init pattern analysis | Rule 40 (Missing Discriminator) | Manual init path audit |
| VULN-03 | Constraint analysis | Rule 2 (Missing Constraints) | has_one / signer verification |
| VULN-04 | Signer analysis | Rule 8 (Signer Verification) | Admin operation authz |
| VULN-05 | Arithmetic analysis | Rule 6 (Arithmetic Safety) | u32 overflow paths |
| VULN-06 | CPI + state analysis | Rule 14 (Reentrancy) | External call ordering |
| VULN-07 | Token analysis | Rule 5 (Token-2022 Fees) | Fee calculation paths |
| VULN-08 | Hook analysis | Rule 33 (Ownership Verification) | Non-transferable bypass |
| VULN-09 | Bump analysis | Rule 22 (One-Time Init) | init_if_needed patterns |
| VULN-10 | Account usage | Rule 38 (Duplicate Accounts) | Batch operation sequencing |
| VULN-11 | CPI analysis | Rule 27 (CPI Validation) | remaining_accounts routing |
| VULN-12 | Deserialization | Rule 39 (Owner Check) | try_from_slice paths |
| VULN-13 | CPI analysis | Rule 4 (CPI Safety) | Arbitrary program invoke |
| VULN-14 | Constraint analysis | Rule 37 (Writable Check) | mut constraint verification |

---

## Appendix: Program Inventory

| Program | File | Functions |
|---------|------|-----------|
| candy-machine | `programs/candy-machine/src/lib.rs` | mint, init_machine, set_authority, update_config, add_items, mint_with_callback |
| nft-minter | `programs/nft-minter/src/lib.rs` | transfer_nft, force_transfer, create_collection, batch_mint |
| metadata | `programs/metadata/src/lib.rs` | create_metadata, read_metadata, update_metadata, set_update_authority |
