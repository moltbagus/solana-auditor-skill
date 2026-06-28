# Methodology Trace — NFT Candy Machine Audit

**Audit Date**: 2026-06-29
**Programs**: candy-machine, nft-minter, metadata
**Ruleset Version**: Solana Auditor Skill v1.0

---

## Phase Mapping

Each finding traces through three phases:

1. **Phase 1 — Recon**: Source-code pattern matching, program inventory, architecture review
2. **Phase 2 — Rule Scan**: Automated scan against `rules/audit.rules` path-scoped rules
3. **Phase 3 — Deep Dive**: Manual audit of flagged code paths, constraint analysis, CPI chain tracing

---

## Per-VULN Trace

### VULN-01 — Discriminator Collision

| Field | Value |
|-------|-------|
| **Phase 1** | Enumerated all public functions in candy-machine program. Identified duplicate discriminator risk by reviewing function naming and instruction dispatch. |
| **Phase 2** | Rule 16 — Type Confusion / Discriminator Collision |
| **Detection** | Static analysis of Anchor discriminator derivation. Multiple functions share same 8-byte prefix. |
| **Score** | CRITICAL (9.8) |
| **Rationale** | Type confusion at instruction dispatch level affects entire program. Any colliding instruction can be triggered by submitting the colliding discriminator. Highest severity in the fixture. |

---

### VULN-02 — Manual Init Without Discriminator

| Field | Value |
|-------|-------|
| **Phase 1** | Reviewed init_machine for proper Anchor #[account] usage. Manual field assignment detected. |
| **Phase 2** | Rule 40 — Missing Account Discriminator |
| **Detection** | init_machine writes fields directly without calling Anchor's discriminator write. |
| **Score** | MEDIUM (6.5) |
| **Rationale** | Reinit attack requires attacker to acquire account key, reducing likelihood vs. unauthenticated paths. Still high impact if account is obtained. |

---

### VULN-03 — Account Constraints Bypassed

| Field | Value |
|-------|-------|
| **Phase 1** | Reviewed set_authority for has_one and signer constraints. Raw AccountInfo mutation detected. |
| **Phase 2** | Rule 2 — Missing Account Constraints |
| **Detection** | No has_one on mint_account, no Signer on authority, direct .authority field assignment. |
| **Score** | HIGH (8.6) |
| **Rationale** | Any caller can redirect mint authority. No authentication required. Enables complete mint hijacking. |

---

### VULN-04 — Missing Signer on Admin Config

| Field | Value |
|-------|
| **Phase 1** | Reviewed update_config for Signer constraint. authority declared as AccountInfo. |
| **Phase 2** | Rule 8 — Signer Verification |
| **Detection** | authority: AccountInfo instead of Signer. No is_signer check in instruction body. |
| **Score** | HIGH (7.2) |
| **Rationale** | Unauthenticated config update allows price manipulation. Impact limited to price changes (not direct fund theft), reducing from CRITICAL. |

---

### VULN-05 — Arithmetic Overflow

| Field | Value |
|-------|-------|
| **Phase 1** | Reviewed add_items for checked arithmetic. u32 accumulation loop with default + operator. |
| **Phase 2** | Rule 6 — Arithmetic Safety |
| **Detection** | `total = total + c` without checked_add. u32::MAX wrap possible. |
| **Score** | MEDIUM (6.8) |
| **Rationale** | Requires attacker to provide specially crafted counts vector. Overflow corrupts supply but doesn't directly enable theft. |

---

### VULN-06 — Reentrancy via Callback

| Field | Value |
|-------|-------|
| **Phase 1** | Traced CPI chain in mint_with_callback. External call precedes state update. |
| **Phase 2** | Rule 14 — Reentrancy |
| **Detection** | token::mint_to CPI called before items_redeemed increment. No reentrancy guard. |
| **Score** | HIGH (7.5) |
| **Rationale** | CPI callback can re-enter same instruction, double-incrementing items_redeemed. Enables supply bypass. |

---

### VULN-07 — Token-2022 Fee Not Accounted

| Field | Value |
|-------|-------|
| **Phase 1** | Reviewed transfer_nft for Token-2022 fee handling. Full amount passed to transfer. |
| **Phase 2** | Rule 5 — Token-2022 Fee Handling |
| **Detection** | token::transfer called with nominal amount; fee withheld from recipient. |
| **Score** | MEDIUM (6.3) |
| **Rationale** | Recipient receives less than sent; fund loss is indirect and bounded by transfer fees. Requires Token-2022 token configuration. |

---

### VULN-08 — Non-Transferable Bypass

| Field | Value |
|-------|-------|
| **Phase 1** | Reviewed force_transfer for non-transferable extension bypass. Raw Program invoke detected. |
| **Phase 2** | Rule 33 — Missing Ownership Verification |
| **Detection** | Direct Token2022 program invoke bypasses non-transferable hook. No ownership check. |
| **Score** | HIGH (7.8) |
| **Rationale** | Non-transferable tokens can be stolen. High impact on NFT ownership guarantees. Moderate complexity to exploit. |

---

### VULN-09 — One-Time Bump Not Enforced

| Field | Value |
|-------|-------|
| **Phase 1** | Reviewed create_collection for bump storage and verification. bump parameter accepted but not stored. |
| **Phase 2** | Rule 22 — Missing One-Time Initialization |
| **Detection** | bump passed but never stored or checked against existing value. Reinit possible. |
| **Score** | HIGH (8.2) |
| **Rationale** | Collection reinit allows authority hijacking or supply inflation. Requires account control but high impact. |

---

### VULN-10 — Duplicate Mutable Account

| Field | Value |
|-------|-------|
| **Phase 1** | Reviewed batch_mint for account usage patterns. Same mint AccountInfo in multiple operations. |
| **Phase 2** | Rule 38 — Duplicate Mutable Account |
| **Detection** | mint account used in mint_ctx() without explicit sequencing. Unchecked overflow in total computation. |
| **Score** | MEDIUM (6.5) |
| **Rationale** | State inconsistency possible but requires specific timing or overflow conditions. Impact limited to mint amount discrepancy. |

---

### VULN-11 — Transfer Hook CPI Routing

| Field | Value |
|-------|-------|
| **Phase 1** | Traced remaining_accounts in create_metadata. Direct invoke without extra account validation. |
| **Phase 2** | Rule 27 — Missing CPI Validation |
| **Detection** | remaining_accounts forwarded to invoke without verifying against expected transfer hook accounts. |
| **Score** | HIGH (7.5) |
| **Rationale** | CPI routing failure or redirection possible. Can cause silent failures or redirect to unintended programs. |

---

### VULN-12 — Unsafe Deserialization

| Field | Value |
|-------|-------|
| **Phase 1** | Reviewed read_metadata for owner check. try_from_slice called without owner verification. |
| **Phase 2** | Rule 39 — Missing Owner Check |
| **Detection** | Metadata::try_from_slice on arbitrary account data without verifying account owner is metadata program. |
| **Score** | MEDIUM (5.9) |
| **Rationale** | Type confusion possible but requires passing arbitrary account. Information disclosure limited to account data. |

---

### VULN-13 — Arbitrary CPI

| Field | Value |
|-------|-------|
| **Phase 1** | Traced remaining_accounts in update_metadata. User-supplied target_program with no allowlist. |
| **Phase 2** | Rule 4 — CPI Safety |
| **Detection** | target_program: AccountInfo with no validation. remaining_accounts forwarded directly. |
| **Score** | HIGH (8.1) |
| **Rationale** | Arbitrary CPI to any program with attacker's chosen data and accounts. Highest exploit potential in metadata program. |

---

### VULN-14 — Missing Writable Check

| Field | Value |
|-------|-------|
| **Phase 1** | Reviewed set_update_authority for is_writable verification. mut constraint present but no explicit check. |
| **Phase 2** | Rule 37 — Missing Writable Check |
| **Detection** | metadata_account mutated without verifying runtime writability. mut generates writable=true in AccountMeta but account could be non-writable in raw instruction path. |
| **Score** | MEDIUM (5.3) |
| **Rationale** | DoS possible but limited impact. Mutation fails if account not writable; no unauthorized state change. |

---

## Score Distribution

| Score Range | Count | VULNs |
|-------------|-------|-------|
| 9.0–10.0 (CRITICAL) | 1 | VULN-01 |
| 7.0–8.9 (HIGH) | 7 | VULN-03, VULN-04, VULN-06, VULN-08, VULN-09, VULN-11, VULN-13 |
| 4.0–6.9 (MEDIUM) | 6 | VULN-02, VULN-05, VULN-07, VULN-10, VULN-12, VULN-14 |
| 0.1–3.9 (LOW) | 0 | — |
| 0.0 (INFO) | 0 | — |

**Total**: 14 findings

---

## Rule Coverage

| Rule ID | Rule Name | VULNs Caught |
|---------|-----------|--------------|
| 2 | Missing Account Constraints | VULN-03 |
| 4 | CPI Safety | VULN-13 |
| 5 | Token-2022 Fee Handling | VULN-07 |
| 6 | Arithmetic Safety | VULN-05 |
| 8 | Signer Verification | VULN-04 |
| 14 | Reentrancy | VULN-06 |
| 16 | Type Confusion / Discriminator | VULN-01 |
| 22 | One-Time Initialization | VULN-09 |
| 27 | CPI Validation | VULN-11 |
| 33 | Missing Ownership Verification | VULN-08 |
| 37 | Missing Writable Check | VULN-14 |
| 38 | Duplicate Mutable Account | VULN-10 |
| 39 | Missing Owner Check | VULN-12 |
| 40 | Missing Account Discriminator | VULN-02 |

All 14 findings map to explicit rules in the audit ruleset.
