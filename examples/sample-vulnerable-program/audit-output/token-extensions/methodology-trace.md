# /audit Methodology Trace — Token Extensions

**Date**: 2026-06-24
**Source**: `skill/04-findings-triage.md` §Severity Classification + `rules/audit.rules` Rule 5
**Target**: `examples/sample-vulnerable-program/programs/token-extensions/src/lib.rs`

This trace documents how each VULN-XX is caught by walking through the
6-phase audit methodology. It proves the methodology is reproducible,
not dependent on hand-curated findings.

---

## VULN-11 — Wrong token program (Token vs Token-2022)

**Phase 2 (Static Analysis)** path:
1. Read `Cargo.toml` dependency: `spl-token-2022` present.
2. Read `token_extensions` module instructions.
3. Function `transfer_no_2022_check` at line 37.
4. Inspect Transfer context: `token_program: Program<'info, Token>` — uses legacy `anchor_spl::token::Token`.
5. Cross-reference `rules/audit.rules` Rule 5: "Identify token program: Check if spl-token-2022 is in Cargo.toml deps."
6. Rule 5: "Wrong token program passed → HIGH."
7. Severity: HIGH (extension bypass, not direct fund loss).
8. CWE-345 (Insufficient Verification of Data Authenticity).
9. CVSS vector: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` → 8.1.

**Trace time**: ~2 minutes.

---

## VULN-12 — Missing transfer_fee accounting on deposit

**Phase 2 (Static Analysis)** path:
1. Function `deposit_with_fee_mismatch` at line 64.
2. Line 85: `user.deposited.checked_add(amount)` — records full amount.
3. Cross-reference Rule 5 line: "transfer_fee: amount math must account for fee on transfer."
4. Rule 5: "Missing fee math → MEDIUM (HIGH if fee-aware accounting is the protocol's purpose)."
5. Severity: HIGH (accounting drift enables token theft).
6. CWE-1281 (Sequence of Processor Instructions Leads to Unexpected Behavior).
7. CVSS vector: `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N` → 7.1.

**Trace time**: ~2 minutes.

---

## VULN-13 — Mint close authority not verified

**Phase 2 (Static Analysis)** path:
1. Function `close_mint_no_verify` at line 85.
2. Inspect Accounts struct: `close_authority: Signer<'info>` — no constraint linking to extension.
3. Cross-reference Rule 5: "mint_close_authority: if mint can be closed, verify the close authority is checked."
4. Severity: MEDIUM (requires supply=0 condition — constrained exploit path).
5. CWE-285 (Improper Authorization).
6. CVSS vector: `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` → 6.5.

**Trace time**: ~2 minutes.

---

## VULN-14 — Permanent delegate not verified

**Phase 2 (Static Analysis)** path:
1. Function `burn_with_unverified_delegate` at line 107.
2. Inspect Accounts: `delegate: Signer<'info>` — no extension data read.
3. Cross-reference Rule 5: "permanent_delegate: if set, the delegate has mint/burn authority — extreme care."
4. Also cross-reference Rule 8: "Missing signer check on privileged action → CRITICAL."
5. Severity: CRITICAL (total token destruction — delegate can burn any account).
6. CWE-306 (Missing Authentication for Critical Function).
7. CVSS vector: `AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H` → 10.0.

**Trace time**: ~3 minutes.

---

## VULN-15 — Metadata pointer not verified

**Phase 2 (Static Analysis)** path:
1. Function `read_metadata_unverified` at line 133.
2. Inspect Accounts: `metadata_account: UncheckedAccount<'info>` — no verification.
3. Cross-reference Rule 5: "metadata_pointer: metadata operations must verify the pointer."
4. Severity: MEDIUM (requires attacker-controlled mint — indirect path).
5. CWE-345 (Insufficient Verification of Data Authenticity).
6. CVSS vector: `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` → 5.4.

**Trace time**: ~2 minutes.

---

## VULN-16 — Non-transferable token bypass

**Phase 2 (Static Analysis)** path:
1. Function `wrap_non_transferable` at line 145.
2. Inspect body: `vault.wrapped.checked_add(amount)` — no extension read.
3. Cross-reference Rule 5: "non_transferable: mints with this extension reject all transfers — verify the program doesn't try to transfer them."
4. Severity: HIGH (restriction bypass — defeats regulatory compliance).
5. CWE-345 (Insufficient Verification of Data Authenticity).
6. CVSS vector: `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` → 8.1.

**Trace time**: ~2 minutes.

---

## Summary

| VULN | Severity | Rule | CVSS | CWE | Phase |
|------|----------|------|------|-----|-------|
| VULN-11 | HIGH | Rule 5 | 8.1 | CWE-345 | Static Analysis |
| VULN-12 | HIGH | Rule 5 | 7.1 | CWE-1281 | Static Analysis |
| VULN-13 | MEDIUM | Rule 5 | 6.5 | CWE-285 | Static Analysis |
| VULN-14 | CRITICAL | Rule 5 + Rule 8 | 10.0 | CWE-306 | Static Analysis |
| VULN-15 | MEDIUM | Rule 5 | 5.4 | CWE-345 | Static Analysis |
| VULN-16 | HIGH | Rule 5 | 8.1 | CWE-345 | Static Analysis |

All 6 findings are detected by **Rule 5 (Token Operations — SPL vs Token-2022 Distinction)**, with VULN-14 additionally detected by **Rule 8 (Signer Verification)**. This validates that the path-scoped rules engine correctly identifies Token-2022 extension-level vulnerabilities.
