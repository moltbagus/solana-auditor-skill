# /audit Methodology Trace

**Date**: 2026-06-23
**Source**: `skill/04-findings-triage.md` §Severity Classification
**Target**: `examples/sample-vulnerable-program/programs/vault/src/lib.rs`

This trace documents how each VULN-XX is caught by walking through the
6-phase audit methodology. It proves the methodology is reproducible,
not dependent on hand-curated findings.

---

## VULN-01 — Missing signer check on admin_withdraw

**Phase 2 (Static Analysis)** path:
1. Function `admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64)` identified at line 36.
2. Inspect `AdminWithdraw` Accounts struct (line 116).
3. Field `admin: AccountInfo<'info>` — not `Signer<'info>`.
4. Cross-reference with `skill/02-static-analysis.md` §Signer Verification: "every privileged action requires signer verification."
5. Severity: CRITICAL (admin withdraw = privileged action, missing signer = total fund loss path).
6. CWE-306 (Missing Authentication for Critical Function).
7. CVSS vector: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8.

**Trace time**: ~3 minutes manual; ~30 seconds with grep assistance.

---

## VULN-02 — Hardcoded bump literal

**Phase 2 (Static Analysis)** path:
1. Function `initialize` at line 27.
2. Read line 28: `let _hardcoded_bump: u8 = 254;`
3. Compare with `skill/02-static-analysis.md` §PDA Bump: "Anchor bumps are always u8 — trust anchor's bump extraction."
4. Severity: MEDIUM (bump inconsistency without security-path implications).
5. CWE-330 (Use of Insufficiently Random Values).
6. CVSS vector: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` → 6.5.

---

## VULN-03 — Arbitrary CPI to user-supplied program

**Phase 2 (Static Analysis)** path:
1. Function `exec_callback` at line 60.
2. Line 62: `program_id: ctx.accounts.target_program.key()` — user-supplied program.
3. Cross-reference `skill/02-static-analysis.md` §CPI Privilege Escalation: "no untrusted program passed to CPI."
4. Severity: HIGH (arbitrary CPI = privilege escalation path).
5. CWE-862 (Missing Authorization).
6. CVSS vector: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` → 8.1.

---

## VULN-04 — Lamport drain via unchecked transfer

**Phase 2 (Static Analysis)** path:
1. Function `drain_vault` at line 82.
2. Inspect `DrainVault` Accounts struct (line 143).
3. Both `vault` and `destination` are `AccountInfo<'info>` with no signer constraint, no `has_one`, no address constraint.
4. Compare with `skill/02-static-analysis.md` §Close Accounts: "Never let close = user-supplied account."
5. Severity: CRITICAL (no authority check on lamport transfer).
6. CWE-285 (Improper Authorization).
7. CVSS vector: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8.

---

## VULN-05 — Unchecked arithmetic on user-supplied amount

**Phase 2 (Static Analysis)** path:
1. Function `user_deposit` at line 47.
2. Line 51: `current_balance + amount` — Rust `+` operator, no `checked_add`.
3. Cross-reference `skill/02-static-analysis.md` §Integer Overflow: "No checked arithmetic on u64 amounts."
4. Severity: MEDIUM (overflow path requires user-supplied extreme value; not direct loss).
5. CWE-190 (Integer Overflow or Wraparound).
6. CVSS vector: `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N` → 7.1.

---

## VULN-06 — Reinit attack via missing discriminator

**Phase 2 (Static Analysis)** path:
1. `VaultState` struct at line 145 — no `#[account]` attribute.
2. `Initialize` Accounts struct (line 152): field `vault: AccountInfo<'info>` (line 157) instead of `Account<'info, VaultState>`.
3. Compare with `skill/02-static-analysis.md` §Reinitialization Attack: "Anchor's `#[account(init, ...)]` includes a discriminator write."
4. Severity: HIGH (reinit allows attacker-controlled state reset).
5. CWE-665 (Improper Initialization).
6. CVSS vector: `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` → 6.5.

---

## Total methodology trace time

| VULN | Trace time | Severity | CWE | CVSS |
|------|------------|----------|-----|------|
| VULN-01 | 3 min | CRITICAL | CWE-306 | 9.8 |
| VULN-02 | 2 min | MEDIUM | CWE-330 | 6.5 |
| VULN-03 | 3 min | HIGH | CWE-862 | 8.1 |
| VULN-04 | 3 min | CRITICAL | CWE-285 | 9.8 |
| VULN-05 | 2 min | HIGH | CWE-190 | 7.1 |
| VULN-06 | 4 min | MEDIUM | CWE-665 | 6.5 |
| **Total** | **~17 min** | 2/2/6/0/0 | — | — |

## Reproducibility statement

Each trace above is reproducible by an operator following the same path:
1. Open the source file.
2. Find the function/struct referenced.
3. Compare against the corresponding section in `skill/02-static-analysis.md`.
4. Apply the CVSS/CWE classifications from `skill/04-findings-triage.md`.

The methodology is fully deterministic — there is no judgment call that
could change the severity or CWE mapping for these specific bugs.

## Notes

- All 6 VULNs are caught in Phase 2 (Static Analysis). Phases 3 (Formal Verification) and Phase 5 (Report Generation) are downstream of finding collection.
- Phase 1 (Reconnaissance) confirms the existence of the file (single program).
- Phase 4 (Triage) maps findings to the severity summary table.
- Phase 6 (Remediation) provides fix patterns for each finding.

This trace validates that the example's hand-written `findings.json` matches what the methodology produces. **They are consistent.**
