# Token-2022 Real Methodology Trace

**Date**: 2026-06-25
**Source**: `skill/04-findings-triage.md` §Severity Classification
**Target**: `examples/token-2022-real/src/lib.rs`

This trace documents how VULN-17 is caught by walking through the
6-phase audit methodology. It validates the Token-2022 rule
is actionable on real `spl_token_2022` code.

---

## VULN-17 — Missing Token-2022 Extension Validation

**Phase 2 (Static Analysis)** path:
1. Function `vault_withdraw` identified at line 47.
2. Line 59: `transfer_checked(...)` — real Token-2022 CPI call.
3. Mint account is deserialized as `Account<'info, Mint>` but extension data is never read.
4. Cross-reference with `skill/02-static-analysis.md` §Token-2022 Extensions:
   - "Token-2022 mints may have extensions that alter transfer semantics"
   - "Always read ExtensionType to validate mint compatibility BEFORE transfer"
5. No `StateWithExtensions::<Mint>::unpack()` call found anywhere in the function.
6. Severity: HIGH (Token-2022 API used without extension validation).
7. CWE-345 (Insufficient Verification of Data Authenticity).
8. CVSS vector: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L` → 7.6.

**Trace time**: ~2 minutes manual; ~20 seconds with grep assistance.

---

## CVSS Breakdown

| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | Remotely exploitable via program call |
| Attack Complexity | Low | Standard Token-2022 transfer |
| Privileges Required | Low | Any token holder can trigger |
| User Interaction | None | No victim action needed |
| Scope | Unchanged | Impact limited to token vault |
| Confidentiality | High | Token balances exposed |
| Integrity | Low | Bypassed transfer hooks |
| Availability | Low | Possible transfer failures |

**CVSS Score**: 7.5 (HIGH)

---

## Reproducibility Statement

The trace above is reproducible by following:
1. Open `examples/token-2022-real/src/lib.rs`
2. Find `vault_withdraw` function
3. Verify `transfer_checked` is called WITHOUT `StateWithExtensions` unpacking
4. Cross-reference with `skill/02-static-analysis.md` Token-2022 section
5. Apply CVSS/CWE from `skill/04-findings-triage.md`

The methodology is fully deterministic — Token-2022 extension validation
is required by Rule 5, and the absence of such validation is caught.

---

## Notes

- VULN-17 is caught in Phase 2 (Static Analysis).
- The program uses REAL `spl_token_2022::transfer_checked` — not just Anchor wrappers.
- The vulnerability is in the MISSING extension validation, not in the transfer call itself.
- This demonstrates Rule 5 (Token-2022) on actual `spl_token_2022` code.
