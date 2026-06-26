# Todo — Kamino Lend Immunefi Submissions (2026-06-26)

> Final triage after verifying actual source code at `https://github.com/kamino-finance/klend master`.

## Status: 4 Verified Submissions Ready

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Withdraw C-1 (div_ceil) submission | ✅ DROPPED | Bug real but .expect() panics, not silent corruption. Quantum-level. Not submission-worthy. |
| 2 | Withdraw C-2 (borrow rate overflow) submission | ✅ DROPPED | Claims "silent wrap" but code has .expect() + direct overflow mathematically impossible at Kamino params. NOT a finding. |
| 3 | Withdraw M-7 (liquidation bonus) submission | ✅ DROPPED | Formula bug is real but impact direction was INVERTED. Rewrite pending as separate report. |
| 4 | Verify ADMIN-001 against source | ✅ VERIFIED | `pending_admin→global_admin` requires only new key in tx2. Phish vector. Write as HIGH. |
| 5 | Verify PERM-003 against source | ✅ VERIFIED | No event, no timelock on permissioning_authority change. Write as HIGH. |
| 6 | Verify MATH-003-3 against source | ✅ VERIFIED | Zero oracle price → divide-by-zero panic. Write as MEDIUM. |
| 7 | Verify MATH-003-5 against source | ✅ VERIFIED | `loan_to_value` plain `/` with no zero collat guard. Callers don't guard either. Write as HIGH. |
| 8 | Write ADMIN-001 submission | ✅ DONE | `audit-report/submissions/ADMIN-001-immunefi-submission.md` |
| 9 | Write PERM-003 submission | ✅ DONE | `audit-report/submissions/PERM-003-immunefi-submission.md` |
| 10 | Write MATH-003-3 submission | ✅ DONE | `audit-report/submissions/MATH-003-3-immunefi-submission.md` |
| 11 | Write MATH-003-5 submission | ✅ DONE | `audit-report/submissions/MATH-003-5-immunefi-submission.md` |

## Submission Summary (Validated)

| Finding | Severity | Bounty Ceiling | Type |
|---------|----------|----------------|------|
| ADMIN-001 (pending_admin 2-step cosmetic) | HIGH | ~$100k max | Access control weakness |
| PERM-003 (permissioning authority no timelock) | HIGH | ~$100k max | Admin process gap |
| MATH-003-5 (LTV divide-by-zero DoS) | HIGH | ~$100k max | Panic / DoS |
| MATH-003-3 (oracle zero-price divide-by-zero) | MEDIUM | $10k flat | Panic / DoS |
| C-1 (div_ceil) | — | — | **DROPPED**: quantum-level. Bug exists, no $ impact. |
| C-2 (borrow rate overflow) | — | — | **DROPPED**: code has .expect(), overflow impossible at real params. |
| M-7 (liquidation bonus formula) | — | — | **DROPPED**: formula bug real, but impact direction was inverted. |

## Key Lessons (for lessons.md)

1. **Always verify source code before submission.** Three of three initial submissions had factual errors that source verification exposed.
2. **Real-code Rust's panic/expect behavior matters.** Immunefi submissions claiming "silent wrap" are wrong when the code has `.expect()`. Panic → DoS, different vulnerability class.
3. **Compute overflow thresholds precisely.** `u128::MAX / 2^60 / u32::MAX = 2.9e20` — any claim of overflow at 10^10 slope_nom is mathematically wrong.
4. **Impact direction matters.** "Liquidator gets 4.762% instead of 5%" is correct. "Protocol systematically undercollects" was inverted.
