# /audit-quick — token-2022-real

**Scanned**: `examples/token-2022-real/`
**Date**: 2026-06-25

## Rule 5: Token-2022 Extension Validation

| # | Check | Result | Details |
|---|-------|--------|---------|
| 1 | Uses `spl_token_2022` | ✅ PASS | Real `spl_token_2022::transfer_checked` used |
| 2 | Extension validation before transfer | ⚠️ VULN-17 | No `StateWithExtensions` unpacking |
| 3 | Transfer hook handling | ⚠️ VULN-17 | No transfer_hook program routing |
| 4 | Non-transferable check | ⚠️ VULN-17 | No non_transferable extension check |
| 5 | Default account state check | ⚠️ VULN-17 | No frozen account validation |
| 6 | Token-2022 program ID verified | ✅ PASS | Uses `Program<'info, Token2022>` |

## VULN Coverage

| VULN-ID | Title | Severity |
|---------|-------|----------|
| VULN-17 | Missing Token-2022 extension validation | HIGH |

**Findings**: 1 (0 CRITICAL, 1 HIGH, 0 MEDIUM)

## Notes

- This fixture demonstrates a REAL Token-2022 vault using `spl_token_2022::transfer_checked`
- Unlike `token-extensions/` which uses Anchor's token wrappers, this program directly calls spl_token_2022 APIs
- VULN-17 covers the missing extension validation that should precede any Token-2022 operation
