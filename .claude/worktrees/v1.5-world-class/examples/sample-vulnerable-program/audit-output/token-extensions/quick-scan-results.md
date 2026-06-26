# /audit-quick — token-extensions

**Scanned**: `examples/sample-vulnerable-program/programs/token-extensions/`
**Date**: 2026-06-24

| # | Check | Result | Details |
|---|-------|--------|---------|
| 1 | Missing signer | ⊘ N/A | No privileged instructions without signer |
| 2 | Unverified CPI program | ✅ PASS | CPI uses typed `Program<'info, Token>` |
| 3 | `invoke_signed` w/o canonical bump | ⊘ N/A | No invoke_signed in this fixture |
| 4 | `init` w/o payer/space | ⊘ N/A | No init instructions in this fixture |
| 5 | Hardcoded bump literal | ⊘ N/A | No PDA derivations in this fixture |
| 6 | Token op w/o mint verification | ⚠️ VULN-14 | Delegate not verified for burn |
| 7 | Wrong `close =` target | ⊘ N/A | No close constraint in this fixture |
| 8 | Arithmetic w/o `checked_*` | ✅ PASS | Uses `checked_add` correctly |
| 9 | Token-2022 fee math missing | ⚠️ VULN-12 | `spl-token-2022` in deps + raw amount math |

**Token-2022 Extension Audit:**

| Extension | Status | Notes |
|-----------|--------|-------|
| `mint_close_authority` | ⚠️ VULN-13 | Not verified on close |
| `metadata_pointer` | ⚠️ VULN-15 | Not verified on read |
| `transfer_fee` | ⚠️ VULN-12 | Not accounted in deposit math |
| `confidential_transfer` | ⊘ N/A | Not used |
| `permanent_delegate` | ⚠️ VULN-14 | Not verified on burn |
| `non_transferable` | ⚠️ VULN-16 | Not checked on wrap |

**Findings**: 6 (1 CRITICAL, 3 HIGH, 2 MEDIUM)
