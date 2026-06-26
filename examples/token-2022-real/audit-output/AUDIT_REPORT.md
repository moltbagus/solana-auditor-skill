# Token-2022 Real Program Audit Report

**Target**: `examples/token-2022-real/src/lib.rs`
**Date**: 2026-06-25
**Rules Applied**: Rule 5 — Token Operations

---

## Executive Summary

The token-2022-real program demonstrates a real-world Token-2022 vault implementation using `spl_token_2022::transfer_checked`. While the program correctly uses the Token-2022 program type, it fails to validate the mint's extension state before performing transfers, violating Rule 5 of the audit framework.

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 1 |
| MEDIUM | 0 |
| LOW | 0 |
| info | 0 |
| **Total** | **2** |

---

## Findings

### VULN-17: Missing Token-2022 Extension Validation

**Severity**: HIGH
**CVSS**: 7.6 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L)
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
**Location**: `src/lib.rs:47` — `vault_withdraw`

#### Description

The `vault_withdraw` instruction uses `spl_token_2022::transfer_checked` for a real Token-2022 transfer but performs zero validation of the mint's extension state before executing the transfer. Token-2022 mints can have extensions that fundamentally alter transfer semantics:

- `default_account_state`: Can freeze all accounts
- `transfer_hook`: Requires custom CPI routing to the hook program
- `non_transferable`: Tokens should never be transferred

#### Impact

Transfer semantics bypass. The vault assumes all Token-2022 mints behave like basic SPL tokens, but Token-2022 extensions can completely change the transfer model. Without extension validation:

1. Transfer hooks are bypassed
2. Frozen accounts may be incorrectly operated on
3. Non-transferable tokens enter the vault

#### Recommendation

Use `StateWithExtensions::<Mint>::unpack(&mint.data.borrow())` to read extension data before transfers. Validate extension compatibility and route accordingly.

---

### VULN-18: Transfer Hook Extension Not Validated Before CPI Routing

**Severity**: CRITICAL
**CVSS**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
**Rule**: Rule 27 — Token-2022 Transfer Hook CPI Routing
**Location**: `src/lib.rs:140` — `hook_withdraw`

#### Description

The `hook_withdraw` instruction uses the TransferHook extension from the mint to route a transfer via CPI to the hook's program. However, it performs no validation of the hook_program_id before routing to it. An attacker can deploy a malicious Token-2022 mint whose TransferHook extension points to an attacker-controlled program. When the vault calls `hook_withdraw`, it CPI's into the attacker's program, which can return success without performing any real transfer, re-enter the vault to drain additional funds, or manipulate vault state arbitrarily. This requires no privileged access — only the ability to create a Token-2022 mint and deposit tokens.

#### Impact

Complete vault drain. An attacker who can create or influence the mint used in the vault can drain all funds by providing a malicious transfer-hook program. The hook can approve any withdrawal, re-enter the vault during the CPI, and recursively drain tokens. There is no authentication on the hook CPI target.

#### Recommendation

Validate hook_program_id against an explicit allowlist of trusted transfer-hook programs before issuing any CPI. Alternatively, verify that the mint itself is in a trusted set before loading and routing to its hook. Add a reentrancy guard to prevent callback attacks from the hook program. Consider disabling hook routing entirely unless the mint and hook are both operator-controlled.

---

## Conclusion

The token-2022-real program demonstrates the common pitfall of using Token-2022 APIs without understanding the extension model. Real Token-2022 security requires pre-flight extension validation before any transfer operation.
