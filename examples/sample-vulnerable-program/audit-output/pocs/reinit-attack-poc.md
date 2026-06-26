# PoC: VULN-11 — Reinitialization Attack

## Overview
Attacker reinitializes their own account to reset state and drain funds.

## Exploit Path

1. Attacker initializes account with 100 tokens
2. Attacker calls `deposit()` to lock funds in protocol
3. Attacker calls `reinit()` on their own account
4. Account discriminator is NOT checked — reinit succeeds
5. Account state resets to zero balance
6. Attacker calls `withdraw()` for original deposit
7. Attacker drains protocol

## Impact
- Complete drain of protocol if attacker can reinit accounts they control
- Loss of all deposited funds
- CVSS: 9.8 (CRITICAL)

## Code Reference
`programs/vault/src/lib.rs:reinit_instruction()`

## Remediation
Add discriminator check before reinitializing:
```rust
require!(account.is_initialized(), ErrorCode::AlreadyInitialized);
```
