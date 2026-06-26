# Immunefi Submission: PERM-003 — Permissioning Authority Update Silently Redirects All Restricted Operations Without Timelock

---

## Program

Kamino Finance — Smart Contract

---

## Vulnerability Type

Missing / Insufficient Administrative Process (CWE-285)

---

## Title

`UpdateLendingMarket(UpdatePermissioningAuthority)` silently replaces the permissioning_authority, immediately enabling all Deposit/Borrow/Liquidate operations on permissioned reserves with no event, no timelock, and no multisig requirement

---

## Severity

**HIGH**

---

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` — **7.2**

| Metric | Value | Rationale |
|--------|-------|-----------|
| AV | N | Exploitable via RPC — no local access needed |
| AC | L | Standard transaction; no special conditions |
| PR | H | Requires lending_market_owner key (or emergency_council on 3 specific modes) |
| UI | N | No victim interaction needed |
| S | U | Scope limited to this program |
| C | H | Full state readable: reserves, obligations, permissions |
| I | H | Full admin control once permissioning_authority replaced |
| A | H | Permanent availability impact if attacker locks permissions |

---

## Description

### Root Cause

In `programs/klend/src/handlers/handler_update_lending_market.rs`, `UpdateLendingMarket(UpdatePermissioningAuthority)` silently overwrites the lending market's `permissioning_authority` with no event, no timelock, no multisig, no notification:

```rust
UpdateLendingMarket(UpdatePermissioningAuthority) => {
    config_items::for_named_field(&mut market.permissioning_authority).set(&value)?;
}
```

No events are emitted. No timelock between setting and activation. The attacker (or malicious insider) immediately has permissioning_authority control.

### Who Controls permissioning_authority

On permissioned reserves, `permissioning_authority` gates:
- `DEPOSIT` — can enable/disable deposits
- `BORROW` — can enable/disable borrows
- `LIQUIDATE` — can exercise liquidation rights on permissioned obligations
- `REQUIREDX_ASSET` — asset-level access control

An attacker who controls `permissioning_authority` can immediately:
1. Block all borrows on affected reserves (Denial of Service)
2. Block all liquidations (trap positions in insolvency)
3. Redirect permissioning to an attacker key and operate on restricted reserves

### Attack Scenario: Insider + Permissioned Reserve

1. Lending market has permissioned reserves (requires explicit allowlist for operations)
2. Insider/compromised key calls `UpdateLendingMarket(UpdatePermissioningAuthority)` → permissioning_authority = attacker_wallet
3. Attacker exercises BORROW on restricted reserve, or disables liquidation
4. No event emitted — off-chain monitoring cannot detect this
5. Funds at risk before anomaly is visible

### Emergency Council Limitation

Emergency council can call UpdateLendingMarket only on 3 modes: `UpdateEmergencyMode`, `UpdateBorrowingDisabled`, `UpdatePriceTriggeredLiquidationDisabled` (and only when `value == true`). `UpdatePermissioningAuthority` requires lending_market_owner directly — no emergency council escalation path.

### Immutable Flag Does Not Protect

The immutable flag on a lending market only prevents modifying market parameters after initialization. The permissioning_authority update happens before immutable is set, or on markets that never set it.

---

## Vulnerable Code

- `UpdateLendingMarket(UpdatePermissioningAuthority)` handler — `handler_update_lending_market.rs`

---

## Recommendation

```rust
// Option 1: Mandatory timelock
pub const PERMISSIONING_AUTHORITY_TIMELOCK_SECONDS: i64 = 48 * 60 * 60; // 48h
global_config.permissioning_authority_timelock_deadline = Clock::get()?.unix_timestamp + PERMISSIONING_AUTHORITY_TIMELOCK_SECONDS;
// emit event PermissioningAuthorityChangeRequested(new_authority, deadline)
require!(
    Clock::get()?.unix_timestamp >= market.permissioning_authority_timelock_deadline,
    LendingError::PermissioningAuthorityTimelockNotExpired
);
market.permissioning_authority = new_authority;
emit!(PermissioningAuthorityChanged { new_authority, timestamp: Clock::get()?.unix_timestamp });

// Option 2: Multisig requirement
require!(is_multisig(market.permissioning_authority), LendingError::Unauthorized);
// emit event
```

Add mandatory event emission at minimum.
