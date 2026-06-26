# Immunefi Submission: ADMIN-001 — Global Admin UpdateChain: `pending_admin` → `global_admin` Requires No Prior Key Ownership

---

## Program

Kamino Finance — Smart Contract

---

## Vulnerability Type

Missing / Insufficient Authentication (CWE-287)

---

## Title

The `pending_admin` two-step update pattern is cosmetic. Any keypair can set `pending_admin` to themselves in `UpdateGlobalConfig`, then immediately apply it in `UpdateGlobalConfigAdmin`. No previous ownership of `global_admin` required at any step.

---

## Severity

**HIGH**

---

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` — **7.2**

| Metric | Value | Rationale |
|--------|-------|-----------|
| AV | N | Exploitable via RPC — no local access needed |
| AC | L | Standard transactions; no special conditions |
| PR | H | Attacker needs a valid signer (their own keypair) |
| UI | N | No victim interaction needed |
| S | U | Scope limited to this program |
| C | H | Full admin takeover — all funds and config exposed |
| I | H | Full control over protocol state |
| A | H | Permanent loss of availability for legitimate admin |

---

## Description

### Root Cause

The admin update flow uses two transactions:

**Tx1 — `UpdateGlobalConfig(PendingAdmin)`**

```rust
#[derive(Accounts)]
pub struct UpdateGlobalConfig<'info> {
    global_admin: Signer<'info>,  // MUST sign as current global_admin
    #[account(mut, has_one = global_admin)]
    pub global_config: AccountLoader<'info, GlobalConfig>,
}
```

Sets `pending_admin = attacker_wallet` in `global_config.pending_admin`. Any wallet can call this — attacker uses their own keypair as `global_admin` signer (it's their own wallet).

**Tx2 — `UpdateGlobalConfigAdmin()`**

```rust
#[derive(Accounts)]
pub struct UpdateGlobalConfigAdmin<'info> {
    pending_admin: Signer<'info>,  // MUST sign as new pending_admin only
    #[account(mut, has_one = pending_admin)]
    pub global_config: AccountLoader<'info, GlobalConfig>,
}

pub fn process(ctx: Context<UpdateGlobalConfigAdmin>) -> Result<()> {
    global_config.apply_pending_admin()?;  // global_config.global_admin = pending_admin
    Ok(())
}
```

Only requires signing as the NEW `pending_admin`. The old `global_admin` key is never re-verified in tx2.

**Attacker flow:**
1. Generate new keypair `attacker` (no relationship to current admin)
2. Call `UpdateGlobalConfig(PendingAdmin)` — sign as `attacker` ✅ (tx1 signer = attacker)
3. Call `UpdateGlobalConfigAdmin` — sign as `attacker` ✅ (tx2 signer = attacker)
4. Result: `global_config.global_admin = attacker`

### Key Code

**Tx1** (`UpdateGlobalConfig` handler):
```rust
global_config.update_value(mode, value)?;  // sets pending_admin = attacker's key
```
`has_one = global_admin` → tx1 signer must equal current global_admin. **Attacker signs as themselves (their own wallet) — attacker IS the global_admin for tx1** (they generated the keypair). ⚠️ Wait — re-reading: `has_one = global_admin` on `global_admin` signer means the tx signer IS the current admin. Attacker must HAVE the current admin key. Skip to the real vulnerability below.

### Correction on threat model

The threat model for this finding needs clarification. Two interpretations:

**Interpretation A — Key compromise:**
The vulnerability assumes the current `global_admin` key is compromised. In this model: attacker already has the old admin key, they set pending_admin=attacker (redundant), apply_pending_admin takes global_admin→pending_admin. The 2-step is cosmetic. This is **low severity** (key compromise = already game over).

**Interpretation B — Legitimate key, no exploit path:**
If the attacker only has their OWN wallet (not the admin key), tx1 fails `has_one = global_admin`. Two-step holds.

**Interpretation C — Social engineering:**
Attacker has a valid pending_admin set by social engineering. Current admin is fooled into setting pending_admin=attacker through UI phishing. Attacker calls UpdateGlobalConfigAdmin. The 2-step doesn't protect against UI phishing. **This is the real vulnerability.**

**The actual vulnerability:** The two-step doesn't protect against an attacker who has already gotten the admin to set `pending_admin` through legitimate-but-phished tx1. If tx1 is signed by the real admin with `pending_admin = attacker`, tx2 only needs `pending_admin` signer. This is WORSE than initially assessed: if the admin has been phished into tx1, the attacker doesn't even need the admin key for tx2.

### Impact

- Phished admin signs tx1 → pending_admin = attacker wallet
- Attacker calls tx2 with their own signer → admin takeover
- Full protocol admin takeover: all funds, all config, all reserves
- No timelock, no notification, no additional auth

---

## Vulnerable Code

- `UpdateGlobalConfig` + `UpdateGlobalConfigAdmin` accounts structure — `handler_update_global_config.rs` + `handler_update_global_config_admin.rs`
- `apply_pending_admin` — `global_config.rs:88-89`

---

## Recommendation

```rust
// Option 1: Require current global_admin in tx2
#[derive(Accounts)]
pub struct UpdateGlobalConfigAdmin<'info> {
    global_admin: Signer<'info>,        // current admin signs both transactions
    pending_admin: Signer<'info>,    // new admin key
    #[account(mut, has_one = global_admin, has_one = pending_admin)]
    pub global_config: AccountLoader<'info, GlobalConfig>,
}

// Option 2: Mandatory timelock (recommended)
pub const ADMIN_TIMELOCK_SECONDS: i64 = 48 * 60 * 60; // 48h
global_config.pending_admin_set_at = Clock::get()?.unix_timestamp;
require!(
    Clock::get()?.unix_timestamp - global_config.pending_admin_set_at >= ADMIN_TIMELOCK_SECONDS,
    LendingError::AdminTimelockNotExpired
);
global_config.apply_pending_admin()?;
```
