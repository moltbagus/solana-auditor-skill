# Audit Report — native-vault

**Program:** `native-vault` (non-Anchor Solana program)
**Framework:** Native `solana-program` 1.18 — no Anchor derive macros
**File:** `programs/native-vault/src/lib.rs`
**Findings:** 4 vulnerabilities (2 CRITICAL, 1 HIGH, 1 MEDIUM)
**Status:** All Open

---

## Scope

| Function | Description |
|---|---|
| `initialize` | Creates vault PDA, stores authority + bump |
| `deposit` | Transfers lamports into vault, updates `total_deposits` |
| `withdraw` | Transfers lamports out, verifies authority |
| `set_authority` | Changes vault authority (correctly signed) |

---

## Findings

| ID | Title | Severity |
|---|---|---|
| VULN-N01 | Clock sysvar deserialised from account data — spoofable | CRITICAL |
| VULN-N02 | Missing signer verification on authority account | CRITICAL |
| VULN-N03 | Unchecked u64 addition in deposit — arithmetic overflow | HIGH |
| VULN-N04 | Non-canonical bump stored in vault state | MEDIUM |

---

## VULN-N01 — Clock Sysvar Spoofing

**Location:** `withdraw`, line 149

The `withdraw` instruction accepts a `clock_account` from the accounts array and calls `Clock::from_account_info(clock_account)` instead of `Clock::get()`. A caller can supply a faked `AccountInfo` whose data deserialises to arbitrary `slot`, `epoch`, and `timestamp` values.

**Impact:** Any time- or slot-gated logic is bypassed. Timelock-release windows, epoch-based cooldowns, and staleness checks are all ineffective against an attacker who controls the clock account.

**Remediation:** Replace `Clock::from_account_info(clock_account)` with `Clock::get()?`. The runtime-provided Clock sysvar requires no account to be passed.

---

## VULN-N02 — Missing Signer Verification

**Location:** `withdraw`, line 163

The instruction checks `authority.key == vault_state.authority` but omits `authority.is_signer`. Solana transaction accounts are independent of signing keys — any account can be included regardless of who signed the transaction. An attacker who supplies an account whose pubkey matches the stored authority passes the pubkey check.

**Impact:** Any transaction including an account with the authority pubkey — regardless of signing key — can drain the vault.

**Remediation:** Add `if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }` before the pubkey comparison.

---

## VULN-N03 — Unchecked Arithmetic (u64 Overflow)

**Location:** `deposit`, line 112

`vault_state.total_deposits = vault_state.total_deposits + amount` uses the unchecked `+` operator. In release mode, `u64` overflow wraps silently.

**Impact:** By depositing strategically sized amounts, an attacker causes `total_deposits` to wrap past `u64::MAX`, then withdraws against the inflated balance.

**Remediation:** `vault_state.total_deposits = vault_state.total_deposits.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;`

---

## VULN-N04 — Non-Canonical Bump

**Location:** `initialize`, line 70

The bump is passed as an instruction argument (`bump: u8`) and stored directly without derivation. The correct pattern calls `Pubkey::find_program_address(seeds, program_id)` which returns the canonical bump.

**Impact:** Storing a non-canonical bump enables PDA collision: an attacker may derive a valid vault PDA using different seed/bump combinations that collide with the stored address, potentially bypassing bump-based access control.

**Remediation:** Derive the bump with `Pubkey::find_program_address(seeds, program_id)` and store only the result from that call. Never accept bump from instruction data.

---

## Comparison with Anchor Vault Fixture

| Bug Class | Anchor vault (VULN-xx) | Native vault (VULN-Nxx) |
|---|---|---|
| Signer verification | VULN-01, VULN-04 | VULN-N02 |
| Arithmetic overflow | VULN-05 | VULN-N03 |
| Canonical bump | VULN-02 | VULN-N04 |
| Sysvar spoofing | N/A (Anchor uses typed wrappers) | VULN-N01 |

The native fixture surfaces sysvar spoofing as a first-class vulnerability class unavailable in the Anchor fixture, where `Clock::get()` is the only available path. Native programs require manual sysvar pubkey validation when accounts are passed, which is a distinct attack surface.
