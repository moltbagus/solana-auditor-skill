---
name: "02-threat-modeling"
description: "Phase 2A: STRIDE threat enumeration for Solana/Anchor programs — enumerate threats, cross-reference with Phase 2 findings, and validate coverage gaps"
triggers:
  - "User requests threat model for a program"
  - "After Phase 1 recon (attack_surface.json, cpi_surface.json available)"
  - "Before Phase 2 static analysis (primes the static analyzer)"
  - "Threat model flag passed: /audit --threat-model"
examples:
  - "enumerate threats for this vault program"
  - "run threat model on programs/vault/src/lib.rs"
  - "/audit examples/sample-vulnerable-program --threat-model"
---

# Phase 2A: Threat Modeling (STRIDE on Solana)

**Goal**: Enumerate threats using STRIDE, cross-reference with Phase 2 findings to validate coverage, and surface missing attack paths.

**Prerequisites**: Phase 1 recon artifacts — `attack_surface.json`, `cpi_surface.json`, `program_metadata.json`.

**Execution order**: Run after Phase 1 recon, in parallel with or immediately before Phase 2 static analysis. Threat model output feeds the CPI surface graph integration in Phase 4 triage.

---

## STRIDE Overview for Solana

| Threat | Property Violated | Solana Root Cause | Detection Rules |
|--------|-------------------|-------------------|----------------|
| **S**poofing | Authentication | Missing signer verification, PDA bump collision | Rules 1, 3, 8, 36 |
| **T**ampering | Integrity | Account data mutation without ownership check | Rules 2, 7, 15, 22, 24, 37, 38 |
| **R**epudiation | Non-repudiation | Missing event emission, unsigned actions | Rules 10, 23 |
| **I**nformation Disclosure | Confidentiality | Deserialized accounts without owner check, sysvar spoof | Rules 17, 36, 39 |
| **D**enial of Service | Availability | Panic in instruction, rent exemption bypass, close drain | Rules 7, 10, 12, 18, 22 |
| **E**levation of Privilege | Authorization | Unsigned invoke, CPI privilege escalation, discriminator collision | Rules 4, 8, 13, 16, 27, 31, 33, 35 |

---

## Threat List Output Format

Produce one JSON artifact per program:

```
audit-report/threats/{program_name}_threats.json
```

```json
{
  "program": "vault_program",
  "version": "1.2.0",
  "analyst": "threat-modeler",
  "stride_map": {
    "spoofing": [...],
    "tampering": [...],
    "repudiation": [...],
    "information_disclosure": [...],
    "denial_of_service": [...],
    "elevation_of_privilege": [...]
  },
  "trust_boundaries": [...],
  "attack_sequences": [...],
  "coverage_gap_summary": "..."
}
```

### Threat Entry Schema

```json
{
  "id": "TM-VAULT-001",
  "stride": "elevation_of_privilege",
  "title": "Missing signer check on withdraw CPI",
  "description": "The withdraw instruction calls token_program::transfer via invoke without verifying that ctx.accounts.user.is_signer. An attacker with the ability to CPI-call the vault program can drain all tokens.",
  "affected_entry_points": ["withdraw"],
  "affected_accounts": ["vault_token", "user_token"],
  "cwe": "CWE-346",
  "cvss_estimate": 8.6,
  "cvss_vector_estimate": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "phase2_rules": ["Rule 4", "Rule 7"],
  "phase2_status": "covered",
  "phase1_artifacts": ["cpi_surface.json:line_142"],
  "poc_status": "pending",
  "remediation": "Add require!(ctx.accounts.user.is_signer) before invoke.",
  "references": []
}
```

---

## Threat Enumeration Procedure

### Step 1: Load Phase 1 Artifacts

```bash
# Verify required artifacts exist
ls audit-report/attack_surface.json
ls audit-report/cpi_surface.json
ls audit-report/raw/recon.md

# Load program entry points
cat audit-report/attack_surface.json | jq '.entry_points'
```

### Step 2: Enumerate Trust Boundaries

Map every external actor that interacts with the program:

```json
{
  "trust_boundaries": [
    {
      "boundary": "user_wallet -> program",
      "trust_level": "partial",
      "channel": "transaction_instruction",
      "verification_point": "Signer account in instruction accounts",
      "bypass_risk": "Stolen key / wallet drain"
    },
    {
      "boundary": "program -> token_program",
      "trust_level": "trusted",
      "channel": "CPI invoke",
      "verification_point": "Token program validates authority",
      "bypass_risk": "Missing owner check on token accounts"
    },
    {
      "boundary": "program -> external_program",
      "trust_level": "untrusted",
      "channel": "CPI invoke_signed",
      "verification_point": "Seeds + bump validation in caller",
      "bypass_risk": "CPI privilege escalation, malicious callback"
    },
    {
      "boundary": "program -> pda_account",
      "trust_level": "internal",
      "channel": "Account validation via #[account(...)]",
      "verification_point": "Discriminator + owner + signer constraints",
      "bypass_risk": "Wrong account type, non-canonical bump"
    }
  ]
}
```

### Step 3: STRIDE Enumeration by Category

#### S — Spoofing

**Solana attack surface for spoofing**:

| Threat | Vector | Anchor Pattern |
|--------|--------|---------------|
| Stolen key drains wallet | Phishing / malware exfiltrates private key | N/A (key management) |
| Fake signer account in CPI | Attacker passes signer's AccountInfo to program | Missing `is_signer` check before `invoke` |
| Mint metadata spoofing | Mint with fake metadata_pointer pointing to legitimate metadata | No `metadata_pointer` verification on mint ops |
| PDA spoofing via non-canonical bump | Derive PDA with non-canonical bump, pass to victim program | No bump canonicalization in `#[account(...)]` |

**Example threat entry**:
```json
{
  "id": "TM-VAULT-S01",
  "stride": "spoofing",
  "title": "Missing is_signer check enables fake signer CPI",
  "description": "The deposit instruction accepts a signer_account parameter that is not verified as a signer before the instruction is processed. An attacker can craft a transaction where signer_account is a legitimate authority key but the transaction itself is not signed by that key, then CPI-call the program with the fake signer_account in the accounts list.",
  "affected_entry_points": ["deposit"],
  "affected_accounts": ["signer_account"],
  "cwe": "CWE-346",
  "cvss_estimate": 9.1,
  "phase2_rules": ["Rule 3"],
  "phase2_status": "pending"
}
```

#### T — Tampering

**Solana attack surface for tampering**:

| Threat | Vector | Anchor Pattern |
|--------|--------|---------------|
| Account reinitialization | Create account with same discriminator after deletion | Missing `init` bump seed validation |
| PDA bump tampering | Use non-canonical bump to derive different address | No bump check in `find_program_address` call |
| Cross-program account morphing | Reallocate account from program A owner to program B owner | Missing `realloc` owner validation |
| Token amount overflow/underflow | Arithmetic without checked_add/checked_sub | Manual u64 arithmetic without overflow guard |
| State corruption via remaining_accounts | Pass unexpected accounts via remaining_accounts | No validation on `ctx.remaining_accounts` |

**Example threat entry**:
```json
{
  "id": "TM-VAULT-T01",
  "stride": "tampering",
  "title": "Reinitialization attack via missing bump validation",
  "description": "The init_vault instruction creates a vault PDA but does not store or verify the canonical bump. An attacker can call init_vault a second time with a different bump, reinitializing the vault state and resetting the balance to zero. All tokens deposited under the old PDA are inaccessible.",
  "affected_entry_points": ["init_vault"],
  "affected_accounts": ["vault_pda"],
  "cwe": "CWE-565",
  "cvss_estimate": 7.5,
  "phase2_rules": ["Rule 18"],
  "phase2_status": "pending"
}
```

#### R — Repudiation

**Solana attack surface for repudiation**:

| Threat | Vector | Anchor Pattern |
|--------|--------|---------------|
| Unsigned instruction ambiguity | Program accepts non-signer caller but logs as if authorized | No `is_signer` enforcement + event emission |
| Missing authority check on events | Events emitted without verifying signer | `emit!` without prior signer check |
| No tx correlation ID | Multiple identical txs indistinguishable | Missing nonce / sequence counter |

**Note**: Solana's transaction log is immutable and public. Repudiation threats focus on ambiguity in program-level authorization, not on-chain log tampering.

#### I — Information Disclosure

**Solana attack surface for information disclosure**:

| Threat | Vector | Anchor Pattern |
|--------|--------|---------------|
| Unintended account data exposure | Account data readable by any program via CPI | Confidential transfer state not cleared |
| PDA derivation exposure | Seeds visible in tx — if seeds contain secrets, disclose | Never use user-controlled or secret data as seeds |
| Token balance enumeration | Read any account balance via `AccountInfo` | No access control on balance queries |
| CPI data leakage | Pass sensitive data through CPI accounts without scoping | Unchecked `AccountInfo` cloning in CPI |

#### D — Denial of Service

**Solana attack surface for denial of service**:

| Threat | Vector | Anchor Pattern |
|--------|--------|---------------|
| Rent exhaustion of program accounts | Close account without proper cleanup, leaving orphaned state | Missing rent validation on close |
| Invalid state lock | Set program to a state that blocks all future instructions | No state transition validation |
| Account size manipulation | Realloc to maximum size, exhausting rent | Missing `max_size` constraint |
| CPI recursion exhaustion | Recursive CPI chain exceeds compute budget | No compute budget check before CPI |
| Anchor constraint bypass via account replacement | Pass modified AccountInfo via remaining_accounts | No `realloc` + `owner` validation |

#### E — Elevation of Privilege

**Solana attack surface for elevation of privilege** (highest density of Solana vulnerabilities):

| Threat | Vector | Anchor Pattern |
|--------|--------|---------------|
| CPI privilege escalation — no signer check | `invoke` without `require!(ctx.accounts.x.is_signer)` | Rules 3, 4, 7 |
| CPI privilege escalation — user-controlled seeds | `invoke_signed` with seeds from untrusted input | Rule 21 |
| Missing owner check on token account | Transfer tokens from account owner is not verified | Rule 8 |
| Anchor constraint bypass | `#[account(...)]` missing required constraint (mut, signer, has_one) | Rules 1–2, 10–12 |
| Missing rent-exemption check on init | New account initialized without verifying rent-exemption | Rule 19 |
| Upgrade authority abuse | Program has upgrade authority — new version can backdoor | Phase 1 check |
| Delegate authority escalation | Token delegate approved, then delegate drains more than authorized | Token Extensions check |
| Mint freeze / close authority | Token mint has freeze authority that can lock all tokens | Token Extensions check |
| Confidential transfer fee not extracted | Receiver settles transfer without deducting fee | Token Extensions Rule 31 |

**Example threat entry**:
```json
{
  "id": "TM-VAULT-E01",
  "stride": "elevation_of_privilege",
  "title": "CPI to token program without signer verification allows arbitrary transfer",
  "description": "The withdraw_tokens instruction invokes spl_token::transfer without first verifying that ctx.accounts.authority.is_signer. Any program that CPI-calls withdraw_tokens can transfer all tokens held by the vault to an arbitrary destination.",
  "affected_entry_points": ["withdraw_tokens"],
  "affected_accounts": ["vault_token", "user_token", "authority"],
  "cwe": "CWE-347",
  "cvss_estimate": 9.8,
  "cvss_vector_estimate": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "phase2_rules": ["Rule 4", "Rule 7"],
  "phase2_status": "pending",
  "phase1_artifacts": ["cpi_surface.json:edge_vault_token_transfer"],
  "remediation": "Add require!(ctx.accounts.authority.is_signer) before invoke. If using invoke_signed, verify canonical bump.",
  "poc_status": "pending"
}
```

---

## CPI Surface Graph Integration

After enumerating threats, annotate the `cpi_surface.json` edges with threat IDs:

```bash
# Augment cpi_surface.json with threat IDs
# For each edge where callee is untrusted:
#   - Add "threat_ids": ["TM-PROG-E01", ...]
#   - Add "threat_level": "CRITICAL|HIGH|MEDIUM|LOW"
```

### Threat-to-Edge Mapping

| CPI Pattern | Primary STRIDE | Threat ID Pattern |
|-------------|---------------|-------------------|
| `invoke` without `is_signer` | E (Elevation) | `TM-{prog}-E01` |
| `invoke_signed` with dynamic seeds | E (Elevation) + T (Tampering) | `TM-{prog}-E02`, `TM-{prog}-T02` |
| `invoke` to untrusted program | E (Elevation) | `TM-{prog}-E03` |
| Token transfer without owner check | E (Elevation) | `TM-{prog}-E04` |
| Account reallocation | T (Tampering) | `TM-{prog}-T01` |
| Reentrancy via CPI callback | E (Elevation) + D (DoS) | `TM-{prog}-E05`, `TM-{prog}-D01` |
| Flash loan path | E (Elevation) | `TM-{prog}-FL01` |

### Augmented cpi_surface.json Edge Schema

```json
{
  "edges": [
    {
      "edge_id": "vault:142",
      "caller": "vault_program",
      "callee": "token_program",
      "instruction": "transfer",
      "file": "programs/vault/src/lib.rs",
      "line": 142,
      "signer_verified": false,
      "threat_ids": ["TM-VAULT-E01"],
      "threat_level": "CRITICAL",
      "stride": ["elevation_of_privilege"],
      "linked_phase2_findings": ["HIGH-003"]
    }
  ]
}
```

---

## Reference Implementation — sample-vulnerable-program

The `examples/sample-vulnerable-program/` fixture contains intentionally vulnerable code mapped to STRIDE categories. Use it to validate threat model coverage:

```
examples/sample-vulnerable-program/
programs/
  vault/src/lib.rs          # Anchor — spoofing, EoP, tampering threats
  token-extensions/src/lib.rs  # Token-2022 — extension threats
  native-vault/src/lib.rs   # Native Solana — Pinocchio threats
tests/
  threat_model_test.rs      # Validates threat enumeration against known vulns
exploit-pocs/
  *.rs                      # PoC exploits keyed by threat ID
```

### Mapping Fixture to STRIDE

| File | STRIDE Category | Threat IDs |
|------|----------------|-----------|
| `programs/vault/src/lib.rs:deposit` | S, E | `TM-VAULT-S01`, `TM-VAULT-E01` |
| `programs/vault/src/lib.rs:withdraw` | E | `TM-VAULT-E01` |
| `programs/vault/src/lib.rs:init_vault` | T | `TM-VAULT-T01` |
| `programs/token-extensions/src/lib.rs` | I, E | `TM-TOKEN-E01`, `TM-TOKEN-I01` |
| `programs/native-vault/src/lib.rs` | E, D | `TM-NATIVE-E01`, `TM-NATIVE-D01` |

Run the validation suite:
```bash
cd examples/sample-vulnerable-program
anchor test --test threat_model_test
# Expect: 6 passing tests (one per STRIDE category coverage check)
```

---

## Threat Model Output Artifacts

| Artifact | Path | Contents |
|----------|------|----------|
| Per-program threat list | `audit-report/threats/{program}_threats.json` | Full STRIDE enumeration |
| Augmented CPI surface | `audit-report/cpi_surface_threats.json` | CPI edges annotated with threat IDs |
| Coverage matrix | `audit-report/threats/coverage_matrix.json` | Threat ID to Phase 2 finding mapping |
| Trust boundary diagram | `audit-report/threats/trust_boundaries.md` | Textual trust boundary map |
| Executive summary | `audit-report/threats/executive_summary.md` | Top 10 threats by CVSS |

---

## Integration with Phase 2 Static Analysis

Threat modeling and static analysis are complementary:

| Aspect | Threat Modeling (Phase 2A) | Static Analysis (Phase 2) |
|--------|--------------------------|--------------------------|
| Direction | Top-down (threat to code) | Bottom-up (code to vulnerability) |
| Output | Threat list with CVSS | Finding list with CVSS |
| Coverage | Threat-complete (all STRIDE) | Pattern-complete (50 rules) |
| Overlap | Each threat maps to rule(s) | Each finding maps to threat(s) |

**Validation step**: For every threat in the threat model, verify that Phase 2 produced a corresponding finding. If a HIGH/CRITICAL threat has no Phase 2 finding, it is a **coverage gap** — flag it explicitly in `coverage_matrix.json`.

**Coverage gap schema**:
```json
{
  "threat_id": "TM-VAULT-E01",
  "has_phase2_finding": false,
  "gap_severity": "HIGH",
  "explanation": "Phase 2 static analysis did not flag the missing is_signer check on line 142 because the rule pattern did not account for CPI context."
}
```

---

## Next Phase

After threat model → load `skill/02-static-analysis.md` (Phase 2) with threat IDs as input context. The threat list primes the static analyzer to look for specific patterns first.

---

## Detailed STRIDE Analysis — Real-World Exploits

The following sections map real-world Solana exploits to STRIDE categories, providing detailed root cause analysis and detection patterns.

### S — Spoofing

#### Wormhole (Feb 2022, $320M) — Guardian Signature Spoofing
The attacker spoofed Guardian signatures on the Wormhole bridge by exploiting a `verify_signature` CPI call that did not validate the guardian set version. The attacker passed a fake guardian set with their own signatures.

**Root cause**: CPI to the signature verification program accepted accounts from `remaining_accounts` without verifying the guardian set discriminator.

**Exploit flow**:
1. Attacker creates a fake guardian set account with their controlled signatures
2. Passes fake guardian set via `remaining_accounts` to CPI
3. `verify_signature` invoked without checking guardian set owner
4. Signed message accepted as valid
5. 120k WETH minted on Solana unbacked on Ethereum

**Code pattern**:
```rust
// VULNERABLE: CPI without remaining_accounts validation
pub fn submit_vaa(ctx: Context<SubmitVaa>, vaa: Vec<u8>) -> Result<()> {
    let accounts = ctx.remaining_accounts; // Attacker controls this slice
    invoke(
        &verification_instruction,
        &accounts, // No validation of guardian set account
    )?;
    // ...
}
```

**Detection**: Rule 15 (remaining_accounts validation), Rule 4 (CPI program ID check), Rule 17 (AccountLoader without owner).

---

#### Cashio ($52M, Mar 2022) — Mint Authority PDA Spoofing
Cashio's `mint_authority` PDA was derived using a hardcoded bump (`255`) instead of the canonical bump. An attacker found a different valid bump that produced the same PDA, bypassing the mint authority check.

**Root cause**: Rule 3 violation — hardcoded bump used as a security parameter.

**Exploit flow**:
1. Attacker derives the "bridge" PDA using a non-canonical bump
2. Calls `mint` with the attacker-derived PDA as authority
3. Program checks `Pubkey::find_program_address` but uses the hardcoded bump directly
4. PDA matches expected mint authority — bypassed
5. 52M CGG tokens minted unbacked

**Code pattern**:
```rust
// VULNERABLE: Uses result from find_program_address but hardcodes bump
let (expected_pda, _) = Pubkey::find_program_address(&[b"bridge"], program_id);
let attacker_pda = Pubkey::create_program_address(&[b"bridge", &[255]], program_id).unwrap();
// attacker_pda == expected_pda when bump 255 produces off-curve

// FIXED:
let vault_auth = Pubkey::find_program_address(
    &[b"bridge", ctx.accounts.user.key().as_ref()],
    &ID,
).0;
require_keys_eq!(ctx.accounts.authority.key(), vault_auth, ErrorCode::NotAuthority);
```

**Detection**: Rule 3 (PDA canonical bump), grep for `[255]` as bump literal.

---

#### Nirvana Finance ($3M, Jul 2022) — Price Feed Spoofing
Nirvana used a Price Authority contract that could be manipulated via flash loan. The price feed was spoofed within the same transaction, causing the protocol to believe the collateral was worth 10x its actual value.

**Root cause**: Price source not commit-reveal, no TWAP staleness check.

**Detection**: Rule 13 (flash loan oracle manipulation), Rule 26 (cross-program flash loan).

---

### T — Tampering

#### Crema Finance ($8.8M, Jul 2022) — Account Tampering via Close + Flash Loan
Crema allowed accounts to be closed and reinitialized within the same transaction via flash loan. The attacker tampered with the liquidity position account's data by closing it mid-transaction and reinitializing with manipulated state.

**Root cause**: Rule 7 — `close` target not properly guarded; Rule 22 — `init_if_needed` + `close` race.

**Code pattern**:
```rust
// VULNERABLE: close target is user-supplied or attacker-accessible
#[derive(Accounts)]
pub struct ClosePosition<'info> {
    #[account(mut, close = victim)] // close target is not the program/PDA
    pub position: Account<'info, Position>,
    pub victim: Signer<'info>, // victim signs, but funds go to attacker
}
```
Attacker front-runs victim's transaction with their own close instruction.

**Detection**: Rule 7 (close authority), Rule 22 (init_if_needed race).

---

#### Raydium ($1.6M, Jan 2023) — `remaining_accounts` Tampering
Raydium's `add_liquidity` instruction accepted `remaining_accounts` that were not validated. An attacker injected a fake pool state account via `remaining_accounts`, causing the program to use attacker-controlled pool data for liquidity calculations.

**Root cause**: Rule 15 — `remaining_accounts` not validated; Rule 24 — count mismatch in CPI.

**Code pattern**:
```rust
// VULNERABLE: remaining_accounts used without validation
pub fn add_liquidity(ctx: Context<AddLiquidity>, ...) -> Result<()> {
    let pool_accounts = ctx.remaining_accounts;
    // No validation: count, signer flags, owner check, pubkey match
    let pool = &pool_accounts[0];
    let reserves = read_reserves(pool)?; // Attacker controls this
}
// FIXED: Validate every remaining_account
let pool_accounts = ctx.remaining_accounts;
require!(pool_accounts.len() >= 3, ErrorCode::InvalidAccounts);
require!(pool_accounts[0].is_writable, ErrorCode::NotWritable);
require!(pool_accounts[0].owner == &amm_pool::ID, ErrorCode::InvalidPoolOwner);
```

**Detection**: Rule 15, Rule 24. Grep for `remaining_accounts` without corresponding validation loops.

---

#### Mango Markets ($117M, Oct 2022) — Oracle Tampering + Account Manipulation
The attacker manipulated Mango's oracle (perp funding rate) and tampered with the on-chain account state by using a different account that passed ownership validation but contained manipulated position data.

**Root cause**: Rule 17 — `AccountLoader` without owner validation; Rule 13 — oracle manipulation within same transaction.

**Detection**: Rule 13, Rule 17, Rule 39.

---

### R — Repudiation

**Social engineering via memo injection** (Rule 23):
```rust
// VULNERABLE: User-supplied memo in CPI to Memo program
invoke(
    &spl_memo::instruction::build(ctx.accounts.user_provided_memo.as_bytes()),
    &[],
)?;
// Logs: "Deposit confirmed" — attacker changes memo to "Withdraw confirmed"
// Off-chain systems reading logs are deceived
```
**Fix**: Always use program-controlled constant memos, or hash user data into a program-generated memo.

---

### I — Information Disclosure

#### Mango Markets — State Reading for Attack Planning
The attacker read Mango's on-chain state (open positions, oracle prices) to craft an optimal attack transaction. While technically legal on-chain behavior, it highlights that programs should not assume information asymmetry.

#### Token-2022 Confidential Transfers
Confidential transfer extension encrypts amounts, but the protocol must still verify fee extraction on settle. Information disclosure here means leaking transfer amounts via timing side-channels or fee calculation bugs.

**Code pattern — timing side-channel**:
```rust
// VULNERABLE: Fee calculation timing reveals transfer amount
let decrypt_start = Clock::get()?.slot;
// ... decrypt and compute fee ...
let decrypt_time = Clock::get()?.slot - decrypt_start;
// Timing of decryption correlates with magnitude of amounts
```
**Fix**: Use constant-time decryption and fixed-iteration fee calculations.

---

### D — Denial of Service

#### Rent-Exemption Exhaustion
An attacker could create thousands of accounts that a victim's program depends on, then close them when rent exemption lapses, causing the victim's instructions to fail when they try to access non-existent accounts.

**Detection**: Rule 12 (rent exemption), Rule 7 (account closing).

#### Instruction Panics (Rule 10, Rule 18)
```rust
// VULNERABLE: panic aborts transaction, may leave state inconsistent
fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> EntrypointResult {
    let data = instruction_data.unwrap(); // panic on malformed data
    // ...
}
```
**Fix**: Use `Result` types with `?` propagation. Never `unwrap()` on untrusted data.

---

### E — Elevation of Privilege

#### Nomad Bridge ($190M, Aug 2022) — Replica Program EoP
Nomad's bridge used a "replica" pattern where a separate program could process messages on behalf of the main bridge. The replica's `process` instruction accepted any message without verifying it was actually confirmed on the main chain.

**Root cause**: Missing origin verification on the replica program; upgrade authority allowed deploying a malicious replica.

**Exploit flow**:
1. Attacker deploys a fake replica program with upgrade authority
2. Or: exploits the legitimate replica's missing message verification
3. Processes a fake "confirmed" message
4. Withdraws tokens without corresponding deposit on origin chain

**Detection**: Rule 9 (upgrade authority), Rule 4 (CPI privilege escalation).

---

#### Mango Markets ($117M, Oct 2022) — Perp Oracle EoP + Liquidity Theft
Two-phase exploit:
1. **Phase 1 — Oracle EoP**: Attacker manipulates Mango's perpetual funding rate to make their large position appear extremely valuable
2. **Phase 2 — Account EoP**: Uses the inflated collateral to drain all liquidity from Mango's deposits

**Root cause**: Rule 13 — oracle manipulation within same transaction; Rule 17 — `AccountLoader` without owner check; no cross-position validation.

**Code pattern**:
```rust
// VULNERABLE: Funding rate from perp market — manipulable within tx
let funding_rate = ctx.accounts.perp_market.funding_rate;
require!(
    perp_market.last_update_slot < Clock::get()?.slot - MIN_FUNDING_INTERVAL,
    ErrorCode::StaleOracle
);
```

**Detection**: Rule 13, Rule 17, Rule 39.

---

#### Harmony Bridge ($100M, Jun 2022) — Validator Set EoP
Harmony's bridge used a trusted validator set that could sign for any transaction. An attacker exploited the multi-sig implementation to bypass the validator threshold.

**Detection**: Rule 4 (CPI privilege escalation), Rule 8 (signer verification).

---

#### Solend ($1.3M, Oct 2022) — Oracle EoP via Liquidation Bot
Solend's liquidation bot read stale oracle prices. An attacker manipulated the oracle within a single transaction and executed a liquidation at an inflated price.

**Root cause**: Rule 13 — oracle staleness not checked; liquidation threshold can be bypassed within the same transaction.

---

## STRIDE-to-Rule Mapping

Complete correlation between STRIDE categories and the 50 audit rules:

| STRIDE | Rules | Severity Floor |
|--------|-------|---------------|
| **S — Spoofing** | 1, 3, 8, 36 | CRITICAL |
| **T — Tampering** | 2, 7, 15, 22, 24, 37, 38 | CRITICAL |
| **R — Repudiation** | 10, 23 | MEDIUM |
| **I — Information Disclosure** | 17, 36, 39 | HIGH |
| **D — Denial of Service** | 7, 10, 12, 18, 22 | MEDIUM |
| **E — Elevation of Privilege** | 4, 8, 13, 16, 27, 31, 33, 35 | CRITICAL |

### Rule Coverage Heatmap

```
Threat     | CRITICAL | HIGH | MEDIUM | LOW | Total
---------- | -------- | ---- | ------ | --- | -----
Spoofing   |    3     |  1   |   1    |  0  |   5
Tampering  |    4     |  3   |   0    |  0  |   7
Repudiation|    0     |  0   |   2    |  0  |   2
Disclosure |    0     |  3   |   0    |  0  |   3
DoS        |    0     |  0   |   4    |  1  |   5
EoP        |    7     |  2   |   0    |  0  |   9
```

---

## False Positive Master List

Reduce noise by understanding these common false positives:

| Rule | False Positive | Clarification |
|------|---------------|---------------|
| Rule 3 | `find_program_address` with literal bump | If result is discarded and `ctx.bumps` is used separately, no issue |
| Rule 4 | `invoke` to System Program | System Program only allows specific operations; not arbitrary code execution |
| Rule 8 | `Signer<T>` in `#[derive(Accounts)]` | Anchor enforces signer verification automatically |
| Rule 13 | Price from Pyth with slot check | If staleness is checked and slot threshold is enforced, this is safe |
| Rule 15 | `remaining_accounts` with explicit validation loop | Validation loop with count + owner + signer checks eliminates risk |
| Rule 16 | Same struct name used twice | Each `#[account]` struct generates unique discriminator |
| Rule 17 | `Account<T>` (not `AccountLoader`) | `Account<T>` enforces owner check automatically |
| Rule 18 | `try_from_slice` on trusted program-owned data | If owner is verified first, this is safe |
| Rule 22 | `init` and `close` in same atomic transaction | If both are in same tx, the race window is closed |
| Rule 27 | `mint` verified via `has_one` or `constraint` | Anchor constraint verification is sufficient |
| Rule 36 | `Clock::get()` from Anchor | Anchor fetches from verified sysvar address |

---

## Helius API Threat Intelligence Integration

Use Helius enhanced APIs for real-time threat detection on deployed programs:

### Transaction Monitoring
```bash
# Get recent transactions for a program — detect anomalous patterns
curl -s -X POST https://mainnet.helius-rpc.com/?api-key=${HELIUS_KEY} \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getSignaturesForAddress",
    "params": ["PROGRAM_ID", {"limit": 100, "commitment": "processed"}]
  }' | jq '.result[] | {signature, slot, err, blockTime}'
```

### Historical Exploit Detection
```bash
# Check if program has interacted with known exploit contract addresses
EXPLOIT_ADDRESSES=(
  "ExploitContract1..."
  "ExploitContract2..."
)

for addr in "${EXPLOIT_ADDRESSES[@]}"; do
  curl -s -X POST https://mainnet.helius-rpc.com/?api-key=${HELIUS_KEY} \
    -H "Content-Type: application/json" \
    -d "{
      \"jsonrpc\": \"2.0\",
      \"id\": 1,
      \"method\": \"getProgramAccounts\",
      \"params\": [\"PROGRAM_ID\", {
        \"filters\": [{\"memcmp\": {
          \"bytes\": \"$addr\",
          \"offset\": 0
        }}]
      }]
    }" | jq '.result | length'
done
```

---

## Evasion Techniques Auditors Should Know

1. **Bump cycling**: Attacker iterates bumps 255->0 to find collision with hardcoded bump. Always use canonical (first valid from 255).
2. **Sysvar substitution via CPI**: In a CPI chain, intermediate programs can pass fake sysvar accounts. Trace full CPI call graph.
3. **LUT poisoning**: Versioned transactions with address lookup tables can substitute account addresses. Always validate account data, not just pubkey.
4. **Duplicate account aliasing**: Same account passed twice under different keys bypasses balance checks. Deduplicate with `BTreeSet`.
5. **Account substitution via LUT**: Validate data contents, not just pubkey, for versioned transactions.
6. **State compression oracle manipulation**: BPF account compression programs trust on-chain state without verification.
7. **ZKA (Zero-Knowledge Account) state corruption**: Programs trusting ZKA-verified state without independent validation are vulnerable to circuit bugs.

---

## Next Phase

After threat model → load `skill/02-static-analysis.md` (Phase 2) with threat IDs as input context. The threat list primes the static analyzer to look for specific patterns first.

---

## STRIDE Overview for Solana

| Threat | Property Violated | Solana Root Cause | Detection Rules |
|--------|-------------------|-------------------|----------------|
| **S**poofing | Authentication | Missing signer verification, PDA bump collision | Rules 1, 8, 36 |
| **T**ampering | Integrity | Account data mutation without ownership check | Rules 2, 7, 37, 38 |
| **R**epudiation | Non-repudiation | Missing event emission, unsigned actions | Rules 10, 23 |
| **I**nformation Disclosure | Confidentiality | Deserialized accounts without owner check, sysvar spoof | Rules 17, 39, 36 |
| **D**enial of Service | Availability | Panic in instruction, rent exemption bypass, close drain | Rules 7, 10, 18, 22 |
| **E**levation of Privilege | Authorization | Unsigned invoke, CPI privilege escalation, discriminator collision | Rules 4, 8, 16, 27 |

---

## S — Spoofing

### Definition
An attacker authenticates as a legitimate user or program without authorization. On Solana, spoofing manifests as PDA derivation bypass, missing signer checks, or sysvar account substitution.

### Real-World Exploits

#### Wormhole (Feb 2022, $320M) — Guardian Signature Spoofing
The attacker spoofed Guardian signatures on the Wormhole bridge by exploiting a `verify_signature` CPI call that did not validate the guardian set version. The attacker passed a fake guardian set with their own signatures.

**Root cause**: CPI to the signature verification program accepted accounts from `remaining_accounts` without verifying the guardian set discriminator.

**Exploit flow**:
1. Attacker creates a fake guardian set account with their controlled signatures
2. Passes fake guardian set via `remaining_accounts` to CPI
3. `verify_signature` invoked without checking guardian set owner
4. Signed message accepted as valid
5. 120k WETH minted on Solana unbacked on Ethereum

**Code pattern**:
```rust
// VULNERABLE: CPI without remaining_accounts validation
pub fn submit_vaa(ctx: Context<SubmitVaa>, vaa: Vec<u8>) -> Result<()> {
    let accounts = ctx.remaining_accounts; // ← Attacker controls this slice
    invoke(
        &verification_instruction,
        &accounts, // ← No validation of guardian set account
    )?;
    // ...
}
```

**Detection**: Rule 15 (remaining_accounts validation), Rule 4 (CPI program ID check), Rule 17 (AccountLoader without owner).

---

#### Cashio ($52M, Mar 2022) — Mint Authority PDA Spoofing
Cashio's `mint_authority` PDA was derived using a hardcoded bump (`255`) instead of the canonical bump. An attacker found a different valid bump that produced the same PDA, bypassing the mint authority check.

**Root cause**: Rule 3 violation — hardcoded bump used as a security parameter.

**Exploit flow**:
1. Attacker derives the "bridge" PDA using a non-canonical bump
2. Calls `mint` with the attacker-derived PDA as authority
3. Program checks `Pubkey::find_program_address` but uses the hardcoded bump directly
4. PDA matches expected mint authority — bypassed
5. 52M CGG tokens minted unbacked

**Code pattern**:
```rust
// VULNERABLE: Uses result from find_program_address but hardcodes bump
let (expected_pda, _) = Pubkey::find_program_address(&[b"bridge"], program_id);
let attacker_pda = Pubkey::create_program_address(&[b"bridge", &[255]], program_id).unwrap();
// attacker_pda == expected_pda when bump 255 produces off-curve

// CHECK: Always use ctx.bumps from Anchor, not hardcoded literals
// FIXED:
let vault_auth = Pubkey::find_program_address(
    &[b"bridge", ctx.accounts.user.key().as_ref()],
    &ID,
).0;
require_keys_eq!(ctx.accounts.authority.key(), vault_auth, ErrorCode::NotAuthority);
```

**Detection**: Rule 3 (PDA canonical bump), grep for `[255]` as bump literal.

---

#### Nirvana Finance ($3M, Jul 2022) — Price Feed Spoofing
Nirvana used a Price Authority contract that could be manipulated via flash loan. The price feed was spoofed within the same transaction, causing the protocol to believe the collateral was worth 10x its actual value.

**Root cause**: Price source not commit-reveal, no TWAP staleness check.

**Detection**: Rule 13 (flash loan oracle manipulation), Rule 26 (cross-program flash loan).

---

### Spoofing Code Patterns

#### 1. Missing Signer Check Before Token Transfer
```rust
// VULNERABLE: invoke without verifying caller signed
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // No: ctx.accounts.authority.is_signer check
    invoke(
        &spl_token::instruction::transfer(
            token_program.key,
            source.key,
            dest.key,
            ctx.accounts.authority.key, // ← Attacker calls this directly
            &[],
            amount,
        )?,
        &accounts,
    )?;
    Ok(())
}
```
**Fix**: Add `require!(ctx.accounts.authority.is_signer, ErrorCode::NotSigner)` before any privileged action.

#### 2. Sysvar Clock Spoofing
```rust
// VULNERABLE: Clock not verified against sysvar ID
pub fn claim(ctx: Context<Claim>) -> Result<()> {
    let clock = Clock::from_account_info(&ctx.accounts.clock)?; // No key check
    let elapsed = clock.slot - ctx.accounts.user.last_claim_slot;
    require!(elapsed >= EPOCH_LENGTH, ErrorCode::TooEarly);
}
```
**Fix**: Use `Clock::get()` from Anchor sysvar, or verify `clock_info.key() == anchor_lang::solana_program::sysvar::clock::ID`.

#### 3. PDA Derivation Without Canonical Bump
```rust
// VULNERABLE: Hardcoded bump
let vault_pda = Pubkey::create_program_address(
    &[b"vault", user.key().as_ref(), &[255]], // ← 255 hardcoded
    program_id,
)?;
```
**Fix**: Always use `ctx.bumps["vault"]` from Anchor, or recompute with `find_program_address` and validate the returned bump.

---

### False Positives for Spoofing

| Pattern | Why It Looks Like Spoofing | Why It's Not |
|---------|---------------------------|--------------|
| `invoke_signed` with implicit signer | Looks like unsigned CPI | Anchor's `invoke_signed` signs only for PDA accounts derived from verified seeds |
| System program CPI | Looks like arbitrary transfer | System program requires signed invocation; only allows specific operations |
| `Clock::get()` with explicit Anchor sysvar | Looks like sysvar spoof | Anchor's `Clock::get()` fetches from verified sysvar address |
| `has_one = authority` constraint | Looks redundant | This IS the correct pattern — not a finding |

### Evasion Techniques Auditors Should Know

1. **Bump cycling**: Attacker iterates bumps 255→0 to find collision with hardcoded bump. Always use canonical (first valid from 255).
2. **Sysvar substitution via CPI**: In a CPI chain, intermediate programs can pass fake sysvar accounts. Trace full CPI call graph.
3. **LUT poisoning**: Versioned transactions with address lookup tables can substitute account addresses. Always validate account data, not just pubkey.
4. **Duplicate account aliasing**: Same account passed twice under different keys bypasses balance checks. Deduplicate with `BTreeSet`.

---

## T — Tampering

### Definition
An attacker modifies program state without proper authorization. On Solana, tampering occurs through account data mutation without ownership verification, `remaining_accounts` injection, or discriminator bypass.

### Real-World Exploits

#### Crema Finance ($8.8M, Jul 2022) — Account Tampering via Close + Flash Loan
Crema allowed accounts to be closed and reinitialized within the same transaction via flash loan. The attacker tampered with the liquidity position account's data by closing it mid-transaction and reinitializing with manipulated state.

**Root cause**: Rule 7 — `close` target not properly guarded; Rule 22 — `init_if_needed` + `close` race.

**Exploit flow**:
1. Flash loan tokens
2. Call `close_position` on victim's account (drains lamports to attacker)
3. Call `init_position` to reinitialize with attacker-controlled parameters
4. Repay flash loan
5. Profit from tampered position

**Code pattern**:
```rust
// VULNERABLE: close target is user-supplied or attacker-accessible
#[derive(Accounts)]
pub struct ClosePosition<'info> {
    #[account(mut, close = victim)] // ← close target is not the program/PDA
    pub position: Account<'info, Position>,
    pub victim: Signer<'info>, // ← victim signs, but funds go to attacker
}
```
Attacker front-runs victim's transaction with their own close instruction.

**Detection**: Rule 7 (close authority), Rule 22 (init_if_needed race).

---

#### Raydium ($1.6M, Jan 2023) — `remaining_accounts` Tampering
Raydium's `add_liquidity` instruction accepted `remaining_accounts` that were not validated. An attacker injected a fake pool state account via `remaining_accounts`, causing the program to use attacker-controlled pool data for liquidity calculations.

**Root cause**: Rule 15 — `remaining_accounts` not validated; Rule 24 — count mismatch in CPI.

**Exploit flow**:
1. Attacker creates a fake AMM pool account with manipulated reserve amounts
2. Calls `add_liquidity` with the fake pool in `remaining_accounts`
3. Program reads fake pool reserves without validation
4. Attacker receives disproportionate liquidity tokens
5. Redeems tokens for excess underlying assets

**Code pattern**:
```rust
// VULNERABLE: remaining_accounts used without validation
pub fn add_liquidity(ctx: Context<AddLiquidity>, ...) -> Result<()> {
    let pool_accounts = ctx.remaining_accounts;
    // No validation: count, signer flags, owner check, pubkey match
    let pool = &pool_accounts[0];
    let reserves = read_reserves(pool)?; // ← Attacker controls this
}
```
**Fix**:
```rust
// FIXED: Validate every remaining_account
let pool_accounts = ctx.remaining_accounts;
require!(pool_accounts.len() >= 3, ErrorCode::InvalidAccounts);
require!(pool_accounts[0].is_writable, ErrorCode::NotWritable);
require!(
    pool_accounts[0].owner == &amm_pool::ID,
    ErrorCode::InvalidPoolOwner
);
```

**Detection**: Rule 15, Rule 24. Grep for `remaining_accounts` without corresponding validation loops.

---

#### Mango Markets ($117M, Oct 2022) — Oracle Tampering + Account Manipulation
The attacker manipulated Mango's oracle (perp funding rate) and tampered with the on-chain account state by using a different account that passed ownership validation but contained manipulated position data.

**Root cause**: Rule 17 — `AccountLoader` without owner validation; Rule 13 — oracle manipulation within same transaction.

**Detection**: Rule 13, Rule 17, Rule 39.

---

### Tampering Code Patterns

#### 1. AccountLoader Without Owner Check
```rust
// VULNERABLE: Deserializes without verifying owner
pub fn update_state(ctx: Context<UpdateState>, data: Vec<u8>) -> Result<()> {
    let state = AccountLoader::<State>::try_from(&ctx.accounts.state)?;
    // No: state.owner == program_id check
    let mut s = state.load_mut()?;
    s.value = decode(&data)?;
}
```
**Fix**: Use `Account<State>` (Anchor enforces owner check), or manually verify `account_info.owner == &program_id`.

#### 2. Mutable Account Without `mut` Constraint
```rust
// VULNERABLE: Account modified but not marked mut
#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub user: Account<'info, User>, // ← Missing mut
}
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    ctx.accounts.user.balance -= amount; // ← Won't persist
}
```
Anchor will reject at runtime, but the vulnerability is the misconfiguration.

#### 3. Duplicate Mutable Account (Same Key, Different Alias)
```rust
// VULNERABLE: Two accounts that are actually the same pubkey
pub fn split_funds(ctx: Context<SplitFunds>, amount: u64) -> Result<()> {
    let a = ctx.accounts.token_a.amount; // Snapshot reads
    let b = ctx.accounts.token_b.amount; // Same account? No check
    // If token_a == token_b, arithmetic corrupts state
    ctx.accounts.token_a.reload()?;
    ctx.accounts.token_b.reload()?;
}
```
**Fix**: Deduplicate with `BTreeSet` or add `#[account(constraint = a != b)]`.

---

### False Positives for Tampering

| Pattern | Why It Looks Like Tampering | Why It's Not |
|---------|---------------------------|--------------|
| `Account::load_mut()` followed by write | Looks like manual mutation | Anchor's `Account` type validates ownership before deserialization |
| `#[account(mut)]` on multiple accounts | Looks like shared mutable state | Intentional pattern for multi-account operations; validate with `constraint` |
| `try_borrow_mut_data()` | Looks like bypassing Anchor | Required for Token-2022 extension data parsing |

### Evasion Techniques

1. **Account substitution via LUT**: In versioned transactions, accounts are passed by address only. Validate data contents, not just pubkey.
2. **State compression oracle manipulation**: BPF account compression programs trust on-chain state without verification. Check compression proof validity.
3. **ZKA (Zero-Knowledge Account) state corruption**: Programs trusting ZKA-verified state without independent validation are vulnerable to circuit bugs.

---

## R — Repudiation

### Definition
A user or program denies having performed an action. On Solana, this manifests as unsigned critical operations, missing event emission, or ambiguous transaction attribution.

### Real-World Context

Solana's transaction logs are public and immutable, but programs must still emit structured events for off-chain indexing. A program that skips event emission forces off-chain systems to reconstruct state from on-chain data — error-prone and manipulable.

**Social engineering via memo injection** (Rule 23):
```rust
// VULNERABLE: User-supplied memo in CPI to Memo program
invoke(
    &spl_memo::instruction::build(ctx.accounts.user_provided_memo.as_bytes()),
    &[],
)?;
// Logs: "Deposit confirmed" — attacker changes memo to "Withdraw confirmed"
// Off-chain systems reading logs are deceived
```
**Fix**: Always use program-controlled constant memos, or hash user data into a program-generated memo.

### Repudiation Code Patterns

#### 1. Missing Event Emission After State Changes
```rust
// VULNERABLE: State changes not emitted
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let user = &mut ctx.accounts.user;
    user.balance = user.balance.checked_sub(amount).unwrap();
    // No event emitted — off-chain cannot verify withdrawal
    Ok(())
}
```
**Fix**: Use `emit!` macro after every state mutation.
```rust
emit!(WithdrawEvent {
    user: ctx.accounts.user.key(),
    amount,
    new_balance: user.balance,
});
```

#### 2. Ambiguous Error Messages
```rust
// VULNERABLE: Generic error hides which check failed
pub fn execute(ctx: Context<Execute>) -> Result<()> {
    require!(ctx.accounts.user.is_signer, ErrorCode::Unauthorized)?;
    require!(ctx.accounts.vault.amount >= amount, ErrorCode::InsufficientFunds)?;
    // ...
}
// Error: "Unauthorized" — could mean signer check OR has_one check failed
// Makes off-chain monitoring ambiguous
```
**Fix**: Use distinct error codes for each failure mode.

#### 3. Missing Nonce/Sequence Tracking
```rust
// VULNERABLE: No instruction ordering guarantee
pub fn execute(ctx: Context<Execute>, instruction: u8, data: Vec<u8>) -> Result<()> {
    // No sequence number — instructions can be reordered or replayed
    // without detection
}
```
**Fix**: Track a monotonically increasing nonce in user state; verify nonce on each instruction.

---

## I — Information Disclosure

### Definition
An attacker reads data they should not have access to. On Solana, all account data is on-chain — "confidential" data is only protected by program logic, not encryption.

### Real-World Context

Solana's account model means every account's data is publicly readable. Information disclosure occurs when programs deserialize accounts they should not access, or when sensitive data (keys, seeds) is logged.

#### Mango Markets — State Reading for Attack Planning
The attacker read Mango's on-chain state (open positions, oracle prices) to craft an optimal attack transaction. While technically legal on-chain behavior, it highlights that programs should not assume information asymmetry.

#### Token-2022 Confidential Transfers
Confidential transfer extension encrypts amounts, but the protocol must still verify fee extraction on settle. Information disclosure here means leaking transfer amounts via timing side-channels or fee calculation bugs.

### Information Disclosure Code Patterns

#### 1. Deserializing Accounts Without Ownership Check (Rule 39)
```rust
// VULNERABLE: Reads arbitrary account data
pub fn get_balance(ctx: Context<GetBalance>, target: Pubkey) -> Result<u64> {
    let account_info = ctx.accounts.target;
    // No owner check — reads ANY account on-chain
    let data = account_info.try_borrow_data()?;
    let balance = u64::from_le_bytes(data[8..16].try_into().unwrap());
    Ok(balance)
}
```
**Fix**: Verify `account_info.owner == &expected_program` before deserialization.

#### 2. Sysvar Information Leakage
```rust
// VULNERABLE: Logs reveal sensitive state
msg!("User {} balance {}", user.key(), user.balance);
// On-chain logs are public — anyone watching can extract user balances
```
**Fix**: Use `emit!` for structured events; avoid logging sensitive fields directly.

#### 3. Token Account Balance Enumeration
```rust
// VULNERABLE: Enumerates all token accounts without access control
pub fn get_all_balances(ctx: Context<GetAllBalances>) -> Result<Vec<(Pubkey, u64)>> {
    // Iterates ALL token accounts owned by the program
    // Any caller can enumerate all deposits
}
```
**Fix**: Add caller verification — only return balances for the calling user or authorized party.

#### 4. Confidential Transfer Amount Leakage via Timing
```rust
// VULNERABLE: Fee calculation timing reveals transfer amount
let decrypt_start = Clock::get()?.slot;
// ... decrypt and compute fee ...
let decrypt_time = Clock::get()?.slot - decrypt_start;
// Timing of decryption correlates with magnitude of amounts
```
**Fix**: Use constant-time decryption and fixed-iteration fee calculations.

---

### False Positives for Information Disclosure

| Pattern | Why It Looks Like Disclosure | Why It's Not |
|---------|----------------------------|--------------|
| `try_borrow_data()` on program-owned account | Looks like reading user data | Correct — program owns the data, caller is the program |
| `msg!` with user pubkey | Looks like info leak | Pubkeys are public — logging them is standard debugging |
| `getTokenAccountsByOwner` RPC call | Looks like account enumeration | Standard RPC — designed for this use case |

---

## D — Denial of Service

### Definition
An attacker prevents legitimate users from using the program. On Solana, DoS manifests as transaction failures, account rent-exemption loss, or instruction panic propagation.

### Real-World Exploits

#### DoS via Rent-Exemption Exhaustion
An attacker could create thousands of accounts that a victim's program depends on, then close them when rent exemption lapses, causing the victim's instructions to fail when they try to access non-existent accounts.

**Detection**: Rule 12 (rent exemption), Rule 7 (account closing).

#### Instruction Panics (Rule 10, Rule 18)
```rust
// VULNERABLE: panic aborts transaction, may leave state inconsistent
fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> EntrypointResult {
    let data = instruction_data.unwrap(); // ← panic on malformed data
    // ...
}
```
**Fix**: Use `Result` types with `?` propagation. Never `unwrap()` on untrusted data.

#### init_if_needed Race (Rule 22)
```rust
// VULNERABLE: Front-run close with init_if_needed
// Attacker monitors mempool for close instruction
// Submits init_if_needed in same block before close executes
// Result: Close fails, victim pays rent twice, account stuck
```

### DoS Code Patterns

#### 1. Unbounded Account Iteration
```rust
// VULNERABLE: Could exceed compute budget
pub fn process_all_positions(ctx: Context<ProcessAll>) -> Result<()> {
    for position in ctx.accounts.positions.iter() {
        // No bounds check — unbounded iteration
        process_position(position)?;
    }
}
```
**Fix**: Add a maximum iteration count, or paginate with an offset parameter.

#### 2. Missing Compute Budget Reservation
```rust
// VULNERABLE: No compute budget management
// Complex operations can exceed 200k CU limit
// Transaction fails, user loses fees
```
**Fix**: Use `sol_set_compute_unit_limit(200_000)` and `sol_set_compute_unit_price(micro_lamports)` via `solana_program`.

#### 3. Account Resurrection After Close
```rust
// VULNERABLE: Account closed but data not zeroed
// Rent sysvar can resurrect account with stale data
// Next init reads stale discriminator → wrong account type accepted
```
**Fix**: Zero account data before closing. Use `anchor_lang::context::CpiAccount::close()` which zeros data.

---

## E — Elevation of Privilege

### Definition
An attacker executes actions beyond their authorization level. On Solana, this is the most common and highest-impact vulnerability class — nearly all major exploits involve EoP.

### Real-World Exploits

#### Wormhole ($320M, Feb 2022) — CPI Privilege Escalation
Described in Spoofing section. The attacker escalated from regular user to bridge validator by spoofing guardian signatures via CPI.

**Root cause**: Rule 4 — CPI without verifying the guardian set account owner and discriminator.

---

#### Raydium ($1.6M, Jan 2023) — `remaining_accounts` Injection EoP
Described in Tampering section. Attacker injected a fake pool account via `remaining_accounts` to bypass pool validation.

**Root cause**: Rule 15, Rule 24 — `remaining_accounts` not validated before being passed to inner CPI instruction.

---

#### Nomad Bridge ($190M, Aug 2022) — Replica Program EoP
Nomad's bridge used a "replica" pattern where a separate program could process messages on behalf of the main bridge. The replica's `process` instruction accepted any message without verifying it was actually confirmed on the main chain.

**Root cause**: Missing origin verification on the replica program; upgrade authority allowed deploying a malicious replica.

**Exploit flow**:
1. Attacker deploys a fake replica program with upgrade authority
2. Or: exploits the legitimate replica's missing message verification
3. Processes a fake "confirmed" message
4. Withdraws tokens without corresponding deposit on origin chain

**Detection**: Rule 9 (upgrade authority), Rule 4 (CPI privilege escalation).

---

#### Mango Markets ($117M, Oct 2022) — Perp Oracle EoP + Liquidity Theft
Two-phase exploit:
1. **Phase 1 — Oracle EoP**: Attacker manipulates Mango's perpetual funding rate to make their large position appear extremely valuable
2. **Phase 2 — Account EoP**: Uses the inflated collateral to drain all liquidity from Mango's deposits

**Root cause**: Rule 13 — oracle manipulation within same transaction; Rule 17 — `AccountLoader` without owner check; no cross-position validation.

**Code pattern**:
```rust
// VULNERABLE: Funding rate from perp market — manipulable within tx
let funding_rate = ctx.accounts.perp_market.funding_rate;
// Check: Is there a TWAP with sufficient lookback?
// Check: Is the funding rate from a slot prior to this transaction?
require!(
    perp_market.last_update_slot < Clock::get()?.slot - MIN_FUNDING_INTERVAL,
    ErrorCode::StaleOracle
);
```

**Detection**: Rule 13, Rule 17, Rule 39.

---

#### Harmony Bridge ($100M, Jun 2022) — Validator Set EoP
Harmony's bridge used a trusted validator set that could sign for any transaction. An attacker exploited the multi-sig implementation to bypass the validator threshold, approving transactions that should have required more signatures.

**Detection**: Rule 4 (CPI privilege escalation), Rule 8 (signer verification).

---

#### Slope Finance ($8M, Aug 2022) — Private Key Exfiltration
Slope Finance's mobile wallet exfiltrated user private keys to a third-party server. Attackers used the stolen keys to drain user wallets.

**Root cause**: Off-chain key management failure — not a Solana program vulnerability, but demonstrates that EoP can originate from key theft rather than on-chain logic bugs.

---

#### Solend ($1.3M, Oct 2022) — Oracle EoP via Liquidation Bot
Solend's liquidation bot read stale oracle prices. An attacker manipulated the oracle within a single transaction and executed a liquidation at an inflated price, extracting more collateral than warranted.

**Root cause**: Rule 13 — oracle staleness not checked; liquidation threshold can be bypassed within the same transaction.

---

### EoP Code Patterns

#### 1. Unsigned `invoke` for Privileged Operation (CRITICAL)
```rust
// CRITICAL: invoke without verifying caller signed
pub fn mint_tokens(ctx: Context<MintTokens>, amount: u64) -> Result<()> {
    invoke(
        &spl_token::instruction::mint_to(
            token_program.key,
            mint.key,
            dest.key,
            ctx.accounts.mint_authority.key, // ← No is_signer check
            &[],
            amount,
        )?,
        &accounts,
    )?;
    Ok(())
}
```
**Fix**: Add `require!(ctx.accounts.mint_authority.is_signer, ErrorCode::NotSigner)` before any privileged action.

#### 2. Discriminator Collision (CRITICAL — Rule 16)
```rust
// VULNERABLE: Two account types with same 8-byte discriminator
#[derive(AnchorDeserialize, AnchorSerialize)]
pub struct Vault { /* ... */ }     // discriminator: "Vault\0\0\0\0\0"

#[derive(AnchorDeserialize, AnchorSerialize)]
pub struct VaultAdmin { /* ... */ } // discriminator: "Vault\0\0\0\0\0" — COLLISION
```
**Exploit**: An instruction expecting `VaultAdmin` will accept `Vault` if the attacker passes the `Vault` account. The `VaultAdmin` fields are read from `Vault` data, bypassing any authorization checks in the `VaultAdmin` struct.

**Fix**: Always use unique account struct names. Check discriminators with Anchor's `DISCRIMINATOR` constant.

#### 3. Missing `has_one` on Critical Authority Field
```rust
// VULNERABLE: Admin field exists but not checked against signer
#[derive(Accounts)]
pub struct AdminUpdate<'info> {
    pub config: Account<'info, Config>, // admin field exists in Config
    pub signer: Signer<'info>,          // ← No has_one constraint
}
pub fn admin_update(ctx: Context<AdminUpdate>, new_value: u64) -> Result<()> {
    ctx.accounts.config.value = new_value; // ← Any signer can update
    // Should be: require!(ctx.accounts.signer.key() == ctx.accounts.config.admin)
}
```

#### 4. Transfer Hook Mint Not Verified (CRITICAL — Rule 27)
```rust
// CRITICAL: Mint from CPI account not verified against expected mint
pub fn transfer_hook(ctx: Context<TransferHook>, amount: u64) -> Result<()> {
    let mint = ctx.accounts.mint.key(); // From remaining_accounts — attacker controls
    let hook_accounts = ctx.remaining_accounts;
    // Uses mint for authorization without checking mint == expected_mint
}
```

#### 5. Hook Program ID Not Allowlisted (CRITICAL — Rule 31)
```rust
// CRITICAL: Arbitrary program invoked via CPI
pub fn transfer_hook(ctx: Context<TransferHook>, amount: u64) -> Result<()> {
    let program_id = ctx.accounts.hook_program.key(); // From remaining_accounts
    invoke(
        &attack_instruction,
        &ctx.remaining_accounts,
    )?; // ← Arbitrary program execution with full context
}
```

---

## STRIDE-to-Rule Mapping

Complete correlation between STRIDE categories and the 50 audit rules:

| STRIDE | Rules | Severity Floor |
|--------|-------|---------------|
| **S — Spoofing** | 1, 3, 8, 36 | CRITICAL |
| **T — Tampering** | 2, 7, 15, 22, 24, 37, 38 | CRITICAL |
| **R — Repudiation** | 10, 23 | MEDIUM |
| **I — Information Disclosure** | 17, 36, 39 | HIGH |
| **D — Denial of Service** | 7, 10, 12, 18, 22 | MEDIUM |
| **E — Elevation of Privilege** | 4, 8, 13, 16, 27, 31, 33, 35 | CRITICAL |

### Rule Coverage Heatmap

```
Threat     | CRITICAL | HIGH | MEDIUM | LOW | Total
---------- | -------- | ---- | ------ | --- | -----
Spoofing   |    3     |  1   |   1    |  0  |   5
Tampering  |    4     |  3   |   0    |  0  |   7
Repudiation|    0     |  0   |   2    |  0  |   2
Disclosure |    0     |  3   |   0    |  0  |   3
DoS        |    0     |  0   |   4    |  1  |   5
EoP        |    7     |  2   |   0    |  0  |   9
```

---

## Helius API Threat Intelligence Integration

Use Helius enhanced APIs for real-time threat detection on deployed programs:

### Transaction Monitoring
```bash
# Get recent transactions for a program — detect anomalous patterns
curl -s -X POST https://mainnet.helius-rpc.com/?api-key=${HELIUS_KEY} \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getSignaturesForAddress",
    "params": ["PROGRAM_ID", {"limit": 100, "commitment": "processed"}]
  }' | jq '.result[] | {signature, slot, err, blockTime}'
```

### Abuse Detection Patterns
```bash
# Detect rapid succession transactions (MEV / sandwich indicator)
# Look for: same user executing >10 tx within 5 slots

# Detect large transfers following price oracle updates
# Cross-reference program logs with Pyth price update slots

# Detect account drainage patterns
# Alert on: vault balance dropping >20% within 10 slots
```

### Historical Exploit Detection
```bash
# Check if program has interacted with known exploit contract addresses
EXPLOIT_ADDRESSES=(
  "ExploitContract1..."
  "ExploitContract2..."
)

for addr in "${EXPLOIT_ADDRESSES[@]}"; do
  curl -s -X POST https://mainnet.helius-rpc.com/?api-key=${HELIUS_KEY} \
    -H "Content-Type: application/json" \
    -d "{
      \"jsonrpc\": \"2.0\",
      \"id\": 1,
      \"method\": \"getProgramAccounts\",
      \"params\": [\"PROGRAM_ID\", {
        \"filters\": [{\"memcmp\": {
          \"bytes\": \"$addr\",
          \"offset\": 0
        }}]
      }]
    }" | jq '.result | length'
done
```

---

## False Positive Master List

Reduce noise by understanding these common false positives:

| Rule | False Positive | Clarification |
|------|---------------|---------------|
| Rule 3 | `find_program_address` with literal bump | If result is discarded and `ctx.bumps` is used separately, no issue |
| Rule 4 | `invoke` to System Program | System Program only allows specific operations; not arbitrary code execution |
| Rule 8 | `Signer<T>` in `#[derive(Accounts)]` | Anchor enforces signer verification automatically |
| Rule 13 | Price from Pyth with slot check | If staleness is checked and slot threshold is enforced, this is safe |
| Rule 15 | `remaining_accounts` with explicit validation loop | Validation loop with count + owner + signer checks eliminates risk |
| Rule 16 | Same struct name used twice | Each `#[account]` struct generates unique discriminator |
| Rule 17 | `Account<T>` (not `AccountLoader`) | `Account<T>` enforces owner check automatically |
| Rule 18 | `try_from_slice` on trusted program-owned data | If owner is verified first, this is safe |
| Rule 22 | `init` and `close` in same atomic transaction | If both are in same tx, the race window is closed |
| Rule 27 | `mint` verified via `has_one` or `constraint` | Anchor constraint verification is sufficient |
| Rule 36 | `Clock::get()` from Anchor | Anchor fetches from verified sysvar address |

---

## Next Phase

After threat modeling → load `skill/02-static-analysis.md` for code-level checks against these threat categories.
