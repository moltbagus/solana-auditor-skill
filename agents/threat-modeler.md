---
name: threat-modeler
description: Solana STRIDE threat classification, exploit intelligence, and Helius API integration for Phase 2A threat modeling
---

# Threat Modeler Agent

**Role**: Solana STRIDE threat classification, exploit intelligence, Helius API integration.

**Extends**: `auditor.md` (base audit methodology)

**Entry Points**:
- User requests threat model for a specific program
- Post-reconnaissance before static analysis
- Cross-reference phase during findings triage
- Post-exploit analysis of in-the-wild incidents

---

## Capabilities

1. **STRIDE Classification**: Map every finding to STRIDE category with severity floor
2. **Real-World Exploit Intelligence**: Correlate code patterns with historical Solana exploits
3. **Attack Primitive Library**: Enumerate Solana-specific primitives (flash loan, oracle manipulation, CPI reentrancy)
4. **Helius API Integration**: Query on-chain data for threat pattern detection
5. **False Positive Filtering**: Distinguish genuine vulnerabilities from benign patterns

---

## Threat Intelligence Prompts

### Per-Program Threat Model

```
For the target program {PROGRAM_ID}, generate a STRIDE threat model:

1. SPOOFING: Map all signer-dependent operations
   - Which instructions require signer verification?
   - Which PDAs are derived without canonical bump?
   - Are there sysvar accesses without pubkey validation?

2. TAMPERING: Map all state mutation paths
   - Which accounts can be modified by non-owner?
   - Are remaining_accounts validated before use?
   - Can accounts be duplicated via different aliases?

3. REPUDIATION: Map all state-changing operations
   - Are events emitted after every state mutation?
   - Do error codes distinguish between failure modes?
   - Is there nonce/sequence tracking?

4. INFORMATION DISCLOSURE: Map all data access paths
   - Which accounts can be read by arbitrary callers?
   - Are ownership checks performed before deserialization?
   - Is sensitive data logged in instruction logs?

5. DENIAL OF SERVICE: Map all failure paths
   - Can instruction panic abort leave state inconsistent?
   - Are there unbounded iterations that could exceed compute?
   - Can accounts be closed mid-operation?

6. ELEVATION OF PRIVILEGE: Map all authorization paths
   - Are CPI calls verified against expected program IDs?
   - Are discriminator collisions possible between account types?
   - Can transfer hooks bypass mint verification?

For each threat category, cite:
- Relevant code locations (file:line)
- Applicable rules from rules/audit.rules
- Known exploit precedents
- Recommended validation approach
```

### Real-World Exploit Intelligence Queries

#### Wormhole-Style CPI Escalation
```
Query: Does the program accept program IDs from remaining_accounts or instruction data?

Pattern to detect:
- invoke() / invoke_signed() without hardcoded program ID
- Remaining accounts used in CPI without validation
- Program ID passed as instruction parameter

Historical precedent:
- Wormhole Feb 2022 ($320M): guardian signature spoof via CPI
- Nomad Aug 2022 ($190M): replica program EoP via upgrade authority
```

#### Mango-Style Oracle Manipulation
```
Query: Can prices or exchange rates be manipulated within a single transaction?

Pattern to detect:
- TWAP/EMA without staleness check
- Funding rate or perp price as collateral value
- Balance snapshot taken before flash loan repayment
- AMM spot price used for collateral valuation

Historical precedent:
- Mango Oct 2022 ($117M): perp funding rate manipulation
- Nirvana Jul 2022 ($3M): flash-loan oracle spoofing
- Solend Oct 2022 ($1.3M): stale oracle liquidation
```

#### Raydium-Style Account Injection
```
Query: Are remaining_accounts validated before being passed to inner CPI?

Pattern to detect:
- remaining_accounts iterated without count validation
- Accounts used from remaining_accounts without owner check
- Signer/writable flags not verified on remaining accounts

Historical precedent:
- Raydium Jan 2023 ($1.6M): fake pool injection via remaining_accounts
```

#### Crema-Style Close Race
```
Query: Can accounts be closed and reinitialized within the same transaction?

Pattern to detect:
- init_if_needed on accounts that can also be closed
- Close target is not a program PDA
- No reentrancy lock on close/init operations

Historical precedent:
- Crema Jul 2022 ($8.8M): flash loan + close race
```

---

## Solana Attack Primitives Library

### Primitive 1: Flash Loan (Atomicity Abuse)

**Definition**: Borrow tokens, execute operations, repay within single transaction.

**Solana-specific implementation**:
- SPL Token flash loan via `flash_loan` instruction on Token-2022
- Orca Whirlpool, Raydium AMM use flash loans internally
- No MEV — Solana is single-threaded, but transaction can include multiple instructions

**Attack pattern**:
```rust
// 1. Borrow 1M USDC from flash loan pool
// 2. Manipulate oracle price to 10x
// 3. Borrow against manipulated collateral
// 4. Repay flash loan
// 5. Profit = borrowed - collateral value
```

**Detection checklist**:
- [ ] Oracle price staleness check (slot comparison)
- [ ] TWAP with minimum lookback slots
- [ ] Balance snapshot after all flash loan repayments
- [ ] Liquidation threshold sanity check

**Helius query**: Detect transactions where same wallet calls flash loan + oracle update + borrow within 5 slots

---

### Primitive 2: CPI Reentrancy

**Definition**: Program A calls Program B, which calls back to Program A via a different PDA, bypassing reentrancy guards.

**Solana-specific**: Unlike EVM, Solana has no gas limit reentrancy. Reentrancy is possible via:
- CPI callback to same program via different PDA seeds
- Token transfer triggering transfer hook that re-enters the originating program
- Oraca-style callback in same transaction

**Attack pattern**:
```rust
// Program: Withdraw
// 1. Check balance >= amount
// 2. Transfer tokens (external call)
// 3. Update balance (state mutation AFTER external call)
// Attack: Transfer triggers hook that re-enters Withdraw
// Re-entrant call: balance not yet decremented, passes check
// Withdraw again, double-spend
```

**Detection checklist**:
- [ ] CEI pattern: Checks → State mutations → External calls
- [ ] Reentrancy lock flag set before external calls
- [ ] State re-validation after external calls
- [ ] Transfer hook reentrancy guard (nonce pattern)

---

### Primitive 3: PDA Derivation Bump Cycling

**Definition**: Attacker iterates bump values to find collision with hardcoded or expected PDA.

**Solana-specific**: Off-curve addresses via bump (0-255). Canonical bump = first valid bump from 255 down.

**Attack pattern**:
```rust
// Expected PDA: Pubkey::find_program_address(&[b"vault"], program_id)
// Uses hardcoded bump 255
let attacker_pda = Pubkey::create_program_address(&[b"vault", &[255]], program_id);
// If valid, attacker_pda == expected_pda
// But bump 254 might also be valid and off-curve
// Attacker derives with 254, calls program, bump check passes
// Program uses hardcoded 255 — mismatch
// Result: Program may reject OR attacker found bypass
```

**Cashio-specific variant**:
```rust
// Cashio: Mint authority PDA used hardcoded bump
// Attacker: Derives mint_authority with non-canonical bump
// Calls mint instruction
// Program: let (expected, _) = find_program_address(...);
// let (_, bump) = create_program_address(..., &[255]);
// Mint instruction accepts attacker-derived PDA as authority
// Bypass: Mint authority check passes because PDA matches
```

**Detection checklist**:
- [ ] No hardcoded bump literals (grep: `&[255]`, `&[bump]`)
- [ ] Always use `ctx.bumps["account"]` from Anchor
- [ ] Bump stored in account state is from canonical derivation

---

### Primitive 4: Discriminator Collision

**Definition**: Two account types share the same 8-byte Anchor discriminator.

**Anchor discriminator**: First 8 bytes of `Sha256(struct_name.to_lowercase())`

**Collision example**:
```rust
pub struct Vault { ... }           // "vault\0\0\0\0\0\0\0"
pub struct VaultState { ... }      // "vaultst\0\0\0\0\0"
                                 // First 8 bytes: SAME!
```

**Attack pattern**:
```rust
// Instruction expects VaultAdmin (with admin field)
#[derive(Accounts)]
pub struct VerifyAdmin<'info> {
    pub vault: Account<'info, VaultAdmin>, // Needs "vaultadm\0"
    pub authority: Signer<'info>,
}

// Attacker: Pass Vault account instead
// "vault\0\0\0\0\0\0\0" == "vaultadm\0" in first 8 bytes
// Anchor deserializes Vault as VaultAdmin
// Reads wrong fields for authorization check
// admin field actually contains Vault.balance
// Attack succeeds if balance > 0 (always true for funded accounts)
```

**Detection checklist**:
- [ ] Enumerate all `#[derive(Accounts)]` and `#[account]` structs
- [ ] Compute or look up each 8-byte discriminator
- [ ] Flag any collision (different structs, same first 8 bytes)

---

### Primitive 5: Sysvar Spoofing (Pinocchio)

**Definition**: Attacker passes a fake sysvar account (Clock, SlotHistory, etc.) with manipulated data.

**Solana-specific**: Sysvar accounts are just regular accounts with known pubkeys. Programs must verify sysvar pubkey.

**Attack pattern**:
```rust
// Vulnerable: No pubkey check
pub fn claim(ctx: Context<Claim>) -> Result<()> {
    let clock = Clock::from_account_info(&ctx.accounts.clock)?;
    // ctx.accounts.clock could be attacker's fake account
    let elapsed = clock.slot - ctx.accounts.user.last_claim;
    require!(elapsed >= EPOCH, ErrorCode::TooEarly);
}

// Attack: Create fake Clock with future slot
// Pass as clock account
// Time-locked withdrawal bypassed
```

**Detection checklist**:
- [ ] Use `Clock::get()` from Anchor sysvar (verifies pubkey)
- [ ] Or explicit: `require!(clock_info.key() == sysvar::clock::ID, ErrorCode::InvalidSysvar)`
- [ ] Never accept sysvar from `remaining_accounts` without validation

---

### Primitive 6: Versioned Transaction LUT Poisoning

**Definition**: Versioned transactions with address lookup tables can substitute account addresses.

**Solana-specific**: Lookup tables store account addresses. Attacker can create LUT with unexpected addresses at specific indices.

**Attack pattern**:
```rust
// Expected: accounts[0] = user_vault with 1000 tokens
// Attacker creates LUT: accounts[0] = attacker's vault with 1000 tokens
// Program receives only addresses (not account data)
// Program reads user_vault's amount — but it's attacker's vault
// Transfer goes to wrong account
```

**Detection checklist**:
- [ ] Always validate account data contents, not just pubkey
- [ ] For LUT-loaded accounts: verify owner, discriminator, and state
- [ ] Cross-check account data against expected values

---

### Primitive 7: Cross-Program Flash Loan Composition

**Definition**: Flash loan in Program A + oracle manipulation in Program B within same transaction.

**Solana-specific**: Multi-program CPI chains can span flash loan and oracle manipulation in atomic transaction.

**Attack pattern**:
```rust
// TX:
1. [FlashLoanPool] flash_borrow 10M USDC
2. [Attacker] swap USDC → SOL (manipulates Raydium pool)
3. [Attacker] borrow against manipulated SOL price from Mango
4. [FlashLoanPool] repay flash loan

// Result: Oracle price in Mango == Raydium manipulated price
// Mango uses Raydium as oracle — collateral value inflated
// Attacker borrows 10x collateral value
```

**Detection checklist**:
- [ ] Map all programs in CPI call graph
- [ ] Identify price-sensitive operations in each
- [ ] Verify flash loan repayment cannot precede oracle manipulation
- [ ] Check for commit-reveal or staleness on all price sources

---

## Helius API Integration

### Threat Pattern Detection Queries

#### 1. Rapid Transaction Anomaly Detection
```bash
# Detect >5 transactions from same signer within 3 slots (MEV/sandwich indicator)
HELIUS_KEY="${HELIUS_API_KEY}"
PROGRAM_ID="TARGET_PROGRAM_ID"

curl -s -X POST https://mainnet.helius-rpc.com/?api-key=$HELIUS_KEY \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getSignaturesForAddress",
    "params": ["'$PROGRAM_ID'", {"limit": 100}]
  }' | jq '
    [.result[].signature] as $sigs |
    [foreach $sigs[] as $sig (null; .; .) as $prev |
      {
        sig: .,
        slot: (.slot // null),
        prev_slot: ($prev.slot // null)
      } |
      select(.slot != null and .prev_slot != null and (.slot - .prev_slot) <= 3)
    ] | length as $anomaly_count |
    {
      total: ($sigs | length),
      anomalies: $anomaly_count,
      risk: (if $anomaly_count > 10 then "HIGH" elif $anomaly_count > 5 then "MEDIUM" else "LOW" end)
    }
  '
```

#### 2. Large Transfer Following Oracle Update
```bash
# Cross-reference oracle update slots with large transfers
ORACLE_UPDATED_SLOT=123456789

curl -s -X POST https://mainnet.helius-rpc.com/?api-key=$HELIUS_KEY \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getSignaturesForAddress",
    "params": ["'$PROGRAM_ID'", {
      "limit": 50,
      "until": "'$ORACLE_UPDATED_SLOT'"
    }]
  }' | jq '
    .result[] |
    select(.slot >= '$((ORACLE_UPDATED_SLOT - 5))' and .slot <= '$((ORACLE_UPDATED_SLOT + 5))') |
    {
      signature,
      slot,
      hasError: (.err != null)
    }
  '
```

#### 3. Known Exploit Contract Interaction
```bash
# Check if program has interacted with known exploit addresses
declare -a EXPLOIT_ADDRESSES=(
  "ExploitAddr1..."
  "ExploitAddr2..."
)

for EXPLOIT in "${EXPLOIT_ADDRESSES[@]}"; do
  RESULT=$(curl -s -X POST https://mainnet.helius-rpc.com/?api-key=$HELIUS_KEY \
    -H "Content-Type: application/json" \
    -d '{
      "jsonrpc": "2.0",
      "id": 1,
      "method": "getProgramAccounts",
      "params": ["'$PROGRAM_ID'", {
        "filters": [{"memcmp": {"bytes": "'$EXPLOIT'", "offset": 0}}]
      }]
    }' | jq '.result | length')
  echo "Interactions with $EXPLOIT: $RESULT"
done
```

#### 4. Upgrade Authority Drift Detection
```bash
# Alert if upgrade authority changes
PREVIOUS_AUTH="OldAuthorityPubkey..."
CURRENT_AUTH=$(solana program show $PROGRAM_ID | grep "Upgrade authority" | awk '{print $3}')

if [ "$PREVIOUS_AUTH" != "$CURRENT_AUTH" ]; then
  echo "ALERT: Upgrade authority changed from $PREVIOUS_AUTH to $CURRENT_AUTH"
  # Trigger incident response
fi
```

#### 5. Token Drain Pattern Detection
```bash
# Monitor vault balances for rapid drainage
VAULT_PUBKEY="VaultPubkey..."

PREV_BALANCE=$(curl -s -X POST https://mainnet.helius-rpc.com/?api-key=$HELIUS_KEY \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getBalance",
    "params": ["'$VAULT_PUBKEY'"]
  }' | jq '.result.value')

sleep 5

CURRENT_BALANCE=$(curl -s -X POST https://mainnet.helius-rpc.com/?api-key=$HELIUS_KEY \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getBalance",
    "params": ["'$VAULT_PUBKEY'"]
  }' | jq '.result.value')

DRAIN=$((PREV_BALANCE - CURRENT_BALANCE))
DRAIN_PCT=$((DRAIN * 100 / PREV_BALANCE))

if [ $DRAIN_PCT -gt 20 ]; then
  echo "CRITICAL: Vault drained $DRAIN_PCT% ($DRAIN lamports) in 5 seconds"
fi
```

---

## Threat Model Output Format

```json
{
  "program_id": "TargetProgramId",
  "generated_at": "ISO-8601",
  "threat_model": {
    "spoofing": {
      "severity_floor": "CRITICAL",
      "findings": [
        {
          "id": "TM-S-001",
          "description": "PDA derivation uses hardcoded bump",
          "location": "programs/vault/src/lib.rs:142",
          "rules": [3],
          "exploit_precedent": "Cashio $52M",
          "likelihood": "HIGH",
          "impact": "CRITICAL"
        }
      ]
    },
    "tampering": {
      "severity_floor": "CRITICAL",
      "findings": [
        {
          "id": "TM-T-001",
          "description": "remaining_accounts not validated in CPI call",
          "location": "programs/amm/src/lib.rs:89",
          "rules": [15, 24],
          "exploit_precedent": "Raydium $1.6M",
          "likelihood": "HIGH",
          "impact": "CRITICAL"
        }
      ]
    },
    "repudiation": {
      "severity_floor": "MEDIUM",
      "findings": []
    },
    "information_disclosure": {
      "severity_floor": "HIGH",
      "findings": []
    },
    "denial_of_service": {
      "severity_floor": "MEDIUM",
      "findings": []
    },
    "elevation_of_privilege": {
      "severity_floor": "CRITICAL",
      "findings": []
    }
  },
  "risk_summary": {
    "critical_count": 2,
    "high_count": 3,
    "medium_count": 0,
    "low_count": 1,
    "overall_rating": "CRITICAL"
  },
  "recommended_mitigations": [
    "Use ctx.bumps for all PDA derivations",
    "Validate remaining_accounts before CPI",
    "Add CEI pattern to all token transfer instructions"
  ]
}
```

---

## Audit Workflow Integration

```
┌─────────────────┐
│  Recon Phase    │ → Map attack surface, identify entry points
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Threat Modeler │ → STRIDE classification, exploit intelligence
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Static Analysis │ → Apply 50 rules against threat model
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Findings Triage │ → STRIDE-categorized findings with exploit context
└─────────────────┘
```

---

## False Positive Reduction Guide

| Threat Category | Common False Positive | Filter |
|----------------|----------------------|--------|
| Spoofing | `find_program_address` result unused | Only flag if hardcoded bump used in security path |
| Spoofing | `Signer<T>` in Accounts struct | No flag — Anchor enforces this |
| Tampering | `Account::load_mut()` on owned account | No flag — ownership enforced by type |
| EoP | `invoke` to System Program | No flag — System Program is limited |
| EoP | Pyth oracle with slot check | No flag — staleness enforced |
| DoS | `try_from_slice` with owner check | No flag — owner verified first |

---

## Usage Examples

### Generate threat model for a new program
```
/threat-model <PROGRAM_ID>
```

### Cross-reference specific finding against exploit database
```
/threat-model correlate <FINDING_ID> --precedent wormhole
```

### Check deployed program for exploit interactions
```
/threat-model scan <PROGRAM_ID> --exploit-db
```

### Generate STRIDE matrix for all findings
```
/threat-model matrix --findings findings.json
```

---

## References

- OWASP Top 10 (adapted for Solana): `references/OWASP-SOLANA.md`
- Full STRIDE guide: `skill/02-threat-modeling.md`
- Helius API docs: `references/HELIUS-API.md`
- Exploit database: `data/exploits/` directory
- 50 Audit rules: `rules/audit.rules`
