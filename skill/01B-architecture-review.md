---
name: "01B-architecture-review"
description: "Phase 1B: Structural architecture review for Solana/Anchor programs — upgrade authority, authority types, token extensions, program upgrade paths, and systemic risk assessment"
triggers:
  - "User requests architecture review for a deployed program"
  - "After Phase 1 recon (program_metadata.json, attack_surface.json available)"
  - "Before Phase 2 static analysis (primes the code-level auditor)"
  - "Architecture flag passed: /audit --architecture"
  - "Pre-deployment assessment for new program design"
examples:
  - "review the upgrade authority on this deployed program"
  - "check the authority types and token extensions for this token"
  - "/audit examples/sample-vulnerable-program --architecture"
---

# Phase 1B: Architecture Review

**Goal**: Assess the structural security posture of a Solana program by examining on-chain configuration, authority topology, token extension usage, and upgrade pathways — before reading a line of Rust.

**Prerequisites**: Phase 1 recon artifacts — `program_metadata.json`, `attack_surface.json`, `cpi_surface.json`.

**Execution order**: Run after Phase 1 recon, in parallel with or immediately before Phase 2 static analysis. Architecture findings feed Phase 4 triage as systemic / design-level issues that cannot be fixed by code changes alone.

---

## Why Architecture Review First

Most Solana security failures are not code bugs — they are **design decisions made at the architecture level** that no amount of SAST can rescue:

| Failure | Code Fixable? | Architecture Root Cause |
|---------|--------------|----------------------|
| Program backdoored via upgrade authority | No | Single EOA holds upgrade authority |
| Token frozen by mint freeze authority | No | Mint freeze authority assigned to hot wallet |
| Token supply manipulated via mint authority | No | Mint authority not renounced |
| Program cannot be upgraded (buggy, no authority) | No | Upgrade authority == address(0) |
| Confidential transfer fee not extracted | Partial | `transfer_fee` extension present but not accounted |
| Extension bypassed because extension not verified | Yes | Missing `#[account(constraint = ...)]` on mint |

Architecture review catches the class of findings that require **redesign**, not refactor.

---

## Architecture Review Checklist

### 1. Upgrade Authority Assessment

**What to check**: Who controls the program's upgrade authority, and how robust is that control?

#### Query Upgrade Authority
```bash
# Get program authority via Solana CLI
solana program show PROGRAM_ID -um | grep -i "upgrade"

# Expected output fields:
# Upgrade authority: <pubkey or "none">
# Buffer authority:  <pubkey or "none">
# Spill address:    <pubkey>
```

#### Authority Type Classification

| Classification | Indicator | Risk |
|----------------|-----------|------|
| **Multisig / DAO** | Authority matches a known multisig program (e.g., Realms, Spl Governance) | LOW — governance-controlled |
| **Timelock** | Authority is a timelock contract with delay | LOW-MEDIUM — delay bounds abuse window |
| **Cold wallet** | Authority is an offline keypair (not used for daily ops) | MEDIUM — key security depends on offline storage |
| **Hot wallet (EOA)** | Authority is a standard pubkey (no program logic) | HIGH — single point of failure |
| **Same as program ID** | Authority == program ID itself | CRITICAL — program can upgrade itself via CPI |
| **Immutable (no authority)** | Program uses BPF Loader 1 | LOW — no upgrade path means no backdoor |
| **Renounced** | Authority == address(0) | LOW — permanently non-upgradeable |

#### Authority Revocation Status (RPC Verification)
```bash
# Permanently non-upgradeable (BPF Loader 1):
#   CLI output: "This program is not upgradeable"

# Upgradeable (BPF Loader 2 / Anchor):
#   CLI output shows: "Upgrade authority: <pubkey>"

# Verify renounced authority via RPC (CLI may still show pubkey):
curl -s -X POST https://mainnet.helius-rpc.com/?api-key=${HELIUS_RPC_KEY} \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getProgramMetadata",
    "params": ["PROGRAM_ID"]
  }' | jq '.result.authorities'
```

#### Finding: Single EOA Upgrade Authority

```json
{
  "id": "ARCH-UPG-001",
  "severity": "CRITICAL",
  "title": "Single EOA holds program upgrade authority",
  "category": "upgrade_authority",
  "description": "The program's upgrade authority is a standard EOA pubkey. Any compromise of this key (phishing, malware, insider threat) allows the attacker to deploy a malicious program version and seize all program-controlled funds.",
  "affected": ["PROGRAM_ID"],
  "location": "on-chain configuration",
  "cvss_estimate": 9.8,
  "cvss_vector_estimate": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cwe": "CWE-306",
  "mitigation": "Transfer upgrade authority to a multisig (e.g., 3/5 Spl Governance) or a timelock contract with a minimum 24-hour delay.",
  "code_fixes": false,
  "design_fixes": true
}
```

#### Finding: Program Self-Upgrade

```json
{
  "id": "ARCH-UPG-002",
  "severity": "CRITICAL",
  "title": "Program upgrade authority equals program ID — self-upgrade via CPI possible",
  "category": "upgrade_authority",
  "description": "The upgrade authority matches the program ID itself. The program can invoke itself via CPI and trigger an upgrade instruction, bypassing any in-program access controls.",
  "affected": ["PROGRAM_ID"],
  "location": "on-chain configuration",
  "cvss_estimate": 10.0,
  "cvss_vector_estimate": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cwe": "CWE-347",
  "mitigation": "Set upgrade authority to a governance contract or multisig. The program ID should never be the upgrade authority.",
  "code_fixes": false,
  "design_fixes": true
}
```

#### Example: sample-vulnerable-program Upgrade Authority Assessment

The `native-vault` program (Program ID: `NatiV8XCvFhMtNTSg9qV9u1KKrn3DLzNaX7cSC8K8H2`) is **non-upgradeable** — it uses the BPF Loader 1 (immutable) and no upgrade authority exists.

```bash
# Program ID from source declaration
PROGRAM_ID="NatiV8XCvFhMtNTSg9qV9u1KKrn3DLzNaX7cSC8K8H2"

# Source inspection (programs/native-vault/src/lib.rs):
#   solana_program::declare_id!("NatiV8XCvFhMtNTSg9qV9u1KKrn3DLzNaX7cSC8K8H2");
#   entrypoint!(process_instruction);
# No Anchor derive macros — native program, not upgradeable

# Assessment:
Classification: IMMUTABLE (BPF Loader 1)
Upgrade authority: NONE
Risk Level: LOW — no upgrade path means no backdoor via upgrade authority
Code Fixable: NO — redeployment required for any bug fix
Design Note: Immutable programs must be audited comprehensively before deployment.
             Critical bugs in immutable programs cannot be patched.
```

**Architecture finding for native-vault**:
```json
{
  "id": "ARCH-UPG-IMM-001",
  "severity": "INFO",
  "title": "Program is non-upgradeable — no patch path for code-level bugs",
  "category": "upgrade_authority",
  "description": "native-vault uses BPF Loader 1 (immutable). Any bugs found in the code require full redeployment to a new program ID. Users must migrate to the new program.",
  "affected": ["NatiV8XCvFhMtNTSg9qV9u1KKrn3DLzNaX7cSC8K8H2"],
  "location": "programs/native-vault/src/lib.rs:29",
  "code_fixes": false,
  "design_fixes": false
}
```

### 2. Authority Types Assessment (Token Programs)

**What to check**: For SPL Token and Token-2022 mints, what authority types are set and are any dangerous?

#### Authority Types on Solana

| Authority Type | Risk | Renounce Pattern |
|---------------|------|-----------------|
| **Mint Authority** | HIGH — can mint unlimited tokens | Set to `None` or call mint with amount=0 |
| **Freeze Authority** | HIGH — can freeze all token accounts | Set to `None` if permanent freezing not needed |
| **Close Authority** | MEDIUM — can close the mint account | Set to `None` if mint should be permanent |
| **Metadata Authority** | MEDIUM (T-2022) | Scope to specific governance-controlled address |
| **Transfer Fee Authority** | MEDIUM (T-2022) | Set to `None` if fees are fixed forever |
| **Withheld Fees Authority** | LOW (T-2022) | Collect and clear fees, then renounce |

#### Query Token Authorities
```bash
# Get SPL Token authority info via RPC
curl -s -X POST https://mainnet.helius-rpc.com/?api-key=${HELIUS_RPC_KEY} \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getTokenSupply",
    "params": ["TOKEN_MINT_ADDRESS"]
  }' | jq '{
    supply: .result.amount,
    decimals: .result.decimals,
    mintAuthority: .result.mintAuthority,
    freezeAuthority: .result.freezeAuthority
  }'

# Also get largest accounts to assess concentration risk
curl -s -X POST https://mainnet.helius-rpc.com/?api-key=${HELIUS_RPC_KEY} \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getTokenLargestAccounts",
    "params": ["TOKEN_MINT_ADDRESS"]
  }' | jq '.result.value[:10] | .[] | {address: .address, amount: .amount, uiAmount: .uiAmount}'
```

#### Finding: Mint Authority Not Renounced

```json
{
  "id": "ARCH-TOKEN-001",
  "severity": "HIGH",
  "title": "Mint authority not renounced — unlimited supply inflation risk",
  "category": "token_authority",
  "description": "The token mint has an active mint authority. The controller can mint unlimited tokens at any time, collapsing the token's market value.",
  "affected": ["TOKEN_MINT_ADDRESS"],
  "location": "on-chain mint configuration",
  "cvss_estimate": 8.1,
  "cvss_vector_estimate": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
  "cwe": "CWE-345",
  "mitigation": "Call the mint instruction with amount=0 to renounce mint authority permanently, or transfer to a multisig requiring governance approval.",
  "code_fixes": false,
  "design_fixes": true
}
```

#### Finding: Freeze Authority Active

```json
{
  "id": "ARCH-TOKEN-002",
  "severity": "HIGH",
  "title": "Freeze authority active — all token accounts can be frozen",
  "category": "token_authority",
  "description": "The token mint has an active freeze authority. The controller can freeze any token account, permanently locking the tokens until unfrozen.",
  "affected": ["TOKEN_MINT_ADDRESS"],
  "location": "on-chain mint configuration",
  "cvss_estimate": 7.5,
  "cvss_vector_estimate": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
  "cwe": "CWE-862",
  "mitigation": "Renounce freeze authority if permanent token freezing is not a design requirement. If freeze authority is needed (compliance), scope to a governance contract.",
  "code_fixes": false,
  "design_fixes": true
}
```

### 3. Token Extensions Assessment (Token-2022)

**What to check**: Which Token-2022 extensions are active, and are they being verified by the program?

#### Token-2022 Extension Reference

| Extension | Risk if Not Verified | What to Check |
|-----------|----------------------|----------------|
| `metadata_pointer` | Wrong metadata accepted for mint operations | Program verifies `metadata_pointer` address |
| `mint_close_authority` | Mint can be closed unexpectedly | Program checks mint still open before operations |
| `transfer_fee` | Fee not deducted from transfer amounts | Total supply / balance calculations account for fees |
| `default_account_state` | Default state may block transfers | Account state verified before transfer |
| `immutable_ownership` | Owner can be changed | Verify `account.owner == expected` in logic |
| `non_transferable` | Tokens may not be transferable | Check `is_transferable` flag before transfers |
| `interest_bearing` | Supply changes over time | Accrued interest accounted in value calculations |
| `confidential_transfer` | Fee not extracted on settle | Fee extraction verified in settle logic |
| `transfer_hook` | Arbitrary program execution via hook | See Rules 27-35 in `rules/audit.rules` |
| `memo_required` | Transfers without memo may be untrackable | Verify memo present for all transfers |
| `permanent_delegate` | Delegate can drain all accounts forever | Delegate is renounced or scoped to governance |

#### Detect Active Extensions
```bash
# Get mint account data to detect Token-2022 extensions
curl -s -X POST https://mainnet.helius-rpc.com/?api-key=${HELIUS_RPC_KEY} \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getAccountInfo",
    "params": ["TOKEN_MINT_ADDRESS", {"encoding": "base64"}]
  }' | jq '.result.value.data[0]' | base64 -d | xxd | head -80

# Token-2022 mints: header is 128 bytes
# Offsets 0-44: same as SPL Token base mint
# Offsets 45-127: extension count and pointers
# Extension type IDs:
#   0 = transfer_fee
#   1 = mint_close_authority
#   2 = opaque (custom extension)
#   etc.
```

#### Check Program Awareness of Extensions
```bash
# Search for extension-aware code patterns in source
grep -rn "extension\|Extension\|transfer_fee\|metadata_pointer\|mint_close" \
  programs/*/src/lib.rs 2>/dev/null | grep -v "//" | grep -v "test"

# For Token-2022 programs, verify each active extension is handled
# List of extensions detected from mint account + extensions active
```

#### Finding: Token-2022 Extension Present, Not Verified

```json
{
  "id": "ARCH-EXT-001",
  "severity": "HIGH",
  "title": "Token-2022 metadata_pointer extension active but not verified by program",
  "category": "token_extension",
  "description": "The mint has a metadata_pointer extension pointing to external metadata. The program does not verify the metadata pointer address before using mint metadata. An attacker who controls the external metadata target can change displayed token name/symbol without changing the mint authority.",
  "affected": ["TOKEN_MINT_ADDRESS"],
  "location": "on-chain mint configuration + program logic",
  "cvss_estimate": 7.5,
  "cvss_vector_estimate": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
  "cwe": "CWE-287",
  "mitigation": "Add metadata pointer verification in mint operations: require the pointer matches a trusted metadata address. Do not use mint metadata without verifying the pointer chain.",
  "code_fixes": true,
  "design_fixes": false
}
```

#### Finding: Transfer Fee Extension Not Accounted

```json
{
  "id": "ARCH-EXT-002",
  "severity": "MEDIUM",
  "title": "Token-2022 transfer_fee extension active but fees not deducted in program logic",
  "category": "token_extension",
  "description": "The mint uses the transfer_fee extension. The program transfers tokens without deducting the transfer fee, causing net transfer to exceed the program's recorded amount. If the program tracks balances, a fee-based transfer will show a higher outgoing balance than incoming.",
  "affected": ["TOKEN_MINT_ADDRESS"],
  "location": "program transfer logic + mint configuration",
  "cvss_estimate": 6.5,
  "cvss_vector_estimate": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
  "cwe": "CWE-682",
  "mitigation": "Use Token-2022 transfer instruction which handles fees atomically, or manually compute and deduct the fee before recording the net transfer amount.",
  "code_fixes": true,
  "design_fixes": false
}
```

### 4. Program Upgrade Path Assessment

**What to check**: If the program is upgradeable, what is the upgrade authority's security posture?

#### Upgrade Path Risk Matrix

| Upgrade Authority | Upgrade Path Security | Recommendation |
|-------------------|----------------------|----------------|
| Multisig (3+/N) | HIGH — N-of-M required | Acceptable for high-value programs |
| Timelock (24h+ delay) | MEDIUM — bounded abuse window | Acceptable; monitor for unauthorized scheduled upgrades |
| Cold wallet (offline key) | MEDIUM — depends on key storage | Acceptable if key is air-gapped and stored securely |
| Hot wallet (daily-use EOA) | HIGH — single point of failure | CRITICAL risk for production programs |
| Same as program ID | CRITICAL — self-upgrade via CPI | Block: program must never upgrade itself |
| Renounced (address(0)) | LOW — permanently immutable | Good; code bugs require redeployment |

#### Timelock Audit Procedure
```bash
# If upgrade authority is a program (timelock), fetch its config
TIMELOCK_ADDR="<upgrade_authority_pubkey>"
solana account $TIMELOCK_ADDR --output json | jq '.'

# Verify the timelock config account fields:
#   unlock_slot / delay_slots — minimum 24h (~43200 slots)
#   admin — can propose upgrades
#   guardian — can cancel pending upgrades (should be independent from admin)
#   bump — canonical bump used for PDA derivation
```

### 5. CPI Surface Systemic Risk

**What to check**: Does the program's CPI call graph introduce systemic risk that code-level fixes cannot address?

#### CPI Systemic Risk Patterns

| Pattern | Why Systemic | Fixable in Code? |
|---------|-------------|-----------------|
| Program CPI-calls itself | Reentrancy possible via CPI callback | Partial — CEI pattern helps but systemic risk remains |
| Program CPI-calls wallet-controlled program | Arbitrary program execution possible | Partial — program allowlist helps |
| Program uses Pyth without staleness check | Oracle manipulation within same tx | Yes — add slot check |
| Program uses flash-loanable token as collateral | Flash loan + oracle manipulation | Partial — balance snapshot after repayment |

#### Analyze CPI Surface
```bash
# Load cpi_surface.json from Phase 1
cat audit-report/cpi_surface.json | jq '{
  total_programs: .metadata.total_programs,
  total_cpi_calls: .metadata.total_cpi_calls,
  untrusted_calls: [.edges[] | select(.threat_level == "CRITICAL" or .threat_level == "HIGH")] | length
}'
```

### 6. Architecture Output Schema

Produce one JSON artifact per program:

```json
{
  "program": "native-vault",
  "version": "1.0.0",
  "analyst": "architecture-reviewer",
  "generated_at": "ISO-8601",
  "program_id": "NatiV8XCvFhMtNTSg9qV9u1KKrn3DLzNaX7cSC8K8H2",
  "classification": {
    "upgradeability": "non-upgradeable",
    "upgrade_authority_type": "none",
    "upgrade_authority_risk": "LOW",
    "token_type": "native_sol",
    "token_extensions": [],
    "systemic_risk": "LOW"
  },
  "authority_findings": [
    {
      "id": "ARCH-UPG-IMM-001",
      "type": "upgrade_authority",
      "status": "not_upgradeable",
      "severity": "INFO",
      "risk": "LOW",
      "rationale": "Program uses BPF Loader 1 — permanently immutable. No backdoor via upgrade authority.",
      "location": "programs/native-vault/src/lib.rs:29"
    }
  ],
  "token_findings": [],
  "extension_findings": [],
  "cpi_findings": [],
  "systemic_risk_factors": [],
  "overall_architecture_rating": "LOW",
  "overall_architecture_rationale": "Non-upgradeable native program with no external authorities. Systemic risk is minimal. Primary attack surface is code-level (signer verification, sysvar handling).",
  "phase2_prime": true,
  "code_fixes_available": false,
  "design_fixes_required": true
}
```

---

## Architecture Rating Scale

| Rating | Criteria |
|--------|----------|
| **CRITICAL** | EOA upgrade authority, or program CPI-calls itself without guards, or mint authority not renounced with high-value token |
| **HIGH** | Hot wallet upgrade authority, or active freeze/mint authority on token with material supply, or Token-2022 extension not verified |
| **MEDIUM** | Cold wallet upgrade authority, or timelock without governance veto, or optional extension not verified |
| **LOW** | Multisig/timelock with veto, or immutable (no upgrade authority), or no token extensions |

---

## Output Artifacts

| Artifact | Path | Contents |
|----------|------|----------|
| Per-program architecture review | `audit-report/architecture/{program}_architecture.json` | Full authority, extension, and upgrade assessment |
| Architecture rating | `audit-report/architecture/ratings.json` | Program-level architecture ratings |
| Design findings | `audit-report/findings.json` (design section) | Architecture findings that feed Phase 4 triage |
| Trust topology | `audit-report/architecture/trust_topology.md` | Textual authority trust map |

---

## Integration with Threat Modeler

The architecture reviewer and threat-modeler coordinate:

```
Phase 1B: Architecture Review
  - Outputs: program authority type, token extensions, upgrade path
  - Feeds: threat-modeler (trust boundaries), Phase 2 (prime for systemic risk)

Phase 2A: Threat Modeler
  - Inputs: architecture rating, authority findings
  - Maps: architecture risk to STRIDE categories
  - Outputs: threat IDs with architecture_enabler flag

Phase 4: Triage
  - Merges: architecture findings + threat model findings + Phase 2 findings
  - Applies: CVSS to all findings regardless of source
```

Architecture findings that enable Phase 2 vulnerabilities should be cross-referenced in the threat model:

```json
{
  "threat_id": "TM-NATIVE-E01",
  "stride": "elevation_of_privilege",
  "architecture_enabler": "non-upgradeable — attacker can exploit without worrying about program upgrade",
  "architecture_finding_id": "ARCH-UPG-IMM-001",
  "mitigation": "Audit thoroughly before deployment since no patch path exists"
}
```

---

## Integration with Phase 2 Static Analysis

Architecture findings and code-level findings are complementary:

| Aspect | Architecture Review (Phase 1B) | Static Analysis (Phase 2) |
|--------|-------------------------------|---------------------------|
| Scope | On-chain config, authority topology, extensions | Source code, instruction logic, CPI paths |
| Finding type | Design-level (cannot fix in code) | Code-level (can fix in code) |
| Fixability | `design_fixes: true` only | `code_fixes: true` |
| Overlap | Authority misconfiguration may enable exploits | Code exploits may be architecture-enablable |
| Triage | Design findings treated same as code findings | CVSS scoring applies to both |

**Coverage gap detection**: If Phase 2 finds a HIGH/CRITICAL vulnerability that is architecture-enablable (e.g., CPI privilege escalation enabled by missing program allowlist), flag a corresponding architecture finding.

---

## Reference Implementation — sample-vulnerable-program

### native-vault Program Architecture

```
Program ID:   NatiV8XCvFhMtNTSg9qV9u1KKrn3DLzNaX7cSC8K8H2
Source:       programs/native-vault/src/lib.rs
Framework:    Native Solana (no Anchor)
Upgrade:      Non-upgradeable (BPF Loader 1)
Token:        Native SOL (no SPL token)
Extensions:   None
```

**Architecture Assessment Walkthrough**:

1. **Upgrade Authority**: None (immutable). `entrypoint!` macro + no `solana_program::program` attribute = BPF Loader 1 deployment. No upgrade authority risk.

2. **Token Authority**: N/A. Program manages native SOL lamports, not SPL tokens. No mint/freeze/close authority to assess.

3. **Token Extensions**: N/A. No Token-2022 usage.

4. **CPI Surface**: Program performs no CPI calls (no `invoke`/`invoke_signed`). No cross-program trust delegation.

5. **Authority Findings**: One INFO finding — immutable means no patch path.

6. **Systemic Risk**: LOW. Code-level vulnerabilities (VULN-N01: Clock sysvar spoofing, VULN-N02: missing signer check) are the attack surface. These are Phase 2 findings, not architecture findings.

**Architecture Rating**: LOW

---

## Next Phase

After architecture review → load `skill/01-recon.md` output (`attack_surface.json`, `cpi_surface.json`, `program_metadata.json`) into context, then load `skill/02-static-analysis.md` (Phase 2) with architecture findings as priming context.

---

## Quick Reference — Architecture Checklist

- [ ] Upgrade authority type identified (EOA / multisig / timelock / immutable)
- [ ] Mint authority renounced (for supply-capped tokens)
- [ ] Freeze authority renounced or scoped to governance
- [ ] Token-2022 extensions detected and verified by program
- [ ] Upgrade path risk assessed (timelock delay, multisig threshold)
- [ ] CPI surface systemic risk evaluated
- [ ] Architecture rating assigned (CRITICAL / HIGH / MEDIUM / LOW)
- [ ] Design findings separated from code findings
- [ ] Findings tagged with `code_fixes` vs `design_fixes` flag
- [ ] Architecture-enabling Phase 2 vulnerabilities cross-referenced
