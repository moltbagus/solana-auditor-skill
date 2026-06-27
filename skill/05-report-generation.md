# Phase 5: Report Generation

**Goal**: Produce a production-grade audit report.

## Report Structure

```
1. Executive Summary
2. Architecture Review Summary
3. Threat Model Summary (STRIDE)
4. Economic Security Analysis
5. Scope
6. Methodology
7. Detailed Findings
8. Findings Summary Table
9. Remediation Recommendations
10. Appendix
```

## 1. Executive Summary

```markdown
## Executive Summary

[Program Name] ("the Program") was audited for security vulnerabilities
from [Date] to [Date]. The audit covered [N] instruction handlers,
[N] account types, and [N] cross-program invocations.

**Total Issues Found**: [N] (N critical, N high, N medium, N low, N info)

**Key Risks Identified**:
- [CRIT] Brief description of most severe finding
- [HIGH] Brief description of second most severe

**Overall Assessment**: [Safe to Deploy / Safe to Deploy with Fixes / Not Safe to Deploy]
```

## 2. Architecture Review Summary

```markdown
## Architecture Review Summary

### Program Design Overview

[Program Name] is a [type] program built on Solana using Anchor framework version [X.Y.Z].
The program manages [N] account types and exposes [N] instruction handlers for
[deposits/withdrawals/swaps/governance/etc.].

### Account Architecture

| Account Type | Purpose | Access Control |
|--------------|---------|----------------|
| [Vault] | [Stores program funds] | [Signer + has_one authority] |
| [UserState] | [Tracks per-user balances] | [PDA derived from user] |
| [Config] | [Global parameters] | [Admin signer only] |

### Cross-Program Invocations

The program performs CPIs to the following external programs:

| Target | Purpose | Trust Assumption |
|--------|---------|------------------|
| System Program | Account creation | Trusted — immutable |
| Token Program | SPL token transfers | Trusted — audited |
| Associated Token Program | ATA derivation | Trusted — standard |
| [Custom Program] | [Purpose] | [Assumption — e.g., audited, allowlist] |

### Program Derived Addresses

| PDA Seeds | Deriver | Access Pattern |
|-----------|---------|----------------|
| ["vault", authority] | initialize | [Authority only] |
| ["user", user, vault] | init_user | [User or authority] |
| ["config"] | initialize | [Admin only] |

### Data Flow

```
User Transaction
      │
      ▼
┌─────────────────┐
│  Instruction    │
│  Deserialization│ ── 8-byte discriminator check
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Account        │ ── Signer verification
│  Validation     │ ── Owner checks
└────────┬────────┘ ── has_one constraints
         │
         ▼
┌─────────────────┐
│  Business Logic │ ── CPI to token/system
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  State Write    │ ── Account mutation
└─────────────────┘
```

### Design Strengths

- [Strength 1 — e.g., Uses Anchor's type-safe Account wrapper]
- [Strength 2 — e.g., PDA-based access control eliminates signer checks]
- [Strength 3 — e.g., Structured event emission for observability]

### Design Concerns

- [Concern 1 — e.g., Single admin key for upgrade authority]
- [Concern 2 — e.g., No timelock on governance changes]
- [Concern 3 — e.g., External CPI target not allowlisted]
```

## 3. Threat Model Summary (STRIDE)

```markdown
## Threat Model Summary (STRIDE)

The STRIDE methodology was applied to identify threats across six categories:
**S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure,
**D**enial of Service, and **E**levation of Privilege.

### Spoofing — Impersonating Users or Programs

| Threat | Affected Component | Likelihood | Impact |
|--------|-------------------|------------|--------|
| Attacker signs transactions with stolen key | [Admin operations] | [Low/Med/High] | [CRITICAL/HIGH] |
| Malicious program impersonates trusted CPI | [CPI targets] | [Low/Med/High] | [CRITICAL/HIGH] |

**Mitigations in place**: [Signer verification, program ID validation]
**Gaps**: [Missing checks identified in findings]

### Tampering — Modifying Data or State

| Threat | Affected Component | Likelihood | Impact |
|--------|-------------------|------------|--------|
| Flash loan manipulation of state | [Price feeds, vault balances] | [Low/Med/High] | [CRITICAL/HIGH] |
| Reentrancy during state update | [Withdraw functions] | [Low/Med/High] | [CRITICAL/HIGH] |

**Mitigations in place**: [Reentrancy guards, checked arithmetic]
**Gaps**: [Missing checks identified in findings]

### Repudiation — Denying Actions Took Place

| Threat | Affected Component | Likelihood | Impact |
|--------|-------------------|------------|--------|
| No event emission for critical actions | [Withdraw, admin ops] | [Low/Med/High] | [MEDIUM/LOW] |

**Mitigations in place**: [Event emission on withdrawals]
**Gaps**: [Missing events identified in findings]

### Information Disclosure — Exposing Confidential Data

| Threat | Affected Component | Likelihood | Impact |
|--------|-------------------|------------|--------|
| Account data publicly readable | [User balances, positions] | [Low/Med/High] | [LOW/INFO] |

**Mitigations in place**: [Solana account model is public by default]
**Gaps**: [No sensitive data should be on-chain]

### Denial of Service — Disrupting Availability

| Threat | Affected Component | Likelihood | Impact |
|--------|-------------------|------------|--------|
| Griefing via dust accounts | [Vault, user accounts] | [Low/Med/High] | [MEDIUM/LOW] |
| Program pause without recovery | [All operations] | [Low/Med/High] | [MEDIUM/LOW] |

**Mitigations in place**: [Rent-exempt minimums, pause authority]
**Gaps**: [No automatic dust cleanup identified]

### Elevation of Privilege — Gaining Unauthorized Access

| Threat | Affected Component | Likelihood | Impact |
|--------|-------------------|------------|--------|
| Missing signer check on admin | [admin_withdraw] | [Low/Med/High] | [CRITICAL/HIGH] |
| CPI to arbitrary program | [exec_callback] | [Low/Med/High] | [CRITICAL/HIGH] |

**Mitigations in place**: [Signer type, program type]
**Gaps**: [Missing constraints identified in findings]

### Threat Surface Summary

| Category | Open Findings | Mitigated Threats |
|----------|--------------|-------------------|
| Spoofing | [N] | [N] |
| Tampering | [N] | [N] |
| Repudiation | [N] | [N] |
| Info Disclosure | [N] | [N] |
| Denial of Service | [N] | [N] |
| Elevation of Privilege | [N] | [N] |

**Total unique threats modeled**: [N]
**Threats with open findings**: [N]
```

## 4. Economic Security Analysis

When the target program involves token mechanics, fee flows, or governance, append
this section. Not every audit requires it — gate on presence of `Mint`, `TokenAccount`,
or governance program accounts in the scope.

---

### 4.1 Tokenomics Analysis Template

#### Supply Mechanics

| Supply Type | Auditor Checklist |
|-------------|------------------|
| Fixed | Verify no `MintTo`/`Burn` authority in program; confirm mint decimals and supply cap in IDL |
| Inflationary | Map all `MintTo` call sites; audit rate governors (who controls emission?). Check for zero-authority mint (anyone can inflate) |
| Capped | Confirm `MaxSupply` in Mint; verify program prevents minting beyond cap |

**Red flags**:
- `MintTo` without signer check
- `Supply::amount` not read/validated before minting
- Program holds mint authority indefinitely with no timelock

#### Fee Flow Mapping

1. Enumerate every `transfer`/`burn`/`fees` CPI call site
2. Identify recipient: treasury, LP, validator stake, token holders, veLOCK model
3. Check conditional gates: are fees only collectible by authorized actors?
4. Trace non-standard fee logic (e.g., protocol take on each swap, flash-loan fee)

**Example fee audit entry**:
```markdown
| Fee Source | Recipient | Condition | Program Path |
|------------|-----------|-----------|--------------|
| Swap fee 30bp | LP reserves | Every swap | dex.rs:127 |
| Protocol take 10bp | Treasury | If `fee_authority` signed | treasury.rs:45 |
| Withdrawal fee | None (burn) | If `burn_fees=true` | vault.rs:88 |
```

#### Emission Schedule

Audit unlock schedules against realistic cliff-and-vest math:

- **TGE allocation**: What % circulating at genesis? (< 5% is healthy; > 20% is high risk)
- **Cliff**: Duration before first unlock (6–12 months is standard)
- **Linear release**: Monthly or daily unlock after cliff
- **Team/investor unlock**: Separated cliffs or back-loaded?

**Real examples**:

| Token | Supply Model | Key Risk | Auditor Flag |
|-------|-------------|----------|--------------|
| USDC | Fully reserved, regulated | Depeg via fractional reserve or regulatory freeze | Check `Reserve::collateral_ratio`; Circle's attestations are off-chain trust anchor |
| UST | Algorithmic (pre-2022) | No real reserve; depeg spiral when demand exits | `mint_ust()` accepts any collateral ratio; no liquidation trigger |
| BONK | Highly inflationary, meme | Massive inflation dilutes early holders | `total_supply` increases by 50%+ per year; verify vesting cliff |

#### Solana-Specific Token Checks

```bash
# Check mint authority — if none, supply is fixed
spl-token supply <MINT>
spl-token display <MINT>  # shows mint authority, freeze authority

# Verify token extensions (2022 program)
spl-token account-info <TOKEN_ACCOUNT> --umami

# Check for unauthorized mint extensions
grep -r "mint_to\|burn" programs/*/src/lib.rs
```

---

### 4.2 Economic Invariant Violations

#### Solvency Checks

Define the protocol's solvency invariants before testing:

```
Invariant 1: Reserve Ratio = Total Liabilities / Total Assets
  - Healthy threshold: > 1.0 (overcollateralized)
  - Failure mode: undercollateralized minting

Invariant 2: Liquidity Coverage = Liquid Assets / Daily Net Outflows
  - Healthy threshold: > 1.0
  - Failure mode: bank run exceeds liquid reserves

Invariant 3: Price Peg Stability (stablecoins)
  - Healthy threshold: |current_peg - 1.0| < 0.01
  - Failure mode: depeg via arbitrage failure or reserve insolvency
```

**Code audit pattern**:
```rust
// WRONG: no solvency check
pub fn repay(ctx: Context<Repay>, amount: u64) -> Result<()> {
    let reserve = &mut ctx.accounts.reserve;
    // mint tokens to user — no reserve ratio check
    token::mint_to(ctx.accounts.mint, amount)?;
    Ok(())
}

// CORRECT: invariant enforced
pub fn repay(ctx: Context<Repay>, amount: u64) -> Result<()> {
    let reserve = &mut ctx.accounts.reserve;
    require!(
        reserve.total_liabilities() <= reserve.total_assets(),
        ErrorCode::Insolvent
    );
    token::mint_to(ctx.accounts.mint, amount)?;
    Ok(())
}
```

#### Insolvency Vectors

| Vector | Mechanism | Solana Attack Surface |
|--------|-----------|----------------------|
| Undercollateralization | Mint more stablecoins than collateral value | `reserve.liquidation_threshold` not enforced |
| Oracle manipulation | Flash-loan oracle price before liquidation | `switchboard::Consumer::fetch` without staleness check |
| Reserve drain | Admin or CPI extracts reserves to zero | Missing `has_one` on reserve account |
| Interest rate spiral | Negative carry accumulates faster than collateral growth | `accrue_interest()` compounds without bound check |

#### Bank Run Susceptibility

1. **Withdrawal limits**: Are there per-block or per-tx caps on withdrawals? If none, unbounded exit is possible
2. **Liquidity cliff**: What happens if all users withdraw simultaneously? Is `total_liquidity >= sum(user_balances)`?
3. **Withdrawal queue**: Does the protocol use a first-come-first-served queue that creates incentive to flee first?

**Real examples**:

| Protocol | Failure | Root Cause | Lesson |
|----------|---------|-----------|--------|
| Iron Finance (Titan) | Bank run, depeg | No withdrawal limits; fractional reserve; panic feedback loop | Add withdrawal limits; overcollateralize |
| Basis Cash | Depeg spiral | Three-token mechanism collapse when `BAC < $1`; arbitrageurs exit | Bound protocol token supply to real demand |
| Mango Markets | Oracle manipulation exploit ($117M) | Attacker manipulated MNGO oracle via perp position; drained spot markets | TWAP oracles; price deviation circuit breakers; cross-market liquidity checks |

---

### 4.3 MEV Exposure Assessment

#### Solana MEV Landscape

Solana's serialization model differs from Ethereum. MEV exists but manifests differently:

| Ecosystem | MEV Infrastructure | Dominant Form |
|-----------|-------------------|---------------|
| Ethereum | Flashbots, MEV-Boost | Sandwich, arb, liquidations |
| Solana | Jito (bundles), Light Protocol, BonkBot | JIT liquidity provision, sniper bots, wash trading |
| Solana | Orderflow auctions (ofe.xyz) | Priority fee extraction |

#### Sandwich Attack Vectors on DEXes

```rust
// VULNERABLE: front-running via priority fee
pub fn swap<'info>(
    ctx: Context<'info, Swap<'info>>,
    amount_in: u64,
    min_amount_out: u64,
) -> Result<()> {
    // No commit-reveal; bot sees mempool (or priority queue) and sandwiches:
    // 1. Front-run: buy asset -> pushes price up
    // 2. User swap executes at worse price
    // 3. Back-run: sell asset -> capture spread
    ctx.accounts.pool.swap(amount_in, min_amount_out)
}

// MITIGATION: TWAP with commit-reveal
// Commit: user submits hash(swap_params)
// Reveal: next slot, user reveals; swap executes at TWAP price
```

#### Oracle Manipulation for MEV

```rust
// VULNERABLE: spot price from single AMM pool
fn get_price() -> u64 {
    let pool = &ctx.accounts.amm_pool;
    // If attacker controls pool liquidity, price is manipulable
    pool.get_spot_price()
}

// MITIGATION: TWAP oracle
fn get_twap_price(lookback_slots: u64) -> u64 {
    let price_data = &ctx.accounts.price_account;
    // Accumulate price * volume over lookback window
    price_data.twap(lookback_slots)
    // Attacker would need to sustain manipulation across entire window
}
```

#### MEV Mitigation Checklist

| Mitigation | Implementation | Audit Check |
|------------|----------------|-------------|
| Commit-reveal | User commits hash; reveal in next slot | No front-running on commit tx |
| Batch auctions | Aggregate orders; clear at uniform price | No individual-order priority |
| TWAP oracles | Time-weighted average over N slots | `slot_diff >= min_window` |
| Priority fee caps | Max priority fee per tx | No unbounded priority fee extraction |

**Audit command**:
```bash
# Check for priority fee extraction without caps
grep -rn "priority_fee| prioritization_tip" programs/*/src/
# Flag: any `tip` parameter that is user-controlled without ceiling
```

---

### 4.4 Governance Security

#### Token-Weighted Voting Risks

| Risk | Description | Solana Attack Surface |
|------|-------------|----------------------|
| Flash loan governance | Borrow tokens, vote, revoke (Ethereum-era) | Solana has no equivalent flash loans for SPL tokens; not directly exploitable |
| Vote buying | OTC trade of governance tokens | Token transfer without timelock enables this |
| Concentration | Whale can pass any proposal | Check `getTokenHoldings` for top-10 voter concentration |
| Snapshot manipulation | Attacker acquires tokens, votes, sells immediately | Solana finality is ~400ms; check vote is on-chain, not off-chain snapshot |

**Solana-specific**: Unlike Ethereum (where Compound's `proposal` system uses off-chain Quorum snapshots),
Solana governance programs (Realms, Mango, Tensor) execute votes on-chain.
Key audit point: **Is there a timelock between proposal passing and execution?**

#### Timelock Importance

```rust
// VULNERABLE: no timelock on governance execution
pub fn execute_proposal(ctx: Context<Execute>) -> Result<()> {
    // Proposal passed -> execute immediately
    // Attacker can front-run by buying tokens, passing proposal, executing, selling
    ctx.accounts.dao.execute(ctx.accounts.proposal)
}

// CORRECT: timelock enforced
pub fn execute_proposal(ctx: Context<Execute>) -> Result<()> {
    let proposal = &ctx.accounts.proposal;
    let now = Clock::get()?.unix_timestamp;
    require!(
        now >= proposal.activation_time + TIMELOCK_SECS, // 48h standard
        ErrorCode::TimelockNotExpired
    );
    ctx.accounts.dao.execute(ctx.accounts.proposal)
}
```

#### Multisig Configuration Audit

| Parameter | Safe Value | Red Flag |
|-----------|-----------|----------|
| Signers (M-of-N) | 3-of-5 minimum | 1-of-2, 2-of-3 |
| Timelock | >= 24h for routine, >= 48h for treasury | None or < 12h |
| Guardians | Separate from signers | Signers == Guardians |
| Delay | > 0 between propose and execute | Immediate execution |
| Emergency action | Separate 1-of-N for pause only | No emergency multisig |

```bash
# Audit multisig configuration on-chain
# Check via Realms (dao.mesh.fi) or SPL governance program
spl-gov show-governance <REALMS_PROGRAM_ID> <PROPOSAL_KEY>
```

#### Real Governance Exploits

| Protocol | Attack | Mechanism | Fix |
|----------|--------|-----------|-----|
| Beanstalk (Ethereum) | Governance flash loan ($182M) | Attacker used flash loan to pass malicious proposal; drained treasury | Add timelock; quorum must be held > N blocks before execution |
| Compound (Proposal 183) | Governance bug | `Comp` token transfer allowed during active proposal, shifting quorum mid-vote | Lock tokens during voting window |

---

### Economic Security Findings Template

```markdown
### [CRIT/HIGH/MEDIUM/LOW]-ECON-##: [Title]

**Severity**: [CRITICAL/HIGH/MEDIUM/LOW]
**Category**: [Tokenomics / Solvency / MEV / Governance]
**CVSS-Econ**: [1.0–10.0]

#### Description

[Economic invariant violated or economic attack vector present]

#### Impact

[Quantitative estimate: $ value at risk, % of TVL, token supply inflation rate]

#### Affected Invariant

- [ ] Solvency (reserve ratio)
- [ ] Peg stability
- [ ] MEV resistance
- [ ] Governance integrity

#### Proof of Concept

```python
# Economic simulation or concrete scenario
# Example: simulate 30% token inflation per year via emission schedule
```

#### Remediation

[Concrete code or config change]

#### References

- [Past exploit with same pattern]
- [Economic model paper]
```

## 5. Scope

```markdown
## Scope

| Component | Version | Commit/IDL Hash |
|-----------|---------|-----------------|
| vault-program | 1.0.0 | 0xabc123... |
| token-extensions | 2022 | - |
| IDL | - | sha256:def456... |

**Out of Scope**:
- Off-chain programs
- Frontend wallet integration
- Token metadata content (only structural validation)
- Testnet/devenv configurations
```

## 6. Methodology

```markdown
## Methodology

1. **Reconnaissance**: Repository enumeration, IDL extraction, program account analysis
2. **Static Analysis**: Manual code review + automated SAST (grep, anchor check)
3. **Formal Verification**: QED 2A invariant testing, Anchor testgen
4. **Triage**: Severity classification using CVSS 3.1 framework
5. **Report**: Structured findings with PoC confirmation

**Tools Used**:
- anchor-build 0.30.x
- solana-cli 1.18.x
- QED 2A (formal verification)
- [Other tools]
```

## 7. Detailed Findings

For each finding:

```markdown
### [CRIT/HIGH/MEDIUM/LOW/INFO]-##: [Title]

**Severity**: [CRITICAL/HIGH/MEDIUM/LOW/INFO]
**CVSS**: [score]
**CWE**: [CWE-ID]
**File**: [path]:[line]
**Function**: [function_name]

#### Description

[Technical description of the vulnerability.
Include code snippet.]

#### Impact

[Concrete impact on fund security or protocol integrity.
Who is affected and under what conditions.]

#### Proof of Concept

```rust
// [PoC code showing exploit]
// Describe expected vs actual behavior
```

#### Remediation

```rust
// [Fixed code]
```

#### References

- [Link to similar past vulnerability]
- [Anchor documentation]
- [CWE description]
```

## 8. Findings Summary Table

```markdown
## Findings Summary

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| CRIT-01 | Unsigned admin action via invoke | CRITICAL | Open |
| HIGH-01 | CPI privilege escalation in transfer | HIGH | Open |
| MED-01 | Missing owner check on user config | MEDIUM | Open |
| LOW-01 | No close authority on vault | LOW | Open |

**Total**: 4 (1 critical, 1 high, 1 medium, 1 low)

**Status Definitions**:
- **Open**: Finding confirmed, not fixed
- **Fixed**: Fix verified by auditor
- **N/A**: Not applicable (false positive)
```

## 9. Remediation Recommendations

```markdown
## Remediation Recommendations

### Immediate (Before Any Deployment)

1. **[CRIT-01]** Add signer verification to `admin_withdraw`
   ```bash
   # Command to verify fix:
   git diff programs/vault/src/lib.rs
   anchor build && anchor test
   ```

2. **[HIGH-01]** Validate CPI target program ID

### Short-term (Before Production Launch)

3. **[MED-01]** Add `has_one` constraint to `UpdateUserConfig`
4. **[MED-02]** Implement reinitialization guards

### Long-term (Future Upgrades)

5. **[LOW-01]** Add explicit close authority
6. **[INFO-01]** Improve test coverage to 80%+
```

## 10. Appendix

```markdown
## Appendix

### A. File Hashes
- Program binary: `sha256:...`
- IDL: `sha256:...`

### B. Test Commands
```bash
anchor build
anchor test
cargo audit
qed-solana verify --program target/deploy/PROGRAM.so
```

### C. Environment
- Anchor: 0.30.x
- Solana CLI: 1.18.x
- Rust: 1.75+
- Toolchain: stable
```

## Report Generation Commands

```bash
# Export findings to JSON
echo '{"findings": [...]}' > findings.json

# Generate markdown from template
# (Use skill/05-report-generation.md as template)

# Build PDF (optional — requires pandoc)
pandoc report.md -o report.pdf --pdf-engine=weasyprint
```

## Next Phase

After report generation, load `skill/06-remediation.md` for fix verification
and remediation guidance for each finding.