---
name: "01C-economic-security"
description: "Phase 1C: Economic security review for Solana programs — tokenomics integrity, MEV exposure, staking/LP economics, governance attack vectors, and invariant enforcement"
triggers:
  - "User requests economic security review for a token or DeFi program"
  - "After Phase 1B architecture review (program authority and token config available)"
  - "After Phase 1 recon (token supply, LP pools, staking accounts available)"
  - "Economic flag passed: /audit --economic"
  - "Pre-deployment assessment for new token or DeFi program design"
examples:
  - "check the economic security of this token"
  - "review MEV exposure on this DEX program"
  - "/audit examples/sample-vulnerable-program --economic"
---

# Phase 1C: Economic Security Review

**Goal**: Assess the economic security posture of a Solana program by examining tokenomics, MEV exposure, staking/LP economics, governance mechanisms, and on-chain invariant enforcement — before reading a line of Rust.

**Prerequisites**: Phase 1 recon artifacts (`program_metadata.json`, `attack_surface.json`, `token_supply.json`) and Phase 1B architecture review output (`audit-report/architecture/{program}_architecture.json`).

**Execution order**: Run after Phase 1B architecture review. Economic findings feed Phase 4 triage as systemic / design-level issues that require economic re-engineering, not refactor.

## Overview

Economic security auditing goes beyond code vulnerabilities to examine whether the protocol's incentive structures, token mechanics, and fee flows are sustainable and resistant to economic exploitation. On Solana, where program composability is deep and MEV is evolving rapidly, economic attacks frequently cause more loss than code exploits.

---

## 1. Tokenomics Analysis

### Supply Mechanics

**Fixed supply** tokens (STARS, BONK) lock mints at initialization — audit `TokenMetadata` with `mint_supply: 0` and verify no additional mint authority exists. **Inflationary supply** tokens (RAY, ORCA) have configurable supply schedules — trace the inflation scheduler program and check whether governance can modify mint rates. **Capped supply** tokens are the safest variant: verify the cap in the mint configuration and ensure no inflation instruction exists in the token program.

**Real examples:**

- **STARS (Star Atlas)** — Fixed supply of 36B tokens with a 6-year vesting cliff. The token distribution to the DAO treasury (40%) created a long-term sell pressure vector that was not disclosed in early tokenomics documentation. Audit check: verify locked allocations are in a program-controlled escrow account, not aEOA.
- **Jito (JTO)** — 10% airdrop to Jito-Sol validators created a natural stakeholder alignment. The governance token launch had a controlled emission schedule with no inflation mechanism. Audit check: confirm inflation disable instruction was called post-distribution.
- **BONK** — 100T initial supply with 50% airdrop to Solana ecosystem participants. The memecoin model means price discovery is entirely speculative, but the burn mechanism (burning tokens from the treasury via program CPI) was audited for double-burn vulnerabilities.

### Red Flags

| Pattern | Severity | Why |
|---------|----------|-----|
| Mint authority not renounced | CRITICAL | Unlimited supply inflation possible |
| Team allocation in EOA instead of vesting contract | HIGH | 100% dump risk at TGE |
| Inflation schedule controlled by single signer | HIGH | Can change emission at will |
| No max supply cap defined | MEDIUM | Inflation can dilute all holders |
| Vesting contract callable by team EOA | HIGH | Backdoor to early unlock |

**Audit procedure:** Read the mint configuration via `getMint()` RPC call. Check `mintAuthority: null` and `freezeAuthority: null` for fully renounced tokens. For vesting contracts, verify the unlock schedule against block timestamps and confirm the contract is a PDA, not an EOA.

---

## 2. Fee Flow Mapping

### Protocol Fee Capture

Solana programs can capture fees at multiple points: swap fees (Raydium, Orca), stake deposits (Marinade, Lido), and performance fees (Jito). Audit the fee vault account — it should be a PDA controlled by the program's authority, not a hardcoded EOA. The fee percentage should be stored in a config account that governance controls, not baked into the instruction logic as an immutable constant (which prevents adaptation to market conditions).

**Real examples:**

- **Raydium** — Swap fees go to the liquidity pool vault (a Serum or Raydium-controlled AMM vault). The protocol fee (0.25% of the 0.25% LP fee) is configurable. Audit check: verify fee recipient is a program vault, not a team wallet. The 2022 Raydium exploit used a fake pool with a modified fee recipient.
- **Marinade Finance** — Staking fees (3% of rewards) flow to the Marinade DAO treasury via a CPI call. The treasury is a multisig (4/7) controlled by mDAO token holders. Audit check: verify the treasury is a real multisig (check `getProgramAccounts` for the multisig program ID), not a假装 multisig with a single key.
- **Jupiter (JUP)** — Token launch fees and swap fees flow to a governance-controlled treasury. The fee basis points are stored in a program account that requires a governance proposal to modify. Audit check: trace `transfer` CPIs from swap instructions to identify fee destinations.

### Red Flags

| Pattern | Severity | Why |
|---------|----------|-----|
| Fees flow to hardcoded EOA | CRITICAL | Team can rug fee revenue |
| Fee percentage not in config account | HIGH | Cannot adjust without program upgrade |
| Fee vault has no authority check | HIGH | Anyone can drain fees |
| Fee split not disclosed in docs | MEDIUM | Regulatory/TVL misalignment |

**Audit procedure:** Parse all `transfer` and `transferChecked` CPIs in the program's instruction handlers. Build a fee flow graph. Verify each fee recipient is either a program vault, a governance-controlled multisig, or a disclosed team address (with appropriate vesting).

---

## 3. Economic Invariant Violations

### Solvency Vectors

The most dangerous class of economic bugs: the protocol believes it is solvent when it is not. On Solana, this manifests as:

1. **Undercollateralization** — LTV ratio checked off-chain but enforced on-chain with stale or manipulated oracle prices. Check all health ratio calculations use blockhash-valid oracles.
2. **Double-counting reserves** — Same lamports counted as both user deposits and protocol equity. Trace reserve increments in deposit/withdraw handlers.
3. **Interest rate model runaway** — Borrow rate function can approach infinity at high utilization, instantly making all positions unhealthy. Verify interest rate model has bounded slopes.

**Real examples:**

- **Mango Markets oracle manipulation (2022, $117M loss)** — Attackers used three large options positions to spike the MNGO oracle price by 10x via wash trading. The inflated collateral allowed borrowing against non-existent value. Audit check: verify oracle staleness checks use `Clock::slot` not `Blockhash::epoch`, and check price deviation against a TWAP. Mango's error was accepting a single slot's price without a deviation gate.
- **Iron Finance (Polygon, 2021)** — Classic bank run triggered by a depeg event in the correlated stablecoin pool. While not Solana, Iron Finance's failure mode (non-linear redeem mechanics) has been replicated on Solana in DeFi protocols with similar correlated-stablecoin LP designs. Audit check: verify redemption formula is linear and bounded.
- **Solend liquidation spiral (2022)** — A large SOL borrower ($26M) caused Solend to pause the protocol via governance to prevent cascading liquidations. The root cause was an insufficient liquidation threshold and lack of circuit breakers for whale positions. Audit check: model worst-case liquidation scenarios at 110%+ utilization.

### Anchor-specific Invariant Checks

```rust
// WRONG: No solvency check on withdraw
fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.lamports -= amount; // Can go negative
    Ok(())
}

// CORRECT: Solvency check before mutation
fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    require!(vault.lamports >= amount, ErrorCode::InsufficientLiquidity);
    vault.lamports -= amount;
    Ok(())
}
```

### Red Flags

| Pattern | Severity | Why |
|---------|----------|-----|
| No reserve balance check before withdraw | CRITICAL | Insolvency exploit |
| Oracle price without staleness check | CRITICAL | Stale price = wrong collateral value |
| Interest rate model without upper bound | HIGH | Instant insolvency at high utilization |
| Health ratio computed with integer math | HIGH | Rounding can flip health status |
| No circuit breaker for whale positions | MEDIUM | Cascading liquidations |

---

## 4. MEV Exposure

### Solana MEV Landscape

Unlike Ethereum's PBS (Proposer-Builder Separation), Solana MEV is dominated by **Jito Labs**' block engine and relay network. Jito captures ~40% of Solana MEV and offers auction-based block space ordering. Other players: **BonkBot** (sandwich attacks on DEX swaps), **Light Protocol** (zkSNARK-based private transactions).

**Key MEV vectors on Solana:**

1. **Sandwich attacks** — Less common than Ethereum due to Solana's atomic transaction model, but possible on Jupiter and Raydium when transactions hit the same block. The attacker front-runs with a swap, then back-runs with the opposing trade.
2. **Oracle manipulation for MEV** — Price oracles that read within-slot prices can be manipulated by sandwiching oracle reads between two transactions that move the price. This enables liquidation captures and borrow mechanics exploitation.
3. **Arbitrage arbitrage** — Competing arbitrageurs can create a feedback loop where each arbitrage triggers the next, causing extreme price impact in illiquid pools.
4. **Quote stuffing** — Flooding the network with failed transactions to delay victim transactions and capture favorable block position (primarily relevant for time-sensitive liquidations).

**Real examples:**

- **Jupiter DEX aggregator** — Routes transactions through Jito tip accounts by default. Users pay an additional 0.0005 SOL/JUP tip. Audit check: verify tip amounts are disclosed and the Jito relay connection does not leak user transaction data to validators.
- **Raydium LP exploitation** — MEV bots exploited LP token price discrepancies during high-volatility periods by being first to call `withdraw` after a price move. The fix was adding a cooldown period between price updates and withdraw eligibility.
- **BonkBot wash trading** — Automated trading bots on BonkBot created artificial volume by trading against themselves, inflating the token's 24h volume metric. This is not a protocol vulnerability but a market manipulation vector that affects token economics.

### Mitigations

| Mitigation | Mechanism | Audit Check |
|------------|-----------|-------------|
| TWAP oracles | Smooths within-slot price spikes | Verify TWAP window >= 10 slots |
| Cooldown periods | Prevents immediate arbitrage after price move | Check for `last_update` comparison |
| Slippage limits | Bounded price impact | Verify slippage passed as parameter, not hardcoded |
| Priority fee caps | Prevents fee-based front-running | Check max priority fee in config |

**Audit procedure:** Trace all price reads in liquidation and borrow instructions. Identify whether the oracle reads within-slot prices. If yes, flag as MEV-manipulable. Check if the protocol uses a TWAP with sufficient window. Examine whether priority fees are configurable or hardcoded.

---

## 5. Governance Security

### Token-Weighted Voting Risks

Solana governance programs (Realms, SplGovernance) use token-weighted voting, which creates plutocratic capture risk. The threshold for passing proposals should require both a minimum quorum AND a minimum token participation, not just a percentage of votes cast.

**Real examples:**

- **Beanstalk (Ethereum, 2022, $182M exploit)** — The governance proposal mechanism allowed flash-loan attacks to pass a malicious proposal that drained the treasury. The attack used a flash loan of 27M BEAN to pass a proposal in a single block. While not Solana, the failure mode (no timelock + flash-loanable governance tokens) has been reproduced on Solana governance protocols. Audit check: verify governance token transfers are blocked during proposal voting windows.
- **Compound GovernorBravo (2022, $80M bug)** — A precision error in the Comp distribution calculation allowed an attacker to claim excess COMP rewards. The bug was in the price oracle math, not the governance mechanism itself, but the governance-controlled timelock was the only way to pause the protocol. Audit check: verify that critical parameter changes require timelock execution.

### Timelock Importance

Any protocol parameter change that affects user funds (LTV ratios, fee percentages, collateral types) must go through a timelock. The timelock delay should be proportional to the financial impact: 24 hours for fee changes, 48 hours for collateral parameter changes, 72+ hours for new collateral type additions.

**Multisig audit points:**

| Check | Severity | Method |
|-------|----------|--------|
| Multisig threshold >= 3/5 | HIGH | `getMultisig` RPC call |
| All signers are distinct hardware wallets | MEDIUM | Check signer addresses |
| Timelock delay >= 24h for fund-affecting changes | HIGH | Read timelock config account |
| Emergency pause callable by >= 2 signers | MEDIUM | Verify pause authority |
| Upgrade authority uses timelock, not single key | CRITICAL | Check upgrade authority PDA derivation |

**Audit procedure:** Read the governance config account. Verify timelock delay is enforced via `Clock::slot` comparison in the instruction handler. Check that upgrade authority derives from a timelock-controlled PDA, not a single key. For multisig: call `get_multisig` RPC to retrieve threshold and signer list.

---

## 6. Liquidity Analysis

### Bootstrapping Vulnerabilities

New protocols on Solana typically bootstrap liquidity via:
1. **Token launch auctions** (via Pump.fun, Raydium Launchpad) — verify the bonding curve has a max supply cap and a clear migration path to a permanent AMM pool.
2. **Incentivized liquidity programs** — verify reward distribution uses on-chain gauges, not off-chain allocation tables that can be changed unilaterally.
3. **Liquidity lockup** — check that LP tokens are locked in a time-locked vault controlled by the protocol, not by the team EOA.

**Rug vectors:**

| Pattern | Severity | Mechanism |
|---------|----------|-----------|
| Team drains LP via hidden admin function | CRITICAL | LP withdrawal only requires team signature |
| Mint authority not renounced after launch | CRITICAL | Infinite token mint via inflation |
| Liquidity migrates to team-controlled pool | HIGH | Migration function callable by owner |
| Reward token has no supply cap | HIGH | Inflation dilutes LP rewards |
| Locked liquidity has emergency unlock | MEDIUM | Owner can unlock early via backdoor |

**Real examples:**

- **Solend (2022)** — Initial liquidity was bootstrapped with a whale ($26M SOL position) as the primary borrower. This created systemic risk where the whale's liquidation would destabilize the entire protocol. The protocol was later forced to emergency-pause via governance. Audit check: model concentration risk — no single position should exceed 20% of total deposits.
- **Crema Finance exploit (2022, $28M)** — The protocol used a novel concentrated liquidity approach with a hidden admin fee mechanism. The exploit used a flash loan to manipulate the fee calculation and drain the pool. Audit check: verify all fee calculations are deterministic and do not depend on unverified external state.
- **Tulip Protocol** — Leveraged yield strategies on Solana. The protocol was exploited via a reentrancy bug in the deposited token handling. The economic root cause was a mismatch between deposited asset accounting and strategy execution timing. Audit check: verify all asset movements are balanced in a single transaction.

### Liquidity Health Metrics

| Metric | Formula | Safe Range |
|--------|---------|------------|
| Utilization | Borrows / Deposits | 60-80% |
| Concentration | Largest position / Total deposits | < 20% |
| Liquidation threshold | Oracle price at liquidation | > Oracle deviation threshold |
| LP lock duration | Time until LP unlock | > 90 days for team LP |
| Volume/TVL ratio | 24h volume / Total value locked | < 5x (suspicious if higher) |

**Audit procedure:** Pull historical utilization data from the protocol's state accounts. Identify utilization spikes above 85% — these are leading indicators of insolvency risk. Check LP token lock status via `getAccountInfo` on the lock vault. Calculate volume/TVL ratio over 30 days to detect wash trading.

---

## Cross-Category Attack Chains

Economic exploits often chain multiple vulnerabilities. Common Solana attack chains:

1. **Oracle manipulation + Liquidation capture** — Manipulate oracle within slot, trigger liquidations at favorable prices, capture collateral spread. Requires: manipulable oracle + liquidation mechanism.
2. **Inflation + Governance attack** — Mint new tokens via hidden mint authority, acquire majority governance tokens, pass malicious proposal to drain treasury. Requires: unrenounced mint authority + governance control.
3. **MEV + Fee drain** — Use block position to sandwich victim transactions, extract favorable execution, drain protocol fees via misconfigured fee recipient. Requires: MEV-accessible routing + hardcoded fee recipient.
4. **Liquidity concentration + Insolvency spiral** — Whale position triggers cascading liquidations, LP providers flee creating liquidity crunch, remaining positions become undercollateralized. Requires: whale position + no circuit breaker.

---

## Audit Checklist

### Tokenomics
- [ ] Mint authority renounced or controlled by governance timelock
- [ ] Max supply cap enforced in program logic
- [ ] Team allocation in vesting contract (not EOA) with disclosed schedule
- [ ] Inflation schedule audited for unbounded growth

### Fee Flows
- [ ] All fee recipients are program vaults or governance-controlled accounts
- [ ] Fee percentages stored in config accounts (not hardcoded)
- [ ] Fee flow traceable via CPI graph analysis

### Invariants
- [ ] Reserve balance checked before all withdrawal instructions
- [ ] Oracle staleness checked with slot or timestamp comparison
- [ ] Interest rate model has bounded maximum borrow rate
- [ ] Health ratio calculation uses integer-safe arithmetic
- [ ] Circuit breakers exist for whale positions (>20% of TVL)

### MEV
- [ ] Price oracles use TWAP with >= 10-slot window
- [ ] Cooldown periods exist between price update and fund movement
- [ ] Slippage limits configurable by user, not hardcoded
- [ ] Priority fees disclosed and not exploitable for front-running

### Governance
- [ ] Governance token transfers blocked during voting window
- [ ] Timelock delay >= 24h for fund-affecting changes
- [ ] Multisig threshold >= 3/5 with distinct hardware signers
- [ ] Upgrade authority derives from timelock PDA, not single key
- [ ] Emergency pause requires >= 2 signers

### Liquidity
- [ ] LP tokens locked in time-locked vault
- [ ] No concentration risk (>20% single position)
- [ ] Volume/TVL ratio analyzed over 30 days
- [ ] All admin functions that can drain liquidity require timelock
- [ ] Liquidation thresholds exceed oracle deviation thresholds

---

## Output Artifacts

| Artifact | Path | Contents |
|----------|------|----------|
| Per-program economic review | `audit-report/economic/{program}_economic.json` | Full tokenomics, MEV, staking, LP, governance, and invariant assessment |
| Economic rating | `audit-report/economic/ratings.json` | Program-level economic security ratings |
| Design findings | `audit-report/findings.json` (design section) | Economic findings that feed Phase 4 triage |
| Tokenomics report | `audit-report/economic/tokenomics.md` | Textual tokenomics analysis |

### Output Schema

```json
{
  "program": "native-vault",
  "version": "1.0.0",
  "analyst": "economic-security-analyst",
  "generated_at": "ISO-8601",
  "program_id": "NatiV8XCvFhMtNTSg9qV9u1KKrn3DLzNaX7cSC8K8H2",
  "classification": {
    "tokenomics_integrity": "low",
    "mev_exposure": "low",
    "staking_economics": "not_applicable",
    "lp_token_economics": "not_applicable",
    "governance_security": "not_applicable",
    "invariant_enforcement": "pending_phase2"
  },
  "findings": [
    {
      "id": "ECON-TOKEN-001",
      "severity": "INFO",
      "title": "Program manages native SOL only — no SPL tokenomics to assess",
      "category": "tokenomics",
      "description": "native-vault manages native SOL lamports, not SPL tokens. No mint/freeze/close authority risk.",
      "code_fixes": false,
      "design_fixes": false
    }
  ],
  "overall_economic_rating": "LOW",
  "overall_economic_rationale": "Native SOL-only program with no tokenomics, MEV-sensitive operations, staking, LP tokens, or governance. Economic attack surface is minimal. Primary risk is code-level (Phase 2 findings).",
  "phase2_prime": true
}
```

### Economic Security Rating Scale

| Rating | Criteria |
|--------|----------|
| **CRITICAL** | LP tokens non-redeemable, or no solvency check, or mint authority active with high-value token |
| **HIGH** | MEV extraction possible, or governance flash loan attack possible, or collateralization not enforced |
| **MEDIUM** | Transfer fee not accounted, or staking reward overflow possible, or LP reserve drain via invariant violation |
| **LOW** | All token authorities renounced, MEV protection in place, economic invariants enforced on-chain |

---

## Integration with Phase 1B (Architecture Review)

Architecture review (Phase 1B) feeds economic review (Phase 1C) with:

```
Phase 1B: Architecture Review
  - Outputs: mint authority status, freeze authority, token extensions, upgrade path
  - Feeds Phase 1C: tokenomics integrity assessment uses architecture findings
    (e.g., mint authority not renounced → ECON-TOKEN-001)
    (e.g., transfer_fee extension active → ECON-TOKEN-002)

Phase 1C: Economic Security Review
  - Inputs from Phase 1B: token authority findings, extension findings
  - Inputs from Phase 1: token supply, LP pools, staking accounts
  - Outputs: economic findings (tokenomics, MEV, staking, LP, governance, invariants)
  - Feeds: Phase 4 triage (design + code findings merged)
```

**Cross-reference table**:

| Phase 1B Finding | Phase 1C Economic Finding |
|------------------|--------------------------|
| ARCH-TOKEN-001 (mint authority active) | ECON-TOKEN-001 (inflation risk) |
| ARCH-TOKEN-002 (freeze authority active) | ECON-GOV-001 (vote weight manipulation) |
| ARCH-EXT-002 (transfer_fee not accounted) | ECON-TOKEN-002 (fee drain) |
| ARCH-EXT-001 (extension not verified) | ECON-TOKEN-003 (confidential fee drain) |

---

## Integration with Phase 2 Static Analysis

Economic findings and code-level findings are complementary:

| Aspect | Economic Review (Phase 1C) | Static Analysis (Phase 2) |
|--------|---------------------------|---------------------------|
| Scope | Tokenomics, MEV, staking, LP, governance, invariants | Source code, instruction logic, CPI paths |
| Finding type | Economic design-level (may require re-design) | Code-level (can fix in code) |
| Fixability | `design_fixes: true` for structural; `code_fixes: true` for calculation errors | `code_fixes: true` |
| Overlap | Economic misdesign may enable code exploits | Code exploits may be economically motivated |
| Triage | Economic findings treated same as code findings | CVSS scoring applies to both |

**Coverage gap detection**: If Phase 2 finds an overflow/underflow in reward calculation (Rule 6), flag a corresponding economic finding (ECON-STAK-001).

---

## Reference Implementation — sample-vulnerable-program

### native-vault Program Economic Assessment

```
Program ID:   NatiV8XCvFhMtNTSg9qV9u1KKrn3DLzNaX7cSC8K8H2
Token:        Native SOL (no SPL token)
MEV:          LOW — no DEX or trading functionality
Staking:      N/A — no staking program
LP:           N/A — no LP tokens
Governance:   N/A — no governance token
Invariants:   Check Phase 2 static analysis
```

**Economic Security Assessment Walkthrough**:

1. **Tokenomics**: Native SOL only. No mint/freeze/close authority to assess. No inflation risk from token minting.

2. **MEV Exposure**: No trading or swap functionality. MEV exposure is minimal — limited to denial-of-service on deposit/withdrawal.

3. **Staking**: N/A. Program does not implement staking.

4. **LP**: N/A. Program does not issue LP tokens.

5. **Governance**: N/A. No governance token.

6. **Invariants**: Phase 1B found the program is non-upgradeable (ARCH-UPG-IMM-001). Phase 2 will assess code-level invariant enforcement (no-negative-balance, solvency).

**Economic Security Rating**: LOW

Note: While the economic security rating is LOW, Phase 2 static analysis found HIGH/CRITICAL code-level vulnerabilities (signer verification, sysvar handling). These are Phase 2 findings, not economic findings.

---

## Next Phase

After economic security review → load `skill/01B-architecture-review.md` output and `skill/02-static-analysis.md` (Phase 2) with economic findings as priming context.

---

## Quick Reference — Economic Security Checklist

- [ ] Mint authority renounced (for supply-capped tokens)
- [ ] Freeze authority renounced or scoped to governance
- [ ] Token-2022 extensions detected and verified by program
- [ ] MEV exposure assessed (Jito, Light, sandwich attacks)
- [ ] Staking reward calculations use checked arithmetic (u128 intermediate)
- [ ] LP tokens redeemable at proportional reserve value
- [ ] LP mint authority renounced or controlled by program
- [ ] Governance token mint authority renounced or timelocked
- [ ] Governance votes gated by token lock (no flash loan voting)
- [ ] Solvency check before withdrawals
- [ ] Collateralization ratio enforced on borrow
- [ ] No-negative-balance checked on all balance operations
- [ ] Economic rating assigned (CRITICAL / HIGH / MEDIUM / LOW)
- [ ] Economic findings separated from code findings
- [ ] Findings tagged with `code_fixes` vs `design_fixes` flag