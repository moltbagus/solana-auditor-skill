# PoC: VULN-13 — Flash Loan Attack (Mango Markets Style)

## Overview
Attacker manipulates asset prices within a single transaction using flash-loaned capital, then uses inflated collateral to drain the protocol.

## Exploit Path

1. Attacker takes flash loan of 10M USDC from Raydium/Solw
2. Attacker uses flash-loaned USDC to heavily buy target asset (e.g., Mango MNGO)
3. Price of target asset spikes 10x within the same transaction
4. Attacker's collateral value is now artificially inflated
5. Attacker borrows maximum against inflated collateral in other assets
6. Attacker repays flash loan in same transaction
7. Attacker wallet now holds stolen borrowed assets
8. Protocol loses real liquidity while attacker profits

## Impact
- Protocol insolvency via artificial collateral inflation
- Loss of all borrowed assets
- CVSS: 9.8 (CRITICAL)

## Real-World Precedent
- Mango Markets exploit (October 2022): $117M drained using this exact pattern

## Code Reference
`programs/mango/src/instructions/flash_loan.rs`

## Remediation
1. Implement price oracle with staleness check
2. Add delay between price updates and collateral valuation
3. Limit flash loan size relative to total pool liquidity
4. Require flash loan fees that exceed manipulation profit margin
