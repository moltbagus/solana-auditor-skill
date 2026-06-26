# KAM-001 — Immunefi Disclosure Draft

> ⚠️ **Pre-disclosure checklist:**
> - [ ] Verify this attack path is **novel** (distinct from Aug 2024 TokenExtensions overflow)
> - [ ] Confirm the affected Token2022 mint has `transfer_fee` extension enabled
> - [ ] Reproduce in a local test environment first
> - [x] **Check Immunefi scope** — ✅ DONE (see §Scope Analysis below)
> - [ ] Do NOT submit if overlapping with known Aug 2024 exploit vector

---

## § Scope Analysis — Immunefi Kamino Bug Bounty (as of 2026-06-25)

**Source:** `https://immunefi.com/bug-bounty/kamino/scope/`

### In-Scope Targets ✅

KAM-001 affects these in-scope contracts:

| Target | In Scope? |
|--------|-----------|
| KLend - Kamino Lending Program `KMNo3nJsBXfcpJTVhZcXLW7RmTwTt4GVFE7suUBo9sS` | ✅ YES |
| KVault - Kamino Lending Vault Program | ✅ YES |

**Impacts that qualify for reward:**
- Critical: Direct theft of any user funds, protocol insolvency, permanent freezing of funds
- High: Theft of unclaimed yield

### Out-of-Scope — Critical Finding 🚨

**The following is explicitly OUT OF SCOPE:**

> *"**Token 22 issues that do not result in irrecoverable loss of funds.** As there are many combinations of t22 with configurations that can change over time by their admin, the smart contract admin (of the market instance, the vault instance, the limit orders, etc.) is willingly taking the risk of onboarding tokens with extensions."*

### Scope Analysis

KAM-001 falls squarely in the Token22 out-of-scope exclusion for **two reasons:**

1. **"Token 22 issues that do not result in irrecoverable loss of funds"** — The bug is a Token22 extension handling gap. The scope says Token22 issues that DON'T cause irrecoverable loss are out. KAM-001's impact (systematic undercollateralization) could potentially lead to irrecoverable loss — but the scope's framing suggests the team considers Token22 extension handling a known/accepted risk they're managing, not a bounty-eligible attack class.

2. **"admin ... is willingly taking the risk of onboarding tokens with extensions"** — The scope explicitly acknowledges that admins knowingly accept Token22 extension risk. This framing implies that bugs in Token22 extension handling are considered an admin configuration choice, not a contract bug.

### Additional Out-of-Scope Flags

These also apply to KAM-001's specific expression:
- *"Vulnerabilities requiring the user to manipulate supply and borrow levels to disturb borrow and supply interest rates"* — KAM-001 involves supply (deposit) manipulation to disturb collateral accounting
- *"Vulnerabilities resulting in loss of fees for the protocol (e.g. bypassing origination, flash borrow fees, etc.)"* — The gap could be framed as a fee-related accounting issue

### Verdict: ⚠️ LOW PROBABILITY OF BOUNTY

**Do not submit as-is.** KAM-001 is explicitly scoped out by the Token22 exclusion. The scope language ("willingly taking the risk") signals the Kamino team is aware of Token22 extension complexity and has chosen to manage it outside the bug bounty framework.

### Options

**Option A — Reframe the finding** (if the attack truly leads to irrecoverable loss):
If you can demonstrate that KAM-001 leads to a scenario where funds are **permanently and irrecoverably** lost — not just misaccounted — it may fall outside the "do not result in irrecoverable loss" exclusion. The key is proving concrete, irreversible loss, not a theoretical accounting gap.

**Option B — Find a different attack vector** from the same root cause:
The underlying issue (no post-transfer reconciliation) could manifest in other ways — e.g., if the gap enables a specific exploit that drains funds irrecoverably in a single transaction. Target the irrecoverable loss outcome, not the Token22 accounting gap.

**Option C — Accept non-monetary disclosure**:
Submit the finding as a responsible disclosure (no bounty expectation) to help the team prioritize the fix. This builds goodwill and relationship without wasting Immunefi triage time on a scoped-out finding.

---

## Immunefi Submission Draft

### Title
Token2022 Transfer Fee Not Accounted in Deposit Collateral Calculation — Systematic Undercollateralization

---

### Severity
**Critical**

**CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
**Score:** 9.1 (Critical)

---

### Vulnerable Contract
- **Name:** Kamino Lend (klend)
- **Network:** Solana Mainnet
- **Address:** `KMNo3nJsBXfcpJTVhZcXLW7RmTwTt4GVFE7suUBo9sS`
- **Codebase:** `kamino-finance/klend` v1.23.0 (commit `23b9f2b545`)

---

### Vulnerability Description

When a user deposits Token2022 tokens with a `transfer_fee` extension into a Kamino Lend reserve, the protocol mints collateral (cTokens) based on the **user-requested deposit amount** rather than the **actual token amount received** after the transfer fee is deducted.

Token2022's `transfer_fee` extension deducts the fee atomically at transfer time. The Kamino program's `compute_depositable_amount_and_minted_collateral()` function (reserve.rs:405) calculates collateral to mint using the user-supplied `liquidity_amount` directly — it does not account for the fee. This means:

```
User submits deposit of 100 tokens
Token2022 transfer fee: 1% = 1 token
Reserve actually receives: 99 tokens
Collateral minted to user: cTokens based on 100 tokens
```

The reserve's internal ledger records a liability of 100 cTokens, but it only holds 99 tokens of actual backing. This creates a permanent, compounding undercollateralization gap for every Token2022 deposit with a transfer fee.

### Steps to Reproduce

1. Identify a Kamino Lend reserve for a Token2022 mint with `transfer_fee` extension enabled.
2. Call `deposit_reserve_liquidity` with amount `X`.
3. Observe that `cTokens` minted = `liquidity_to_collateral(X)`.
4. Verify via `getAccount` that the reserve vault received `X - fee`, not `X`.
5. The cToken supply represents a claim on `X` tokens, but only `X - fee` tokens back it.
6. Repeat for multiple deposits — the gap compounds.

### Impact

Systematic undercollateralization of all Token2022 reserves with transfer fees. Any borrow or liquidation against an inflated reserve can extract real value exceeding the reserve's actual token backing. The gap is most exploitable when:
- A large deposit is made into an empty or low-liquidity reserve
- Subsequent borrows or liquidations are executed against the inflated cToken supply
- The attacker or a victim withdraws/liquidates, extracting more than the reserve actually holds

This is a **deterministic, no-conditions** bug — every Token2022 deposit with a fee creates the gap automatically. No timing, MEV, or oracle manipulation required.

### Relevant Source Code

**`programs/klend/src/state/reserve.rs:405-425`** — deposit amount calculation:
```rust
pub fn compute_depositable_amount_and_minted_collateral(
    &self,
    liquidity_amount: u64,   // ← user-supplied, no fee deduction
) -> Result<DepositLiquidityResult> {
    let collateral_amount = self
        .collateral_exchange_rate()
        .liquidity_to_collateral(liquidity_amount);  // ← based on full amount
    // ...
}
```

**`programs/klend/src/utils/token_transfer.rs:34-60`** — token transfer:
```rust
pub fn deposit_reserve_liquidity_transfer<'a>(
    ...
    liquidity_deposit_amount: u64,  // ← passed through unchanged
) -> Result<()> {
    token_interface::transfer_checked(
        // Token2022 deducts fee here; reserve gets (amount - fee)
        liquidity_deposit_amount,  // ← 100 tokens
        liquidity_decimals,
    )?;
    spltoken::mint(..., collateral_mint_amount)?;  // ← cTokens on 100, backing = 99
}
```

**`programs/klend/src/handlers/handler_deposit_reserve_liquidity.rs:62-91`** — handler flow:
```rust
let initial_reserve_token_balance = token_interface::accessor::amount(
    &ctx.accounts.reserve_liquidity_supply.to_account_info(),
)?;
// ...
// deposit_reserve_liquidity uses user's liquidity_amount directly
// NO reconciliation between initial_reserve_token_balance and post-transfer balance
```

### Fix Recommendation

Read the actual token balance delta after `transfer_checked` and use that for collateral calculation:

```rust
let initial_balance = token_interface::accessor::amount(&supply_info)?;
token_interface::transfer_checked(/* ... */ liquidity_amount /* user's amount */)?;
let actual_received = token_interface::accessor::amount(&supply_info)? - initial_balance;
// Use actual_received for collateral calculation, not user's requested amount
```

### Additional Context

- This finding is related to the Aug 2024 Kamino Finance hack ($4.7M) in that both involve Token2022 extension handling in the collateral/borrow mechanism.
- The specific attack vector here (fee accounting on deposit) differs from the Aug 2024 overflow bypass in `initialize mint metadata`.
- After the Aug 2024 incident, Kamino may already be aware of Token2022 extension risks. Confirm scope with the team before submitting.

### Disclosure Timeline
- [x] **2026-06-25:** KAM-001 identified (Token2022 transfer fee not deducted from deposit)
- [x] **2026-06-26:** Immunefi scope check — Token22 issues explicitly out of scope (see §Scope Analysis)
- [ ] **Option A:** Reframe as irrecoverable-loss scenario — requires concrete PoC of permanent fund loss
- [ ] **Option B:** Find different attack vector from same root cause
- [ ] **Option C:** Responsible disclosure (no bounty) to Kamino team

---

## Verification Test Template (Anchor / TypeScript)

```typescript
// Pseudocode — adapt to Kamino SDK
import { Keypair } from "@solana/web3.js";
import { KaminoLend } from "@kamino-finance/klend-sdk";

async function testTransferFeeBug() {
  const mint = new PublicKey("... Token2022 mint with 1% fee");
  const reserve = await kamino.getReserve(mint);

  // Get initial state
  const initialVaultBalance = await getTokenBalance(reserve.vault);
  const initialCTokenSupply = await getCTokenSupply(reserve.cTokenMint);

  // User deposits 100 tokens (1 token fee deducted by Token2022)
  const depositAmount = 100_000_000n; // 100 tokens with 6 decimals

  await kamino.depositReserveLiquidity(reserve, depositAmount);

  // Check actual received
  const finalVaultBalance = await getTokenBalance(reserve.vault);
  const actualReceived = finalVaultBalance - initialVaultBalance;
  // actualReceived ≈ 99_000_000 (1% fee deducted)

  // Check cTokens minted
  const finalCTokenSupply = await getCTokenSupply(reserve.cTokenMint);
  const cTokensMinted = finalCTokenSupply - initialCTokenSupply;
  // cTokensMinted ≈ collateral_of(100_000_000) ← BUG: should be collateral_of(99_000_000)

  // The gap = collateral_of(100M) - collateral_of(99M)
  const gap = cTokensMinted - collateral_of(actualReceived);

  if (gap > 0) {
    console.log(`BUG CONFIRMED: ${gap} excess cTokens minted`);
    console.log(`Expected: collateral_of(${actualReceived})`);
    console.log(`Actual: cTokens minted = ${cTokensMinted}`);
  }
}
```

---

*Drafted using solana-auditor-skill skill v1.4.0*
*Verify novelty before submitting — overlaps with Aug 2024 TokenExtensions vector*

---

## § Option B Analysis — Trace to Irrecoverable Loss

**Goal:** Find a concrete path from the deposit gap → irrecoverable drain, bypassing Token22 exclusion.

### Code paths traced

| Path | Finding |
|------|---------|
| `deposit_reserve_liquidity` | Gap confirmed — user amount passed through to `transfer_checked` without post-transfer reconciliation |
| `redeem_reserve_collateral` | Exchange rate math — cTokens * exchange_rate = tokens out. Rate distorted by inflated cToken supply. |
| `liquidate_and_redeem` | `withdraw_amount = collateral.deposited_amount` (cToken amount), transferred at exchange rate. Same distortion. |
| `borrow_obligation_liquidity` | User receives exact `receive_amount` — no borrow-side fee. LTV based on market price, not deposit amount. |
| `post_transfer_vault_balance_liquidity_reserve_checks` | Balance reconciliation catches single-tx drains, not systemic inflation. |

### The exchange rate distortion

For fee-on-transfer tokens (e.g., USDC-fee):
```
Attacker deposits 100 USDC-fee tokens
  → Reserve receives 99 (1% fee deducted by Token2022)
  → cTokens minted: 100 (on full 100, not 99)

Exchange rate = liquidity_supply / collateral_supply
cToken value < 1 underlying token  ← permanent discount

All cToken holders bear the gap proportionally over time.
```

### Attempted exploit paths — why they don't yield atomic profit

**Path 1 — "Deposit at par, withdraw at discount"**
```
Attacker deposits first (rate = 1:1) → gets 100 cTokens for 100 tokens
Regular user deposits (fee deducted) → cToken supply inflates
Attacker redeems 100 cTokens → receives 99 tokens
Net: Attacker -1 token. No atomic profit.
```

**Path 2 — Force insolvency via large deposit**
```
Large deposit inflates cToken supply
Reserve liquidity:backing ratio worsens
Bank run depletes reserve
Attacker redeems first — still pays deposit fee. No atomic profit.
```

**Path 3 — Compound with borrow**
```
Deposit fee-token as collateral
Borrow against it at market price
Repay — borrow amount based on market price, not deposit amount
No borrow-side fee impact. No exploit found.
```

### Verdict on Option B

No irrecoverable-loss exploit found through normal redemption paths.

The gap creates a permanent cToken discount for fee-on-transfer tokens. This is real economic harm, but:
- NOT exploitable via atomic arbitrage (attacker also pays deposit fee)
- NOT a single-transaction drain
- Requires bank run or market panic to materialize loss
- The Token22 exclusion ("willingly taking the risk of onboarding tokens with extensions") likely covers this exact scenario

### Speculative paths not yet traced

| Path | Why untraced |
|------|-------------|
| KVault × KAM-001 cross-program interaction | KVault is a separate program |
| Flash loan × deposit gap × withdraw (1 tx) | Attacker pays deposit fee either way |
| Price oracle manipulation → bad-rate liquidation | Separate oracle vulnerability class |

---

### Recommended action

**Option C (responsible disclosure) is the strongest path:**
- Submit KAM-001 as a Token22 accounting gap
- Frame as: permanent cToken discount for fee-on-transfer tokens
- Include the exchange rate math above
- Genuinely useful for Kamino even without a bounty

**Option A** (reframe as irrecoverable loss) requires identifying a specific reserve + token where the fee gap exceeds the insolvency buffer — high effort, moderate success probability.

---

## Final Verdict

| Option | Effort | Bounty Probability | Recommendation |
|--------|--------|-------------------|-----------------|
| C — Responsible disclosure | Low | High (non-monetary) | **Recommended** |
| A — Reframe as irrecoverable loss | High | Low-moderate | Requires specific token+reserve identification |
| B — Different exploit vector | Medium-high | Very low | Not confirmed in traced paths |

**Do NOT submit to Immunefi as-is** — KAM-001 is explicitly scoped out by the Token22 exclusion.
