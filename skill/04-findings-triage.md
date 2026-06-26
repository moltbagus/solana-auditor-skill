# Phase 4: Findings Triage

**Goal**: Classify, deduplicate, and prioritize all findings from recon + SAST + FV.

## Severity Classification

### CRITICAL — Emergency
- **Definition**: Direct path to total fund loss or complete authority bypass
- **Action**: Immediate fix required before any deployment
- **Examples**:
  - `invoke` without `is_signer` on withdrawal
  - Token transfer without owner verification
  - PDA derivation bypass allowing attacker-controlled addresses
  - Missing `has_one` on withdrawal authority
  - Integer overflow enabling unlimited mint

### HIGH — Serious
- **Definition**: Significant loss path OR major protocol logic flaw
- **Action**: Fix before production launch
- **Examples**:
  - CPI privilege escalation (unverified CPI target)
  - Integer overflow in fee calculation (loss < full balance)
  - Missing rent-exempt validation (account deletion possible)
  - Reinitialization without bump check (state corruption)
  - Missing `close` authority check (fund locking)

### MEDIUM — Moderate
- **Definition**: Indirect loss path, moderate impact, or best-practice violation
- **Action**: Fix in next release cycle
- **Examples**:
  - Missing owner check on account data mutation
  - Weak access control (not using `has_one`)
  - Token-2022 extension not validated
  - No `realloc` for variable-size accounts
  - Missing error codes (`.into()` instead of specific errors)

### LOW — Minor
- **Definition**: Minor issue, no direct loss path, best practice
- **Action**: Fix when convenient
- **Examples**:
  - Missing `close` authority on token accounts
  - Unused `#[account]` fields
  - Hardcoded constants instead of config
  - Missing `deprecated` attribute on old instructions
  - Logging sensitive data (though Solana logs are visible to validators anyway)

### INFO — Informational
- **Definition**: Documentation, code quality, architectural notes
- **Action**: Not a security issue
- **Examples**:
  - Missing Rust docs
  - Complex function that could be simplified
  - No test coverage on edge cases
  - Code duplication

## CVSS 3.1 Derivation Guide

### Metric Definitions for Solana Programs

Use this guide to derive CVSS vectors for any Solana vulnerability.

| Metric | Option | Meaning in Solana Context |
|--------|--------|---------------------------|
| **AV** (Attack Vector) | N=Network | Exploitable over RPC/API without local access |
| | L=Local | Requires direct node access or validator participation |
| | A=Adjacent | Requires being on the same validator or RPC endpoint |
| **AC** (Attack Complexity) | L=Low | No special conditions; exploit works reliably |
| | H=High | Requires timing, specific state, or rare conditions |
| **PR** (Privileges Required) | N=None | No account required; anyone can trigger |
| | L=Low | Requires any valid signer (e.g., user wallet) |
| | H=High | Requires privileged account (admin, upgrade authority) |
| **UI** (User Interaction) | N=None | No user action needed |
| | R=Required | Requires victim to sign a specific transaction |
| **S** (Scope) | U=Unchanged | Vulnerability affects only the program |
| | C=Changed | Vulnerability spills beyond program scope |
| **C** (Confidentiality) | N=None | No data exposure |
| | L=Low | Minor data leak (e.g., account state revealed) |
| | H=High | Full data exposure (e.g., key material, full state) |
| **I** (Integrity) | N=None | No data modification |
| | L=Low | Minor modification possible |
| | H=High | Full authority to modify program state |
| **A** (Availability) | N=None | No availability impact |
| | L=Low | Temporary disruption (e.g., temporary denial) |
| | H=High | Permanent loss of funds or complete DOS |

### Solana-Specific Scoring Rules

- **AV=N**: Default for all on-chain vulnerabilities accessible via RPC
- **AC=L**: Exploits requiring only standard transaction construction
- **AC=H**: Use when exploit requires MEV, specific slot timing, or validator co-location
- **PR=L**: Use when exploit requires a valid signer (e.g., anyone can drain if they get a user to sign)
- **PR=H**: Use when exploit requires admin/upgrade authority specifically
- **S=C**: Use only when anchor program can pivot to modify other programs via CPI

### Worked Example: Unsigned Admin Action

**Scenario**: An admin instruction lacks `is_signer` check. Anyone who can craft a transaction referencing the admin key can invoke the instruction.

**Vector Derivation**:
| Metric | Selection | Rationale |
|--------|-----------|-----------|
| AV | N | Exploitable via standard RPC (no local/adjacent access needed) |
| AC | L | No special timing or conditions required |
| PR | N | No privileges needed — anyone can construct the transaction |
| UI | N | No user interaction required |
| S | U | Scope limited to this program only |
| C | H | Admin keys or vault contents fully readable |
| I | H | Full authority to modify program state and drain funds |
| A | H | Complete loss of availability for affected funds |

**Result**: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **Base Score 10.0 (CRITICAL)**

---

### Worked Example: CPI Privilege Escalation

**Scenario**: Program performs CPI to an external token program without verifying the target.

| Metric | Selection | Rationale |
|--------|-----------|-----------|
| AV | N | Exploitable via RPC |
| AC | L | Standard transaction construction |
| PR | L | Requires a valid signer (the original caller) |
| UI | N | No victim interaction needed |
| S | U | Limited to programs reachable via CPI |
| C | H | Token accounts fully readable |
| I | H | Can redirect token transfers |
| A | H | Can drain token balances |

**Result**: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = **Base Score 8.2 (HIGH)**

---

### Worked Example: Missing Owner Check

**Scenario**: Program modifies account data without verifying the owner field matches expected program.

| Metric | Selection | Rationale |
|--------|-----------|-----------|
| AV | N | Exploitable via RPC |
| AC | L | Standard transaction construction |
| PR | L | Requires a valid signer (account owner) |
| UI | N | No victim interaction needed |
| S | U | Limited to this program |
| C | N | No confidentiality impact |
| I | H | Can corrupt arbitrary account data |
| A | N | No availability impact |

**Result**: `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = **Base Score 6.5 (MEDIUM)**

---

## CVSS Scoring (Optional)

For formal CVSS 3.1 scoring:

| Finding | CVSS Vector | Score |
|---------|-------------|-------|
| Unsigned admin action | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 10.0 |
| CPI privilege escalation | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.2 |
| Missing owner check | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N | 6.5 |
| Missing signer check | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 |
| Integer overflow | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 |

## False Positive Recognition

Not every flagged code pattern is a real vulnerability. Recognize these common false positives:

### 1. Anchor's `#[account]` Macro Validation

**False Positive**: Flagging missing owner check when Anchor's `#[account]` macro validates owner automatically.

```rust
#[account]
pub struct UserData {
    pub value: u64,
}
// Anchor validates owner automatically for #[account] types
```

**Recognition**: If the account type is defined with `#[account]` and used via `Ctx`, the owner is validated implicitly. Only flag if the account is deserialized via raw `&mut T` without the macro.

### 2. Benign Missing `is_signer` Check

**False Positive**: Flagging missing signer check on instructions intended to be callable by any program via CPI.

```rust
#[program]
pub fn settle_position(ctx: Context<SettlePosition>) -> Result<()> {
    // Called via CPI from another program — signer check on caller is
    // handled by the calling program's validation
}
```

**Recognition**: If the instruction's purpose is to be callable via CPI, and the caller is already validated, the missing `is_signer` on this instruction may be intentional. Check if the instruction is documented as "CPI-only" or called exclusively from other program instructions.

### 3. Integer Overflow in Unreachable Code

**False Positive**: Flagging potential integer overflow in code paths that are provably unreachable due to upstream validation.

```rust
fn process_withdrawal(amount: u64, balance: u64) -> u64 {
    // balance comes from account data that was already validated
    // to be >= minimum deposit in a prior instruction
    amount + balance  // flagged as overflow, but balance >= MIN_DEPOSIT
}
```

**Recognition**: If the calculation occurs after `require!` or `assert!` that guarantees the operands are bounded, the overflow is unreachable. Flag only if the overflow can occur under valid inputs.

## Deduplication

### Duplicate Finding Types
1. **Same root cause** — Multiple findings from one code pattern -> report as one
2. **Cascading findings** — Finding A enables Finding B -> separate but linked
3. **Cross-instruction** — Same bug in multiple instructions -> one finding, list all instances

### Finding Linkage
```
[CRIT-01] Unsigned withdrawal via invoke
  -> enables [HIGH-02] DPA derivation bypass
  -> enables [CRIT-03] Complete vault drain
```

## Findings Database Format

```json
{
  "findings": [
    {
      "id": "CRIT-01",
      "title": "Unsigned admin action via invoke",
      "severity": "CRITICAL",
      "file": "programs/vault/src/lib.rs",
      "line": 142,
      "cwe": "CWE-306",
      "description": "The `admin_withdraw` instruction calls `invoke` without verifying `ctx.accounts.admin.is_signer`. Any transaction signed by the admin account can be routed through this program to transfer funds.",
      "impact": "Complete drain of program vault if admin key is compromised or used in a phishing transaction.",
      "recommendation": "Add `require!(ctx.accounts.admin.is_signer)` at the start of `admin_withdraw`.",
      "poc_status": "pending",
      "cvss": "9.1"
    }
  ],
  "summary": {
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 2,
    "info": 1
  }
}
```

## Triaging Checklist

- [ ] Each finding has severity assigned
- [ ] Each finding has a concrete code location
- [ ] Each finding has impact description
- [ ] Each finding has a remediation recommendation
- [ ] No duplicate findings
- [ ] Linked findings are documented
- [ ] CVSS scored for CRIT/HIGH
- [ ] PoC status tracked (pending/confirmed/fixed)

## Next Phase
After triage -> load `skill/05-report-generation.md` for the final deliverable.
