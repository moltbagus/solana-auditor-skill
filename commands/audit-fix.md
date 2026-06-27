---
name: audit-fix
description: Generate inline security fix suggestions for HIGH/CRITICAL findings
---

# /audit-fix — Remediation Workflow Command

Get fix suggestions, apply fixes, and verify remediation for security findings.

## Usage

```
/audit-fix <finding-id>              # Get fix suggestion for a finding
/audit-fix --apply <finding-id>      # Apply Tier A fix automatically
/audit-fix --verify <finding-id>     # Verify a fix resolves the vulnerability
/audit-fix --report                  # Generate remediation status report
/audit-fix --list                    # List all findings with fix tiers
```

## Arguments

| Argument | Description |
|----------|-------------|
| `<finding-id>` | Finding ID (e.g., `CRIT-01`, `HIGH-03`) |

## Flags

| Flag | Description |
|------|-------------|
| `--apply` | Apply Tier A fix automatically (with consent notification) |
| `--verify` | Verify fix resolves the vulnerability |
| `--report` | Generate full remediation status report |
| `--list` | List all findings with their fix tiers |
| `--cvss` | Show CVSS before/after comparison |
| `--tier <A\|B\|C>` | Filter by fix tier |

## Examples

### Get fix suggestion for a finding

```
/audit-fix CRIT-01
```

Output:
```
=== Fix Suggestion for CRIT-01 ===

Title: Missing signer check on admin_withdraw
Rule: Rule 8 (Signer Verification)
Severity: CRITICAL | CVSS: 9.1

Fix Tier: A (Auto-Applicable)
Confidence: 98%
CVSS After: 7.5 (Reduction: 1.6)
Poker Risk: LOW
Effort: ~5 min

Files to modify:
  programs/vault/src/lib.rs:42

=== BEFORE ===
pub fn admin_withdraw(ctx: Context<Admin>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.withdraw(ctx.accounts.recipient.key(), amount)?;
    Ok(())
}

=== AFTER ===
pub fn admin_withdraw(ctx: Context<Admin>) -> Result<()> {
    if !ctx.accounts.admin.is_signer {
        return Err(ErrorCode::NotSigner.into());
    }
    let vault = &mut ctx.accounts.vault;
    vault.withdraw(ctx.accounts.admin.key(), amount)?;
    Ok(())
}

=== VERIFICATION TEST ===
#[test]
fn test_crit01_requires_admin_signer() {
    // Attempt admin_withdraw without admin signer should fail
    // Attempt with admin signer should succeed
}
```

### Apply a Tier A fix

```
/audit-fix --apply CRIT-01
```

Output:
```
[Tier A Auto-Fix] Applying CRIT-01 fix to programs/vault/src/lib.rs:42

NOTICE: This fix has been applied. Please verify:
1. Review the code change
2. Run: anchor build
3. Run: anchor test
4. Run: /audit-fix --verify CRIT-01

If you need to revert, use: git checkout programs/vault/src/lib.rs
```

### Verify a fix

```
/audit-fix --verify CRIT-01
```

Output:
```
=== Verification for CRIT-01 ===

Status: VERIFIED

Checks:
  [PASS] anchor build succeeds
  [PASS] anchor test passes
  [PASS] Finding-specific test exists
  [PASS] Exploit scenario now fails

CVSS Recalculation:
  Before: 9.1 (Critical)
  After:  7.5 (High)
  Reduction: 1.6

The fix for CRIT-01 has been verified.
```

### Generate remediation report

```
/audit-fix --report
```

Output:
```
=== REMEDIATION STATUS REPORT ===

Total Findings: 6
  Open: 3
  Fixed: 2
  Pending: 1

By Severity:
  CRITICAL: 2
  HIGH: 2
  MEDIUM: 1
  LOW: 1

By Fix Tier:
  Tier A: 3 (Auto-applicable)
  Tier B: 2 (Assisted)
  Tier C: 1 (Manual)

CVSS Impact Summary:
  CRIT-01: 9.1 -> 7.5 (Reduction: 1.6)
  CRIT-02: 9.8 -> 8.1 (Reduction: 1.7)
  HIGH-01: 7.5 -> 5.9 (Reduction: 1.6)
  ...

Remediation Timeline:
  CRIT-01: Fixed by operator@2024-01-15 (Tier A)
  CRIT-02: Fixed by operator@2024-01-15 (Tier A)
```

### List all findings with tiers

```
/audit-fix --list
```

Output:
```
=== All Findings with Fix Tiers ===

CRIT-01 | Rule 8  | Tier A | 98% | CVSS 9.1 -> 7.5
CRIT-02 | Rule 7  | Tier A | 95% | CVSS 9.8 -> 8.1
HIGH-01 | Rule 14 | Tier B | 87% | CVSS 8.9 -> 6.2
HIGH-02 | Rule 6  | Tier A | 98% | CVSS 7.5 -> 5.9
MED-01  | Rule 3  | Tier A | 95% | CVSS 5.3 -> 4.2
LOW-01  | Rule 10 | Tier A | 95% | CVSS 2.8 -> 1.8

Tier A (Auto-Applicable): 4 findings
Tier B (Assisted): 1 finding
Tier C (Manual): 1 finding
```

## Fix Tier Classification

| Tier | Criteria | How to Apply |
|------|----------|--------------|
| **A** | confidence >= 90%, poker risk LOW | Auto-apply with notification |
| **B** | confidence 60-89%, poker risk MEDIUM | Confirm before applying |
| **C** | confidence < 60%, poker risk HIGH | Manual implementation required |

## Consent Gate

Even Tier A fixes require explicit operator consent:

```
/audit-fix --apply CRIT-01

[Tier A Auto-Fix] Ready to apply CRIT-01 fix

This will add a signer check to admin_withdraw.
Type YES to apply, or NO to cancel: _
```

## Integration with Other Commands

- `/audit-findings` — View all findings, use `FIX` link to jump to `/audit-fix`
- `/audit-poc` — Run PoC to verify exploit exists, then `/audit-fix` to remediate
- `/audit-report` — Includes remediation status section automatically

## Technical Details

The command uses `scripts/audit-fix-suggestions.py` for fix generation and `scripts/fix-verification.sh` for verification.

### Confidence Scoring

Confidence is computed using a prediction-market model:
```
confidence = base_rate(rule_id) * pattern_match_bonus * fix_history_bonus
```

Where:
- **base_rate**: Historical fix success rate for that rule (0.60-0.98)
- **pattern_match_bonus**: 1.0 for exact pattern match, 0.85 otherwise
- **fix_history_bonus**: 1.0 + (successful_fixes / 100), capped at 1.2

### CVSS Recalculation

After applying a fix, CVSS is recalculated based on:
- Metrics that change (e.g., Privileges Required when adding signer check)
- Metrics that remain (e.g., Attack Vector, Scope)

The CVSS math is verified by `tests/severity_counts.py::check_cvss_math()`.

## Constraints

1. **Never auto-apply without consent**: Even Tier A requires explicit approval
2. **Never skip verification**: Always run tests after fix
3. **No breaking changes**: Fixes must preserve intended behavior
4. **Document all changes**: Record fix in findings.json remediation block

---

## /audit-fix-explain — Deep Remediation Analysis

Generate detailed root cause analysis, attack scenarios, and regression tests for a finding.

### Usage

```
/audit-fix-explain <finding-id>            # Full analysis (root_cause + attack + regression)
/audit-fix-explain <finding-id> --root-cause    # Root cause analysis only
/audit-fix-explain <finding-id> --regression    # Regression test only
/audit-fix-explain <finding-id> --full           # Everything including tradeoffs + CU impact
```

### Flags

| Flag | Description |
|------|-------------|
| `--root-cause` | Emit root cause analysis, attack scenario, and business impact |
| `--regression` | Emit concrete regression test code (not a placeholder) |
| `--full` | Emit all sections: root cause, attack scenario, business impact, regression test, tradeoffs, CU impact |
| (default) | Emit root_cause + attack_scenario + business_impact + regression_test |

### Output Schema

Each section is emitted only if requested and if the data exists in `skill/06-remediation.md` or `scripts/audit-fix-suggestions.py`.

```json
{
  "finding_id": "CRIT-01",
  "root_cause": "Human-readable root cause (2-3 sentences)",
  "attack_scenario": ["Step 1", "Step 2", "..."],
  "business_impact": "Quantified impact description",
  "regression_test": "fn test_xxx() { ... }",
  "tradeoffs": {
    "gas_cost": "+600 CU",
    "breaking_changes": "none | may affect X | significant",
    "complexity": "low | medium | high"
  },
  "compute_unit_impact": "~+600 CU estimate"
}
```

### Examples

```
/audit-fix-explain CRIT-01
```

Output:
```
=== Remediation Analysis: CRIT-01 ===

Root cause:
The admin field in AdminWithdraw was declared as AccountInfo<'info> instead of
Signer<'info>. Anchor's deserializer accepts any AccountInfo regardless of whether
it signed the transaction. The raw lamport transfer then executes because no signer
gate exists at any level.

Attack scenario:
  1. Attacker constructs a transaction invoking admin_withdraw with their own pubkey
  2. Transaction is signed only by the attacker's wallet (for the payer account)
  3. Anchor deserializes the instruction without verifying the admin field signed
  4. Program executes vault.lamports -= amount unconditionally
  5. Vault is drained; attacker receives lamports at their chosen destination

Business impact:
Total loss of vault funds. Unbounded SOL drain. All depositors lose funds.
Protocol insolvency with no recovery path.

Regression test:
#[tokio::test]
async fn test_admin_withdraw_requires_signer() {
    let malicious_tx = Transaction::new_signed_with_payer(
        &[instruction::admin_withdraw(...)],
        Some(&payer.pubkey()),
        &[&payer],  // Only payer signs — admin does NOT sign
        recent_blockhash,
    );
    let result = program.rpc().process_transaction(&malicious_tx).await;
    assert!(result.is_err());  // Must fail with NotSigner
}
```

```
/audit-fix-explain CRIT-01 --full
```

Output includes additional tradeoffs and CU impact:
```
Tradeoffs:
  Gas cost: +600 CU (Signer deserialization overhead)
  Breaking changes: Existing callers must sign with the admin key
  Complexity: None — single type swap from AccountInfo to Signer

Compute unit impact: ~+600 CU. Signer verification is a single sysvar
check at deserialization.
```

### Implementation

The command delegates to `scripts/audit-fix-suggestions.py` which reads:
- `skill/06-remediation.md` for pre-authored Remediation Analysis blocks (PoC walkthroughs)
- `scripts/audit-fix-suggestions.py` rule templates for mechanically-derivable analysis
- `findings.json` for finding metadata (severity, CVSS, rule)

If no Remediation Analysis block exists for the finding, the engine synthesizes one from the fix template for that rule (Rule 1-50), falling back to a generic analysis.

### Constraints

1. **Never fabricate analysis**: If no analysis exists for a rule, say so rather than generating plausible-sounding but unverified content
2. **Preserve test syntax**: Regression test blocks must use syntactically valid Rust (`#[test]`, `fn test_`, `assert!`)
3. **Quantify where possible**: Business impact should use concrete terms (SOL amounts, user counts, protocol insolvency)
