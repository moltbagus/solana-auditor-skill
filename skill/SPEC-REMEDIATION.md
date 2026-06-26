# SPEC: Remediation Phase Enhancement (v1.7)

**Status**: Draft spec for implementation
**Owner**: solana-auditor-skill v1.7
**Supersedes**: `skill/06-remediation.md` (becomes Phase 6 reference)
**CVSS verified by**: `tests/severity_counts.py::check_cvss_math()`

---

## 1. Motivation

The current Phase 6 (`06-remediation.md`) provides fix patterns and checklists but lacks:

1. **Structured fix-suggestion engine** -- fixes are prose, not machine-readable patches
2. **Confidence scoring** -- no way to assess fix reliability before applying
3. **CVSS reduction tracking** -- no before/after severity quantification
4. **Auto-fix tiers** -- no distinction between safe-auto, assisted, and manual fixes
5. **Verification loop** -- no programmatic confirmation that a fix resolves the vuln
6. **Fix history** -- no record of which findings were remediated and how

This spec defines all six gaps so the remediation phase can graduate from "fix guidance" to "fix automation with human oversight."

---

## 2. Fix Suggestion Schema

Every finding in `findings.json` gets a `remediation` block appended:

```json
{
  "id": "CRIT-01",
  "severity": "CRITICAL",
  "cvss": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cwe": "CWE-306",
  "title": "Unsigned privileged action in admin_withdraw",
  "location": {"file": "programs/vault/src/lib.rs", "line": 42, "function": "admin_withdraw"},
  "description": "...",
  "impact": "...",
  "recommendation": "Add signer verification to the admin_withdraw instruction",
  "poc_status": "confirmed",
  "rule_caught": "Rule 8",
  "status": "Open",
  "remediation": {
    "fix_tier": "A",
    "confidence_score": 0.97,
    "fix_type": "constraint_addition",
    "patch": {
      "file": "programs/vault/src/lib.rs",
      "line": 38,
      "before": "pub admin: AccountInfo,",
      "after": "pub admin: Signer<'info>,"
    },
    "cvss_after": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
    "poker_risk": "LOW",
    "estimated_effort_minutes": 5,
    "status": "pending | applied | verified | rejected",
    "applied_at": null,
    "applied_by": null,
    "verification": {
      "anchor_test": "tests/admin_withdraw_test.ts",
      "anchor_build_pass": true,
      "formal_verified": false,
      "regression_pass": true,
      "verified_at": null
    },
    "history": []
  }
}
```

### Field Definitions

| Field | Type | Description |
|-------|------|-------------|
| `fix_tier` | `A \| B \| C` | Auto-fix tier (see Section 3) |
| `confidence_score` | `float [0.0, 1.0]` | Prediction-market confidence based on rule pattern frequency |
| `fix_type` | enum | One of the 6 fix types (see Section 4) |
| `patch` | object | Structured before/after code diff |
| `cvss_after` | object | Post-fix CVSS score and vector |
| `poker_risk` | `LOW \| MEDIUM \| HIGH \| CRITICAL` | Poker-style risk of the fix introducing new bugs |
| `estimated_effort_minutes` | `int` | Time to implement (0 = auto, >10 = manual) |
| `status` | enum | Remediation lifecycle state |
| `verification` | object | Verification loop results |
| `history` | array | Audit trail of all remediation attempts |

---

## 3. Auto-Fix Tiers

### Tier A -- Safe Auto-Fix (confidence >= 0.90)

The auditor may auto-apply these without prompting. Examples:

| Rule | Pattern | Fix Action |
|------|---------|------------|
| Rule 2 | Missing `owner` check on account | Add `owner = expected_program` to `#[account()]` constraint |
| Rule 2 | Missing `mut` on account being written | Add `mut` to `#[account()]` constraint |
| Rule 6 | Integer overflow (`+`, `-`, `*` on u64) | Replace with `checked_add`, `checked_sub`, `checked_mul` |
| Rule 10 | `panic!` in instruction | Replace with `err!(MyError::Variant)` |
| Rule 18 | `unwrap()` on untrusted `BorshDeserialize` | Replace `.unwrap()` with `?` |
| Rule 19 | Missing `owner =` alongside `address =` constraint | Add redundant `owner =` for defense-in-depth |

**Implementation**: Tier A fixes are written as structured `Patch` objects. The auditor applies them directly, records `applied_at`, and triggers verification.

**Consent gate**: Operator is notified (not asked) via audit output:

```
[Tier A Auto-Fix] Applied CRIT-01 fix to programs/vault/src/lib.rs:38
  Added: pub admin: Signer<'info>,
  Confidence: 0.97 | CVSS reduction: 9.8 -> 7.5
```

### Tier B -- Assisted Fix (confidence 0.60-0.89)

The auditor generates the patch, displays it, and asks for confirmation.

**Prompt to operator**:

```
[Tier B Assisted Fix] Fix suggestion for CRIT-01

  BEFORE (line 42):
    pub fn admin_withdraw(ctx: Context<Admin>) -> Result<()> {

  AFTER:
    pub fn admin_withdraw(ctx: Context<Admin>) -> Result<()> {
        if !ctx.accounts.admin.is_signer {
            return Err(ErrorCode::NotSigner.into());
        }

  Confidence: 0.87 | CVSS reduction: 9.8 -> 6.2
  Estimated effort: 5 min | Poker risk: LOW

  [APPLY] [EDIT] [REJECT]
```

**Risk escalation**: If `poker_risk = HIGH` or `CRITICAL`, auto-escalate to Tier C regardless of confidence.

### Tier C -- Manual Fix (confidence < 0.60)

The auditor provides detailed guidance (the current `06-remediation.md` output) and documents the fix path. The operator implements manually.

**Output format**:

```
[Tier C Manual Fix] CRIT-01 requires architectural review

  Root cause: The instruction trusts `ctx.accounts.admin` without verifying
  signer status. This allows any caller to invoke admin_withdraw.

  Recommended approach:
    1. Change account type from AccountInfo to Signer<'info> (Anchor enforces)
       OR
    2. Add manual check: if !ctx.accounts.admin.is_signer { return Err(...) }

  CVSS reduction after fix: 9.8 -> 6.2 (HIGH, not fully eliminated)

  NOTE: This instruction also needs a remaining_accounts validation review
        (Rule 15). Consider addressing together.

  Poker risk: MEDIUM -- changing the account type may break existing tests.
  Estimated effort: 15-60 min

  Reference: skill/06-remediation.md, Rule 8
```

---

## 4. Fix Types

| Fix Type | Description | Typical Rules |
|----------|-------------|---------------|
| `constraint_addition` | Adding Anchor account constraints (`mut`, `owner`, `singer`) | Rules 2, 8, 11, 17, 19 |
| `arithmetic_safety` | Replacing raw arithmetic with `checked_*` | Rule 6 |
| `validation_check` | Adding explicit checks (`require!`, `if !is_signer`) | Rules 8, 15, 24 |
| `state_guard` | Adding reentrancy locks, discriminator checks, init guards | Rules 14, 21, 22 |
| `pda_canonicalization` | Replacing hardcoded bumps with `ctx.bumps` | Rule 3 |
| `architectural_refactor` | Restructuring instruction logic, atomicity changes | Rules 7, 13, 26 |

---

## 5. Confidence Scoring (Prediction-Market Model)

Each fix suggestion carries a `confidence_score` computed from:

```
confidence = base_rate(rule_id) * pattern_match_bonus * fix_history_bonus
```

Where:
- **`base_rate(rule_id)`** = historical fix success rate for that rule pattern, stored in `~/.solana-auditor-skill/fix-history.json`
- **`pattern_match_bonus`** = 1.0 if the finding exactly matches a known fix pattern (e.g., `old_amount + deposit` -> `checked_add`), else 0.85
- **`fix_history_bonus`** = 1.0 + (successful_previous_fixes_for_this_rule / 100), capped at 1.2

**Initial base rates** (seeded from audit-rules patterns):

| Rule | Base Rate | Rationale |
|------|-----------|-----------|
| Rule 2 (missing constraint) | 0.95 | Anchor type system enforces fix |
| Rule 6 (overflow) | 0.97 | `checked_*` replacement is exact |
| Rule 8 (missing signer) | 0.93 | `Signer<'info>` or `is_signer` check is unambiguous |
| Rule 10 (`panic!`) | 0.99 | Mechanical `panic!` -> `err!` replacement |
| Rule 18 (`unwrap`) | 0.98 | Mechanical `?` propagation |
| Rule 11 (reinit) | 0.88 | Requires discriminator addition; breaking change risk |
| Rule 14 (reentrancy) | 0.72 | CEI pattern correct but may need lock flag logic |
| Rule 22 (init/close race) | 0.60 | Architectural refactor, high breaking-change risk |
| Rule 26 (cross-program flash) | 0.45 | Requires oracle redesign, always Tier C |

**Calibration**: After each fix, the operator rates the outcome (`verified`, `rejected`, `broke_something`). This feedback updates the base rate in `fix-history.json`. After 20+ fixes per rule, the confidence score is statistically meaningful.

---

## 6. Poker-Style Risk Assessment

For each fix, assess **three dimensions**:

| Dimension | LOW | MEDIUM | HIGH | CRITICAL |
|-----------|-----|--------|------|----------|
| **Code change size** | <5 lines | 5-20 lines | 20-50 lines | >50 lines |
| **State touched** | None (static only) | One account | Multiple accounts | Cross-program state |
| **Trust boundary** | Internal only | User accounts | Authority accounts | Program upgrade |

**Poker risk** = highest dimension reached:

```
poker_risk = max(size_risk, state_risk, boundary_risk)
```

**Interaction with tiers**:
- If `poker_risk = CRITICAL` -> Tier C (manual only)
- If `poker_risk = HIGH` and confidence >= 0.90 -> Tier B only (not auto)
- If `poker_risk = LOW` and confidence >= 0.90 -> Tier A (safe auto-fix)

**Detailed poker risk matrix**:

```
                    Code Change Size
                   SMALL    MED     LARGE    XLARGE
              +---------+-------+--------+--------+
 State Touched|         |       |        |        |
 NONE         |  LOW    | LOW   | MEDIUM | HIGH   |
 USER ACCOUNTS|  LOW    | MEDIUM| MEDIUM | HIGH   |
 AUTH ACCOUNTS|  MEDIUM | MEDIUM| HIGH   | CRIT   |
 CROSS-PROGRAM|  HIGH   | HIGH  | CRIT   | CRIT   |
              +---------+-------+--------+--------+

SMALL    = <5 lines, single file
MED      = 5-20 lines, single file
LARGE    = 20-50 lines, or 2 files
XLARGE   = >50 lines, or 3+ files, or architectural
```

---

## 7. CVSS Reduction Tracking

Every fix must include a **post-fix CVSS assessment**. The auditor recomputes the score by adjusting the likely-improved metric:

```python
def estimate_post_fix_cvss(finding: dict, fix_type: str) -> dict:
    """
    Estimate CVSS after a fix.
    Actual score requires human review; this is a planning signal.
    """
    vec = parse_cvss_vector(finding["cvss_vector"])
    sev = finding["severity"]

    # Fixes typically reduce PR or UI
    if fix_type == "constraint_addition":
        # Adding a constraint typically adds PR:L
        vec["PR"] = "L"
    elif fix_type == "validation_check":
        # Adding validation typically adds PR:L or UI:R
        vec["PR"] = "L"
    elif fix_type == "architectural_refactor":
        # Major refactors may reduce C, I, or A to L
        vec["C"] = "L"
        vec["I"] = "L"

    new_score = compute_cvss_score(vec)
    return {"score": new_score, "vector": format_vector(vec)}
```

**Example reduction**:

| Finding | Before CVSS | Fix | After CVSS | Delta |
|---------|-------------|-----|------------|-------|
| CRIT-01 (missing signer) | 9.8 (PR:N) | Add `Signer<'info>` | 7.5 (PR:L) | -2.3 |
| HIGH-04 (overflow) | 8.1 | `checked_add` | 4.2 (C:L, I:N) | -3.9 |
| CRIT-12 (reentrancy) | 9.1 | CEI pattern | 6.5 (PR:L) | -2.6 |

**Verification**: After a fix is applied, the auditor re-scores the finding with the operator's confirmation and writes the post-fix vector to `findings.json`.

---

## 8. Verification Loop

After a fix is applied, the auditor runs a **four-stage verification loop**:

```
Stage 1: Anchor Build
  anchor build
  Exit code != 0 -> FIX REJECTED. Revert and re-assess.

Stage 2: Anchor Test
  anchor test [--grep "<finding_function_name>"]
  All tests pass -> Stage 3
  Any test fails -> FIX REJECTED. Revert and re-assess.

Stage 3: Regression Check
  python3 tests/severity_counts.py check-cvss-math <findings.json>
  python3 tests/severity_counts.py check-summary <findings.json>
  Mismatch -> FIX REJECTED. Revert and re-assess.

Stage 4: (Tier 2 only) Formal Verification
  qed-solana verify --program target/deploy/<PROGRAM>.so \
    --invariants tests/invariants/
  Pass -> FIX VERIFIED
  Fail -> FIX REJECTED. Revert and re-assess.
```

**On verification success**:

```json
"remediation": {
  "status": "verified",
  "cvss_after": {"score": 6.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
  "verification": {
    "anchor_build_pass": true,
    "anchor_test_pass": true,
    "formal_verified": true,
    "regression_pass": true,
    "verified_at": "2026-06-26T12:00:00Z"
  }
}
```

**On verification failure**: The fix is marked `rejected`, the finding reverts to `status: "Open"`, and the auditor logs the failure reason in `history`.

---

## 9. Integration Points

### 9.1 findings.json

The top-level `findings.json` is extended with a `remediation` key per finding. The `poc_status` field gains two new values:

```
poc_status: pending | confirmed | verified | fixed | disproved
                                                              ^^^^^^^^ new
                                                              ^^^^^^ new
```

`status` also gains `In Remediation` as a terminal state (separate from `Open`).

### 9.2 AUDIT_REPORT.md

A new section appears after each finding:

```markdown
### CRIT-01: Unsigned privileged action

**CVSS**: 9.8 | **CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

...

**Remediation**
- **Fix Tier**: A (Safe Auto-Fix)
- **Confidence**: 0.97
- **Fix Type**: constraint_addition
- **CVSS After Fix**: 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- **Status**: Verified (2026-06-26)
- **Poker Risk**: LOW
- **Anchor Test**: `tests/admin_withdraw_test.ts` -- pass
- **Formal Verification**: verified
```

### 9.3 Fix History DB

`audit-history.sh` is extended to track remediation events:

```bash
# New subcommands
./scripts/audit-history.sh fix-log <finding_id> <event> <details>
./scripts/audit-history.sh fix-summary
./scripts/audit-history.sh cvss-reduction-report
```

The history DB schema gains:

```sql
CREATE TABLE fix_history (
    id INTEGER PRIMARY KEY,
    finding_id TEXT NOT NULL,
    fix_tier TEXT NOT NULL,
    confidence_score REAL NOT NULL,
    poker_risk TEXT NOT NULL,
    patch_file TEXT,
    status TEXT NOT NULL,  -- applied | verified | rejected | reverted
    applied_at TEXT,
    verified_at TEXT,
    applied_by TEXT,
    cvss_before REAL,
    cvss_after REAL,
    notes TEXT
);
```

### 9.4 Pre-Commit Hook

When a finding is `verified` (fix applied + verification loop passed), the pre-commit hook may allow the commit even if the finding was previously `Open`. A new flag in `audit-output/audit-state.json`:

```json
{
  "findings": {
    "CRIT-01": {
      "status": "Verified",
      "fix_tier": "A",
      "verification_passed": true,
      "verified_at": "2026-06-26T12:00:00Z"
    }
  }
}
```

### 9.5 export-sarif.py

SARIF export gains a `fix` property block:

```json
{
  "results": [{
    "id": "CRIT-01",
    "properties": {
      "fix_tier": "A",
      "fix_confidence": 0.97,
      "cvss_after_fix": 6.5,
      "remediation_status": "verified"
    }
  }]
}
```

---

## 10. scripts/audit-fix-suggestions.py

This script (currently missing, referenced in CLAUDE.md) implements the fix suggestion engine.

### Command Interface

```bash
# Generate fix suggestions for all open findings
python3 scripts/audit-fix-suggestions.py \
    --findings examples/sample-vulnerable-program/audit-output/findings.json \
    --output   examples/sample-vulnerable-program/audit-output/findings.json

# Generate fix suggestions for one finding
python3 scripts/audit-fix-suggestions.py \
    --findings examples/sample-vulnerable-program/audit-output/findings.json \
    --filter   CRIT-01

# Apply a Tier A fix (auto)
python3 scripts/audit-fix-suggestions.py \
    --findings examples/sample-vulnerable-program/audit-output/findings.json \
    --apply    CRIT-01 \
    --confirm   # Tier B only; omit for Tier A

# Run verification loop
python3 scripts/audit-fix-suggestions.py \
    --verify   CRIT-01 \
    --findings examples/sample-vulnerable-program/audit-output/findings.json

# Show CVSS reduction summary
python3 scripts/audit-fix-suggestions.py \
    --summary  examples/sample-vulnerable-program/audit-output/findings.json
```

### Module API (for integration with other phases)

```python
from scripts.audit_fix_suggestions import (
    generate_fixes,
    apply_fix,
    verify_fix,
    estimate_cvss_reduction,
    confidence_from_rule,
)

# Generate fixes for all open findings
fixes = generate_fixes("audit-output/findings.json")

# Filter by tier
tier_a = [f for f in fixes if f["fix_tier"] == "A"]
tier_b = [f for f in fixes if f["fix_tier"] == "B"]
tier_c = [f for f in fixes if f["fix_tier"] == "C"]

# Apply a Tier A fix
result = apply_fix("CRIT-01", dry_run=False)

# Verify and record
verify_result = verify_fix("CRIT-01", findings_path="audit-output/findings.json")
```

---

## 11. Implementation Gaps vs Current Codebase

| Gap | Current State | Required Change |
|-----|--------------|-----------------|
| `scripts/audit-fix-suggestions.py` | Does not exist | Create (see Section 10) |
| `remediation` block in findings.json | `recommendation` only (string) | Add structured `remediation` object |
| `poc_status` values | 5 values, no `fixed`/`rejected` for remediated state | Extend enum; `fixed` = applied + verified |
| `severity_counts.py` | No CVSS reduction tracking | Add `check-cvss-reduction` subcommand |
| `06-remediation.md` | Prose patterns + checklist | Becomes: Phase 6 reference doc + examples |
| `audit-history.sh` | No fix tracking | Add `fix-log`, `fix-summary` subcommands |
| `export-sarif.py` | No remediation metadata | Add `fix_tier`, `cvss_after_fix` to SARIF properties |
| `rules/audit.rules` | Fix patterns embedded in prose | Add `**Fix pattern:**` block to each rule |
| Pre-commit hook | Blocks on HIGH+ Open findings | Add `--allow-verified` flag |
| Confidence base rates | No history | Seed from rule patterns; persist to `fix-history.json` |

---

## 12. File Changes

| File | Action |
|------|--------|
| `skill/SPEC-REMEDIATION.md` | Create (this spec) |
| `skill/06-remediation.md` | Rewrite as Phase 6 reference doc |
| `scripts/audit-fix-suggestions.py` | Create fix suggestion engine |
| `scripts/audit-fix-suggestions.md` | Create CLI usage guide |
| `scripts/audit-history.sh` | Add fix-log, fix-summary, cvss-reduction-report |
| `tests/severity_counts.py` | Add `check-cvss-reduction` mode |
| `rules/audit.rules` | Add `**Fix pattern:**` blocks per rule |
| `scripts/pre-commit-audit.sh` | Add `--allow-verified` flag |
| `scripts/export-sarif.py` | Add remediation metadata fields |
| `examples/.../findings.json` | Update schema (patch field in remediation) |

---

## 13. Example: Full Remediation Flow

```
> /audit-fix CRIT-01

[1] Fix Suggestion Engine
    CRIT-01: Unsigned privileged action (admin_withdraw, line 42)
    Rule: 8 (CWE-306, missing signer verification)
    Fix Tier: A (confidence 0.97)
    Fix Type: constraint_addition
    Poker Risk: LOW

    Patch:
      File:   programs/vault/src/lib.rs
      Line:   38
      Before: pub admin: AccountInfo<'info>,
      After:  pub admin: Signer<'info>,

    CVSS Estimate: 9.8 -> 7.5 (PR:N -> PR:L)
    (Confidence computed from Rule 8 base_rate=0.93, pattern_match=exact)

[2] Consent
    [Tier A] Confidence >= 0.90, poker_risk=LOW
    Auto-applying fix...

[3] Patch Applied
    Applied CRIT-01 fix to programs/vault/src/lib.rs
    Recording to findings.json...

[4] Verification Loop

    Stage 1: anchor build ...................... PASS
    Stage 2: anchor test --grep admin_withdraw . PASS
    Stage 3: regression (severity_counts) ...... PASS
    Stage 4: formal verification ................ PASS

[5] Result

    CRIT-01 FIX VERIFIED

    CVSS: 9.8 -> 7.5 (HIGH)
    Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
    Status: Open -> Verified
    Verified at: 2026-06-26T12:00:00Z

    finding[id=CRIT-01].remediation.status = "verified"
    finding[id=CRIT-01].remediation.cvss_after = {score: 7.5, vector: "..."}
    finding[id=CRIT-01].verification = {anchor_build_pass: true, ...}
```

---

## 14. Backward Compatibility

- `findings.json` with the existing 11-field schema remains valid; `remediation` is optional
- Scripts that read `findings.json` and don't handle `remediation` field must be updated
- `poc_status` values are extended, not changed; existing `pending | confirmed | verified | disproved` remain valid
- `severity_counts.py` check modes remain unchanged; new `check-cvss-reduction` mode is additive
