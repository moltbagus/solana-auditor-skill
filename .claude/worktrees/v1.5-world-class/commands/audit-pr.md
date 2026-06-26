---
name: audit-pr
description: Audit a GitHub PR for security vulnerabilities — diff-based SAST targeting changed lines only
agent_type: command
---

# /audit-pr — PR Security Audit

Audit a GitHub pull request by fetching the diff, running targeted SAST against changed lines, and comparing against the base branch audit (if exists). Only analyze what changed — no full repo audit.

**Two modes**:
- **Diff-only mode** (default): SAST on changed lines from `gh pr diff`
- **Delta mode** (`--compare`): Cross-reference with base branch audit findings to flag NEW or FIXED vulnerabilities

## Usage

```
/audit-pr <owner/repo#pr_number>       # owner/repo#42 format
/audit-pr <pr-url>                    # Full GitHub PR URL
/audit-pr <owner/repo#pr_number> --compare   # Compare against base branch audit
/audit-pr <owner/repo#pr_number> --output <dir>  # Custom output directory
/audit-pr <owner/repo#pr_number> --severity THRESHOLD  # Minimum severity to report
```

## Pre-flight

1. **Parse PR identifier**:
   - If `owner/repo#123` format: extract `owner`, `repo`, `pr_number`
   - If full URL (`https://github.com/owner/repo/pull/123`): extract same fields
   - If bare number (`123`): require repo context (current directory must be a git repo with `origin`)
   - Error if parse fails: `"ERROR: Cannot parse PR identifier. Expected owner/repo#number or https://github.com/owner/repo/pull/number"`

2. **Validate gh CLI**:
   ```bash
   gh auth status 2>&1
   ```
   Abort if not authenticated: `"ERROR: gh CLI not authenticated. Run 'gh auth login' first."`

3. **Verify PR exists**:
   ```bash
   gh pr view <owner>/<repo>#<pr_number> --json title,state,base,head 2>&1
   ```
   Abort if PR not found or not accessible.

4. **Check if PR is mergeable**: Skip draft PRs without explicit consent.

5. **Output directory**: Default `<cwd>/pr-audit/<owner>-<repo>-PR-<number>/`. Create if not exists.

6. **Consent gate** (CRITICAL findings only):
   ```
   WARNING: This PR audit may surface CRITICAL-severity vulnerabilities.
   Proceed with diff-only analysis? [y/N]
   ```

## Diff Analysis

### Fetch PR Diff

```bash
gh pr diff <owner>/<repo>#<pr_number> --stat  # Get summary first
gh pr diff <owner>/<repo>#<pr_number>         # Full diff output
```

Parse diff statistics:
- `files_changed`: Number of files modified
- `insertions`: Total lines added
- `deletions`: Total lines removed
- `files`: List of changed file paths

### Filter Changed Rust Files

Extract only `.rs` files from the diff:
```bash
gh pr diff <owner>/<repo>#<pr_number> | grep '^+' | grep '\.rs$' | cut -d: -f1 | sort -u
```

For each changed file:
1. Extract changed lines (hunks with `+` lines)
2. Identify the function/instruction context from surrounding lines
3. Focus rule activation on lines that are NEW (added lines only)

### Changed Line Extraction

Parse the unified diff to extract:
- `added_lines`: Line numbers and content of `+` lines (excluding diff markers)
- `removed_lines`: Line numbers and content of `-` lines
- `context_lines`: Surrounding unchanged lines for function/discriminator context
- `hunks`: Grouped changes with minimum context (3 lines default)

## Audit Flow

### Step 1: Diff Fetch and Parse

```
1. Execute: gh pr diff <owner>/<repo>#<pr_number>
2. Parse unified diff output
3. Build changed_files[] array
4. Compute diff_stats{}
```

### Step 2: Changed Files Analysis

For each file in `changed_files[]` where `filename.endsWith('.rs')`:

1. **Load base file** (fetch from base branch):
   ```bash
   gh api repos/<owner>/<repo>/contents/<path>?ref=<base_branch> --jq '.content' | base64 -d
   ```

2. **Apply diff hunks** to reconstruct proposed version

3. **Run targeted rules** against only the changed lines:

| Rule(s) | Trigger Pattern in Diff | Severity |
|---------|----------------------|----------|
| Rule 1, 2 | `#[account(` or `#[derive(Accounts)]` added | HIGH→CRIT |
| Rule 3 | `find_program_address` or bump seeds changed | MED→CRIT |
| Rule 4 | `invoke(` or `invoke_signed(` or `CpiContext::` added | HIGH→CRIT |
| Rule 5 | Token program ops (`mint_to`, `burn`, `transfer`) changed | HIGH |
| Rule 6 | Arithmetic on amounts (`+`, `-`, `*`) added | MEDIUM |
| Rule 7 | `close =` constraint changed | CRITICAL |
| Rule 8 | Signer verification missing in new instruction | CRITICAL |
| Rule 9 | `Anchor.toml` changed, upgrade authority modified | MEDIUM |
| Rule 10 | `error.rs` or error handling changed | LOW |
| Rule 11 | `init` without discriminator guard in new account type | CRITICAL |
| Rule 12 | Rent/lamport handling changed | MEDIUM |
| Rule 13 | Oracle/price reads in changed instruction | CRITICAL |
| Rule 14 | External call followed by state mutation (CEI) | CRITICAL |
| Rule 15 | `remaining_accounts` indexing added | CRITICAL |
| Rule 16 | New `#[derive(Accounts)]` struct added | CRITICAL |
| Rule 17 | `AccountLoader` or `UncheckedAccount` usage | HIGH |
| Rule 18 | `BorshDeserialize` with `unwrap()` | HIGH |
| Rule 19 | `verify =` or `address =` constraint added | MED→HIGH |
| Rule 20 | Token-2022 extension initialization order | MEDIUM |
| Rule 21 | CPI callback paths modified | CRITICAL |
| Rule 22 | `init_if_needed` combined with `close` | CRITICAL |
| Rule 23 | `spl_memo` CPI with user-supplied data | MEDIUM |
| Rule 24 | `remaining_accounts` in `invoke_signed` | CRITICAL |
| Rule 25 | Versioned transaction / LUT handling | HIGH |
| Rule 26 | Multi-program CPI chain composition | CRITICAL |

### Step 3: Function-Level Context Recovery

For each changed hunk:
1. Extract 20 lines of context above the change
2. Identify the containing function name (regex: `pub fn (\w+)`)
3. Identify the instruction context (Anchor `#[instruction(...)]` attribute)
4. Build finding location: `{file, line, function, instruction}`

### Step 4: Compare Against Base Audit (Optional)

If `--compare` flag is set and `base_branch_audit/findings.json` exists:
```
1. Load base_branch_audit/findings.json
2. For each base finding:
   - If same file + similar code pattern: check if FIXED
   - If same file + new vulnerable pattern: flag as REGRESSION
3. For each new finding:
   - If new file or new code pattern: flag as NEW
4. Categorize: {new_findings[], fixed_findings[], regressions[]}
```

### Step 5: Severity Classification

Apply CVSS 3.1 scoring to each finding:
- Parse the vulnerability pattern
- Map to CWE
- Compute vector from exploitability + impact
- Assign numeric score

## Output

### findings-pr.json

```json
{
  "pr_number": 42,
  "owner": "moltbagus",
  "repo": "my-program",
  "base_branch": "main",
  "head_branch": "feat/vulnerable-code",
  "title": "Add admin withdrawal functionality",
  "url": "https://github.com/moltbagus/my-program/pull/42",
  "diff_stats": {
    "files_changed": 3,
    "insertions": 150,
    "deletions": 20,
    "files": [
      "programs/vault/src/lib.rs",
      "programs/vault/src/instructions/withdraw.rs",
      "Anchor.toml"
    ]
  },
  "new_findings": [
    {
      "id": "PR-NEW-01",
      "severity": "CRITICAL",
      "cvss": 9.1,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cwe": "CWE-306",
      "title": "Missing signer verification on admin withdrawal",
      "location": {
        "file": "programs/vault/src/instructions/withdraw.rs",
        "line": 42,
        "function": "admin_withdraw",
        "instruction": "withdraw"
      },
      "description": "The admin_withdraw instruction allows arbitrary withdrawal without verifying that the caller is a signer.",
      "diff_hunk": "@@ -38,6 +38,11 @@ pub fn admin_withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {\n+    let destination = &mut ctx.accounts.destination;\n+    let source = &mut ctx.accounts.source;\n+    // BUG: No signer check\n+    source.lamports -= amount;\n+    destination.lamports += amount;",
      "impact": "Any user can drain the vault by calling admin_withdraw.",
      "recommendation": "Add #[account(signer)] to the admin account and verify: require!(ctx.accounts.admin.is_signer, MyError::NotSigner);",
      "rule_caught": "Rule 8",
      "status": "Open",
      "poc_status": "pending"
    }
  ],
  "fixed_findings": [
    {
      "id": "PR-FIXED-01",
      "severity": "HIGH",
      "title": "Hardcoded bump in vault derivation",
      "location": {
        "file": "programs/vault/src/lib.rs",
        "line": 156
      },
      "description": "PR removed the hardcoded bump &[255] and now uses ctx.bumps.vault.",
      "rule_fixed": "Rule 3",
      "previous_finding_id": "HIGH-07"
    }
  ],
  "regressions": [],
  "summary": {
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
    "total": 1,
    "new": 1,
    "fixed": 1
  },
  "audit_metadata": {
    "audited_at": "2026-06-25T10:30:00Z",
    "tool_version": "1.5.0",
    "base_audit_exists": false,
    "compared_against": null
  }
}
```

### quick-pr-report.md (Generated)

```
# PR Security Audit Report

**PR**: #42 — Add admin withdrawal functionality
**Repo**: moltbagus/my-program
**Branch**: feat/vulnerable-code → main
**Audited**: 2026-06-25

## Diff Summary

| Metric | Value |
|--------|-------|
| Files Changed | 3 |
| Lines Added | 150 |
| Lines Deleted | 20 |

## New Findings

| ID | Severity | Title | Location |
|----|----------|-------|----------|
| PR-NEW-01 | CRITICAL | Missing signer verification on admin withdrawal | withdraw.rs:42 |

## Fixed Findings

| ID | Previous Severity | Title | Resolution |
|----|-----------------|-------|------------|
| PR-FIXED-01 | HIGH | Hardcoded bump in vault derivation | Removed hardcoded bump |

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 0 |

**Recommendation**: Do not merge until CRITICAL finding PR-NEW-01 is addressed.
```

## Consent Gate (CRITICAL Findings)

If any CRITICAL findings are detected:

```
WARNING: CRITICAL Severity Findings Detected
─────────────────────────────────────────────────────────
PR #42 contains 1 CRITICAL vulnerability that may allow
complete vault drainage.

PR-NEW-01: Missing signer verification on admin withdrawal
  Location: programs/vault/src/instructions/withdraw.rs:42
  Impact: Any user can drain the vault

The PR author should be notified. Proceed with reporting
without PoC execution? [y/N]
```

**Rules**:
- PoC generation requires explicit consent (same gate as `/audit-poc`)
- Never execute PoCs against live programs
- Reference PoC paths only in the report

## Integration

### Agent Delegation

For complex CPI chains detected in diff:
```json
{
  "agent": "cross-program-agent",
  "phase": "pr-audit",
  "input_artifacts": ["pr-diff.json", "cpi_surface.json"],
  "context": "PR #42 modifies CPI paths in vault program"
}
```

### Rule Activation

Rules activate on diff hunks matching the patterns in the audit flow table. Only changed lines trigger full rule evaluation. Context lines provide function/instruction scope.

## Error Handling

| Error | Handling |
|-------|----------|
| gh not authenticated | Abort with auth instructions |
| PR not found | Abort with error message |
| Diff too large (>100 files) | Warn and proceed, focus on .rs files only |
| Base branch audit missing | Skip comparison, diff-only mode |
| Invalid diff format | Abort with parse error |
| Rate limit hit | Retry with exponential backoff (max 3) |

## Rules (Absolute)

- **Never** auto-apply fixes to the PR branch
- **Never** execute PoCs without explicit typed consent
- **Never** include exploit code in the report — reference PoC path only
- **Always** compare against base audit when available
- **Always** flag both new vulnerabilities AND fixed vulnerabilities
- CVSS 3.1 mandatory for HIGH/CRITICAL findings
