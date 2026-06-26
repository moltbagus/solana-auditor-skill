# Sample Vulnerable Program — Audit Fixture

This directory contains a deliberately vulnerable Anchor program used to demonstrate the **solana-auditor-shiba** skill.

## ⚠️ DO NOT DEPLOY

The programs in this directory contain **16 intentional vulnerabilities** across two fixtures: the core Anchor vault (10 vulns) and the Token-2022 extensions (6 vulns). These are **documentation fixtures**, not production code.

## What this demonstrates

- **Vault fixture** (`programs/vault/`): Core Anchor vulnerability classes — signer checks, CPI safety, arithmetic, PDA bumps, reinit attacks
- **Token-2022 fixture** (`programs/token-extensions/`): Token Extensions vulnerability classes — wrong token program, transfer fee accounting, mint close authority, permanent delegate, metadata pointer, non-transferable bypass

Running `/audit examples/sample-vulnerable-program` against this program should produce findings matching the respective `audit-output/*/findings.json` files. Each bug is tagged in the source with `// VULN-XX: <description>` comments.

## Bug inventory — Vault fixture

| ID | Severity | Rule that catches it | Pattern |
|----|----------|---------------------|---------|
| VULN-01 | CRITICAL | Rule 8 — Signer Verification | `admin: AccountInfo` instead of `Signer` on privileged withdraw |
| VULN-02 | MEDIUM | Rule 3 — PDA Canonical Bump | Hardcoded bump literal (254) instead of `ctx.bumps` |
| VULN-03 | HIGH | Rule 4 — CPI Safety | `invoke` to user-supplied program with no allowlist |
| VULN-04 | CRITICAL | Rule 7 — Close Accounts | `drain_vault` debits vault to user-supplied destination with no signer/has_one |
| VULN-05 | HIGH | Rule 6 — Arithmetic | `+` on `u64` amounts without `checked_add` |
| VULN-06 | MEDIUM | Rule 11 — Reinit Attacks | `AccountInfo` without `#[account]` discriminator check |
| VULN-07 | MEDIUM | (non-rule — triage judgment) | `deposit / divisor` truncates; users get 0 shares for non-zero deposits |
| VULN-08 | MEDIUM | (non-rule — triage judgment) | `>` instead of `>=` allows threshold bypass |
| VULN-09 | MEDIUM | (non-rule — Rule 4 adjacent) | `let _ = invoke(...)` discards CPI result |
| VULN-10 | MEDIUM | (non-rule — best practice) | Withdrawals emit no event — audit trail gap |

## Bug inventory — Token-2022 fixture

| ID | Severity | Rule that catches it | Pattern |
|----|----------|---------------------|---------|
| VULN-11 | HIGH | Rule 5 — Token Operations | `anchor_spl::token::Token` instead of `token_2022::Token2022` |
| VULN-12 | HIGH | Rule 5 — Token-2022 extensions | Full amount recorded without deducting transfer_fee |
| VULN-13 | MEDIUM | Rule 5 — Token-2022 extensions | Mint close authority not verified against extension |
| VULN-14 | CRITICAL | Rule 5 + Rule 8 | Permanent delegate accepted without extension validation |
| VULN-15 | MEDIUM | Rule 5 — Token-2022 extensions | Metadata pointer not verified against mint extension |
| VULN-16 | HIGH | Rule 5 — Token-2022 extensions | Non-transferable restriction bypassed via wrapping |

## File layout

```
examples/sample-vulnerable-program/
├── README.md                       # this file
├── Anchor.toml                     # minimal Anchor config (both programs)
├── programs/
│        ├── vault/
│   │   ├── Cargo.toml              # Anchor 0.31.1 deps (Anchor + SPL Token)
│   │   └── src/
│   │       └── lib.rs              # 10 tagged vulnerabilities (VULN-01..VULN-10)
│   └── token-extensions/
│       ├── Cargo.toml              # Anchor 0.31.1 + spl-token-2022 6.0
│       └── src/
│           └── lib.rs              # 6 tagged vulnerabilities (VULN-11..VULN-16)
└── audit-output/
    ├── findings.json               # expected /audit output (vault — 10 findings)
    ├── AUDIT_REPORT.md             # expected /audit-report output (vault)
    ├── quick-scan-results.md       # expected /audit-quick output (vault)
    ├── methodology-trace.md        # methodology trace (vault)
    └── token-extensions/
        ├── findings.json           # expected /audit output (6 findings)
        ├── AUDIT_REPORT.md         # expected /audit-report output
        ├── quick-scan-results.md   # expected /audit-quick output
        └── methodology-trace.md    # methodology trace
```

## Verifying the audit matches expectations

### Vault fixture
```bash
rg -o "VULN-[0-9]+" programs/vault/src/lib.rs | sort -u
rg -o '"id": "VULN-[0-9]+"' audit-output/vault/findings.json | sort -u
# Both commands should print: VULN-01 through VULN-10
```

### Token-2022 fixture
```bash
rg -o "VULN-[0-9]+" programs/token-extensions/src/lib.rs | sort -u
rg -o '"id": "VULN-[0-9]+"' audit-output/token-extensions/findings.json | sort -u
# Both commands should print: VULN-11 through VULN-16
```

## Fixture coverage

| Metric | Vault | Token-2022 | Total |
|--------|-------|-----------|-------|
| VULN tags | 10 | 6 | 16 |
| CRITICAL | 2 | 1 | 3 |
| HIGH | 2 | 3 | 5 |
| MEDIUM | 6 | 2 | 8 |
| Rules exercised | Rule 3,4,6,7,8,11 | Rule 5 (+ Rule 8) | 7 of 12 |

## Toolchain note

This example is shipped **without** a Solana toolchain. It is designed to be inspected as code:

```bash
# Read the vulnerable code
cat programs/vault/src/lib.rs
cat programs/token-extensions/src/lib.rs
# Inspect expected findings
cat audit-output/vault/findings.json
cat audit-output/token-extensions/findings.json
```

If you have `anchor` and `solana-cli` installed, you can run the full audit lifecycle:

```bash
# From the skill root:
/audit examples/sample-vulnerable-program
```

The output should match the respective `audit-output/*/findings.json` files (modulo execution-specific data like timestamps).

## Educational use

This fixture is meant for:
- Skill reviewers evaluating solana-auditor-shiba
- Solana developers learning to spot common Anchor vulnerability classes, including Token-2022 extension-level bugs
- Test data for tools that consume findings.json / AUDIT_REPORT.md formats

If you find a bug in this fixture that the audit skill does NOT catch, that's a useful signal — please file an issue on the skill's GitHub repo with the missed pattern.
