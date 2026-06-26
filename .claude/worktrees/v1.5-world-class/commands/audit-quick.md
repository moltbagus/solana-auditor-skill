---
description: Fast heuristic SAST scan — surface likely vulns in minutes, false positives expected
---

# /audit-quick — Fast SAST Scan (TIER1)

Triage-only scan using Tier 1 (static analysis only). Skips recon, formal verification, Phase 2B runtime testing, and full triage. Use this for first-look at a new repo or PR — **always run `/audit` before acting on HIGH/CRITICAL hits**.

**TIER1 operation**: No Anchor/Solana toolchain required. Pattern matching via ripgrep only.

## Usage

```
/audit-quick <repo-path>
/audit-quick <repo-path> --severity CRITICAL,HIGH
/audit-quick <repo-path> --json
```

## Pre-flight

1. Confirm: anchor programs only. For Token-2022 / CPI deep review, use `/audit`.
2. Output: `<repo>/audit-report/quick-findings.{md,json}`.

## Heuristic checks

For each `.rs` under `<repo>/programs/`, run ripgrep patterns and stop-on-first-hit per check. Severity defaults in brackets.

**Also run `cargo audit`** if Cargo.toml exists — check for known vulnerable dependencies. Severity CRITICAL if any vulnerabilities found, HIGH for advisories.

| # | Check | Pattern | Default |
|---|-------|---------|---------|
| 1 | Missing signer | `pub fn (\w+)` body without `is_signer`/`Signer` | CRITICAL |
| 2 | Unverified CPI program | `invoke\s*\(` with user-supplied program account | HIGH |
| 3 | `invoke_signed` without canonical bump | seeds without `bump` constraint | HIGH |
| 4 | `init` without `payer` / `space` | `init[^,]*\)` | HIGH |
| 5 | Hardcoded bump literal | `find_program_address` followed by `[&[2-5][0-9]*\]\]` | MEDIUM |
| 6 | Token op without mint verification | `mint_to\|burn\|token::transfer` without owner check | HIGH |
| 7 | Wrong `close =` target | `close\s*=\s*<user_supplied>` | CRITICAL |
| 8 | Arithmetic without `checked_*` | `+`/`-`/`*` on `u64` amounts | MEDIUM |
| 9 | Token-2022 fee math missing | `spl-token-2022` in `Cargo.toml` + raw amount math | MEDIUM |

If `Cargo.toml` includes `spl-token-2022`, also check: `mint_close_authority`, `metadata_pointer`, `transfer_fee`, `confidential_transfer` accounting.

Escalate severity if impact warrants (e.g., unchecked `+` on user balance → HIGH).

## Output

Default markdown (table of findings with file:line + ripgrep snippet).

With `--json`, emit `{ repo, scanned_at, files_scanned, findings: [{id, severity, file, line, title, snippet}] }`.

With `--severity CRITICAL,HIGH`, filter output.

## Limitations

**Heuristic — false positives expected.** Always confirm with `/audit` before acting. Use `/audit-quick` as:
- Initial triage on a new repo
- PR review sanity check
- Pre-screening before deep audit
