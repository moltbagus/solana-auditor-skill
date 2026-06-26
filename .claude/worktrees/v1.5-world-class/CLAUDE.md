# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Solana Auditor Shiba Skill

World-class Solana security auditor — 7-phase lifecycle, 26 path-scoped rules, 6 specialist agents, two-tier execution (SAST + runtime), compile-verified example fixture.

**Extends**: solana-dev-skill  
**Agents**: orchestrator, auditor, formal-verifier, report-writer, cross-program-agent  
**Commands**: `/audit`, `/audit-quick`, `/audit-resume`, `/audit-report`, `/audit-poc`, `/audit-findings`, `/audit-pr`, `/audit-history`

**Hooks**: `./scripts/pre-commit-audit.sh --install` (blocks commits on HIGH+ findings)

---

## Commands

```bash
# Install skill
./install.sh -y

# Demo (no Solana toolchain needed)
bash demo.sh

# Integrity checks (62 verification points)
bash tests/test-skill-integrity.sh

# Single category
bash tests/test-skill-integrity.sh 2>&1 | grep "Check 10"

# Fuzz tests (19 Hypothesis strategies)
python3 -m pytest tests/fuzz/ -v

# Single fuzz test
python3 -m pytest tests/fuzz/test_properties.py::test_cvss_vector_roundtrip -v
```

---

## Architecture

```
skill/SKILL.md (hub)
    ├─ skill/01-recon.md          # Phase 1: Attack surface
    ├─ skill/02-static-analysis.md # Phase 2A: Anchor/Token/CPI checks
    ├─ skill/02B-runtime-testing.md # Phase 2B: Runtime verification (Tier 2 only)
    ├─ skill/03-formal-verification.md  # Phase 3: QED 2A invariants
    ├─ skill/04-findings-triage.md      # Phase 4: CVSS scoring
    ├─ skill/05-report-generation.md     # Phase 5: Report output
    └─ skill/06-remediation.md          # Phase 6: Fix guidance

agents/
    ├─ orchestrator.md      # Entry point, routes to specialists
    ├─ auditor.md           # Primary audit execution
    ├─ formal-verifier.md    # Invariant proofs
    ├─ report-writer.md     # Structured findings → report
    └─ cross-program-agent.md  # CPI chain analysis

commands/
    ├─ audit.md, audit-quick.md, audit-resume.md
    ├─ audit-report.md, audit-poc.md, audit-findings.md
    └─ audit-pr.md, audit-history.md  # v1.6 additions

rules/audit.rules     # 26 path-scoped security rules (v1.5: 18-26 new)

scripts/
    ├─ generate-cpi-graph.sh  # CPI surface graph generator
    ├─ pre-commit-audit.sh    # Pre-commit hook (blocks HIGH+ findings)
    ├─ audit-history.sh        # Audit history DB manager
    └─ audit-fix-suggestions.py  # Inline fix suggestions from findings
```

### Agent Handoff Protocol

Orchestrator → Specialist:
```json
{"agent": "auditor", "phase": 2, "input_artifacts": [...], "context": "..."}
```

Specialist → Orchestrator:
```json
{"status": "ok", "outputs": [...], "next_agent": "formal-verifier", "notes": "..."}
```

---

## 26 Security Rules (Path-Scoped)

Rules auto-activate when editing matching file patterns. No command invocation needed.

| Rule | Triggers | Catches | Default |
|------|----------|---------|---------|
| 1 | `programs/**/src/lib.rs` | Privileged instruction surface | HIGH |
| 2 | `programs/**/*.rs` | Missing discriminator/owner/init | HIGH→CRIT |
| 3 | `programs/**/*.rs` | Hardcoded/non-canonical PDA bump | MED→CRIT |
| 4 | `programs/**/*.rs` | CPI escalation, unverified program ID | HIGH→CRIT |
| 5 | `programs/**/*.rs` + `Cargo.toml` | SPL vs Token-2022 mismatch | HIGH |
| 6 | `programs/**/*.rs` | Integer overflow on u64 amounts | MEDIUM |
| 7 | `programs/**/*.rs` | Lamport drain via wrong close target | CRITICAL |
| 8 | `programs/**/*.rs` | Unsigned privileged action | CRITICAL |
| 9 | `Anchor.toml` | Upgrade authority surface | MEDIUM |
| 10 | `programs/**/src/error.rs` | panic!, missing error mapping | LOW |
| 11 | `programs/**/src/state.rs` | Reinit without discriminator | CRITICAL |
| 12 | `programs/**/*.rs` | Rent exemption breaking | MEDIUM |
| 13 | `programs/**/*.rs` | Flash loan oracle manipulation | CRITICAL |
| 14 | `programs/**/*.rs` | Reentrancy (CEI violation) | CRITICAL |
| 15 | `programs/**/*.rs` | missing remaining_accounts validation | CRITICAL |
| 16 | `programs/**/*.rs` | Discriminator collision | CRITICAL |
| 17 | `programs/**/*.rs` | AccountLoader without owner check | HIGH |
| 18 | `programs/**/*.rs` | BorshDeserialize panic | HIGH |
| 19 | `programs/**/*.rs` | Anchor verify/address constraint bypass | HIGH |
| 20 | `programs/**/*.rs` | Token-2022 extension ordering | HIGH |
| 21 | `programs/**/*.rs` | CPI callback reentrancy | CRITICAL |
| 22 | `programs/**/*.rs` | init_if_needed + close race | CRITICAL |
| 23 | `programs/**/*.rs` | Memo program CPI injection | MEDIUM |
| 24 | `programs/**/*.rs` | remaining_accounts count mismatch | CRITICAL |
| 25 | `programs/**/*.rs` | Versioned transaction LUT manipulation | HIGH |
| 26 | `programs/**/*.rs` | Cross-program flash loan composition | CRITICAL |

Each rule cites CWE + real exploit references (Wormhole, Cashio, Crema, Mango, etc.).

---

## Critical Constraints

| Constraint | Rationale |
|------------|-----------|
| **PoC consent required** | Explicit user consent before executing any exploit code |
| **No auto-apply fixes** | Operator reviews and applies remediation |
| **No live exploit execution** | Consent gate enforced; mainnet requires owner authorization |
| **CVSS math verified** | `severity_counts.py:check_cvss_math()` recomputes from vectors |
| **VULN ↔ findings 1:1** | Every `// VULN-XX:` tag must have matching finding |

### Absolute Prohibitions
1. Never auto-apply security fixes without operator review
2. Never execute PoCs without explicit typed consent ("YES" or equivalent)
3. Never commit secrets/private keys to audit scope files
4. Never audit mainnet program without double-confirmation of program owner identity
5. Never write live exploit code in audit reports — reference PoC path only

---

## Severity Scale

| Level | Meaning | Examples |
|-------|---------|----------|
| CRITICAL | Total fund loss / authority bypass | `invoke` without signer, wrong close target |
| HIGH | Significant loss / major logic flaw | Integer overflow, CPI escalation |
| MEDIUM | Indirect loss path | Missing owner check, hardcoded bump |
| LOW | Minor / best practice | `panic!`, missing error codes |
| INFO | Documentation / code quality | Unnecessary complexity |

---

## Output Schema

Example fixture structure (`examples/sample-vulnerable-program/`):
```
programs/vault/src/lib.rs         # 10 VULN tags (VULN-01 to VULN-10)
programs/token-extensions/src/lib.rs  # 6 VULN tags (VULN-11 to VULN-16)
audit-output/
   ├─ findings.json              # Structured findings (6 total)
   ├─ AUDIT_REPORT.md            # Human-readable report
   ├─ quick-scan-results.md      # /audit-quick output
   └─ methodology-trace.md       # Phase-to-finding mapping
```

findings.json schema:
```json
{
  "id": "CRIT-01",
  "severity": "CRITICAL",
  "cvss": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cwe": "CWE-306",
  "title": "<finding-title>",
  "location": {"file": "path.rs", "line": 42, "function": "admin_withdraw"},
  "description": "<technical-description>",
  "impact": "<concrete-impact>",
  "recommendation": "<fix-guidance>",
  "poc_status": "pending | confirmed | verified | fixed | disproved",
  "rule_caught": "Rule 8",
  "status": "Open"
}
```

---

## File Contracts

| File | Contract |
|------|----------|
| `tests/test-skill-integrity.sh` | Single source of truth for fixture paths (`VAULT_SRC`, `TOKEN_SRC`) |
| `tests/severity_counts.py` | Validates findings.json → AUDIT_REPORT.md consistency + CVSS math |
| `rules/audit.rules` | 1:1 mapping: every rule → one `**References:**` block with CWE URL |
| `skill/0N-*.md` | Filename prefix must match `# Phase N:` heading |

---

## CVSS Scoring

All scores are **mathematically verified** from vectors using CVSS 3.1 formula:
```python
# In tests/severity_counts.py
check_cvss_math()  # Recomputes score from vector, flags mismatch
```

Example vector → score mapping:
- `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → **9.8** (CRITICAL)

---

## Two-Tier Execution Model

The skill auto-detects available toolchain and runs accordingly:

| Tier | Tools Available | What Runs | When |
|------|----------------|-----------|------|
| **Tier 1 (SAST)** | None required | 26 rules, cargo-audit, CPI graph | Any machine |
| **Tier 2 (Full)** | anchor + solana CLI | Tier 1 + Phase 2B (anchor test, banks_client fuzz, QED 2A) | When toolchain present |

Detected in Phase 1 via:
```bash
if command -v anchor &> /dev/null && command -v solana &> /dev/null; then
    TIER2_ENABLED=true
fi
```

---

## Tool Requirements

- **Tier 1** (SAST only): `rustc` 1.75+, `cargo-audit` (recommended)
- **Tier 2** (full runtime): above + `anchor-cli` 0.31.1 + `solana-cli` 2.x
- QED 2A (optional — phase 3 formal verification)

Local toolchain setup:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
cargo install --git https://github.com/coral-xyz/anchor --tag v0.31.1 anchor-cli --locked
```
