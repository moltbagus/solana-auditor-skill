# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Solana Auditor Shiba Skill

Submission-grade Solana security auditor — 7-phase lifecycle (Phase 0 Safety Guard + Phases 1–6), 45 path-scoped rules + 5 agent-safety rules, 9 specialist agents, compile-verified example fixtures, 47 integrity checks, 22 fuzz tests.

**Extends**: solana-dev-skill  
**Agents**: orchestrator, auditor, architecture-reviewer, threat-modeler, economic-security-analyst, formal-verifier, report-writer, cross-program-agent, safety-guard  
**Commands**: `/audit`, `/audit-quick`, `/audit-resume`, `/audit-report`, `/audit-poc`, `/audit-findings`, `/audit-fix`, `/audit-history`, `/audit-pr`  
**References**: `references/LIMITATIONS.md` — honest coverage ceiling (business-logic gaps are outside SAST scope)
**Automation**: pre-commit hook (`scripts/pre-commit-audit.sh`), PR auditing (`/audit-pr`), audit history DB (`scripts/audit-history.sh`), inline fix suggestions (`scripts/audit-fix-suggestions.py`), SARIF export (`scripts/export-sarif.py`)


---

## Commands

```bash
# Install skill
./install.sh -y

# Demo (no Solana toolchain needed)
bash demo.sh

# Integrity checks (153 verification points — all pass)
bash tests/test-skill-integrity.sh

# Single category
bash tests/test-skill-integrity.sh 2>&1 | grep "Check 10"

# Fuzz tests (22 Hypothesis strategies)
python3 tests/fuzz/test_properties.py

# Single fuzz test
python3 -c "import pytest; pytest.main(['-v', 'tests/fuzz/test_properties.py', '-k', 'test_cvss_vector_roundtrip'])"
```

---

## Architecture

```
skill/SKILL.md (hub)
    ├─ skill/00-safety-guard.md       # Phase 0: Safety pre-flight
    ├─ skill/01-recon.md               # Phase 1: Attack surface
    ├─ skill/02-static-analysis.md     # Phase 2: SAST (Rules 1–50)
    ├─ skill/03-formal-verification.md  # Phase 3: QED 2A invariants
    ├─ skill/04-findings-triage.md     # Phase 4: CVSS scoring
    ├─ skill/05-report-generation.md    # Phase 5: Report output
    └─ skill/06-remediation.md        # Phase 6: Fix guidance

agents/
    ├─ orchestrator.md       # Entry point, routes to specialists
    ├─ auditor.md            # Primary audit execution
    ├─ formal-verifier.md    # Invariant proofs
    ├─ report-writer.md      # Structured findings → report
    ├─ cross-program-agent.md # CPI chain analysis
    └─ safety-guard.md       # Phase 0 consent / scope guard

commands/
    ├─ audit.md, audit-quick.md, audit-resume.md
    ├─ audit-report.md, audit-poc.md, audit-findings.md
    ├─ audit-fix.md, audit-pr.md, audit-history.md

rules/audit.rules     # 50 path-scoped security rules (Rules 1–50)
references/
    └─ LIMITATIONS.md   # Honest coverage ceiling
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

## 50 Security Rules (Path-Scoped, 4 Groups)

Rules auto-activate when editing matching file patterns. No command invocation needed.

| Rule | Triggers | Catches | Default |
|------|----------|---------|---------|
| **1–26: Anchor Core** |
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
| 11 | `programs/**/*.rs` | Reinit without discriminator | CRITICAL |
| 12 | `programs/**/*.rs` | Rent exemption breaking | MEDIUM |
| 13 | `programs/**/*.rs` | Flash loan oracle manipulation | CRITICAL |
| 14 | `programs/**/*.rs` | Reentrancy (CEI violation) | CRITICAL |
| 15 | `programs/**/*.rs` | Missing remaining_accounts validation | CRITICAL |
| 16 | `programs/**/*.rs` | Discriminator collision | CRITICAL |
| 17 | `programs/**/*.rs` | AccountLoader without owner check | HIGH |
| 18–26 | `programs/**/*.rs` | Extended Anchor coverage | Various |
| **27–35: Token-2022 Transfer Hook** |
| 27 | `programs/**/*.rs` | Missing TransferHook account validation | HIGH→CRIT |
| 28 | `programs/**/*.rs` | CPI to transfer hook without extra_accounts | HIGH |
| 29–35 | `programs/**/*.rs` | Extension-specific bypass patterns | HIGH→CRIT |
| **36–45: Pinocchio / Native Solana** |
| 36 | `programs/**/*.rs` | Missing/unchecked sysvar account | HIGH→CRIT |
| 37–44 | `programs/**/*.rs` | Runtime / sealevel patterns | Various |
| 45 | `programs/**/*.rs` | Confidential transfer proof bypass | HIGH |
| **46–50: AI Agent Safety** |
| 46–50 | Skill operations | Pre-flight, scope, consent, audit trail | N/A |

Each rule cites CWE + real exploit references (Wormhole, Cashio, Crema, Mango, Raydium, Tulip, Nirvana, Neodyme, etc.). Full list in `rules/audit.rules`.

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

## Tool Requirements

- `anchor-cli` 0.31.1 (example fixture built against this version)
- `solana-cli` 2.x
- `rustc` 1.75+
- QED 2A (optional — phase 3 formal verification)

Local toolchain setup:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
cargo install --git https://github.com/coral-xyz/anchor --tag v0.31.1 anchor-cli --locked
```
