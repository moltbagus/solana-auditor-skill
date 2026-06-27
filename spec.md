# Spec — Solana Auditor Skill

> **Technical Specification**
> _Version 1.8.1 — Dashboard + Exploit Simulation_
> Last updated: 2026-06-27

---

## 1. System Architecture

### 1.1 Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      Claude Code CLI                           │
│  ┌───────────────────────────────────────────────────────┐   │
│  │             solana-auditor-skill Skill                  │   │
│  │  ┌──────────────┐  ┌───────────┐  ┌────────────────┐  │   │
│  │  │ Orchestrator  │→ │  Auditor  │→ │ Skill Files    │  │   │
│  │  │  Agent       │  │  Agent    │  │ (7 phases)     │  │   │
│  │  └───────┬──────┘  └─────┬─────┘  └────────────────┘  │   │
│  │          │                │                             │   │
│  │  ┌───────┴────────┐  ┌───┴──────┐                     │   │
│  │  │ Formal-Verif   │  │ Report   │                     │   │
│  │  │ Agent          │  │ Writer   │                     │   │
│  │  └────────────────┘  └──────────┘                     │   │
│  │  ┌────────────────────────────────────────────────┐   │   │
│  │  │ Cross-Program Agent (CPI surface + validation)     │   │   │
│  │  └────────────────────────────────────────────────┘   │   │
│  │  ┌────────────────────────────────────────────────┐   │   │
│  │  │ Rules Engine (50 path-scoped rules)             │   │   │
│  │  └────────────────────────────────────────────────┘   │   │
│  │  ┌────────────────────────────────────────────────┐   │   │
│  │  │ Commands (9 slash commands)                     │   │   │
│  │  └────────────────────────────────────────────────┘   │
│  │  ┌────────────────────────────────────────────────┐   │
│  │  │ Integrity (32 checks) + Fuzz (22 tests)          │   │
│  │  └────────────────────────────────────────────────┘   │
│  └───────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Kit Submission v1.8.1**: Added HTML audit dashboard generator (`scripts/dashboard.py`), standalone report CLI (`scripts/audit-report.py`), `demo.sh` step 7 auto-generates dashboard. All 9 commands have `name:` frontmatter for Claude Code registration.

```

### 1.2 Data Flow

```
User Input
  │
  ▼
Orchestrator Agent ──► Intent matching ──► Phase routing
  │                                                │
  ▼                                                ▼
Skill Files (00-06) ──► Agent execution ──► Findings DB
  │                                                │
  ▼                                                ▼
Phase 2B Runtime ──► CPI Surface Graph ──► Cross-Program Analysis
                                                    │
                                              ┌─────┴─────┐
                                              ▼           ▼
                                    runtime_findings.json  cross_program_findings.json
                                                    │
                                                    ▼
                                            Report Writer
                                                    │
                                          ┌─────────┴──────────┐
                                          ▼                    ▼
                                    findings.json     AUDIT_REPORT.md
                                              + methodology-trace.md
```

### 1.3 Two-Tier Execution Model

| Tier | Mode | Phases | Use Case |
|------|------|--------|----------|
| **Tier 1** | SAST-only | 0, 1, 2, 4, 5, 6 | Quick audit, no toolchain required |
| **Tier 2** | Full runtime | 0, 1, 2, 2B, 3, 4, 5, 6 | Comprehensive audit with validator |

Tier 1 runs without Solana toolchain. Tier 2 enables:
- Runtime verification via Solana test validator
- CPI transaction replay with Helius API
- QED 2A formal verification with fallback chain
- cargo-audit dependency vulnerability scan

---

## 2. Agent Contracts

### 2.1 Orchestrator → Specialist Handoff

```json
{
  "agent": "<specialist-name>",
  "phase": "1-6 | 2B",
  "input_artifacts": ["<path>"],
  "expected_outputs": ["<path>"],
  "context": "<user-request-summary>"
}
```

### 2.2 Specialist → Orchestrator Response

```json
{
  "status": "ok | needs_input | failed",
  "outputs": ["<path>"],
  "next_agent": "<name | null>",
  "notes": "<free-form>"
}
```

### 2.3 Agent Roster (6 specialists)

| Agent | Role | Primary Phase |
|-------|------|---------------|
| orchestrator | Entry point, routes to specialists | All |
| auditor | Primary audit execution | 1, 2, 2B |
| formal-verifier | Invariant proofs, QED 2A | 3 |
| report-writer | Structured findings → report | 5 |
| cross-program | CPI surface graph, cross-program analysis | 2B |
| safety-guard | Agent safety guardrails, prevents harmful ops | 0 |

---

## 3. Findings Database Schema

### 3.1 JSON Schema (findings.json)

```json
{
  "findings": [
    {
      "id": "VULN-01",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
      "cvss": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cwe": "CWE-306",
      "title": "<finding-title>",
      "location": {
        "file": "programs/vault/src/lib.rs",
        "line": 142,
        "function": "admin_withdraw"
      },
      "description": "<technical-description>",
      "impact": "<concrete-impact>",
      "recommendation": "<fix-guidance>",
      "poc_status": "pending | confirmed | verified | fixed | disproved",
      "rule_caught": "<rule-number | null>",
      "status": "Open"
    }
  ],
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
    "total": 0
  }
}
```

### 3.2 Runtime Findings Schema (runtime_findings.json)

```json
{
  "runtime_findings": [
    {
      "id": "RT-01",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "cvss": 8.1,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
      "cwe": "CWE-682",
      "title": "<runtime-finding-title>",
      "location": {
        "file": "programs/vault/src/lib.rs",
        "line": 89,
        "function": "process_instruction"
      },
      "description": "<transaction-replay-description>",
      "impact": "<runtime-impact>",
      "recommendation": "<runtime-fix>",
      "reproduced": true,
      "tier": "Tier 2"
    }
  ],
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "total": 0
  }
}
```

### 3.3 Cross-Program Findings Schema (cross_program_findings.json)

```json
{
  "cross_program_findings": [
    {
      "id": "CPI-01",
      "severity": "HIGH",
      "cvss": 7.5,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
      "cwe": "CWE-347",
      "title": "<CPI-finding-title>",
      "source_program": "<program_id>",
      "target_program": "<program_id>",
      "instruction": "instruction_name",
      "accounts": ["<account>"],
      "privilege_escalation": true,
      "description": "<CPI-analysis-description>",
      "impact": "<cross-program-impact>",
      "recommendation": "<CPI-fix>",
      "rule_caught": "Rule 4",
      "tier": "Tier 2"
    }
  ],
  "cpi_surface": {
    "total_cpi_calls": 0,
    "programs_invoked": [],
    "unchecked_programs": []
  }
}
```

---

## 4. Integrity Check Specification

### 4.1 Current Checks (93+ PASS points, 33+ named categories)

| Check | Description | PASS Points | Verification |
|-------|-------------|-------------|-------------|
| 1 | Phase file numbering | 7 | Filename matches `# Phase N:` heading |
| 2 | Command cross-refs | 1 | All referenced paths exist |
| 3 | Vault VULN ↔ findings | 4 | Every VULN-XX has a finding + audit files exist |
| 4 | CWE format | 1 | 50 CWE refs valid + point to mitre.org |
| 5 | Rules/Refs 1:1 | 1 | 50 rules = 50 References blocks |
| 6 | Summary ↔ counts | 2 | findings.json summary matches actual (all fixtures) |
| 7 | Report ↔ findings | 2 | AUDIT_REPORT.md counts match findings.json (all fixtures) |
| 8 | CVSS consistency | 2 | Score + vector match across files (all fixtures) |
| 9 | Agent consistency | 3 | Docs match agents/ directory (all 6 agents) |
| 10 | CVSS math | 2 | Scores derivable from vectors (all fixtures) |
| 11 | Phase chaining | 5 | Each phase references next |
| 12 | Quick-scan alignment | 1 | Pattern numbers match commands |
| 13 | Agent YAML | 4 | All 6 agents have frontmatter |
| 14 | Fuzz tests pass | 1 | 19 property-based tests pass |
| 15 | PT-BR glossary | 1 | ≥5 PT-BR references in terminology file |
| 16 | SDD files present | 5 | PRD, Spec, Kanban, Learnings present |
| 17 | Demo script exists | 1 | demo.sh present and executable |
| 18 | Token-2022 VULN coverage | 4 | Every VULN-XX has a finding + audit files exist |
| 19 | Methodology-trace CVSS | 2 | Trace CVSS scores match findings.json (all fixtures) |
| 20 | Two-tier execution paths | 3 | Tier 1 bypasses Phase 2B/3 correctly |
| 21 | CPI surface graph format | 2 | cross_program_findings.json schema valid |
| 22 | Runtime findings schema | 2 | runtime_findings.json schema valid |
| 23 | Helius API integration | 2 | Recon phase includes Helius curl template |
| 24 | cargo-audit integration | 2 | Recon phase includes cargo audit check |
| 25 | Cross-program agent presence | 2 | agents/cross-program.md exists + YAML frontmatter |
| 26 | Phase 2B routing | 3 | Tier 2 routes through 2B, Tier 1 skips |
| 27 | QED 2A fallback chain | 2 | Formal verification has QED fallback |
| 28 | New rules coverage | 6 | Rules 18-26 have VULN tags in fixtures |
| 29 | Transfer Hook rules coverage | 9 | Rules 27-35 have VULN tags in fixtures |
| 30 | Native/Pinocchio rules coverage | 10 | Rules 36-45 have VULN tags in fixtures |
| 31 | Agent safety guardrails coverage | 5 | Rules 46-50 have VULN tags in fixtures |
| 32 | Phase 0 safety guard presence | 3 | skill/00-safety-guard.md exists + YAML frontmatter |
| 33 | Safety-guard agent presence | 2 | agents/safety-guard.md exists + YAML frontmatter |

### 4.2 Verification Methods

| Method | Tool | When |
|--------|------|------|
| Markdown structure | ripgrep + shell assertions | Every CI run |
| JSON validity | Python json.load | Every CI run |
| CVSS math | `tests/severity_counts.py check-cvss-math` | Every CI run |
| Count consistency | `tests/severity_counts.py check-summary` / `check-report` | Every CI run |
| Cross-file consistency | `tests/severity_counts.py check-cvss` | Every CI run |
| Property-based invariants | Hypothesis (19 tests, 1000s of examples) | Every CI run |
| Trace CVSS consistency | `check_trace_cvss_for_fixture()` in bash | Every CI run |
| Schema validation | Python jsonschema | Tier 2 findings |

---

## 5. Rules Engine Design

### 5.1 Rule Lifecycle

```
File opened → Path-matched against rules/audit.rules
  → Matching rules injected into system prompt
  → Rules apply to all responses for that file
  → On file close: rules are removed from prompt
```

### 5.2 Severity Defaulting Matrix

```python
DEFAULTS = {
    "unsigned_privileged_action": "CRITICAL",
    "unsigned_invoke_transfer": "CRITICAL",
    "wrong_close_target": "CRITICAL",
    "wrong_token_program": "HIGH",
    "missing_init_payer_space": "HIGH",
    "unverified_cpi_program": "HIGH",
    "missing_checked_arith": "MEDIUM",
    "hardcoded_pda_bump": "MEDIUM",
    "missing_token_fee_math": "MEDIUM",
    "panic_in_instruction": "LOW",
    "missing_error_mapping": "LOW",
    "unwrap_on_cpi": "MEDIUM",
    "flash_loan_oracle_manip": "CRITICAL",
    "reentrancy_cei_violation": "CRITICAL",
    "missing_remaining_accounts": "CRITICAL",
    "discriminator_collision": "CRITICAL",
    "account_loader_no_owner": "HIGH",
    # v1.5 additions
    "type_confusion": "CRITICAL",
    "unsafe_unchecked_account": "HIGH",
    "cpi_signer_propagation": "CRITICAL",
    "pda_signer_confusion": "HIGH",
    "mint_authority_bypass": "CRITICAL",
    "delegate_authority_abuse": "HIGH",
    "close_authority_drain": "CRITICAL",
    "token_metadata_tamper": "HIGH",
    "confidential_transfer_fee_leak": "MEDIUM",
}
```

### 5.3 Security Rules (v1.7 — 50 total rules)

#### 5.3.1 Core Rules 1-17 (v1.0–v1.4)

| Rule | Triggers | Catches | Default |
|------|----------|---------|---------|
| 1 | `programs/**/*.rs` | Missing owner check | HIGH |
| 2 | `programs/**/*.rs` | Missing signer check | CRITICAL |
| 3 | `programs/**/*.rs` | Missing token check | HIGH |
| 4 | `programs/**/*.rs` | Missing freeze authority | MEDIUM |
| 5 | `programs/**/*.rs` | Missing mint checks | HIGH |
| 6 | `programs/**/*.rs` | Unchecked math | HIGH |
| 7 | `programs/**/*.rs` | Missing instruction data validation | MEDIUM |
| 8 | `programs/**/*.rs` | Wrong close target | CRITICAL |
| 9 | `programs/**/*.rs` | Missing reinit guard | HIGH |
| 10 | `programs/**/*.rs` | Missing CPI trust verification | HIGH |
| 11 | `programs/**/*.rs` | Missing admin checks | HIGH |
| 12 | `programs/**/*.rs` | Missing PDA verification | MEDIUM |
| 13 | `programs/**/*.rs` | Missing rent exemption | MEDIUM |
| 14 | `programs/**/*.rs` | Wrong token program | HIGH |
| 15 | `programs/**/*.rs` | Missing init payer | MEDIUM |
| 16 | `programs/**/*.rs` | Missing checked arithmetic | MEDIUM |
| 17 | `programs/**/*.rs` | Missing token fee math | MEDIUM |

#### 5.3.2 Phase 1: Transfer Hook (Rules 27-35)

| Rule | Triggers | Catches | Default |
|------|----------|---------|---------|
| 27 | `programs/**/*.rs` | Transfer hook unauthorized extra data | HIGH |
| 28 | `programs/**/*.rs` | Transfer hook callback reentrancy | HIGH |
| 29 | `programs/**/*.rs` | Transfer hook account validation | HIGH |
| 30 | `programs/**/*.rs` | Transfer hook privilege escalation | CRITICAL |
| 31 | `programs/**/*.rs` | Transfer hook state corruption | CRITICAL |
| 32 | `programs/**/*.rs` | Transfer hook oracle manipulation | HIGH |
| 33 | `programs/**/*.rs` | Transfer hook missing access control | HIGH |
| 34 | `programs/**/*.rs` | Transfer hook insufficient reserves | MEDIUM |
| 35 | `programs/**/*.rs` | Transfer hook overflow/underflow | HIGH |

#### 5.3.3 Phase 2: Pinocchio/Native Programs (Rules 36-45)

| Rule | Triggers | Catches | Default |
|------|----------|---------|---------|
| 36 | `programs/**/*.rs` | System program unauthorized use | CRITICAL |
| 37 | `programs/**/*.rs` | Sysvar account mismatch | HIGH |
| 38 | `programs/**/*.rs` | Secp256k1 signature validation | HIGH |
| 39 | `programs/**/*.rs` | Keccak hash collision | MEDIUM |
| 40 | `programs/**/*.rs` | Native program privilege escalation | CRITICAL |
| 41 | `programs/**/*.rs` | Invalid slot hash lookup | MEDIUM |
| 42 | `programs/**/*.rs` | Vote program unauthorized instruction | HIGH |
| 43 | `programs/**/*.rs` | Stake program delegate mismatch | HIGH |
| 44 | `programs/**/*.rs` | System instruction ambiguity | MEDIUM |
| 45 | `programs/**/*.rs` | BPF loader version confusion | MEDIUM |

#### 5.3.4 Phase 3: Agent Safety Guardrails (Rules 46-50)

| Rule | Triggers | Catches | Default |
|------|----------|---------|---------|
| 46 | `commands/**/*.sh` | Command injection in shell | CRITICAL |
| 47 | `commands/**/*.sh` | Unsafe environment variable exposure | HIGH |
| 48 | `commands/**/*.sh` | Unverified artifact execution | CRITICAL |
| 49 | `commands/**/*.sh` | Secrets in logs/stdout | CRITICAL |
| 50 | `commands/**/*.sh` | Sandbox escape attempt | CRITICAL |

#### 5.3.5 Rules 18-26 (v1.5 Additions)

| Rule | Triggers | Catches | Default |
|------|----------|---------|---------|
| 18 | `programs/**/*.rs` | Type confusion (struct identity) | CRITICAL |
| 19 | `programs/**/*.rs` | Unsafe UncheckedAccount usage | HIGH |
| 20 | `programs/**/*.rs` | CPI signer propagation failure | CRITICAL |
| 21 | `programs/**/*.rs` | PDA signer vs wallet confusion | HIGH |
| 22 | `programs/**/*.rs` | Mint authority bypass | CRITICAL |
| 23 | `programs/**/*.rs` | Delegate authority abuse | HIGH |
| 24 | `programs/**/*.rs` | Close authority drain (rev2) | CRITICAL |
| 25 | `programs/**/*.rs` | Token metadata tampering | HIGH |
| 26 | `programs/**/*.rs` | Confidential transfer fee leak | MEDIUM |

---

## 6. Property-Based Testing Design

### 6.1 Fuzz Targets (19 tests)

| Test | Property Verified | Examples Generated |
|------|------------------|-------------------|
| P1 | CVSS score in [0.0, 10.0] | 200 random vectors |
| P2 | Score is multiple of 0.1 (roundUp) | 200 random vectors |
| P3 | Parse roundtrip is idempotent | 200 random vectors |
| P4 | Scope:C >= Scope:U (all else equal) | 100 metric combinations |
| P5 | AV:Pseudo > AV:L (all else equal) | 100 metric combinations |
| P6 | Base score maxes at 10.0 | 200 corner-case vectors |
| P7 | Severity thresholds: 9.0+ CRIT, 7.0-8.9 HIGH, 4.0-6.9 MED, <4.0 LOW | 200 random |
| P8 | Vector roundtrip preserves original | 500 vectors |
| P9 | cvss_to_severity roundtrip | 200 vectors |
| P10 | Vector string format validation | 300 malformed inputs |
| P11 | Finding ID uniqueness | 1000 ID combinations |
| P12 | Summary totals match findings array | 200 finding sets |
| P13 | Line numbers stay within source bounds | 300 VULN placements |
| P14 | CWE URL format validation | 100 CWE references |
| P15 | PoC status enum validation | 100 status transitions |
| P16 | VULN-ID sequence continuity | 100 fixture checks |
| P17 | Report heading count matches severity | 100 reports |
| P18 | Findings.json schema keys present | 100 missing-key tests |
| P19 | Agent handoff JSON roundtrip | 200 handoff objects |

---

## 7. CPI Surface Graph

### 7.1 Graph Structure

```
CPI Call Graph (directed, multi-edge):
  Program A
    ├─invoke─► Program B (token mint)
    ├─invoke─► Program C (bridge)
    └─invoke_signed─► Program D (vault PDA)
```

### 7.2 Analysis Outputs

- `cpi_surface.total_cpi_calls`: Count of all invoke/invoke_signed
- `cpi_surface.programs_invoked`: Unique program IDs
- `cpi_surface.unchecked_programs`: Programs not whitelisted
- `cpi_surface.signer_propagation`: Accounts passed as signers to callee

---

## 8. QED 2A Fallback Chain

### 8.1 Verification Priority

1. **QED 2A primary** — If qed-solana installed, run invariant proofs
2. **Anchor test fallback** — If anchor available, run integration tests
3. **Manual assertion fallback** — Static analysis with runtime assertions

### 8.2 Fallback Detection

```bash
# Check QED 2A
qed-solana --version 2>/dev/null && USE_QED=true || USE_QED=false

# Check Anchor
anchor --version 2>/dev/null && USE_ANCHOR=true || USE_ANCHOR=false

# Fallback chain
if $USE_QED; then
    qed-solana prove --invariants <file>
elif $USE_ANCHOR; then
    anchor test --skip-local-validator
else
    echo "QED 2A not available — manual assertion mode"
fi
```
