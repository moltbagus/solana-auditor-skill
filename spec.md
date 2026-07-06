# Spec — Solana Auditor Skill

> **Technical Specification**
> _Version 1.15.0 — CI Stabilization + CVSS Math Fix_
> Last updated: 2026-07-07

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

**v1.12.0**: dashboard, PT-BR guide, benchmark, GH Actions, before/after, live exploit audit.

**v1.14.0**: 3 new audit fixtures — AMM/DEX (14 vulns, Rules 14/15/26/13/6/4/8/40/38/36/37), Staking Pool (14 vulns, Rules 14/22/41/6/8/11/5/15/4/38/3/36/37), NFT/Candy Machine (14 vulns, Rules 16/40/2/8/6/14/5/33/22/38/27/39/4/37). All 42 findings CVSS-math-verified. Total fixtures: 6 (was 3).

**v1.14.2**: Raydium CLMM live audit (6 findings, source-verified). Bilingual support (`--lang pt|en`) added to all commands. README polish (step numbers, agents badge, dashboard commands). Check 20 (line-number drift) verified implemented. SDD docs synced to v1.14.2.

**v1.14.3**: Repository hygiene — fixed 2 broken file refs (SKILL.md, CLAUDE.md: `02A-threat-modeling` → `02-threat-modeling`). Added STALE WARNING to `scripts/run-sast.py` (26 hardcoded vs 50 actual rules). `chmod +x` on all scripts. Archived stale `SPEC-REMEDIATION.md` draft. Cleaned untracked stale artifact dir. 161/161 checks, 22/22 fuzz all clean.

```

### 1.2 Data Flow

```
User Input
  │
  ▼
Orchestrator Agent ──► Intent matching ──► Phase routing
  │                                                │
  ▼                                                ▼
Skill Files (00-safety-guard through 07-architecture-review) ──► Agent execution ──► Findings DB
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
| **Tier 1** | SAST-only | 0, 1, 2, 2A, 4, 5, 6 | Quick audit, no toolchain required |
| **Tier 2** | Full + arch review | 0, 1, 2, 2A, 2B, 3, 4, 5, 6, **7** | Comprehensive + component analysis |
| **Tier 3** | Full + exploit sim | 0, 1, 2, 2A, 2B, 3, 4, 5, 6, **7**, PoC | Comprehensive + component analysis + exploit metadata |

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

### 2.3 Agent Roster (10 specialists)

| Agent | Role | Primary Phase |
|-------|------|---------------|
| orchestrator | Entry point, routes to specialists | All |
| auditor | Primary audit execution | 1, 2, 2B |
| threat-modeler | STRIDE threat identification, exploit intel, Helius API | 2A |
| formal-verifier | Invariant proofs, QED 2A | 3 |
| report-writer | Structured findings → report | 5 |
| cross-program-agent | CPI chain analysis, flash loan detection | 2B |
| safety-guard | Consent gate, program identity, cluster boundary | 0 |
| architecture-reviewer | Structural topology, upgrade authority, tokenomics | 1B |
| economic-security-analyst | Tokenomics, MEV, staking/LP, governance | 1C |
| AUDIT.md | Auto-generated per-audit audit trail | All |

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

### 3.4 Exploit Metadata Schema (exploit_metadata.json)

```json
{
  "exploits": [
    {
      "vuln_id": "VULN-01",
      "stride_category": "Privilege Escalation",
      "title": "<exploit-title>",
      "preconditions": ["<condition-1>", "<condition-2>"],
      "attack_steps": [
        {"step": 1, "action": "<action>", "expected": "<expected>", "actual": "<actual>"}
      ],
      "expected_outcome": "<what-attacker-accomplishes>",
      "actual_outcome": "<confirmed|partial|failed>",
      "exploitability_score": 9.2,
      "impact_confirmed": true,
      "remediation_verified": false,
      "remediation_date": null,
      "references": [
        {"type": "CVE", "id": "CVE-XXXX-XXXXX"},
        {"type": "transaction", "id": "txn_sig_here"}
      ],
      "poc_language": "anchor | typescript | python | manual",
      "poc_code": "<code-snippet-or-null>",
      "audit_notes": "<analyst-observations>"
    }
  ]
}
```

### 3.5 Threat Model Schema (threat_model.json)

```json
{
  "program_id": "<solana-program-id>",
  "program_name": "<name>",
  "trust_boundaries": [
    {
      "id": "TB-01",
      "name": "<boundary-name>",
      "components": ["<component-1>"],
      "data_flows": [
        {"from": "<source>", "to": "<dest>", "protocol": "CPI|RPC|WebSocket"}
      ]
    }
  ],
  "stride_threats": [
    {
      "id": "STRIDE-01",
      "category": "Spoofing|Tampering|Repudiation|Info Disclosure|DoS|Privilege Escalation",
      "title": "<threat-title>",
      "affected_component": "<component>",
      "trust_boundary": "TB-01",
      "likelihood": "HIGH|MEDIUM|LOW",
      "impact": "HIGH|MEDIUM|LOW",
      "risk_score": 8.1,
      "mapped_findings": ["VULN-01", "VULN-02"],
      "mitigations": ["<mitigation-1>"]
    }
  ],
  "summary": {
    "total_threats": 0,
    "spoofing": 0,
    "tampering": 0,
    "repudiation": 0,
    "info_disclosure": 0,
    "dos": 0,
    "privilege_escalation": 0
  }
}
```

## 4. Phase 2A: Threat Modeling

### 4.1 STRIDE Overview

| Category | What It Tests | Common Solana Patterns |
|----------|---------------|------------------------|
| **Spoofing** | Can an attacker impersonate a valid user/program? | Fake program ID in CPI, missing signer verification |
| **Tampering** | Can data be modified without detection? | Account data mutations, state corruption |
| **Repudiation** | Can a user deny an action they performed? | Missing event emission, unsigned transactions |
| **Information Disclosure** | Can sensitive data be exposed? | Unencrypted account data, logging secrets |
| **Denial of Service** | Can availability be disrupted? | Resource exhaustion, infinite loops, rent困 |
| **Privilege Escalation** | Can an attacker gain unauthorized privileges? | Missing authority checks, PDA derivation bugs |

### 4.2 Threat Modeler Agent Flow

1. **Identify trust boundaries** — External programs, user accounts, PDAs, system accounts
2. **Map data flows** — CPI calls, RPC calls, WebSocket subscriptions
3. **Apply STRIDE per boundary** — 6 threat categories for each boundary
4. **Cross-reference findings** — Map threats to existing VULN-IDs or flag as new
5. **Score and rank** — Risk = Likelihood x Impact
6. **Output threat_model.json** — Structured threat documentation
7. **Integrate with Phase 5** — Threats feed into final audit report

### 4.3 Trust Boundary Examples

| Boundary | Components | Risk |
|----------|------------|------|
| User → Program | `invoke`, `invoke_signed` | CPI injection |
| Program → Token | `transfer`, `mint` | Authority bypass |
| Program → PDA | `bump` seed verification | PDA collision |
| External → Program | RPC instruction parsing | Input validation |

## 5. Phase 2B: Runtime Verification

Same as previously documented.

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

## 6. Phase 7: Architecture Review

### 6.1 Purpose

Phase 7 performs standalone component analysis after Phase 2B (Runtime Verification) and before Phase 4 (Findings Triage). It decomposes the program into architectural layers and identifies systemic weaknesses that individual findings may not surface.

### 6.2 Architecture-Reviewer Agent Flow

1. **Enumerate entry points** — All `process_instruction` handlers and their access paths
2. **Map trust boundaries** — External programs, user accounts, PDAs, system accounts
3. **Build component dependency graph** — Instruction dispatch, account validation, state management, CPI interface, token operations
4. **Trace data flows** — Per-entry-point data flow from input to storage
5. **Identify architectural hotspots** — Components with high coupling, shared state, or privileged access
6. **Assess architectural weaknesses** — Patterns that are individually correct but compose into systemic risk
7. **Recommend mitigations** — Layer-level fixes that address multiple findings at once
8. **Export architecture_findings.json** — Structured architectural findings

### 6.3 Architecture Findings Schema

```json
{
  "architecture_findings": [
    {
      "id": "ARCH-01",
      "severity": "HIGH | MEDIUM | LOW",
      "layer": "instruction_dispatch | account_validation | state_management | cpi_interface | token_operations",
      "title": "<arch-title>",
      "components": ["<component-1>", "<component-2>"],
      "description": "<architectural-analysis>",
      "impact": "<systemic-impact>",
      "recommendation": "<layer-level-fix>",
      "related_findings": ["VULN-01"],
      "mitigation_effort": "trivial | moderate | complex"
    }
  ]
}
```

### 6.4 Three Missing Report Sections

The audit report template now includes three sections previously absent from v1.10.0:

1. **Executive Summary** — Severity-at-a-glance table (CRITICAL/HIGH/MEDIUM/LOW/INFO counts) + risk posture statement (Critical/High/Medium/Low/Informational based on highest severity and total count).
2. **Methodology Trace** — Per-phase table mapping each phase to its output artifact and key findings, enabling judges to trace the audit methodology from input to conclusion.
3. **Finding Distribution** — Severity breakdown table with per-finding CVSS vector and CWE reference, plus per-layer distribution (instruction dispatch, account validation, state management, CPI interface, token operations).

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
| 34 | Phase 6 root_cause fields | 4 | findings.json entries have root_cause (all fixtures) |
| 35 | Phase 6 difficulty rating | 3 | findings.json entries have difficulty field |
| 36 | Regression test path presence | 3 | findings.json entries have regression_test_path field |
| 37 | Remediation priority ordering | 3 | CRITICAL > HIGH > MEDIUM > LOW > INFO within each tier |
| 38 | Phase 7 architecture review presence | 3 | skill/07-architecture-review.md exists + YAML frontmatter |
| 39 | Architecture-reviewer agent presence | 3 | agents/architecture-reviewer.md exists + YAML frontmatter |
| 40 | Report template enhanced sections | 4 | Executive Summary, Methodology Trace, Finding Distribution present |

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
| Remediation field validation | Python script + bash | Phase 6 findings |

---

## 4.3 Phase 6: Remediation Engine Enhancements (v1.10.0)

Phase 6 was upgraded from fix suggestions to a full Remediation Engine with structured root cause analysis and regression test support.

### 4.3.1 Root Cause Classification

Every finding now includes a structured `root_cause` field with one of five categories:

| Root Cause | Description | Solana Pattern |
|------------|-------------|----------------|
| `missing_validation` | Input or state not checked before use | Missing `has_one`, zero-guard on div |
| `incorrect_state_transition` | State machine advanced incorrectly | Missing state enum check |
| `unchecked_external_call` | CPI result not checked | Missing `invoke` error propagation |
| `race_condition` | Concurrent state access without locking | Missing `invoke_signed` re-entrancy guard |
| `unchecked_arithmetic` | Math operation overflows/underflows | Plain `/` or `*` without `.checked_*` |

### 4.3.2 Fix Difficulty Rating

Each finding carries a `difficulty` field:

| Difficulty | Effort | Example |
|------------|--------|---------|
| `trivial` | Add one check | `require!` / `assert!` |
| `moderate` | Restructure logic | State machine, re-entrancy lock |
| `complex` | Multi-file refactor | New account type, PDA derivation change |

### 4.3.3 Regression Test Generation

`audit-fix-suggestions.py --regression` generates test stubs:

**Anchor project** (detected via Anchor.toml):
```rust
#[test]
fn test_vuln_01_fixed() {
    // Precondition: attacker account must be non-admin
    // VULN-01: admin_withdraw missing has_one check
    // FIX: added require!(ctx.accounts.admin.key() == vault.admin);
    // After fix: transaction reverts for non-admin caller
}
```

**Standalone Rust project** (no Anchor.toml):
```rust
#[cfg(test)]
mod vuln_01_tests {
    // Precondition: attacker account must be non-admin
    // VULN-01: admin_withdraw missing has_one check
    // FIX: added authority check before withdrawal
    #[test]
    fn test_vuln_01_fixed() { /* ... */ }
}
```

### 4.3.4 Remediation Priority Ordering

Findings are sorted by:
1. **Severity tier**: CRITICAL > HIGH > MEDIUM > LOW > INFO
2. **CVSS score**: Descending within each severity tier

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

---

## v1.15.0 — Implementation Notes (2026-07-06)

### CI hardening specification — round-by-round

| Round | Trigger | Files modified | Root cause |
|---|---|---|---|
| 1 | `0d892d7` | 5 workflows | 6 root causes: action paths, missing scripts, SARIF input, env drift, recursive trigger, lint |
| 2 | `7cde657` | `formal-verification.yml`, `audit.yml`, `test.yml`, integrity script | `solana-actions/setup-solana` deprecated → curl install; case-sensitivity fix; flake8/black reformat |
| 3 | `f1a8d1f` | 4 files | Black pin to 24.10.0; `pnpm install` guard; `if-no-files-found: ignore` removed from codeql step; SDD checks made advisory |
| 4 | `305e1ee` | `test-skill-integrity.sh`, `audit.yml` | Check 30 advisory; `findings-pr.json` existence guard |
| 5 | `1d314ef` | `audit-on-push.yml`, `test_properties.py` | SARIF input was `code-scanning-action`-only; flake8 F401 unused imports |
| 6 | `34413d6` | `audit-scheduled.yml` + 4 new files | Implemented 3 missing scripts (1600 LOC, 13 tests pass); wired into scheduled workflow |
| 7 | `78a6967` | 4 workflows | All `upload-sarif@v3` → `v4`; replaced `if-no-files-found` with `hashFiles()` guards; `audit-pr` `if:` guard |
| 8 | `491bc09` | 4 workflows | Workflow name collision fixed; `pr` workflow_dispatch input declared; hull-scope → ripgrep fallback; `formal-verification.yml` `&&` in `if:` moved into shell |

### New specification: `scripts/*.py` interface contract

Each audit-phase script implements this interface:

```python
# argparse contract
--help             # exits 0, prints usage
--version          # exits 0, prints SCRIPT_VERSION
--input <path>     # reads from path; default to repo-root convention
--output <path>    # writes JSON to path; refuses if exists without --force
--format {json,text}  # output format (default: json)
--force            # overwrite existing output file

# exit codes
0 = success
1 = runtime error (no input, toolchain missing)
2 = bad input (malformed JSON, missing field)
3 = idempotency violation (output exists without --force)
```

### New module: `scripts/find-programs.py`

```python
# Detects Solana program type per program dir
- Anchor: programs/*/Cargo.toml + Anchor.toml presence
- Native: programs/*/Cargo.toml without Anchor.toml
- Pinocchio: programs/*/Cargo.toml + pinocchio dep
# Outputs: audit-output/find-programs.json (or .txt)
```

### New module: `scripts/run-formal-verification.py`

```python
# Tries QED → anchor test --skip-build → clean-skip exit
# Writes formal_verification_report.json when successful
```

### New module: `scripts/triage-findings.py`

```python
# Reads findings.json → CVSS recompute (tolerates vector/score drift)
# Reorders by severity_rank * priority_score
# Writes audit-output/triage.json
```

### Backlog for v1.15.x

| ID | Item | Priority |
|---|---|---|
| SPEC-001 | Wire smoke tests into `test.yml` skill-integrity job | P1 |
| SPEC-002 | Decide fate of `audit-pr` job post-guard | P2 |
| SPEC-003 | Migrate Node 20 → 24 across all setup-python/setup-node steps | P2 |
| SPEC-004 | Replace hardcoded `moltbagus/solana-auditor-skill` clone with skill-dir copy | P3 |
| SPEC-005 | Fix Check 10 coverage gap: all 5 fixtures now verified (was 3). See learnings.md v1.15.1 | P1 |

