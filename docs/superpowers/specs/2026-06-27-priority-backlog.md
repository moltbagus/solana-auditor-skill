# Priority Backlog — Post-Contest Improvements

**Date**: 2026-06-27
**Based on**: Gap Analysis 2026-06-27

---

## Top 5 Highest-Impact, Lowest-Effort Items

### 1. Remediation Engine Enhancement — Root Cause Analysis Layer
**Label**: CONTEST-CRITICAL
**Effort**: MEDIUM
**Impact**: Transforms skill from "finding reporter" to "actionable security partner"

**Description**: Add root cause analysis, attack scenario, business impact, and regression test fields to each of the 50 rule fix templates in Phase 6. Currently `skill/06-remediation.md` provides fix code but no contextual analysis.

**Files to create/modify**:
| File | Action |
|------|--------|
| `skill/06-remediation.md` | Add `root_cause`, `attack_scenario`, `business_impact` fields per rule |
| `scripts/audit-fix-suggestions.py` | Add `--explain` flag for root cause output |
| `commands/audit-fix.md` | Add `/audit-fix-explain` subcommand |

**Schema addition**:
```json
{
  "root_cause": "Why the vuln exists (design vs implementation flaw)",
  "attack_scenario": "Step-by-step attack narrative",
  "business_impact": "Quantified impact (funds at risk, protocol disruption)",
  "regression_test": "Test pattern to catch reintroduction"
}
```

**Test plan**: Pick 5 rules (1 per severity), add full metadata, verify `--explain` flag outputs root cause.

---

### 2. Exploit Simulation Framework — Structured PoC Metadata
**Label**: CONTEST-CRITICAL
**Effort**: MEDIUM
**Impact**: Transforms findings from "security observations" to "actionable risk assessments"

**Description**: Add structured exploit metadata to every finding: preconditions, required privileges, capital requirements, exploit complexity (1–10), exploit likelihood, attack path, expected outcome, residual risk.

**Files to create/modify**:
| File | Action |
|------|--------|
| `skill/06-remediation.md` | Add `exploit_metadata` section per rule |
| `commands/audit-poc.md` | Add `--metadata` flag for structured JSON output |
| `examples/.../audit-output/pocs/` | Add `metadata.json` per PoC |

**Exploit Metadata Schema**:
```json
{
  "preconditions": ["attacker must control SOL for fees"],
  "required_privileges": {"signer_status": "required", "token_holdings": null},
  "capital_requirements": {"sol": 0.01, "tokens": 0},
  "complexity": {"score": 3, "scale": "1-10", "factors": ["simple CPI call"]},
  "likelihood": {"score": 8, "factors": ["no rate limiting"]},
  "attack_path": ["step 1", "step 2", "step 3"],
  "expected_outcome": {"primary": "fund drain", "recovery": "impossible without upgrade"},
  "residual_risk": {"after_mitigation": "LOW", "remaining_vectors": []}
}
```

**Test plan**: Add metadata to 3 existing PoC walkthroughs, verify `--metadata` outputs structured JSON.

---

### 3. Threat Modeling Module — STRIDE Integration
**Label**: HIGH
**Effort**: MEDIUM
**Impact**: Differentiates from "SAST scanner"; critical for enterprise/audit-firm users

**Description**: Create standalone threat modeling phase applying STRIDE to Solana programs. Leverage existing CPI surface graph and cross-program agent.

**Files to create/modify**:
| File | Action |
|------|--------|
| `skill/02-threat-modeling.md` | New phase file |
| `agents/threat-modeler.md` | New specialist agent |
| `skill/SKILL.md` | Add Phase 2A routing |
| `commands/audit.md` | Add `--threat-model` flag |

**STRIDE mapping**:
| Category | Solana Pattern | Detection |
|---------|--------------|----------|
| Spoofing | Fake account, impersonate signer | `is_signer` gaps |
| Tampering | Modify account data mid-transaction | Write-after-write |
| Repudiation | No event emission | Missing `emit!` |
| Information Disclosure | Owner check gaps | Sensitive account access |
| Denial of Service | Rent exemption, overflow panic | Missing rent checks |
| Elevation of Privilege | Unverified CPI, non-canonical bump | Unchecked `invoke` |

**Test plan**: Run threat modeler on `examples/sample-vulnerable-program`, verify 8/10 vulns map to STRIDE.

---

### 4. Architecture Review Module — Standalone Component Analysis
**Label**: HIGH
**Effort**: MEDIUM
**Impact**: Fills professional audit standard of care; addresses enterprise persona

**Description**: Standalone architecture review analyzing: component interaction diagrams, upgradeability patterns, tokenomics, proxy patterns, shared ownership risks.

**Files to create/modify**:
| File | Action |
|------|--------|
| `skill/01B-architecture-review.md` | New phase file |
| `agents/architecture-reviewer.md` | New specialist agent |
| `skill/SKILL.md` | Add Phase 1B routing |
| `skill/01-recon.md` | Reference architecture review |

**Checklist**: Component Map · Upgrade Authority (multisig/timelock/immutable) · Proxy Pattern (UUPS vs transparent) · Tokenomics · Shared State · Economic Invariants · Attack Surface

**Test plan**: Run on fixture, verify component map includes all 3 programs and upgrade authority assessment is present.

---

### 5. Report Generator Enhancement — 3 Missing Sections
**Label**: HIGH
**Effort**: LOW
**Impact**: Comprehensive report differentiates from open-source scanners

**Description**: Add 3 missing sections to the report generator: Architecture Review Summary, Threat Model (STRIDE) Summary, Economic Security Analysis.

**Files to create/modify**:
| File | Action |
|------|--------|
| `skill/05-report-generation.md` | Add 3 new sections to template |
| `commands/audit-report.md` | Add `--include-architecture`, `--include-threat-model`, `--include-economic` flags |

**New sections**: Architecture Review (component map, upgrade authority, proxy pattern) · Threat Model (STRIDE findings by category) · Economic Security (tokenomics, fee flows, MEV exposure)

**Test plan**: Run `/audit-report --include-all`, verify all 3 sections appear in correct order.

---

## Summary

| # | Item | Label | Effort | Impact |
|---|------|-------|--------|--------|
| 1 | Remediation Engine Enhancement | CONTEST-CRITICAL | MEDIUM | HIGH |
| 2 | Exploit Simulation Framework | CONTEST-CRITICAL | MEDIUM | HIGH |
| 3 | Threat Modeling (STRIDE) | HIGH | MEDIUM | HIGH |
| 4 | Architecture Review Module | HIGH | MEDIUM | HIGH |
| 5 | Report Generator Enhancement | HIGH | LOW | HIGH |

**Total new files**: 4 (2 agents, 2 phase files)
**Total modified files**: 7
**Estimated effort**: ~3–4 weeks solo
