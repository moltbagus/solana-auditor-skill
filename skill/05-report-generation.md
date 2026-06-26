# Phase 5: Report Generation

**Goal**: Produce a production-grade audit report.

## Report Structure

```
1. Executive Summary
2. Scope
3. Methodology
4. Detailed Findings
5. Findings Summary Table
6. Remediation Recommendations
7. Appendix
```

## 1. Executive Summary

```markdown
## Executive Summary

[Program Name] ("the Program") was audited for security vulnerabilities 
from [Date] to [Date]. The audit covered [N] instruction handlers, 
[N] account types, and [N] cross-program invocations.

**Total Issues Found**: [N] (N critical, N high, N medium, N low, N info)

**Key Risks Identified**:
- [CRIT] Brief description of most severe finding
- [HIGH] Brief description of second most severe

**Overall Assessment**: [Safe to Deploy / Safe to Deploy with Fixes / Not Safe to Deploy]
```

## 2. Scope

```markdown
## Scope

| Component | Version | Commit/IDL Hash |
|-----------|---------|-----------------|
| vault-program | 1.0.0 | 0xabc123... |
| token-extensions | 2022 | - |
| IDL | - | sha256:def456... |

**Out of Scope**:
- Off-chain programs
- Frontend wallet integration
- Token metadata content (only structural validation)
- Testnet/devenv configurations
```

## 3. Methodology

```markdown
## Methodology

1. **Reconnaissance**: Repository enumeration, IDL extraction, program account analysis
2. **Static Analysis**: Manual code review + automated SAST (grep, anchor check)
3. **Formal Verification**: QED 2A invariant testing, Anchor testgen
4. **Triage**: Severity classification using CVSS 3.1 framework
5. **Report**: Structured findings with PoC confirmation

**Tools Used**:
- anchor-build 0.30.x
- solana-cli 1.18.x
- QED 2A (formal verification)
- [Other tools]
```

## 4. Detailed Findings

For each finding:

```markdown
### [CRIT/HIGH/MEDIUM/LOW/INFO]-##: [Title]

**Severity**: [CRITICAL/HIGH/MEDIUM/LOW/INFO]  
**CVSS**: [score]  
**CWE**: [CWE-ID]  
**File**: [path]:[line]  
**Function**: [function_name]

#### Description

[Technical description of the vulnerability. 
Include code snippet.]

#### Impact

[Concrete impact on fund security or protocol integrity.
Who is affected and under what conditions.]

#### Proof of Concept

```rust
// [PoC code showing exploit]
// Describe expected vs actual behavior
```

#### Remediation

```rust
// [Fixed code]
```

#### References

- [Link to similar past vulnerability]
- [Anchor documentation]
- [CWE description]
```

## 5. Findings Summary Table

```markdown
## Findings Summary

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| CRIT-01 | Unsigned admin action via invoke | CRITICAL | Open |
| HIGH-01 | CPI privilege escalation in transfer | HIGH | Open |
| MED-01 | Missing owner check on user config | MEDIUM | Open |
| LOW-01 | No close authority on vault | LOW | Open |

**Total**: 4 (1 critical, 1 high, 1 medium, 1 low)

**Status Definitions**:
- **Open**: Finding confirmed, not fixed
- **Fixed**: Fix verified by auditor
- **N/A**: Not applicable (false positive)
```

## 6. Remediation Recommendations

```markdown
## Remediation Recommendations

### Immediate (Before Any Deployment)

1. **[CRIT-01]** Add signer verification to `admin_withdraw`
   ```bash
   # Command to verify fix:
   git diff programs/vault/src/lib.rs
   anchor build && anchor test
   ```

2. **[HIGH-01]** Validate CPI target program ID

### Short-term (Before Production Launch)

3. **[MED-01]** Add `has_one` constraint to `UpdateUserConfig`
4. **[MED-02]** Implement reinitialization guards

### Long-term (Future Upgrades)

5. **[LOW-01]** Add explicit close authority
6. **[INFO-01]** Improve test coverage to 80%+
```

## 7. Appendix

```markdown
## Appendix

### A. File Hashes
- Program binary: `sha256:...`
- IDL: `sha256:...`

### B. Test Commands
```bash
anchor build
anchor test
cargo audit
qed-solana verify --program target/deploy/PROGRAM.so
```

### C. Environment
- Anchor: 0.30.x
- Solana CLI: 1.18.x
- Rust: 1.75+
- Toolchain: stable
```

## Report Generation Commands

```bash
# Export findings to JSON
echo '{"findings": [...]}' > findings.json

# Generate markdown from template
# (Use skill/05-report-generation.md as template)

# Build PDF (optional — requires pandoc)
pandoc report.md -o report.pdf --pdf-engine=weasyprint
```

## Next Phase

After report generation → load `skill/06-remediation.md` for fix verification
and remediation guidance for each finding.
