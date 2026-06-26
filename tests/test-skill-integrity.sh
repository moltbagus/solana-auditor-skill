#!/bin/bash
# tests/test-skill-integrity.sh
# Skill integrity checks for Solana AI Kit submission.
# Exit 0 if all pass, non-zero on first failure.

set -e

PASS=0; FAIL=0
ok()  { echo "  ✓ $1"; PASS=$((PASS+1)); }
fail(){ echo "  ✗ $1"; FAIL=$((FAIL+1)); exit 1; }

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Phase structure
echo "Phase structure..."
[[ -f skill/00-safety-guard.md ]] && ok "Phase 0: safety-guard" || fail "Missing safety-guard"
[[ -f skill/01-recon.md ]] && ok "Phase 1: recon" || fail "Missing recon"
[[ -f skill/02-static-analysis.md ]] && ok "Phase 2: SAST" || fail "Missing SAST phase"
[[ -f skill/03-formal-verification.md ]] && ok "Phase 3: formal-verification" || fail "Missing FV phase"
[[ -f skill/04-findings-triage.md ]] && ok "Phase 4: findings-triage" || fail "Missing triage phase"
[[ -f skill/05-report-generation.md ]] && ok "Phase 5: report-generation" || fail "Missing report phase"
[[ -f skill/06-remediation.md ]] && ok "Phase 6: remediation" || fail "Missing remediation phase"

# SKILL.md routing
echo "SKILL.md routing..."
rg -q "^## Skill Files" SKILL.md && ok "SKILL.md has routing table" || fail "SKILL.md missing routing"

# Commands
echo "Slash commands..."
[[ -f commands/audit.md ]] && ok "audit command" || fail "Missing audit"
[[ -f commands/audit-quick.md ]] && ok "audit-quick command" || fail "Missing audit-quick"
[[ -f commands/audit-resume.md ]] && ok "audit-resume command" || fail "Missing audit-resume"
[[ -f commands/audit-report.md ]] && ok "audit-report command" || fail "Missing audit-report"
[[ -f commands/audit-poc.md ]] && ok "audit-poc command" || fail "Missing audit-poc"
[[ -f commands/audit-findings.md ]] && ok "audit-findings command" || fail "Missing audit-findings"
[[ -f commands/audit-fix.md ]] && ok "audit-fix command" || fail "Missing audit-fix"
[[ -f commands/audit-history.md ]] && ok "audit-history command" || fail "Missing audit-history"
[[ -f commands/audit-pr.md ]] && ok "audit-pr command" || fail "Missing audit-pr"

# Agents
echo "Agents..."
[[ -f agents/orchestrator.md ]] && ok "orchestrator agent" || fail "Missing orchestrator"
[[ -f agents/auditor.md ]] && ok "auditor agent" || fail "Missing auditor"
[[ -f agents/formal-verifier.md ]] && ok "formal-verifier agent" || fail "Missing FV agent"
[[ -f agents/report-writer.md ]] && ok "report-writer agent" || fail "Missing report-writer"
[[ -f agents/cross-program-agent.md ]] && ok "cross-program-agent" || fail "Missing cross-program agent"
[[ -f agents/safety-guard.md ]] && ok "safety-guard agent" || fail "Missing safety-guard agent"

# Rules
echo "Security rules..."
RULE_COUNT=$(rg -c "^## Rule " rules/audit.rules || echo 0)
[[ "$RULE_COUNT" -ge 45 ]] && ok "audit.rules has $RULE_COUNT rules (≥45)" || fail "audit.rules has only $RULE_COUNT rules"

# MIT license
echo "License..."
[[ -f LICENSE ]] && ok "MIT license present" || fail "Missing LICENSE"
rg -q "MIT License" LICENSE && ok "License is MIT" || fail "LICENSE not MIT"

# README
echo "Documentation..."
[[ -f README.md ]] && ok "README.md exists" || fail "Missing README"
rg -q "install.sh" README.md && ok "README mentions install" || fail "README missing install instructions"

# Install script
echo "Install..."
[[ -f install.sh ]] && ok "install.sh exists" || fail "Missing install.sh"
bash -n install.sh && ok "install.sh syntax OK" || fail "install.sh syntax error"

# References
echo "References..."
[[ -f references/LIMITATIONS.md ]] && ok "LIMITATIONS.md present" || fail "Missing LIMITATIONS"

# Terminology
echo "Terminology..."
[[ -f skill/00-terminology.md ]] && ok "PT-BR terminology file" || fail "Missing terminology"

echo ""
echo "PASS: $PASS / FAIL: $FAIL"
[[ "$FAIL" -eq 0 ]]
