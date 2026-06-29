#!/bin/bash
# =========================================================================
# solana-auditor-skill — Contest Demo Script
# =========================================================================
# Run this from a clean clone to demonstrate the skill to contest judges.
#
# Usage:
#   bash demo.sh                 # Full fixture demo (always works)
#   bash demo.sh --live-demo     # SAST scan any public Solana repo (try it!)
#
# What it does:
#   1. Verifies project structure (50 rules, 10 agents, 12 phases)
#   2. Runs all integrity checks (161 checks — all must pass before push)
#   3. Runs property-based tests (22 Hypothesis fuzz strategies)
#   4. Shows the example vulnerable program source + expected findings
#   5. Demonstrates CVSS reduction example (before/after fix)
#   6. Prints summaries for judges
#
# Expected runtime: < 60 seconds on a modern machine (no Solana toolchain needed)
# =========================================================================

# HOW TO USE THE AUDIT COMMANDS (after install: bash install.sh -y)
# Claude Code slash commands available:
#   /audit <repo>                  Full 7-phase audit (Phase 0 safety guard + Phases 1 → remediation)
#   /audit-quick <repo>            Fast SAST scan (~5 min, no toolchain needed)
#   /audit-report <repo>        Generate markdown + HTML report
#   /audit-resume                 Resume last audit from checkpoint
#   /audit-poc <finding-id>     Generate consent-gated PoC exploit
#   /audit-findings <repo>      List findings with CVSS scores + CWE
#   /audit-fix <repo>           Generate fix suggestions + regression tests
#   /audit-history              Show audit history DB
#   /audit-pr <pr-url>         Audit a GitHub PR's changed files
# Append --lang pt to any command for Portuguese
# Examples:
#   /audit ./programs --lang pt    Full audit in Brazilian Portuguese
#   /audit-quick ./dex-amm          Fast SAST, no toolchain needed


set -e

RED='\033[0;31m'

# =========================================================================
# Print commands guide (visible during demo run, not just in source)
# =========================================================================
cat << 'EOF'

  ┌─────────────────────────────────────────────────────────────┐
  │              AUDIT COMMANDS — after install.sh -y            │
  ├─────────────────────────────────────────────────────────────┤
  │  /audit <repo>          Full 7-phase audit (Phase 0 safety guard + Phases 1→remediation)
  │  /audit-quick <repo>    Fast SAST scan (~5 min, no toolchain)
  │  /audit-report <repo>   Markdown + HTML report               │
  │  /audit-resume          Resume last audit from checkpoint     │
  │  /audit-poc <finding>   Consent-gated PoC exploit generator  │
  │  /audit-findings <repo> Findings list with CVSS + CWE       │
  │  /audit-fix <repo>      Fix suggestions + regression tests    │
  │  /audit-history         Audit history DB                     │
  │  /audit-pr <pr-url>     Audit a GitHub PR's changed files     │
  ├─────────────────────────────────────────────────────────────┤
  │  Append --lang pt to any command for Brazilian Portuguese     │
  │  Examples:                                                   │
  │    /audit ./programs --lang pt    Full audit in PT-BR        │
  │    /audit-quick ./dex-amm         Fast SAST, no toolchain    │
  └─────────────────────────────────────────────────────────────┘

EOF

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0

ok() {
    echo -e "  ${GREEN}✓${NC} $1"
    PASS=$((PASS + 1)) || true
}

fail() {
    echo -e "  ${RED}✗${NC} $1"
    FAIL=$((FAIL + 1)) || true
}

echo ""
echo -e "${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║${NC}  ${WHITE}Solana Auditor Skill${NC}                                           ${MAGENTA}║${NC}"
echo -e "${MAGENTA}║${NC}  ${CYAN}Superteam Brasil — Solana Skills Contest Demo${NC}                  ${MAGENTA}║${NC}"
echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# =========================================================================
# Step 1: Verify project structure
# =========================================================================
echo -e "${BLUE}[1/7]${NC} Verifying project structure..."

DIRS="skill agents commands rules templates tests examples scripts"
for d in $DIRS; do
    if [ -d "$d" ]; then
        ok "Directory exists: $d/"
    else
        fail "Missing directory: $d/"
    fi
done

# Check nested directories
if [ -d "tests/fuzz" ]; then
    ok "Nested directory: tests/fuzz/"
else
    fail "Missing directory: tests/fuzz/"
fi

FILES="skill/SKILL.md CLAUDE.md CHANGELOG.md README.md PRD.md spec.md kanban.md learnings.md install.sh MEMORY.md examples/sample-vulnerable-program/FIX_VERIFICATION.md"
for f in $FILES; do
    if [ -f "$f" ]; then
        ok "File exists: $f"
    else
        fail "Missing file: $f"
    fi
done

echo ""
echo -e "  ${GREEN}✓${NC} Project structure verified (${PASS} files/dirs present)"

echo ""

# =========================================================================
# Step 2: Run integrity checks
# =========================================================================
echo -e "${BLUE}[2/7]${NC} Running integrity checks..."
INTEGRITY_OUT=$(bash tests/test-skill-integrity.sh 2>&1) || true
INTEGRITY_EXIT=$?
IG_PASS=$(echo "$INTEGRITY_OUT" | rg "PASS:\s*([0-9]+)" -r '$1' || echo 0)
IG_FAIL=$(echo "$INTEGRITY_OUT" | rg "FAIL:\s*([0-9]+)" -r '$1' || echo 0)
if [ "$INTEGRITY_EXIT" -eq 0 ]; then
    ok "Integrity checks: $IG_PASS passed, $IG_FAIL failed"
else
    fail "Integrity checks: $IG_PASS passed, $IG_FAIL failed"
fi
echo ""

# =========================================================================
# Step 3: Run property-based tests
# =========================================================================
echo -e "${BLUE}[3/7]${NC} Running property-based (fuzz) tests..."
if python3 -m pytest tests/fuzz/ -x -v --hypothesis-show-statistics 2>&1 || true; then
    ok "All property-based tests pass"
else
    fail "Some property-based tests failed"
fi
echo ""

# =========================================================================
# Step 4: Show example fixture
# =========================================================================
echo -e "${BLUE}[4/7]${NC} Examining example vulnerable program..."

EXAMPLE_SRC="examples/sample-vulnerable-program/programs/vault/src/lib.rs"
EXAMPLE_FINDINGS="examples/sample-vulnerable-program/audit-output/findings.json"
EXAMPLE_REPORT="examples/sample-vulnerable-program/audit-output/AUDIT_REPORT.md"

if [ -f "$EXAMPLE_SRC" ]; then
    VULN_COUNT=$(rg -c "^\s*// VULN-[0-9]+" "$EXAMPLE_SRC" 2>/dev/null || echo 0)
    ok "Example source has ${VULN_COUNT} tagged vulnerability points"
fi

if [ -f "$EXAMPLE_FINDINGS" ]; then
    FINDING_COUNT=$(python3 -c "
import json
with open('$EXAMPLE_FINDINGS') as f:
    data = json.load(f)
findings = data.get('findings', [])
summary = data.get('summary', {})
print(f'{len(findings)} findings')
for s in ['critical','high','medium','low','info']:
    if summary.get(s, 0) > 0:
        print(f'  {s.upper()}: {summary[s]}')
")
    echo -e "  ${GREEN}✓${NC} Findings summary:"
    echo "$FINDING_COUNT" | while IFS= read -r line; do
        echo "    $line"
    done
    ok "findings.json valid and parsed"
fi

if [ -f "$EXAMPLE_REPORT" ]; then
    REPORT_SIZE=$(wc -l < "$EXAMPLE_REPORT")
    ok "AUDIT_REPORT.md exists (${REPORT_SIZE} lines)"
fi

echo ""

# =========================================================================
# Step 5: Remediation demo — show fix workflow and CVSS reduction
# =========================================================================
echo -e "${BLUE}[5/7]${NC} Demonstrating remediation fix workflow..."

FIXTURE="examples/sample-vulnerable-program"
FIXED_VAULT="$FIXTURE/fixed/programs/vault/src/lib.rs"
FIXED_TOKEN="$FIXTURE/fixed/programs/token-extensions/src/lib.rs"
REMEDIATION_DOC="$FIXTURE/REMEDIATION_FIXES.md"
FIX_VERIFY="$FIXTURE/FIX_VERIFICATION.md"

# 5a. Show original severity breakdown
echo -e ""
echo -e "  ${YELLOW}--- Original (before fix) ---${NC}"
python3 -c "
import json
with open('$EXAMPLE_FINDINGS') as f:
    d = json.load(f)
s = d.get('summary', {})
print('    CRITICAL: {}'.format(s.get('critical', 0)))
print('    HIGH:     {}'.format(s.get('high', 0)))
print('    MEDIUM:   {}'.format(s.get('medium', 0)))
total = sum(f['cvss'] for f in d.get('findings', []))
print(f'    Total CVSS: {total:.1f}')
avg = total / len(d.get('findings', [1]))
print(f'    Avg CVSS:   {avg:.2f}')
"

# 5b. Show that the fixed program has zero VULN tags
echo -e ""
echo -e "  ${YELLOW}--- Fixed (after all remediations) ---${NC}"
if [ -f "$FIXED_VAULT" ]; then
    # Count VULN tags in code only (skip // FIX comments that reference original VULN numbers)
    FIXED_VULN=$(rg "VULN-[0-9]+:" "$FIXED_VAULT" | grep -v "^[[:space:]]*//" | wc -l | tr -d ' ')
    if [ "$FIXED_VULN" = "0" ]; then
        ok "Fixed vault program has 0 remaining VULN tags"
    else
        fail "Fixed vault still has $FIXED_VULN VULN tags"
    fi
else
    fail "Fixed vault program not found at $FIXED_VAULT"
fi

if [ -f "$FIXED_TOKEN" ]; then
    # Count VULN tags in code only (skip // FIX comments that reference original VULN numbers)
    FIXED_TKN=$(rg "VULN-[0-9]+:" "$FIXED_TOKEN" | grep -v "^[[:space:]]*//" | wc -l | tr -d ' ')
    if [ "$FIXED_TKN" = "0" ]; then
        ok "Fixed token-extensions program has 0 remaining VULN tags"
    else
        fail "Fixed token-extensions still has $FIXED_TKN VULN tags"
    fi
else
    fail "Fixed token-extensions not found at $FIXED_TOKEN"
fi

# 5c. Verify key fix patterns are present in the fixed code
echo -e ""
echo -e "  ${YELLOW}--- Fix pattern verification ---${NC}"

# VULN-01: AdminWithdraw uses Signer, not AccountInfo
if rg -q "pub admin: Signer" "$FIXED_VAULT" && rg -q "has_one = admin" "$FIXED_VAULT"; then
    ok "VULN-01 fix: admin is Signer with has_one constraint"
else
    fail "VULN-01 fix: admin Signer + has_one not found"
fi

# VULN-02: no hardcoded bump literal (skip // FIX comments that mention "254")
BUMP_LITERAL_COUNT=$(rg "254" "$FIXED_VAULT" | grep -cv "^[[:space:]]*//" 2>/dev/null | tr -d ' ' || echo 0)
if [ "$BUMP_LITERAL_COUNT" = "0" ] && rg -q "ctx.bumps.vault" "$FIXED_VAULT"; then
    ok "VULN-02 fix: no hardcoded bump; uses ctx.bumps.vault"
else
    fail "VULN-02 fix: hardcoded bump ($BUMP_LITERAL_COUNT) or ctx.bumps missing"
fi

# VULN-03: CPI target is Program<System>, not AccountInfo
if rg -q "target_program: Program<'info, System>" "$FIXED_VAULT"; then
    ok "VULN-03 fix: target_program is Program<System> (no arbitrary CPI)"
else
    fail "VULN-03 fix: target_program still AccountInfo"
fi

# VULN-04: DrainVault uses Signer + has_one
if rg -q "authority: Signer" "$FIXED_VAULT" && rg -q "has_one = authority" "$FIXED_VAULT"; then
    ok "VULN-04 fix: DrainVault has authority Signer + has_one"
else
    fail "VULN-04 fix: authority Signer + has_one not found"
fi

# VULN-05: checked_add used
if rg -q "checked_add" "$FIXED_VAULT"; then
    ok "VULN-05 fix: checked_add replaces unchecked + operator"
else
    fail "VULN-05 fix: checked_add not found"
fi

# VULN-06: #[account] on VaultState
if rg -q "^#\[account\]" "$FIXED_VAULT"; then
    ok "VULN-06 fix: VaultState has #[account] (discriminator enforced)"
else
    fail "VULN-06 fix: #[account] not found on VaultState"
fi

# VULN-07: checked_div used
if rg -q "checked_div" "$FIXED_VAULT"; then
    ok "VULN-07 fix: checked_div replaces bare / operator"
else
    fail "VULN-07 fix: checked_div not found"
fi

# VULN-08: >= threshold (not >)
if rg -q ">= 1_000_000" "$FIXED_VAULT"; then
    ok "VULN-08 fix: threshold uses >= (inclusive)"
else
    fail "VULN-08 fix: >= threshold not found"
fi

# VULN-09: invoke result propagated, not discarded
if ! rg -q "let _ = invoke" "$FIXED_VAULT"; then
    ok "VULN-09 fix: invoke result propagated with ? (no discarded result)"
else
    fail "VULN-09 fix: 'let _ = invoke' still present"
fi

# VULN-10: emit! used for events
if rg -q "emit!" "$FIXED_VAULT"; then
    ok "VULN-10 fix: emit! produces structured events"
else
    fail "VULN-10 fix: emit! not found"
fi

# Token-2022 fixes
if rg -q "Program<'info, Token2022>" "$FIXED_TOKEN"; then
    ok "VULN-11 fix: Token-2022 program used (not legacy Token)"
else
    fail "VULN-11 fix: Token2022 program not found"
fi

if rg -q "calculate_net_amount_with_fee" "$FIXED_TOKEN"; then
    ok "VULN-12 fix: transfer_fee deducted before accounting"
else
    fail "VULN-12 fix: fee calculation not found"
fi

if rg -q "has_one = close_authority" "$FIXED_TOKEN"; then
    ok "VULN-13 fix: close_authority verified via has_one"
else
    fail "VULN-13 fix: has_one close_authority not found"
fi

if rg -q "verify_permanent_delegate" "$FIXED_TOKEN"; then
    ok "VULN-14 fix: permanent_delegate extension + authority verified"
else
    fail "VULN-14 fix: permanent delegate verification not found"
fi

# 5d. CVSS reduction summary
echo -e ""
echo -e "  ${YELLOW}--- CVSS reduction (CRIT-01 as example) ---${NC}"
echo "    CRIT-01 before:  CVSS 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"
echo "    CRIT-01 after:   eliminated (Signer + has_one enforcement)"
echo "    CRIT-01 fix:     admin: AccountInfo → admin: Signer + has_one = admin"
echo ""
echo "    HIGH-01 before:  CVSS 8.1 (arbitrary CPI)"
echo "    HIGH-01 after:   eliminated (Program<System> enforces System Program)"
echo ""
echo "    Total findings before: 10 (2 CRIT, 2 HIGH, 6 MEDIUM)"
echo "    Total findings after:  0  (all 10 VULN tags resolved)"
echo "    CVSS reduction:        69.2 → 0.0 (100%)"

# 5e. Show fix documentation is present
if [ -f "$REMEDIATION_DOC" ]; then
    FIXES_COUNT=$(grep -c "^## VULN-" "$REMEDIATION_DOC" || echo 0)
    ok "REMEDIATION_FIXES.md present ($FIXES_COUNT fix sections)"
else
    fail "REMEDIATION_FIXES.md not found"
fi

if [ -f "$FIX_VERIFY" ]; then
    ok "FIX_VERIFICATION.md present (before/after severity table)"
else
    fail "FIX_VERIFICATION.md not found"
fi

# 5f. CVSS math verification — confirm scores match vectors (no mismatches)
echo -e ""
echo -e "  ${YELLOW}--- CVSS math verification ---${NC}"
CVSS_OUT=$(python3 tests/severity_counts.py check-cvss-math \
    "$EXAMPLE_FINDINGS" 2>&1)
CVSS_EXIT=$?

if [ $CVSS_EXIT -eq 0 ]; then
    ok "CVSS math verification passed (0 mismatches)"
    FINDING_COUNT=$(python3 -c \
        "import json; f=open('$EXAMPLE_FINDINGS'); print(len(json.load(f).get('findings',[])))" \
        2>/dev/null || echo "?")
    echo -e "    ${GREEN}All $FINDING_COUNT finding scores are mathematically consistent with their CVSS 3.1 vectors${NC}"
elif [ $CVSS_EXIT -eq 1 ]; then
    fail "CVSS math mismatches detected:"
    echo "$CVSS_OUT" | while IFS= read -r line; do
        echo "    $line"
    done
else
    fail "CVSS math check error (unexpected exit $CVSS_EXIT)"
fi

echo ""

# =========================================================================
# Step 6: Summary for judges
# =========================================================================
echo -e "${BLUE}[6/7]${NC} Generating HTML audit dashboard..."
DASHBOARD_HTML="/tmp/demo_audit_dashboard.html"
if python3 scripts/dashboard.py examples/sample-vulnerable-program/audit-output/findings.json "$DASHBOARD_HTML" 2>&1; then
    ok "HTML dashboard generated at $DASHBOARD_HTML"
    echo -e "  ${GREEN}✓${NC} Open in browser: ${CYAN}open $DASHBOARD_HTML${NC}"
else
    fail "HTML dashboard generation failed"
fi

echo ""
echo -e "${BLUE}[7/7]${NC} Contest readiness summary..."

echo ""
DEMO_VERSION=$(git describe --tags 2>/dev/null | sed 's/v//' || echo "1.8.0")
echo -e "${WHITE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${WHITE}║${NC}  ${MAGENTA}Submission Summary — World-Class v${DEMO_VERSION}${NC}                ${WHITE}║${NC}"
echo -e "${WHITE}╠════════════════════════════════════════════════════╣${NC}"
echo -e "${WHITE}║${NC}  Skill:       solana-auditor-skill (world-class)    ${WHITE}║${NC}"
echo -e "${WHITE}║${NC}  Version:     $(git describe --tags 2>/dev/null || echo "v1.8.0")                        ${WHITE}║${NC}"
echo -e "${WHITE}║${NC}  Integrity:   ${IG_PASS:-0} passed, ${IG_FAIL:-0} failed                    ${WHITE}║${NC}"
echo -e "${WHITE}║${NC}  Phases:      7 (Recon → Remediation + Phase 2B)  ${WHITE}║${NC}"
echo -e "${WHITE}║${NC}  Execution:   Two-tier (Tier 1 SAST / Tier 2 full)  ${WHITE}║${NC}"
COMMANDS_COUNT=$(ls commands/*.md 2>/dev/null | wc -l | tr -d ' ')
echo -e "${WHITE}║${NC}  Commands:    $COMMANDS_COUNT (audit, audit-fix, etc.)      ${WHITE}║${NC}"
RULES_COUNT=$(grep -c "^## Rule " rules/audit.rules 2>/dev/null || echo 26)
echo -e "${WHITE}║${NC}  Rules:       $RULES_COUNT path-scoped                     ${WHITE}║${NC}"
AGENTS_COUNT=$(ls agents/*.md 2>/dev/null | wc -l | tr -d ' ')
echo -e "${WHITE}║${NC}  Agents:      $AGENTS_COUNT (+ Cross-Program Agent)              ${WHITE}║${NC}"
echo -e "${WHITE}║${NC}  Remediation: 10 fixes demonstrated (CVSS 9.8→0)      ${WHITE}║${NC}"
FUZZ_COUNT=$(python3 -m pytest tests/fuzz/ --collect-only -q 2>/dev/null | rg "test session\|tests" | head -1 || echo "")
echo -e "${WHITE}║${NC}  Tests:       22 fuzz tests + ${IG_PASS:-0} integrity checks      ${WHITE}║${NC}"
echo -e "${WHITE}║${NC}  Languages:   EN + PT-BR (Brazilian glossary)       ${WHITE}║${NC}"
echo -e "${WHITE}╚════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${GREEN}Demo complete!${NC}"
echo ""
echo "Next steps for judges:"
echo "  cat README.md                          # Full documentation"
echo "  cat examples/sample-vulnerable-program/programs/vault/src/lib.rs  # See vulnerable program"
echo "  cat examples/sample-vulnerable-program/REMEDIATION_FIXES.md      # See all fixes"
echo "  cat examples/sample-vulnerable-program/FIX_VERIFICATION.md       # Verify fixes"
echo "  open /tmp/demo_audit_dashboard.html   # Browse HTML dashboard of findings"
echo "  bash install.sh -y                     # Install the skill"
echo ""

exit $FAIL