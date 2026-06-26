#!/bin/bash
# =========================================================================
# solana-auditor-skill — Demo Script
# =========================================================================
# Run from clone: proves the skill is installed and working.
# No Solana toolchain required. < 30 seconds.
#
# Usage: bash demo.sh

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; WHITE='\033[1;37m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PASS=0; FAIL=0
ok()  { echo -e "  ${GREEN}✓${NC} $1"; PASS=$((PASS+1)); }
fail(){ echo -e "  ${RED}✗${NC} $1"; FAIL=$((FAIL+1)); }

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}  ${WHITE}Solana Auditor Skill${NC}                                ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}  ${GREEN}50 rules · 6 agents · 9 commands${NC}                 ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"
echo ""

# 1. Structure
echo -e "${BLUE}[1/4]${NC} Verifying structure..."
for d in skill agents commands rules tests references; do
    [[ -d "$d" ]] && ok "$d/" || fail "Missing $d/"
done

# 2. SKILL.md routing
echo -e "${BLUE}[2/4]${NC} Verifying SKILL.md entry point..."
[[ -f SKILL.md ]] && ok "SKILL.md exists" || fail "SKILL.md missing"
[[ -f skill/01-recon.md ]] && ok "skill/01-recon.md exists" || fail "Missing recon phase"
[[ -f skill/02-static-analysis.md ]] && ok "skill/02-static-analysis.md exists" || fail "Missing SAST phase"

# 3. Integrity checks
echo -e "${BLUE}[3/4]${NC} Running integrity checks..."
if bash tests/test-skill-integrity.sh > /tmp/integrity.out 2>&1; then
    IG=$(rg "PASS:" /tmp/integrity.out -r '$1' || echo 0)
    ok "Integrity checks: $IG passed"
else
    fail "Integrity checks failed"
    rg "FAIL:" /tmp/integrity.out | head -5
fi

# 4. CVSS math fuzz
echo -e "${BLUE}[4/4]${NC} Running CVSS property-based tests..."
if python3 -m pytest tests/fuzz/ -x -q 2>&1 | tail -3 | rg -q "passed"; then
    ok "CVSS fuzz tests passed"
else
    # Even if pytest output format varies, check exit code
    python3 -m pytest tests/fuzz/ -x -q > /tmp/fuzz.out 2>&1
    [[ $? -eq 0 ]] && ok "CVSS fuzz tests passed" || fail "Fuzz tests failed"
fi

# Summary
echo ""
echo -e "${GREEN}Demo complete!${NC}"
echo "  $PASS passed, $FAIL failed"
echo ""
echo "Next steps:"
echo "  bash install.sh -y          # Install the skill"
echo "  /audit https://github.com/org/repo  # Start an audit"
echo ""

exit $FAIL
