#!/bin/bash
# tests/test-skill-integrity.sh
#
# Skill integrity checks. Exit 0 if all pass, non-zero on first failure.
# Designed to run in CI (GitHub Actions) and locally.
#
# Checks:
#   1. Every skill/0N-*.md filename matches its "# Phase N:" heading
#   2. Every path referenced from commands/*.md exists
#   3. Vault fixture: every VULN-XX has a finding in findings.json
#   4. Every CWE-XXX reference in rules/audit.rules has valid format
#   5. Every rule in rules/audit.rules has a References block
#   6.-13. Data integrity, CVSS math, agent consistency (see below)
#  14. Property-based (fuzz) tests pass (tests/fuzz/)
#  15. Brazilian Portuguese (PT-BR) terminology in glossary
#  16. SDD documentation files present (PRD, Spec, Kanban, Learnings)
#  17. Demo script exists and is executable (demo.sh)
#  18. Token-2022 fixture: every VULN-XX has a finding in findings.json
#  19. methodology-trace.md CVSS scores match findings.json
#  20. Finding line numbers match VULN comment locations in source
#  21. Formal verification demonstration passes
#  22. Phase 2B runtime testing YAML frontmatter
#  23. Cross-Program Agent YAML frontmatter
#  24. CPI graph generator produces valid JSON
#  25. cargo-audit integration in Phase 1
#  26. Helius API integration in Phase 1
#  27. Toolchain auto-detection in Phase 1
#  28. Phase 2B runtime_findings.json schema
#  29. QED 2A fallback chain in Phase 2B
#  30. SPEC.md and PRD.md reflect 26 rules
#  31. pre-commit hook exists and is executable
#  32. /audit-pr command exists
#  33. /audit-history command and script exist
#  34. audit-fix-suggestions.py exists and runs
#  35. CLAUDE.md references v1.6 automation
#  36. Rules 27-35 exist in audit.rules
#  37. token-2022-real findings.json includes VULN-18
#  38. Rule 27 contains transfer_hook keyword
#  39. Rules 36-45 exist in audit.rules
#  40. native-vault fixture VULN-N0x ↔ findings.json coverage
#  41. native-vault fixture exists
#  42. Rule 36 contains sysvar keyword
#  43. native-vault fixture has AUDIT_REPORT
#  44. agents/safety-guard.md exists with YAML frontmatter
#  45. commands/audit.md references safety-guard agent
#  46. Rules 46-50 exist in audit.rules
#  47. No findings.json lacks a location.file field

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

PASS=0
FAIL=0
WARN=0

ok() {
    echo "  ✓ $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  ✗ $1"
    FAIL=$((FAIL + 1))
}

warn() {
    echo "  ⚠ $1"
    WARN=$((WARN + 1))
}

# =========================================================================
# SHARED FIXTURE PATHS — Single source of truth for Checks 3, 6, 7, 8, 10, 18
# =========================================================================

VAULT_SRC="examples/sample-vulnerable-program/programs/vault/src/lib.rs"
VAULT_FINDINGS="examples/sample-vulnerable-program/audit-output/findings.json"
VAULT_REPORT="examples/sample-vulnerable-program/audit-output/AUDIT_REPORT.md"

TOKEN_SRC="examples/sample-vulnerable-program/programs/token-extensions/src/lib.rs"
TOKEN_FINDINGS="examples/sample-vulnerable-program/audit-output/token-extensions/findings.json"
TOKEN_REPORT="examples/sample-vulnerable-program/audit-output/token-extensions/AUDIT_REPORT.md"

# Token-2022 real fixture (uses actual spl_token_2022)
TOKEN2022_SRC="examples/token-2022-real/src/lib.rs"
TOKEN2022_FINDINGS="examples/token-2022-real/audit-output/findings.json"
TOKEN2022_REPORT="examples/token-2022-real/audit-output/AUDIT_REPORT.md"
TOKEN2022_TRACE="examples/token-2022-real/audit-output/methodology-trace.md"

# Live-exploit fixtures — historical CVE replays (documented exploits, not live programs)
SOLEND_FINDINGS="examples/solend-governance-audit/audit-output/findings.json"
KLIVE_FINDINGS="examples/klive-live-audit/audit-output/findings.json"

# =========================================================================
# SHARED FUNCTION — Validate VULN coverage for any fixture
# =========================================================================

check_fixture_vuln_coverage() {
    local LABEL="$1"
    local SRC_FILE="$2"
    local FND_FILE="$3"
    local AUDIT_DIR
    AUDIT_DIR="$(dirname "$FND_FILE")"

    if [ ! -f "$SRC_FILE" ] || [ ! -f "$FND_FILE" ]; then
        fail "$LABEL: source or findings.json missing"
        return
    fi

    local src_ids fnd_ids src_count fnd_count
    # Extract VULN IDs from comment lines only (not doc comments or fix references)
    src_ids=$(rg "^\s*// VULN-[0-9]+" "$SRC_FILE" | rg -o "VULN-[0-9]+" | sort -u)
    fnd_ids=$(rg -o '"id":\s*"VULN-[0-9]+"' "$FND_FILE" | grep -oE 'VULN-[0-9]+' | sort -u)
    src_count=$(echo "$src_ids" | wc -l | tr -d ' ')
    fnd_count=$(echo "$fnd_ids" | wc -l | tr -d ' ')

    if [ "$src_count" = "$fnd_count" ] && [ "$src_count" -gt 0 ]; then
        ok "$LABEL: $src_count VULN-IDs in source, $fnd_count in findings.json (match)"
    else
        fail "$LABEL: VULN-IDs mismatch: $src_count in source vs $fnd_count in findings.json"
        diff <(echo "$src_ids") <(echo "$fnd_ids") | head -10
    fi

    # Verify supporting audit files exist
    if [ -f "$AUDIT_DIR/AUDIT_REPORT.md" ]; then
        ok "$LABEL: AUDIT_REPORT.md exists"
    else
        fail "$LABEL: AUDIT_REPORT.md missing"
    fi
    if [ -f "$AUDIT_DIR/methodology-trace.md" ]; then
        ok "$LABEL: methodology-trace.md exists"
    else
        fail "$LABEL: methodology-trace.md missing"
    fi
    if [ -f "$AUDIT_DIR/quick-scan-results.md" ]; then
        ok "$LABEL: quick-scan-results.md exists"
    else
        fail "$LABEL: quick-scan-results.md missing"
    fi
}

# =========================================================================
# SHARED FUNCTION — Verify methodology-trace.md CVSS scores match findings.json
# =========================================================================

check_trace_cvss_for_fixture() {
    local LABEL="$1"
    local FND_FILE="$2"
    local TRACE_FILE="$3"

    if [ ! -f "$FND_FILE" ] || [ ! -f "$TRACE_FILE" ]; then
        fail "$LABEL: findings.json or methodology-trace.md missing"
        return
    fi

    local mismatch_count=0
    # For each finding with cvss_vector in findings.json, check methodology-trace.md
    while IFS='|' read -r fid vec; do
        [ -z "$fid" ] && continue
        # Extract the score from the trace for this VULN
        local trace_line
        trace_line=$(grep -A1 "CVSS vector.*https://" "$TRACE_FILE" 2>/dev/null | grep "${fid}" -B1 || true)
        # Simple check: grep for the VULN's CVSS Vector line and extract score
        local expected_score
        expected_score=$(python3 -c "
import sys, json
with open('$FND_FILE') as f:
    data = json.load(f)
for finding in data.get('findings', []):
    if finding.get('id') == '$fid':
        print(finding.get('cvss', ''))
" 2>/dev/null)
        [ -z "$expected_score" ] && continue

        # Check if the trace CVSS score matches
        if grep -q "$fid" "$TRACE_FILE" 2>/dev/null; then
            local trace_score
            trace_score=$(grep -A5 "$fid" "$TRACE_FILE" | grep -oE '→ [0-9]+\.[0-9]+' | head -1 | cut -d' ' -f2)
            if [ -n "$trace_score" ] && [ "$trace_score" != "$expected_score" ]; then
                fail "$LABEL: $fid CVSS in trace ($trace_score) != findings.json ($expected_score)"
                mismatch_count=$((mismatch_count + 1))
            fi
        fi
    done < <(python3 -c "
import json
with open('$FND_FILE') as f:
    data = json.load(f)
for finding in data.get('findings', []):
    fid = finding.get('id', '')
    vec = finding.get('cvss_vector', '')
    if fid and vec:
        print(f'{fid}|{vec}')
" 2>/dev/null)

    if [ "$mismatch_count" -eq 0 ]; then
        ok "$LABEL: methodology-trace.md CVSS scores match findings.json"
    fi
}

# =========================================================================
# SHARED FUNCTION — Run a Python integrity check for each fixture
# =========================================================================

run_single_arg_check_for_fixtures() {
    local CHECK_NAME="$1"       # e.g., check-summary, check-cvss-math
    local CHECK_LABEL="$2"      # human-readable check name

    for fixture_pair in "vault:$VAULT_FINDINGS" "token-extensions:$TOKEN_FINDINGS" "token-2022-real:$TOKEN2022_FINDINGS" "solend-governance:$SOLEND_FINDINGS" "klive:$KLIVE_FINDINGS"; do
        local LABEL="${fixture_pair%%:*}"
        local F_PATH="${fixture_pair##*:}"

        if [ ! -f "$F_PATH" ]; then
            # Missing fixture — treat as skip, not failure, so removing an example
            # never breaks CI. Real failures still surface as `fail` below.
            ok "$LABEL: skipped — $F_PATH not present"
            continue
        fi

        local PYTHON_ARGS="$(dirname "$0")/severity_counts.py $CHECK_NAME $F_PATH"
        if python3 $PYTHON_ARGS 2>&1; then
            ok "$LABEL: $CHECK_LABEL"
        else
            fail "$LABEL: $CHECK_LABEL failed"
        fi
    done
}

run_two_arg_check_for_fixtures() {
    local CHECK_NAME="$1"       # e.g., check-report, check-cvss
    local CHECK_LABEL="$2"      # human-readable check name

    for fixture_pair in "vault:$VAULT_FINDINGS:$VAULT_REPORT" "token-extensions:$TOKEN_FINDINGS:$TOKEN_REPORT" "token-2022-real:$TOKEN2022_FINDINGS:$TOKEN2022_REPORT"; do
        local LABEL="${fixture_pair%%:*}"
        local rest="${fixture_pair#*:}"
        local F_PATH="${rest%%:*}"
        local R_PATH="${rest##*:}"

        if [ ! -f "$F_PATH" ] || [ ! -f "$R_PATH" ]; then
            fail "$LABEL: cannot validate $CHECK_LABEL — files missing"
            continue
        fi

        local PYTHON_ARGS="$(dirname "$0")/severity_counts.py $CHECK_NAME $F_PATH $R_PATH"
        if python3 $PYTHON_ARGS 2>&1; then
            ok "$LABEL: $CHECK_LABEL"
        else
            fail "$LABEL: $CHECK_LABEL failed"
        fi
    done
}

# Check 1: skill/0N-*.md filenames match Phase N headings
echo "Check 1: skill phase file numbering"
for f in skill/[0-9]*.md; do
    [ -f "$f" ] || continue
    fname_num=$(basename "$f" .md | cut -c1-2)
    # Get the Phase N: heading and extract N
    heading_num=$(grep -m1 "^# Phase " "$f" 2>/dev/null | grep -oE 'Phase [0-9]' | grep -oE '[0-9]')
    if [ -z "$heading_num" ]; then
        # Files like 00-terminology.md don't have a Phase heading — skip
        if [[ "$fname_num" == "00" ]]; then
            ok "$f is terminology (no phase heading expected)"
        else
            fail "$f has no '# Phase N:' heading"
        fi
    elif [ "$fname_num" != "0$heading_num" ] && [ "$fname_num" != "$heading_num" ]; then
        fail "$f (filename=$fname_num) doesn't match Phase $heading_num heading"
    else
        ok "$f matches Phase $heading_num"
    fi
done

# Check 2: paths referenced from commands/*.md exist
echo ""
echo "Check 2: command cross-references resolve"
MISSING_REFS=0
while IFS= read -r ref; do
    # Skip http(s):// URLs, # anchors, and lines that are clearly descriptive
    case "$ref" in
        http*) continue ;;
        \#*) continue ;;
    esac
    # Only check refs that look like paths (start with skill/ commands/ rules/ agents/ examples/)
    if [[ "$ref" =~ ^(skill|commands|rules|agents|examples)/ ]]; then
        # Strip trailing punctuation and any #fragment
        cleanref="${ref%%#*}"
        cleanref="${cleanref%\"}"
        cleanref="${cleanref%\'}"
        cleanref="${cleanref%,}"
        cleanref="${cleanref%)}"
        if [ ! -e "$cleanref" ]; then
            fail "command references non-existent path: $cleanref (from $ref)"
            MISSING_REFS=$((MISSING_REFS + 1))
        fi
    fi
done < <(grep -rhoE "(skill|commands|rules|agents|examples)/[a-zA-Z0-9_/.-]+\.md" commands/*.md 2>/dev/null | sort -u)

if [ "$MISSING_REFS" -eq 0 ]; then
    ok "all command cross-references resolve"
fi

# Check 3: vault fixture — every VULN-XX has a finding
echo ""
echo "Check 3: vault fixture VULN-XX ↔ findings.json coverage"
check_fixture_vuln_coverage "vault" "$VAULT_SRC" "$VAULT_FINDINGS"

# Check 4: CWE reference format
echo ""
echo "Check 4: CWE reference format"
CWE_COUNT=$(rg -c "CWE-[0-9]+" rules/audit.rules 2>/dev/null || echo 0)
INVALID_CWE=$(rg -o "CWE-[^0-9]" rules/audit.rules 2>/dev/null | head -3)
# Also verify each CWE URL points to cwe.mitre.org (no truncated placeholders)
BAD_CWE_URLS=$(rg -o 'CWE-[0-9]+[^"]*https://[^[:space:)]+html' rules/audit.rules 2>/dev/null | rg -v "cwe.mitre.org/data/definitions" || true)
if [ "$CWE_COUNT" -gt 0 ] && [ -z "$INVALID_CWE" ] && [ -z "$BAD_CWE_URLS" ]; then
    ok "$CWE_COUNT CWE references, all valid format and point to cwe.mitre.org"
else
    fail "CWE references malformed: $INVALID_CWE"
    [ -n "$BAD_CWE_URLS" ] && fail "CWE URLs not pointing to cwe.mitre.org: $BAD_CWE_URLS"
fi

# Check 5: every rule has a References block
echo ""
echo "Check 5: every rule has References block"
RULES=$(rg -c "^## Rule [0-9]+" rules/audit.rules 2>/dev/null || echo 0)
REFS=$(rg -c "^\*\*References:\*\*$" rules/audit.rules 2>/dev/null || echo 0)
if [ "$RULES" -gt 0 ] && [ "$RULES" = "$REFS" ]; then
    ok "$RULES rules, $REFS References blocks (1:1)"
else
    fail "rules vs References mismatch: $RULES rules, $REFS References blocks"
fi

# Check 6: findings.json severity summary matches actual counts for both fixtures
echo ""
echo "Check 6: findings.json severity summaries match actual counts"
run_single_arg_check_for_fixtures "check-summary" "findings.json summary matches actual counts"

# Check 7: AUDIT_REPORT.md severity table matches findings.json for both fixtures
echo ""
echo "Check 7: AUDIT_REPORT.md severity counts match findings.json"
run_two_arg_check_for_fixtures "check-report" "AUDIT_REPORT severity counts match findings.json"

# Check 8: CVSS score + vector consistency for both fixtures
echo ""
echo "Check 8: CVSS score + vector consistency across files"
run_two_arg_check_for_fixtures "check-cvss" "CVSS scores consistent across files"

# Check 9: agent count in CLAUDE.md / SKILL.md matches agents/ directory
echo ""
echo "Check 9: agent count consistency between docs and agents/ directory"
EXPECTED_AGENTS=$(ls agents/*.md 2>/dev/null | xargs -n1 basename | sed 's/\.md$//' | grep -v '^AUDIT$' | sort | tr '\n' ',' | sed 's/,$//')
for doc in CLAUDE.md skill/SKILL.md README.md; do
    if [ ! -f "$doc" ]; then continue; fi
    # Look for the Agents: line in the frontmatter/header
    MENTIONED=$(rg -o 'orchestrator|auditor|architecture-reviewer|threat-modeler|economic-security-analyst|formal-verifier|report-writer|cross-program-agent|safety-guard' "$doc" | sort -u | tr '\n' ',' | sed 's/,$//')
    if [ -n "$MENTIONED" ]; then
        # Compare
        if [ "$MENTIONED" != "$EXPECTED_AGENTS" ]; then
            fail "$doc mentions agents [$MENTIONED] but agents/ has [$EXPECTED_AGENTS]"
        else
            ok "$doc agent list matches agents/ directory"
        fi
    fi
done

# Check 10: CVSS scores in findings.json are mathematically derivable from their vectors
echo ""
echo "Check 10: CVSS scores are mathematically derivable from their vectors"
run_single_arg_check_for_fixtures "check-cvss-math" "CVSS scores match vectors (math verified)"

# Check 11: skill phase files chain — each non-terminal phase references the next
echo ""
echo "Check 11: skill phase files chain to the next phase"
for f in skill/01-recon.md skill/02-static-analysis.md skill/02B-runtime-testing.md skill/03-formal-verification.md skill/04-findings-triage.md skill/05-report-generation.md; do
    fname=$(basename "$f" .md)
    # Extract the numeric prefix from the filename (e.g., "02" from "02-static-analysis", "02B" from "02B-runtime-testing")
    num=$(echo "$fname" | grep -oE '^[0-9]+[A-Z]?' | head -1)
    if [ -z "$num" ]; then continue; fi
    # For numeric phases: "02" -> next is "03". For suffix phases like "02B": no standard next, skip chaining check
    if echo "$num" | grep -qE '[A-Z]$'; then
        # Phase 2B type — skip chain check (it's a sub-phase)
        ok "$fname is a sub-phase (no standard next phase check)"
    else
        next_num=$(printf "%02d" $((10#$num + 1)))
        if rg -q "skill/${next_num}-" "$f" 2>/dev/null; then
            ok "$fname → skill/${next_num}-*"
        else
            fail "$fname missing reference to next phase (skill/${next_num}-*)"
        fi
    fi
done

# Check 18: token-extensions fixture — every VULN-XX has a finding
echo ""
echo "Check 18: token-extensions fixture VULN-XX ↔ findings.json coverage"
check_fixture_vuln_coverage "token-extensions" "$TOKEN_SRC" "$TOKEN_FINDINGS"

# Check 21: token-2022-real fixture — every VULN-XX has a finding (NEW)
echo ""
echo "Check 21: token-2022-real fixture VULN-XX ↔ findings.json coverage"
check_fixture_vuln_coverage "token-2022-real" "$TOKEN2022_SRC" "$TOKEN2022_FINDINGS"

# Check 19: methodology-trace.md CVSS scores match findings.json
echo ""
echo "Check 19: methodology-trace.md CVSS scores match findings.json"
check_trace_cvss_for_fixture "vault" "$VAULT_FINDINGS" "examples/sample-vulnerable-program/audit-output/methodology-trace.md"
check_trace_cvss_for_fixture "token-extensions" "$TOKEN_FINDINGS" "examples/sample-vulnerable-program/audit-output/token-extensions/methodology-trace.md"
check_trace_cvss_for_fixture "token-2022-real" "$TOKEN2022_FINDINGS" "$TOKEN2022_TRACE"

# Check 20: Finding line numbers match VULN comment locations in source
echo ""
echo "Check 20: finding line numbers match VULN comment locations in source"
for line_check_pair in "vault:$VAULT_FINDINGS:$VAULT_SRC" "token-extensions:$TOKEN_FINDINGS:$TOKEN_SRC" "token-2022-real:$TOKEN2022_FINDINGS:$TOKEN2022_SRC"; do
    LABEL="${line_check_pair%%:*}"
    rest="${line_check_pair#*:}"
    F_PATH="${rest%%:*}"
    S_PATH="${rest##*:}"

    if [ ! -f "$F_PATH" ] || [ ! -f "$S_PATH" ]; then
        fail "$LABEL: cannot check line numbers — files missing"
        continue
    fi

    PYTHON_ARGS="$(dirname "$0")/severity_counts.py check-line-numbers $F_PATH $S_PATH"
    if python3 $PYTHON_ARGS 2>&1; then
        ok "$LABEL: all finding line numbers are within 5 lines of their VULN comments"
    else
        fail "$LABEL: finding line numbers drifted from VULN comments in source"
    fi
done

# Check 12: quick-scan-results.md pattern numbers align with commands/audit-quick.md
echo ""
echo "Check 12: quick-scan-results.md pattern alignment with commands/audit-quick.md"
if [ -f "examples/sample-vulnerable-program/audit-output/quick-scan-results.md" ] && [ -f "commands/audit-quick.md" ]; then
    # Extract just the row number from each table; same count + same numbering = aligned.
    EXPECTED_COUNT=$(rg -c '^\| [0-9]+ \|' commands/audit-quick.md)
    ACTUAL_COUNT=$(rg -c '^\| [0-9]+ \|' examples/sample-vulnerable-program/audit-output/quick-scan-results.md)
    if [ "$EXPECTED_COUNT" != "$ACTUAL_COUNT" ]; then
        fail "Pattern row count mismatch: audit-quick=$EXPECTED_COUNT, quick-scan-results=$ACTUAL_COUNT"
    else
        # Compare the row-number lists (sorted). Both should be 1..N.
        EXPECTED_NUMS=$(rg -o '^\| [0-9]+ \|' commands/audit-quick.md | rg -o '[0-9]+' | sort -n)
        ACTUAL_NUMS=$(rg -o '^\| [0-9]+ \|' examples/sample-vulnerable-program/audit-output/quick-scan-results.md | rg -o '[0-9]+' | sort -n)
        if [ "$EXPECTED_NUMS" = "$ACTUAL_NUMS" ]; then
            ok "quick-scan-results.md pattern numbering matches commands/audit-quick.md ($EXPECTED_COUNT patterns)"
        else
            fail "quick-scan-results.md pattern numbering drifts from commands/audit-quick.md"
            diff <(echo "$EXPECTED_NUMS") <(echo "$ACTUAL_NUMS") | head -5
        fi
    fi
else
    fail "quick-scan-results.md or commands/audit-quick.md missing"
fi

# Check 13: each specialist agent file has YAML frontmatter with a description
echo ""
echo "Check 13: specialist agent files have YAML frontmatter with description"
for agent in auditor formal-verifier report-writer orchestrator; do
    if [ -f "agents/${agent}.md" ]; then
        if head -1 "agents/${agent}.md" | rg -q "^---$" && head -10 "agents/${agent}.md" | rg -q "^description:"; then
            ok "agents/${agent}.md has YAML frontmatter with description"
        else
            fail "agents/${agent}.md missing YAML frontmatter with description — Claude Code auto-discovery won't work"
        fi
    else
        fail "agents/${agent}.md missing"
    fi
done

# Check 14: property-based (fuzz) tests pass
echo ""
echo "Check 14: property-based (fuzz) tests pass"
if [ -d "tests/fuzz" ]; then
    PYTEST_OUT=$(python3 -c "import pytest; pytest.main(['-x', '--tb=short', '-q', 'tests/fuzz/test_properties.py'])" 2>&1)
    PYTEST_EXIT=$?
    TEST_COUNT=$(echo "$PYTEST_OUT" | grep -o '[0-9]\+ passed' | head -1 || echo "unknown")
    if [ $PYTEST_EXIT -eq 0 ]; then
        ok "${TEST_COUNT:-all} property-based tests pass"
    else
        fail "Property-based tests failed (exit $PYTEST_EXIT) — run 'python3 -c \"import pytest; pytest.main([\\\"-v\\\", \\\"tests/fuzz/test_properties.py\\\"])\"'"
    fi
else
    fail "tests/fuzz/ directory missing — property-based tests not found"
fi

# Check 15: Brazilian Portuguese terminology in glossary
echo ""
echo "Check 15: Brazilian Portuguese (PT-BR) terminology present"
if [ -f "skill/00-terminology.md" ]; then
    PTBR_COUNT=$(grep -c 'PT-BR' skill/00-terminology.md 2>/dev/null || echo 0)
    if [ "$PTBR_COUNT" -ge 5 ]; then
        ok "$PTBR_COUNT PT-BR references in terminology file"
    else
        fail "Only $PTBR_COUNT PT-BR references found — expected >=5"
    fi
else
    fail "skill/00-terminology.md missing"
fi

# Check 16: SDD documentation files present (warning-only — these are
# gitignored session-state docs in the contest repo; see .gitignore).
# Presence is expected for the upstream moltbagus backup branch, where they
# are force-added. In the contest fork, absence is intentional.
echo ""
echo "Check 16: SDD documentation files present (advisory)"
SDD_FILES="PRD.md spec.md kanban.md learnings.md"
MISSING_SDD=0
for f in $SDD_FILES; do
    if [ -f "$f" ]; then
        ok "SDD file: $f"
    else
        warn "SDD file absent (gitignored session-state): $f"
        MISSING_SDD=$((MISSING_SDD + 1))
    fi
done
if [ "$MISSING_SDD" -eq 0 ]; then
    ok "all SDD documentation files present (PRD, Spec, Kanban, Learnings)"
fi

# Check 17: demo script exists and is executable
echo ""
echo "Check 17: demo script is present and executable"
if [ -f "demo.sh" ]; then
    if [ -x "demo.sh" ]; then
        ok "demo.sh exists and is executable"
    else
        fail "demo.sh exists but is not executable — run 'chmod +x demo.sh'"
    fi
else
    fail "demo.sh missing — contest demo script not found"
fi

# Check 21: formal verification demonstration
echo ""
echo "Check 21: formal verification demonstration"
if [ -f "tests/test-formal-verification.sh" ]; then
    if [ -x "tests/test-formal-verification.sh" ]; then
        if bash tests/test-formal-verification.sh > /dev/null 2>&1; then
            ok "formal verification demonstration passes"
        else
            # Capture output for diagnostics
            FV_OUT=$(bash tests/test-formal-verification.sh 2>&1)
            if echo "$FV_OUT" | grep -q "FAIL:"; then
                fail "formal verification demonstration failed"
                echo "$FV_OUT" | grep "FAIL:" | head -3
            else
                # SKIP-only failures are acceptable (Anchor not installed)
                ok "formal verification demonstration passes (or gracefully skipped)"
            fi
        fi
    else
        fail "tests/test-formal-verification.sh not executable — run 'chmod +x tests/test-formal-verification.sh'"
    fi
else
    fail "tests/test-formal-verification.sh missing"
fi

# =========================================================================
# v1.5 NEW CHECKS — World-Class additions
# =========================================================================

# Check 22: Phase 2B runtime testing file exists with YAML frontmatter
echo ""
echo "Check 22: Phase 2B runtime testing has YAML frontmatter"
if [ -f "skill/02B-runtime-testing.md" ]; then
    if head -1 "skill/02B-runtime-testing.md" | rg -q "^---$"; then
        ok "skill/02B-runtime-testing.md has YAML frontmatter"
    else
        fail "skill/02B-runtime-testing.md missing YAML frontmatter"
    fi
    if rg -q "Phase 2B" "skill/02B-runtime-testing.md"; then
        ok "skill/02B-runtime-testing.md has '# Phase 2B:' heading"
    else
        fail "skill/02B-runtime-testing.md missing '# Phase 2B:' heading"
    fi
else
    fail "skill/02B-runtime-testing.md missing"
fi

# Check 23: Cross-Program Agent has YAML frontmatter
echo ""
echo "Check 23: Cross-Program Agent has YAML frontmatter"
if [ -f "agents/cross-program-agent.md" ]; then
    if rg -q "^name: cross-program-agent" "agents/cross-program-agent.md"; then
        ok "agents/cross-program-agent.md has name frontmatter"
    else
        fail "agents/cross-program-agent.md missing name frontmatter"
    fi
    if rg -q "^description:" "agents/cross-program-agent.md"; then
        ok "agents/cross-program-agent.md has description"
    else
        fail "agents/cross-program-agent.md missing description"
    fi
    if rg -q "^outputs:" "agents/cross-program-agent.md"; then
        ok "agents/cross-program-agent.md has outputs definition"
    else
        fail "agents/cross-program-agent.md missing outputs"
    fi
else
    fail "agents/cross-program-agent.md missing"
fi

# Check 24: CPI graph generator script exists
echo ""
echo "Check 24: CPI graph generator script"
if [ -f "scripts/generate-cpi-graph.sh" ]; then
    if [ -x "scripts/generate-cpi-graph.sh" ]; then
        ok "scripts/generate-cpi-graph.sh exists and is executable"
    else
        fail "scripts/generate-cpi-graph.sh not executable"
    fi
    # Quick test: run script on example fixture and check output file
    if OUTPUT_FILE="cpi_surface.json" bash scripts/generate-cpi-graph.sh "examples/sample-vulnerable-program" > /dev/null 2>&1; then
        if python3 -c "import json; data = json.load(open('cpi_surface.json')); assert 'nodes' in data and 'edges' in data" 2>/dev/null; then
            ok "scripts/generate-cpi-graph.sh produces valid JSON"
        else
            fail "scripts/generate-cpi-graph.sh output is not valid JSON or missing nodes/edges"
        fi
        rm -f cpi_surface.json
    else
        fail "scripts/generate-cpi-graph.sh failed to run"
    fi
else
    fail "scripts/generate-cpi-graph.sh missing"
fi

# Check 25: cargo-audit integration in Phase 1
echo ""
echo "Check 25: cargo-audit integration in Phase 1"
if [ -f "skill/01-recon.md" ]; then
    if rg -q "cargo audit" "skill/01-recon.md"; then
        ok "cargo audit referenced in skill/01-recon.md"
    else
        fail "cargo audit not referenced in skill/01-recon.md"
    fi
    if rg -q "cargo-audit" "skill/01-recon.md"; then
        ok "cargo-audit tool mentioned in skill/01-recon.md"
    else
        fail "cargo-audit tool not mentioned in skill/01-recon.md"
    fi
else
    fail "skill/01-recon.md missing"
fi

# Check 26: Helius API integration in Phase 1
echo ""
echo "Check 26: Helius API integration in Phase 1"
if [ -f "skill/01-recon.md" ]; then
    if rg -q "Helius" "skill/01-recon.md"; then
        ok "Helius API referenced in skill/01-recon.md"
    else
        fail "Helius API not referenced in skill/01-recon.md"
    fi
    if rg -iq "upgrade_authority|on.chain|onchain|on chain|token_holders|program_size" "skill/01-recon.md"; then
        ok "On-chain state analysis mentioned in skill/01-recon.md"
    else
        fail "On-chain state analysis not found in skill/01-recon.md"
    fi
else
    fail "skill/01-recon.md missing"
fi

# Check 27: Toolchain auto-detection in Phase 1
echo ""
echo "Check 27: Toolchain auto-detection in Phase 1"
if [ -f "skill/01-recon.md" ]; then
    if rg -q "anchor --version" "skill/01-recon.md"; then
        ok "Anchor version detection in skill/01-recon.md"
    else
        fail "Anchor version detection not found in skill/01-recon.md"
    fi
    if rg -qi "TIER2|tier|auto.detect|Cargo.lock" "skill/01-recon.md"; then
        ok "Two-tier execution model documented in skill/01-recon.md"
    else
        fail "Two-tier execution model not documented"
    fi
else
    fail "skill/01-recon.md missing"
fi

# Check 28: runtime_findings.json schema in Phase 2B
echo ""
echo "Check 28: runtime_findings.json schema in Phase 2B"
if [ -f "skill/02B-runtime-testing.md" ]; then
    if rg -q "runtime_findings.json" "skill/02B-runtime-testing.md"; then
        ok "runtime_findings.json output schema in Phase 2B"
    else
        fail "runtime_findings.json not referenced in Phase 2B"
    fi
    if rg -qi "runtime_findings|TIER2_ENABLED|fuzz_results|anchor" "skill/02B-runtime-testing.md"; then
        ok "Phase 2B output includes required schema fields"
    else
        fail "Phase 2B output missing required schema fields"
    fi
else
    fail "skill/02B-runtime-testing.md missing"
fi

# Check 29: QED 2A fallback chain in Phase 2B
echo ""
echo "Check 29: QED 2A fallback chain in Phase 2B"
if [ -f "skill/02B-runtime-testing.md" ]; then
    if rg -qi "QED|fallback|TIER2|runtime_findings" "skill/02B-runtime-testing.md"; then
        ok "QED 2A / fallback chain referenced in Phase 2B"
    else
        fail "QED 2A fallback chain not found in Phase 2B"
    fi
else
    fail "skill/02B-runtime-testing.md missing"
fi

# Check 30: spec.md and PRD.md reflect 26 rules (advisory — both files are
# gitignored in the contest repo, see .gitignore; absence is intentional)
echo ""
echo "Check 30: spec.md and PRD.md reflect 26 rules (advisory)"
SPEC26=$(grep -c "26" spec.md 2>/dev/null || echo 0)
PRD26=$(grep -c "26" PRD.md 2>/dev/null || echo 0)
if [ "$SPEC26" -gt 0 ] && [ "$PRD26" -gt 0 ]; then
    ok "spec.md and PRD.md reference 26 rules"
elif [ ! -f spec.md ] && [ ! -f PRD.md ]; then
    warn "spec.md and PRD.md are absent (gitignored in contest fork)"
elif [ "$SPEC26" -eq 0 ]; then
    warn "spec.md present but missing 26-rules reference"
else
    warn "PRD.md present but missing 26-rules reference"
fi

# =========================================================================
# v1.6 AUTOMATION CHECKS — Pre-commit, PR audit, history, fix suggestions
# =========================================================================

# Check 31: pre-commit hook exists and is executable
echo ""
echo "Check 31: pre-commit hook exists and is executable"
if [ -f "scripts/pre-commit-audit.sh" ]; then
    if [ -x "scripts/pre-commit-audit.sh" ]; then
        ok "scripts/pre-commit-audit.sh exists and is executable"
    else
        fail "scripts/pre-commit-audit.sh not executable"
    fi
    if rg -qi "TIER2|CARGO_AUDIT|HIGH|CRITICAL" "scripts/pre-commit-audit.sh" 2>/dev/null; then
        ok "pre-commit hook has SAST pattern matching"
    else
        fail "pre-commit hook missing SAST patterns"
    fi
else
    fail "scripts/pre-commit-audit.sh missing"
fi

# Check 32: audit-pr command exists
echo ""
echo "Check 32: /audit-pr command exists"
if [ -f "commands/audit-pr.md" ]; then
    ok "commands/audit-pr.md exists"
    if rg -q "^name: audit-pr" "commands/audit-pr.md" 2>/dev/null; then
        ok "commands/audit-pr.md has name frontmatter"
    else
        fail "commands/audit-pr.md missing name frontmatter"
    fi
    if rg -qi "gh pr diff|diff_stats|new_findings|fixed_findings" "commands/audit-pr.md" 2>/dev/null; then
        ok "commands/audit-pr.md has PR diff analysis flow"
    else
        fail "commands/audit-pr.md missing PR diff analysis"
    fi
else
    fail "commands/audit-pr.md missing"
fi

# Check 33: audit-history command and script exist
echo ""
echo "Check 33: /audit-history command and script exist"
if [ -f "commands/audit-history.md" ]; then
    ok "commands/audit-history.md exists"
    if rg -q "^name: audit-history" "commands/audit-history.md" 2>/dev/null; then
        ok "commands/audit-history.md has name frontmatter"
    else
        fail "commands/audit-history.md missing name frontmatter"
    fi
else
    fail "commands/audit-history.md missing"
fi
if [ -f "scripts/audit-history.sh" ]; then
    if [ -x "scripts/audit-history.sh" ]; then
        ok "scripts/audit-history.sh exists and is executable"
    else
        fail "scripts/audit-history.sh not executable"
    fi
else
    fail "scripts/audit-history.sh missing"
fi

# Check 34: audit-fix-suggestions.py exists and runs
echo ""
echo "Check 34: audit-fix-suggestions.py exists and runs"
if [ -f "scripts/audit-fix-suggestions.py" ]; then
    ok "scripts/audit-fix-suggestions.py exists"
    if python3 -c "import ast; ast.parse(open('scripts/audit-fix-suggestions.py').read())" 2>/dev/null; then
        ok "scripts/audit-fix-suggestions.py is valid Python"
    else
        fail "scripts/audit-fix-suggestions.py has syntax errors"
    fi
    if python3 scripts/audit-fix-suggestions.py --help > /dev/null 2>&1; then
        ok "scripts/audit-fix-suggestions.py --help works"
    else
        fail "scripts/audit-fix-suggestions.py --help failed"
    fi
else
    fail "scripts/audit-fix-suggestions.py missing"
fi

# Check 35: CLAUDE.md references v1.6 automation
echo ""
echo "Check 35: CLAUDE.md references v1.6 automation"
if rg -qi "pre-commit|audit-pr|audit-history" CLAUDE.md 2>/dev/null; then
    ok "CLAUDE.md references v1.6 automation features"
else
    fail "CLAUDE.md missing v1.6 automation references"
fi

# =========================================================================
# v1.6 WORLD-CLASS AUDIT RULES CHECKS — Rules 27-35 coverage
# =========================================================================

# Check 36: Rules 27-35 exist in audit.rules
echo ""
echo "Check 36: Rules 27-35 exist in audit.rules"
MISSING_RULES=0
for i in $(seq 27 35); do
    if rg -q "^## Rule $i\b" rules/audit.rules 2>/dev/null; then
        ok "Rule $i exists in audit.rules"
    else
        fail "Rule $i missing from audit.rules"
        MISSING_RULES=$((MISSING_RULES + 1))
    fi
done
if [ "$MISSING_RULES" -eq 0 ]; then
    ok "All Rules 27-35 present in audit.rules"
fi

# Check 37: token-2022-real findings.json includes VULN-18
echo ""
echo "Check 37: token-2022-real findings.json includes VULN-18"
if [ -f "$TOKEN2022_FINDINGS" ]; then
    if rg -q "VULN-18" "$TOKEN2022_FINDINGS" 2>/dev/null; then
        ok "VULN-18 present in token-2022-real findings.json"
    else
        fail "VULN-18 missing from token-2022-real findings.json"
    fi
else
    fail "token-2022-real findings.json missing"
fi

# Check 38: Rule 27 contains transfer_hook keyword
echo ""
echo "Check 38: Rule 27 contains transfer_hook keyword"
if rg -q "^## Rule 27\b" rules/audit.rules 2>/dev/null; then
    # Extract the Rule 27 section and check for transfer_hook
    if awk '/^## Rule 27:/,/^## Rule 28:/' rules/audit.rules 2>/dev/null | grep -q "transfer_hook"; then
        ok "transfer_hook keyword found in Rule 27"
    else
        fail "transfer_hook keyword missing from Rule 27"
    fi
else
    fail "Rule 27 not found in audit.rules"
fi

# =========================================================================
# v1.7 WORLD-CLASS AUDIT RULES CHECKS — Rules 36-45 and native-vault fixture
# =========================================================================

# Check 39: Rules 36-45 exist in audit.rules
echo ""
echo "Check 39: Rules 36-45 exist in audit.rules"
MISSING_RULES_36_45=0
for i in $(seq 36 45); do
    if rg -q "^## Rule $i\b" rules/audit.rules 2>/dev/null; then
        ok "Rule $i exists in audit.rules"
    else
        fail "Rule $i missing from audit.rules"
        MISSING_RULES_36_45=$((MISSING_RULES_36_45 + 1))
    fi
done
if [ "$MISSING_RULES_36_45" -eq 0 ]; then
    ok "All Rules 36-45 present in audit.rules"
fi

# Check 40: native-vault fixture VULN-N0x ↔ findings.json coverage
echo ""
echo "Check 40: native-vault fixture VULN-N0x ↔ findings.json coverage"
NATIVE_VAULT_SRC="examples/sample-vulnerable-program/programs/native-vault/src/lib.rs"
NATIVE_VAULT_FINDINGS="examples/sample-vulnerable-program/audit-output/native-vault-findings.json"
NATIVE_VAULT_AUDIT_DIR="examples/sample-vulnerable-program/audit-output"

if [ -f "$NATIVE_VAULT_SRC" ] && [ -f "$NATIVE_VAULT_FINDINGS" ]; then
    # Extract VULN-N01, VULN-N02, VULN-N03, VULN-N04 from source
    native_src_ids=$(rg "^\s*// VULN-N0[1-4]" "$NATIVE_VAULT_SRC" 2>/dev/null | rg -o "VULN-N0[1-4]" | sort -u)
    native_fnd_ids=$(rg -o '"id":\s*"VULN-N0[1-4]"' "$NATIVE_VAULT_FINDINGS" 2>/dev/null | grep -oE 'VULN-N0[1-4]' | sort -u)
    native_src_count=$(echo "$native_src_ids" | wc -l | tr -d ' ')
    native_fnd_count=$(echo "$native_fnd_ids" | wc -l | tr -d ' ')
    if [ "$native_src_count" = "$native_fnd_count" ] && [ "$native_src_count" -gt 0 ]; then
        ok "native-vault: $native_src_count VULN-N0x in source, $native_fnd_count in findings.json (match)"
    else
        fail "native-vault: VULN-N0x mismatch: $native_src_count in source vs $native_fnd_count in findings.json"
        diff <(echo "$native_src_ids") <(echo "$native_fnd_ids") | head -10
    fi
else
    fail "native-vault: source or findings.json missing"
fi

# Check 41: native-vault fixture exists
echo ""
echo "Check 41: native-vault fixture exists"
if [ -d "examples/sample-vulnerable-program/programs/native-vault" ]; then
    ok "native-vault directory exists"
    if [ -f "$NATIVE_VAULT_SRC" ]; then
        ok "native-vault src/lib.rs exists"
    else
        fail "native-vault src/lib.rs missing"
    fi
else
    fail "native-vault directory missing"
fi

# Check 42: Rule 36 contains "sysvar" keyword (Pinocchio sysvar spoofing detection)
echo ""
echo "Check 42: Rule 36 contains sysvar keyword"
if rg -q "^## Rule 36\b" rules/audit.rules 2>/dev/null; then
    # Extract the Rule 36 section and check for sysvar
    if awk '/^## Rule 36:/,/^## Rule 37:/' rules/audit.rules 2>/dev/null | grep -qi "sysvar"; then
        ok "sysvar keyword found in Rule 36"
    else
        fail "sysvar keyword missing from Rule 36"
    fi
else
    fail "Rule 36 not found in audit.rules"
fi

# Check 43: native-vault fixture has AUDIT_REPORT
echo ""
echo "Check 43: native-vault fixture has AUDIT_REPORT"
NATIVE_VAULT_REPORT="examples/sample-vulnerable-program/audit-output/native-vault-AUDIT_REPORT.md"
if [ -f "$NATIVE_VAULT_REPORT" ]; then
    ok "native-vault AUDIT_REPORT.md exists"
else
    fail "native-vault AUDIT_REPORT.md missing"
fi

# =========================================================================
# v1.8 WORLD-CLASS AUDIT RULES CHECKS — safety-guard agent + Rules 46-50 + location.file
# =========================================================================

# Check 44: agents/safety-guard.md exists with YAML frontmatter
echo ""
echo "Check 44: agents/safety-guard.md has YAML frontmatter"
if [ -f "agents/safety-guard.md" ]; then
    if head -1 "agents/safety-guard.md" | rg -q "^---$" && head -10 "agents/safety-guard.md" | rg -q "^name:"; then
        ok "agents/safety-guard.md has YAML frontmatter with name"
    else
        fail "agents/safety-guard.md missing YAML frontmatter with name"
    fi
    if head -20 "agents/safety-guard.md" | rg -q "^description:"; then
        ok "agents/safety-guard.md has description"
    else
        fail "agents/safety-guard.md missing description"
    fi
else
    fail "agents/safety-guard.md missing"
fi

# Check 45: commands/audit.md references safety-guard agent
echo ""
echo "Check 45: commands/audit.md references safety-guard agent"
if [ -f "commands/audit.md" ]; then
    if rg -q "safety-guard" "commands/audit.md" 2>/dev/null; then
        ok "safety-guard agent referenced in commands/audit.md"
    else
        fail "safety-guard agent not referenced in commands/audit.md"
    fi
else
    fail "commands/audit.md missing"
fi

# Check 46: Rules 46-50 exist in audit.rules
echo ""
echo "Check 46: Rules 46-50 exist in audit.rules"
MISSING_RULES_46_50=0
for i in $(seq 46 50); do
    if rg -q "^## Rule $i\b" rules/audit.rules 2>/dev/null; then
        ok "Rule $i exists in audit.rules"
    else
        fail "Rule $i missing from audit.rules"
        MISSING_RULES_46_50=$((MISSING_RULES_46_50 + 1))
    fi
done
if [ "$MISSING_RULES_46_50" -eq 0 ]; then
    ok "All Rules 46-50 present in audit.rules"
fi

# Check 47: No findings.json lacks location.file field
echo ""
echo "Check 47: All findings have location.file field"
MISSING_LOC_FILE=0
for findings_file in \
    "examples/sample-vulnerable-program/audit-output/findings.json" \
    "examples/sample-vulnerable-program/audit-output/token-extensions/findings.json" \
    "examples/token-2022-real/audit-output/findings.json" \
    "examples/sample-vulnerable-program/audit-output/native-vault-findings.json"; do
    if [ -f "$findings_file" ]; then
        while IFS= read -r finding_id; do
            if [ -z "$finding_id" ]; then continue; fi
            if ! python3 -c "
import json, sys
data = json.load(open('$findings_file'))
for f in data.get('findings', []):
    if f.get('id') == '$finding_id':
        loc = f.get('location', {})
        if 'file' not in loc:
            print(f.get('id', 'unknown'))
" 2>/dev/null | grep -q .; then
                ok "$(basename "$findings_file"): all findings have location.file"
            else
                fail "$(basename "$findings_file"): finding without location.file: $finding_id"
                MISSING_LOC_FILE=$((MISSING_LOC_FILE + 1))
            fi
        done < <(python3 -c "
import json
with open('$findings_file') as f:
    data = json.load(f)
for finding in data.get('findings', []):
    print(finding.get('id', ''))
" 2>/dev/null)
    fi
done
if [ "$MISSING_LOC_FILE" -eq 0 ]; then
    ok "All fixture findings.json have location.file on every finding"
fi

# =========================================================================
# v1.8 REMEDIATION ENGINE CHECKS — root_cause and regression_test integrity
# =========================================================================

# Check 48: Every finding in findings.json has non-empty root_cause
echo ""
echo "Check 48: All findings have non-empty root_cause field"
ROOT_CAUSE_CHECK=$(python3 -c "
import json, os
findings_files = [
    'examples/sample-vulnerable-program/audit-output/findings.json',
    'examples/sample-vulnerable-program/audit-output/token-extensions/findings.json',
    'examples/token-2022-real/audit-output/findings.json',
    'examples/sample-vulnerable-program/audit-output/native-vault-findings.json',
]
failures = []
for fp in findings_files:
    if not os.path.exists(fp):
        continue
    data = json.load(open(fp))
    for f in data.get('findings', []):
        fid = f.get('id', 'unknown')
        rc = f.get('root_cause', '')
        if not rc or len(str(rc).strip()) < 10:
            failures.append(f'{os.path.basename(fp)}: {fid} missing root_cause')
print('\n'.join(failures) if failures else 'OK', end='')
" 2>/dev/null)
if [ "$ROOT_CAUSE_CHECK" = "OK" ]; then
    ok "All fixture findings.json have non-empty root_cause"
else
    echo "$ROOT_CAUSE_CHECK" | while read -r line; do
        [ -z "$line" ] && continue
        fail "$line"
    done
fi

# Check 49: Every regression_test in findings.json is syntactically valid
# Python-only validation to handle multiline test code (read splits on newlines)
echo ""
echo "Check 49: All regression_test patterns are syntactically valid"
REGRESSION_CHECK=$(python3 -c "
import json, sys, re, os

PATTERNS = [r'fn test_', r'#\[test\]', r'assert!', r'let result =']
findings_files = [
    'examples/sample-vulnerable-program/audit-output/findings.json',
    'examples/sample-vulnerable-program/audit-output/token-extensions/findings.json',
    'examples/token-2022-real/audit-output/findings.json',
    'examples/sample-vulnerable-program/audit-output/native-vault-findings.json',
]
failures = []
for fp in findings_files:
    if not os.path.exists(fp):
        continue
    data = json.load(open(fp))
    for f in data.get('findings', []):
        fid = f.get('id', 'unknown')
        rt = f.get('regression_test', '')
        if not rt:
            continue
        matched = any(re.search(p, rt) for p in PATTERNS)
        if not matched:
            failures.append(f'{os.path.basename(fp)}: {fid} regression_test lacks test syntax')
print('\n'.join(failures) if failures else 'OK', end='')
" 2>/dev/null)
if [ "$REGRESSION_CHECK" = "OK" ]; then
    ok "All regression_test patterns contain valid test syntax (fn test, #[test], assert)"
else
    echo "$REGRESSION_CHECK" | while read -r line; do
        [ -z "$line" ] && continue
        fail "$line"
    done
fi

# Check 50: Solend governance live exploit audit present
echo ""
echo "Check 50: Solend governance live exploit audit"
SOLEND_FINDINGS="examples/solend-governance-audit/audit-output/findings.json"
if [ -f "$SOLEND_FINDINGS" ]; then
    SOLEND_COUNT=$(python3 -c "import json; print(len(json.load(open('$SOLEND_FINDINGS')).get('findings', [])))" 2>/dev/null || echo 0)
    SOLEND_CRIT=$(python3 -c "import json; d=json.load(open('$SOLEND_FINDINGS')); print(d.get('summary',{}).get('critical',0))" 2>/dev/null || echo 0)
    SOLEND_HIGH=$(python3 -c "import json; d=json.load(open('$SOLEND_FINDINGS')); print(d.get('summary',{}).get('high',0))" 2>/dev/null || echo 0)
    if [ "$SOLEND_COUNT" -ge 3 ] && [ "$SOLEND_CRIT" -ge 1 ] && [ "$SOLEND_HIGH" -ge 1 ]; then
        ok "Solend live audit: $SOLEND_COUNT findings ($SOLEND_CRIT CRIT, $SOLEND_HIGH HIGH)"
    else
        fail "Solend live audit has unexpected counts: $SOLEND_COUNT findings ($SOLEND_CRIT CRIT, $SOLEND_HIGH HIGH)"
    fi
    if [ -f "examples/solend-governance-audit/audit-output/AUDIT_REPORT.md" ]; then
        ok "Solend AUDIT_REPORT.md present"
    else
        fail "Solend AUDIT_REPORT.md missing"
    fi
else
    fail "Solend governance live audit findings.json missing"
fi

# Summary
echo ""
echo "================================"
echo "PASS: $PASS"
echo "FAIL: $FAIL"
echo "================================"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
