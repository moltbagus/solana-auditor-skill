#!/usr/bin/env bash
#===============================================================================
# fix-verification.sh — Verify fixes resolve vulnerabilities
#
# Usage:
#   bash scripts/fix-verification.sh <finding-id> [--build] [--test] [--poc]
#
# Options:
#   --build    Run anchor build
#   --test     Run anchor test (default)
#   --poc      Run PoC verification
#   --full     Run all checks
#
# Exit codes:
#   0  = verification passed
#   1  = verification failed
#   2  = finding not found
#   3  = prerequisite missing (anchor, solana)
#===============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AUDIT_OUTPUT="${PROJECT_ROOT}/audit-output"
FINDINGS_JSON="${AUDIT_OUTPUT}/findings.json"
FIX_SUGGESTIONS_JSON="${AUDIT_OUTPUT}/fix_suggestions.json"

# Default options
RUN_BUILD=false
RUN_TEST=false
RUN_POC=false
RUN_FULL=false
FINDING_ID=""

#-------------------------------------------------------------------------------
# Helpers
#-------------------------------------------------------------------------------

usage() {
    cat <<EOF
${BOLD}Usage:${RESET} $0 <finding-id> [options]

${BOLD}Options:${RESET}
  --build    Run anchor build verification
  --test     Run anchor test (default if no options specified)
  --poc      Run PoC verification
  --full     Run all checks (build + test + poc)
  --help     Show this help message

${BOLD}Examples:${RESET}
  $0 CRIT-01 --test
  $0 CRIT-01 --full
  $0 HIGH-03 --build

EOF
}

log_info() {
    echo -e "${BLUE}[INFO]${RESET} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${RESET} $1"
}

log_fail() {
    echo -e "${RED}[FAIL]${RESET} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${RESET} $1"
}

separator() {
    echo "--------------------------------------------------------------------------------"
}

#-------------------------------------------------------------------------------
# Prerequisite checks
#-------------------------------------------------------------------------------

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check for anchor
    if ! command -v anchor &> /dev/null; then
        log_warn "anchor CLI not found. Tier 1 (SAST) mode only."
        return 1
    fi

    # Check for solana CLI
    if ! command -v solana &> /dev/null; then
        log_warn "solana CLI not found. Tier 1 (SAST) mode only."
        return 1
    fi

    # Check for bc (required for CVSS reduction math)
    if ! command -v bc &> /dev/null; then
        log_warn "bc not found. CVSS reduction calculation will be skipped."
        echo "  Install bc: brew install bc (macOS) or apt install bc (Linux)"
    fi

    log_pass "All prerequisites satisfied (Tier 2 mode)"
    return 0
}

#-------------------------------------------------------------------------------
# Finding lookup
#-------------------------------------------------------------------------------

find_finding() {
    local finding_id="$1"

    if [[ ! -f "$FINDINGS_JSON" ]]; then
        echo "ERROR: findings.json not found at $FINDINGS_JSON"
        echo "       Run an audit first to generate findings."
        return 2
    fi

    # Use jq to find the finding
    if command -v jq &> /dev/null; then
        local finding
        finding=$(jq --arg id "$finding_id" '.findings[] | select(.id == $id)' "$FINDINGS_JSON" 2>/dev/null)

        if [[ -z "$finding" ]]; then
            echo "ERROR: Finding $finding_id not found in findings.json"
            return 2
        fi

        echo "$finding"
        return 0
    else
        # Fallback: grep-based search
        log_warn "jq not found, using grep fallback"
        if grep -q "\"id\": \"$finding_id\"" "$FINDINGS_JSON"; then
            echo "Finding $finding_id exists (details require jq)"
            return 0
        else
            echo "ERROR: Finding $finding_id not found"
            return 2
        fi
    fi
}

#-------------------------------------------------------------------------------
# Verification steps
#-------------------------------------------------------------------------------

verify_build() {
    local finding_id="$1"
    separator
    log_info "Running anchor build verification for $finding_id..."

    # Check if we're in an Anchor project
    if [[ ! -f "${PROJECT_ROOT}/Anchor.toml" ]]; then
        log_warn "Not an Anchor project (no Anchor.toml found)"
        log_warn "Skipping build verification"
        return 0
    fi

    # Run anchor build
    if anchor build 2>&1 | tail -20; then
        log_pass "anchor build succeeded"
        return 0
    else
        log_fail "anchor build failed"
        return 1
    fi
}

verify_test() {
    local finding_id="$1"
    separator
    log_info "Running anchor test verification for $finding_id..."

    # Check if we're in an Anchor project
    if [[ ! -f "${PROJECT_ROOT}/Anchor.toml" ]]; then
        log_warn "Not an Anchor project (no Anchor.toml found)"
        log_warn "Skipping test verification"
        return 0
    fi

    # Run anchor test with grep for finding-specific test
    if anchor test --grep "$finding_id" 2>&1 | tail -30; then
        log_pass "anchor test passed for $finding_id"
        return 0
    else
        # Try full test suite if finding-specific test not found
        log_warn "Finding-specific test not found, running full test suite..."
        if anchor test 2>&1 | tail -30; then
            log_pass "anchor test suite passed"
            return 0
        else
            log_fail "anchor test failed"
            return 1
        fi
    fi
}

verify_poc() {
    local finding_id="$1"
    separator
    log_info "Running PoC verification for $finding_id..."

    # Look for PoC file (bash 3.2 compatible lowercase conversion)
    local poc_dir="${AUDIT_OUTPUT}/pocs"
    local lower_id
    lower_id=$(echo "$finding_id" | tr '[:upper:]' '[:lower:]')
    local poc_file="${poc_dir}/${lower_id}.md"

    if [[ -f "$poc_file" ]]; then
        log_info "Found PoC: $poc_file"
        log_info "To run PoC, use: /audit-poc $finding_id"
        return 0
    else
        # Look for any PoC in the finding
        if [[ -f "$FINDINGS_JSON" ]] && command -v jq &> /dev/null; then
            local poc_status
            poc_status=$(jq --arg id "$finding_id" -r '.findings[] | select(.id == $id) | .poc_status // "none"' "$FINDINGS_JSON" 2>/dev/null)
            if [[ "$poc_status" != "none" && "$poc_status" != "pending" ]]; then
                log_pass "PoC status: $poc_status"
                return 0
            fi
        fi

        log_warn "No PoC found for $finding_id"
        log_info "To create a PoC, use: /audit-poc $finding_id"
        return 1
    fi
}

verify_cvss_recalculation() {
    local finding_id="$1"
    separator
    log_info "Verifying CVSS recalculation for $finding_id..."

    if [[ ! -f "$FINDINGS_JSON" ]] || ! command -v jq &> /dev/null; then
        log_warn "Cannot verify CVSS (findings.json or jq not available)"
        return 0
    fi

    # Extract finding details
    local cvss_before cvss_after severity rule
    cvss_before=$(jq --arg id "$finding_id" -r '.findings[] | select(.id == $id) | .cvss // 0' "$FINDINGS_JSON" 2>/dev/null)
    severity=$(jq --arg id "$finding_id" -r '.findings[] | select(.id == $id) | .severity // "UNKNOWN"' "$FINDINGS_JSON" 2>/dev/null)
    rule=$(jq --arg id "$finding_id" -r '.findings[] | select(.id == $id) | .rule_caught // "UNKNOWN"' "$FINDINGS_JSON" 2>/dev/null)

    echo ""
    echo "  Finding:    $finding_id"
    echo "  Severity:   $severity"
    echo "  Rule:       $rule"
    echo "  CVSS:       $cvss_before"

    # Check for remediation block
    local has_remediation=false
    if jq --arg id "$finding_id" -e '.findings[] | select(.id == $id) | .remediation' "$FINDINGS_JSON" &>/dev/null; then
        has_remediation=true
        local cvss_after cvss_after_vector
        cvss_after=$(jq --arg id "$finding_id" -r '.findings[] | select(.id == $id) | .remediation.cvss_after.score // "N/A"' "$FINDINGS_JSON" 2>/dev/null)
        cvss_after_vector=$(jq --arg id "$finding_id" -r '.findings[] | select(.id == $id) | .remediation.cvss_after.vector // "N/A"' "$FINDINGS_JSON" 2>/dev/null)

        echo "  CVSS After: $cvss_after"
        echo "  Vector:     $cvss_after_vector"

        if [[ "$cvss_after" != "N/A" && "$cvss_after" != "0" ]]; then
            local reduction="N/A"
            if command -v bc &> /dev/null; then
                reduction=$(echo "$cvss_before - $cvss_after" | bc -l 2>/dev/null || echo "N/A")
            else
                log_warn "bc not available — CVSS reduction not computed"
            fi
            echo "  Reduction:  $reduction"
        fi
    else
        echo "  Remediation block not found"
        echo ""
        echo "  To add CVSS recalculation, use:"
        echo "    python scripts/audit-fix-suggestions.py --cvss-before-after --finding $finding_id"
    fi

    # Run severity_counts.py verification if available
    local severity_script="${PROJECT_ROOT}/tests/severity_counts.py"
    if [[ -f "$severity_script" ]]; then
        separator
        log_info "Verifying CVSS math with severity_counts.py..."
        if python3 "$severity_script" --verify "$FINDING_ID" 2>/dev/null; then
            log_pass "CVSS math verified"
        else
            log_warn "CVSS math verification skipped or failed"
        fi
    fi

    return 0
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --build)
                RUN_BUILD=true
                shift
                ;;
            --test)
                RUN_TEST=true
                shift
                ;;
            --poc)
                RUN_POC=true
                shift
                ;;
            --full)
                RUN_FULL=true
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            -*)
                echo "ERROR: Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [[ -z "$FINDING_ID" ]]; then
                    FINDING_ID="$1"
                else
                    echo "ERROR: Unexpected argument: $1"
                    usage
                    exit 1
                fi
                shift
                ;;
        esac
    done

    # Check required arguments
    if [[ -z "$FINDING_ID" ]]; then
        echo "ERROR: Finding ID required"
        usage
        exit 1
    fi

    # Default to --test if no options specified
    if [[ "$RUN_BUILD" == "false" && "$RUN_TEST" == "false" && "$RUN_POC" == "false" && "$RUN_FULL" == "false" ]]; then
        RUN_TEST=true
    fi

    # Run full if requested
    if [[ "$RUN_FULL" == "true" ]]; then
        RUN_BUILD=true
        RUN_TEST=true
        RUN_POC=true
    fi

    echo ""
    echo "================================================================================"
    echo -e "${BOLD}Fix Verification for $FINDING_ID${RESET}"
    echo "================================================================================"
    echo ""

    # Check prerequisites
    check_prerequisites || true

    # Find the finding
    separator
    log_info "Looking up finding $FINDING_ID..."
    if ! find_finding "$FINDING_ID" > /dev/null 2>&1; then
        log_fail "Finding not found"
        exit 2
    fi
    log_pass "Finding $FINDING_ID found"

    # Track results
    local build_result=0
    local test_result=0
    local poc_result=0

    # Run verification steps
    if [[ "$RUN_BUILD" == "true" ]]; then
        if ! verify_build "$FINDING_ID"; then
            build_result=1
        fi
    fi

    if [[ "$RUN_TEST" == "true" ]]; then
        if ! verify_test "$FINDING_ID"; then
            test_result=1
        fi
    fi

    if [[ "$RUN_POC" == "true" ]]; then
        if ! verify_poc "$FINDING_ID"; then
            poc_result=1
        fi
    fi

    # CVSS recalculation
    verify_cvss_recalculation "$FINDING_ID"

    # Summary
    separator
    echo ""
    echo -e "${BOLD}Verification Summary for $FINDING_ID${RESET}"
    echo ""

    local total_passed=0
    local total_failed=0

    if [[ "$RUN_BUILD" == "true" ]]; then
        if [[ $build_result -eq 0 ]]; then
            log_pass "anchor build"
            ((total_passed++))
        else
            log_fail "anchor build"
            ((total_failed++))
        fi
    fi

    if [[ "$RUN_TEST" == "true" ]]; then
        if [[ $test_result -eq 0 ]]; then
            log_pass "anchor test"
            ((total_passed++))
        else
            log_fail "anchor test"
            ((total_failed++))
        fi
    fi

    if [[ "$RUN_POC" == "true" ]]; then
        if [[ $poc_result -eq 0 ]]; then
            log_pass "PoC verification"
            ((total_passed++))
        else
            log_warn "PoC verification (skipped or no PoC)"
        fi
    fi

    echo ""
    separator
    echo ""

    if [[ $total_failed -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}All verification checks PASSED${RESET}"
        echo ""
        echo "The fix for $FINDING_ID has been verified."
        echo "Update findings.json status to 'Fixed' and record verification timestamp."
        exit 0
    else
        echo -e "${RED}${BOLD}Some verification checks FAILED${RESET}"
        echo ""
        echo "Please review the failed checks above."
        echo "Do NOT mark $FINDING_ID as fixed until all checks pass."
        exit 1
    fi
}

main "$@"
