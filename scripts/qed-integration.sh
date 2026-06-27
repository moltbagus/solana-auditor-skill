#!/bin/bash
# =============================================================================
# qed-integration.sh — QED 2A formal verification CI wrapper
# =============================================================================
# Exit codes:
#   0  = success (all invariants proved or disproved with findings)
#   1  = failure (tool error, unexpected state)
#   2  = skip (no toolchain available)
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

REPORT_FILE="$REPO_ROOT/formal_verification_report.json"
PROGRAMS_DIR="$REPO_ROOT/programs"
MAX_INVARIANT_TIME=60  # seconds per invariant

# ── Detect toolchain ──────────────────────────────────────────────────────────
detect_qed() {
    if command -v qed-solana >/dev/null 2>&1; then
        qed-solana --version 2>/dev/null || true
        echo "QED_SOLANA_FOUND"
    else
        echo "QED_SOLANA_NOT_FOUND"
    fi
}

# ── Check program directory ───────────────────────────────────────────────────
check_programs() {
    if [ ! -d "$PROGRAMS_DIR" ]; then
        echo "No programs/ directory found — nothing to verify"
        return 1
    fi
    local count
    count=$(find "$PROGRAMS_DIR" -name "Cargo.toml" -maxdepth 2 | wc -l | tr -d ' ')
    if [ "$count" -eq 0 ]; then
        echo "No Anchor programs found in programs/"
        return 1
    fi
    echo "Found $count program(s) to verify"
}

# ── Generate report header ───────────────────────────────────────────────────
init_report() {
    local program_count="${1:-0}"
    cat > "$REPORT_FILE" <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "tool": "qed-solana",
  "version": "$(qed-solana --version 2>/dev/null | head -1 || echo 'unknown')",
  "programs_verified": $program_count,
  "status": "running",
  "invariants": [],
  "findings": [],
  "skipped": [],
  "errors": []
}
EOF
}

# ── Run QED against one program ──────────────────────────────────────────────
verify_program() {
    local program_path="$1"
    local program_name
    program_name=$(basename "$program_path")

    echo "=== Verifying: $program_name ==="

    # Check for compiled .so file
    local so_file="$program_path/target/deploy/${program_name}.so"
    if [ ! -f "$so_file" ]; then
        echo "SKIP: No compiled .so for $program_name (build required)"
        jq --arg name "$program_name" --arg reason "not_compiled" \
           '.skipped += [{"program": $name, "reason": $reason}]' \
           "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
        return 0
    fi

    # Run QED with timeout per invariant
    local start_time
    start_time=$(date +%s)

    local result
    result=$(timeout "$MAX_INVARIANT_TIME" qed-solana verify \
        --program "$so_file" \
        --output json 2>&1) || local qed_exit=$?

    local elapsed=$(( $(date +%s) - start_time ))

    if [ -n "${qed_exit:-}" ]; then
        case $qed_exit in
            124) # timeout
                echo "TIMEOUT: $program_name exceeded ${MAX_INVARIANT_TIME}s"
                jq --arg name "$program_name" --arg reason "timeout_${elapsed}s" \
                   '.skipped += [{"program": $name, "reason": $reason}]' \
                   "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
                ;;
            127) # command not found
                echo "ERROR: qed-solana not found"
                return 2
                ;;
            *)   # other error
                echo "ERROR: qed-solana exited $qed_exit for $program_name"
                jq --arg name "$program_name" --arg exit_code "$qed_exit" \
                   '.errors += [{"program": $name, "exit_code": ($exit_code | tonumber)}]' \
                   "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
                ;;
        esac
        return 1
    fi

    # Parse result
    local status
    status=$(echo "$result" | jq -r '.status // "unknown"' 2>/dev/null || echo "parse_error")

    echo "  status: $status (${elapsed}s)"
    jq --arg name "$program_name" --arg status "$status" \
       --argjson elapsed "$elapsed" \
       --argjson raw "$result" \
       '.invariants += [{
         "program": $name,
         "status": $status,
         "elapsed_seconds": $elapsed,
         "raw_output": $raw
       }]' \
       "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"

    # Extract counterexamples → findings
    if [ "$status" = "violated" ] || [ "$status" = "counterexample" ]; then
        local findings
        findings=$(echo "$result" | jq -r '.counterexamples // [] | length' 2>/dev/null || echo "0")
        if [ "$findings" -gt 0 ]; then
            echo "$result" | jq -r '.counterexamples[] |
              @json' 2>/dev/null | while read -r finding; do
                jq --argjson f "$finding" --arg program "$program_name" \
                   '.findings += [{
                     "program": $program,
                     "severity": "HIGH",
                     "source": "formal-verification",
                     "rule_caught": "formal-verification",
                     "description": ($f.description // "Invariant violated"),
                     "counterexample": $f
                   }]' \
                   "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
            done
        fi
    fi

    echo "  → $program_name: $status"
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
    echo "=== QED 2A Formal Verification ==="

    local qed_status
    qed_status=$(detect_qed)

    if [ "$qed_status" = "QED_SOLANA_NOT_FOUND" ]; then
        echo "SKIP: qed-solana not installed"
        echo '{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'","status":"skipped","reason":"qed-solana_not_found"}' > "$REPORT_FILE"
        exit 2
    fi

    echo "QED toolchain: $qed_status"

    if ! check_programs; then
        echo "SKIP: No programs to verify"
        echo '{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'","status":"skipped","reason":"no_programs"}' > "$REPORT_FILE"
        exit 2
    fi

    local program_count
    program_count=$(find "$PROGRAMS_DIR" -name "Cargo.toml" -maxdepth 2 | wc -l | tr -d ' ')
    init_report "$program_count"

    # Verify each program
    local exit_code=0
    for program in "$PROGRAMS_DIR"/*/Cargo.toml; do
        local dir
        dir=$(dirname "$program")
        verify_program "$dir" || exit_code=$?
    done

    # Finalize report
    local total_invariants
    total_invariants=$(jq '.invariants | length' "$REPORT_FILE")
    local total_findings
    total_findings=$(jq '.findings | length' "$REPORT_FILE")

    jq --argjson total_invariants "$total_invariants" \
       --argjson total_findings "$total_findings" \
       '.total_invariants = $total_invariants |
        .total_findings = $total_findings |
        .status = if .errors | length > 0 then "partial" else "complete" end' \
       "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"

    echo "=== Summary ==="
    echo "  Programs: $program_count"
    echo "  Invariants checked: $total_invariants"
    echo "  Findings: $total_findings"

    exit $exit_code
}

main "$@"
