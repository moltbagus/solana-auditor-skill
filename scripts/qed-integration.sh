#!/bin/bash
# =============================================================================
# qed-integration.sh — QEDGen formal verification CI wrapper
# =============================================================================
# Supports both qedgen (new) and qed-solana (legacy) toolchains.
#
# Exit codes:
#   0  = success (all invariants proved or findings generated)
#   1  = failure (tool error, unexpected state)
#   2  = skip (no toolchain available)
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

REPORT_FILE="$REPO_ROOT/formal_verification_report.json"
PROGRAMS_DIR="$REPO_ROOT/programs"
MAX_INVARIANT_TIME=120  # seconds per invariant

# ── Detect toolchain ──────────────────────────────────────────────────────────
detect_toolchain() {
    # Check for qedgen (new) first, then qed-solana (legacy)
    if command -v qedgen >/dev/null 2>&1; then
        echo "QEDGEN_FOUND"
        return
    fi
    if command -v qed-solana >/dev/null 2>&1; then
        echo "QED_SOLANA_FOUND"
        return
    fi
    echo "NOT_FOUND"
}

get_tool_name() {
    if command -v qedgen >/dev/null 2>&1; then
        echo "qedgen"
    elif command -v qed-solana >/dev/null 2>&1; then
        echo "qed-solana"
    else
        echo ""
    fi
}

get_tool_version() {
    local tool
    tool=$(get_tool_name)
    if [ -z "$tool" ]; then
        echo "unknown"
        return
    fi
    "$tool" --version 2>/dev/null | head -1 || echo "unknown"
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
        echo "No programs found in programs/"
        return 1
    fi
    echo "Found $count program(s) to verify"
}

# ── Generate report ──────────────────────────────────────────────────────────
init_report() {
    local program_count="${1:-0}"
    local tool
    tool=$(get_tool_name)
    local version
    version=$(get_tool_version)
    cat > "$REPORT_FILE" <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "tool": "${tool:-qedgen}",
  "version": "${version:-unknown}",
  "programs_verified": $program_count,
  "status": "running",
  "invariants": [],
  "findings": [],
  "skipped": [],
  "errors": []
}
EOF
}

# ── Run QED verify on one program ───────────────────────────────────────────
verify_program() {
    local program_path="$1"
    local program_name
    program_name=$(basename "$program_path")

    echo "=== Verifying: $program_name ==="

    local tool
    tool=$(get_tool_name)
    if [ -z "$tool" ]; then
        echo "ERROR: No QED tool available"
        return 2
    fi

    # For qedgen: run check + verify
    # For qed-solana: run directly on .so file
    local start_time
    start_time=$(date +%s)

    local result=""
    local qed_exit=0

    if [ "$tool" = "qedgen" ]; then
        # QEDGen: spec-driven verification
        local specs_dir="$REPO_ROOT/.qed"
        if [ -d "$specs_dir" ]; then
            # Run spec lint and drift check first
            echo "  → Running qedgen check..."
            result=$(timeout "$MAX_INVARIANT_TIME" qedgen check --spec "$specs_dir"/*.qedspec 2>&1) || qed_exit=$?
        else
            # No specs found — try probe mode
            echo "  → No .qedspec files found; attempting probe..."
            result=$(timeout "$MAX_INVARIANT_TIME" qedgen probe --program "$program_path" 2>&1) || qed_exit=$?
        fi
    else
        # Legacy qed-solana: direct program verification
        local so_file="$program_path/target/deploy/${program_name}.so"
        if [ ! -f "$so_file" ]; then
            echo "SKIP: No compiled .so for $program_name (build required)"
            jq --arg name "$program_name" --arg reason "not_compiled" \
               '.skipped += [{"program": $name, "reason": $reason}]' \
               "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
            return 0
        fi

        echo "  → Running $tool verify..."
        result=$(timeout "$MAX_INVARIANT_TIME" "$tool" verify \
            --program "$so_file" \
            --output json 2>&1) || qed_exit=$?
    fi

    local elapsed=$(( $(date +%s) - start_time ))

    # Handle exit codes
    if [ "$qed_exit" -ne 0 ]; then
        case $qed_exit in
            124)
                echo "TIMEOUT: $program_name exceeded ${MAX_INVARIANT_TIME}s"
                jq --arg name "$program_name" --arg reason "timeout_${elapsed}s" \
                   '.skipped += [{"program": $name, "reason": $reason}]' \
                   "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
                ;;
            127)
                echo "ERROR: $tool not found"
                return 2
                ;;
            *)
                echo "ERROR: $tool exited $qed_exit for $program_name"
                jq --arg name "$program_name" --arg exit_code "$qed_exit" \
                   '.errors += [{"program": $name, "exit_code": ($exit_code | tonumber)}]' \
                   "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
                ;;
        esac
        return 1
    fi

    # Parse result
    local status="complete"
    if echo "$result" | jq -e '.status' >/dev/null 2>&1; then
        status=$(echo "$result" | jq -r '.status // "complete"')
    fi

    echo "  status: $status (${elapsed}s)"
    jq --arg name "$program_name" --arg status "$status" \
       --argjson elapsed "$elapsed" \
       --arg raw "$result" \
       '.invariants += [{
         "program": $name,
         "status": $status,
         "elapsed_seconds": $elapsed,
         "raw_output": $raw
       }]' \
       "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"

    # Extract counterexamples → findings
    if echo "$result" | jq -e '.counterexamples' >/dev/null 2>&1; then
        local findings
        findings=$(echo "$result" | jq '.counterexamples | length' 2>/dev/null || echo "0")
        if [ "$findings" -gt 0 ]; then
            echo "$result" | jq -c '.counterexamples[]' 2>/dev/null | while read -r finding; do
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
    echo "=== QED Formal Verification ==="

    local tool_status
    tool_status=$(detect_toolchain)

    if [ "$tool_status" = "NOT_FOUND" ]; then
        echo "SKIP: No QED toolchain found (qedgen or qed-solana)"
        cat > "$REPORT_FILE" <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "status": "skipped",
  "reason": "no_toolchain"
}
EOF
        exit 2
    fi

    local tool_name
    tool_name=$(get_tool_name)
    local tool_version
    tool_version=$(get_tool_version)
    echo "Toolchain: $tool_name ($tool_version)"

    if ! check_programs; then
        echo "SKIP: No programs to verify"
        cat > "$REPORT_FILE" <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "status": "skipped",
  "reason": "no_programs"
}
EOF
        exit 2
    fi

    local program_count
    program_count=$(find "$PROGRAMS_DIR" -name "Cargo.toml" -maxdepth 2 | wc -l | tr -d ' ')
    init_report "$program_count"

    # Verify each program
    local exit_code=0
    for program in "$PROGRAMS_DIR"/*/Cargo.toml; do
        [ -f "$program" ] || continue
        local dir
        dir=$(dirname "$program")
        verify_program "$dir" || exit_code=$?
    done

    # Finalize report
    local total_invariants=0
    local total_findings=0
    if [ -f "$REPORT_FILE" ]; then
        total_invariants=$(jq '.invariants | length' "$REPORT_FILE")
        total_findings=$(jq '.findings | length' "$REPORT_FILE")
    fi

    local final_status="complete"
    local has_errors
    has_errors=$(jq '.errors | length' "$REPORT_FILE" 2>/dev/null || echo "0")
    if [ "$has_errors" -gt 0 ]; then
        final_status="partial"
    fi

    jq --argjson total_invariants "$total_invariants" \
       --argjson total_findings "$total_findings" \
       --arg status "$final_status" \
       '.total_invariants = $total_invariants |
        .total_findings = $total_findings |
        .status = $status' \
       "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"

    echo "=== Summary ==="
    echo "  Tool: $tool_name"
    echo "  Programs: $program_count"
    echo "  Invariants checked: $total_invariants"
    echo "  Findings: $total_findings"
    echo "  Status: $final_status"

    exit $exit_code
}

main "$@"
