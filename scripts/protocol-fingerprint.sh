#!/bin/bash
#
# protocol-fingerprint.sh
# Protocol fingerprinting system for Solana DeFi programs
#
# Identifies which DeFi protocol a program resembles based on:
# - Program ID matching
# - Instruction signature patterns
# - IDL analysis
# - Known vulnerability cross-referencing
#
# Usage:
#   ./protocol-fingerprint.sh <program_id> [idl_file]
#   ./protocol-fingerprint.sh --scan-dir <directory>
#   ./protocol-fingerprint.sh --check-vuln <vuln_id>
#   ./protocol-fingerprint.sh --list-protocols
#
# Exit codes:
#   0 - Success
#   1 - Invalid arguments
#   2 - File not found
#   3 - Protocol database error
#   4 - Analysis error
#

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VULN_DB="${PROJECT_ROOT}/data/protocols/known-vulns.json"
SIG_DB="${PROJECT_ROOT}/data/protocols/protocol-signatures.json"

# Ensure required tools are available
if ! command -v jq >/dev/null 2>&1; then
    echo "[ERROR] jq is required but not installed. Install it with: brew install jq (macOS) or apt-get install jq (Linux)" >&2
    exit 3
fi

# Default confidence thresholds
readonly HIGH_CONFIDENCE_THRESHOLD=80
readonly MEDIUM_CONFIDENCE_THRESHOLD=50

# ============================================================================
# Color codes for output
# ============================================================================

COLOR_RESET='\033[0m'
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_BLUE='\033[0;34m'
COLOR_CYAN='\033[0;36m'

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*" >&2
}

log_success() {
    echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_RESET} $*" >&2
}

log_warning() {
    echo -e "${COLOR_YELLOW}[WARNING]${COLOR_RESET} $*" >&2
}

log_error() {
    echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $*" >&2
}

log_debug() {
    if [[ "${DEBUG:-0}" == "1" ]]; then
        echo -e "${COLOR_CYAN}[DEBUG]${COLOR_RESET} $*" >&2
    fi
}

# Validate JSON file exists and is valid
validate_db() {
    local db_path="$1"
    local db_name="$2"

    if [[ ! -f "$db_path" ]]; then
        log_error "${db_name} database not found: $db_path"
        return 3
    fi

    if ! jq empty "$db_path" 2>/dev/null; then
        log_error "Invalid JSON in ${db_name} database"
        return 3
    fi

    return 0
}

# Extract JSON value safely using jq
jq_get() {
    local query="$1"
    local default="${2:-}"
    local db_path="${3:-$VULN_DB}"
    local result

    if [[ ! -f "$db_path" ]]; then
        echo "$default"
        return 1
    fi

    result=$(jq -r "$query // empty" "$db_path" 2>/dev/null || echo "")
    if [[ -z "$result" ]]; then
        echo "$default"
    else
        echo "$result"
    fi
}

# ============================================================================
# Core Detection Functions
# ============================================================================

# Detect protocol from program ID
detect_by_program_id() {
    local program_id="$1"
    local matched_protocol=""
    local match_confidence=0

    log_debug "Checking program ID: $program_id"

    # Get all protocols from signatures database
    local protocols
    protocols=$(jq_get ".protocols | keys | .[]" "" "$SIG_DB")

    while IFS= read -r protocol; do
        if [[ -z "$protocol" ]]; then
            continue
        fi

        local known_id
        known_id=$(jq_get ".protocols[\"$protocol\"].program_id" "" "$SIG_DB")

        if [[ -z "$known_id" ]]; then
            continue
        fi

        # Exact match
        if [[ "$known_id" == "$program_id" ]]; then
            matched_protocol="$protocol"
            match_confidence=100
            log_debug "Exact program ID match: $protocol"
            break
        fi

        # Partial match (first 20 chars)
        if [[ "${program_id:0:20}" == "${known_id:0:20}" ]]; then
            matched_protocol="$protocol"
            match_confidence=75
            log_debug "Partial program ID match: $protocol"
        fi
    done <<< "$protocols"

    echo "$matched_protocol:$match_confidence"
}

# Detect protocol from instruction names in IDL
detect_by_instructions() {
    local idl_content="$1"
    local matched_protocol=""
    local best_protocol=""
    local best_score=0

    log_debug "Analyzing instruction patterns from IDL"

    # Get all protocols
    local protocols
    protocols=$(jq_get ".protocols | keys | .[]" "" "$SIG_DB")

    while IFS= read -r protocol; do
        if [[ -z "$protocol" ]]; then
            continue
        fi

        local instructions_json
        instructions_json=$(jq_get ".protocols[\"$protocol\"].instructions" "[]" "$SIG_DB")

        # Count matching instructions
        local count=0
        local instruction
        while IFS= read -r instruction; do
            if [[ -n "$instruction" ]]; then
                # Check if instruction exists in IDL content
                if echo "$idl_content" | grep -qiE "(^|\"|\s)$instruction(\"|\s|,)" 2>/dev/null; then
                    ((count++))
                fi
            fi
        done <<< "$instructions_json"

        if [[ $count -gt $best_score ]]; then
            best_score=$count
            best_protocol="$protocol"
            log_debug "Protocol $protocol: $count instruction matches (new best)"
        fi
    done <<< "$protocols"

    # Calculate confidence based on match ratio
    local confidence=0
    if [[ $best_score -ge 5 ]]; then
        confidence=90
    elif [[ $best_score -ge 3 ]]; then
        confidence=70
    elif [[ $best_score -ge 1 ]]; then
        confidence=50
    fi

    echo "$best_protocol:$confidence"
}

# Detect protocol category from instruction patterns
detect_category() {
    local idl_content="$1"

    if echo "$idl_content" | grep -qiE "(perp|perpetual|futures|margin_trading)"; then
        echo "perpetuals"
    elif echo "$idl_content" | grep -qiE "(lend|borrow|reserve|collateral|interest_rate)"; then
        echo "lending"
    elif echo "$idl_content" | grep -qiE "(stake|unstake|validator|liquid_stake)"; then
        echo "liquid_staking"
    elif echo "$idl_content" | grep -qiE "(pool|liquidity|swap|amm)"; then
        echo "amm_dex"
    elif echo "$idl_content" | grep -qiE "(orderbook|trade|match)"; then
        echo "orderbook_dex"
    elif echo "$idl_content" | grep -qiE "(vault|strategy|structured)"; then
        echo "structured_products"
    elif echo "$idl_content" | grep -qiE "(portfolio|rebalance|aggregat)"; then
        echo "portfolio_manager"
    else
        echo "unknown"
    fi
}

# ============================================================================
# Vulnerability Analysis Functions
# ============================================================================

# Get known vulnerabilities for a protocol
get_protocol_vulns() {
    local protocol="$1"
    local vulns

    vulns=$(jq_get ".protocols[\"$protocol\"].vulnerabilities" "[]")

    if [[ -z "$vulns" || "$vulns" == "[]" || "$vulns" == "null" ]]; then
        echo "[]"
    else
        # Ensure it's a valid array
        echo "$vulns" | jq 'if type == "array" then . else [.] end' 2>/dev/null || echo "[]"
    fi
}

# Check if IDL contains patterns matching known vulnerabilities
check_vulnerability_patterns() {
    local protocol="$1"
    local idl_content="$2"

    log_debug "Checking vulnerability patterns for $protocol"

    # Get protocol vulnerabilities from database
    local vulns_json
    vulns_json=$(jq_get ".protocols[\"$protocol\"].vulnerabilities" "[]")

    if [[ -z "$vulns_json" || "$vulns_json" == "[]" || "$vulns_json" == "null" ]]; then
        log_debug "No vulnerabilities in database for $protocol"
        echo "[]"
        return 0
    fi

    # Count vulnerabilities
    local vuln_count
    vuln_count=$(echo "$vulns_json" | jq 'length' 2>/dev/null || echo 0)

    local findings_json="[]"
    local first=true

    for ((i=0; i<vuln_count; i++)); do
        local vuln_id vuln_name cwe severity description detection_rules
        vuln_id=$(echo "$vulns_json" | jq -r ".[$i].id // empty" 2>/dev/null || echo "")
        vuln_name=$(echo "$vulns_json" | jq -r ".[$i].vulnerability // empty" 2>/dev/null || echo "")
        cwe=$(echo "$vulns_json" | jq -r ".[$i].cwe // empty" 2>/dev/null || echo "")
        severity=$(echo "$vulns_json" | jq -r ".[$i].severity // empty" 2>/dev/null || echo "")
        description=$(echo "$vulns_json" | jq -r ".[$i].description // empty" 2>/dev/null || echo "")
        detection_rules=$(echo "$vulns_json" | jq -r ".[$i].detection_rules | join(\"|\")" 2>/dev/null || echo "")

        # Skip if essential fields are missing
        if [[ -z "$vuln_id" || -z "$vuln_name" ]]; then
            continue
        fi

        # Check if IDL matches any detection rule
        if [[ -n "$detection_rules" ]]; then
            local matched_rule=""

            # Split by | and check each rule
            local rule
            for rule in $(echo "$detection_rules" | tr '|' '\n'); do
                # Remove common prefixes for pattern matching
                local pattern="$rule"
                pattern="${pattern#missing: }"
                pattern="${pattern#pattern: }"
                pattern="${pattern#instruction: }"
                pattern="${pattern#array access: }"

                if echo "$idl_content" | grep -qiE "$pattern" 2>/dev/null; then
                    matched_rule="$rule"
                    break
                fi
            done

            if [[ -n "$matched_rule" ]]; then
                # Build JSON object manually
                local finding
                finding=$(jq -n \
                    --arg id "$vuln_id" \
                    --arg v "$vuln_name" \
                    --arg c "$cwe" \
                    --arg s "$severity" \
                    --arg d "$description" \
                    --arg m "$matched_rule" \
                    '{id: $id, vulnerability: $v, cwe: $c, severity: $s, description: $d, matched_rule: $m}')

                if [[ "$first" == "true" ]]; then
                    findings_json="[$finding"
                    first=false
                else
                    findings_json="$findings_json,$finding"
                fi
            fi
        fi
    done

    if [[ "$first" == "true" ]]; then
        echo "[]"
    else
        echo "${findings_json}]"
    fi
}

# ============================================================================
# Output Functions
# ============================================================================

# Extract matched instructions from IDL
extract_matched_instructions() {
    local idl_content="$1"
    local instructions

    instructions=$(echo "$idl_content" | grep -oE "(swap|deposit|withdraw|borrow|liquidate|mint|burn|transfer|initialize|claim|settle|place_order|open_position|close_position|stake|unstake|add_liquidity|remove_liquidity|create_pool|create_pool|route_swap|quote|aggregated_swap|initialize_tick_array|increase_liquidity|decrease_liquidity|open_position|close_position|refresh_reserve|init_reserve|place_perp_order|settle_pnl|funding_payment|update_funding|emergency_unstake|add_validator|remove_validator|deposit_vault|rebalance|deposit_collateral|withdraw_collateral|place_perp_order|cancel_order|fill_order|orderbook)" 2>/dev/null | sort -u || true)

    if [[ -n "$instructions" ]]; then
        echo "$instructions" | jq -R . | jq -s . 2>/dev/null || echo "[]"
    else
        echo "[]"
    fi
}

# Run full protocol analysis
analyze_protocol() {
    local program_id="$1"
    local idl_content="$2"

    log_info "Analyzing program: $program_id"

    # Step 1: Detect by program ID
    local id_result
    id_result=$(detect_by_program_id "$program_id")
    local id_protocol="${id_result%%:*}"
    local id_confidence="${id_result#*:}"

    # Step 2: Detect by instruction patterns
    local instr_result
    instr_result=$(detect_by_instructions "$idl_content")
    local instr_protocol="${instr_result%%:*}"
    local instr_confidence="${instr_result#*:}"

    # Step 3: Determine best match
    local best_protocol=""
    local best_confidence=0

    if [[ -n "$id_protocol" ]] && [[ $id_confidence -gt 0 ]]; then
        best_protocol="$id_protocol"
        best_confidence=$id_confidence
    fi

    if [[ -n "$instr_protocol" ]] && [[ $instr_confidence -gt 0 ]]; then
        if [[ $instr_confidence -gt $best_confidence ]]; then
            best_protocol="$instr_protocol"
            best_confidence=$instr_confidence
        fi
    fi

    # Calculate combined confidence
    if [[ -n "$id_protocol" ]] && [[ -n "$instr_protocol" ]]; then
        if [[ "$id_protocol" == "$instr_protocol" ]]; then
            best_confidence=$(( (id_confidence + instr_confidence) / 2 * 100 / 100 ))
        else
            best_confidence=$(( (id_confidence + instr_confidence) / 2 * 70 / 100 ))
        fi
    fi

    # Determine confidence level
    local confidence_level="low"
    if [[ $best_confidence -ge $HIGH_CONFIDENCE_THRESHOLD ]]; then
        confidence_level="high"
    elif [[ $best_confidence -ge $MEDIUM_CONFIDENCE_THRESHOLD ]]; then
        confidence_level="medium"
    fi

    # Step 4: Detect category
    local category
    category=$(detect_category "$idl_content")

    # Step 5: Get known vulnerabilities
    local vulns
    vulns=$(get_protocol_vulns "$best_protocol")

    # Step 6: Check for vulnerability patterns
    local audit_flags
    audit_flags=$(check_vulnerability_patterns "$best_protocol" "$idl_content")

    # Step 7: Extract matched instructions
    local matched_instr
    matched_instr=$(extract_matched_instructions "$idl_content")

    # Get database version
    local db_version
    db_version=$(jq_get '.version' 'unknown')

    # Validate JSON values
    if [[ -z "$vulns" || "$vulns" == "null" ]]; then
        vulns="[]"
    fi
    if [[ -z "$audit_flags" || "$audit_flags" == "null" ]]; then
        audit_flags="[]"
    fi
    if [[ -z "$matched_instr" || "$matched_instr" == "null" ]]; then
        matched_instr="[]"
    fi

    # Output results
    log_success "Protocol: ${best_protocol:-unknown} (confidence: $confidence_level)"

    # Build final JSON output
    local timestamp
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown")

    cat <<EOF
{
  "program_id": "$program_id",
  "protocol": "$best_protocol",
  "confidence": "$confidence_level",
  "category": "$category",
  "known_vulnerabilities": $vulns,
  "audit_flags": $audit_flags,
  "matched_instructions": $matched_instr,
  "scan_timestamp": "$timestamp",
  "database_version": "$db_version"
}
EOF
}

# ============================================================================
# Command Handlers
# ============================================================================

cmd_single() {
    local program_id="$1"
    local idl_file="${2:-}"

    validate_db "$VULN_DB" "Vulnerability" || exit 3
    validate_db "$SIG_DB" "Signature" || exit 3

    local idl_content=""
    if [[ -n "$idl_file" ]]; then
        if [[ ! -f "$idl_file" ]]; then
            log_error "IDL file not found: $idl_file"
            exit 2
        fi
        idl_content=$(cat "$idl_file")
    else
        # Try to load from common locations
        for path in \
            "./target/idl/${program_id}.json" \
            "./target/idl.json" \
            "./idl.json" \
            "./anchor.toml"
        do
            if [[ -f "$path" ]]; then
                idl_content=$(cat "$path")
                log_info "Loaded IDL from: $path"
                break
            fi
        done
    fi

    if [[ -z "$idl_content" ]]; then
        log_warning "No IDL content loaded, using empty content"
        idl_content="{}"
    fi

    analyze_protocol "$program_id" "$idl_content"
}

cmd_scan_directory() {
    local dir="$1"

    if [[ ! -d "$dir" ]]; then
        log_error "Directory not found: $dir"
        exit 2
    fi

    validate_db "$VULN_DB" "Vulnerability" || exit 3
    validate_db "$SIG_DB" "Signature" || exit 3

    log_info "Scanning directory: $dir"

    local count=0
    local timestamp
    timestamp=$(date +%Y%m%d-%H%M%S 2>/dev/null || echo "scan")
    local output_file="fingerprint-scan-${timestamp}.json"

    echo "[" > "$output_file"
    local first=true

    while IFS= read -r idl_file; do
        local program_id
        program_id=$(basename "$idl_file" .json)

        log_info "Processing: $idl_file"

        local idl_content
        idl_content=$(cat "$idl_file")

        local result
        result=$(analyze_protocol "$program_id" "$idl_content")

        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> "$output_file"
        fi
        echo "$result" >> "$output_file"

        ((count++))
    done < <(find "$dir" -name "*.json" -type f 2>/dev/null | head -100)

    echo "]" >> "$output_file"

    log_success "Scan complete. Processed $count programs."
    log_info "Results saved to: $output_file"
}

cmd_check_vulnerability() {
    local vuln_id="$1"

    validate_db "$VULN_DB" "Vulnerability" || exit 3

    local vuln_data
    vuln_data=$(jq_get ".protocols | to_entries[] | .value.vulnerabilities[] | select(.id == \"$vuln_id\")" "null")

    if [[ "$vuln_data" == "null" || -z "$vuln_data" ]]; then
        log_error "Vulnerability not found: $vuln_id"
        exit 1
    fi

    echo "$vuln_data" | jq '.'
}

cmd_list_protocols() {
    validate_db "$VULN_DB" "Vulnerability" || exit 3
    validate_db "$SIG_DB" "Signature" || exit 3

    local protocols
    protocols=$(jq_get ".protocols | keys | .[]" "" "$SIG_DB")

    echo "Supported protocols:"
    echo ""

    while IFS= read -r protocol; do
        if [[ -z "$protocol" ]]; then
            continue
        fi

        local vuln_count
        vuln_count=$(jq_get ".protocols[\"$protocol\"].vulnerabilities | length" 0)
        local category
        category=$(jq_get ".protocols[\"$protocol\"].category" "unknown" "$SIG_DB")

        printf "  %-15s [%s] - %d known vulnerabilities\n" "$protocol" "$category" "$vuln_count"
    done <<< "$protocols"
}

cmd_generate_findings() {
    local program_id="$1"
    local idl_file="$2"

    if [[ ! -f "$idl_file" ]]; then
        log_error "IDL file not found: $idl_file"
        exit 2
    fi

    validate_db "$VULN_DB" "Vulnerability" || exit 3

    local idl_content
    idl_content=$(cat "$idl_file")

    # Run analysis to get audit flags
    local result
    result=$(analyze_protocol "$program_id" "$idl_content")

    local audit_flags
    audit_flags=$(echo "$result" | jq -r '.audit_flags // "[]"' 2>/dev/null || echo "[]")

    local vuln_count
    vuln_count=$(echo "$audit_flags" | jq 'length' 2>/dev/null || echo 0)

    if [[ $vuln_count -eq 0 ]]; then
        log_info "No protocol-specific vulnerabilities detected."
        echo "[]"
        return 0
    fi

    log_warning "Found $vuln_count potential vulnerability matches"

    # Generate findings for each match
    echo "["
    local first=true
    echo "$audit_flags" | jq -c '.[]' 2>/dev/null | while IFS= read -r vuln_json; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo ","
        fi
        # Generate audit finding
        local vuln_id vuln_name cwe severity description matched_rule
        vuln_id=$(echo "$vuln_json" | jq -r '.id' 2>/dev/null || echo "")
        vuln_name=$(echo "$vuln_json" | jq -r '.vulnerability' 2>/dev/null || echo "")
        cwe=$(echo "$vuln_json" | jq -r '.cwe' 2>/dev/null || echo "")
        severity=$(echo "$vuln_json" | jq -r '.severity' 2>/dev/null || echo "")
        description=$(echo "$vuln_json" | jq -r '.description' 2>/dev/null || echo "")
        matched_rule=$(echo "$vuln_json" | jq -r '.matched_rule' 2>/dev/null || echo "")

        local finding_id="${vuln_id}-${program_id:0:8}"

        jq -n \
            --arg id "$finding_id" \
            --arg s "$severity" \
            --arg c "$cwe" \
            --arg t "Potential $vuln_name in target program" \
            --arg p "$program_id" \
            --arg d "$description" \
            --arg m "$matched_rule" \
            --arg r "Protocol Fingerprint Match: $vuln_id" \
            '{id: $id, severity: $s, cwe: $c, title: $t, program_id: $p, description: $d, matched_pattern: $m, rule_caught: $r, status: "Open"}'
    done
    echo "]"
}

# ============================================================================
# Main Entry Point
# ============================================================================

usage() {
    cat <<EOF
Protocol Fingerprinting System for Solana DeFi Programs

Usage: $0 <command> [options]

Commands:
  <program_id> [idl_file]     Analyze a single program
  --scan-dir <directory>      Scan all JSON files in a directory
  --check-vuln <vuln_id>      Check details of a known vulnerability
  --list-protocols            List all supported protocols
  --generate-findings <pid> <idl>  Generate audit findings from matches

Options:
  -d, --debug                 Enable debug output
  -h, --help                  Show this help message

Examples:
  $0 JUP6LkbZ5SgX1erA9Xh8x8vL2mE7jX3N9V4KjKjKjK ./idl.json
  $0 --scan-dir ./target/idl
  $0 --list-protocols
  $0 --generate-findings MyProgram ./target/idl/MyProgram.json

Exit codes:
  0 - Success
  1 - Invalid arguments
  2 - File not found
  3 - Protocol database error
EOF
}

main() {
    # Parse arguments
    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi

    # Handle global options
    if [[ "${1:-}" == "-d" || "${1:-}" == "--debug" ]]; then
        export DEBUG=1
        shift
    fi

    local command="${1:-}"

    case "$command" in
        -h|--help)
            usage
            exit 0
            ;;
        --scan-dir)
            cmd_scan_directory "${2:-}"
            exit 0
            ;;
        --check-vuln)
            cmd_check_vulnerability "${2:-}"
            exit 0
            ;;
        --list-protocols)
            cmd_list_protocols
            exit 0
            ;;
        --generate-findings)
            cmd_generate_findings "${2:-}" "${3:-}"
            exit 0
            ;;
        -*)
            log_error "Unknown option: $command"
            usage
            exit 1
            ;;
        *)
            # Single program analysis
            if [[ -z "$command" ]]; then
                log_error "Program ID required"
                usage
                exit 1
            fi
            cmd_single "$command" "${2:-}"
            exit 0
            ;;
    esac
}

main "$@"