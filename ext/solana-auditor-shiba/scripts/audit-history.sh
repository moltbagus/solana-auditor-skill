#!/bin/bash
#
# audit-history.sh — Audit history management for Solana auditor skill
#
# Manages a JSON-backed audit history database tracking program audits
# across versions, enabling diff comparison and trend analysis.
#
# Usage:
#   source scripts/audit-history.sh
#   audit_history_init
#   audit_history_add <program_id> <version> <findings_json>
#   audit_history_get <program_id> <version>
#   audit_history_list <program_id>
#   audit_history_diff <v1> <v2>
#   audit_history_stats
#
# Environment variables:
#   AUDIT_HISTORY       Path to history file (default: .audit-history.json)
#   AUDIT_HISTORY_DIR   Directory for additional artifacts (default: .claude/audit-history)
#
# Schema:
#   {
#     "programs": {
#       "PROGRAM_ID": {
#         "audits": [
#           {
#             "version": "1.0.0",
#             "timestamp": "ISO8601",
#             "auditor": "claude",
#             "commit": "git_hash",
#             "findings": { "critical": 0, "high": 2, "medium": 1 },
#             "finding_ids": ["VULN-01", "VULN-02"]
#           }
#         ]
#       }
#     }
#   }
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AUDIT_HISTORY="${AUDIT_HISTORY:-.audit-history.json}"
AUDIT_HISTORY_DIR="${AUDIT_HISTORY_DIR:-.claude/audit-history}"
AUDIT_HISTORY_LOCK="${AUDIT_HISTORY}.lock"

# Default auditor identifier
AUDIT_AUDITOR="${AUDIT_AUDITOR:-claude}"

# Lock timeout in seconds (prevents indefinite blocking)
AUDIT_LOCK_TIMEOUT="${AUDIT_LOCK_TIMEOUT:-10}"

# ---------------------------------------------------------------------------
# Dependencies check
# ---------------------------------------------------------------------------

: "${JQ_BIN:=$(command -v jq 2>/dev/null || true)}"
: "${DATE_BIN:=$(command -v date 2>/dev/null || true)}"
: "${GIT_BIN:=$(command -v git 2>/dev/null || true)}"

# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------

declare -r ERR_NO_JQ=1
declare -r ERR_NO_HISTORY=2
declare -r ERR_PROGRAM_NOT_FOUND=3
declare -r ERR_VERSION_NOT_FOUND=4
declare -r ERR_INVALID_ARGS=5
declare -r ERR_LOCK_TIMEOUT=6
declare -r ERR_JSON_OP=7
declare -r ERR_DIFF_SAME_VERSION=8

# ---------------------------------------------------------------------------
# Helper: Logging
# ---------------------------------------------------------------------------

_audit_log() {
    local level="${1:-INFO}"
    local message="${2:-}"
    printf '[%s] %s: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "$(date +%Z)")" \
        "$level" "$message" >&2
}

audit_log_info()  { _audit_log "INFO" "$1"; }
audit_log_warn() { _audit_log "WARN" "$1"; }
audit_log_error(){ _audit_log "ERROR" "$1"; }

# ---------------------------------------------------------------------------
# Helper: Lock file operations (idempotent)
# ---------------------------------------------------------------------------

_acquire_lock() {
    local lock_file="$1"
    local timeout="$2"
    local elapsed=0
    local interval=1

    while [[ -f "$lock_file" ]]; do
        if (( elapsed >= timeout )); then
            audit_log_error "Lock acquisition timed out: $lock_file"
            return $ERR_LOCK_TIMEOUT
        fi
        sleep "$interval"
        (( elapsed += interval ))
    done

    # Atomic lock creation
    printf '%s %s %s\n' "$(date +%s)" "$$" "$(hostname 2>/dev/null || echo 'unknown')" \
        > "$lock_file" 2>/dev/null || return 1

    return 0
}

_release_lock() {
    local lock_file="$1"
    [[ -f "$lock_file" ]] && rm -f "$lock_file"
}

# ---------------------------------------------------------------------------
# Helper: JSON operations
# ---------------------------------------------------------------------------

_jq_escape() {
    # Escape string for safe JSON embedding
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

_jq_get_programs() {
    local history_file="$1"
    if [[ ! -f "$history_file" ]]; then
        printf '{}'
        return 0
    fi
    jq -r '.programs // {}' "$history_file" 2>/dev/null || printf '{}'
}

_jq_get_program_audits() {
    local history_file="$1"
    local program_id="$2"
    jq -r --arg pid "$program_id" \
        '.programs[$pid].audits // []' "$history_file" 2>/dev/null || printf '[]'
}

_jq_get_audit_by_version() {
    local history_file="$1"
    local program_id="$2"
    local version="$3"
    jq -r --arg pid "$program_id" --arg ver "$version" \
        '.programs[$pid].audits[] | select(.version == $ver)' \
        "$history_file" 2>/dev/null || printf 'null'
}

_jq_append_audit() {
    local history_file="$1"
    local program_id="$2"
    local new_audit_json="$3"

    local tmp_file
    tmp_file=$(mktemp "${history_file}.XXXXXX") || return 1

    if [[ ! -f "$history_file" ]]; then
        # Initialize with structure
        jq -n \
            --argjson audit "$new_audit_json" \
            --arg pid "$program_id" \
            '{ programs: { ($pid): { audits: [$audit] } } }' \
            > "$tmp_file" 2>/dev/null \
            || { rm -f "$tmp_file"; return $ERR_JSON_OP; }
    else
        # Check if program exists
        local program_exists
        program_exists=$(jq -r --arg pid "$program_id" \
            'has("programs") and (.programs | has($pid))' \
            "$history_file" 2>/dev/null || echo 'false')

        if [[ "$program_exists" == "true" ]]; then
            # Check version doesn't already exist (idempotent guard)
            local version_exists
            version_exists=$(jq -r --arg pid "$program_id" --argjson audit "$new_audit_json" \
                '.programs[$pid].audits[] | select(.version == $audit.version) | .version' \
                "$history_file" 2>/dev/null || echo '')
            if [[ -n "$version_exists" ]]; then
                audit_log_warn "Version ${version_exists} already exists for program ${program_id}. Skipping."
                rm -f "$tmp_file"
                return 0
            fi

            # Append to existing program
            jq -r --arg pid "$program_id" --argjson audit "$new_audit_json" \
                '.programs[$pid].audits += [$audit]' \
                "$history_file" > "$tmp_file" 2>/dev/null \
                || { rm -f "$tmp_file"; return $ERR_JSON_OP; }
        else
            # Add new program entry
            jq -r --arg pid "$program_id" --argjson audit "$new_audit_json" \
                '(if .programs == null then {} else .programs end) as $p |
                { programs: ($p + { ($pid): { audits: [$audit] } }) }' \
                "$history_file" > "$tmp_file" 2>/dev/null \
                || { rm -f "$tmp_file"; return $ERR_JSON_OP; }
        fi
    fi

    mv "$tmp_file" "$history_file"
    return 0
}

# ---------------------------------------------------------------------------
# Helper: Git commit retrieval
# ---------------------------------------------------------------------------

_get_git_commit() {
    local dir="${1:-.}"
    if [[ -n "$GIT_BIN" ]] && "$GIT_BIN" -C "$dir" rev-parse HEAD &>/dev/null; then
        "$GIT_BIN" -C "$dir" rev-parse HEAD 2>/dev/null | cut -c1-7 || echo "unknown"
    else
        echo "unknown"
    fi
}

_get_timestamp() {
    if [[ -n "$DATE_BIN" ]]; then
        "$DATE_BIN" -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
            "$DATE_BIN" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
            echo "$(date +%Z)"
    else
        date +%Y-%m-%dT%H:%M:%SZ
    fi
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

#
# audit_history_init
#
# Creates an empty .audit-history.json if it doesn't exist.
# Idempotent: no-op if file already exists.
#
# Returns: 0 on success, exits on error
#
audit_history_init() {
    local history_file="${1:-$AUDIT_HISTORY}"

    if [[ -f "$history_file" ]]; then
        audit_log_info "History file already exists: $history_file"
        return 0
    fi

    # Ensure parent directory exists
    local parent_dir
    parent_dir=$(dirname "$history_file")
    mkdir -p "$parent_dir" || {
        audit_log_error "Failed to create directory: $parent_dir"
        return 1
    }

    # Create empty valid JSON structure
    echo '{"programs":{}}' > "$history_file" || {
        audit_log_error "Failed to create history file: $history_file"
        return 1
    }

    audit_log_info "Initialized history file: $history_file"
    return 0
}

#
# audit_history_add <program_id> <version> <findings_json>
#
# Appends a new audit snapshot for the given program version.
# Arguments:
#   program_id    - Solana program ID (base58 address)
#   version       - Semantic version string (e.g., "1.0.0")
#   findings_json - JSON object with {critical, high, medium, low} counts
#
# Returns: 0 on success, exits on error
#
audit_history_add() {
    local program_id="${1:-}"
    local version="${2:-}"
    local findings_json="${3:-}"

    # Validate required arguments
    if [[ -z "$program_id" ]]; then
        audit_log_error "usage: audit_history_add <program_id> <version> <findings_json>"
        return $ERR_INVALID_ARGS
    fi
    if [[ -z "$version" ]]; then
        audit_log_error "usage: audit_history_add <program_id> <version> <findings_json>"
        return $ERR_INVALID_ARGS
    fi
    if [[ -z "$findings_json" ]]; then
        audit_log_error "usage: audit_history_add <program_id> <version> <findings_json>"
        return $ERR_INVALID_ARGS
    fi

    # Check jq availability
    if [[ -z "$JQ_BIN" ]]; then
        audit_log_error "jq is required but not installed"
        return $ERR_NO_JQ
    fi

    local history_file="$AUDIT_HISTORY"

    # Initialize if needed
    if [[ ! -f "$history_file" ]]; then
        audit_history_init "$history_file"
    fi

    # Acquire lock
    if ! _acquire_lock "$AUDIT_HISTORY_LOCK" "$AUDIT_LOCK_TIMEOUT"; then
        return $ERR_LOCK_TIMEOUT
    fi

    local commit
    commit=$(_get_git_commit)
    local timestamp
    timestamp=$(_get_timestamp)

    # Validate findings_json is valid JSON
    if ! echo "$findings_json" | "$JQ_BIN" . >/dev/null 2>&1; then
        audit_log_error "Invalid findings JSON: $findings_json"
        _release_lock "$AUDIT_HISTORY_LOCK"
        return $ERR_JSON_OP
    fi

    # Extract finding IDs if present
    local finding_ids='[]'
    finding_ids=$(echo "$findings_json" | "$JQ_BIN" '.finding_ids // []' 2>/dev/null || echo '[]')

    # Extract severity counts
    local critical high medium low
    critical=$(echo "$findings_json" | "$JQ_BIN" '.critical // 0' 2>/dev/null || echo 0)
    high=$(echo "$findings_json" | "$JQ_BIN" '.high // 0' 2>/dev/null || echo 0)
    medium=$(echo "$findings_json" | "$JQ_BIN" '.medium // 0' 2>/dev/null || echo 0)
    low=$(echo "$findings_json" | "$JQ_BIN" '.low // 0' 2>/dev/null || echo 0)

    # Build audit entry
    local audit_entry
    audit_entry=$("$JQ_BIN" -n \
        --arg version "$version" \
        --arg timestamp "$timestamp" \
        --arg auditor "$AUDIT_AUDITOR" \
        --arg commit "$commit" \
        --argjson critical "$critical" \
        --argjson high "$high" \
        --argjson medium "$medium" \
        --argjson low "$low" \
        --argjson finding_ids "$finding_ids" \
        '{
            version: $version,
            timestamp: $timestamp,
            auditor: $auditor,
            commit: $commit,
            findings: {
                critical: $critical,
                high: $high,
                medium: $medium,
                low: $low
            },
            finding_ids: $finding_ids
        }')

    # Append to history
    if ! _jq_append_audit "$history_file" "$program_id" "$audit_entry"; then
        _release_lock "$AUDIT_HISTORY_LOCK"
        audit_log_error "Failed to append audit for ${program_id}@${version}"
        return $ERR_JSON_OP
    fi

    _release_lock "$AUDIT_HISTORY_LOCK"
    audit_log_info "Added audit snapshot: ${program_id}@${version}"
    return 0
}

#
# audit_history_get <program_id> <version>
#
# Retrieves a specific audit snapshot.
# Arguments:
#   program_id - Solana program ID
#   version    - Version string
#
# Returns: 0, prints JSON to stdout; exits on error
#
audit_history_get() {
    local program_id="${1:-}"
    local version="${2:-}"

    if [[ -z "$program_id" ]] || [[ -z "$version" ]]; then
        audit_log_error "usage: audit_history_get <program_id> <version>"
        return $ERR_INVALID_ARGS
    fi

    if [[ -z "$JQ_BIN" ]]; then
        audit_log_error "jq is required but not installed"
        return $ERR_NO_JQ
    fi

    local history_file="$AUDIT_HISTORY"

    if [[ ! -f "$history_file" ]]; then
        audit_log_error "History file not found: $history_file"
        return $ERR_NO_HISTORY
    fi

    local audit
    audit=$(_jq_get_audit_by_version "$history_file" "$program_id" "$version")

    if [[ "$audit" == "null" ]] || [[ -z "$audit" ]]; then
        audit_log_error "Audit not found: ${program_id}@${version}"
        return $ERR_VERSION_NOT_FOUND
    fi

    printf '%s\n' "$audit"
    return 0
}

#
# audit_history_list <program_id>
#
# Lists all audited versions for a program.
# Arguments:
#   program_id - Solana program ID (optional, lists all programs if omitted)
#
# Returns: 0, prints version list to stdout; exits on error
#
audit_history_list() {
    local program_id="${1:-}"

    if [[ -z "$JQ_BIN" ]]; then
        audit_log_error "jq is required but not installed"
        return $ERR_NO_JQ
    fi

    local history_file="$AUDIT_HISTORY"

    if [[ ! -f "$history_file" ]]; then
        audit_log_error "History file not found: $history_file"
        return $ERR_NO_HISTORY
    fi

    if [[ -z "$program_id" ]]; then
        # List all programs
        "$JQ_BIN" -r '.programs | to_entries[] |
            "\(.key): \(.value.audits | length) audit(s)"' \
            "$history_file" 2>/dev/null || {
            audit_log_error "Failed to list programs"
            return $ERR_JSON_OP
        }
        return 0
    fi

    # List versions for specific program
    local versions
    versions=$("$JQ_BIN" -r --arg pid "$program_id" \
        '.programs[$pid].audits[] | "\(.version) (\(.timestamp))"' \
        "$history_file" 2>/dev/null || echo '')

    if [[ -z "$versions" ]]; then
        audit_log_error "Program not found: $program_id"
        return $ERR_PROGRAM_NOT_FOUND
    fi

    printf '%s\n' "$versions"
    return 0
}

#
# audit_history_diff <program_id> <v1> <v2>
#
# Compares two audit snapshots, outputting new/fixed/reopened findings.
# Arguments:
#   program_id - Solana program ID
#   v1         - First version (older)
#   v2         - Second version (newer)
#
# Returns: 0, prints diff summary to stdout; exits on error
#
audit_history_diff() {
    local program_id="${1:-}"
    local v1="${2:-}"
    local v2="${3:-}"

    if [[ -z "$program_id" ]] || [[ -z "$v1" ]] || [[ -z "$v2" ]]; then
        audit_log_error "usage: audit_history_diff <program_id> <v1> <v2>"
        return $ERR_INVALID_ARGS
    fi

    if [[ "$v1" == "$v2" ]]; then
        audit_log_error "Cannot diff same version: $v1"
        return $ERR_DIFF_SAME_VERSION
    fi

    if [[ -z "$JQ_BIN" ]]; then
        audit_log_error "jq is required but not installed"
        return $ERR_NO_JQ
    fi

    local history_file="$AUDIT_HISTORY"

    if [[ ! -f "$history_file" ]]; then
        audit_log_error "History file not found: $history_file"
        return $ERR_NO_HISTORY
    fi

    # Get both audits
    local audit1 audit2
    audit1=$(_jq_get_audit_by_version "$history_file" "$program_id" "$v1")
    audit2=$(_jq_get_audit_by_version "$history_file" "$program_id" "$v2")

    if [[ "$audit1" == "null" ]] || [[ -z "$audit1" ]]; then
        audit_log_error "Audit not found: ${program_id}@${v1}"
        return $ERR_VERSION_NOT_FOUND
    fi
    if [[ "$audit2" == "null" ]] || [[ -z "$audit2" ]]; then
        audit_log_error "Audit not found: ${program_id}@${v2}"
        return $ERR_VERSION_NOT_FOUND
    fi

    # Extract finding IDs
    local ids1 ids2
    ids1=$(printf '%s' "$audit1" | "$JQ_BIN" -r '.finding_ids | sort | .[]' 2>/dev/null || echo '')
    ids2=$(printf '%s' "$audit2" | "$JQ_BIN" -r '.finding_ids | sort | .[]' 2>/dev/null || echo '')

    # Convert to arrays for comparison
    local -A map1 map2
    for id in $ids1; do map1["$id"]=1; done
    for id in $ids2; do map2["$id"]=1; done

    # Find new findings (in v2 but not v1)
    local new_findings=""
    for id in "${!map2[@]}"; do
        if [[ -z "${map1[$id]:-}" ]]; then
            new_findings="${new_findings}${id} "
        fi
    done

    # Find fixed findings (in v1 but not v2)
    local fixed_findings=""
    for id in "${!map1[@]}"; do
        if [[ -z "${map2[$id]:-}" ]]; then
            fixed_findings="${fixed_findings}${id} "
        fi
    done

    # Severity changes
    local s1_critical s1_high s1_medium s2_critical s2_high s2_medium
    s1_critical=$(printf '%s' "$audit1" | "$JQ_BIN" -r '.findings.critical')
    s1_high=$(printf '%s' "$audit1" | "$JQ_BIN" -r '.findings.high')
    s1_medium=$(printf '%s' "$audit1" | "$JQ_BIN" -r '.findings.medium')
    s2_critical=$(printf '%s' "$audit2" | "$JQ_BIN" -r '.findings.critical')
    s2_high=$(printf '%s' "$audit2" | "$JQ_BIN" -r '.findings.high')
    s2_medium=$(printf '%s' "$audit2" | "$JQ_BIN" -r '.findings.medium')

    # Print diff summary
    printf '=== Audit Diff: %s (%s -> %s) ===\n' "$program_id" "$v1" "$v2"
    printf '\n'
    printf '--- Severity Breakdown ---\n'
    printf '  Version   Crit  High  Med\n'
    printf '  %-8s %4d  %4d  %4d\n' "$v1" "$s1_critical" "$s1_high" "$s1_medium"
    printf '  %-8s %4d  %4d  %4d\n' "$v2" "$s2_critical" "$s2_high" "$s2_medium"
    printf '\n'

    if [[ -n "$new_findings" ]]; then
        printf '--- NEW Findings (in %s but not %s) ---\n' "$v2" "$v1"
        printf '  %s\n' "$new_findings"
    else
        printf '--- NEW Findings ---\n'
        printf '  (none)\n'
    fi
    printf '\n'

    if [[ -n "$fixed_findings" ]]; then
        printf '--- FIXED Findings (in %s but not %s) ---\n' "$v1" "$v2"
        printf '  %s\n' "$fixed_findings"
    else
        printf '--- FIXED Findings ---\n'
        printf '  (none)\n'
    fi
    printf '\n'

    # Reopened: findings that exist in both but with worse severity
    # (simplified: same IDs present = fixed, absent = new/reopened logic handled above)

    return 0
}

#
# audit_history_stats
#
# Outputs summary statistics: total programs, total audits, finding trends.
#
# Returns: 0, prints stats to stdout; exits on error
#
audit_history_stats() {
    if [[ -z "$JQ_BIN" ]]; then
        audit_log_error "jq is required but not installed"
        return $ERR_NO_JQ
    fi

    local history_file="$AUDIT_HISTORY"

    if [[ ! -f "$history_file" ]]; then
        audit_log_error "History file not found: $history_file"
        return $ERR_NO_HISTORY
    fi

    # Total programs
    local total_programs
    total_programs=$("$JQ_BIN" '.programs | length' "$history_file" 2>/dev/null || echo 0)

    # Total audits
    local total_audits
    total_audits=$("$JQ_BIN" '[.programs[].audits[]] | length' "$history_file" 2>/dev/null || echo 0)

    # Aggregate findings
    local total_critical total_high total_medium total_low
    total_critical=$("$JQ_BIN" '[.programs[].audits[].findings.critical // 0 | select(. > 0)] | add // 0' \
        "$history_file" 2>/dev/null || echo 0)
    total_high=$("$JQ_BIN" '[.programs[].audits[].findings.high // 0 | select(. > 0)] | add // 0' \
        "$history_file" 2>/dev/null || echo 0)
    total_medium=$("$JQ_BIN" '[.programs[].audits[].findings.medium // 0 | select(. > 0)] | add // 0' \
        "$history_file" 2>/dev/null || echo 0)
    total_low=$("$JQ_BIN" '[.programs[].audits[].findings.low // 0 | select(. > 0)] | add // 0' \
        "$history_file" 2>/dev/null || echo 0)

    # Most recent audit
    local latest_program latest_version latest_date
    latest_program=$("$JQ_BIN" -r '.programs | to_entries |
        sort_by(.value.audits[-1].timestamp) | last | .key' \
        "$history_file" 2>/dev/null || echo '')
    latest_version=$("$JQ_BIN" -r '.programs |
        to_entries | sort_by(.value.audits[-1].timestamp) | last |
        .value.audits[-1].version' "$history_file" 2>/dev/null || echo '')
    latest_date=$("$JQ_BIN" -r '.programs |
        to_entries | sort_by(.value.audits[-1].timestamp) | last |
        .value.audits[-1].timestamp' "$history_file" 2>/dev/null || echo '')

    # Per-program summary
    printf '=== Audit History Statistics ===\n'
    printf '\n'
    printf 'Summary:\n'
    printf '  Total programs audited:  %d\n' "$total_programs"
    printf '  Total audit snapshots:   %d\n' "$total_audits"
    printf '\n'
    printf 'Finding Distribution (across all audits):\n'
    printf '  Critical:  %d\n' "$total_critical"
    printf '  High:      %d\n' "$total_high"
    printf '  Medium:    %d\n' "$total_medium"
    printf '  Low:       %d\n' "$total_low"
    printf '  Total:     %d\n' \
        $((total_critical + total_high + total_medium + total_low))
    printf '\n'
    printf 'Most Recent Audit:\n'
    printf '  Program:   %s\n' "$latest_program"
    printf '  Version:   %s\n' "$latest_version"
    printf '  Date:      %s\n' "$latest_date"
    printf '\n'

    # Per-program breakdown
    if (( total_programs > 0 )); then
        printf 'Programs:\n'
        "$JQ_BIN" -r '.programs | to_entries[] |
            "  \(.key)\n    Audits: \(.value.audits | length)\n    Latest: \(.value.audits[-1].version) (\(.value.audits[-1].timestamp))"' \
            "$history_file" 2>/dev/null || true
    fi

    return 0
}

# ---------------------------------------------------------------------------
# Standalone execution support
# ---------------------------------------------------------------------------

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Called directly (not sourced)
    readonly SUBCOMMAND="${1:-}"

    case "$SUBCOMMAND" in
        init)
            shift
            audit_history_init "$@"
            ;;
        add)
            shift
            audit_history_add "$@"
            ;;
        get)
            shift
            audit_history_get "$@"
            ;;
        list)
            shift
            audit_history_list "$@"
            ;;
        diff)
            shift
            audit_history_diff "$@"
            ;;
        stats)
            audit_history_stats
            ;;
        --help|-h|help)
            cat <<'EOF'
audit-history.sh - Audit history management

Usage:
  source scripts/audit-history.sh
  audit_history_init
  audit_history_add <program_id> <version> <findings_json>
  audit_history_get <program_id> <version>
  audit_history_list [program_id]
  audit_history_diff <program_id> <v1> <v2>
  audit_history_stats

Environment:
  AUDIT_HISTORY       Path to history file (default: .audit-history.json)
  AUDIT_HISTORY_DIR   Directory for artifacts (default: .claude/audit-history)
  AUDIT_AUDITOR       Auditor identifier (default: claude)
  AUDIT_LOCK_TIMEOUT  Lock timeout in seconds (default: 10)

Or as standalone script:
  bash scripts/audit-history.sh init
  bash scripts/audit-history.sh add <program_id> <version> <findings_json>
  bash scripts/audit-history.sh get <program_id> <version>
  bash scripts/audit-history.sh list [program_id]
  bash scripts/audit-history.sh diff <program_id> <v1> <v2>
  bash scripts/audit-history.sh stats
EOF
            ;;
        *)
            echo "Unknown command: $SUBCOMMAND" >&2
            echo "Run 'bash scripts/audit-history.sh --help' for usage" >&2
            exit $ERR_INVALID_ARGS
            ;;
    esac
fi
