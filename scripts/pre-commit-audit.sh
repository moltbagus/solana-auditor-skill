#!/bin/bash
#
# pre-commit-audit.sh — Git pre-commit hook for Solana security SAST
# Blocks CRITICAL/HIGH findings, warns on MEDIUM
# Bash 3.2+ compatible (macOS default)
#
# Usage:
#   ./pre-commit-audit.sh --install   # Install as .git/hooks/pre-commit
#   ./pre-commit-audit.sh             # Run manually or via hook
#   git commit --no-verify            # Skip hook
#

set -euo pipefail

# ─── Constants ────────────────────────────────────────────────────────────────

readonly SCRIPT_NAME="pre-commit-audit"
readonly HOOK_NAME="pre-commit"
readonly HOOK_TARGET=".git/hooks/${HOOK_NAME}"
readonly JSON_OUTPUT=".audit-precommit.json"

# Exit codes
readonly EXIT_PASS=0
readonly EXIT_BLOCKED=1
readonly EXIT_ERROR=2

# Colors (respect NO_COLOR env)
if [[ -z "${NO_COLOR:-}" ]] && command -v tput &>/dev/null && [[ -n "${TERM:-}" ]]; then
    RED=$(tput setaf 1 2>/dev/null || echo "")
    YELLOW=$(tput setaf 3 2>/dev/null || echo "")
    GREEN=$(tput setaf 2 2>/dev/null || echo "")
    BOLD=$(tput bold 2>/dev/null || echo "")
    RESET=$(tput sgr0 2>/dev/null || echo "")
else
    RED="" YELLOW="" GREEN="" BOLD="" RESET=""
fi

# ─── Patterns ────────────────────────────────────────────────────────────────
# Format: "description|severity|regex"
# Severity: CRITICAL, HIGH, MEDIUM

declare -a SAST_PATTERNS=(
    # CRITICAL patterns
    "invoke without require_signed~CRITICAL~invoke[[:space:]]*\(.*\)[[:space:]]*;[[:space:]]*\n[[:space:]]*//.*@security[[:space:]]*check|invoke[[:space:]]*\([^)]*\)(?!.*require_signed)(?!.*is_signer)(?!.*signer)"
    "init_if_needed with close in same instruction~CRITICAL~init_if_needed.*\n.*close[[:space:]]*\("
    "unsafe block with privileged operation~CRITICAL~unsafe[[:space:]]*\{[^}]*invoke[^}]*\}"
    "SystemProgram::transfer without signer check~CRITICAL~SystemProgram::transfer(?!.*is_signer)"
    "wrong close authority check~CRITICAL~close.*authority.*!=|CLOSE_AUTHORITY.*!="

    # HIGH patterns
    "remaining_accounts without length check~HIGH~remaining_accounts[[:space:]]*\[.*\](?!.*len\(\))"
    "remaining_accounts without iteration validation~HIGH~remaining_accounts\.iter\(\)(?!.*any\(|!\.len\(\))"
    "try_from_slice without error handling~HIGH~try_from_slice.*unwrap\(\)"
    "unchecked in function name with privileged action~HIGH~fn[[:space:]]+[a-z_]*unchecked[a-z_]*[[:space:]]*\([^)]*\).*\{[^}]*invoke"
    "AccountLoader without owner check~HIGH~AccountLoader.*load\(\)(?!.*owner)"
    "unverified CPI call~HIGH~invoke_signed.*!(.*program_id.*==.*)"
    "PDA derivation without bump validation~HIGH~create_program_address.*\(.*\)(?!.*bump)"
    "token transfer without amount validation~HIGH~transfer\[.*\]\.into_iter\(\)\.next\(\)\.unwrap\(\)[[:space:]]*==[[:space:]]*0"
    "missing signer verification~HIGH~is_signer.*==[[:space:]]*false[[:space:]]*\n.*return|\.signer\(\)[[:space:]]*\?;[[:space:]]*\n.*panic"

    # MEDIUM patterns
    "integer overflow on u64 amounts~MEDIUM~amount[[:space:]]*\+[[:space:]]*amount(?!.*checked_)"

    "hardcoded bump seed~MEDIUM~bump[[:space:]]*=[[:space:]]*[0-9]+[[:space:]]*;"
    "panic in instruction~MEDIUM~panic!\(|unwrap\(\)(?!.*is_err\(\))"
    "missing error handling~MEDIUM~\.ok\(\)[[:space:]]*\?\.|[^_]expect\("
)

# ─── Functions ───────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
${BOLD}Usage:${RESET} $SCRIPT_NAME [OPTIONS]

Git pre-commit hook for Solana security SAST.

${BOLD}OPTIONS:${RESET}
    --install    Install hook as .git/hooks/pre-commit
    --help       Show this help message

${BOLD}ENVIRONMENT:${RESET}
    NO_COLOR     Disable colored output

${BOLD}EXIT CODES:${RESET}
    0            Pass (no CRITICAL/HIGH findings)
    1            Blocked (CRITICAL/HIGH findings found)
    2            Error (invalid usage or script failure)

${BOLD}EXAMPLES:${RESET}
    $SCRIPT_NAME --install
    $SCRIPT_NAME
    git commit --no-verify  # Skip hook
EOF
}

log_info() {
    echo "${BOLD}[AUDIT]${RESET} $*"
}

log_pass() {
    echo "${GREEN}${BOLD}[PASS]${RESET} $*"
}

log_warn() {
    echo "${YELLOW}${BOLD}[WARN]${RESET} $*"
}

log_block() {
    echo "${RED}${BOLD}[BLOCKED]${RESET} $*"
}

log_error() {
    echo "${RED}${BOLD}[ERROR]${RESET} $*" >&2
}

# Check if git is available and we're in a repo
check_git() {
    if ! command -v git &>/dev/null; then
        log_error "git not found"
        exit $EXIT_ERROR
    fi

    if ! git rev-parse --is-inside-work-tree &>/dev/null; then
        log_error "not inside a git repository"
        exit $EXIT_ERROR
    fi
}

# Get the git hooks directory (handles worktrees correctly)
get_git_hooks_dir() {
    git rev-parse --git-path hooks 2>/dev/null || {
        # Fallback for older git or edge cases
        local git_dir
        git_dir=$(git rev-parse --git-dir)
        echo "${git_dir}/hooks"
    }
}

# Install hook
install_hook() {
    check_git

    local hook_source
    hook_source="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

    # Get actual hooks directory (works with git worktrees)
    local hooks_dir
    hooks_dir=$(get_git_hooks_dir)

    # Create hooks directory if it doesn't exist
    mkdir -p "${hooks_dir}"

    local hook_target="${hooks_dir}/${HOOK_NAME}"

    # Backup existing hook if present
    if [[ -f "$hook_target" ]] && ! grep -q "$SCRIPT_NAME" "$hook_target" 2>/dev/null; then
        local backup="${hook_target}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$hook_target" "$backup"
        log_info "Backed up existing hook to $backup"
    fi

    # Create wrapper that includes this script
    # Note: Using heredoc so git rev-parse is evaluated at install time
    local git_root
    git_root=$(git rev-parse --show-toplevel 2>/dev/null)
    local script_path="${git_root}/scripts/pre-commit-audit.sh"

    cat > "$hook_target" <<WRAPPER
#!/bin/bash
# Pre-commit hook managed by pre-commit-audit.sh
# Do not edit directly — modify scripts/pre-commit-audit.sh and re-run --install
exec "${script_path}" "\$@"
WRAPPER

    chmod +x "$hook_target"
    log_pass "Installed hook to $hook_target"
    log_info "Hook will run SAST on staged .rs files before each commit"
}

# Get staged Rust files
get_staged_files() {
    git diff --cached --name-only --diff-filter=ACM 2>/dev/null | grep '\.rs$' || true
}

# Extract staged content for a file (combined diff)
get_staged_content() {
    local file="$1"
    git show ":${file}" 2>/dev/null || true
}

# Run SAST on a single file
scan_file() {
    local file="$1"
    local content
    content=$(get_staged_content "$file")

    if [[ -z "$content" ]]; then
        return 0
    fi

    local findings=()
    local line_num=0

    # Use awk for multi-line pattern matching (bash 3.2 compatible)
    while IFS='~' read -r desc severity pattern; do
        [[ -z "$desc" ]] && continue

        # Count matches using grep
        local count
        count=$(echo "$content" | grep -c "$pattern" 2>/dev/null || echo "0")

        if [[ "$count" -gt 0 ]]; then
            # Get first match line number
            local first_line
            first_line=$(echo "$content" | grep -n "$pattern" 2>/dev/null | head -1 | cut -d: -f1 || echo "?")

            findings+=("${severity}~${desc}~${file}~${first_line}~${count}")
        fi
    done <<< "$(printf '%s\n' "${SAST_PATTERNS[@]}")"

    # Output findings
    for finding in "${findings[@]:-}"; do
        [[ -z "$finding" ]] && continue
        echo "$finding"
    done
}

# Aggregate findings by severity
aggregate_findings() {
    local all_findings=("$@")

    local critical_count=0
    local high_count=0
    local medium_count=0

    local critical_details=()
    local high_details=()
    local medium_details=()

    for finding in "${all_findings[@]:-}"; do
        [[ -z "$finding" ]] && continue

        IFS='~' read -r severity desc file line count <<< "$finding"

        case "$severity" in
            CRITICAL)
                ((critical_count++))
                critical_details+=("${file}:${line} (${count}x)")
                ;;
            HIGH)
                ((high_count++))
                high_details+=("${file}:${line} (${count}x)")
                ;;
            MEDIUM)
                ((medium_count++))
                medium_details+=("${file}:${line} (${count}x)")
                ;;
        esac
    done

    echo "CRITICAL=$critical_count"
    echo "HIGH=$high_count"
    echo "MEDIUM=$medium_count"

    # Store details for JSON output
    if [[ ${#critical_details[@]} -gt 0 ]]; then
        printf '%s\n' "${critical_details[@]}" > /tmp/audit_critical_$$
    fi
    if [[ ${#high_details[@]} -gt 0 ]]; then
        printf '%s\n' "${high_details[@]}" > /tmp/audit_high_$$
    fi
    if [[ ${#medium_details[@]} -gt 0 ]]; then
        printf '%s\n' "${medium_details[@]}" > /tmp/audit_medium_$$
    fi
}

# Generate JSON report
generate_json() {
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local critical_count high_count medium_count
    critical_count=0
    high_count=0
    medium_count=0

    # Read counts from temp files
    if [[ -f /tmp/audit_critical_$$ ]]; then
        critical_count=$(wc -l < /tmp/audit_critical_$$ | tr -d ' ')
    fi
    if [[ -f /tmp/audit_high_$$ ]]; then
        high_count=$(wc -l < /tmp/audit_high_$$ | tr -d ' ')
    fi
    if [[ -f /tmp/audit_medium_$$ ]]; then
        medium_count=$(wc -l < /tmp/audit_medium_$$ | tr -d ' ')
    fi

    local blocked=$((critical_count + high_count > 0 ? 1 : 0))

    cat > "$JSON_OUTPUT" <<EOF
{
  "timestamp": "$timestamp",
  "commit": "$(git rev-parse HEAD 2>/dev/null || echo "none")",
  "blocked": $blocked,
  "summary": {
    "critical": $critical_count,
    "high": $high_count,
    "medium": $medium_count
  },
  "findings": [
$(generate_findings_json)
  ]
}
EOF

    log_info "JSON report saved to $JSON_OUTPUT"
}

generate_findings_json() {
    local first=true

    for severity in CRITICAL HIGH MEDIUM; do
        local tmpfile=""
        case "$severity" in
            CRITICAL) tmpfile="/tmp/audit_critical_$$" ;;
            HIGH)     tmpfile="/tmp/audit_high_$$" ;;
            MEDIUM)   tmpfile="/tmp/audit_medium_$$" ;;
        esac

        if [[ -f "$tmpfile" ]] && [[ -s "$tmpfile" ]]; then
            while IFS= read -r detail; do
                IFS=':' read -r file line rest <<< "$detail"
                printf '%s    {"severity": "%s", "file": "%s", "line": "%s"}\n' \
                    "$([ "$first" = true ] && echo "" || echo ",")" \
                    "$severity" "$file" "$line"
                first=false
            done < "$tmpfile"
        fi
    done
}

# Cleanup temp files
cleanup() {
    rm -f /tmp/audit_critical_$$ /tmp/audit_high_$$ /tmp/audit_medium_$$
}

# Run main audit
run_audit() {
    check_git

    # Check for --no-verify flag (git passes this automatically)
    for arg in "$@"; do
        if [[ "$arg" == "--no-verify" ]]; then
            log_info "Skipping audit (--no-verify)"
            exit $EXIT_PASS
        fi
    done

    # Get staged Rust files
    local staged_files
    staged_files=$(get_staged_files)

    if [[ -z "$staged_files" ]]; then
        log_pass "No Rust files staged — passing"
        exit $EXIT_PASS
    fi

    log_info "Scanning staged Rust files..."
    echo ""

    # Run SAST on each file
    local all_findings=()
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        log_info "Scanning: $file"

        while IFS='~' read -r finding; do
            [[ -z "$finding" ]] && continue
            all_findings+=("$finding")

            IFS='~' read -r severity desc f line count <<< "$finding"
            local suffix=""; [[ "$count" -gt 1 ]] && suffix="es"
            echo "  ${RED}${severity}${RESET}: $desc in ${f}:${line} (${count} match${suffix})"

        done < <(scan_file "$file")
    done <<< "$staged_files"

    echo ""

    # Aggregate and report
    aggregate_findings "${all_findings[@]}"

    local critical_count high_count medium_count
    critical_count=0
    high_count=0
    medium_count=0

    [[ -f /tmp/audit_critical_$$ ]] && critical_count=$(wc -l < /tmp/audit_critical_$$ | tr -d ' ')
    [[ -f /tmp/audit_high_$$ ]] && high_count=$(wc -l < /tmp/audit_high_$$ | tr -d ' ')
    [[ -f /tmp/audit_medium_$$ ]] && medium_count=$(wc -l < /tmp/audit_medium_$$ | tr -d ' ')

    # Generate JSON report
    generate_json

    # Final output
    echo ""
    if [[ $critical_count -gt 0 ]] || [[ $high_count -gt 0 ]]; then
        log_block "COMMIT BLOCKED"
        echo ""
        echo "${RED}Found ${BOLD}${critical_count} CRITICAL${RESET} and ${BOLD}${high_count} HIGH${RESET} findings."
        echo "Review and fix, or use ${BOLD}git commit --no-verify${RESET} to skip."
        echo ""
        cleanup
        exit $EXIT_BLOCKED
    fi

    if [[ $medium_count -gt 0 ]]; then
        log_warn "COMMIT ALLOWED with ${BOLD}${medium_count} MEDIUM${RESET} warnings"
        echo ""
        echo "Review warnings above, or use ${BOLD}git commit --no-verify${RESET} to skip."
        echo ""
        cleanup
        exit $EXIT_PASS
    fi

    log_pass "No security findings — commit allowed"
    echo ""
    cleanup
    exit $EXIT_PASS
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
    # Trap for cleanup
    trap cleanup EXIT

    case "${1:-}" in
        --install)
            install_hook
            ;;
        --help|-h)
            usage
            exit $EXIT_PASS
            ;;
        *)
            run_audit "$@"
            ;;
    esac
}

main "$@"
