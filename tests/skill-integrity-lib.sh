#!/bin/bash
# tests/skill-integrity-lib.sh
#
# Shared library for skill integrity checks.
# Extracted from test-skill-integrity.sh for modularity.
# Source this file:  source "$(dirname "$0")/skill-integrity-lib.sh"

# =========================================================================
# COUNTERS
# =========================================================================
PASS=0
FAIL=0
WARN=0

# =========================================================================
# OUTPUT HELPERS
# =========================================================================
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
# FIXTURE PATH VARIABLES — Single source of truth
# =========================================================================
# Vault fixture
VAULT_SRC="examples/sample-vulnerable-program/programs/vault/src/lib.rs"
VAULT_FINDINGS="examples/sample-vulnerable-program/audit-output/findings.json"
VAULT_REPORT="examples/sample-vulnerable-program/audit-output/AUDIT_REPORT.md"

# Token-extensions fixture
TOKEN_SRC="examples/sample-vulnerable-program/programs/token-extensions/src/lib.rs"
TOKEN_FINDINGS="examples/sample-vulnerable-program/audit-output/token-extensions/findings.json"
TOKEN_REPORT="examples/sample-vulnerable-program/audit-output/token-extensions/AUDIT_REPORT.md"

# Token-2022 real fixture
TOKEN2022_SRC="examples/token-2022-real/src/lib.rs"
TOKEN2022_FINDINGS="examples/token-2022-real/audit-output/findings.json"
TOKEN2022_REPORT="examples/token-2022-real/audit-output/AUDIT_REPORT.md"
TOKEN2022_TRACE="examples/token-2022-real/audit-output/methodology-trace.md"

# Live-exploit fixtures
SOLEND_FINDINGS="examples/solend-governance-audit/audit-output/findings.json"
KLIVE_FINDINGS="examples/klive-live-audit/audit-output/findings.json"

# =========================================================================
# CHECK FUNCTIONS
# =========================================================================

# Validate VULN coverage for any fixture
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
    # Extract VULN IDs from source (VULN-NN comments)
    src_ids=$(rg "^\\s*// VULN-[0-9]+" "$SRC_FILE" | rg -o "VULN-[0-9]+" | sort -u)
    # Extract VULN IDs from findings.json using Python (reliable JSON parsing)
    fnd_ids=$(python3 -c "
import json
with open('$FND_FILE') as f:
    data = json.load(f)
for finding in data.get('findings', []):
    fid = finding.get('id', '')
    if fid.startswith('VULN-'):
        print(fid)
" 2>/dev/null | sort -u)
    src_count=$(echo "$src_ids" | tr -d '\n' | wc -w | tr -d ' ')
    fnd_count=$(echo "$fnd_ids" | tr -d '\n' | wc -w | tr -d ' ')

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

# Verify methodology-trace.md CVSS scores match findings.json
check_trace_cvss_for_fixture() {
    local LABEL="$1"
    local FND_FILE="$2"
    local TRACE_FILE="$3"

    if [ ! -f "$FND_FILE" ] || [ ! -f "$TRACE_FILE" ]; then
        fail "$LABEL: findings.json or methodology-trace.md missing"
        return
    fi

    local mismatch_count=0
    while IFS='|' read -r fid vec; do
        [ -z "$fid" ] && continue
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

        if grep -q "$fid" "$TRACE_FILE" 2>/dev/null; then
            local trace_score
            trace_score=$(grep -A5 "$fid" "$TRACE_FILE" | grep -oE '→ [0-9]+\\.[0-9]+' | head -1 | cut -d' ' -f2)
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

# Run a Python integrity check for each fixture (single arg: findings.json)
run_single_arg_check_for_fixtures() {
    local CHECK_NAME="$1"
    local CHECK_LABEL="$2"
    local SCRIPT_DIR="${3:-$(dirname "$0")}"

    for fixture_pair in "vault:$VAULT_FINDINGS" "token-extensions:$TOKEN_FINDINGS" "token-2022-real:$TOKEN2022_FINDINGS" "solend-governance:$SOLEND_FINDINGS" "klive:$KLIVE_FINDINGS"; do
        local LABEL="${fixture_pair%%:*}"
        local F_PATH="${fixture_pair##*:}"

        if [ ! -f "$F_PATH" ]; then
            ok "$LABEL: skipped — $F_PATH not present"
            continue
        fi

        if python3 "$SCRIPT_DIR/severity_counts.py" "$CHECK_NAME" "$F_PATH" 2>&1; then
            ok "$LABEL: $CHECK_LABEL"
        else
            fail "$LABEL: $CHECK_LABEL failed"
        fi
    done
}

# Run a Python integrity check for each fixture (two args: findings.json + report.md)
run_two_arg_check_for_fixtures() {
    local CHECK_NAME="$1"
    local CHECK_LABEL="$2"
    local SCRIPT_DIR="${3:-$(dirname "$0")}"

    for fixture_pair in "vault:$VAULT_FINDINGS:$VAULT_REPORT" "token-extensions:$TOKEN_FINDINGS:$TOKEN_REPORT" "token-2022-real:$TOKEN2022_FINDINGS:$TOKEN2022_REPORT"; do
        local LABEL="${fixture_pair%%:*}"
        local rest="${fixture_pair#*:}"
        local F_PATH="${rest%%:*}"
        local R_PATH="${rest##*:}"

        if [ ! -f "$F_PATH" ] || [ ! -f "$R_PATH" ]; then
            fail "$LABEL: cannot validate $CHECK_LABEL — files missing"
            continue
        fi

        if python3 "$SCRIPT_DIR/severity_counts.py" "$CHECK_NAME" "$F_PATH" "$R_PATH" 2>&1; then
            ok "$LABEL: $CHECK_LABEL"
        else
            fail "$LABEL: $CHECK_LABEL failed"
        fi
    done
}

# Run a line-number check for each fixture
run_line_number_check_for_fixtures() {
    local SCRIPT_DIR="${1:-$(dirname "$0")}"

    for line_check_pair in "vault:$VAULT_FINDINGS:$VAULT_SRC" "token-extensions:$TOKEN_FINDINGS:$TOKEN_SRC" "token-2022-real:$TOKEN2022_FINDINGS:$TOKEN2022_SRC"; do
        local LABEL="${line_check_pair%%:*}"
        local rest="${line_check_pair#*:}"
        local F_PATH="${rest%%:*}"
        local S_PATH="${rest##*:}"

        if [ ! -f "$F_PATH" ] || [ ! -f "$S_PATH" ]; then
            fail "$LABEL: cannot check line numbers — files missing"
            continue
        fi

        if python3 "$SCRIPT_DIR/severity_counts.py" check-line-numbers "$F_PATH" "$S_PATH" 2>&1; then
            ok "$LABEL: all finding line numbers are within 5 lines of their VULN comments"
        else
            fail "$LABEL: finding line numbers drifted from VULN comments in source"
        fi
    done
}
