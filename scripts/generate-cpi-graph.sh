#!/bin/bash
# =============================================================================
# generate-cpi-graph.sh
# Extracts all CPI calls and builds a program dependency graph
# Output: cpi_surface.json
# Compatible with bash 3.2+ (macOS default)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_FILE="${OUTPUT_FILE:-cpi_surface.json}"

# Known SPL program pubkeys
get_spl_program_type() {
    local pubkey="$1"
    case "$pubkey" in
        TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA) echo "spl_token" ;;
        TokenzQdBkbNNPeDs6DcXXRkQPphdB99YhEELFMZzUPRxM) echo "spl_token_2022" ;;
        ATokenGPvbdGVxr2bvgtdq2gYhS4WSGLHeVV8nkdst5e) echo "associated_token" ;;
        11111111111111111111111111111111) echo "system_program" ;;
        Stake11111111111111111111111111111111111111) echo "stake_program" ;;
        Vote111111111111111111111111111111111111111) echo "vote_program" ;;
        Sysvar1111111111111111111111111111111111111) echo "sysvar" ;;
        Config111111111111111111111111111111111111) echo "config_program" ;;
        Memo1UhkJRfHyvLMcRuc7u5MC7iBwlZ6EEgMw424FWP) echo "memo_program" ;;
        ComputeBudget111111111111111111111111111111) echo "compute_budget" ;;
        *) echo "" ;;
    esac
}

get_program_name() {
    local pubkey="$1"
    local spl_type
    spl_type=$(get_spl_program_type "$pubkey")
    if [ -n "$spl_type" ]; then
        echo "$spl_type"
    else
        echo "custom_${pubkey:0:8}..."
    fi
}

echo "Generating CPI surface graph..."

# Initialize JSON arrays
NODES='[]'
EDGES='[]'

# Find Rust files
if [ -d "$PROJECT_ROOT/programs" ]; then
    RUST_FILES=$(find "$PROJECT_ROOT/programs" -name "*.rs" -type f 2>/dev/null)
else
    RUST_FILES=$(find "$PROJECT_ROOT" -name "*.rs" -type f 2>/dev/null | grep -v target | grep -v ".git")
fi

# Use newline-separated string for discovered programs (bash 3.2 compatible)
DISCOVERED_PROGRAMS=""
add_program() {
    local pubkey="$1"
    echo "$DISCOVERED_PROGRAMS" | grep -qxF "$pubkey" && return
    DISCOVERED_PROGRAMS="${DISCOVERED_PROGRAMS}${pubkey}"$'\n'
}

# Temp files
INVOKE_TMP=$(mktemp)
INVOKE_SIGNED_TMP=$(mktemp)
CONTEXT_TMP=$(mktemp)

# Process each file
while IFS= read -r file; do
    [ -z "$file" ] && continue
    # Skip non-program files
    echo "$file" | grep -qE '/tests/|/target/' && continue

    # Extract invoke calls
    if grep -q "invoke(" "$file" 2>/dev/null; then
        grep -n "invoke(" "$file" | grep -v "//.*invoke" | while IFS= read -r line; do
            linenum=$(echo "$line" | cut -d: -f1)
            content=$(echo "$line" | sed 's/^[0-9]*: *//')
            program_id=""
            if echo "$content" | grep -q "program_id\.key()"; then
                prev_lines=$(head -n "$linenum" "$file" 2>/dev/null | tail -20)
                program_id=$(echo "$prev_lines" | grep -oE '[a-zA-Z_][a-zA-Z0-9_]*\.key()' | tail -1 | sed 's/\.key()//')
            fi
            function=$(grep -B 50 "fn " "$file" 2>/dev/null | grep "fn " | tail -1 | sed 's/.*fn \([^(]*\).*/\1/' || echo "unknown")
            echo "INVOKE|$file|$linenum|$program_id|$function"
        done >> "$INVOKE_TMP"
    fi

    # Extract invoke_signed calls
    if grep -q "invoke_signed(" "$file" 2>/dev/null; then
        grep -n "invoke_signed(" "$file" | grep -v "//.*invoke_signed" | while IFS= read -r line; do
            linenum=$(echo "$line" | cut -d: -f1)
            content=$(echo "$line" | sed 's/^[0-9]*: *//')
            program_id=""
            if echo "$content" | grep -q "program_id\.key()"; then
                prev_lines=$(head -n "$linenum" "$file" 2>/dev/null | tail -20)
                program_id=$(echo "$prev_lines" | grep -oE '[a-zA-Z_][a-zA-Z0-9_]*\.key()' | tail -1 | sed 's/\.key()//')
            fi
            function=$(grep -B 50 "fn " "$file" 2>/dev/null | grep "fn " | tail -1 | sed 's/.*fn \([^(]*\).*/\1/' || echo "unknown")
            echo "INVOKE_SIGNED|$file|$linenum|$program_id|$function"
        done >> "$INVOKE_SIGNED_TMP"
    fi

    # Extract CpiContext
    if grep -q "CpiContext" "$file" 2>/dev/null; then
        grep -n "CpiContext" "$file" | grep -v "//.*CpiContext" | while IFS= read -r line; do
            linenum=$(echo "$line" | cut -d: -f1)
            signer="false"
            context_start=$(($linenum > 5 ? linenum - 5 : 1))
            context_lines=$(sed -n "${context_start},${linenum}p" "$file" 2>/dev/null)
            echo "$context_lines" | grep -q "\.with_signer" && signer="true"
            function=$(grep -B 50 "fn " "$file" 2>/dev/null | grep "fn " | tail -1 | sed 's/.*fn \([^(]*\).*/\1/' || echo "unknown")
            echo "CPI_CONTEXT|$file|$linenum|$signer|$function"
        done >> "$CONTEXT_TMP"
    fi

done <<< "$RUST_FILES"

echo "Building dependency graph..."

# Process invoke calls
if [ -f "$INVOKE_TMP" ]; then
    while IFS='|' read -r call_type file line program_id function; do
        [ -z "$file" ] && continue
        short_file=$(basename "$file")
        prog_target="${program_id:-unknown}"
        EDGES=$(echo "$EDGES" | jq --arg type "$call_type" --arg f "$short_file" \
            --arg l "$line" --arg func "$function" --arg prog "$prog_target" \
            '. + [{source: "program", target: $prog, call_type: $type, file: $f, line: ($l | tonumber), function: $func, signer: ($type == "INVOKE_SIGNED")}]' 2>/dev/null || echo "$EDGES")
        [ -n "$program_id" ] && [ "$program_id" != "unknown" ] && add_program "$program_id"
    done < "$INVOKE_TMP"
fi

# Process invoke_signed calls
if [ -f "$INVOKE_SIGNED_TMP" ]; then
    while IFS='|' read -r call_type file line program_id function; do
        [ -z "$file" ] && continue
        short_file=$(basename "$file")
        prog_target="${program_id:-unknown}"
        EDGES=$(echo "$EDGES" | jq --arg type "$call_type" --arg f "$short_file" \
            --arg l "$line" --arg func "$function" --arg prog "$prog_target" \
            '. + [{source: "program", target: $prog, call_type: $type, file: $f, line: ($l | tonumber), function: $func, signer: true}]' 2>/dev/null || echo "$EDGES")
        [ -n "$program_id" ] && [ "$program_id" != "unknown" ] && add_program "$program_id"
    done < "$INVOKE_SIGNED_TMP"
fi

# Build nodes from discovered programs
echo "$DISCOVERED_PROGRAMS" | while IFS= read -r pubkey; do
    [ -z "$pubkey" ] && continue
    prog_type=$(get_spl_program_type "$pubkey")
    [ -z "$prog_type" ] && prog_type="custom"
    prog_name=$(get_program_name "$pubkey")
    NODES=$(echo "$NODES" | jq --arg id "$prog_name" --arg label "$pubkey" --arg type "$prog_type" \
        '. + [{id: $id, label: $label, type: $type}]' 2>/dev/null || echo "$NODES")
done

# Add main node
NODES=$(echo "$NODES" | jq '. + [{id: "program", label: "target_program", type: "target"}]' 2>/dev/null || echo "$NODES")

# Count totals
total_programs=$(echo "$NODES" | jq 'length' 2>/dev/null || echo 0)
total_cpi_calls=$(echo "$EDGES" | jq 'length' 2>/dev/null || echo 0)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Generate output
cat > "$OUTPUT_FILE" << EOF
{
  "metadata": {
    "generated_at": "$TIMESTAMP",
    "program_id": "${TARGET_PROGRAM_ID:-unknown}",
    "total_programs": $total_programs,
    "total_cpi_calls": $total_cpi_calls,
    "analysis_version": "1.0"
  },
  "nodes": $NODES,
  "edges": $EDGES
}
EOF

# Cleanup
rm -f "$INVOKE_TMP" "$INVOKE_SIGNED_TMP" "$CONTEXT_TMP"

echo "CPI surface graph generated: $OUTPUT_FILE"
echo "  - Programs: $total_programs"
echo "  - CPI calls: $total_cpi_calls"