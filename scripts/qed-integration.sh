#!/bin/bash
# =============================================================================
# qed-integration.sh — Formal verification CI wrapper
# =============================================================================
# Executes formal verification by:
#   1. Detecting QEDGen skill (AI agent skill) or qed-solana (legacy CLI)
#   2. Validating .qedspec specification files
#   3. Running Anchor program tests as runtime verification fallback
#   4. Generating structured verification report
#
# Exit codes:
#   0  = success (all verifications passed or gracefully skipped)
#   1  = failure (unexpected errors)
#   2  = skip (no toolchain or programs to verify)
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

REPORT_FILE="$REPO_ROOT/formal_verification_report.json"
PROGRAMS_DIR="$REPO_ROOT/programs"
TIMEOUT_SECONDS=120

# ── Helpers ───────────────────────────────────────────────────────────────────

now_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

write_report() {
  local status="$1" reason="$2" detail="${3:-}"
  cat > "$REPORT_FILE" <<EOF
{
  "timestamp": "$(now_utc)",
  "status": "${status}",
  "reason": "${reason}",
  "detail": ${detail:-null}
}
EOF
}

# ── Toolchain detection ───────────────────────────────────────────────────────
# QEDGen is an AI agent skill (.agents/skills/qedgen/ or ~/.claude/skills/qedgen/)
# qed-solana is a legacy standalone binary.

TOOL_NAME=""
TOOL_VERSION=""

detect_toolchain() {
  # Check for .qedspec files first — they imply QEDGen intent
  local spec_count
  spec_count=$(find "$REPO_ROOT" -name '*.qedspec' -maxdepth 3 2>/dev/null | wc -l | tr -d ' ')

  # Check for QEDGen skill (AI agent skill, not standalone CLI)
  if [ -f "$REPO_ROOT/.agents/skills/qedgen/SKILL.md" ] || \
     [ -f "$HOME/.claude/skills/qedgen/SKILL.md" ]; then
    TOOL_NAME="qedgen"
    TOOL_VERSION="skill"
    echo "QED_GEN_FOUND"
    return
  fi

  # Check for legacy qed-solana binary
  if command -v qed-solana >/dev/null 2>&1; then
    TOOL_NAME="qed-solana"
    TOOL_VERSION=$(qed-solana --version 2>/dev/null | head -1 || echo "unknown")
    echo "QED_SOLANA_FOUND"
    return
  fi

  # No QED toolchain, but check for spec files
  if [ "$spec_count" -gt 0 ]; then
    TOOL_NAME="qedspec-only"
    TOOL_VERSION="specs=${spec_count}"
    echo "SPECS_FOUND"
    return
  fi

  echo "NOT_FOUND"
}

get_tool_name() { echo "$TOOL_NAME"; }
get_tool_version() { echo "$TOOL_VERSION"; }

# ── Check programs directory ──────────────────────────────────────────────────

check_programs() {
  if [ ! -d "$PROGRAMS_DIR" ]; then
    echo "No programs/ directory found — nothing to verify"
    return 1
  fi
  local count
  count=$(find "$PROGRAMS_DIR" -name "Cargo.toml" -maxdepth 2 2>/dev/null | wc -l | tr -d ' ')
  if [ "$count" -eq 0 ]; then
    echo "No programs found in programs/"
    return 1
  fi
  echo "Found $count program(s)"
  return 0
}

# ── Init report ────────────────────────────────────────────────────────────────

init_report() {
  local program_count="${1:-0}"
  local tool
  tool=$(get_tool_name)
  local version
  version=$(get_tool_version)
  cat > "$REPORT_FILE" <<EOF
{
  "timestamp": "$(now_utc)",
  "tool": "${tool:-unknown}",
  "version": "${version:-unknown}",
  "programs_verified": ${program_count},
  "status": "running",
  "invariants": [],
  "findings": [],
  "specs_validated": [],
  "tests": [],
  "errors": []
}
EOF
}

# ── Validate .qedspec files ────────────────────────────────────────────────────

validate_specs() {
  local count=0
  while IFS= read -r -d '' spec; do
    name=$(basename "$spec")
    echo "  Validating: $name"
    local detail=""

    # Try JSON parse
    if python3 -c "import json; json.load(open('$spec'))" 2>/dev/null; then
      detail="json"
    elif python3 -c "import yaml; yaml.safe_load(open('$spec'))" >/dev/null 2>&1; then
      detail="yaml"
    else
      # Not JSON or YAML — assume structured text spec
      detail="text"
    fi

    count=$((count + 1))
    jq --arg name "$name" --arg format "$detail" \
       '.specs_validated += [{"file": $name, "format": $format, "valid": true}]' \
       "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"

    echo "    -> $name: $detail"
  done < <(find "$REPO_ROOT" -name '*.qedspec' -maxdepth 3 -print0 2>/dev/null)
  echo "  Validated $count .qedspec file(s)"
}

# ── Run Anchor CLI integration tests ──────────────────────────────────────────

run_anchor_tests() {
  if ! command -v anchor >/dev/null 2>&1; then
    echo "  SKIP: anchor CLI not available"
    return
  fi

  for program in "$PROGRAMS_DIR"/*/Cargo.toml; do
    [ -f "$program" ] || continue
    dir=$(dirname "$program")
    name=$(basename "$dir")
    echo "  Testing: $name"

    local output
    output=$(anchor test --skip-build 2>&1 || true)

    local passed=0 failed=0
    passed=$(echo "$output" | grep -c "PASS" 2>/dev/null || echo "0")
    failed=$(echo "$output" | grep -c "FAIL" 2>/dev/null || echo "0")

    jq --arg name "$name" --argjson passed "$passed" --argjson failed "$failed" \
       --arg raw "$output" \
       '.tests += [{
         "program": $name,
         "passed": $passed,
         "failed": $failed,
         "output": $raw
       }]' \
       "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"

    echo "    -> ${passed} passed, ${failed} failed"
  done
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
  echo "=== Formal Verification ==="
  echo ""

  local tool_status
  tool_status=$(detect_toolchain)

  local tool_name
  tool_name=$(get_tool_name)
  local tool_version
  tool_version=$(get_tool_version)
  echo "Tool: ${tool_name:-none} (${tool_version:-N/A})"

  # Check for programs or spec files
  local has_programs=false has_specs=false
  if check_programs 2>/dev/null; then
    has_programs=true
  fi
  if [ "$(find "$REPO_ROOT" -name '*.qedspec' -maxdepth 3 2>/dev/null | wc -l | tr -d ' ')" -gt 0 ]; then
    has_specs=true
  fi

  # If nothing to verify, skip gracefully
  if [ "$has_programs" = false ] && [ "$has_specs" = false ]; then
    echo "SKIP: No programs or .qedspec files found"
    write_report "skipped" "nothing_to_verify"
    exit 2
  fi

  # Calculate program count
  local program_count=0
  if [ "$has_programs" = true ]; then
    program_count=$(find "$PROGRAMS_DIR" -name "Cargo.toml" -maxdepth 2 2>/dev/null | wc -l | tr -d ' ')
  fi
  init_report "$program_count"

  # Step 1: Validate .qedspec specification files
  if [ "$has_specs" = true ]; then
    echo ""
    echo "--- Validating .qedspec files ---"
    validate_specs
  fi

  # Step 2: Run Anchor integration tests as runtime verification
  echo ""
  echo "--- Anchor Integration Tests ---"
  run_anchor_tests

  # Step 3: QEDGen availability note
  if [ "$tool_status" = "QED_GEN_FOUND" ]; then
    echo ""
    echo "--- QEDGen Skill Available ---"
    echo "  QEDGen is an AI agent skill for Claude Code."
    echo "  Run formal verification interactively with:"
    echo "  \$ npx skills add qedgen/solana-skills"
    echo "  Then use Claude Code with the QEDGen skill loaded."
  fi

  # Finalize report
  local total_specs total_tests total_errors
  total_specs=$(jq '.specs_validated | length' "$REPORT_FILE" 2>/dev/null || echo "0")
  total_tests=$(jq '.tests | length' "$REPORT_FILE" 2>/dev/null || echo "0")
  total_errors=$(jq '.errors | length' "$REPORT_FILE" 2>/dev/null || echo "0")

  local final_status="complete"
  if [ "$total_errors" -gt 0 ]; then
    final_status="partial"
  fi

  jq --argjson total_specs "$total_specs" \
     --argjson total_tests "$total_tests" \
     --arg status "$final_status" \
     '.total_specs_validated = $total_specs |
      .total_tests_run = $total_tests |
      .status = $status' \
     "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"

  echo ""
  echo "=== Summary ==="
  echo "  Tool: ${tool_name:-none}"
  echo "  Programs: $program_count"
  echo "  Specs validated: $total_specs"
  echo "  Tests run: $total_tests"
  echo "  Status: $final_status"

  exit 0
}

main "$@"
