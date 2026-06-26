#!/bin/bash
#
# solana-auditor-shiba — Claude Code Skill Installer
# ==================================================
# Installs the 6-phase Solana security auditor lifecycle into any
# Claude Code instance. Targets $HOME/.claude/{skills,commands,rules}.
#
# Supported shells: bash 3+, zsh, fish (via env var pass-through)
# Idempotent — safe to re-run on existing installs.
#
# Usage:
#   ./install.sh              # interactive
#   ./install.sh --yes       # non-interactive (CI / automation)
#   ./install.sh --dry-run   # show what would be installed
#   ./install.sh --uninstall # remove all installed files
#   ./install.sh --verify    # check install status
#   ./install.sh --help      # this help
#
# Exit codes:
#   0  success
#   1  error (missing source files, permission denied)
#   2  user cancelled
#   3  unsupported OS
#
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m';  YELLOW='\033[1;33m'
BLUE='\033[0;34m';  MAGENTA='\033[0;35m'; CYAN='\033[0;36m'
WHITE='\033[1;37m'; NC='\033[0m'   # No Colour

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$SCRIPT_DIR"                    # package root = install.sh dir
SRC_SKILL="$PKG_DIR/skill"
SRC_AGENTS="$PKG_DIR/agents"
SRC_CMDS="$PKG_DIR/commands"
SRC_RULES="$PKG_DIR/rules"
SRC_TMPL="$PKG_DIR/templates"

SKILLS_DIR="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"
SKILL_PATH="$SKILLS_DIR/solana-auditor-shiba"
CMDS_PATH="${CLAUDE_COMMANDS_DIR:-$HOME/.claude/commands}"
RULES_PATH="${CLAUDE_RULES_DIR:-$HOME/.claude/rules}"
TMPL_PATH="${CLAUDE_TEMPLATES_DIR:-$HOME/.claude/templates}"

# ── Options ──────────────────────────────────────────────────────────────────
SKIP_CONFIRM=false
DRY_RUN=false
UNINSTALL=false
VERIFY_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -y|--yes|--non-interactive) SKIP_CONFIRM=true ;;
        --dry-run) DRY_RUN=true ;;
        --uninstall) UNINSTALL=true ;;
        --verify) VERIFY_MODE=true ;;
        -h|--help) HELP=true ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
    shift
done

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${BLUE}[*]${NC} $*"; }
ok()      { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[✗]${NC} $*" >&2; }
run()     { [[ "$DRY_RUN" == true ]] && echo "    DRY-RUN: $* →" || "$@"; }

count_src() {
    local dir=$1; local ext=$2
    if [[ -d "$dir" ]]; then
        if [[ -n "$ext" ]]; then
            find "$dir" -type f \( -name "$ext" -o -name "${ext%.*}" \) 2>/dev/null | wc -l | tr -d ' '
        else
            find "$dir" -type f 2>/dev/null | wc -l | tr -d ' '
        fi
    else echo 0; fi
}

# ── Banner ────────────────────────────────────────────────────────────────────
banner() {
    echo ""
    echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC}  ${WHITE}Solana Auditor Shiba — Claude Code Skill Installer${NC}       ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}║${NC}  ${CYAN}6-phase audit lifecycle · 17 rules · 6 slash commands${NC}     ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ── Verify source ─────────────────────────────────────────────────────────────
verify_sources() {
    local missing=0
    for f in "$SRC_SKILL/SKILL.md" "$SRC_CMDS/audit.md" "$SRC_RULES/audit.rules"; do
        if [[ ! -f "$f" ]]; then
            err "Missing required source: $f"
            missing=1
        fi
    done
    [[ $missing -eq 1 ]] && exit 1
}

# ── Uninstall ────────────────────────────────────────────────────────────────
do_uninstall() {
    banner
    info "Removing solana-auditor-shiba skill..."

    local removed=0
    [[ -d "$SKILL_PATH" ]] && { rm -rf "$SKILL_PATH"; ok "Removed $SKILL_PATH"; removed=1; }
    [[ -f "$CMDS_PATH/audit.md" ]] && { rm "$CMDS_PATH"/audit*.md "$CMDS_PATH"/audit-*.md 2>/dev/null || true; ok "Removed slash commands"; removed=1; }
    [[ -f "$RULES_PATH/audit.rules" ]] && { rm "$RULES_PATH"/audit.rules 2>/dev/null || true; ok "Removed path-scoped rules"; removed=1; }
    [[ -d "$TMPL_PATH/solana-auditor-shiba" ]] && { rm -rf "$TMPL_PATH/solana-auditor-shiba"; ok "Removed PoC templates"; removed=1; }

    if [[ $removed -eq 0 ]]; then
        warn "Nothing to remove — skill not found at expected paths."
    fi

    echo ""
    ok "Uninstall complete."
    exit 0
}

# ── Verify ─────────────────────────────────────────────────────────────────────
do_verify() {
    banner
    local ok_count=0; local fail_count=0

    check() {
        local label=$1; local path=$2
        if [[ -f "$path" ]] || [[ -d "$path" && "$(count_src "$path" "")" -gt 0 ]]; then
            ok "$label"; ((ok_count++))
        else
            err "$label  ($path)"; ((fail_count++))
        fi
    }

    info "Skill install status:"
    check "  SKILL.md"         "$SKILL_PATH/SKILL.md"
    check "  Phase files"      "$SKILL_PATH/skill/"
    check "  Agents"           "$SKILL_PATH/agents/"
    check "  Slash commands"   "$CMDS_PATH/audit.md"
    check "  Path-scoped rules" "$RULES_PATH/audit.rules"
    check "  PoC templates"    "$TMPL_PATH/solana-auditor-shiba/"

    echo ""
    info "Installed at: $SKILL_PATH"
    info "Commands at:  $CMDS_PATH"
    info "Rules at:     $RULES_PATH"

    echo ""
    if [[ $fail_count -eq 0 ]]; then
        ok "Verification passed ($ok_count/$((ok_count + fail_count)) checks)"
        exit 0
    else
        err "Verification failed ($fail_count of $((ok_count + fail_count)) checks)"
        exit 1
    fi
}

# ── Help ───────────────────────────────────────────────────────────────────────
do_help() {
    banner
    cat << 'EOF'
Usage: install.sh [OPTIONS]

OPTIONS
  -y, --yes, --non-interactive
          Run without confirmation prompts (CI / automation).

  --dry-run
          Show what would be installed without modifying any files.

  --uninstall
          Remove all installed skill files from ~/.claude/.

  --verify
          Check whether the skill is currently installed and report status.

  -h, --help
          Show this help message.

ENVIRONMENT VARIABLES
  CLAUDE_SKILLS_DIR      Override skills install path  (default: ~/.claude/skills)
  CLAUDE_COMMANDS_DIR    Override commands install path (default: ~/.claude/commands)
  CLAUDE_RULES_DIR       Override rules install path    (default: ~/.claude/rules)
  CLAUDE_TEMPLATES_DIR   Override templates path        (default: ~/.claude/templates)

EXAMPLES
  # Interactive install
  ./install.sh

  # Non-interactive install (CI)
  ./install.sh --yes

  # Preview what would be installed
  ./install.sh --dry-run

  # Check if already installed
  ./install.sh --verify

  # Remove all skill files
  ./install.sh --uninstall

  # Install to custom Claude data dir
  CLAUDE_SKILLS_DIR=/opt/claude/skills ./install.sh --yes

EXIT CODES
  0  Success
  1  Error (missing sources, permission denied, verification failed)
  2  User cancelled
  3  Unsupported platform

SKILL CONTENTS
  skill/       — 7 phase/reference files (SKILL.md + 00-06-*.md)
  agents/      — 4 specialist agents (orchestrator, auditor, formal-verifier, report-writer)
  commands/    — 6 slash commands (/audit, /audit-quick, /audit-report, /audit-poc,
                  /audit-findings, /audit-resume)
  rules/       — 17 path-scoped audit.rules (auto-activate on Anchor/Token2022/CPI code)
  templates/   — 3 PoC templates (Anchor Rust, TypeScript, manual Markdown)
  tests/       — severity_counts.py (CVSS math verifier)
EOF
    exit 0
}

# ── Install ───────────────────────────────────────────────────────────────────
do_install() {
    banner
    verify_sources

    echo -e "${WHITE}Install summary:${NC}"
    echo "  Skill:      $SKILL_PATH"
    echo "  Commands:   $CMDS_PATH"
    echo "  Rules:      $RULES_PATH"
    echo "  Templates:  $TMPL_PATH/solana-auditor-shiba/"
    echo ""

    local n_skills=$(count_src "$SRC_SKILL" "*.md")
    local n_agents=$(count_src "$SRC_AGENTS" "*.md")
    local n_cmds=$(count_src "$SRC_CMDS" "*.md")
    local n_rules=$(count_src "$SRC_RULES" "*.rules")
    local n_tmpl=$(count_src "$SRC_TMPL" "*")

    echo "  Phase files:      $n_skills"
    echo "  Agent configs:    $n_agents"
    echo "  Slash commands:   $n_cmds"
    echo "  Path-scoped rules: $n_rules"
    echo "  PoC templates:    $n_tmpl"
    echo ""

    if [[ "$SKIP_CONFIRM" != "true" ]]; then
        read -p "Proceed with install? [Y/n] " -n 1 -r
        echo ""
        [[ $REPLY =~ ^[Nn]$ ]] && { echo -e "${YELLOW}[-] Cancelled.${NC}"; exit 2; }
    fi

    # ── Create destination dirs ──
    info "Creating destination directories..."
    run mkdir -p "$SKILLS_DIR" "$SKILL_PATH" "$CMDS_PATH" "$RULES_PATH" "$TMPL_PATH/solana-auditor-shiba"

    # ── Copy skill files ──
    info "Installing skill files..."
    run cp -r "$SRC_SKILL"/. "$SKILL_PATH/"
    ok "Skill installed ($(find "$SKILL_PATH" -name '*.md' | wc -l | tr -d ' ') markdown files)"

    # ── Copy agents ──
    if [[ -d "$SRC_AGENTS" ]]; then
        run mkdir -p "$SKILL_PATH/agents"
        run cp -r "$SRC_AGENTS"/. "$SKILL_PATH/agents/"
        ok "Agents installed ($n_agents configs)"
    fi

    # ── Copy slash commands ──
    if [[ -d "$SRC_CMDS" ]]; then
        run cp -f "$SRC_CMDS"/*.md "$CMDS_PATH/" 2>/dev/null || true
        ok "Slash commands installed ($n_cmds commands)"
    fi

    # ── Copy path-scoped rules ──
    if [[ -d "$SRC_RULES" ]]; then
        run cp -f "$SRC_RULES"/*.rules "$RULES_PATH/" 2>/dev/null || true
        ok "Path-scoped rules installed ($n_rules rule files)"
    fi

    # ── Copy PoC templates ──
    if [[ -d "$SRC_TMPL" ]]; then
        run cp -r "$SRC_TMPL"/. "$TMPL_PATH/solana-auditor-shiba/"
        ok "PoC templates installed ($n_tmpl templates)"
    fi

    # ── Integrity sanity check ──
    if [[ "$DRY_RUN" != "true" ]]; then
        if [[ ! -f "$SKILL_PATH/SKILL.md" ]]; then
            err "Integrity check failed — SKILL.md missing after copy!"
            exit 1
        fi
        if [[ ! -f "$RULES_PATH/audit.rules" ]]; then
            err "Integrity check failed — audit.rules missing after copy!"
            exit 1
        fi
    fi

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  ${WHITE}Install complete!${NC}                                                   ${GREEN}║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC}  Skill:    $SKILL_PATH${NC}"
    echo -e "${GREEN}║${NC}  Commands: $CMDS_PATH${NC}"
    echo -e "${GREEN}║${NC}  Rules:    $RULES_PATH${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${CYAN}Quick start:${NC}"
    echo -e "    /audit-quick <repo>   # Fast SAST triage (~5 min)"
    echo -e "    /audit <repo>        # Full 6-phase audit"
    echo -e "    /audit --help        # Full usage"
    echo ""
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
main() {
    if [[ "${HELP:-false}" == true ]]; then do_help; fi
    if [[ "$UNINSTALL" == true ]]; then do_uninstall; fi
    if [[ "$VERIFY_MODE" == true ]]; then do_verify; fi
    do_install
}

main
