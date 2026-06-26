#!/bin/bash
#
# solana-auditor-shiba Skill - Installer
# Installs the auditor-lifecycle skill for Solana AI Kit
#
# Usage: ./install.sh [-y|--yes]
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/skill"
AGENTS_DIR="$SCRIPT_DIR/agents"
COMMANDS_DIR="$SCRIPT_DIR/commands"
RULES_DIR="$SCRIPT_DIR/rules"
TEMPLATES_DIR="$SCRIPT_DIR/templates"
SCRIPTS_DIR="$SCRIPT_DIR/scripts"

SKILLS_DIR="$HOME/.claude/skills"
AUDIT_SKILL_PATH="$SKILLS_DIR/solana-auditor-shiba"
COMMANDS_PATH="$HOME/.claude/commands"
RULES_PATH="$HOME/.claude/rules"
TEMPLATES_PATH="$HOME/.claude/templates"
CLAUDE_MD_PATH="$HOME/.claude/CLAUDE.md"

SKIP_CONFIRM=false
EXT_MODE=false

print_banner() {
    local version="${1:-v1.5.0}"
    local mode_tag="${2:-Standard}"
    echo ""
    echo -e "${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC}  ${WHITE}Solana Auditor Shiba Skill for Claude Code${NC}              ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}║${NC}  ${CYAN}World-Class Security Auditor — ${version}${NC}"
    echo -e "${MAGENTA}║${NC}  ${CYAN}26 rules, 6 agents, 8 commands, pre-commit hook${NC}         ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}║${NC}  ${CYAN}Mode: ${mode_tag}${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_help() {
    echo "Solana Auditor Shiba Skill - Installer"
    echo ""
    echo "Usage: ./install.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -y, --yes       Skip confirmation prompt"
    echo "  --ext-mode      Install for AI Kit ext/ structure (thin symlinks)"
    echo "  -h, --help      Show this help message"
    echo ""
    echo "Modes:"
    echo "  Standard (default)  Installs to ~/.claude/skills/solana-auditor-shiba"
    echo "  --ext-mode          Creates symlinks in ./ext/solana-auditor-shiba/"
    echo ""
    echo "For AI Kit users, run:  ./install.sh --ext-mode"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -y|--yes)
            SKIP_CONFIRM=true
            shift
            ;;
        --ext-mode)
            EXT_MODE=true
            shift
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_help
            exit 1
            ;;
    esac
done

install_skill() {
    echo -e "${BLUE}[*] Creating skills directory...${NC}"
    mkdir -p "$SKILLS_DIR"

    echo -e "${BLUE}[*] Installing auditor skill to $AUDIT_SKILL_PATH${NC}"
    mkdir -p "$AUDIT_SKILL_PATH"

    # Copy skill files
    # CRITICAL: copy INTO $AUDIT_SKILL_PATH (not $SKILLS_DIR). The skill
    # is registered as "solana-auditor-shiba" by Claude Code based on the
    # directory name; copying into $SKILLS_DIR/skill/ would not be picked up.
    if [[ -d "$SOURCE_DIR" ]]; then
        cp -r "$SOURCE_DIR"/. "$AUDIT_SKILL_PATH/" 2>/dev/null || {
            echo -e "${RED}[!] Failed to copy skill files into $AUDIT_SKILL_PATH${NC}"
            exit 1
        }
        if [[ ! -f "$AUDIT_SKILL_PATH/SKILL.md" ]]; then
            echo -e "${RED}[!] Skill copy did not produce SKILL.md — aborting${NC}"
            exit 1
        fi
        echo -e "${GREEN}[+] Skill files copied to $AUDIT_SKILL_PATH${NC}"
    fi

    # Copy agents
    if [[ -d "$AGENTS_DIR" ]]; then
        mkdir -p "$AUDIT_SKILL_PATH/agents"
        cp -r "$AGENTS_DIR"/* "$AUDIT_SKILL_PATH/agents/" 2>/dev/null || true
        echo -e "${GREEN}[+] Agent configs copied${NC}"
    fi

    # Copy slash commands to ~/.claude/commands/
    if [[ -d "$COMMANDS_DIR" ]]; then
        mkdir -p "$COMMANDS_PATH"
        cp "$COMMANDS_DIR"/*.md "$COMMANDS_PATH/" 2>/dev/null || true
        echo -e "${GREEN}[+] Slash commands installed ($(ls "$COMMANDS_DIR"/*.md 2>/dev/null | wc -l | tr -d ' ') commands)${NC}"
    fi

    # Copy path-scoped rules to ~/.claude/rules/
    if [[ -d "$RULES_DIR" ]]; then
        mkdir -p "$RULES_PATH"
        cp "$RULES_DIR"/*.rules "$RULES_PATH/" 2>/dev/null || true
        echo -e "${GREEN}[+] Path-scoped rules installed${NC}"
    fi

    # Copy PoC templates to ~/.claude/templates/solana-auditor-shiba/
    if [[ -d "$TEMPLATES_DIR" ]]; then
        mkdir -p "$TEMPLATES_PATH/solana-auditor-shiba"
        cp "$TEMPLATES_DIR"/* "$TEMPLATES_PATH/solana-auditor-shiba/" 2>/dev/null || true
        echo -e "${GREEN}[+] PoC templates installed${NC}"
    fi

    # Copy helper scripts to $AUDIT_SKILL_PATH/scripts/
    if [[ -d "$SCRIPTS_DIR" ]]; then
        mkdir -p "$AUDIT_SKILL_PATH/scripts"
        cp "$SCRIPTS_DIR"/*.sh "$AUDIT_SKILL_PATH/scripts/" 2>/dev/null || true
        cp "$SCRIPTS_DIR"/*.py "$AUDIT_SKILL_PATH/scripts/" 2>/dev/null || true
        echo -e "${GREEN}[+] Helper scripts installed ($(ls "$SCRIPTS_DIR"/*.sh 2>/dev/null | wc -l | tr -d ' ') bash + $(ls "$SCRIPTS_DIR"/*.py 2>/dev/null | wc -l | tr -d ' ') python)${NC}"
        # Offer pre-commit hook installation
        if [[ -f "$SCRIPTS_DIR/pre-commit-audit.sh" ]]; then
            echo -e "${YELLOW}[!] Run '$AUDIT_SKILL_PATH/scripts/pre-commit-audit.sh --install' to enable the pre-commit hook${NC}"
        fi
    fi

    # Copy CLAUDE.md
    if [[ -f "$SCRIPT_DIR/CLAUDE.md" ]]; then
        cp "$SCRIPT_DIR/CLAUDE.md" "$AUDIT_SKILL_PATH/CLAUDE.md"
        echo -e "${GREEN}[+] CLAUDE.md installed${NC}"
    fi

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  ${WHITE}Install complete!${NC}                                                ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}Skill: $AUDIT_SKILL_PATH${NC}                          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}v1.5.0: 26 rules, 8 commands, pre-commit hook${NC}            ${GREEN}║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ── EXT MODE ──────────────────────────────────────────────────────────────────
# Installs the thin ext/ structure: symlinks into root, unique files copied.
# Target: ext/solana-auditor-shiba/ — ready to drop into ~/.claude/skills/ext/
install_ext_mode() {
    local EXT_DIR="$SCRIPT_DIR/ext/solana-auditor-shiba"

    echo -e "${BLUE}[*] Setting up AI Kit ext/ structure at $EXT_DIR${NC}"

    # Create ext/ directory layout
    mkdir -p "$EXT_DIR"/{skill,agents,commands,rules,scripts,templates}

    # Copy unique ext/ files
    if [[ -f "$SCRIPT_DIR/ext/solana-auditor-shiba/skill-registry.json" ]]; then
        echo -e "${GREEN}[+] skill-registry.json already present${NC}"
    else
        echo -e "${RED}[!] skill-registry.json not found — aborting ext-mode install${NC}"
        exit 1
    fi

    # Run symlink generator (generates all symlinks + ensures unique files exist)
    local SYMLINK_SCRIPT="$SCRIPTS_DIR/generate-ext-symlinks.sh"
    if [[ -x "$SYMLINK_SCRIPT" ]]; then
        bash "$SYMLINK_SCRIPT"
    else
        echo -e "${RED}[!] generate-ext-symlinks.sh not found at $SYMLINK_SCRIPT${NC}"
        exit 1
    fi

    # Copy ext/ README into place
    if [[ -f "$EXT_DIR/README.md" ]]; then
        echo -e "${GREEN}[+] README.md present${NC}"
    fi

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  ${WHITE}Ext-mode install complete!${NC}                                     ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}Ext dir: $EXT_DIR${NC}   ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${WHITE}Next:${NC} cp -r $EXT_DIR ~/.claude/skills/ext/                  ${GREEN}║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Main
if [[ "$EXT_MODE" == "true" ]]; then
    print_banner "v1.5.0" "AI Kit ext/"
    install_ext_mode
else
    print_banner
    if [[ "$SKIP_CONFIRM" != "true" ]]; then
        echo -e "${YELLOW}[!] This will install solana-auditor-shiba skill to:${NC}"
        echo "    $AUDIT_SKILL_PATH"
        echo ""
        read -p "Proceed? [y/N] " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${RED}[-] Install cancelled.${NC}"
            exit 0
        fi
    fi
    install_skill
fi