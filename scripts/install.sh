#!/usr/bin/env bash
# dinotrust installer
# Injects security rules into your AI agent's config file.
# Usage: bash scripts/install.sh [options]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
RULES_TEMPLATE="$REPO_DIR/security_rules.md"
VERSION_FILE="$REPO_DIR/VERSION"
VERSION="$(cat "$VERSION_FILE" 2>/dev/null || echo "unknown")"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Args ──────────────────────────────────────────────────────────────────────
OPT_PLATFORM=""
OPT_OWNER_ID=""
OPT_PROFILE=""
OPT_GLOBAL=false
OPT_FORCE=false
OPT_DRY_RUN=false
OPT_PROTECTED_FILES=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)   OPT_PLATFORM="$2"; shift 2 ;;
    --owner-id)   OPT_OWNER_ID="$2"; shift 2 ;;
    --profile)    OPT_PROFILE="$2"; shift 2 ;;
    --global)     OPT_GLOBAL=true; shift ;;
    --force)      OPT_FORCE=true; shift ;;
    --dry-run)    OPT_DRY_RUN=true; shift ;;
    --protected)  OPT_PROTECTED_FILES="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: bash scripts/install.sh [options]"
      echo ""
      echo "Options:"
      echo "  --platform NAME     Platform: openclaw|hermes|claude-code|codex-cli|goose|cursor|windsurf|continue|aider"
      echo "  --owner-id ID       Your platform user ID"
      echo "  --profile NAME      Preset: private-assistant|market-analyst|custom"
      echo "  --global            Inject into global config (where supported)"
      echo "  --force             Overwrite existing dinotrust block"
      echo "  --dry-run           Preview injection, no changes"
      echo "  --protected FILES   Comma-separated extra protected files"
      exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}→${NC} $*"; }
success() { echo -e "${GREEN}✓${NC} $*"; }
warn()    { echo -e "${YELLOW}⚠${NC} $*"; }
error()   { echo -e "${RED}✗${NC} $*" >&2; exit 1; }
ask()     { echo -e "${BOLD}?${NC} $*"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}🦖 dinotrust v${VERSION}${NC} — Access control & prompt-injection defense for AI agents"
echo "────────────────────────────────────────────────────────"
echo ""

# ── Step 1: Platform ──────────────────────────────────────────────────────────
PLATFORMS=(openclaw hermes claude-code codex-cli goose cursor windsurf continue aider)

if [[ -z "$OPT_PLATFORM" ]]; then
  # Auto-detect
  DETECTED=""
  [[ -f "$HOME/.openclaw/openclaw.json" ]] && DETECTED="openclaw"
  [[ -f "$HOME/.claude/CLAUDE.md" ]] && DETECTED="${DETECTED:+$DETECTED|}claude-code"
  [[ -f "$HOME/.codex/AGENTS.md" ]] && DETECTED="${DETECTED:+$DETECTED|}codex-cli"
  [[ -f "$HOME/.hermes/SOUL.md" ]] && DETECTED="${DETECTED:+$DETECTED|}hermes"

  if [[ -n "$DETECTED" ]]; then
    info "Detected: $DETECTED"
  fi

  echo ""
  ask "Which platform are you installing for?"
  echo "  1) OpenClaw"
  echo "  2) Hermes"
  echo "  3) Claude Code"
  echo "  4) OpenAI Codex CLI"
  echo "  5) Goose"
  echo "  6) Cursor"
  echo "  7) Windsurf"
  echo "  8) Continue.dev"
  echo "  9) Aider"
  echo ""
  read -rp "Enter number [1-9]: " PLATFORM_NUM
  case "$PLATFORM_NUM" in
    1) OPT_PLATFORM="openclaw" ;;
    2) OPT_PLATFORM="hermes" ;;
    3) OPT_PLATFORM="claude-code" ;;
    4) OPT_PLATFORM="codex-cli" ;;
    5) OPT_PLATFORM="goose" ;;
    6) OPT_PLATFORM="cursor" ;;
    7) OPT_PLATFORM="windsurf" ;;
    8) OPT_PLATFORM="continue" ;;
    9) OPT_PLATFORM="aider" ;;
    *) error "Invalid selection." ;;
  esac
fi

info "Platform: $OPT_PLATFORM"

# ── Step 2: Config file path ──────────────────────────────────────────────────
resolve_config_file() {
  local platform="$1"
  local global="$2"

  case "$platform" in
    openclaw)
      # Find workspace AGENTS.md
      if [[ -n "${OPENCLAW_WORKSPACE:-}" ]]; then
        echo "$OPENCLAW_WORKSPACE/AGENTS.md"
      else
        local workspaces
        workspaces=$(ls -d "$HOME/.openclaw/workspace-"*/ 2>/dev/null || true)
        local count
        count=$(echo "$workspaces" | grep -c . || true)
        if [[ $count -eq 1 ]]; then
          echo "${workspaces%$'\n'}/AGENTS.md"
        else
          echo "__ask__"
        fi
      fi
      ;;
    hermes)
      echo "$HOME/.hermes/SOUL.md" ;;
    claude-code)
      if [[ "$global" == "true" ]]; then
        echo "$HOME/.claude/CLAUDE.md"
      else
        echo "./CLAUDE.md"
      fi ;;
    codex-cli)
      if [[ "$global" == "true" ]]; then
        echo "$HOME/.codex/AGENTS.md"
      else
        echo "./AGENTS.md"
      fi ;;
    goose)
      echo "./AGENTS.md" ;;
    cursor)
      echo ".cursor/rules/dinotrust.mdc" ;;
    windsurf)
      if [[ "$global" == "true" ]]; then
        echo "global_rules.md"
      else
        echo ".windsurfrules"
      fi ;;
    continue)
      echo ".continuerules" ;;
    aider)
      echo "CONVENTIONS.md" ;;
    *)
      echo "__ask__" ;;
  esac
}

CONFIG_FILE=$(resolve_config_file "$OPT_PLATFORM" "$OPT_GLOBAL")

if [[ "$CONFIG_FILE" == "__ask__" ]]; then
  echo ""
  ask "Path to your agent's config file:"
  read -rp "> " CONFIG_FILE
fi

# Handle OpenClaw multi-workspace
if [[ "$OPT_PLATFORM" == "openclaw" && "$CONFIG_FILE" == "__ask__" ]]; then
  echo ""
  ask "Path to your OpenClaw workspace AGENTS.md:"
  read -rp "> " CONFIG_FILE
fi

info "Config file: $CONFIG_FILE"

# ── Step 3: Owner ID ──────────────────────────────────────────────────────────
if [[ -z "$OPT_OWNER_ID" ]]; then
  echo ""
  ask "Your platform user ID (numeric):"
  echo "  Telegram: Settings → Advanced → copy numeric ID"
  echo "  Discord:  Developer Mode → right-click username → Copy ID"
  echo "  Other:    Check your platform's user metadata"
  echo ""
  read -rp "Owner ID: " OPT_OWNER_ID
fi

[[ -z "$OPT_OWNER_ID" ]] && error "Owner ID is required."
info "Owner ID: $OPT_OWNER_ID"

# ── Step 4: Profile preset ────────────────────────────────────────────────────
if [[ -z "$OPT_PROFILE" ]]; then
  echo ""
  ask "Agent profile preset:"
  echo "  1) private-assistant   — personal assistant; non-owners get nothing"
  echo "  2) market-analyst      — market analysis bot; non-owners get data tools only"
  echo "  3) custom              — you define allowed actions manually"
  echo ""
  read -rp "Enter number [1-3]: " PROFILE_NUM
  case "$PROFILE_NUM" in
    1) OPT_PROFILE="private-assistant" ;;
    2) OPT_PROFILE="market-analyst" ;;
    3) OPT_PROFILE="custom" ;;
    *) error "Invalid selection." ;;
  esac
fi

info "Profile: $OPT_PROFILE"

# ── Step 5: Protected files ───────────────────────────────────────────────────
# Auto-detect common sensitive files
AUTO_PROTECTED=("AGENTS.md" ".env" "credentials" "secrets" "internal_configs" "owner_metadata")

# Platform-specific additions
case "$OPT_PLATFORM" in
  openclaw) AUTO_PROTECTED+=("openclaw.json") ;;
  claude-code) AUTO_PROTECTED+=("CLAUDE.md") ;;
  cursor) AUTO_PROTECTED+=(".cursor/rules/") ;;
esac

if [[ -z "$OPT_PROTECTED_FILES" ]]; then
  echo ""
  ask "Additional files/folders to protect? (comma-separated, or Enter to skip)"
  echo "  Auto-protected: ${AUTO_PROTECTED[*]}"
  echo ""
  read -rp "Extra protected: " EXTRA_PROTECTED
  OPT_PROTECTED_FILES="$EXTRA_PROTECTED"
fi

# Build protected resources YAML block
PROTECTED_YAML=""
for f in "${AUTO_PROTECTED[@]}"; do
  PROTECTED_YAML+="    - $f"$'\n'
done
if [[ -n "$OPT_PROTECTED_FILES" ]]; then
  IFS=',' read -ra EXTRA_FILES <<< "$OPT_PROTECTED_FILES"
  for f in "${EXTRA_FILES[@]}"; do
    f="${f// /}"  # trim spaces
    [[ -n "$f" ]] && PROTECTED_YAML+="    - $f"$'\n'
  done
fi

# ── Step 6: Profile-specific config ──────────────────────────────────────────
case "$OPT_PROFILE" in
  private-assistant)
    DEFLECTION_MSG="This assistant is private"
    ALLOWED_ACTIONS="      - none"
    ;;
  market-analyst)
    DEFLECTION_MSG="I use various data sources for market analysis"
    ALLOWED_ACTIONS="      - market_data_queries: true
      - web_search: true
      - memory_search: true"
    ;;
  custom)
    echo ""
    ask "Deflection message for non-owners (what the agent says when refusing):"
    read -rp "> " DEFLECTION_MSG
    echo ""
    ask "What are non-owners allowed to do? (describe briefly, or 'none')"
    read -rp "> " ALLOWED_RAW
    ALLOWED_ACTIONS="      - $ALLOWED_RAW"
    ;;
esac

# ── Step 7: Build injection block ─────────────────────────────────────────────
# Read template and fill placeholders
RULES_CONTENT=$(cat "$RULES_TEMPLATE")
RULES_CONTENT="${RULES_CONTENT//DINOTRUST_OWNER_ID/$OPT_OWNER_ID}"
RULES_CONTENT="${RULES_CONTENT//DINOTRUST_DEFLECTION_MESSAGE/$DEFLECTION_MSG}"
RULES_CONTENT="${RULES_CONTENT//DINOTRUST_PROTECTED_RESOURCES/$PROTECTED_YAML}"
RULES_CONTENT="${RULES_CONTENT//DINOTRUST_ALLOWED_ACTIONS/$ALLOWED_ACTIONS}"

INJECTION_BLOCK="# --- dinotrust begin (v${VERSION}) ---
# Platform: ${OPT_PLATFORM} | Profile: ${OPT_PROFILE} | Installed: $(date -u +%Y-%m-%d)
${RULES_CONTENT}
# --- dinotrust end ---"

# ── Step 8: Dry run or apply ──────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────────────────"

if [[ "$OPT_DRY_RUN" == "true" ]]; then
  warn "DRY RUN — no changes made"
  echo ""
  echo "Would inject into: $CONFIG_FILE"
  echo ""
  echo "$INJECTION_BLOCK"
  echo ""
  exit 0
fi

# Check for existing block
if grep -q "dinotrust begin" "$CONFIG_FILE" 2>/dev/null; then
  if [[ "$OPT_FORCE" == "false" ]]; then
    warn "dinotrust block already exists in $CONFIG_FILE"
    echo ""
    read -rp "Overwrite? [y/N]: " CONFIRM_OVERWRITE
    [[ "$CONFIRM_OVERWRITE" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
  fi
  # Remove existing block
  info "Removing existing dinotrust block..."
  TMPFILE=$(mktemp)
  awk '/# --- dinotrust begin/,/# --- dinotrust end ---/{next}1' "$CONFIG_FILE" > "$TMPFILE"
  mv "$TMPFILE" "$CONFIG_FILE"
fi

# Create parent dirs if needed
mkdir -p "$(dirname "$CONFIG_FILE")"

# Append injection
echo "" >> "$CONFIG_FILE"
echo "$INJECTION_BLOCK" >> "$CONFIG_FILE"

# Aider: also patch .aider.conf.yml
if [[ "$OPT_PLATFORM" == "aider" ]]; then
  AIDER_CONF=".aider.conf.yml"
  if [[ -f "$AIDER_CONF" ]]; then
    if ! grep -q "CONVENTIONS.md" "$AIDER_CONF"; then
      echo "read: CONVENTIONS.md" >> "$AIDER_CONF"
      info "Patched $AIDER_CONF to read CONVENTIONS.md"
    fi
  else
    echo "read: CONVENTIONS.md" > "$AIDER_CONF"
    info "Created $AIDER_CONF"
  fi
fi

# Cursor: add frontmatter
if [[ "$OPT_PLATFORM" == "cursor" ]]; then
  CURSOR_FRONTMATTER="---
description: dinotrust security rules
alwaysApply: true
---

"
  TMPFILE=$(mktemp)
  echo "$CURSOR_FRONTMATTER" > "$TMPFILE"
  cat "$CONFIG_FILE" >> "$TMPFILE"
  mv "$TMPFILE" "$CONFIG_FILE"
fi

echo ""
success "dinotrust v${VERSION} installed"
echo ""
echo "  Platform : $OPT_PLATFORM"
echo "  Config   : $CONFIG_FILE"
echo "  Owner ID : $OPT_OWNER_ID"
echo "  Profile  : $OPT_PROFILE"
echo ""
echo "Next: restart your agent for the rules to take effect."
echo ""
echo "Verify:"
echo "  grep 'dinotrust begin' \"$CONFIG_FILE\""
echo ""
