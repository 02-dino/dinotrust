#!/usr/bin/env bash
# dinotrust uninstaller
# Removes the dinotrust block from your agent's config file.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}→${NC} $*"; }
success() { echo -e "${GREEN}✓${NC} $*"; }
warn()    { echo -e "${YELLOW}⚠${NC} $*"; }
error()   { echo -e "${RED}✗${NC} $*" >&2; exit 1; }

OPT_CONFIG_FILE=""
OPT_FORCE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) OPT_CONFIG_FILE="$2"; shift 2 ;;
    --force)  OPT_FORCE=true; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

echo ""
echo -e "${BOLD}🦖 dinotrust${NC} — Uninstaller"
echo "────────────────────────────────────────────────────────"
echo ""

if [[ -z "$OPT_CONFIG_FILE" ]]; then
  echo -e "${BOLD}?${NC} Path to the config file where dinotrust was installed:"
  read -rp "> " OPT_CONFIG_FILE
fi

[[ -z "$OPT_CONFIG_FILE" ]] && error "Config file path required."
[[ ! -f "$OPT_CONFIG_FILE" ]] && error "File not found: $OPT_CONFIG_FILE"

if ! grep -q "dinotrust begin" "$OPT_CONFIG_FILE"; then
  warn "No dinotrust block found in $OPT_CONFIG_FILE"
  exit 0
fi

if [[ "$OPT_FORCE" == "false" ]]; then
  warn "This will remove the dinotrust security block from: $OPT_CONFIG_FILE"
  echo ""
  read -rp "Continue? [y/N]: " CONFIRM
  [[ "$CONFIRM" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
fi

TMPFILE=$(mktemp)
awk '/# --- dinotrust begin/,/# --- dinotrust end ---/{next}1' "$OPT_CONFIG_FILE" > "$TMPFILE"
mv "$TMPFILE" "$OPT_CONFIG_FILE"

echo ""
success "dinotrust block removed from $OPT_CONFIG_FILE"
echo ""
echo "Restart your agent for changes to take effect."
echo ""
