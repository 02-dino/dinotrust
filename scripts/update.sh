#!/usr/bin/env bash
# dinotrust updater
# Pulls latest and re-runs install with --force (idempotent: the AGENTS.md block
# is marker-scoped strip+re-inject, the enforce plugin files are cp-overwrite, and
# the openclaw.json plugin entry is a keyed merge — re-running never duplicates).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

echo ""
echo -e "${BOLD}🦖 dinotrust${NC} — Updater"
echo "────────────────────────────────────────────────────────"
echo ""

cd "$REPO_DIR"

PREV_VERSION="$(cat VERSION 2>/dev/null || echo unknown)"
echo -e "${CYAN}→${NC} Current: v${PREV_VERSION}"
echo -e "${CYAN}→${NC} Pulling latest..."
git pull
NEW_VERSION="$(cat VERSION 2>/dev/null || echo unknown)"

if [[ "$PREV_VERSION" == "$NEW_VERSION" ]]; then
  echo -e "${GREEN}✓${NC} Already on the latest (v${NEW_VERSION}). Re-running installer to reconcile state."
else
  echo -e "${GREEN}✓${NC} v${PREV_VERSION} → v${NEW_VERSION}"
fi
echo ""

# Surface breaking / behavioral changes for anyone crossing the 1.19.0 boundary,
# where dinotrust gained the enforce layer and narrowed supported runtimes.
_major_of() { echo "${1%%.*}"; }
_minor_of() { local v="${1#*.}"; echo "${v%%.*}"; }
if [[ "$PREV_VERSION" != "unknown" ]]; then
  _pm=$(_major_of "$PREV_VERSION"); _pn=$(_minor_of "$PREV_VERSION")
  if [[ "$_pm" -lt 1 || ( "$_pm" -eq 1 && "$_pn" -lt 19 ) ]]; then
    echo -e "${YELLOW}⚠  Crossing the v1.19.0 boundary — what changes on this update:${NC}"
    echo "   • NEW enforce layer: a code-level pre-tool hook now BLOCKS disallowed"
    echo "     tool calls (non-owner write/exec, secret reads) before they run —"
    echo "     not just the instruction layer. Installed automatically below."
    echo "   • Owner model: approval now fires ONLY on critical/irreversible actions"
    echo "     and is a courtesy confirmation that FAILS OPEN (never strands you),"
    echo "     instead of a blanket approval-before-every-write."
    echo "   • Supported runtimes narrowed to OpenClaw, Hermes, Claude Code, Codex CLI."
    echo "     Cursor/Windsurf/Continue.dev/Aider/Goose are no longer supported."
    echo "   • Observability audit layer now installs by default (was opt-in)."
    echo "   Opt out per-layer with --no-enforce / --no-observability."
    echo ""
  fi
fi

echo -e "${CYAN}→${NC} Re-running installer with --force..."
echo ""
bash "$SCRIPT_DIR/install.sh" --force "$@"

echo ""
echo -e "${GREEN}✓${NC} Update complete (v${NEW_VERSION})."
echo -e "${CYAN}→${NC} On OpenClaw, restart the gateway to load the enforce plugin: openclaw gateway restart"
echo ""
