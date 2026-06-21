#!/usr/bin/env bash
# dinotrust updater
# Pulls latest and re-runs install with --force.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

CYAN='\033[0;36m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}🦖 dinotrust${NC} — Updater"
echo "────────────────────────────────────────────────────────"
echo ""

cd "$REPO_DIR"

echo -e "${CYAN}→${NC} Pulling latest..."
git pull

echo -e "${CYAN}→${NC} Re-running installer with --force..."
echo ""
bash "$SCRIPT_DIR/install.sh" --force "$@"

echo -e "${GREEN}✓${NC} Update complete."
echo ""
