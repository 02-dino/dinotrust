#!/usr/bin/env bash
# dinotrust manage-trusted — DEPRECATED SHIM.
#
# Trusted-tier management moved into the unified front door scripts/manage-access.sh.
# This shim forwards to it so existing commands keep working. Prefer:
#   bash scripts/manage-access.sh trusted <list|show|add|remove> ...
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo -e "\033[1;33m⚠\033[0m  manage-trusted.sh is deprecated; use: bash scripts/manage-access.sh trusted $*" >&2
exec bash "$SCRIPT_DIR/manage-access.sh" trusted "$@"
