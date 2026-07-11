#!/usr/bin/env bash
# dinotrust manage-owner — DEPRECATED SHIM.
#
# Owner management moved into the unified front door scripts/manage-access.sh.
# This shim forwards to it so existing commands keep working. Prefer:
#   bash scripts/manage-access.sh owner <list|add|remove> ...
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo -e "\033[1;33m⚠\033[0m  manage-owner.sh is deprecated; use: bash scripts/manage-access.sh owner $*" >&2
exec bash "$SCRIPT_DIR/manage-access.sh" owner "$@"
