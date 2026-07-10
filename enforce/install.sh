#!/usr/bin/env bash
# dinotrust enforce installer — installs the code-level enforcement hook.
# Supported platforms (real pre-tool veto only): openclaw, hermes, claude-code, codex-cli.
# Runtimes without a pre-tool veto are intentionally unsupported here.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENFORCE_DIR="$SCRIPT_DIR"

_print_oc_block() {
  cat <<EOF

  plugins.entries."dinotrust-enforce" = {
    "module": "${EXT_DIR:-<ext-dir>/index.ts}",
    "enabled": true,
    "hooks": { "allowConversationAccess": true },
    "config": {
      "agentFilter": "${OPT_AGENT_FILTER:-agent:<your-agent>}",
      "ownerIds": ${OWNER_ARR:-[]},
      "nonOwnerAllowedScripts": ${SCRIPTS_ARR:-[]},
      "enforce": ${OPT_ENFORCE:-true}
    }
  }

EOF
}
REPO_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="$(cat "$REPO_DIR/VERSION" 2>/dev/null || echo unknown)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}ℹ${NC}  $*"; }
success() { echo -e "${GREEN}✓${NC}  $*"; }
warn()    { echo -e "${YELLOW}⚠${NC}  $*"; }
err()     { echo -e "${RED}✗${NC}  $*" >&2; }

OPT_PLATFORM=""; OPT_OWNER_ID=""; OPT_ALLOW_SCRIPTS=""; OPT_CONFIG=""; OPT_AGENT_FILTER=""
OPT_ENFORCE="true"; OPT_DRY_RUN=false; OPT_FORCE=false; OPT_NONINTERACTIVE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)      OPT_PLATFORM="$2"; shift 2 ;;
    --owner-id)      OPT_OWNER_ID="$2"; shift 2 ;;
    --allow-scripts) OPT_ALLOW_SCRIPTS="$2"; shift 2 ;;
    --agent|--agent-filter) OPT_AGENT_FILTER="$2"; shift 2 ;;
    --config)        OPT_CONFIG="$2"; shift 2 ;;
    --workspace)     OPT_CONFIG="${2%/}"; shift 2 ;;
    --shadow|--dry-enforce) OPT_ENFORCE="false"; shift ;;
    --dry-run)       OPT_DRY_RUN=true; shift ;;
    --force)         OPT_FORCE=true; shift ;;
    --non-interactive|--yes|-y) OPT_NONINTERACTIVE=true; shift ;;
    -h|--help)
      cat <<EOF
dinotrust enforce installer (v$VERSION)

Usage: bash enforce/install.sh --platform <p> --owner-id <id> [options]

Supported platforms (real enforcement): openclaw | hermes | claude-code | codex-cli

Options:
  --owner-id IDS         Owner platform id(s), comma-separated (e.g. 111111,222222).
                         Every id gets identical owner tier (warn-only + critical-
                         approval); no primary/secondary. To add/remove owners
                         after install, re-run with --force and the FULL new list
                         (replaces the array, does not append) — or edit the config
                         directly and restart/reload. See enforce/README.md.
  --allow-scripts LIST   Non-owner exec allowlist (comma-separated script names,
                         e.g. exchange_data,semantic_search). Default: none.
  --config PATH          Runtime config file to register the hook in.
  --shadow               Install in dry-run enforce mode (log only, no block).
  --dry-run              Print actions, change nothing.
  --force                Overwrite existing hook config.
  --non-interactive      No prompts (requires --platform, --owner-id).
EOF
      exit 0 ;;
    *) err "Unknown option: $1"; exit 2 ;;
  esac
done

# ── Platform ──
SUPPORTED=(openclaw hermes claude-code codex-cli)
if [[ -z "$OPT_PLATFORM" ]]; then
  if [[ "$OPT_NONINTERACTIVE" == "true" ]]; then err "--platform required (one of: ${SUPPORTED[*]})"; exit 2; fi
  echo "Which runtime? (enforce is only supported on these — they have a real pre-tool veto)"
  echo "  1) openclaw   2) hermes   3) claude-code   4) codex-cli"
  read -rp "Enter number [1-4]: " n
  case "$n" in 1) OPT_PLATFORM=openclaw ;; 2) OPT_PLATFORM=hermes ;; 3) OPT_PLATFORM=claude-code ;; 4) OPT_PLATFORM=codex-cli ;; *) err "invalid"; exit 2 ;; esac
fi
if [[ ! " ${SUPPORTED[*]} " =~ " ${OPT_PLATFORM} " ]]; then
  err "Platform '$OPT_PLATFORM' does not support enforcement (no pre-tool veto)."
  err "Enforce supports only: ${SUPPORTED[*]}. For unsupported runtimes, dinotrust core"
  err "(instruction layer) is the most you can get — but it is compliance-dependent."
  exit 2
fi

if [[ -z "$OPT_OWNER_ID" && "$OPT_NONINTERACTIVE" != "true" ]]; then
  echo "Owner(s): platform id(s) that get warn-only + critical-approval access."
  echo "Everyone else falls under strict non-owner rules (read-only, allowlisted scripts only)."
  echo "Enter one or more, comma-separated (e.g. 111111,222222) — no primary/secondary,"
  echo "every id listed gets identical owner tier. You can add/remove owners later by"
  echo "re-running this installer with --force and the FULL new list (replaces, not appends),"
  echo "or by editing the config directly — see enforce/README.md 'Owners' section."
  read -rp "Owner id(s) (comma-separated): " OPT_OWNER_ID
fi
[[ -z "$OPT_OWNER_ID" ]] && { err "--owner-id required"; exit 2; }

# Build config JSON (owner ids + allow scripts). jq if present, else python3.
owner_json() { python3 -c "import json,sys; print(json.dumps([x.strip() for x in sys.argv[1].split(',') if x.strip()]))" "$1"; }
OWNER_ARR="$(owner_json "$OPT_OWNER_ID")"
SCRIPTS_ARR="$(owner_json "${OPT_ALLOW_SCRIPTS:-}")"

info "Platform:  $OPT_PLATFORM"
info "Owner ids: $OWNER_ARR"
info "Allow:     $SCRIPTS_ARR"
info "Enforce:   $OPT_ENFORCE $([[ "$OPT_ENFORCE" == "false" ]] && echo '(shadow/dry-run)')"
$OPT_DRY_RUN && { warn "--dry-run: no changes made."; }

case "$OPT_PLATFORM" in
  openclaw)
    # Install the managed-hook plugin into ~/.openclaw/extensions and write config.
    EXT_DIR="${HOME}/.openclaw/extensions/dinotrust-enforce"
    info "Plugin dir: $EXT_DIR"
    if ! $OPT_DRY_RUN; then
      mkdir -p "$EXT_DIR"
      cp "$ENFORCE_DIR/adapters/openclaw/handler.ts" "$EXT_DIR/index.ts"
      cp "$ENFORCE_DIR/adapters/openclaw/openclaw.plugin.json" "$EXT_DIR/openclaw.plugin.json"
      cp "$ENFORCE_DIR/adapters/openclaw/package.json" "$EXT_DIR/package.json" 2>/dev/null || true
      cp "$ENFORCE_DIR/adapters/openclaw/selftest.mjs" "$EXT_DIR/selftest.mjs" 2>/dev/null || true
      success "Plugin files installed."
    fi
    # Auto-merge the plugin entry into openclaw.json (idempotent, backed up).
    # Merge semantics: create plugins.entries.dinotrust-enforce if absent; if it
    # already exists (re-run / upgrade), update module + refresh config keys we
    # own (ownerIds/nonOwnerAllowedScripts/enforce/agentFilter) WITHOUT clobbering
    # other user-set keys or the rest of the file. Falls back to paste-instructions
    # only if python3 is missing or the file can't be parsed.
    OC_JSON="${HOME}/.openclaw/openclaw.json"
    AGENT_FILTER="${OPT_AGENT_FILTER:-}"
    if $OPT_DRY_RUN; then
      info "[dry-run] would merge plugins.entries.dinotrust-enforce into $OC_JSON"
    elif [[ -f "$OC_JSON" ]] && command -v python3 >/dev/null 2>&1; then
      cp "$OC_JSON" "${OC_JSON}.dinotrust-bak.$(date -u +%Y%m%d-%H%M%S)" 2>/dev/null || true
      if OC_JSON="$OC_JSON" MODULE="$EXT_DIR/index.ts" OWNERS="$OWNER_ARR" \
         SCRIPTS="$SCRIPTS_ARR" ENFORCE="$OPT_ENFORCE" AGENTF="$AGENT_FILTER" \
         python3 "$ENFORCE_DIR/adapters/openclaw/merge_config.py"; then
        success "Merged plugin config into $OC_JSON (backup written)."
        info "Restart the gateway to load it: openclaw gateway restart"
      else
        warn "Auto-merge failed — add this to openclaw.json plugins.entries manually:"
        _print_oc_block
      fi
    else
      warn "openclaw.json not found or python3 missing — add this to plugins.entries manually:"
      _print_oc_block
    fi
    ;;

  hermes|claude-code|codex-cli)
    # Install the pre_tool_call handler + write ~/.dinotrust/enforce.json.
    DT_DIR="${HOME}/.dinotrust"
    HANDLER_DST="$DT_DIR/enforce-pre_tool_call.py"
    CONF="$DT_DIR/enforce.json"
    if ! $OPT_DRY_RUN; then
      mkdir -p "$DT_DIR/logs"
      cp "$ENFORCE_DIR/adapters/pre_tool_call/handler.py" "$HANDLER_DST"
      chmod +x "$HANDLER_DST"
      python3 - "$CONF" "$OWNER_ARR" "$SCRIPTS_ARR" "$OPT_ENFORCE" <<'PY'
import json, sys
conf, owners, scripts, enforce = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
data = {"ownerIds": json.loads(owners),
        "nonOwnerAllowedScripts": json.loads(scripts),
        "enforce": enforce == "true"}
with open(conf, "w") as f:
    json.dump(data, f, indent=2)
PY
      chmod 600 "$CONF"
      success "Handler: $HANDLER_DST"
      success "Config:  $CONF"
    fi
    echo ""
    info "Register the hook in your runtime:"
    case "$OPT_PLATFORM" in
      hermes)
        cat <<EOF
  # cli-config.yaml
  hooks:
    pre_tool_call:
      - command: "python3 $HANDLER_DST"
EOF
        ;;
      claude-code)
        cat <<EOF
  # ~/.claude/settings.json
  "hooks": {
    "PreToolUse": [
      { "matcher": "*", "hooks": [ { "type": "command", "command": "python3 $HANDLER_DST" } ] }
    ]
  }
EOF
        ;;
      codex-cli)
        cat <<EOF
  # ~/.codex/config — pre_tool_call hook
  [hooks.pre_tool_call]
  command = "python3 $HANDLER_DST"
EOF
        ;;
    esac
    echo ""
    warn "The handler reads sender_id from the hook event. On single-user CLIs"
    warn "there is no inbound sender, so the owner id is a local identifier you set;"
    warn "non-owner gating only bites on multi-identity runtimes (Hermes channels)."
    ;;
esac

echo ""
success "dinotrust enforce ($OPT_PLATFORM) install steps emitted. Verify with the selftests in enforce/."
