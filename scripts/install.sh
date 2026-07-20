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
OPT_CONFIG=""
OPT_NONINTERACTIVE=false
# Observability chaining (OpenClaw only). After core installs, optionally chain
# observability/install.sh. Opt-out by default for humans; never forced in
# headless (it needs a leak-sensitive --report-target we must not guess).
OPT_NO_OBSERVABILITY=false   # --no-observability: skip the chain entirely
OPT_WITH_OBSERVABILITY=false # --with-observability: force the chain (e.g. headless)
# Enforce layer (code-level pre-tool veto). Default-on for platforms that support
# it (openclaw|hermes|claude-code|codex-cli). --no-enforce opts out.
OPT_NO_ENFORCE=false
OPT_ENFORCE_SHADOW=false     # --enforce-shadow: install enforce in dry-run (log, no block)
OPT_ALLOW_SCRIPTS=""         # --allow-scripts: non-owner exec allowlist for enforce
OPT_AGENT=""                 # --agent: agentFilter substring for enforce (empty = all agents)
OPT_REPORT_TARGET=""         # forwarded to observability/install.sh
OPT_REPORT_CHANNEL=""        # delivery channel (telegram|discord|slack|file)
OPT_REPORT_THREAD=""         # thread/topic ID for forum channels

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)   OPT_PLATFORM="$2"; shift 2 ;;
    --owner-id)   OPT_OWNER_ID="$2"; shift 2 ;;
    --profile)    OPT_PROFILE="$2"; shift 2 ;;
    --global)     OPT_GLOBAL=true; shift ;;
    --force)      OPT_FORCE=true; shift ;;
    --dry-run)    OPT_DRY_RUN=true; shift ;;
    --protected)  OPT_PROTECTED_FILES="$2"; shift 2 ;;
    # --config and --workspace both name the exact target. --config takes the
    # file path as-is; --workspace is sugar for <dir>/AGENTS.md (OpenClaw style).
    --config)     OPT_CONFIG="$2"; shift 2 ;;
    --workspace)  OPT_CONFIG="${2%/}/AGENTS.md"; shift 2 ;;
    --no-observability)   OPT_NO_OBSERVABILITY=true; shift ;;
    --with-observability) OPT_WITH_OBSERVABILITY=true; shift ;;
    --no-enforce)         OPT_NO_ENFORCE=true; shift ;;
    --enforce-shadow)     OPT_ENFORCE_SHADOW=true; shift ;;
    --allow-scripts)      OPT_ALLOW_SCRIPTS="$2"; shift 2 ;;
    --agent)              OPT_AGENT="$2"; shift 2 ;;
    --report-target)      OPT_REPORT_TARGET="$2"; shift 2 ;;
    --report-channel)     OPT_REPORT_CHANNEL="$2"; shift 2 ;;
    --report-thread)      OPT_REPORT_THREAD="$2"; shift 2 ;;
    --non-interactive|--yes|-y) OPT_NONINTERACTIVE=true; shift ;;
    -h|--help)
      echo "Usage: bash scripts/install.sh [options]"
      echo ""
      echo "Options:"
      echo "  --platform NAME     Runtime: openclaw|hermes|claude-code|codex-cli (only these support enforcement)"
      echo "  --owner-id IDS      Your platform user ID(s); comma-separated for multiple owners."
      echo "                      Scope an owner to specific platform(s) with id@platform"
      echo "                      (e.g. 123456789@telegram, or 123@telegram+discord). A bare"
      echo "                      id is owner on any platform."
      echo "  --profile NAME      Preset: private-assistant|market-analyst|custom"
      echo "  --config PATH       Exact target config file (bypasses workspace auto-detect/prompt)"
      echo "  --workspace DIR     Target an OpenClaw workspace dir (uses DIR/AGENTS.md)"
      echo "  --global            Inject into global config (where supported)"
      echo "  --force             Overwrite existing dinotrust block without asking"
      echo "  --non-interactive   Never prompt; error (with the flag to pass) if input is missing. Alias: --yes, -y"
      echo "  --dry-run           Preview injection, no changes"
      echo "  --protected FILES   Comma-separated extra protected files"
      echo ""
      echo "Observability (audit layer — installed BY DEFAULT, all platforms):"
      echo "  Installed as part of the main install (local audit log). A report target"
      echo "  adds remote digest delivery; it is optional and never guessed."
      echo "  T1 (OpenClaw, Hermes): hook-based audit.  T3 (claude-code, codex): self-audit."
      echo "  --no-observability     Opt out of the audit layer entirely."
      echo "  --with-observability   Force-chain (default-on anyway; kept for clarity)."
      echo "  --report-target ID     Digest destination (chat/channel ID). Optional."
      echo "  --report-channel NAME  Delivery channel: telegram|discord|slack|file."
      echo ""
      echo "Enforce (code-level pre-tool veto — installed BY DEFAULT on supported runtimes):"
      echo "  Supported: openclaw | hermes | claude-code | codex-cli (they have a real"
      echo "  pre-tool veto). Unsupported runtimes get the instruction layer only."
      echo "  --no-enforce           Opt out; instruction layer only (compliance-dependent)."
      echo "  --enforce-shadow       Install enforce in dry-run (log, no block) to shadow-test."
      echo "  --allow-scripts LIST   Non-owner exec allowlist, comma-separated (e.g."
      echo "                         exchange_data,semantic_search). Default: none."
      echo ""
      echo "Headless/agent use: pass --platform, --owner-id, --profile, and --config (or"
      echo "--workspace), plus --non-interactive and --force. Missing input then fails fast"
      echo "with the exact flag to add, instead of hanging on a prompt. Observability and"
      echo "enforce are installed by default (opt out with --no-observability / --no-enforce)."
      exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# If stdin is not a TTY, enable non-interactive automatically so the script
# fails fast instead of blocking forever on a read with no terminal.
if [[ ! -t 0 ]]; then
  OPT_NONINTERACTIVE=true
fi

# need_input: in non-interactive mode, abort with the flag the caller should
# pass instead of prompting. Used to guard every interactive read below.
# $3 = source hint for an autonomous caller (e.g. an installing agent):
#   "self"  -> the agent can resolve this from its own host/workspace context
#             and retry; no human needed.
#   "owner" -> identity or security policy the agent MUST NOT guess; pause and
#             ask the human owner for the value, then retry.
need_input() {
  # $1 = human description, $2 = flag hint, $3 = self|owner (default: self)
  if [[ "$OPT_NONINTERACTIVE" == "true" ]]; then
    local _src="${3:-self}"
    local _guide
    local _hint=""
    if [[ "$_src" == "owner" ]]; then
      _hint=$(id_discovery_hint "$OPT_PLATFORM" owner)
      _guide="ACTION[agent]: ask the OWNER for this (identity/security policy — do not guess). Hint: $_hint. Then re-run with the flag."
    else
      _guide="ACTION[agent]: resolve this from your own host/workspace context and re-run with the flag."
    fi
    error "Missing required input: $1. Pass $2 (running non-interactively / no TTY). $_guide"
  fi
}

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
# Supported = runtimes with a real pre-tool veto (the enforce hook point).
# Others get instruction-only, which is compliance-dependent, so we do not offer
# them here. See README "Supported runtimes".
PLATFORMS=(openclaw hermes claude-code codex-cli)
UNSUPPORTED=(goose cursor windsurf continue aider)

if [[ -z "$OPT_PLATFORM" ]]; then
  need_input "platform" "--platform openclaw|hermes|claude-code|codex-cli" self
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
  ask "Which runtime are you installing for? (only these support enforcement)"
  echo "  1) OpenClaw"
  echo "  2) Hermes"
  echo "  3) Claude Code"
  echo "  4) OpenAI Codex CLI"
  echo ""
  read -rp "Enter number [1-4]: " PLATFORM_NUM
  case "$PLATFORM_NUM" in
    1) OPT_PLATFORM="openclaw" ;;
    2) OPT_PLATFORM="hermes" ;;
    3) OPT_PLATFORM="claude-code" ;;
    4) OPT_PLATFORM="codex-cli" ;;
    *) error "Invalid selection." ;;
  esac
fi

# Guard: reject unsupported runtimes (passed via --platform) with the rationale.
if [[ " ${UNSUPPORTED[*]} " =~ " ${OPT_PLATFORM} " ]]; then
  echo -e "${RED}✗${NC} '$OPT_PLATFORM' is not supported: it has no pre-tool veto, so dinotrust could" >&2
  echo -e "${RED}✗${NC} only inject the instruction layer — which a non-compliant agent can ignore," >&2
  echo -e "${RED}✗${NC} with no independent audit to catch it. That's a false sense of security, not" >&2
  echo -e "${RED}✗${NC} the posture dinotrust promises. Supported runtimes: ${PLATFORMS[*]}." >&2
  echo -e "${RED}✗${NC} For '$OPT_PLATFORM', a tool built for its native permission model serves you better." >&2
  exit 2
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
        elif [[ $count -gt 1 ]]; then
          # Multiple workspaces — let the caller present a numbered menu.
          echo "__menu__"
        else
          # Zero workspaces found — signal so the caller can say so explicitly.
          echo "__none__"
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

# Explicit --config/--workspace wins over all auto-detection and prompts.
if [[ -n "$OPT_CONFIG" ]]; then
  CONFIG_FILE="$OPT_CONFIG"
else
  CONFIG_FILE=$(resolve_config_file "$OPT_PLATFORM" "$OPT_GLOBAL")
fi

# OpenClaw: multiple workspaces found — present a numbered menu of what we detected.
if [[ "$CONFIG_FILE" == "__menu__" ]]; then
  need_input "which OpenClaw workspace to target (multiple detected)" "--config PATH or --workspace DIR" self
  echo ""
  ask "Multiple OpenClaw workspaces detected — pick one:"
  mapfile -t _WS_LIST < <(ls -d "$HOME/.openclaw/workspace-"*/ 2>/dev/null || true)
  _i=1
  for _ws in "${_WS_LIST[@]}"; do
    echo "  $_i) ${_ws%/}"
    _i=$((_i + 1))
  done
  echo "  0) Enter a custom path"
  echo ""
  read -rp "Enter number [0-$(( ${#_WS_LIST[@]} ))]: " _WS_NUM
  if [[ "$_WS_NUM" == "0" ]]; then
    ask "Path to your OpenClaw workspace AGENTS.md:"
    read -rp "> " CONFIG_FILE
  elif [[ "$_WS_NUM" =~ ^[0-9]+$ ]] && (( _WS_NUM >= 1 && _WS_NUM <= ${#_WS_LIST[@]} )); then
    CONFIG_FILE="${_WS_LIST[$((_WS_NUM - 1))]%/}/AGENTS.md"
  else
    error "Invalid selection."
  fi
fi

# OpenClaw: zero workspaces found — say so, then ask.
if [[ "$CONFIG_FILE" == "__none__" ]]; then
  need_input "target config path (no OpenClaw workspace detected)" "--config PATH or --workspace DIR" self
  echo ""
  warn "No OpenClaw workspaces detected under $HOME/.openclaw/workspace-*/"
  ask "Path to your OpenClaw workspace AGENTS.md:"
  read -rp "> " CONFIG_FILE
fi

# Generic fallback for non-OpenClaw platforms that returned __ask__.
if [[ "$CONFIG_FILE" == "__ask__" ]]; then
  need_input "target config path" "--config PATH" self
  echo ""
  ask "Path to your agent's config file:"
  read -rp "> " CONFIG_FILE
fi

info "Config file: $CONFIG_FILE"

# Per-platform ID discovery instructions for headless AI agents.
# Returns a string the agent can surface to the human owner, or use to auto-resolve.
id_discovery_hint() {
  local _platform="$1"
  local _what="$2"  # "owner" or "target"
  case "$_platform" in
    openclaw|telegram)
      if [[ "$_what" == "owner" ]]; then
        echo "Telegram: send /start to @userinfobot (it replies with your numeric ID), or use @RawDataBot"
      else
        echo "Telegram: your chat ID is the number @userinfobot replies with, or the channel ID (starts with -100)"
      fi
      ;;
    discord)
      if [[ "$_what" == "owner" ]]; then
        echo "Discord: enable Developer Mode (Settings → Advanced), then right-click your username anywhere → Copy ID"
      else
        echo "Discord: right-click the channel/server → Copy ID. For DMs, use your own user ID."
      fi
      ;;
    slack)
      if [[ "$_what" == "owner" ]]; then
        echo "Slack: open your profile → click 'More' → Copy member ID (starts with U)"
      else
        echo "Slack: right-click the channel → Copy link → extract the channel ID (starts with C)"
      fi
      ;;
    hermes)
      echo "Hermes: check your platform's user metadata or auth.test response for the verified user id"
      ;;
    claude-code|codex-cli)
      if [[ "$_what" == "owner" ]]; then
        echo "CLI agent: your owner ID is typically your platform user ID (check the agent's config or the platform's account settings)"
      else
        echo "CLI agent: for report delivery, use a Telegram/Discord/Slack ID (see --report-channel) or a webhook URL"
      fi
      ;;
    *)
      echo "Check your platform's user settings or developer tools for the verified user ID"
      ;;
  esac
}
if [[ -z "$OPT_OWNER_ID" ]]; then
  need_input "owner ID(s)" "--owner-id ID[,ID...]" owner
  echo ""
  ask "Your platform user ID(s) (numeric/UUID; comma-separated for multiple owners):"
  echo "  $(id_discovery_hint "$OPT_PLATFORM" owner)"
  echo "  Multiple owners: e.g. 123456789,987654321 (each is a full owner)"
  echo ""
  read -rp "Owner ID(s): " OPT_OWNER_ID
fi

[[ -z "$OPT_OWNER_ID" ]] && error "At least one owner ID is required."

# Parse comma-separated owner IDs into a YAML inline list.
# Each entry may be a bare id (e.g. 123456789) → owner on ANY platform, OR a
# platform-scoped id of the form id@platform[+platform2...] (e.g.
# 123456789@telegram) → owner ONLY on the listed platform(s). Scoped entries
# render as an inline object {id: X, platforms: [a, b]}; bare entries render as
# the bare id (fully backward-compatible).
OWNER_IDS_YAML="["
OWNER_ID_COUNT=0
IFS=',' read -ra _OWNER_IDS <<< "$OPT_OWNER_ID"
for _entry in "${_OWNER_IDS[@]}"; do
  _entry="${_entry// /}"   # trim spaces
  [[ -z "$_entry" ]] && continue
  if [[ "$_entry" == *"@"* ]]; then
    _oid="${_entry%%@*}"
    _plats="${_entry#*@}"
  else
    _oid="$_entry"
    _plats=""
  fi
  # Shape sanity check: most platform IDs are numeric (Telegram/Discord) or
  # UUID-ish (some platforms). Warn — never block — on anything else, since a
  # garbage/typo'd owner id silently grants no one (or the wrong one) access.
  if [[ ! "$_oid" =~ ^[0-9]+$ && ! "$_oid" =~ ^[0-9a-fA-F-]{16,}$ ]]; then
    warn "Owner ID '$_oid' doesn't look numeric or UUID-like — double-check it matches your platform's user ID, or the agent won't recognize you as owner."
  fi
  if [[ $OWNER_ID_COUNT -gt 0 ]]; then OWNER_IDS_YAML+=", "; fi
  if [[ -n "$_plats" ]]; then
    _plats_yaml="["
    _pc=0
    IFS='+' read -ra _PLAT_ARR <<< "$_plats"
    for _p in "${_PLAT_ARR[@]}"; do
      _p="${_p// /}"
      [[ -z "$_p" ]] && continue
      if [[ $_pc -gt 0 ]]; then _plats_yaml+=", "; fi
      _plats_yaml+="$_p"
      _pc=$((_pc + 1))
    done
    _plats_yaml+="]"
    OWNER_IDS_YAML+="{id: $_oid, platforms: $_plats_yaml}"
    info "Owner '$_oid' scoped to platform(s): $_plats_yaml"
  else
    OWNER_IDS_YAML+="$_oid"
  fi
  OWNER_ID_COUNT=$((OWNER_ID_COUNT + 1))
done
OWNER_IDS_YAML+="]"
[[ $OWNER_ID_COUNT -eq 0 ]] && error "At least one valid owner ID is required."
if [[ $OWNER_ID_COUNT -eq 1 ]]; then
  info "Owner ID: ${OWNER_IDS_YAML}"
else
  info "Owner IDs ($OWNER_ID_COUNT owners): ${OWNER_IDS_YAML}"
  warn "Multiple owners = multiple full-access accounts. Each is a trust surface; if any one is compromised, the agent is fully exposed."
fi

# ── Step 4: Profile preset ────────────────────────────────────────────────────
if [[ -z "$OPT_PROFILE" ]]; then
  need_input "profile preset" "--profile private-assistant|market-analyst|custom" owner
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

# Optional input: in non-interactive mode just skip (no extra protected files)
# rather than erroring — the auto-protected set already covers the essentials.
if [[ -z "$OPT_PROTECTED_FILES" && "$OPT_NONINTERACTIVE" != "true" ]]; then
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
    need_input "custom profile details (deflection message + allowed actions)" "a preset --profile private-assistant|market-analyst (custom needs interactive input)" owner
    echo ""
    ask "Deflection message for non-owners (what the agent says when refusing):"
    read -rp "> " DEFLECTION_MSG
    echo ""
    ask "What are non-owners allowed to do? (comma-separated for multiple, or 'none')"
    echo "  Example: market_data_queries: true, web_search: true, memory_search: true"
    read -rp "> " ALLOWED_RAW
    # Build a multi-item YAML list from comma-separated input. 'none'/empty -> '- none'.
    ALLOWED_ACTIONS=""
    if [[ -z "$ALLOWED_RAW" || "${ALLOWED_RAW,,}" == "none" ]]; then
      ALLOWED_ACTIONS="      - none"
    else
      IFS=',' read -ra _ALLOWED_ITEMS <<< "$ALLOWED_RAW"
      for _item in "${_ALLOWED_ITEMS[@]}"; do
        _item="${_item#"${_item%%[![:space:]]*}"}"   # ltrim
        _item="${_item%"${_item##*[![:space:]]}"}"   # rtrim
        [[ -n "$_item" ]] && ALLOWED_ACTIONS+="      - $_item"$'\n'
      done
      ALLOWED_ACTIONS="${ALLOWED_ACTIONS%$'\n'}"   # drop trailing newline
      [[ -z "$ALLOWED_ACTIONS" ]] && ALLOWED_ACTIONS="      - none"
    fi
    ;;
  *)
    # Fail-closed: unrecognized profile -> most restrictive baseline, never leak
    # an unfilled placeholder or an empty (permissive) allowlist.
    warn "Unknown profile '$OPT_PROFILE' — falling back to locked-down defaults (non-owners: none)."
    DEFLECTION_MSG="This assistant is private"
    ALLOWED_ACTIONS="      - none"
    ;;
esac
# Final safety net: if anything left these empty, fail closed.
[[ -z "${ALLOWED_ACTIONS:-}" ]] && ALLOWED_ACTIONS="      - none"
[[ -z "${DEFLECTION_MSG:-}" ]] && DEFLECTION_MSG="This assistant is private"

# ── Step 7: Build injection block ─────────────────────────────────────────────
# Read template and fill placeholders
RULES_CONTENT=$(cat "$RULES_TEMPLATE")
RULES_CONTENT="${RULES_CONTENT//DINOTRUST_OWNER_IDS/$OWNER_IDS_YAML}"
RULES_CONTENT="${RULES_CONTENT//DINOTRUST_DEFLECTION_MESSAGE/$DEFLECTION_MSG}"
RULES_CONTENT="${RULES_CONTENT//DINOTRUST_PROTECTED_RESOURCES/$PROTECTED_YAML}"
RULES_CONTENT="${RULES_CONTENT//DINOTRUST_ALLOWED_ACTIONS/$ALLOWED_ACTIONS}"

INJECTION_BLOCK="# --- dinotrust begin (v${VERSION}) ---
# Platform: ${OPT_PLATFORM} | Profile: ${OPT_PROFILE} | Installed: $(date -u +%Y-%m-%d)
${RULES_CONTENT}
# --- dinotrust end ---"

# ── Step 7b: Bootstrap budget check ───────────────────────────────────────────
# dinotrust injects into the file the agent loads as instructions EVERY turn.
# If that file grows past the platform's per-turn injection budget, the platform
# silently TRUNCATES it — and if part of the dinotrust ruleset is cut, enforcement
# runs half-applied with no error. For a security ruleset that is a silent hole,
# so we check size up front and warn loudly. (Warn, never block: budgets can be
# raised, and non-OpenClaw caps vary.)
BLOCK_CHARS=$(printf '%s' "$INJECTION_BLOCK" | wc -c)
# Existing target size with any prior dinotrust block stripped (avoid double-count).
EXISTING_CHARS=0
if [[ -f "$CONFIG_FILE" ]]; then
  EXISTING_CHARS=$(awk '/# --- dinotrust begin/,/# --- dinotrust end ---/{next}1' "$CONFIG_FILE" | wc -c)
fi
PROJECTED_CHARS=$((EXISTING_CHARS + BLOCK_CHARS))

if [[ "$OPT_PLATFORM" == "openclaw" ]]; then
  # OpenClaw bootstrap caps: per-file 20000, total 60000 (defaults).
  if [[ "$PROJECTED_CHARS" -gt 20000 ]]; then
    warn "After injection, $CONFIG_FILE would be ~${PROJECTED_CHARS} chars — over OpenClaw's per-file bootstrap cap (20000)."
    warn "  OpenClaw truncates the bootstrap silently — part of the dinotrust ruleset may NOT be injected, leaving enforcement INCOMPLETE."
    warn "  Fix: trim $CONFIG_FILE, or raise agents.defaults.bootstrapMaxChars, then verify the whole 'dinotrust begin..end' block is present in the agent's context."
  elif [[ "$PROJECTED_CHARS" -gt 17000 ]]; then
    warn "After injection, $CONFIG_FILE would be ~${PROJECTED_CHARS} chars — approaching OpenClaw's bootstrap cap (20000). Trim soon so the ruleset can't get truncated."
  else
    success "Bootstrap budget: ~${PROJECTED_CHARS} chars after injection — within OpenClaw's per-file cap (20000)."
  fi
else
  # Other platforms (Claude Code, Cursor, Windsurf, Aider, …): truncation behavior
  # and caps vary or are undocumented. Use a conservative generic threshold.
  if [[ "$PROJECTED_CHARS" -gt 20000 ]]; then
    warn "After injection, $CONFIG_FILE would be ~${PROJECTED_CHARS} chars — large for an instruction file."
    warn "  Some platforms truncate long instruction files, which could silently cut part of the dinotrust ruleset and leave enforcement INCOMPLETE."
    warn "  Verify your agent actually reads the full 'dinotrust begin..end' block (ask it to quote a rule near the end), and trim the file if it doesn't."
  else
    success "Instruction file: ~${PROJECTED_CHARS} chars after injection — reasonable size."
    info "  Note: $OPT_PLATFORM has no configurable per-file cap to auto-raise (unlike OpenClaw). If this file grows large later, verify the agent still sees the end by asking it to quote the last dinotrust rule."
  fi
fi

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

# Back up the target before any in-place mutation. This file is the agent's
# instruction source; we strip/append in place, so a timestamped backup is the
# undo path if anything goes wrong (incl. a malformed prior block confusing the
# awk range strip below). Only back up a non-empty existing file.
if [[ -f "$CONFIG_FILE" && -s "$CONFIG_FILE" ]]; then
  BACKUP_FILE="${CONFIG_FILE}.dinotrust-bak.$(date -u +%Y%m%d-%H%M%S)"
  cp "$CONFIG_FILE" "$BACKUP_FILE"
  info "Backed up $CONFIG_FILE → $BACKUP_FILE"
fi

# Check for existing block
if grep -q "dinotrust begin" "$CONFIG_FILE" 2>/dev/null; then
  if [[ "$OPT_FORCE" == "false" ]]; then
    need_input "confirmation to overwrite the existing dinotrust block" "--force" owner
    warn "dinotrust block already exists in $CONFIG_FILE"
    echo ""
    read -rp "Overwrite? [y/N]: " CONFIRM_OVERWRITE
    [[ "$CONFIRM_OVERWRITE" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
  fi
  # Guard against a malformed prior block: an unterminated 'begin' (no matching
  # 'end') would make the awk range delete everything to EOF. Detect and refuse
  # rather than silently eat the rest of the file (the backup above is the net).
  _begins=$(grep -c '# --- dinotrust begin' "$CONFIG_FILE" || true)
  _ends=$(grep -c '# --- dinotrust end ---' "$CONFIG_FILE" || true)
  if [[ "$_begins" != "$_ends" ]]; then
    error "Malformed existing dinotrust block in $CONFIG_FILE ($_begins begin / $_ends end markers). Fix manually (backup at ${BACKUP_FILE:-none}) and re-run."
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

# ── OpenClaw bootstrap cap auto-raise ─────────────────────────────────────────
# dinotrust is a SECURITY ruleset injected into AGENTS.md every turn. If AGENTS.md
# now exceeds OpenClaw's per-file bootstrap cap (default 20000), OpenClaw silently
# TRUNCATES — and a half-injected security ruleset enforces with holes and no
# error. The Step 7b check above only WARNS; here we actually fix it on OpenClaw:
# raise agents.defaults.bootstrapMaxChars (and total, if needed) to fit the file,
# so the whole ruleset always reaches the model. Measured against the just-written
# file, raise-only (never lowers, never clobbers a higher user value), and skipped
# cleanly if python3 is missing (falls back to the Step 7b warning). OpenClaw-only:
# other platforms have different/undocumented caps we must not guess at.
if [[ "$OPT_PLATFORM" == "openclaw" ]]; then
  OPENCLAW_JSON="${OPENCLAW_CONFIG:-$HOME/.openclaw/openclaw.json}"
  if [[ -f "$OPENCLAW_JSON" ]] && command -v python3 &>/dev/null; then
    # Workspace dir = parent of the AGENTS.md we just wrote (measure sibling root files for the total cap).
    WS_DIR="$(dirname "$CONFIG_FILE")"
    cp "$OPENCLAW_JSON" "${OPENCLAW_JSON}.dinotrust-bak.$(date -u +%Y%m%d-%H%M%S)" 2>/dev/null || true
    CAP_RESULT=$(WS_DIR="$WS_DIR" OPENCLAW_JSON="$OPENCLAW_JSON" python3 - <<'PYCAP'
import json, os, sys
path = os.environ["OPENCLAW_JSON"]
ws = os.environ["WS_DIR"]
try:
    cfg = json.load(open(path))
except Exception as e:
    print(f"SKIP could not parse openclaw.json: {e}"); sys.exit(0)
d = cfg.setdefault("agents", {}).setdefault("defaults", {})
FILE_DEFAULT, TOTAL_DEFAULT, FILE_BUF, TOTAL_BUF = 20000, 60000, 10000, 10000
root_files = ["AGENTS.md", "SOUL.md", "IDENTITY.md", "TOOLS.md", "USER.md", "MEMORY.md"]
sizes = {}
for rf in root_files:
    p = os.path.join(ws, rf)
    if os.path.isfile(p):
        sizes[rf] = os.path.getsize(p)
if not sizes:
    print("SKIP no root bootstrap files found"); sys.exit(0)
max_file = max(sizes.values()); total = sum(sizes.values())
biggest = max(sizes, key=sizes.get)
cur_file = d.get("bootstrapMaxChars", FILE_DEFAULT)
cur_total = d.get("bootstrapTotalMaxChars", TOTAL_DEFAULT)
new_file = max(cur_file, FILE_DEFAULT, max_file + FILE_BUF)
new_total = max(cur_total, TOTAL_DEFAULT, total + TOTAL_BUF)
msgs = []
if new_file != d.get("bootstrapMaxChars"):
    d["bootstrapMaxChars"] = new_file
    msgs.append(f"bootstrapMaxChars -> {new_file} (fits {biggest}={max_file} + {FILE_BUF})")
if new_total != d.get("bootstrapTotalMaxChars"):
    d["bootstrapTotalMaxChars"] = new_total
    msgs.append(f"bootstrapTotalMaxChars -> {new_total} (fits all root {total} + {TOTAL_BUF})")
# Pin contextInjection=always so the SECURITY ruleset is injected EVERY turn, not
# dropped on continuation turns. Default is already 'always', but it is a
# user-changeable knob — if a user set it to skip-on-continuation, dinotrust's
# rules would silently stop enforcing mid-conversation with no error. For a
# security ruleset that is the exact failure to prevent, so we pin it defensively.
# (Valid key is contextInjection, NOT workspaceBootstrap; strip that legacy key if
# an older install left it — it is not in the OpenClaw schema and crashes the gateway.)
if d.pop("workspaceBootstrap", None) is not None:
    msgs.append("removed legacy invalid key workspaceBootstrap")
if d.get("contextInjection") != "always":
    d["contextInjection"] = "always"
    msgs.append("contextInjection -> always (ruleset injected every turn, not skipped on continuation)")
# thinkingDefault -> medium: dinotrust is a security ruleset injected into root
# files. Without a minimum thinking floor, the agent may acknowledge the rules
# but not reliably internalize and act on them — especially the injection-defense
# patterns which require genuine reasoning to apply correctly. medium is the
# safe floor. Skip if user already has a non-default value set.
if d.get("thinkingDefault") in (None, "adaptive"):
    d["thinkingDefault"] = "medium"
    msgs.append("thinkingDefault -> medium (ensures security rules are internalized, not just acknowledged)")
if msgs:
    json.dump(cfg, open(path, "w"), indent=2, ensure_ascii=False)
    json.load(open(path))  # validate
    print("RAISED " + "; ".join(msgs))
else:
    print("OK caps + contextInjection + thinkingDefault already correct")
PYCAP
)
    case "$CAP_RESULT" in
      RAISED*) success "OpenClaw bootstrap caps raised so the full ruleset injects: ${CAP_RESULT#RAISED }" ;;
      OK*)     info "OpenClaw bootstrap caps already fit the ruleset" ;;
      SKIP*)   warn "Bootstrap cap auto-raise skipped: ${CAP_RESULT#SKIP } — see Step 7b note above" ;;
    esac
  elif [[ -f "$OPENCLAW_JSON" ]]; then
    warn "python3 not found — cannot auto-raise bootstrapMaxChars. If Step 7b warned about the cap, raise agents.defaults.bootstrapMaxChars manually so the ruleset isn't truncated."
  fi
fi

# ── OpenClaw exec-approval route auto-wire ────────────────────────────────────
# dinotrust's enforce hook ESCALATES critical/non-owner tool calls for approval.
# But OpenClaw only shows an approval card if an approval ROUTE is configured for
# the channel/account (channels.<chan>.accounts.<acct>.execApprovals). When that
# is unset, OpenClaw resolves the prompt via askFallback — which DEFAULTS TO DENY.
# Net effect for a fresh installer: dinotrust flags a command → no route → OpenClaw
# silently DENIES (or emits "no approval route") → the user thinks dinotrust "broke
# exec". The approval plumbing lives in openclaw.json, NOT in the hook, so dinotrust
# cannot fix it at runtime — it has to be wired at install. We do it here:
# for every configured Telegram/Discord/Slack account with NO execApprovals set,
# wire enabled=true + approvers=<owner ids> + target=dm. Idempotent (never touches
# an account that already has execApprovals — respects an explicit user choice),
# raise-only, validated by re-parsing the JSON, OpenClaw-only, and skipped cleanly
# if python3 is missing. Owner IDs come from the same --owner-id the installer
# already collected; @platform suffixes are stripped so the raw id is the approver.
if [[ "$OPT_PLATFORM" == "openclaw" ]]; then
  OPENCLAW_JSON="${OPENCLAW_CONFIG:-$HOME/.openclaw/openclaw.json}"
  if [[ -f "$OPENCLAW_JSON" ]] && command -v python3 &>/dev/null; then
    APPROVE_RESULT=$(OPENCLAW_JSON="$OPENCLAW_JSON" DT_OWNER_IDS="$OPT_OWNER_ID" python3 - <<'PYAPPROVE'
import json, os, sys
path = os.environ["OPENCLAW_JSON"]
raw = os.environ.get("DT_OWNER_IDS", "")
# Parse comma-separated owner ids; strip any @platform scoping to the bare id.
approvers = []
for entry in raw.split(","):
    e = entry.strip().replace(" ", "")
    if not e:
        continue
    oid = e.split("@", 1)[0]
    if oid and oid not in approvers:
        approvers.append(oid)
if not approvers:
    print("SKIP no owner ids to set as approvers"); sys.exit(0)
try:
    cfg = json.load(open(path))
except Exception as e:
    print(f"SKIP could not parse openclaw.json: {e}"); sys.exit(0)
channels = cfg.get("channels")
if not isinstance(channels, dict):
    print("SKIP no channels block in openclaw.json"); sys.exit(0)
# Only chat channels that support native approval cards.
APPROVAL_CHANNELS = ("telegram", "discord", "slack")
wired = []
for chan_name in APPROVAL_CHANNELS:
    chan = channels.get(chan_name)
    if not isinstance(chan, dict):
        continue
    accounts = chan.get("accounts")
    if not isinstance(accounts, dict):
        continue
    for acct_name, acct in accounts.items():
        if not isinstance(acct, dict):
            continue
        # Idempotent: never touch an account that already has execApprovals set
        # (respects an explicit user choice, incl. enabled=false to opt out).
        if "execApprovals" in acct:
            continue
        acct["execApprovals"] = {
            "enabled": True,
            "approvers": list(approvers),
            "target": "dm",
        }
        wired.append(f"{chan_name}.{acct_name}")
if not wired:
    print("OK all approval-capable accounts already have execApprovals (or none configured)"); sys.exit(0)
json.dump(cfg, open(path, "w"), indent=2, ensure_ascii=False)
json.load(open(path))  # validate round-trip
print("WIRED " + "; ".join(wired) + "  approvers=" + ",".join(approvers))
PYAPPROVE
)
    case "$APPROVE_RESULT" in
      WIRED*) success "OpenClaw exec-approval route wired so dinotrust escalations reach you (not silently denied): ${APPROVE_RESULT#WIRED }" ;;
      OK*)    info "OpenClaw exec-approval route already configured — left as-is" ;;
      SKIP*)  warn "exec-approval auto-wire skipped: ${APPROVE_RESULT#SKIP } — without a route, dinotrust escalations may hit askFallback=deny. Set channels.<chan>.accounts.<acct>.execApprovals manually." ;;
    esac
  elif [[ -f "$OPENCLAW_JSON" ]]; then
    warn "python3 not found — cannot auto-wire the exec-approval route. Without it, dinotrust escalations may be silently denied. Set channels.<chan>.accounts.<acct>.execApprovals.{enabled:true,approvers:[<your id>],target:dm} manually."
  fi
fi

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

# Skill: install the dinotrust-security-model reference skill next to the config.
# The injected block points to it for the identity/trust mechanics (kept out of
# the always-on prompt to save space). Degrades safely if not copied: the block
# only *references* it, never depends on it for enforcement.
DT_SKILL_SRC="$REPO_DIR/skills/dinotrust-security-model"
if [[ -d "$DT_SKILL_SRC" ]]; then
  DT_SKILL_DEST="$(dirname "$CONFIG_FILE")/skills/dinotrust-security-model"
  if mkdir -p "$(dirname "$DT_SKILL_DEST")" 2>/dev/null && cp -r "$DT_SKILL_SRC" "$DT_SKILL_DEST" 2>/dev/null; then
    info "Installed skill: dinotrust-security-model -> $DT_SKILL_DEST"
    # Auto-discovered from <workspace>/skills (highest-precedence root). Visible
    # by default; if you pin an agent skills allowlist (agents.*.skills), add
    # "dinotrust-security-model" to it or the agent won't see the reference layer.
  else
    warn "Could not copy dinotrust-security-model skill to $DT_SKILL_DEST — the injected block references it; copy skills/dinotrust-security-model/ manually if you want the reference layer."
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
echo "  Owner ID(s) : $OWNER_IDS_YAML"
echo "  Profile  : $OPT_PROFILE"
echo ""
echo "Next: restart your agent for the rules to take effect."
echo ""
echo "Verify:"
echo "  grep 'dinotrust begin' \"$CONFIG_FILE\""
echo ""

# ── Post-install feature discovery ───────────────────────────────────
# Install is intentionally fast/seamless — but that means users often never
# learn the advanced surface. Surface it here, briefly, without adding friction.
echo "You can tune this anytime — the rules are plain text in your config file:"
echo "  • What non-owners may do  — edit the 'allowed:' list under non_owner_rules"
echo "  • The refusal message     — edit 'deflection_message'"
echo "  • Off-limits files        — edit 'protected_resources'"
echo "  Edit between the '# --- dinotrust begin/end ---' markers, then restart."
echo "  Or re-run with --profile custom to set them interactively."
echo ""
if [[ "$OPT_PROFILE" == "private-assistant" ]]; then
  echo "  (Current profile 'private-assistant': non-owners get NO access. If this"
  echo "   agent will face a public/group channel, consider 'market-analyst' or"
  echo "   'custom' so non-owners get a scoped, useful surface.)"
  echo ""
fi

# ── Optional chain: observability audit layer ────────────────────────────────
# Core (enforcement) is now installed. Observability (the audit layer) is a
# SEPARATE, opt-out step. We chain it by default for interactive humans, never
# force it headless (it needs a leak-sensitive --report-target we must not
# guess).
#
# Platform routing:
#   T1 (OpenClaw, Hermes)  -> chain to observability/install.sh (hook-based)
#   T3 (claude-code, codex, cursor, windsurf, continue, aider, goose)
#                          -> set up self-audit env + log dir (no daemon)
OBS_INSTALLER="$REPO_DIR/observability/install.sh"

# T3 platforms (no-daemon CLIs): the agent self-reports reject-pattern hits.
# We set up the env vars + log dir so the agent knows where to write and
# the consumer knows where to read.
setup_t3_observability() {
  local _platform="$1"
  local _log_dir="$HOME/.dinotrust/logs"
  local _env_file="$HOME/.dinotrust/env"
  local _selfaudit_log="$_log_dir/${_platform}-selfaudit.jsonl"

  mkdir -p "$_log_dir"

  # Build env file content
  local _env="# dinotrust observability — auto-generated by install.sh"
  _env+="\nexport DT_SELFAUDIT_LOG=\"$_selfaudit_log\""
  _env+="\nexport DT_CHANNEL=\"${OPT_REPORT_CHANNEL:-telegram}\""
  [[ -n "$OPT_REPORT_TARGET" ]] && _env+="\nexport DT_TARGET=\"$OPT_REPORT_TARGET\""
  [[ -n "$OPT_REPORT_THREAD" ]] && _env+="\nexport DT_THREAD_ID=\"$OPT_REPORT_THREAD\""

  echo -e "$_env" > "$_env_file"
  chmod 600 "$_env_file"

  success "Observability (self-audit) configured for $_platform"
  info "Log file:  $_selfaudit_log"
  info "Env file:  $_env_file"
  info "Channel:   ${OPT_REPORT_CHANNEL:-telegram}"
  [[ -n "$OPT_REPORT_TARGET" ]] && info "Target:    $OPT_REPORT_TARGET"
  echo ""
  echo "Usage:"
  echo "  1. Source the env file in your shell or agent startup:"
  echo "       source $_env_file"
  echo "  2. The agent will append reject-pattern audit lines to the log."
  echo "  3. Run the digest on demand (or add to cron):"
  echo "       source $_env_file && python3 $REPO_DIR/observability/adapters/openclaw/report.py --period daily"
  echo "  4. Or with a specific output / webhook:"
  echo "       source $_env_file && python3 $REPO_DIR/observability/adapters/openclaw/report.py --period daily --output digest.txt"
  echo ""
}

chain_observability() {
  [[ "$OPT_NO_OBSERVABILITY" == "true" ]] && { info "Skipping observability (--no-observability)."; return 0; }

  # Observability is now part of the DEFAULT install (dino: "install it as part of
  # the main installer"). It logs injection attempts locally regardless; a
  # --report-target only adds remote digest DELIVERY, which stays optional and is
  # never guessed. So: default-on everywhere, including headless. Opt out with
  # --no-observability. Delivery-less installs still get the local audit log.
  local _run=true
  if [[ "$OPT_WITH_OBSERVABILITY" == "true" ]]; then
    _run=true
  elif [[ "$OPT_NONINTERACTIVE" == "true" ]]; then
    # Headless: install the audit layer (local logging). If no --report-target was
    # given, remote delivery is simply not configured — the digest still runs
    # on-demand and reads the local log.
    _run=true
    [[ -z "$OPT_REPORT_TARGET" ]] && info "Observability: installing local audit layer (no --report-target given, remote delivery unconfigured)."
  else
    echo ""
    ask "Install the observability audit layer? (default: yes) It logs injection"
    info "attempts locally; a report target adds remote digest delivery. [Y/n]"
    local _ans
    read -rp "> " _ans
    [[ "$_ans" =~ ^[Nn]$ ]] && _run=false
  fi
  if [[ "$_run" != "true" ]]; then
    info "Skipped observability (the optional audit layer — a daily/weekly digest"
    info "of injection attempts + which reject-patterns fired). Core enforcement is"
    info "fully active without it. Add it anytime:"
    info "  bash scripts/install.sh --with-observability --report-target <chat-id>"
    return 0
  fi

  # ── Platform routing ──
  case "$OPT_PLATFORM" in
    openclaw|hermes)
      # T1/T2 — chain to the observability installer (hook or daemon)
      if [[ ! -f "$OBS_INSTALLER" ]]; then
        warn "Observability installer not found at $OBS_INSTALLER — skipping. (Install core only.)"
        return 0
      fi

      local _obs_args=()
      [[ "$OPT_PLATFORM" == "hermes" ]] && _obs_args+=(--platform hermes)
      local _ws_dir
      _ws_dir="$(dirname "$CONFIG_FILE")"
      [[ -d "$_ws_dir" ]] && _obs_args+=(--workspace "$_ws_dir")
      [[ -n "$OPT_REPORT_TARGET" ]] && _obs_args+=(--report-target "$OPT_REPORT_TARGET")
      [[ "$OPT_FORCE" == "true" ]] && _obs_args+=(--force)
      [[ "$OPT_DRY_RUN" == "true" ]] && _obs_args+=(--dry-run)
      if [[ "$OPT_NONINTERACTIVE" == "true" && -n "$OPT_REPORT_TARGET" ]]; then
        _obs_args+=(--non-interactive)
      fi

      echo ""
      info "Chaining observability: bash $OBS_INSTALLER ${_obs_args[*]}"
      bash "$OBS_INSTALLER" "${_obs_args[@]}" || warn "Observability install did not complete — core enforcement is unaffected. Re-run observability/install.sh manually."
      ;;

    claude-code|codex-cli)
      # T3 — no-daemon CLI: set up self-audit env + log dir
      # (goose/cursor/windsurf/continue/aider are rejected earlier by the
      #  UNSUPPORTED guard, so only the two supported CLIs reach here.)
      # Prompt for channel + target if not given
      if [[ -z "$OPT_REPORT_TARGET" && "$OPT_NONINTERACTIVE" != "true" ]]; then
        echo ""
        ask "Where should security digests be delivered?"
        echo "  1) Telegram   (default)"
        echo "  2) Discord"
        echo "  3) Slack"
        echo "  4) File only  (--dry-run / stdout)"
        echo ""
        read -rp "Enter number [1-4]: " _chnum
        case "$_chnum" in
          2) OPT_REPORT_CHANNEL="discord" ;;
          3) OPT_REPORT_CHANNEL="slack" ;;
          4) OPT_REPORT_CHANNEL="file" ;;
          *) OPT_REPORT_CHANNEL="telegram" ;;
        esac
        if [[ "$OPT_REPORT_CHANNEL" != "file" ]]; then
          ask "Target ID (chat/channel ID) — this is where digests go:"
          echo "  $(id_discovery_hint "$OPT_REPORT_CHANNEL" target)"
          read -rp "> " OPT_REPORT_TARGET
        fi
      fi
      setup_t3_observability "$OPT_PLATFORM"
      ;;

    *)
      warn "Observability not yet implemented for platform '$OPT_PLATFORM' — skipping. (Core enforcement is unaffected.)"
      ;;
  esac
}

# ── Chain: enforce layer (code-level pre-tool veto) ──────────────────────────
# The instruction layer (security_rules.md) is now installed. For platforms with
# a real pre-tool veto, also install the enforce hook so policy holds even if the
# model doesn't comply. Default-on; --no-enforce opts out. Unsupported platforms
# (cursor/windsurf/continue/aider/goose) are skipped with a clear note.
ENFORCE_INSTALLER="$REPO_DIR/enforce/install.sh"
chain_enforce() {
  [[ "$OPT_NO_ENFORCE" == "true" ]] && { info "Skipping enforce layer (--no-enforce). Instruction layer is active; enforcement is not."; return 0; }
  case "$OPT_PLATFORM" in
    openclaw|hermes|claude-code|codex-cli) : ;;
    *)
      warn "Enforce layer not supported on '$OPT_PLATFORM' (no pre-tool veto)."
      warn "You have the instruction layer only, which is compliance-dependent."
      warn "For real enforcement use OpenClaw, Hermes, Claude Code, or Codex CLI."
      return 0 ;;
  esac
  if [[ ! -f "$ENFORCE_INSTALLER" ]]; then
    warn "Enforce installer not found at $ENFORCE_INSTALLER — skipping."; return 0
  fi
  local _args=(--platform "$OPT_PLATFORM")
  [[ -n "$OPT_OWNER_ID" ]] && _args+=(--owner-id "$OPT_OWNER_ID")
  [[ -n "$OPT_ALLOW_SCRIPTS" ]] && _args+=(--allow-scripts "$OPT_ALLOW_SCRIPTS")
  [[ -n "${OPT_AGENT:-}" ]] && _args+=(--agent "$OPT_AGENT")
  [[ -n "$OPT_CONFIG" ]] && _args+=(--config "$OPT_CONFIG")
  [[ "$OPT_ENFORCE_SHADOW" == "true" ]] && _args+=(--shadow)
  [[ "$OPT_FORCE" == "true" ]] && _args+=(--force)
  $OPT_DRY_RUN && _args+=(--dry-run)
  [[ "$OPT_NONINTERACTIVE" == "true" ]] && _args+=(--non-interactive)
  echo ""
  info "Chaining enforce: bash $ENFORCE_INSTALLER ${_args[*]}"
  bash "$ENFORCE_INSTALLER" "${_args[@]}" || warn "Enforce install did not complete — instruction layer is unaffected. Re-run enforce/install.sh manually."
}

# Note: core --dry-run exits earlier (Step 8), so the chain only runs on a real
# install — dry-run never reaches here, by design.
chain_observability
chain_enforce
