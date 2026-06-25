#!/usr/bin/env bash
# dinotrust observability installer
# Installs the activity + jailbreak/injection audit layer (hook producer + digest
# consumer + patterns taxonomy) into an OpenClaw agent. Zero-infra: regex + thin
# adapters, no LLM. Reference adapter = OpenClaw (this script).
# Usage: bash observability/install.sh [options]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
PATTERNS_SRC="$SCRIPT_DIR/patterns.json"
HANDLER_SRC="$SCRIPT_DIR/adapters/openclaw/handler.ts"
REPORT_SRC="$SCRIPT_DIR/adapters/openclaw/report.py"
VALIDATE_SRC="$SCRIPT_DIR/validate.py"
SECURITY_RULES="$REPO_DIR/security_rules.md"
VERSION_FILE="$REPO_DIR/VERSION"
VERSION="$(cat "$VERSION_FILE" 2>/dev/null || echo "unknown")"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}→${NC} $*"; }
success() { echo -e "${GREEN}✓${NC} $*"; }
warn()    { echo -e "${YELLOW}⚠${NC} $*"; }
error()   { echo -e "${RED}✗${NC} $*" >&2; exit 1; }
ask()     { echo -e "${BOLD}?${NC} $*"; }

# ── Args ──────────────────────────────────────────────────────────────────────
# AUTO vars (forced detection; overridable by flag for edge cases / testing).
OPT_WORKSPACE=""        # ~/.openclaw/workspace-<agent>
OPT_AGENT=""            # derived from workspace dir name
OPT_OPENCLAW_BIN=""     # openclaw binary path
OPT_ACTIVITY_LOG=""     # activity producer log
OPT_JAILBREAK_LOG=""    # jailbreak/injection producer log
# OWNER-INPUT vars (must be confirmed; never silently auto — leak vectors).
OPT_REPORT_TARGET=""    # REQUIRED, no default
OPT_REPORT_THREAD=""    # optional
OPT_REPORT_CHANNEL=""   # delivery channel (default telegram)
OPT_REPORT_ACCOUNT=""   # delivery account id (optional)
OPT_SCHEDULE="30 10 * * *"   # daily default
OPT_REPORT_TZ=""        # default host TZ
OPT_PRIVACY="patterns-only"  # safest default
# Mode flags.
OPT_FORCE=false
OPT_DRY_RUN=false
OPT_NONINTERACTIVE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace)       OPT_WORKSPACE="${2%/}"; shift 2 ;;
    --agent)           OPT_AGENT="$2"; shift 2 ;;
    --openclaw-bin)    OPT_OPENCLAW_BIN="$2"; shift 2 ;;
    --activity-log)    OPT_ACTIVITY_LOG="$2"; shift 2 ;;
    --jailbreak-log)   OPT_JAILBREAK_LOG="$2"; shift 2 ;;
    --report-target)   OPT_REPORT_TARGET="$2"; shift 2 ;;
    --report-thread)   OPT_REPORT_THREAD="$2"; shift 2 ;;
    --report-channel)  OPT_REPORT_CHANNEL="$2"; shift 2 ;;
    --report-account)  OPT_REPORT_ACCOUNT="$2"; shift 2 ;;
    --schedule)        OPT_SCHEDULE="$2"; shift 2 ;;
    --report-tz)       OPT_REPORT_TZ="$2"; shift 2 ;;
    --privacy)         OPT_PRIVACY="$2"; shift 2 ;;
    --force)           OPT_FORCE=true; shift ;;
    --dry-run)         OPT_DRY_RUN=true; shift ;;
    --non-interactive|--yes|-y) OPT_NONINTERACTIVE=true; shift ;;
    -h|--help)
      echo "Usage: bash observability/install.sh [options]"
      echo ""
      echo "AUTO (detected; override only for edge cases):"
      echo "  --workspace DIR       OpenClaw workspace dir (~/.openclaw/workspace-<agent>)"
      echo "  --agent ID            Agent id (default: derived from workspace dir name)"
      echo "  --openclaw-bin PATH   openclaw binary (default: PATH, then Homebrew fallback)"
      echo "  --activity-log PATH   Activity log (default: ~/.openclaw/logs/<agent>-activity.log)"
      echo "  --jailbreak-log PATH  Jailbreak log (default: ~/.openclaw/logs/<agent>-jailbreak.log)"
      echo ""
      echo "OWNER-INPUT (confirmed; never silently defaulted):"
      echo "  --report-target ID    REQUIRED. Where the digest is delivered (chat/channel id)."
      echo "  --report-thread ID    Optional thread/topic id."
      echo "  --report-channel NAME Delivery channel (default: telegram)."
      echo "  --report-account ID   Delivery account id (optional)."
      echo "  --schedule CRON       Cron expr for the digest (default: '30 10 * * *')."
      echo "  --report-tz TZ        IANA tz for the schedule (default: host TZ)."
      echo "  --privacy MODE        patterns-only|truncated|full (default: patterns-only)."
      echo ""
      echo "Modes:"
      echo "  --force               Overwrite an existing install."
      echo "  --dry-run             Print the plan; change nothing."
      echo "  --non-interactive     Never prompt; fail fast with the flag to add. Alias: --yes, -y"
      echo ""
      echo "Headless/agent use: pass all OWNER-INPUT flags (at least --report-target) plus"
      echo "--non-interactive. Missing input fails fast with the exact flag, plus a self|owner"
      echo "hint, instead of hanging on a prompt."
      echo ""
      echo "Note: this is the AUDIT layer only. dinotrust ENFORCEMENT (security_rules.md)"
      echo "installs separately via scripts/install.sh. Observability is most useful with"
      echo "core present — it audits the very reject-patterns core defines."
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
# pass instead of prompting. $3 = source hint for an autonomous caller:
#   "self"  -> agent resolves from its own host/workspace context, retries.
#   "owner" -> identity/security policy the agent MUST NOT guess; ask the human.
need_input() {
  # $1 = human description, $2 = flag hint, $3 = self|owner (default: self)
  if [[ "$OPT_NONINTERACTIVE" == "true" ]]; then
    local _src="${3:-self}"
    local _guide
    if [[ "$_src" == "owner" ]]; then
      _guide="ACTION[agent]: ask the OWNER for this (identity/security policy — do not guess), then re-run with the flag."
    else
      _guide="ACTION[agent]: resolve this from your own host/workspace context and re-run with the flag."
    fi
    error "Missing required input: $1. Pass $2 (running non-interactively / no TTY). $_guide"
  fi
}

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}🦖 dinotrust observability v${VERSION}${NC} — activity + injection audit layer"
echo "────────────────────────────────────────────────────────"
echo "This is the AUDIT layer. Enforcement (security_rules.md) installs separately"
echo "via scripts/install.sh."
echo ""

# ── AUTO-detect: runtime class + route ────────────────────────────────────
# This installer wires the Tier-1 OpenClaw hook (the independent producer). For
# other runtimes it does NOT dead-end — it routes you to the right tier:
#   Tier-1 OpenClaw  -> installed here (hook + cron).
#   Tier-2 daemon    -> Hermes/Discord/Slack: copy adapters/_template (or
#                       adapters/discord) into your bot; in-proc, no installer.
#   Tier-3 CLI       -> Claude Code/Cursor/Aider/...: no producer possible;
#                       use adapters/cli-selfaudit (self-audit clause + on-demand
#                       digest). Honestly weaker, documented as such.
if [[ ! -f "$HOME/.openclaw/openclaw.json" ]]; then
  warn "No ~/.openclaw/openclaw.json — this installer wires the Tier-1 OpenClaw hook."
  echo ""
  info "Detecting your runtime to point you at the right tier..."
  _detected=""
  [[ -d "$HOME/.hermes" ]] && _detected="hermes (Tier-1 gateway hook)"
  [[ -f "$HOME/.claude/CLAUDE.md" || -f "./CLAUDE.md" ]] && _detected="${_detected:+$_detected, }claude-code (Tier-3 CLI)"
  [[ -f "$HOME/.codex/AGENTS.md" ]] && _detected="${_detected:+$_detected, }codex-cli (Tier-3 CLI)"
  [[ -d "$HOME/.cursor" ]] && _detected="${_detected:+$_detected, }cursor (Tier-3 CLI)"
  [[ -f "./.windsurfrules" ]] && _detected="${_detected:+$_detected, }windsurf (Tier-3 CLI)"
  [[ -f "./.continuerules" ]] && _detected="${_detected:+$_detected, }continue (Tier-3 CLI)"
  [[ -f "./CONVENTIONS.md" || -f "./.aider.conf.yml" ]] && _detected="${_detected:+$_detected, }aider (Tier-3 CLI)"
  [[ -n "$_detected" ]] && info "Detected: $_detected"
  echo ""
  echo "Next steps by tier:"
  echo "  • Tier-1 (Hermes — gateway hook, independent producer):"
  echo "      Hermes has a real hook API (HOOK.yaml + handler.py in ~/.hermes/hooks/)."
  echo "      Copy $SCRIPT_DIR/adapters/hermes/ there + patterns.json; set the DT_* env."
  echo "      Same schema + independence as OpenClaw. See adapters/hermes/README.md."
  echo "  • Tier-2 (Discord, Slack — long-lived bot, no hook API):"
  echo "      Reuse the shared core. Copy $SCRIPT_DIR/adapters/_template/daemon-adapter.ts"
  echo "      (or the working $SCRIPT_DIR/adapters/discord/tap.ts) into your bot and wire"
  echo "      the 4 TODO taps. In-process timer, no installer. Same schema as Tier-1."
  echo "  • Tier-3 (Claude Code, Codex CLI, Cursor, Windsurf, Continue, Aider, Goose):"
  echo "      No independent producer is possible (no daemon, no hook). Use"
  echo "      $SCRIPT_DIR/adapters/cli-selfaudit/README.md — self-audit clause +"
  echo "      on-demand digest. Honestly best-effort; depends on agent compliance."
  echo ""
  error "Not an OpenClaw host — see the per-tier guidance above (this installer only wires Tier-1)."
fi
success "Platform: openclaw (openclaw.json found) — Tier-1 (independent hook producer)"

# ── AUTO-detect: workspace ────────────────────────────────────────────────────
# Explicit --workspace wins. Otherwise: single workspace auto, multiple -> menu,
# zero -> say so and ask. Mirrors dinotrust install.sh sentinel pattern.
if [[ -z "$OPT_WORKSPACE" ]]; then
  _ws_glob=$(ls -d "$HOME/.openclaw/workspace-"*/ 2>/dev/null || true)
  _ws_count=$(echo "$_ws_glob" | grep -c . || true)
  if [[ "$_ws_count" -eq 1 ]]; then
    OPT_WORKSPACE="${_ws_glob%/}"
    OPT_WORKSPACE="${OPT_WORKSPACE%$'\n'}"
  elif [[ "$_ws_count" -gt 1 ]]; then
    need_input "which OpenClaw workspace to target (multiple detected)" "--workspace DIR" self
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
    read -rp "Enter number [0-${#_WS_LIST[@]}]: " _WS_NUM
    if [[ "$_WS_NUM" == "0" ]]; then
      ask "Path to your OpenClaw workspace dir:"
      read -rp "> " OPT_WORKSPACE
      OPT_WORKSPACE="${OPT_WORKSPACE%/}"
    elif [[ "$_WS_NUM" =~ ^[0-9]+$ ]] && (( _WS_NUM >= 1 && _WS_NUM <= ${#_WS_LIST[@]} )); then
      OPT_WORKSPACE="${_WS_LIST[$((_WS_NUM - 1))]%/}"
    else
      error "Invalid selection."
    fi
  else
    need_input "target workspace (no OpenClaw workspace detected)" "--workspace DIR" self
    echo ""
    warn "No OpenClaw workspaces under $HOME/.openclaw/workspace-*/"
    ask "Path to your OpenClaw workspace dir:"
    read -rp "> " OPT_WORKSPACE
    OPT_WORKSPACE="${OPT_WORKSPACE%/}"
  fi
fi
[[ -d "$OPT_WORKSPACE" ]] || error "Workspace dir not found: $OPT_WORKSPACE"
info "Workspace: $OPT_WORKSPACE"

# ── Soft dependency: is dinotrust core (enforcement) injected here? ──────────
# Observability AUDITS the reject-patterns that core's security_rules.md DEFINES.
# It works without core, but auditing rules nothing enforces is half the value.
# Warn (never block) if the core block isn't present in this workspace's AGENTS.md.
_CORE_CONFIG="$OPT_WORKSPACE/AGENTS.md"
if [[ -f "$_CORE_CONFIG" ]] && grep -q "dinotrust begin" "$_CORE_CONFIG" 2>/dev/null; then
  success "dinotrust core (enforcement) detected in $_CORE_CONFIG."
else
  warn "dinotrust core (enforcement) not detected in $_CORE_CONFIG."
  warn "  Observability audits the reject-patterns core defines — it is most useful WITH core."
  warn "  Install enforcement separately:  bash scripts/install.sh --owner-id <id>"
  warn "  (Continuing anyway — audit-only is a valid setup.)"
fi

# ── AUTO-detect: agent id (from workspace dir name) ───────────────────────────
# workspace-analyst -> analyst. Override with --agent for non-standard layouts.
if [[ -z "$OPT_AGENT" ]]; then
  _ws_base="$(basename "$OPT_WORKSPACE")"
  OPT_AGENT="${_ws_base#workspace-}"
  if [[ -z "$OPT_AGENT" || "$OPT_AGENT" == "$_ws_base" ]]; then
    need_input "agent id (could not derive from workspace dir name '$_ws_base')" "--agent ID" self
    ask "Agent id:"
    read -rp "> " OPT_AGENT
  fi
fi
[[ -n "$OPT_AGENT" ]] || error "Agent id is required."
info "Agent: $OPT_AGENT"

# ── AUTO-detect: log paths ────────────────────────────────────────────────────
_LOG_DIR="$HOME/.openclaw/logs"
[[ -n "$OPT_ACTIVITY_LOG" ]]  || OPT_ACTIVITY_LOG="$_LOG_DIR/${OPT_AGENT}-activity.log"
[[ -n "$OPT_JAILBREAK_LOG" ]] || OPT_JAILBREAK_LOG="$_LOG_DIR/${OPT_AGENT}-jailbreak.log"
info "Activity log:  $OPT_ACTIVITY_LOG"
info "Jailbreak log: $OPT_JAILBREAK_LOG"

# ── AUTO-detect: openclaw binary (PATH, then Homebrew fallback) ───────────────
# Bare cron/non-login envs often lack Homebrew on PATH — learned bug. Resolve to
# an absolute path here so the producer hook and any binary calls are env-safe.
if [[ -z "$OPT_OPENCLAW_BIN" ]]; then
  if command -v openclaw >/dev/null 2>&1; then
    OPT_OPENCLAW_BIN="$(command -v openclaw)"
  elif [[ -x "/home/linuxbrew/.linuxbrew/bin/openclaw" ]]; then
    OPT_OPENCLAW_BIN="/home/linuxbrew/.linuxbrew/bin/openclaw"
  elif [[ -x "$HOME/.linuxbrew/bin/openclaw" ]]; then
    OPT_OPENCLAW_BIN="$HOME/.linuxbrew/bin/openclaw"
  else
    warn "openclaw binary not found on PATH or in Homebrew — cron/PATH wiring will still set the Homebrew dir, but verify the binary exists."
    OPT_OPENCLAW_BIN="openclaw"
  fi
fi
info "openclaw binary: $OPT_OPENCLAW_BIN"

# ── Validate OWNER-INPUT: privacy mode ────────────────────────────────────────
case "$OPT_PRIVACY" in
  patterns-only|truncated|full) : ;;
  *) error "Invalid --privacy '$OPT_PRIVACY' (expected: patterns-only|truncated|full)." ;;
esac

# ── Validate OWNER-INPUT: report channel (default telegram) ───────────────────
[[ -n "$OPT_REPORT_CHANNEL" ]] || OPT_REPORT_CHANNEL="telegram"

# ── Validate OWNER-INPUT: report tz (default host) ────────────────────────────
if [[ -z "$OPT_REPORT_TZ" ]]; then
  if [[ -f /etc/timezone ]]; then
    OPT_REPORT_TZ="$(cat /etc/timezone 2>/dev/null || true)"
  fi
  [[ -n "$OPT_REPORT_TZ" ]] || OPT_REPORT_TZ="${TZ:-UTC}"
fi

# ── Validate OWNER-INPUT: report target (REQUIRED, never silent default) ──────
# This is a leak vector: a wrong/auto target sends the audit digest to the wrong
# place. Require it explicitly. Interactive may suggest, but must be confirmed.
if [[ -z "$OPT_REPORT_TARGET" ]]; then
  need_input "report target (where the audit digest is delivered)" "--report-target ID" owner
  echo ""
  warn "The audit digest reports injection attempts — it must go ONLY to a trusted owner target."
  ask "Report target (chat/channel id for digest delivery):"
  read -rp "> " OPT_REPORT_TARGET
fi
[[ -n "$OPT_REPORT_TARGET" ]] || error "A report target is required (--report-target)."
info "Report target: $OPT_REPORT_TARGET (channel: $OPT_REPORT_CHANNEL${OPT_REPORT_THREAD:+, thread: $OPT_REPORT_THREAD})"
info "Schedule: $OPT_SCHEDULE (tz: $OPT_REPORT_TZ) | Privacy: $OPT_PRIVACY"

# ── Install targets ─────────────────────────────────────────────────────
HOOK_DIR="$HOME/.openclaw/hooks/${OPT_AGENT}-dinotrust-observability"
HOOK_DEST="$HOOK_DIR/handler.ts"
PATTERNS_DEST="$HOOK_DIR/patterns.json"
REPORT_DEST="$HOME/.openclaw/scripts/${OPT_AGENT}-dinotrust-report.py"
AGENT_FILTER_VAL="agent:${OPT_AGENT}"

# ── Source-file preflight ──────────────────────────────────────────────
for _src in "$HANDLER_SRC" "$REPORT_SRC" "$PATTERNS_SRC"; do
  [[ -f "$_src" ]] || error "Missing source file: $_src"
done

# ── Idempotency / overwrite guard ──────────────────────────────────────
ALREADY_INSTALLED=false
if [[ -f "$HOOK_DEST" || -f "$REPORT_DEST" ]]; then
  ALREADY_INSTALLED=true
  if [[ "$OPT_FORCE" != "true" && "$OPT_DRY_RUN" != "true" ]]; then
    need_input "confirmation to overwrite the existing observability install" "--force" owner
    warn "dinotrust observability already installed for agent '$OPT_AGENT':"
    [[ -f "$HOOK_DEST" ]]   && warn "  hook:   $HOOK_DEST"
    [[ -f "$REPORT_DEST" ]] && warn "  report: $REPORT_DEST"
    echo ""
    read -rp "Overwrite? [y/N]: " _CONFIRM
    [[ "$_CONFIRM" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
  fi
fi

# ── Placeholder substitution (safe: writes to a tmp copy, never the repo src) ──
# Uses python for substitution — values contain '/' and ':'; literal replace, no
# regex surprises. Returns the substituted text on stdout.
substitute() {
  # $1 = source file; remaining args = KEY=VALUE pairs
  local _src="$1"; shift
  SUBST_SRC="$_src" SUBST_PAIRS="$*" python3 - "$@" <<'PYEOF'
import os, sys
src = os.environ["SUBST_SRC"]
with open(src, "r", encoding="utf-8") as fh:
    text = fh.read()
for pair in sys.argv[1:]:
    key, _, val = pair.partition("=")
    text = text.replace(key, val)
sys.stdout.write(text)
PYEOF
}

# Build the substituted content in memory (so --dry-run can show without writing).
HANDLER_OUT="$(substitute "$HANDLER_SRC" \
  "__AGENT_FILTER__=$AGENT_FILTER_VAL" \
  "__ACTIVITY_LOG__=$OPT_ACTIVITY_LOG" \
  "__JAILBREAK_LOG__=$OPT_JAILBREAK_LOG" \
  "__PATTERNS_FILE__=$PATTERNS_DEST" \
  "__PRIVACY__=$OPT_PRIVACY")"
REPORT_OUT="$(substitute "$REPORT_SRC" \
  "__ACTIVITY_LOG__=$OPT_ACTIVITY_LOG" \
  "__JAILBREAK_LOG__=$OPT_JAILBREAK_LOG" \
  "__CHANNEL__=$OPT_REPORT_CHANNEL" \
  "__TARGET__=$OPT_REPORT_TARGET" \
  "__THREAD_ID__=$OPT_REPORT_THREAD" \
  "__ACCOUNT__=$OPT_REPORT_ACCOUNT")"

# Residual-placeholder guard: any un-substituted __FOO__ token left is a bug that
# would silently break the installed hook/report. Catch it here, not at runtime.
_residual=$(printf '%s\n%s\n' "$HANDLER_OUT" "$REPORT_OUT" | grep -oE '__[A-Z_]+__' | sort -u || true)
if [[ -n "$_residual" ]]; then
  error "Unsubstituted placeholder(s) remain: $(echo "$_residual" | tr '\n' ' '). Refusing to install a broken hook."
fi

# ── File install (skipped on --dry-run; cron handled in 1b-ii) ────────────────
install_files() {
  mkdir -p "$HOOK_DIR" "$(dirname "$REPORT_DEST")" "$_LOG_DIR"
  printf '%s' "$HANDLER_OUT" > "$HOOK_DEST"
  printf '%s' "$REPORT_OUT" > "$REPORT_DEST"
  chmod +x "$REPORT_DEST"
  cp "$PATTERNS_SRC" "$PATTERNS_DEST"
  success "Installed hook:    $HOOK_DEST"
  success "Installed patterns:$PATTERNS_DEST"
  success "Installed report:  $REPORT_DEST"
}

# ── Cron wiring ─────────────────────────────────────────────────────────
# Idempotent: tag our line so re-runs replace (not duplicate). PATH prefix is
# CRITICAL — bare cron env lacks Homebrew, so python3/openclaw vanish. We prepend
# the Homebrew bin dir (+ the openclaw binary's own dir) to PATH on the cron line.
CRON_TAG="# dinotrust-observability:${OPT_AGENT}"
_BREW_BIN="/home/linuxbrew/.linuxbrew/bin"
_OC_DIR="$(dirname "$OPT_OPENCLAW_BIN")"
# Build a PATH that puts Homebrew + the openclaw dir first, then the existing PATH.
# De-dupe when the openclaw binary already lives in the Homebrew dir.
if [[ "$_OC_DIR" == "$_BREW_BIN" || "$_OC_DIR" == "." ]]; then
  CRON_PATH="${_BREW_BIN}:\$PATH"
else
  CRON_PATH="${_BREW_BIN}:${_OC_DIR}:\$PATH"
fi
# tz: crontab has no per-line TZ field portably; set CRON_TZ= on the line (Vixie/
# cronie support it). Harmless on crons that ignore it (falls back to host tz).
CRON_TZ_PREFIX=""
[[ -n "$OPT_REPORT_TZ" ]] && CRON_TZ_PREFIX="CRON_TZ=${OPT_REPORT_TZ} "
CRON_CMD="PATH=${CRON_PATH} python3 ${REPORT_DEST} --period daily >> ${_LOG_DIR}/${OPT_AGENT}-dinotrust-report.log 2>&1"
CRON_LINE="${CRON_TZ_PREFIX}${OPT_SCHEDULE} ${CRON_CMD} ${CRON_TAG}"

# Compute the merged crontab text WITHOUT installing (so --dry-run can show it).
# Read current crontab (empty if none), strip any prior line carrying our tag,
# then append the fresh line. Never clobbers unrelated entries.
_CURRENT_CRON="$(crontab -l 2>/dev/null || true)"
if [[ -n "$_CURRENT_CRON" ]]; then
  _MERGED_CRON="$(printf '%s\n' "$_CURRENT_CRON" | grep -vF "$CRON_TAG" || true)"
else
  _MERGED_CRON=""
fi
if [[ -n "$_MERGED_CRON" ]]; then
  _MERGED_CRON="${_MERGED_CRON}"$'\n'"${CRON_LINE}"
else
  _MERGED_CRON="${CRON_LINE}"
fi

install_cron() {
  printf '%s\n' "$_MERGED_CRON" | crontab -
  success "Cron wired: $OPT_SCHEDULE (tz: ${OPT_REPORT_TZ:-host}) — tag $CRON_TAG"
}

# ── Preflight: validate.py taxonomy drift guard ────────────────────────────
# If patterns.json rule_ids drift out of security_rules.md, the audit layer would
# report against rules that no longer exist (or miss new ones). Fail closed here.
if [[ -f "$VALIDATE_SRC" ]]; then
  info "Preflight: validating taxonomy (patterns.json ⊆ security_rules.md)..."
  if ! python3 "$VALIDATE_SRC"; then
    error "Taxonomy validation failed — patterns.json drifted from security_rules.md. Fix before installing."
  fi
  success "Taxonomy valid."
else
  warn "validate.py not found at $VALIDATE_SRC — skipping taxonomy preflight (cannot guarantee drift safety)."
fi

# ── Plan summary (shown for both dry-run and real apply) ────────────────────
print_plan() {
  echo ""
  echo "────────────────────────────────────────────────────────"
  echo -e "${BOLD}PLAN${NC} — dinotrust observability v${VERSION} for agent '${OPT_AGENT}'"
  echo "────────────────────────────────────────────────────────"
  echo "Files to write:"
  echo "  hook     : $HOOK_DEST"
  echo "  patterns : $PATTERNS_DEST"
  echo "  report   : $REPORT_DEST  (chmod +x)"
  echo ""
  echo "Substitutions:"
  echo "  handler.ts  __AGENT_FILTER__=$AGENT_FILTER_VAL"
  echo "              __ACTIVITY_LOG__=$OPT_ACTIVITY_LOG"
  echo "              __JAILBREAK_LOG__=$OPT_JAILBREAK_LOG"
  echo "              __PATTERNS_FILE__=$PATTERNS_DEST"
  echo "              __PRIVACY__=$OPT_PRIVACY"
  echo "  report.py   __ACTIVITY_LOG__=$OPT_ACTIVITY_LOG"
  echo "              __JAILBREAK_LOG__=$OPT_JAILBREAK_LOG"
  echo "              __CHANNEL__=$OPT_REPORT_CHANNEL"
  echo "              __TARGET__=$OPT_REPORT_TARGET"
  echo "              __THREAD_ID__=${OPT_REPORT_THREAD:-(empty)}"
  echo "              __ACCOUNT__=${OPT_REPORT_ACCOUNT:-(empty)}"
  echo ""
  echo "Cron line (merged into existing crontab, tag $CRON_TAG):"
  echo "  $CRON_LINE"
  echo ""
  if [[ "$ALREADY_INSTALLED" == "true" ]]; then
    warn "An existing install was detected (will be overwritten${OPT_FORCE:+ via --force})."
  fi
}

# ── Dry-run: print plan, change nothing ───────────────────────────────────
if [[ "$OPT_DRY_RUN" == "true" ]]; then
  print_plan
  echo ""
  warn "DRY RUN — no files written, crontab untouched."
  exit 0
fi

# ── Apply ─────────────────────────────────────────────────────────────
print_plan
echo ""
install_files
install_cron
# Ensure log files exist so the first hook write + first digest read don't race.
touch "$OPT_ACTIVITY_LOG" "$OPT_JAILBREAK_LOG"

echo ""
success "dinotrust observability v${VERSION} installed for agent '${OPT_AGENT}'."
echo ""
echo "  Hook     : $HOOK_DEST"
echo "  Report   : $REPORT_DEST"
echo "  Patterns : $PATTERNS_DEST"
echo "  Digest   : $OPT_SCHEDULE (tz ${OPT_REPORT_TZ:-host}) → $OPT_REPORT_CHANNEL:$OPT_REPORT_TARGET"
echo "  Privacy  : $OPT_PRIVACY"
echo ""
echo "Next: restart the agent so OpenClaw loads the new hook."
echo "Verify cron:  crontab -l | grep '$CRON_TAG'"
echo "Test digest:  python3 $REPORT_DEST --period daily --dry-run"
echo ""




