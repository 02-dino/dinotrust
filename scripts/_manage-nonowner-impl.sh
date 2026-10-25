#!/usr/bin/env bash
# dinotrust manage-access nonowner — manage the DEFAULT public tier.
#
# WHY THIS EXISTS (measured 2026-10-24): owner and trusted both had a managed
# front door; the non-owner tier had NONE. Changing what the public tier may do
# meant re-running install.sh with a --profile (which re-templates the whole
# ruleset and can clobber hand-hardening) or hand-editing JSON. So the single
# most frequently tuned surface was the only one with no safe way to tune it.
#
# Edits ONLY the enforce hook's own config — the same two stores the trusted
# subject writes (openclaw.json plugin entry, or ~/.dinotrust/enforce.json on CLI
# runtimes). No instruction-layer copy: this is a code-enforced allowlist.
#
#   nonowner list
#   nonowner add-tool <name>      nonowner remove-tool <name>
#   nonowner add-script <name>    nonowner remove-script <name>
#
# TOOLS vs SCRIPTS — different questions, do not mix them up:
#   tools   = tool NAMES the gate lets a non-owner call at all (read, web_fetch).
#   scripts = the exec allowlist: which .py files `exec` may invoke. Adding
#             `exec` as a TOOL is not what grants this; the script list is
#             consulted separately and is what actually opens a command.
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}ℹ${NC}  $*"; }
success() { echo -e "${GREEN}✓${NC}  $*"; }
warn()    { echo -e "${YELLOW}⚠${NC}  $*"; }
err()     { echo -e "${RED}✗${NC}  $*" >&2; }
error()   { err "$*"; exit 1; }

USAGE="Usage: manage-access.sh nonowner <list|add-tool|remove-tool|add-script|remove-script> [name] [--oc-json PATH] [--dt-conf PATH] [--force]"

ACTION="${1:-}"; shift || true
ARG_NAME=""
case "$ACTION" in
  list) ;;
  add-tool|remove-tool|add-script|remove-script)
    ARG_NAME="${1:-}"; shift || true
    [[ -z "$ARG_NAME" ]] && error "manage-access.sh nonowner $ACTION requires a name (e.g. image, yt_dlp_tool)."
    ;;
  ""|-h|--help) echo "$USAGE"; exit 0 ;;
  *) error "Unknown action '$ACTION'. $USAGE" ;;
esac

OPT_OC_JSON=""; OPT_DT_CONF=""; OPT_FORCE=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --oc-json) OPT_OC_JSON="$2"; shift 2 ;;
    --dt-conf) OPT_DT_CONF="$2"; shift 2 ;;
    --force)   OPT_FORCE=true; shift ;;
    *) error "Unknown option: $1" ;;
  esac
done

command -v python3 >/dev/null 2>&1 || error "python3 required."

# Same resolution ladder the trusted subject uses, plus OPENCLAW_CONFIG so this
# works on a multi-gateway box without needing the flag every time.
[[ -z "$OPT_OC_JSON" ]] && OPT_OC_JSON="${OPENCLAW_CONFIG:-${HOME}/.openclaw/openclaw.json}"
[[ -z "$OPT_DT_CONF" ]] && OPT_DT_CONF="${HOME}/.dinotrust/enforce.json"

HAS_OC=false; HAS_DT=false
[[ -f "$OPT_OC_JSON" ]] && grep -q '"dinotrust-enforce"' "$OPT_OC_JSON" 2>/dev/null && HAS_OC=true
[[ -f "$OPT_DT_CONF" ]] && HAS_DT=true
if [[ "$HAS_OC" == "false" && "$HAS_DT" == "false" ]]; then
  error "No enforce hook config found at $OPT_OC_JSON or $OPT_DT_CONF. Run enforce/install.sh first, or pass --oc-json/--dt-conf."
fi
[[ "$HAS_OC" == "true" && "$HAS_DT" == "true" ]] && \
  warn "Both store types found — updating BOTH so they stay in sync."

# ── Safety gate on TOOL grants ───────────────────────────────────────────────
# These tool names are the mutating set the gate blocks for non-owners by
# default. Allowlisting one hands the public tier write/exec reach in one word,
# with no path scope and no per-command review — a far bigger grant than it
# looks while typing. Require an explicit --force so it can never be a slip.
MUTATING_TOOLS="exec write edit apply_patch"
if [[ "$ACTION" == "add-tool" ]] && [[ " $MUTATING_TOOLS " == *" $ARG_NAME "* ]] && ! $OPT_FORCE; then
  err "Refusing to grant '$ARG_NAME' to the non-owner tier without --force."
  err "That is a MUTATING tool: it gives every non-owner write/exec reach with no path scope."
  if [[ "$ARG_NAME" == "exec" ]]; then
    err "If you only want one command to run, add it to the SCRIPT list instead:"
    err "  manage-access.sh nonowner add-script <script_name>"
  fi
  exit 1
fi

apply_to_store() {
  local kind="$1" path="$2"
  cp "$path" "${path}.dinotrust-bak.$(date -u +%Y%m%d-%H%M%S)" 2>/dev/null || true
  KIND="$kind" ACTION="$ACTION" NAME="$ARG_NAME" python3 - "$path" <<'PY'
import json, os, sys
path = sys.argv[1]
kind, action, name = os.environ["KIND"], os.environ["ACTION"], os.environ["NAME"]
with open(path) as f:
    data = json.load(f)
if kind == "oc":
    cfg = (data.setdefault("plugins", {}).setdefault("entries", {})
               .setdefault("dinotrust-enforce", {}).setdefault("config", {}))
else:
    cfg = data
key = "nonOwnerAllowedTools" if action.endswith("-tool") else "nonOwnerAllowedScripts"
cur = cfg.get(key)
if not isinstance(cur, list):
    cur = []
if action.startswith("add-"):
    if name in cur:
        print(f"UNCHANGED {key}: '{name}' already present"); sys.exit(0)
    cur.append(name)
    verb = "added"
else:
    if name not in cur:
        print(f"UNCHANGED {key}: '{name}' not present"); sys.exit(0)
    cur = [x for x in cur if x != name]
    verb = "removed"
cfg[key] = cur
with open(path, "w") as f:
    json.dump(data, f, indent=2); f.write("\n")
print(f"OK {verb} '{name}' -> {key} (now {len(cur)}: {', '.join(cur) or '<empty>'})")
PY
}

print_store() {
  local kind="$1" path="$2"
  KIND="$kind" python3 - "$path" <<'PY'
import json, os, sys
path = sys.argv[1]
with open(path) as f:
    data = json.load(f)
cfg = (data.get("plugins", {}).get("entries", {}).get("dinotrust-enforce", {}).get("config", {})
       if os.environ["KIND"] == "oc" else data)
scripts = cfg.get("nonOwnerAllowedScripts") or []
for key, label in (("nonOwnerAllowedTools", "tools  "), ("nonOwnerAllowedScripts", "scripts")):
    vals = cfg.get(key) or []
    print(f"    {label}: {', '.join(str(v) for v in vals) if vals else '(none — nothing granted)'}")

# WHO ACTUALLY RECEIVES THE SCRIPT LIST. A trusted entry that sets its own
# allowedScripts is CUT OFF from this list permanently -- the engine does
# `entry.allowedScripts ?? global`, which is override, not merge. Measured
# 2026-10-25: two ids sat out a fleet-wide grant for exactly this reason, and
# nothing in any list output would have shown it. Adding to the global list is
# the natural next action after reading this screen, so the exception belongs
# ON this screen -- otherwise the operator walks away believing it applied.
cut = [e for e in (cfg.get("trustedIds") or [])
       if isinstance(e, dict) and e.get("allowedScripts") is not None]
if cut:
    print()
    print("    ⚠ these trusted ids do NOT inherit the script list above:")
    for e in cut:
        own = e.get("allowedScripts") or []
        missing = [s for s in scripts if s not in own]
        print(f"      {e.get('id')}: has [{', '.join(own) or 'empty'}]")
        if missing:
            print(f"        missing: {', '.join(missing)}")
            print(f"        fix: manage-access.sh trusted add {e.get('id')} "
                  f"--add-scripts {','.join(missing)}")
PY
}

if [[ "$ACTION" == "list" ]]; then
  echo ""
  echo -e "${BOLD}non-owner tier${NC} — what the public/default tier may do"
  $HAS_OC && { info "OpenClaw ($OPT_OC_JSON):"; print_store oc "$OPT_OC_JSON"; }
  $HAS_DT && { info "CLI runtime ($OPT_DT_CONF):"; print_store dt "$OPT_DT_CONF"; }
  echo ""
  echo "  tools   = tool names a non-owner may call at all"
  echo "  scripts = which .py files 'exec' may invoke (consulted separately)"
  exit 0
fi

rc=0
$HAS_OC && { out=$(apply_to_store oc "$OPT_OC_JSON") || rc=$?; echo "  $out"; }
$HAS_DT && { out=$(apply_to_store dt "$OPT_DT_CONF") || rc=$?; echo "  $out"; }
[[ $rc -ne 0 ]] && error "Update failed (backup left beside the config)."

if [[ "$ACTION" == "add-script" ]]; then
  # The gate matches an allowlist key as <key>.py OR <key><suffix>.py, so a short
  # key quietly admits every sibling sharing that prefix. Measured: key 'yt_dlp'
  # also matches a stranger 'yt_dlp_evil.py' dropped in the same directory.
  info "Key '$ARG_NAME' matches ${ARG_NAME}.py AND ${ARG_NAME}<suffix>.py."
  info "Use the FULL filename stem (e.g. yt_dlp_tool, not yt_dlp) unless you intend that family."
fi
success "Done. Restart the gateway to load the change."
