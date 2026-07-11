#!/usr/bin/env bash
# dinotrust manage-owner — add/remove/list owner IDs WITHOUT touching anything
# else in your setup.
#
# WHY THIS EXISTS: scripts/install.sh --force regenerates the ENTIRE injected
# instruction block from scratch (profile, protected_resources, deflection
# message, allowed_actions — everything), because it has no way to detect or
# preserve hand-edits you made to that block after install. If all you want is
# to add or remove a single owner, re-running the full installer risks
# silently discarding any customization. This script is the surgical
# alternative: it finds the existing `owner_ids:` line inside the injected
# block and replaces ONLY that line, in place. Everything else in the file
# (profile, protected_resources, deflection message, allowed_actions, and any
# hand-edits) is left byte-for-byte untouched.
#
# ENFORCE HOOK SYNC IS AUTOMATIC BY DEFAULT: this script also updates the
# separate enforce-hook config (openclaw.json plugin entry, or
# ~/.dinotrust/enforce.json on CLI runtimes) so both layers stay in sync in one
# command. It looks in the exact same two hardcoded locations enforce/install.sh
# itself always writes to (${HOME}/.openclaw/openclaw.json,
# ${HOME}/.dinotrust/enforce.json — that installer has no path-override flag
# either, there's only ever one of each per host). Pass --oc-json/--dt-conf to
# point at a nonstandard path instead, or --no-sync-enforce to skip the enforce
# side entirely (instruction layer only). The update is key-scoped (via the
# same merge_config.py install.sh uses for OpenClaw), backed up first, and
# never touches any other config key.
#
# LIMITATION: platform-scoped owner entries ({id, platforms:[...]}) are an
# instruction-layer-only concept. The enforce hook's ownerIds is a flat array
# with no scoping support — if you add a scoped entry, it goes into the synced
# enforce config as its bare id (unscoped there), and this script WARNS you
# that the two layers will disagree on that entry's platform restriction until
# the enforce hook itself supports scoping.
#
# NOTE: this is the owner-subject IMPLEMENTATION behind the unified front door
# scripts/manage-access.sh. Users normally invoke it as:
#   bash scripts/manage-access.sh owner <list|add|remove> ...
# The manage-access.sh dispatcher forwards `owner ...` here unchanged. Running
# this file directly still works (back-compat), but the documented entry point
# is manage-access.sh.
#
# Usage (via front door):
#   bash scripts/manage-access.sh owner list   [--config PATH]
#   bash scripts/manage-access.sh owner add    <id[@platform[+platform2]]> [--config PATH] [--oc-json PATH] [--dt-conf PATH] [--no-sync-enforce]
#   bash scripts/manage-access.sh owner remove <id> [--config PATH] [--oc-json PATH] [--dt-conf PATH] [--no-sync-enforce]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
ENFORCE_DIR="$REPO_DIR/enforce"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}ℹ${NC}  $*"; }
success() { echo -e "${GREEN}✓${NC}  $*"; }
warn()    { echo -e "${YELLOW}⚠${NC}  $*"; }
err()     { echo -e "${RED}✗${NC}  $*" >&2; }
error()   { err "$*"; exit 1; }

ACTION="${1:-}"; shift || true
[[ "$ACTION" != "list" && "$ACTION" != "add" && "$ACTION" != "remove" ]] && \
  error "Usage: manage-access.sh owner <list|add|remove> [id[@platform]] [--config PATH] [--oc-json PATH] [--dt-conf PATH] [--no-sync-enforce]"

ARG_ID=""
if [[ "$ACTION" != "list" ]]; then
  ARG_ID="${1:-}"; shift || true
  [[ -z "$ARG_ID" ]] && error "manage-access.sh owner $ACTION requires an id (e.g. 123456789 or 123456789@telegram)."
fi

OPT_CONFIG=""; OPT_SYNC_ENFORCE=true; OPT_OC_JSON=""; OPT_DT_CONF=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)           OPT_CONFIG="$2"; shift 2 ;;
    --no-sync-enforce)  OPT_SYNC_ENFORCE=false; shift ;;
    --oc-json)          OPT_OC_JSON="$2"; shift 2 ;;
    --dt-conf)          OPT_DT_CONF="$2"; shift 2 ;;
    *) error "Unknown option: $1" ;;
  esac
done

# ── Resolve the instruction-layer config file (same logic as install.sh) ─────
if [[ -n "$OPT_CONFIG" ]]; then
  CONFIG_FILE="$OPT_CONFIG"
else
  # Auto-detect a single existing dinotrust-injected file across known locations.
  CANDIDATES=()
  [[ -n "${OPENCLAW_WORKSPACE:-}" ]] && CANDIDATES+=("$OPENCLAW_WORKSPACE/AGENTS.md")
  while IFS= read -r ws; do
    [[ -n "$ws" ]] && CANDIDATES+=("${ws%/}/AGENTS.md")
  done < <(ls -d "$HOME/.openclaw/workspace-"*/ 2>/dev/null || true)
  CANDIDATES+=("$HOME/.claude/CLAUDE.md" "./CLAUDE.md" "$HOME/.codex/AGENTS.md" "./AGENTS.md" "$HOME/.hermes/SOUL.md")

  FOUND=()
  for c in "${CANDIDATES[@]}"; do
    [[ -f "$c" ]] && grep -q "dinotrust begin" "$c" 2>/dev/null && FOUND+=("$c")
  done
  # De-dupe
  mapfile -t FOUND < <(printf '%s\n' "${FOUND[@]}" | awk '!seen[$0]++')

  if [[ ${#FOUND[@]} -eq 0 ]]; then
    error "No dinotrust-injected config file found. Pass --config PATH explicitly."
  elif [[ ${#FOUND[@]} -gt 1 ]]; then
    warn "Multiple dinotrust-injected files found:"
    for f in "${FOUND[@]}"; do echo "    $f"; done
    error "Pass --config PATH to pick one."
  fi
  CONFIG_FILE="${FOUND[0]}"
fi

[[ -f "$CONFIG_FILE" ]] || error "Config file not found: $CONFIG_FILE"
grep -q "dinotrust begin" "$CONFIG_FILE" || error "No dinotrust block found in $CONFIG_FILE. Run scripts/install.sh first."

info "Config file: $CONFIG_FILE"

# Extract the current owner_ids: line's array content (the block after 'owner_ids:'
# up to the closing bracket on the same line — install.sh always emits it as a
# single-line inline YAML array).
CURRENT_LINE=$(grep -n "^\s*owner_ids:" "$CONFIG_FILE" | head -1)
[[ -z "$CURRENT_LINE" ]] && error "Could not find 'owner_ids:' line in the dinotrust block. The block may be malformed — check $CONFIG_FILE manually."
LINE_NUM="${CURRENT_LINE%%:*}"
CURRENT_ARR=$(echo "$CURRENT_LINE" | sed 's/^[0-9]*:\s*owner_ids:\s*//')

if [[ "$ACTION" == "list" ]]; then
  echo ""
  info "Current owner_ids: $CURRENT_ARR"
  exit 0
fi

# Parse the current array (python does the heavy lifting — bash YAML parsing
# for the {id, platforms} object form is not worth hand-rolling).
NEW_ARR=$(python3 - "$CURRENT_ARR" "$ACTION" "$ARG_ID" <<'PY'
import sys, re, json

current, action, arg = sys.argv[1], sys.argv[2], sys.argv[3]

# The array is a restricted YAML-ish inline list: bare ids or {id: X, platforms: [a, b]}.
# Convert to JSON-parseable form: unquoted keys -> quoted, bare ids stay numbers/strings.
def to_json(s):
    s = s.strip()
    s = re.sub(r'(\bid\b|\bplatforms\b)\s*:', r'"\1":', s)
    def quote_bare(tok):
        if tok in ('[', ']', '{', '}', ',') or re.match(r'^-?\d+$', tok) or tok.startswith('"'):
            return tok
        return f'"{tok}"'
    out = []
    buf = ""
    for ch in s:
        if ch in '[]{}, :':
            if buf:
                out.append(quote_bare(buf))
                buf = ""
            out.append(ch)
        else:
            buf += ch
    if buf:
        out.append(quote_bare(buf))
    return "".join(out)

try:
    arr = json.loads(to_json(current))
except Exception as e:
    sys.stderr.write(f"PARSE_ERROR: could not parse existing owner_ids array: {e}\n")
    sys.stderr.write(f"Raw: {current}\n")
    sys.exit(1)

if not isinstance(arr, list):
    sys.stderr.write("PARSE_ERROR: owner_ids is not a list\n")
    sys.exit(1)

def entry_id(e):
    return str(e["id"]) if isinstance(e, dict) else str(e)

if action == "add":
    if "@" in arg:
        oid, plats = arg.split("@", 1)
        plat_list = [p.strip() for p in plats.split("+") if p.strip()]
        new_entry = {"id": oid.strip(), "platforms": plat_list}
        if plat_list:
            sys.stderr.write(f"SCOPED_WARN: owner '{oid}' scoped to platform(s) {plat_list}. "
                              f"NOTE: the enforce hook's own ownerIds config does NOT support platform "
                              f"scoping (flat array only) -- this id goes in UNSCOPED there, so on the "
                              f"enforce layer it's owner on ANY platform, not just {plat_list}. Only the "
                              f"instruction layer honors the scope restriction.\n")
    else:
        new_entry = arg.strip()
    existing_ids = {entry_id(e) for e in arr}
    add_id = entry_id(new_entry) if isinstance(new_entry, dict) else str(new_entry)
    if add_id in existing_ids:
        sys.stderr.write(f"NOOP: '{add_id}' is already an owner. No change.\n")
        print(json.dumps(arr))
        sys.exit(3)
    arr.append(new_entry)
elif action == "remove":
    before = len(arr)
    arr = [e for e in arr if entry_id(e) != str(arg)]
    if len(arr) == before:
        sys.stderr.write(f"NOOP: '{arg}' is not in owner_ids. No change.\n")
        print(json.dumps(arr))
        sys.exit(3)
    if len(arr) == 0:
        sys.stderr.write("REFUSED: removing this id would leave ZERO owners. At least one owner is required.\n")
        sys.exit(4)

# Re-render as the same inline-YAML style install.sh uses: bare ids unquoted,
# scoped entries as {id: X, platforms: [a, b]}.
def render(e):
    if isinstance(e, dict):
        plats = ", ".join(str(p) for p in e.get("platforms", []))
        return f'{{id: {e["id"]}, platforms: [{plats}]}}'
    return str(e)

print("[" + ", ".join(render(e) for e in arr) + "]")
PY
)
PY_EXIT=$?
if [[ $PY_EXIT -eq 3 ]]; then
  info "No change needed."
  exit 0
elif [[ $PY_EXIT -eq 4 ]]; then
  error "Cannot remove the last remaining owner. Add a new owner first, or edit the file manually if this is intentional (e.g. transferring to a fresh install)."
elif [[ $PY_EXIT -ne 0 ]]; then
  error "Failed to parse/update owner_ids. See error above. Edit $CONFIG_FILE manually if needed (owner_ids: line $LINE_NUM)."
fi

# ── Backup + apply the single-line edit ───────────────────────────────────────
BACKUP_FILE="${CONFIG_FILE}.dinotrust-bak.$(date -u +%Y%m%d-%H%M%S)"
cp "$CONFIG_FILE" "$BACKUP_FILE"
info "Backed up $CONFIG_FILE → $BACKUP_FILE"

# Preserve original leading whitespace of the owner_ids: line.
INDENT=$(sed -n "${LINE_NUM}p" "$CONFIG_FILE" | sed 's/owner_ids:.*//')
TMPFILE=$(mktemp)
awk -v ln="$LINE_NUM" -v indent="$INDENT" -v newarr="$NEW_ARR" \
  'NR==ln { print indent "owner_ids: " newarr; next } { print }' \
  "$CONFIG_FILE" > "$TMPFILE"
mv "$TMPFILE" "$CONFIG_FILE"

success "owner_ids updated in $CONFIG_FILE:"
echo "    $NEW_ARR"
echo ""
echo "  Nothing else in the file was touched (profile, protected_resources,"
echo "  deflection message, allowed_actions, and any hand-edits are preserved)."

# ── Enforce hook's own ownerIds config — auto-synced by default ─────────────
# enforce/install.sh itself hardcodes these exact two paths with no override
# flag at all (${HOME}/.openclaw/openclaw.json, ${HOME}/.dinotrust/enforce.json)
# -- there's only ever one of each per host, same convention the rest of
# dinotrust already assumes. Auto-syncing whichever one exists here isn't a
# guess, it's matching that same default. --oc-json/--dt-conf remain as
# overrides for a nonstandard path; --no-sync-enforce opts out entirely.

# Build a flat unscoped array for the enforce hook (it has no platform-scoping
# concept). Extract just the bare ids from NEW_ARR.
ENFORCE_OWNERS=$(python3 - "$NEW_ARR" <<'PY'
import sys, json, re
def to_json(s):
    s = s.strip()
    s = re.sub(r'(\bid\b|\bplatforms\b)\s*:', r'"\1":', s)
    out, buf = [], ""
    for ch in s:
        if ch in '[]{}, :':
            if buf:
                out.append(buf if (buf in ('[',']','{','}',',') or re.match(r'^-?\d+$', buf) or buf.startswith('"')) else f'"{buf}"')
                buf = ""
            out.append(ch)
        else:
            buf += ch
    if buf:
        out.append(buf if re.match(r'^-?\d+$', buf) else f'"{buf}"')
    return "".join(out)
arr = json.loads(to_json(sys.argv[1]))
flat = [str(e["id"]) if isinstance(e, dict) else str(e) for e in arr]
print(json.dumps(flat))
PY
)

if [[ "$OPT_SYNC_ENFORCE" == "false" ]]; then
  echo ""
  info "Enforce hook NOT synced (--no-sync-enforce passed)."
  echo "  If you run the enforce layer, update it to match:"
  echo "    OpenClaw:     plugins.entries.\"dinotrust-enforce\".config.ownerIds = $ENFORCE_OWNERS"
  echo "                  in your openclaw.json, then: openclaw gateway restart"
  echo "    CLI runtime:  ownerIds in ~/.dinotrust/enforce.json = $ENFORCE_OWNERS"
  echo ""
  success "Done. $ACTION applied for owner: $ARG_ID (instruction layer only)"
  exit 0
fi

# Resolve paths: explicit --oc-json/--dt-conf override, else the same defaults
# enforce/install.sh itself hardcodes.
[[ -z "$OPT_OC_JSON" ]] && OPT_OC_JSON="${HOME}/.openclaw/openclaw.json"
[[ -z "$OPT_DT_CONF" ]] && OPT_DT_CONF="${HOME}/.dinotrust/enforce.json"

SYNCED_ENFORCE=false
FOUND_ANY_ENFORCE_CONFIG=false

if [[ -f "$OPT_OC_JSON" ]] && grep -q '"dinotrust-enforce"' "$OPT_OC_JSON" 2>/dev/null; then
  FOUND_ANY_ENFORCE_CONFIG=true
  info "Syncing enforce hook config (ownerIds only — no other keys touched)..."
  OC_JSON="$OPT_OC_JSON"
  # Read existing nonOwnerAllowedScripts/module/agentFilter/enforce so merge_config.py
  # (which requires them as env) doesn't reset them.
  EXIST=$(python3 - "$OC_JSON" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
entry = data.get("plugins", {}).get("entries", {}).get("dinotrust-enforce", {})
cfg = entry.get("config", {})
print(entry.get("module", ""))
print(json.dumps(cfg.get("nonOwnerAllowedScripts", [])))
print("true" if cfg.get("enforce", True) else "false")
print(cfg.get("agentFilter", ""))
PY
)
  MODULE=$(echo "$EXIST" | sed -n 1p)
  SCRIPTS_ARR=$(echo "$EXIST" | sed -n 2p)
  ENFORCE_FLAG=$(echo "$EXIST" | sed -n 3p)
  AGENTF=$(echo "$EXIST" | sed -n 4p)
  OC_BACKUP="${OC_JSON}.dinotrust-bak.$(date -u +%Y%m%d-%H%M%S)"
  cp "$OC_JSON" "$OC_BACKUP"
  if OC_JSON="$OC_JSON" MODULE="$MODULE" OWNERS="$ENFORCE_OWNERS" SCRIPTS="$SCRIPTS_ARR" \
     ENFORCE="$ENFORCE_FLAG" AGENTF="$AGENTF" \
     python3 "$ENFORCE_DIR/adapters/openclaw/merge_config.py"; then
    success "Enforce hook (OpenClaw): ownerIds synced in $OC_JSON. Backup: $OC_BACKUP"
    warn "Restart required for the enforce hook to pick this up: openclaw gateway restart"
    SYNCED_ENFORCE=true
  else
    warn "Auto-sync to $OC_JSON failed. Manually update plugins.entries.\"dinotrust-enforce\".config.ownerIds to: $ENFORCE_OWNERS"
    rm -f "$OC_BACKUP" 2>/dev/null || true
  fi
fi

if [[ -f "$OPT_DT_CONF" ]]; then
  FOUND_ANY_ENFORCE_CONFIG=true
  info "Syncing enforce hook config (ownerIds only — no other keys touched)..."
  DT_CONF="$OPT_DT_CONF"
  DT_BACKUP="${DT_CONF}.dinotrust-bak.$(date -u +%Y%m%d-%H%M%S)"
  cp "$DT_CONF" "$DT_BACKUP"
  if python3 - "$DT_CONF" "$ENFORCE_OWNERS" <<'PY'
import json, sys
conf, owners = sys.argv[1], sys.argv[2]
with open(conf) as f:
    data = json.load(f)
data["ownerIds"] = json.loads(owners)
with open(conf, "w") as f:
    json.dump(data, f, indent=2)
PY
  then
    success "Enforce hook (CLI runtime): ownerIds synced in $DT_CONF. Backup: $DT_BACKUP"
    SYNCED_ENFORCE=true
  else
    warn "Auto-sync to $DT_CONF failed. Manually update ownerIds to: $ENFORCE_OWNERS"
    rm -f "$DT_BACKUP" 2>/dev/null || true
  fi
fi

if [[ "$FOUND_ANY_ENFORCE_CONFIG" == "false" ]]; then
  echo ""
  info "No enforce hook config found at ${OPT_OC_JSON} or ${OPT_DT_CONF} — nothing to sync."
  echo "  If you haven't installed the enforce layer, this is expected (instruction layer only)."
  echo "  If it lives somewhere nonstandard, pass --oc-json PATH or --dt-conf PATH."
fi

if [[ "$SYNCED_ENFORCE" == "false" && "$FOUND_ANY_ENFORCE_CONFIG" == "true" ]]; then
  warn "Enforce hook sync did not complete (see errors above). New value if you need it manually: $ENFORCE_OWNERS"
fi

echo ""
success "Done. $ACTION applied for owner: $ARG_ID"
