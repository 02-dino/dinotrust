#!/usr/bin/env bash
# dinotrust manage-trusted — add/remove/list/show trusted (delegated) ids.
#
# WHAT THIS IS: a THIRD tier, ABOVE non-owner, BELOW owner. Each trusted id is
# independently configured (no shared named roles) with any combination of:
#   --tools   extra tool allowlist beyond the non-owner default (e.g. write,edit,exec)
#   --scripts exec allowlist for this id specifically (falls back to the shared
#             nonOwnerAllowedScripts if omitted)
#   --scope   path glob confinement -- ANY call touching a path must match one
#             of these globs or it's blocked outright ("not your workspace").
#             Omit for a pure tool-allowlist grant with no path restriction.
#
# THE CEILING (always enforced, no override, this is what keeps it below owner):
#   - protectedGlobs (secrets, other agents' configs, this repo's own security
#     files, etc.) are STILL hard-blocked even inside a trusted id's own scope.
#   - critical/irreversible actions are BLOCKED for trusted, never auto-approved
#     the way an owner's critical action becomes an "are you sure?" prompt.
# See enforce/core/policy.ts TrustedEntry doc comment for the full semantics.
#
# WHERE THIS LIVES: unlike owner_ids (which has a dual instruction-layer +
# enforce-layer store), trustedIds is ENFORCE-LAYER ONLY -- it's a purely
# code-enforced allowlist mechanism, not an identity/ownership claim, so there's
# no instruction-layer copy to keep in sync (see security_rules.md trusted_rules
# for why). This script edits ONLY the enforce hook's own config: the
# openclaw.json plugin entry, or ~/.dinotrust/enforce.json on CLI runtimes --
# auto-detected the same way manage-owner.sh finds them (same two hardcoded
# paths enforce/install.sh itself always writes to), or point at a nonstandard
# path with --oc-json/--dt-conf.
#
# Usage:
#   bash scripts/manage-trusted.sh list
#   bash scripts/manage-trusted.sh show   <id>
#   bash scripts/manage-trusted.sh add    <id> [--tools t1,t2,...] [--scripts s1,s2,...] [--scope glob1,glob2,...] [--oc-json PATH] [--dt-conf PATH]
#   bash scripts/manage-trusted.sh remove <id> [--oc-json PATH] [--dt-conf PATH]
#
# Examples:
#   bash scripts/manage-trusted.sh add 555555 --scope "workspace-bob/**"
#     # delegated admin of their own workspace folder only, default trusted tool set inside it
#   bash scripts/manage-trusted.sh add 666666 --tools read,write --scripts exchange_data
#     # extra tool access, no path restriction (their own risk surface is just those tools)
#   bash scripts/manage-trusted.sh remove 555555
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

USAGE="Usage: manage-trusted.sh <list|show|add|remove> [id] [--tools t1,t2,...] [--scripts s1,s2,...] [--scope glob1,glob2,...] [--oc-json PATH] [--dt-conf PATH]"

ACTION="${1:-}"; shift || true
[[ "$ACTION" != "list" && "$ACTION" != "show" && "$ACTION" != "add" && "$ACTION" != "remove" ]] && \
  error "$USAGE"

ARG_ID=""
if [[ "$ACTION" != "list" ]]; then
  ARG_ID="${1:-}"; shift || true
  [[ -z "$ARG_ID" ]] && error "manage-trusted.sh $ACTION requires an id (e.g. 123456789)."
fi

OPT_TOOLS=""; OPT_SCRIPTS=""; OPT_SCOPE=""; OPT_OC_JSON=""; OPT_DT_CONF=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tools)    OPT_TOOLS="$2"; shift 2 ;;
    --scripts)  OPT_SCRIPTS="$2"; shift 2 ;;
    --scope)    OPT_SCOPE="$2"; shift 2 ;;
    --oc-json)  OPT_OC_JSON="$2"; shift 2 ;;
    --dt-conf)  OPT_DT_CONF="$2"; shift 2 ;;
    *) error "Unknown option: $1" ;;
  esac
done

# ── Resolve the enforce config file: explicit override, else the same defaults
# enforce/install.sh itself hardcodes (only one of each per host). ─────────────
[[ -z "$OPT_OC_JSON" ]] && OPT_OC_JSON="${HOME}/.openclaw/openclaw.json"
[[ -z "$OPT_DT_CONF" ]] && OPT_DT_CONF="${HOME}/.dinotrust/enforce.json"

HAS_OC=false; HAS_DT=false
[[ -f "$OPT_OC_JSON" ]] && grep -q '"dinotrust-enforce"' "$OPT_OC_JSON" 2>/dev/null && HAS_OC=true
[[ -f "$OPT_DT_CONF" ]] && HAS_DT=true

if [[ "$HAS_OC" == "false" && "$HAS_DT" == "false" ]]; then
  error "No enforce hook config found at $OPT_OC_JSON or $OPT_DT_CONF. Run enforce/install.sh first, or pass --oc-json/--dt-conf to point at a nonstandard path."
fi
if [[ "$HAS_OC" == "true" && "$HAS_DT" == "true" ]]; then
  warn "Both an OpenClaw config ($OPT_OC_JSON) and a CLI-runtime config ($OPT_DT_CONF) were found."
  warn "This host runs both adapter types. Updating BOTH so they stay in sync."
fi

# ── list / show: read-only, just print current trustedIds from whichever store(s) exist ──
if [[ "$ACTION" == "list" || "$ACTION" == "show" ]]; then
  if [[ "$HAS_OC" == "true" ]]; then
    info "OpenClaw ($OPT_OC_JSON):"
    python3 - "$OPT_OC_JSON" "$ACTION" "$ARG_ID" <<'PY'
import json, sys
path, action, filter_id = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f:
    data = json.load(f)
entries = data.get("plugins", {}).get("entries", {}).get("dinotrust-enforce", {}).get("config", {}).get("trustedIds", [])
if action == "show":
    entries = [e for e in entries if str(e.get("id")) == filter_id]
    if not entries:
        print(f"    (no trusted entry for id {filter_id})")
if not entries and action == "list":
    print("    (none)")
for e in entries:
    print(f"    id={e.get('id')}  tools={e.get('allowedTools', '(default)')}  scripts={e.get('allowedScripts', '(shared default)')}  scope={e.get('scopePathGlobs', '(none - unrestricted paths)')}")
PY
  fi
  if [[ "$HAS_DT" == "true" ]]; then
    info "CLI runtime ($OPT_DT_CONF):"
    python3 - "$OPT_DT_CONF" "$ACTION" "$ARG_ID" <<'PY'
import json, sys
path, action, filter_id = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f:
    data = json.load(f)
entries = data.get("trustedIds", [])
if action == "show":
    entries = [e for e in entries if str(e.get("id")) == filter_id]
    if not entries:
        print(f"    (no trusted entry for id {filter_id})")
if not entries and action == "list":
    print("    (none)")
for e in entries:
    print(f"    id={e.get('id')}  tools={e.get('allowedTools', '(default)')}  scripts={e.get('allowedScripts', '(shared default)')}  scope={e.get('scopePathGlobs', '(none - unrestricted paths)')}")
PY
  fi
  exit 0
fi

# ── add / remove: build the new entry (or removal), apply to each existing store ──
csv_to_json_array() {
  # "a,b,c" -> ["a","b","c"]; "" -> null (omit the key)
  local csv="$1"
  [[ -z "$csv" ]] && { echo "null"; return; }
  python3 -c "import json,sys; print(json.dumps([s.strip() for s in sys.argv[1].split(',') if s.strip()]))" "$csv"
}

if [[ "$ACTION" == "add" ]]; then
  TOOLS_JSON=$(csv_to_json_array "$OPT_TOOLS")
  SCRIPTS_JSON=$(csv_to_json_array "$OPT_SCRIPTS")
  SCOPE_JSON=$(csv_to_json_array "$OPT_SCOPE")
  if [[ "$TOOLS_JSON" == "null" && "$SCRIPTS_JSON" == "null" && "$SCOPE_JSON" == "null" ]]; then
    info "No --tools/--scripts/--scope given: this id gets the DEFAULT_TRUSTED_TOOLS set (read/write/edit/apply_patch/exec/web_search/web_fetch/browser/memory_search/memory_get), the shared nonOwnerAllowedScripts, and NO path restriction (any path allowed for allowed tools)."
  fi
fi

apply_to_store() {
  local store_kind="$1" store_path="$2"
  local backup="${store_path}.dinotrust-bak.$(date -u +%Y%m%d-%H%M%S)"
  cp "$store_path" "$backup"

  local rc=0
  if [[ "$store_kind" == "oc" ]]; then
    python3 - "$store_path" "$ACTION" "$ARG_ID" "${TOOLS_JSON:-null}" "${SCRIPTS_JSON:-null}" "${SCOPE_JSON:-null}" <<'PY' && rc=0 || rc=$?
import json, sys
path, action, arg_id, tools_j, scripts_j, scope_j = sys.argv[1:7]
with open(path) as f:
    data = json.load(f)
entry = data.setdefault("plugins", {}).setdefault("entries", {}).setdefault("dinotrust-enforce", {})
cfg = entry.setdefault("config", {})
trusted = cfg.get("trustedIds", [])
if not isinstance(trusted, list):
    trusted = []

if action == "remove":
    before = len(trusted)
    trusted = [e for e in trusted if str(e.get("id")) != arg_id]
    if len(trusted) == before:
        sys.stderr.write(f"NOOP: '{arg_id}' is not a trusted id. No change.\n")
        sys.exit(3)
else:  # add
    trusted = [e for e in trusted if str(e.get("id")) != arg_id]  # replace if exists
    new_entry = {"id": arg_id}
    if tools_j != "null":
        new_entry["allowedTools"] = json.loads(tools_j)
    if scripts_j != "null":
        new_entry["allowedScripts"] = json.loads(scripts_j)
    if scope_j != "null":
        new_entry["scopePathGlobs"] = json.loads(scope_j)
    trusted.append(new_entry)

cfg["trustedIds"] = trusted
entry["config"] = cfg
with open(path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
  else  # dt
    python3 - "$store_path" "$ACTION" "$ARG_ID" "${TOOLS_JSON:-null}" "${SCRIPTS_JSON:-null}" "${SCOPE_JSON:-null}" <<'PY' && rc=0 || rc=$?
import json, sys
path, action, arg_id, tools_j, scripts_j, scope_j = sys.argv[1:7]
with open(path) as f:
    data = json.load(f)
trusted = data.get("trustedIds", [])
if not isinstance(trusted, list):
    trusted = []

if action == "remove":
    before = len(trusted)
    trusted = [e for e in trusted if str(e.get("id")) != arg_id]
    if len(trusted) == before:
        sys.stderr.write(f"NOOP: '{arg_id}' is not a trusted id. No change.\n")
        sys.exit(3)
else:  # add
    trusted = [e for e in trusted if str(e.get("id")) != arg_id]
    new_entry = {"id": arg_id}
    if tools_j != "null":
        new_entry["allowedTools"] = json.loads(tools_j)
    if scripts_j != "null":
        new_entry["allowedScripts"] = json.loads(scripts_j)
    if scope_j != "null":
        new_entry["scopePathGlobs"] = json.loads(scope_j)
    trusted.append(new_entry)

data["trustedIds"] = trusted
with open(path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
  fi
  if [[ $rc -eq 3 ]]; then
    info "No change needed for $store_path."
    rm -f "$backup"
    return 0
  elif [[ $rc -ne 0 ]]; then
    warn "Failed to update $store_path. Backup untouched at $backup. See error above."
    return 1
  fi
  success "$store_path updated. Backup: $backup"
  return 0
}

ANY_APPLIED=false
if [[ "$HAS_OC" == "true" ]]; then
  apply_to_store "oc" "$OPT_OC_JSON" && ANY_APPLIED=true
  warn "Restart required for the enforce hook to pick this up: openclaw gateway restart"
fi
if [[ "$HAS_DT" == "true" ]]; then
  apply_to_store "dt" "$OPT_DT_CONF" && ANY_APPLIED=true
fi

echo ""
if [[ "$ANY_APPLIED" == "true" ]]; then
  success "Done. $ACTION applied for trusted id: $ARG_ID"
else
  warn "Nothing was applied. See messages above."
fi
