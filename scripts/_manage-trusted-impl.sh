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
#   --allow-scoped-critical / --no-scoped-critical
#             OPT-IN (default OFF): let this id run critical/irreversible EXEC
#             (rm -rf, --hard ...) INSIDE its own --scope. Requires --scope: a
#             grant with no jail grants nothing. Without it a PIC cannot clear
#             their own build dir, so they work around the gate instead (`rm -fr`
#             is not matched by an `rm -rf` pattern) -- illusory control for the
#             owner, random friction for the karyawan.
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
# auto-detected the same way the owner subject finds them (same two hardcoded
# paths enforce/install.sh itself always writes to), or point at a nonstandard
# path with --oc-json/--dt-conf.
#
# NOTE: this is the trusted-subject IMPLEMENTATION behind the unified front door
# scripts/manage-access.sh. Users normally invoke it as:
#   bash scripts/manage-access.sh trusted <list|show|add|remove> ...
# The manage-access.sh dispatcher forwards `trusted ...` here unchanged. Running
# this file directly still works (back-compat), but the documented entry point
# is manage-access.sh.
#
# Usage (via front door):
#   bash scripts/manage-access.sh trusted list
#   bash scripts/manage-access.sh trusted show   <id>
#   bash scripts/manage-access.sh trusted add    <id> [--tools t1,t2,...] [--scripts s1,s2,...] [--scope glob1,glob2,...] [--allow-scoped-critical] [--oc-json PATH] [--dt-conf PATH]
#   bash scripts/manage-access.sh trusted remove <id> [--oc-json PATH] [--dt-conf PATH]
#
# Examples:
#   bash scripts/manage-access.sh trusted add 555555 --scope "workspace-bob/**"
#     # delegated admin of their own workspace folder only, default trusted tool set inside it
#   bash scripts/manage-access.sh trusted add 666666 --tools read,write --scripts exchange_data
#     # extra tool access, no path restriction (their own risk surface is just those tools)
#   bash scripts/manage-access.sh trusted add 555555 --scope "workspace-bob/**" --allow-scoped-critical
#     # same jail, but may now `rm -rf` inside it. .env/openclaw.json/secrets still blocked.
#   bash scripts/manage-access.sh trusted remove 555555
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

read -r -d '' USAGE <<'EOU' || true
Usage: manage-access.sh trusted <list|show|add|remove> [id] [flags]

Lists (pick the verb that matches your intent):
  --add-tools a,b      union into the current list   (safe, idempotent)
  --del-tools a        subtract from the current list
  --tools a,b          REPLACE the whole list
  --add-scripts / --del-scripts / --scripts   same three for the exec allowlist

Scope:
  --scope glob1,glob2        confine to these paths (replaces)
  --agents agent:x,agent:y   confine to these agents (replaces)
  --allow-scoped-critical | --no-scoped-critical

Other:
  --dry-run            show the field-level diff, write nothing
  --oc-json PATH       target a specific gateway config (multi-agent boxes)
  --dt-conf PATH       target a CLI-runtime config

WHY --add-* EXISTS: --tools/--scripts replace. Measured 2026-10-25:
`--scripts yt_dlp_tool` on an entry holding ["sheet_fill_links"] silently
produced ["yt_dlp_tool"] -- the prior grant vanished with no warning. Replace
is legitimate, but it must be chosen, not be the default of someone who meant
"also allow this". Use --dry-run first when you are unsure.
EOU

ACTION="${1:-}"; shift || true
[[ "$ACTION" != "list" && "$ACTION" != "show" && "$ACTION" != "add" && "$ACTION" != "remove" ]] && \
  error "$USAGE"

ARG_ID=""
if [[ "$ACTION" != "list" ]]; then
  ARG_ID="${1:-}"; shift || true
  [[ -z "$ARG_ID" ]] && error "manage-access.sh trusted $ACTION requires an id (e.g. 123456789)."
fi

OPT_TOOLS=""; OPT_SCRIPTS=""; OPT_SCOPE=""; OPT_AGENTS=""; OPT_OC_JSON=""; OPT_DT_CONF=""
# tri-state: "" = flag not passed (preserve prior value on merge), true/false = set it
OPT_SCOPED_CRIT=""
# LIST MODE per field. WHY (measured 2026-10-25): `--scripts X` on an entry
# already holding ["sheet_fill_links"] silently produced ["X"] -- the prior grant
# vanished with no warning, and the loss is invisible until someone's workflow
# breaks. Replace is a legitimate operation but it must be CHOSEN, not be the
# accidental default of someone who meant "also allow this". --add-*/--del-* are
# the safe verbs; --tools/--scripts keep replacing (back-compat) but now say so.
TOOLS_MODE="set"; SCRIPTS_MODE="set"; DRY_RUN="false"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tools)        OPT_TOOLS="$2";   TOOLS_MODE="set";   shift 2 ;;
    --add-tools)    OPT_TOOLS="$2";   TOOLS_MODE="add";   shift 2 ;;
    --del-tools)    OPT_TOOLS="$2";   TOOLS_MODE="del";   shift 2 ;;
    --scripts)      OPT_SCRIPTS="$2"; SCRIPTS_MODE="set"; shift 2 ;;
    --add-scripts)  OPT_SCRIPTS="$2"; SCRIPTS_MODE="add"; shift 2 ;;
    --del-scripts)  OPT_SCRIPTS="$2"; SCRIPTS_MODE="del"; shift 2 ;;
    --scope)    OPT_SCOPE="$2"; shift 2 ;;
    --agents)   OPT_AGENTS="$2"; shift 2 ;;
    --allow-scoped-critical) OPT_SCOPED_CRIT="true"; shift ;;
    --no-scoped-critical)    OPT_SCOPED_CRIT="false"; shift ;;
    --oc-json)  OPT_OC_JSON="$2"; shift 2 ;;
    --dt-conf)  OPT_DT_CONF="$2"; shift 2 ;;
    --dry-run)  DRY_RUN="true"; shift ;;
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
  # ONE renderer for both stores (was two identical heredocs). Its job is not
  # prettiness: it makes INHERITED vs PINNED visible. `allowedScripts` ABSENT
  # means the id keeps inheriting every future global addition; `allowedScripts:
  # [...]` means cut off forever (the engine does `entry ?? global` -- override,
  # not merge). Measured 2026-10-25: two ids were silently excluded from a
  # fleet-wide grant for exactly that reason, and the old one-line output gave
  # no way to see it.
  echo ""
  if [[ "$HAS_OC" == "true" ]]; then
    info "OpenClaw ($OPT_OC_JSON):"
    python3 "$SCRIPT_DIR/_trusted_view.py" "$OPT_OC_JSON" oc "$ACTION" "$ARG_ID"
  fi
  if [[ "$HAS_DT" == "true" ]]; then
    info "CLI runtime ($OPT_DT_CONF):"
    python3 "$SCRIPT_DIR/_trusted_view.py" "$OPT_DT_CONF" dt "$ACTION" "$ARG_ID"
  fi
  echo ""
  echo "  Change a list without clobbering it:"
  echo "    trusted add <id> --add-scripts a,b     union (safe, idempotent)"
  echo "    trusted add <id> --del-scripts a       subtract"
  echo "    trusted add <id> --scripts a,b         REPLACE the whole list"
  echo "    ...add --dry-run to preview the diff without writing."
  exit 0
fi

# ── add / remove: build the new entry (or removal), apply to each existing store ──
csv_to_json_array() {
  # "a,b,c" -> ["a","b","c"]; "" -> null (omit the key)
  local csv="$1"
  [[ -z "$csv" ]] && { echo "null"; return; }
  python3 -c "import json,sys; print(json.dumps([s.strip() for s in sys.argv[1].split(',') if s.strip()]))" "$csv"
}

# True when the id ALREADY has a scopePathGlobs in a store, so re-running
# `add <id> --allow-scoped-critical` without re-passing --scope is still valid
# (the merge preserves the prior scope).
prior_has_scope() {
  local id="$1" p
  for p in "$OPT_OC_JSON" "$OPT_DT_CONF"; do
    [[ -f "$p" ]] || continue
    python3 - "$p" "$id" <<'PY' && return 0
import json, sys
d = json.load(open(sys.argv[1]))
t = (d.get("plugins", {}).get("entries", {}).get("dinotrust-enforce", {}).get("config", {}).get("trustedIds")
     if "plugins" in d else d.get("trustedIds")) or []
sys.exit(0 if any(str(e.get("id")) == sys.argv[2] and e.get("scopePathGlobs") for e in t) else 1)
PY
  done
  return 1
}

if [[ "$ACTION" == "add" ]]; then
  TOOLS_JSON=$(csv_to_json_array "$OPT_TOOLS")
  SCRIPTS_JSON=$(csv_to_json_array "$OPT_SCRIPTS")
  SCOPE_JSON=$(csv_to_json_array "$OPT_SCOPE")
  AGENTS_JSON=$(csv_to_json_array "$OPT_AGENTS")
  SCOPED_CRIT_JSON="${OPT_SCOPED_CRIT:-null}"   # tri-state: null = flag absent, preserve prior
  # A critical grant with no jail grants nothing (the engine requires BOTH the
  # flag AND an in-scope path), so refuse loudly rather than write a no-op flag.
  if [[ "$SCOPED_CRIT_JSON" == "true" && "$SCOPE_JSON" == "null" ]] && ! prior_has_scope "$ARG_ID"; then
    error "--allow-scoped-critical requires --scope. The grant is 'wreck your OWN jail'; with no jail it grants nothing and the engine would still block."
  fi
  if [[ "$SCOPED_CRIT_JSON" == "true" ]]; then
    warn "--allow-scoped-critical: this id may now run critical/irreversible exec (rm -rf, --hard) INSIDE its own scope."
    warn "STILL blocked regardless: protected globs (.env/secrets/keys), writes to openclaw.json or .env, security-doc writes, and any command whose paths are not ALL inside the scope."
  fi
  if [[ "$TOOLS_JSON" == "null" && "$SCRIPTS_JSON" == "null" && "$SCOPE_JSON" == "null" ]]; then
    info "No --tools/--scripts/--scope given: this id gets the DEFAULT_TRUSTED_TOOLS set (read/write/edit/apply_patch/exec/web_search/web_fetch/browser/memory_search/memory_get), the shared nonOwnerAllowedScripts, and NO path restriction (any path allowed for allowed tools)."
  fi
fi

apply_to_store() {
  local store_kind="$1" store_path="$2"
  local backup="${store_path}.dinotrust-bak.$(date -u +%Y%m%d-%H%M%S)"
  local rc=0

  # ONE merge engine for BOTH store kinds. WHY: this was two near-identical
  # heredocs differing only in where trustedIds lives. Two hand-kept copies of a
  # privilege-granting merge is drift waiting to happen -- and the incident this
  # code carries a comment about (silently erased scopeAgents) is exactly that
  # class of bug. The engine also prints a field-level diff, so a grant change is
  # visible BEFORE it is trusted.
  if [[ "$DRY_RUN" != "true" ]]; then
    cp "$store_path" "$backup"
  fi
  python3 "$SCRIPT_DIR/_trusted_merge.py" \
    "$store_path" "$store_kind" "$ACTION" "$ARG_ID" \
    "${TOOLS_JSON:-null}" "${SCRIPTS_JSON:-null}" "${SCOPE_JSON:-null}" \
    "${AGENTS_JSON:-null}" "${SCOPED_CRIT_JSON:-null}" \
    "$TOOLS_MODE" "$SCRIPTS_MODE" "$DRY_RUN" || rc=$?

  if [[ "$DRY_RUN" == "true" ]]; then
    return 0
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
