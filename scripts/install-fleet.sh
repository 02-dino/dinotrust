#!/usr/bin/env bash
# dinotrust install-fleet — run the installer across EVERY agent lane on a box.
#
# WHY THIS EXISTS (measured 2026-10-24, 19-lane box):
# install.sh targets ONE lane per run. On a multi-agent box that is not just
# tedious, it is a silent correctness trap: install.sh resolves the gateway
# config as ${OPENCLAW_CONFIG:-$HOME/.openclaw/openclaw.json}. Run it N times
# without setting that env and all N runs rewrite the SAME main config with N
# different lanes' settings — every lane's own config untouched, main clobbered,
# zero errors raised. It looks like N successful installs. It is one file
# overwritten N times. This script sets OPENCLAW_CONFIG per lane, always.
#
# DEFAULTS ARE FAIL-CLOSED, on purpose:
#   * DRY RUN unless --apply. A tool that writes to every lane on a box by
#     default is one typo away from a fleet-wide incident.
#   * NO --force. install.sh's block_guard refuses to overwrite a hand-edited
#     managed block without it; passing --force here would strip that protection
#     from every lane at once, which is exactly backwards for a bulk tool.
#   * A lane with no resolvable owner is SKIPPED, never guessed. Writing a
#     security ruleset with the wrong owner id is worse than not writing it.
#
# Usage:
#   scripts/install-fleet.sh --list
#   scripts/install-fleet.sh --profile private-assistant            # dry run
#   scripts/install-fleet.sh --profile private-assistant --apply
#   scripts/install-fleet.sh --only analyst --apply
#   scripts/install-fleet.sh --skip analyst,extractor --apply
#   scripts/install-fleet.sh --instruction-only --apply             # no enforce re-template
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
info() { echo -e "${CYAN}→${NC} $*"; }
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC} $*"; }
err()  { echo -e "${RED}✗${NC} $*" >&2; }

APPLY=false; ONLY=""; SKIP=""; PROFILE="private-assistant"
INSTRUCTION_ONLY=false; LIST_ONLY=false; PASS_FORCE=false; PIN_UNGUARDED=false
GW_ROOT="${DINOTRUST_GATEWAY_ROOT:-$HOME}"

# block_guard gives us per-lane provenance (installer output vs hand-edited vs
# UNGUARDED). Sourced best-effort: an older checkout without block_guard_status
# degrades to "?" rather than failing the whole fleet run.
# shellcheck source=../lib/block_guard.sh
[ -r "$REPO_DIR/lib/block_guard.sh" ] && . "$REPO_DIR/lib/block_guard.sh" 2>/dev/null || true
guard_state() {
  declare -f block_guard_status >/dev/null 2>&1 || { echo "?"; return; }
  block_guard_status "$1" "# --- dinotrust begin" "# --- dinotrust end ---" dinotrust
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)            APPLY=true; shift ;;
    --dry-run)          APPLY=false; shift ;;
    --only)             ONLY="$2"; shift 2 ;;
    --skip)             SKIP="$2"; shift 2 ;;
    --profile)          PROFILE="$2"; shift 2 ;;
    --instruction-only) INSTRUCTION_ONLY=true; shift ;;
    --force)            PASS_FORCE=true; shift ;;
    --list)             LIST_ONLY=true; shift ;;
    # PIN-ONLY MODE, not an install modifier (fixed 2026-10-24 after it bit me).
    # It first read as "also pin unguarded lanes during the normal run", so a
    # maintenance invocation silently performed a FULL INSTALL on every lane that
    # happened not to be unguarded. Nothing was lost (the one lane it hit had no
    # block and a backup was written), but a flag whose name describes a narrow
    # safety action must never widen into writing config -- that is the same
    # surprising-behaviour class this whole tool exists to remove.
    --pin-unguarded)    PIN_UNGUARDED=true; shift ;;
    -h|--help)
      sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) err "Unknown option: $1"; exit 2 ;;
  esac
done

command -v python3 >/dev/null 2>&1 || { err "python3 required for lane discovery."; exit 1; }

# ── Lane discovery ────────────────────────────────────────────────────────────
# A "lane" = one agent inside one gateway state dir ($HOME/.openclaw[-<name>]).
# Owner ids come from THAT gateway's own dinotrust-enforce config (agentOwners
# first, then ownerIds) so the ruleset we inject can never disagree with what
# actually enforces on that lane. Emits TSV: agent, gateway_json, workspace, owners.
discover() {
  GW_ROOT="$GW_ROOT" python3 - <<'PY'
import json, os, sys
root = os.environ["GW_ROOT"]
try:
    names = sorted(os.listdir(root))
except OSError:
    sys.exit(0)
for name in names:
    if not (name == ".openclaw" or name.startswith(".openclaw-")):
        continue
    cfg_path = os.path.join(root, name, "openclaw.json")
    if not os.path.isfile(cfg_path):
        continue
    try:
        d = json.load(open(cfg_path))
    except Exception:
        print("\t".join(["(unreadable)", cfg_path, "", ""])); continue
    agents = d.get("agents", {}) or {}
    ent = ((d.get("plugins", {}).get("entries", {}) or {})
           .get("dinotrust-enforce", {}) or {}).get("config", {}) or {}
    owner_map = ent.get("agentOwners") or {}
    flat_owners = ent.get("ownerIds") or []
    lst = agents.get("list") or []
    if not lst:
        lst = [{"id": name.replace(".openclaw-", "") or "main"}]
    for a in lst:
        if not isinstance(a, dict):
            continue
        aid = a.get("id") or ""
        ws = a.get("workspace") or (agents.get("defaults", {}) or {}).get("workspace") or ""
        # agentOwners keys are sessionKey substrings e.g. "agent:analyst"
        owners = []
        for k, v in owner_map.items():
            if aid and aid in k:
                owners = list(v or []); break
        if not owners:
            owners = list(flat_owners)
        print("\t".join([aid, cfg_path, ws, ",".join(str(o) for o in owners)]))
PY
}

echo ""
echo -e "${BOLD}🦖 dinotrust${NC} — fleet installer"
echo "────────────────────────────────────────────────────────"
$APPLY || warn "DRY RUN (no writes). Add --apply to execute."
$PASS_FORCE && warn "--force given: hand-edit protection (block_guard) is DISABLED on every lane."
echo ""

ok_n=0; fail_n=0; skip_n=0
while IFS=$'\t' read -r agent gateway workspace owners; do
  [[ -z "$agent" ]] && continue
  if [[ -n "$ONLY" && "$agent" != "$ONLY" ]]; then continue; fi
  if [[ -n "$SKIP" && ",$SKIP," == *",$agent,"* ]]; then
    echo "SKIP  $agent — excluded via --skip"; skip_n=$((skip_n+1)); continue
  fi
  if [[ "$agent" == "(unreadable)" ]]; then
    err "SKIP  unreadable config: $gateway"; skip_n=$((skip_n+1)); continue
  fi
  if [[ -z "$workspace" || ! -d "$workspace" ]]; then
    echo "SKIP  $agent — no workspace dir resolved"; skip_n=$((skip_n+1)); continue
  fi
  if [[ -z "$owners" ]]; then
    echo "SKIP  $agent — no owner id in $gateway; refusing to guess an owner"
    skip_n=$((skip_n+1)); continue
  fi

  _gs="$(guard_state "$workspace/AGENTS.md")"

  if $LIST_ONLY; then
    printf '  %-14s guard=%-10s owners=%-22s ws=%s\n' "$agent" "$_gs" "$owners" "$workspace"
    ok_n=$((ok_n+1)); continue
  fi

  # UNGUARDED = a managed block with no checksum sidecar, i.e. installed before
  # the guard shipped. block_guard_check FAILS OPEN there, so a plain re-run
  # overwrites it without even needing --force -- and if a human hand-edited that
  # block, the edit dies silently. We cannot know its provenance, so the safe
  # move is to pin it closed (--pin-unguarded) and let a human decide, rather
  # than record its hash and thereby assert "this is installer output".
  if [[ "$_gs" == "unguarded" ]]; then
    if $PIN_UNGUARDED; then
      if $APPLY && declare -f block_guard_pin >/dev/null 2>&1; then
        block_guard_pin "$workspace/AGENTS.md" dinotrust
        ok "$agent — pinned PROTECTED (was unguarded); re-run with --force to overwrite"
      else
        info "$agent — would pin PROTECTED (was unguarded)"
      fi
      skip_n=$((skip_n+1)); continue
    fi
    warn "SKIP  $agent — block is UNGUARDED (pre-guard install, provenance unknown)"
    # (pin-only mode returns above; this path is the plain run's refusal)
    warn "      a write here cannot be distinguished from clobbering a hand-edit"
    warn "      run with --pin-unguarded to pin it closed, or --force to overwrite"
    skip_n=$((skip_n+1)); continue
  fi

  # Pin-only mode never installs: a lane that is already guarded has nothing to
  # pin, so there is simply no work here.
  if $PIN_UNGUARDED; then
    printf '  %-14s guard=%s — nothing to pin\n' "$agent" "$_gs"
    skip_n=$((skip_n+1)); continue
  fi

  _args=(--platform openclaw --owner-id "$owners" --profile "$PROFILE"
         --workspace "$workspace" --agent "$agent" --non-interactive)
  $INSTRUCTION_ONLY && _args+=(--no-enforce)
  $PASS_FORCE && _args+=(--force)
  $APPLY || _args+=(--dry-run)

  echo -e "${BOLD}$agent${NC}  (owners=$owners)"
  info "OPENCLAW_CONFIG=$gateway"
  _log="${TMPDIR:-/tmp}/dinotrust-fleet-$agent.log"
  if OPENCLAW_CONFIG="$gateway" bash "$REPO_DIR/scripts/install.sh" "${_args[@]}" \
       >"$_log" 2>&1; then
    ok "done (log: $_log)"; ok_n=$((ok_n+1))
  else
    err "FAILED rc=$? — tail:"; tail -5 "$_log" | sed 's/^/      /'; fail_n=$((fail_n+1))
  fi
done < <(discover)

echo "────────────────────────────────────────────────────────"
echo "ok=$ok_n failed=$fail_n skipped=$skip_n"
$APPLY || echo "(dry run — nothing was written)"
[[ $fail_n -eq 0 ]]
