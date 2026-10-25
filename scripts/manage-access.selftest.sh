#!/usr/bin/env bash
# Self-test for manage-access.sh list semantics.
#
# WEIGHTED TOWARD SILENT-LOSS CASES. A grant that fails to apply is noticed the
# first time someone uses the tool. A grant that silently REPLACES another one
# is invisible until an unrelated workflow breaks, possibly weeks later -- and
# that is the bug this suite exists for (measured 2026-10-25: `--scripts X` on
# an entry holding ["sheet_fill_links"] produced ["X"], no warning).
#
# Run: bash scripts/manage-access.selftest.sh
set -uo pipefail
S="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MA="$S/manage-access.sh"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
export DINOTRUST_COLOR=false
pass=0; fail=0
ok() { echo "PASS  $1"; pass=$((pass+1)); }
no() { echo "FAIL  $1 ${2:-}"; fail=$((fail+1)); }

fresh() {  # $1 = json body for the dinotrust config object
  cat > "$T/oc.json" <<EOF
{"plugins":{"entries":{"dinotrust-enforce":{"config":$1}}}}
EOF
}
run()   { bash "$MA" "$@" --oc-json "$T/oc.json" --dt-conf /nonexistent 2>&1; }
field() { python3 -c "
import json,sys
e=json.load(open('$T/oc.json'))['plugins']['entries']['dinotrust-enforce']['config']
t=[x for x in e.get('trustedIds',[]) if str(x.get('id'))=='$1']
print(json.dumps((t[0] if t else {}).get('$2')))"; }
glob()  { python3 -c "
import json
e=json.load(open('$T/oc.json'))['plugins']['entries']['dinotrust-enforce']['config']
print(json.dumps(e.get('$1')))"; }

PINNED='{"trustedIds":[{"id":"999","allowedScripts":["keep_me"],"scopeAgents":["agent:x"],"scopePathGlobs":["**/ws-x/**"],"allowScopedCritical":true}]}'

# ── the core regression: add must not erase ──────────────────────────────────
fresh "$PINNED"
run trusted add 999 --add-scripts new_one >/dev/null
[[ "$(field 999 allowedScripts)" == '["keep_me", "new_one"]' ]] \
  && ok "--add-scripts unions (prior grant survives)" \
  || no "--add-scripts" "got $(field 999 allowedScripts)"

# Scope fields must survive ANY list edit. Losing scopePathGlobs silently
# WIDENS a deliberately confined id -- the worst outcome this tool can produce.
for f in scopeAgents scopePathGlobs allowScopedCritical; do
  [[ "$(field 999 $f)" != "null" ]] && ok "scope preserved: $f" || no "scope lost: $f"
done

fresh "$PINNED"
run trusted add 999 --scripts only_this >/dev/null
[[ "$(field 999 allowedScripts)" == '["only_this"]' ]] \
  && ok "--scripts still REPLACES (back-compat kept, now documented)" \
  || no "--scripts replace" "got $(field 999 allowedScripts)"

fresh '{"trustedIds":[{"id":"999","allowedScripts":["a","b","c"]}]}'
run trusted add 999 --del-scripts b >/dev/null
[[ "$(field 999 allowedScripts)" == '["a", "c"]' ]] \
  && ok "--del-scripts subtracts" || no "--del-scripts" "got $(field 999 allowedScripts)"

# Idempotence matters for automation: a re-run must be a no-op, not a duplicate.
fresh '{"trustedIds":[{"id":"999","allowedScripts":["a"]}]}'
run trusted add 999 --add-scripts a >/dev/null
[[ "$(field 999 allowedScripts)" == '["a"]' ]] \
  && ok "re-adding an existing value does not duplicate" || no "idempotence"
# Capture first, THEN grep. Piping into `grep -q` under `set -o pipefail` is a
# trap: grep exits on first match, the writer takes SIGPIPE, and pipefail reports
# the whole pipeline as failed -- so a PASSING case reads as a failure.
out=$(run trusted add 999 --add-scripts a)
grep -q "no field changed" <<<"$out" \
  && ok "no-op is reported as such" || no "no-op not reported"

# ── dry-run must not write ───────────────────────────────────────────────────
fresh '{"trustedIds":[{"id":"999","allowedScripts":["a"]}]}'
out=$(run trusted add 999 --add-scripts zzz --dry-run)
grep -q "dry run" <<<"$out" && ok "dry-run says so" || no "dry-run not announced"
grep -q '"a", "zzz"' <<<"$out" && ok "dry-run shows the resulting diff" || no "dry-run diff missing"
[[ "$(field 999 allowedScripts)" == '["a"]' ]] \
  && ok "dry-run wrote nothing" || no "dry-run WROTE" "got $(field 999 allowedScripts)"

# ── visibility: inherited vs pinned ──────────────────────────────────────────
# The whole point of the view rewrite. An operator adding to the global list
# must be able to SEE which ids will not receive it.
fresh '{"nonOwnerAllowedScripts":["g1","g2"],"trustedIds":[{"id":"111"},{"id":"222","allowedScripts":["own"]}]}'
out=$(run trusted list)
grep -q "inherits global" <<<"$out" && ok "list marks inheriting ids" || no "inherit not shown"
grep -q "PINNED" <<<"$out" && ok "list marks pinned ids" || no "PINNED not shown"
grep -q "not inherited: g1, g2" <<<"$out" && ok "list names what a pinned id misses" || no "missing not named"
grep -q -- "--add-scripts g1,g2" <<<"$out" && ok "list prints the exact fix command" || no "fix command missing"

out=$(run nonowner list)
grep -q "do NOT inherit" <<<"$out" && ok "nonowner list warns about cut-off ids" || no "nonowner warning missing"
grep -q "222" <<<"$out" && ok "nonowner list names the cut-off id" || no "cut-off id not named"

# ── nonowner guardrails (unchanged behaviour, must stay) ─────────────────────
fresh '{"nonOwnerAllowedTools":["read"],"nonOwnerAllowedScripts":[]}'
run nonowner add-tool exec >/dev/null 2>&1
[[ "$(glob nonOwnerAllowedTools)" == '["read"]' ]] \
  && ok "mutating tool refused without --force" || no "exec slipped in"
run nonowner add-tool exec --force >/dev/null 2>&1
grep -q exec <<<"$(glob nonOwnerAllowedTools)" \
  && ok "mutating tool allowed with --force" || no "--force did not apply"

echo ""
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
