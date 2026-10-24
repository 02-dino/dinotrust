#!/usr/bin/env bash
# Self-test for wrappers/run_binary.py.
#
# Weighted toward REFUSAL paths on purpose: the happy path fails loudly the
# first time anyone uses it, while a refusal that silently stopped refusing
# looks exactly like a working tool until it is abused.
#
# Run: bash wrappers/selftest.sh
set -uo pipefail
W="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
SPEC="$T/spec.json"
cp "$W/binaries.default.json" "$SPEC"; chmod 600 "$SPEC"
export DINOTRUST_BINARY_SPEC="$SPEC"
run() { python3 "$W/run_binary.py" "$@"; }

printf '{"name":"dino","age":3}' > "$T/d.json"
printf '<a><b>hi</b></a>' > "$T/d.xml"
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
no()  { echo "FAIL  $1 ${2:-}"; fail=$((fail+1)); }
rc_is() { [[ "$2" == "$3" ]] && ok "$1" || no "$1" "(rc=$2 want $3)"; }

# ── allow path ───────────────────────────────────────────────────────────────
out=$(run jq -r .name "$T/d.json" 2>&1); rc=$?
rc_is "jq runs" "$rc" 0
[[ "$out" == "dino" ]] && ok "jq output correct" || no "jq output" "($out)"

out=$(run xmllint --xpath '//b/text()' "$T/d.xml" 2>&1); rc=$?
rc_is "xmllint runs with forcedFlags" "$rc" 0
[[ "$out" == "hi" ]] && ok "xmllint output correct" || no "xmllint output" "($out)"

# ── refusal paths ────────────────────────────────────────────────────────────
run jq --unknown-flag . "$T/d.json" >/dev/null 2>&1
rc_is "unlisted flag refused" "$?" 1
run curl https://example.com >/dev/null 2>&1
rc_is "binary absent from spec refused" "$?" 1
run /usr/bin/jq . "$T/d.json" >/dev/null 2>&1
rc_is "absolute path refused (caller must not pick the executable)" "$?" 1
run jq --exec 'id' . "$T/d.json" >/dev/null 2>&1
rc_is "HARD_DENY flag refused" "$?" 1

# `--opt=value` must normalise to `--opt` before the allowlist test, or the =
# form becomes a bypass for every flag check below it.
run jq --unknown=x . "$T/d.json" >/dev/null 2>&1
rc_is "unlisted flag in --opt=value form refused" "$?" 1
run jq --exec=id . "$T/d.json" >/dev/null 2>&1
rc_is "HARD_DENY in --opt=value form refused" "$?" 1

# A spec that allows a dangerous flag must still be refused: the spec is the
# surface most likely to be edited casually, so it cannot be the last word.
printf '{"jq":{"allowedFlags":["--exec","-r"],"forcedFlags":[]}}' > "$T/evil.json"
chmod 600 "$T/evil.json"
DINOTRUST_BINARY_SPEC="$T/evil.json" run jq -r . "$T/d.json" >/dev/null 2>&1
rc_is "spec allowing --exec is itself refused" "$?" 1

# A policy file anyone can rewrite is not a policy.
cp "$SPEC" "$T/loose.json"; chmod 666 "$T/loose.json"
DINOTRUST_BINARY_SPEC="$T/loose.json" run jq -r .name "$T/d.json" >/dev/null 2>&1
rc_is "world-writable spec refused" "$?" 1

# Exit status must come from the BINARY, not be swallowed into a flat success.
run jq -e .missing "$T/d.json" >/dev/null 2>&1
[[ $? -ne 0 ]] && ok "binary exit status propagates" || no "exit status swallowed"

echo ""
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
