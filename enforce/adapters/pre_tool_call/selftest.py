#!/usr/bin/env python3
"""Self-test for pre_tool_call handler.decide — parity with enforce/core/policy.ts."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import handler  # noqa: E402

CFG = dict(handler.DEFAULTS)
CFG["ownerIds"] = ["1083618205"]
CFG["nonOwnerAllowedScripts"] = ["exchange_data", "semantic_search", "consensus_search"]

OWNER, SELF, STRANGER = "1083618205", None, "999"
_pass = 0
_fail = 0


def t(name, tool, sender, expect, command="", paths=None):
    global _pass, _fail
    action, reason = handler.decide(tool, paths or [], command, sender, CFG)
    ok = action == expect
    print(("PASS" if ok else "FAIL") + "  %s  -> %s (%s)" % (name, action, reason))
    if ok:
        _pass += 1
    else:
        _fail += 1


# owner
t("owner normal exec", "exec", OWNER, "allow", command="ls -la")
t("owner rm -rf approve", "exec", OWNER, "approve", command="rm -rf /tmp/x")
t("owner git force approve", "exec", OWNER, "approve", command="git push origin main --force")
t("owner write config approve", "write", OWNER, "approve", paths=["/root/.openclaw/openclaw.json"])
t("owner write normal allow", "write", OWNER, "allow", paths=["/tmp/x.txt"])
t("owner cat .env warn (read not write)", "exec", OWNER, "warn", command="cat .env")
t("owner grep security file allow (read arg)", "exec", OWNER, "allow", command="grep -n foo docs/security_rules.md")
t("owner echo > openclaw.json approve (write target)", "exec", OWNER, "approve", command="echo x > /root/.openclaw/openclaw.json")
t("owner tee -a .env approve (tee write)", "exec", OWNER, "approve", command="echo x | tee -a /x/.env")
# quoted-arg false-positive guard: destructive pattern inside quotes is inert -> allow, not approve.
t("owner commit msg with destructive words quoted allow", "exec", OWNER, "allow", command='git commit -m "docs: mention rm -rf and --force in notes"')
t("owner echo quoted DROP TABLE allow", "exec", OWNER, "allow", command='echo "DROP TABLE users"')
# operator outside quotes still fires with a quoted arg:
t("owner destructive op with quoted path approve", "exec", OWNER, "approve", command='rm -rf "/tmp/some path"')
# split: reversible security-DOC edits -> warn only (not approve)
t("owner edit AGENTS.md warn (reversible doc)", "edit", OWNER, "warn", paths=["/x/AGENTS.md"])
t("owner edit security_rules.md warn (reversible doc)", "edit", OWNER, "warn", paths=["/x/security_rules.md"])
t("owner echo > security_rules.md warn (exec-write doc)", "exec", OWNER, "warn", command="echo x > /x/security_rules.md")
# escalation paths still approve
t("owner edit .env approve (escalation)", "edit", OWNER, "approve", paths=["/x/.env"])
# claude-code native tool names
t("owner Bash rm -rf approve", "Bash", OWNER, "approve", command="rm -rf x")
t("owner Write normal allow", "Write", OWNER, "allow", paths=["/tmp/n.txt"])
# self
t("self exec allow", "exec", SELF, "allow", command="python3 backup.py")
t("self rm -rf approve", "exec", SELF, "approve", command="rm -rf x")
# non-owner strict
t("stranger allowed script", "exec", STRANGER, "allow", command="python3 tools/exchange_data.py price BTC")
t("stranger consensus", "exec", STRANGER, "allow", command="python3 tools/consensus_search.py BTC")
t("stranger arbitrary exec", "exec", STRANGER, "block", command="ls -la /root")
t("stranger chaining", "exec", STRANGER, "block", command="python3 tools/exchange_data.py; rm -rf /")
t("stranger Bash arbitrary", "Bash", STRANGER, "block", command="whoami")
t("stranger write", "write", STRANGER, "block", paths=["/tmp/x"])
t("stranger Edit", "Edit", STRANGER, "block", paths=["/tmp/x"])
t("stranger read normal", "read", STRANGER, "allow", paths=["/tmp/x"])
t("stranger Read normal", "Read", STRANGER, "allow", paths=["/tmp/x"])
t("stranger read .env", "read", STRANGER, "block", paths=["/x/.env"])
t("stranger web_search", "web_search", STRANGER, "allow")
t("stranger WebSearch", "WebSearch", STRANGER, "allow")
t("stranger memory_search", "memory_search", STRANGER, "allow")
t("stranger cat credentials", "exec", STRANGER, "block", command="cat ~/.config/credentials")
t("stranger unknown tool", "some_write_tool", STRANGER, "block")

# ── trusted/delegated tier (above non-owner, below owner) ──
CFG_TRUSTED = dict(handler.DEFAULTS)
CFG_TRUSTED["ownerIds"] = ["1083618205"]
CFG_TRUSTED["nonOwnerAllowedScripts"] = ["exchange_data", "semantic_search", "consensus_search"]
CFG_TRUSTED["trustedIds"] = [
    {"id": "555555", "scopePathGlobs": ["workspace-bob/**"]},
    {"id": "666666", "allowedTools": ["read", "write"], "allowedScripts": ["exchange_data"]},
    {"id": "777777", "allowedTools": ["read", "write", "exec"], "allowedScripts": ["exchange_data"]},
]

def tt(name, tool, sender, expect, command="", paths=None):
    global _pass, _fail
    action, reason = handler.decide(tool, paths or [], command, sender, CFG_TRUSTED)
    ok = action == expect
    print(("PASS" if ok else "FAIL") + "  %s  -> %s (%s)" % (name, action, reason))
    if ok:
        _pass += 1
    else:
        _fail += 1

tt("trusted scope: in-scope write allowed", "write", "555555", "allow", paths=["workspace-bob/notes.md"])
tt("trusted scope: out-of-scope write blocked", "write", "555555", "block", paths=["workspace-alice/notes.md"])
tt("trusted scope: protected glob wins even in scope", "write", "555555", "block", paths=["workspace-bob/.env"])
tt("trusted scope: critical action blocked not approved", "exec", "555555", "block", command="rm -rf workspace-bob/x")
tt("trusted tool-allowlist: allowed tool passes", "read", "666666", "allow", paths=["anywhere.txt"])
tt("trusted tool-allowlist: disallowed tool blocked", "edit", "666666", "block", paths=["anywhere.txt"])
tt("trusted exec: not granted -> blocked", "exec", "666666", "block", command="python3 tools/exchange_data.py price BTC")
tt("trusted exec: granted + allowlisted script -> allowed", "exec", "777777", "allow", command="python3 tools/exchange_data.py price BTC")
tt("trusted exec: granted but script not allowlisted -> blocked", "exec", "777777", "block", command="python3 tools/arkham_search.py x")
tt("trusted with no scopePathGlobs: any path allowed if tool allowed", "write", "777777", "allow", paths=["/etc/random/path.txt"])
tt("non-trusted stranger still hits normal non-owner path", "write", "999999", "block", paths=["anywhere.txt"])
tt("owner unaffected by trustedIds config", "write", "1083618205", "allow", paths=["anything.txt"])

# back-compat: empty trustedIds -> byte-identical to pre-trusted-tier behavior
CFG_BACKCOMPAT = dict(handler.DEFAULTS)
CFG_BACKCOMPAT["ownerIds"] = ["1083618205"]
action, reason = handler.decide("read", [], "", "555555", CFG_BACKCOMPAT)
ok = action == "allow" and reason == "non-owner allowed tool"
print(("PASS" if ok else "FAIL") + "  back-compat: empty trustedIds unaffected  -> %s (%s)" % (action, reason))
if ok:
    _pass += 1
else:
    _fail += 1

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
