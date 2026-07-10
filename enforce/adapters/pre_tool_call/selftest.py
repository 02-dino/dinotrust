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
t("owner edit AGENTS.md approve", "edit", OWNER, "approve", paths=["/x/AGENTS.md"])
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

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
