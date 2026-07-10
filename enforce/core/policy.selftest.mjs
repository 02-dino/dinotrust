// Self-test for the shared enforce policy engine.
// Run: node --experimental-strip-types enforce/core/policy.selftest.mjs
//  (or transpile). Uses dynamic import of the .ts via strip-types.
import { decide, normalizeConfig } from "./policy.ts";

const CFG = normalizeConfig({
  ownerIds: ["1083618205"],
  nonOwnerAllowedScripts: ["exchange_data", "semantic_search", "consensus_search"],
});

let pass = 0, fail = 0;
function call(toolName, { command = "", paths = [] } = {}) { return { toolName, command, paths }; }
function t(name, c, sender, expect) {
  const v = decide(c, sender, CFG);
  const ok = v.action === expect;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  -> ${v.action} (${v.reason})`);
  ok ? pass++ : fail++;
}
const OWNER = "1083618205", SELF = null, STRANGER = "999";

// owner: allow / warn / approve
t("owner normal exec", call("exec", { command: "ls -la" }), OWNER, "allow");
t("owner rm -rf -> approve", call("exec", { command: "rm -rf /tmp/x" }), OWNER, "approve");
t("owner git push --force -> approve", call("exec", { command: "git push origin main --force" }), OWNER, "approve");
t("owner write openclaw.json -> approve", call("write", { paths: ["/root/.openclaw/openclaw.json"] }), OWNER, "approve");
t("owner write normal -> allow", call("write", { paths: ["/tmp/x.txt"] }), OWNER, "allow");
t("owner read .env -> warn (read, not write)", call("exec", { command: "cat .env" }), OWNER, "warn");
t("owner grep security file -> allow (read arg)", call("exec", { command: "grep -n foo docs/security_rules.md" }), OWNER, "allow");
t("owner echo > openclaw.json -> approve (write target)", call("exec", { command: "echo x > /root/.openclaw/openclaw.json" }), OWNER, "approve");
t("owner tee -a .env -> approve (tee write)", call("exec", { command: "echo x | tee -a /x/.env" }), OWNER, "approve");
t("owner edit AGENTS.md -> approve", call("edit", { paths: ["/x/AGENTS.md"] }), OWNER, "approve");

// self (agent-operated-by-owner)
t("self exec normal -> allow", call("exec", { command: "python3 procedures/backup.py" }), SELF, "allow");
t("self rm -rf -> approve", call("exec", { command: "rm -rf x" }), SELF, "approve");

// non-owner: strict
t("stranger exec allowed script", call("exec", { command: "python3 tools/exchange_data.py price BTC" }), STRANGER, "allow");
t("stranger exec consensus", call("exec", { command: "python3 tools/consensus_search.py BTC" }), STRANGER, "allow");
t("stranger exec arbitrary", call("exec", { command: "ls -la /root" }), STRANGER, "block");
t("stranger exec chaining", call("exec", { command: "python3 tools/exchange_data.py; rm -rf /" }), STRANGER, "block");
t("stranger write", call("write", { paths: ["/tmp/x"] }), STRANGER, "block");
t("stranger edit", call("edit", { paths: ["/tmp/x"] }), STRANGER, "block");
t("stranger read normal", call("read", { paths: ["/tmp/x"] }), STRANGER, "allow");
t("stranger read .env", call("read", { paths: ["/x/.env"] }), STRANGER, "block");
t("stranger web_search", call("web_search"), STRANGER, "allow");
t("stranger memory_search", call("memory_search"), STRANGER, "allow");
t("stranger exec cat credentials", call("exec", { command: "cat ~/.config/credentials" }), STRANGER, "block");
t("stranger unknown tool", call("some_write_tool"), STRANGER, "block");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
