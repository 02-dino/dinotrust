// Self-test for the shared enforce policy engine.
// Run: node --experimental-strip-types enforce/core/policy.selftest.mjs
//  (or transpile). Uses dynamic import of the .ts via strip-types.
import { decide, normalizeConfig } from "./policy.ts";

const CFG = normalizeConfig({
  ownerIds: ["111111"],
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
/** Assert on the deny REASON, not just the action: a block whose reason names the
 * wrong cause still produces a wrong outcome one layer up (measured 2026-10-22). */
function r(name, c, sender, reasonRe) {
  const v = decide(c, sender, CFG);
  const ok = v.action === "block" && reasonRe.test(v.reason);
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  -> ${v.action} (${v.reason})`);
  ok ? pass++ : fail++;
}
const OWNER = "111111", SELF = null, STRANGER = "999";

// owner: allow / warn / approve
t("owner normal exec", call("exec", { command: "ls -la" }), OWNER, "allow");
// INTERACTIVE owner (real senderId) still gets the approval card -- only
// UNATTENDED self (senderId==null) is warn-not-gate under ownerSelfApproval=warn.
t("owner rm -rf real path -> approve (interactive owner still gated)", call("exec", { command: "rm -rf /root/data" }), OWNER, "approve");
t("owner git push --force -> approve", call("exec", { command: "git push origin main --force" }), OWNER, "approve");
t("owner write openclaw.json -> approve", call("write", { paths: ["/root/.openclaw/openclaw.json"] }), OWNER, "approve");
t("owner write normal -> allow", call("write", { paths: ["/tmp/x.txt"] }), OWNER, "allow");
t("owner read .env -> warn (read, not write)", call("exec", { command: "cat .env" }), OWNER, "warn");
t("owner grep security file -> allow (read arg)", call("exec", { command: "grep -n foo docs/security_rules.md" }), OWNER, "allow");
t("owner echo > openclaw.json -> approve (write target)", call("exec", { command: "echo x > /root/.openclaw/openclaw.json" }), OWNER, "approve");
t("owner tee -a .env -> approve (tee write)", call("exec", { command: "echo x | tee -a /x/.env" }), OWNER, "approve");
// split: reversible security-DOC edits (security_rules.md / AGENTS.md) -> warn only, NOT approve.
t("owner edit AGENTS.md -> warn (reversible doc)", call("edit", { paths: ["/x/AGENTS.md"] }), OWNER, "warn");
t("owner edit security_rules.md -> warn (reversible doc)", call("edit", { paths: ["/x/security_rules.md"] }), OWNER, "warn");
t("owner write security_rules.md -> warn (reversible doc)", call("write", { paths: ["/repo/security_rules.md"] }), OWNER, "warn");
t("owner echo > security_rules.md -> warn (exec-write reversible doc)", call("exec", { command: "echo x > /x/security_rules.md" }), OWNER, "warn");
// escalation paths (openclaw.json / .env) STILL approve -- injection tripwire kept.
t("owner edit .env -> approve (escalation)", call("edit", { paths: ["/x/.env"] }), OWNER, "approve");
// quoted-arg false-positive guard: a destructive pattern INSIDE a quoted arg is inert text -> must NOT approve.
t("owner git commit -m with rm -rf in msg -> allow (quoted, inert)", call("exec", { command: `git commit -m "docs: mention rm -rf and git push --force in changelog"` }), OWNER, "allow");
t("owner echo quoted DROP TABLE -> allow (quoted, inert)", call("exec", { command: `echo "DROP TABLE users -- example"` }), OWNER, "allow");
t("owner single-quoted dd if= -> allow (quoted, inert)", call("exec", { command: `grep -n 'dd if=/dev/zero' notes.txt` }), OWNER, "allow");
// but the operator OUTSIDE quotes still fires even when its ARG is quoted:
t("owner rm -rf quoted-path -> approve (operator unquoted)", call("exec", { command: `rm -rf "/tmp/some path"` }), OWNER, "approve");
t("owner force-push after quoted arg -> approve (operator unquoted)", call("exec", { command: `git commit -m "wip" && git push origin main --force` }), OWNER, "approve");

// self (agent-operated-by-owner). NOOB-DEFAULT ownerSelfApproval="warn":
// the UNATTENDED agent's own critical actions warn-log (no human to answer a
// card) instead of hanging the turn. senderId==null == self.
t("self exec normal -> allow", call("exec", { command: "python3 procedures/backup.py" }), SELF, "allow");
t("self rm -rf -> warn (ownerSelfApproval=warn: unattended self, no hang)", call("exec", { command: "rm -rf x" }), SELF, "warn");

// non-owner: strict
t("stranger exec allowed script", call("exec", { command: "python3 tools/exchange_data.py price BTC" }), STRANGER, "allow");
t("stranger exec consensus", call("exec", { command: "python3 tools/consensus_search.py BTC" }), STRANGER, "allow");
t("stranger exec arbitrary", call("exec", { command: "ls -la /root" }), STRANGER, "block");
t("stranger exec chaining", call("exec", { command: "python3 tools/exchange_data.py; rm -rf /" }), STRANGER, "block");
// DENY-REASON SPECIFICITY (2026-10-22): blocking is not enough -- the reason must
// name the ACTUAL cause, or the caller mis-diagnoses an allowlisted-but-chained
// command as a missing permission and escalates instead of re-issuing it split.
r("chained ALLOWLISTED script -> reason names chaining, not permission",
  call("exec", { command: "python3 tools/exchange_data.py price BTC; python3 tools/exchange_data.py price ETH" }),
  STRANGER, /chaining|ONE plain script/);
r("piped ALLOWLISTED script -> reason names chaining",
  call("exec", { command: "python3 tools/exchange_data.py price BTC | python3 -c 'import sys'" }),
  STRANGER, /chaining|ONE plain script/);
// Inverse: a NON-allowlisted script must keep the generic reason even when chained,
// so the specific hint can never imply "this tool would be fine unchained".
r("chained NON-allowlisted script -> stays generic",
  call("exec", { command: "python3 tools/evil.py; ls" }), STRANGER, /restricted to allowlisted tools/);
r("plain NON-allowlisted script -> stays generic",
  call("exec", { command: "ls -la /root" }), STRANGER, /restricted to allowlisted tools/);
t("stranger write", call("write", { paths: ["/tmp/x"] }), STRANGER, "block");
t("stranger edit", call("edit", { paths: ["/tmp/x"] }), STRANGER, "block");
t("stranger read normal", call("read", { paths: ["/tmp/x"] }), STRANGER, "allow");
t("stranger read .env", call("read", { paths: ["/x/.env"] }), STRANGER, "block");
t("stranger web_search", call("web_search"), STRANGER, "allow");
t("stranger memory_search", call("memory_search"), STRANGER, "allow");
t("stranger exec cat credentials", call("exec", { command: "cat ~/.config/credentials" }), STRANGER, "block");
t("stranger unknown tool", call("some_write_tool"), STRANGER, "block");

// ── trusted/delegated tier (above non-owner, below owner) ──
const CFG_TRUSTED = normalizeConfig({
  ownerIds: ["111111"],
  nonOwnerAllowedScripts: ["exchange_data", "semantic_search", "consensus_search"],
  trustedIds: [
    { id: "555555", scopePathGlobs: ["workspace-bob/**"] },
    { id: "666666", allowedTools: ["read", "write"], allowedScripts: ["exchange_data"] },
    { id: "777777", allowedTools: ["read", "write", "exec"], allowedScripts: ["exchange_data"] },
    // scopeAgents: trusted only inside agent:ads on a shared gateway
    { id: "888888", scopeAgents: ["agent:ads"], scopePathGlobs: ["workspace-ads/**"] },
    // allowScopedCritical: opted-in PIC who may clean their OWN workspace
    { id: "444444", scopePathGlobs: ["workspace-pic/**"], allowScopedCritical: true },
    // opted in but NO scope -> a grant with no jail grants nothing
    { id: "333333", allowScopedCritical: true },
  ],
});
function tt(name, c, sender, expect, sessionKey = "") {
  const v = decide(c, sender, CFG_TRUSTED, sessionKey);
  const ok = v.action === expect;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  -> ${v.action} (${v.reason})`);
  ok ? pass++ : fail++;
}
tt("trusted scope: in-scope write allowed", call("write", { paths: ["workspace-bob/notes.md"] }), "555555", "allow");
tt("trusted scope: out-of-scope write blocked", call("write", { paths: ["workspace-alice/notes.md"] }), "555555", "block");
tt("trusted scope: protected glob wins even in scope", call("write", { paths: ["workspace-bob/.env"] }), "555555", "block");
tt("trusted scope: critical action blocked not approved", call("exec", { command: "rm -rf workspace-bob/x" }), "555555", "block");
// ── allowScopedCritical: opt-in, default strict (owner decision 2026-10-23) ──
// DEFAULT STRICT: 555555 has a scope but never opted in -> unchanged above.
tt("scopedCritical OFF by default: rm -rf own scope still blocked", call("exec", { command: "rm -rf workspace-bob/build" }), "555555", "block");
// OPTED IN: own jail only.
tt("scopedCritical: rm -rf INSIDE own scope allowed", call("exec", { command: "rm -rf workspace-pic/build" }), "444444", "allow");
tt("scopedCritical: rm -rf OUTSIDE own scope blocked", call("exec", { command: "rm -rf workspace-bob/build" }), "444444", "block");
tt("scopedCritical: mixed in+out of scope blocked (every token must resolve)", call("exec", { command: "rm -rf workspace-pic/a workspace-bob/b" }), "444444", "block");
tt("scopedCritical: tokenless critical cannot be proven in-scope -> blocked", call("exec", { command: "git push --force" }), "444444", "block");
// CEILING UNCHANGED: self-promotion paths stay shut even when opted in.
tt("scopedCritical: protected glob STILL wins inside own scope", call("exec", { command: "rm -rf workspace-pic/.env" }), "444444", "block");
tt("scopedCritical: write to openclaw.json STILL blocked", call("write", { paths: ["workspace-pic/openclaw.json"] }), "444444", "block");
tt("scopedCritical: exec-write redirect into .env STILL blocked", call("exec", { command: "echo x > workspace-pic/.env" }), "444444", "block");
tt("scopedCritical: security-doc write STILL blocked", call("write", { paths: ["workspace-pic/AGENTS.md"] }), "444444", "block");
tt("scopedCritical: opted in but NO scopePathGlobs -> grants nothing", call("exec", { command: "rm -rf /tmp/anything" }), "333333", "block");
tt("trusted tool-allowlist: allowed tool passes", call("read", { paths: ["anywhere.txt"] }), "666666", "allow");
tt("trusted tool-allowlist: disallowed tool blocked", call("edit", { paths: ["anywhere.txt"] }), "666666", "block");
tt("trusted exec: not granted -> blocked", call("exec", { command: "python3 tools/exchange_data.py price BTC" }), "666666", "block");
tt("trusted exec: granted + allowlisted script -> allowed", call("exec", { command: "python3 tools/exchange_data.py price BTC" }), "777777", "allow");
tt("trusted exec: granted but script not allowlisted -> blocked", call("exec", { command: "python3 tools/arkham_search.py x" }), "777777", "block");
tt("trusted with no scopePathGlobs: any path allowed if tool allowed", call("write", { paths: ["/etc/random/path.txt"] }), "777777", "allow");
tt("non-trusted stranger still hits normal non-owner path", call("write", { paths: ["anywhere.txt"] }), "999999", "block");
tt("owner unaffected by trustedIds config", call("write", { paths: ["anything.txt"] }), "111111", "allow");
// ── read/write asymmetry: scopePathGlobs confines MUTATING tools only ──
tt("trusted scope: READ outside scope path ALLOWED (cross-agent collab)", call("read", { paths: ["workspace-alice/shared.db"] }), "555555", "allow");
tt("trusted scope: memory_get outside scope ALLOWED", call("memory_get", { paths: ["workspace-alice/x.md"] }), "555555", "allow");
tt("trusted scope: EDIT outside scope still BLOCKED (mutating)", call("edit", { paths: ["workspace-alice/x.md"] }), "555555", "block");
// ── scopeAgents: trusted only inside its agent lane ──
tt("scopeAgents: in-agent write allowed", call("write", { paths: ["workspace-ads/x.md"] }), "888888", "allow", "agent:ads:telegram:direct:1");
tt("scopeAgents: WRONG agent -> falls through to non-owner block", call("write", { paths: ["workspace-ads/x.md"] }), "888888", "block", "agent:sosmed:telegram:direct:1");
tt("scopeAgents: in-agent read cross-workspace allowed", call("read", { paths: ["workspace-sosmed/shared.db"] }), "888888", "allow", "agent:ads:telegram:direct:1");

// ── SECURITY REGRESSION SUITE (external review 2026-10-21) ──
// These encode gaps a reviewer reproduced against v1.30.3. They MUST fail on
// the pre-fix engine: a green suite that misses them is the real bug.
function ts(name, c, sender, expect, sessionKey = "") {
  const v = decide(c, sender, CFG, sessionKey);
  const ok = v.action === expect;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  -> ${v.action} (${v.reason})`);
  ok ? pass++ : fail++;
}

// #3 path traversal: scope/protected globs matched raw text, so "../" walked out.
tt("SEC#3 traversal: ../ into another workspace BLOCKED", call("write", { paths: ["workspace-bob/../workspace-alice/x.md"] }), "555555", "block");
tt("SEC#3 traversal: ../ to a dotenv BLOCKED", call("write", { paths: ["workspace-bob/../.env"] }), "555555", "block");
tt("SEC#3 traversal: deep ../../ BLOCKED", call("write", { paths: ["workspace-bob/a/b/../../../etc/passwd"] }), "555555", "block");
tt("SEC#3 traversal: ./ noise inside scope still ALLOWED", call("write", { paths: ["workspace-bob/./notes.md"] }), "555555", "allow");
tt("SEC#3 traversal: in-scope ../ that stays inside ALLOWED", call("write", { paths: ["workspace-bob/sub/../notes.md"] }), "555555", "allow");

// #4 empty identity: sender==null was treated as owner. On a CHANNEL lane a
// missing id means metadata was LOST -> must not inherit owner.
ts("SEC#4 identity: null sender on telegram lane is NOT owner", call("write", { paths: ["/root/.openclaw/openclaw.json"] }), null, "block", "agent:acme:telegram:group:-100:topic:1");
ts("SEC#4 identity: null sender on whatsapp lane is NOT owner", call("exec", { command: "rm -rf /root/data" }), null, "block", "agent:acme:whatsapp:direct:62811");
ts("SEC#4 identity: null sender on NON-channel lane stays agent-self (cron keeps working)", call("exec", { command: "rm -rf /root/data" }), null, "warn", "agent:acme:explicit");
ts("SEC#4 identity: real owner id on channel lane unaffected", call("write", { paths: ["/root/.openclaw/openclaw.json"] }), OWNER, "approve", "agent:acme:telegram:direct:111111");
ts("SEC#4 identity: back-compat empty sessionKey + null sender = agent-self", call("exec", { command: "ls -la" }), null, "allow");

// #2 script allowlist: the name was matched ANYWHERE in the command string, so
// an allowlisted name sitting in an ARGUMENT vouched for a different binary.
t("SEC#2 script: real invocation allowed", call("exec", { command: "python3 tools/exchange_data.py price BTC" }), STRANGER, "allow");
t("SEC#2 script: venv interpreter allowed", call("exec", { command: "./venv/bin/python tools/exchange_data.py price BTC" }), STRANGER, "allow");
t("SEC#2 script: direct ./tools shebang allowed", call("exec", { command: "./tools/exchange_data.py price BTC" }), STRANGER, "allow");
t("SEC#2 script: documented suffix (semantic_search -> _cli.py) allowed", call("exec", { command: "python3 tools/semantic_search_cli.py query" }), STRANGER, "allow");
t("SEC#2 script: interpreter flag before script allowed", call("exec", { command: "python3 -u tools/exchange_data.py price BTC" }), STRANGER, "allow");
t("SEC#2 script: allowlisted name as ARGUMENT must NOT vouch", call("exec", { command: "python3 tools/evil_exfil.py --config exchange_data.py" }), STRANGER, "block");
t("SEC#2 script: cat of an allowlisted file is not an invocation", call("exec", { command: "cat exchange_data.py" }), STRANGER, "block");
t("SEC#2 script: non-allowlisted script blocked", call("exec", { command: "python3 tools/evil_exfil.py" }), STRANGER, "block");
t("SEC#2 script: traversal out to a same-named script blocked", call("exec", { command: "python3 ../../evil/exchange_data.py" }), STRANGER, "block");
t("SEC#2 script: prefix-only name must not match (exchange_data vs exchange_datax)", call("exec", { command: "python3 tools/exchange_data_evil.sh" }), STRANGER, "block");

// ── SCOPED-CRITICAL for trusted (feature that lived ONLY in a hand-patched
// install until 2026-10-22). A path-scoped PIC may wreck their OWN jail; the
// ceiling (protected/escalation) still wins. Fail-CLOSED: a command with no
// visible target cannot be proven in-scope, so it stays blocked.
// 555555 has a scope but did NOT set allowScopedCritical, so every case in this
// block stays BLOCKED -- it is now the DEFAULT-STRICT suite. The owner decision
// the old KNOWN-DEAD note deferred was taken 2026-10-23: opting in is a
// per-entry flag, covered by the allowScopedCritical block above.
tt("SCOPED-CRIT: delete inside own scope -> blocked (no allowScopedCritical opt-in)", call("exec", { command: "rm -rf workspace-bob/build" }), "555555", "block");
tt("SCOPED-CRIT: rm -rf OUTSIDE scope -> block", call("exec", { command: "rm -rf workspace-alice/build" }), "555555", "block");
tt("SCOPED-CRIT: traversal out of scope -> block", call("exec", { command: "rm -rf workspace-bob/../workspace-alice" }), "555555", "block");
tt("SCOPED-CRIT: mixed in+out of scope -> block", call("exec", { command: "rm -rf workspace-bob/a workspace-alice/b" }), "555555", "block");
tt("SCOPED-CRIT: tokenless critical (force-push) -> block", call("exec", { command: "git push origin main --force" }), "555555", "block");
tt("SCOPED-CRIT: escalation path never in scope -> block", call("exec", { command: "rm -rf workspace-bob/.env" }), "555555", "block");
tt("SCOPED-CRIT: entry WITHOUT scope gets no carve-out", call("exec", { command: "rm -rf /anything" }), "777777", "block");
tt("SCOPED-CRIT: non-exec critical unaffected", call("write", { paths: ["workspace-bob/x"] , command: "" }), "555555", "allow");
// ── WORKSPACE-SCOPED EXEC: a path scope replaces the per-script allowlist,
// because a per-script list does not survive a PIC writing a new tool.
tt("SCOPED-EXEC: own-scope script runs", call("exec", { command: "python3 workspace-bob/tools/new_tool.py" }), "555555", "allow");
tt("SCOPED-EXEC: out-of-scope script blocked", call("exec", { command: "python3 workspace-alice/tools/x.py" }), "555555", "block");
tt("SCOPED-EXEC: tokenless command allowed", call("exec", { command: "git status" }), "555555", "allow");
tt("SCOPED-EXEC: no-scope entry still allowlist-only", call("exec", { command: "python3 tools/whatever.py" }), "777777", "block");

// ── D3: teardown SCRIPT in --dry-run -> not critical (narrow carve-out) ──
// The carve-out must NOT become a magic word: `rm` has no --dry-run flag, so a
// blanket skip would let `rm -rf /x --dry-run` delete /x while reading as safe.
t("dry-run uninstall.sh -> allow (prints only)", call("exec", { command: "bash /tmp/x/scripts/uninstall.sh --harness generic --dry-run" }), OWNER, "allow");
t("dry-run ./uninstall.sh -> allow", call("exec", { command: "./scripts/uninstall.sh --dry-run" }), OWNER, "allow");
t("REAL uninstall.sh (no dry-run) -> approve (still gated)", call("exec", { command: "bash /tmp/x/scripts/uninstall.sh --harness generic" }), OWNER, "approve");
t("BYPASS GUARD: rm -rf with --dry-run -> approve (rm has no such flag)", call("exec", { command: "rm -rf /root/data --dry-run" }), OWNER, "approve");
t("BYPASS GUARD: dry-run script chained with real rm -> approve", call("exec", { command: "bash uninstall.sh --dry-run && rm -rf /root/data" }), OWNER, "approve");
t("BYPASS GUARD: apt remove --dry-run -> approve (pkg mgr not covered)", call("exec", { command: "apt remove rea-agents --dry-run" }), OWNER, "approve");
t("BYPASS GUARD: dry-run script + force-push -> approve", call("exec", { command: "bash uninstall.sh --dry-run; git push origin main --force" }), OWNER, "approve");

// back-compat: empty trustedIds -> byte-identical to pre-trusted-tier behavior
const v = decide(call("read"), "555555", CFG);
const backOk = v.action === "allow" && v.reason === "non-owner allowed tool";
console.log(`${backOk ? "PASS" : "FAIL"}  back-compat: empty trustedIds unaffected  -> ${v.action} (${v.reason})`);
backOk ? pass++ : fail++;

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
