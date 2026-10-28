// Self-test for the shared enforce policy engine.
// Run: node --experimental-strip-types enforce/core/policy.selftest.mjs
//  (or transpile). Uses dynamic import of the .ts via strip-types.
import { decide, normalizeConfig } from "./policy.ts";

const CFG = normalizeConfig({
  ownerIds: ["111111"],
  nonOwnerAllowedScripts: ["exchange_data", "semantic_search", "consensus_search"],
});

let pass = 0, fail = 0;
function call(toolName, { command = "", paths = [], action, cwd } = {}) { return { toolName, command, paths, action, cwd }; }
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
// Config whose allowlist SHIPS A WRAPPER -- used by the bare-binary deny-message
// cases below. r()/t() above bind CFG at call time, so these need their own
// helpers rather than another sender constant (a sender cannot carry a config).
const CFG_W = normalizeConfig({
  ownerIds: ["111111"],
  nonOwnerAllowedScripts: ["exchange_data", "yt_dlp_tool"],
});
function rw(name, c, sender, reasonRe) {
  const v = decide(c, sender, CFG_W);
  const ok = v.action === "block" && reasonRe.test(v.reason);
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  -> ${v.action} (${v.reason})`);
  ok ? pass++ : fail++;
}
function tw(name, c, sender, expect) {
  const v = decide(c, sender, CFG_W);
  const ok = v.action === expect;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  -> ${v.action} (${v.reason})`);
  ok ? pass++ : fail++;
}

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
// BARE BINARY WITH A SHIPPED WRAPPER (measured 2026-10-23, cost: 2 hours).
// The allowlist matches *.py, so a raw binary can never match it -- and the
// generic denial reads as a missing permission. An agent acted on exactly that
// and asked for an allowlist that already contained the wrapper. Blocking is
// correct; the EXPLANATION is what the caller acts on one layer up.
rw("bare binary w/ wrapper -> names the wrapper, not a permission problem",
  call("exec", { command: "yt-dlp https://youtu.be/abc" }), STRANGER, /yt_dlp_tool\.py/);
rw("bare binary w/ wrapper -> says it is NOT a missing permission",
  call("exec", { command: "yt-dlp https://youtu.be/abc" }), STRANGER, /NOT a missing permission/);
// Still a BLOCK: the hint is diagnostic only and must never widen what runs.
tw("bare binary w/ wrapper is still blocked",
  call("exec", { command: "yt-dlp https://youtu.be/abc" }), STRANGER, "block");
// Tight matching: an unrelated binary must NOT be pointed at someone else's
// wrapper -- naming the wrong script sends the caller somewhere worse than silence.
rw("unrelated bare binary -> stays generic",
  call("exec", { command: "curl https://example.com" }), STRANGER, /restricted to allowlisted tools/);
// The wrapper itself, invoked properly, must ALLOW -- proving the hint points at
// a form that actually works rather than at another dead end.
tw("the wrapper invoked properly -> allow",
  call("exec", { command: "python3 wrappers/yt_dlp_tool.py info https://youtu.be/abc" }), STRANGER, "allow");

// RETRY-LOOP DEFENCE (measured 2026-10-26). In one WhatsApp group lane 28 of 34
// denied exec calls were `echo ok` liveness probes ~3s apart: the model read the
// bare generic denial as a TRANSIENT outage and kept testing whether exec had
// "come back". The wall is fixed policy, so the reason must SAY it is fixed and
// name what IS available -- otherwise the gate blocks correctly and still burns
// a retry loop one layer up. Diagnostic only: widens nothing (tw asserts block).
const CFG_L = normalizeConfig({
  ownerIds: ["111111"],
  nonOwnerAllowedTools: ["read", "web_search", "web_fetch", "peer_recall"],
  nonOwnerAllowedScripts: ["yt_dlp_tool", "run_binary"],
});
function rl(name, c, sender, reasonRe) {
  const v = decide(c, sender, CFG_L);
  const ok = v.action === "block" && reasonRe.test(v.reason);
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  -> ${v.action} (${v.reason})`);
  ok ? pass++ : fail++;
}
function tl(name, c, sender, expect) {
  const v = decide(c, sender, CFG_L);
  const ok = v.action === expect;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  -> ${v.action} (${v.reason})`);
  ok ? pass++ : fail++;
}
rl("liveness probe -> reason says FIXED wall, not an outage",
  call("exec", { command: "echo ok" }), STRANGER, /FIXED policy wall/);
rl("liveness probe -> reason tells caller NOT to retry",
  call("exec", { command: "echo ok" }), STRANGER, /do NOT retry/);
rl("liveness probe -> reason names the tools that ARE available",
  call("exec", { command: "echo ok" }), STRANGER, /read, web_search, web_fetch, peer_recall/);
// Wrong-door case: reading a file via exec when the `read` tool is allowed. The
// capability EXISTS; only the door is wrong. Naming the working door beats a
// denial the caller reads as "no access to that file".
rl("file read via exec -> points at the allowed read tool",
  call("exec", { command: "sed -n '1,40p' scripts/x.sh" }), STRANGER, /'read' tool IS allowed/);
rl("cat via exec -> points at the allowed read tool",
  call("exec", { command: "cat /etc/hosts" }), STRANGER, /read\(<path>\)/);
// Still blocks: every hint is diagnostic and must never widen what runs.
tl("liveness probe is still blocked", call("exec", { command: "echo ok" }), STRANGER, "block");
tl("file read via exec is still blocked",
  call("exec", { command: "cat /etc/hosts" }), STRANGER, "block");
// The read-tool hint must NOT appear when `read` is not allowed in that lane --
// pointing at a door that is also shut is worse than silence.
const CFG_NR = normalizeConfig({ ownerIds: ["111111"], nonOwnerAllowedTools: ["web_search"], nonOwnerAllowedScripts: [] });
{
  const v = decide(call("exec", { command: "cat /etc/hosts" }), STRANGER, CFG_NR);
  const ok = v.action === "block" && !/'read' tool IS allowed/.test(v.reason);
  console.log(`${ok ? "PASS" : "FAIL"}  no read tool in lane -> no read hint  -> ${v.action} (${v.reason})`);
  ok ? pass++ : fail++;
}
// Empty allowlist must render "none", never an empty dangling sentence.
{
  const v = decide(call("exec", { command: "echo ok" }), STRANGER, CFG_NR);
  const ok = v.action === "block" && /Available here instead: web_search/.test(v.reason);
  console.log(`${ok ? "PASS" : "FAIL"}  lane alternatives are rendered  -> ${v.action} (${v.reason})`);
  ok ? pass++ : fail++;
}
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

// ── RELATIVE-PATH FRICTION (measured 2026-10-28): the token filter keeps any arg
// containing "/", and a relative token can never match an absolute-rooted glob.
// A PIC could run their tool by absolute path but not the relative form the
// workspace docs tell them to use. Resolve relative tokens against the caller's
// KNOWN cwd -- and ONLY a known cwd (see the regression guard below).
tt("REL: relative token + cwd in scope -> allow",
  call("exec", { command: "python3 tools/mine.py", cwd: "workspace-bob" }), "555555", "allow");
tt("REL: venv interpreter prefix + cwd -> allow",
  call("exec", { command: "./venv/bin/python tools/mine.py", cwd: "workspace-bob" }), "555555", "allow");
tt("REL: ../ escape is normalised BEFORE matching -> block",
  call("exec", { command: "python3 ../workspace-alice/x.py", cwd: "workspace-bob" }), "555555", "block");
tt("REL: absolute out-of-scope token is never re-rooted by cwd",
  call("exec", { command: "python3 /etc/evil.py", cwd: "workspace-bob" }), "555555", "block");
// REGRESSION GUARD: an earlier draft re-rooted against the scope globs when no
// cwd was known, which made EVERY relative token in-scope -- "workspace-alice/x.py"
// became "workspace-bob/workspace-alice/x.py" and matched. Caught by selftest.
tt("REL: no cwd -> relative token stays blocked (not re-rooted into scope)",
  call("exec", { command: "python3 workspace-alice/tools/x.py" }), "555555", "block");
// SCRATCH: writing a temp file was blocked over a path that grants nothing.
tt("SCRATCH: /tmp output arg allowed",
  call("exec", { command: "python3 workspace-bob/tools/mine.py --out /tmp/x.json" }), "555555", "allow");
tt("SCRATCH: protectedGlobs still wins inside /tmp",
  call("exec", { command: "cat /tmp/.env" }), "555555", "block");

// ── agentWorkspaces: the COMMON call omits workdir entirely (exec's own schema
// says "omit to use the default cwd", and fleet docs tell people to omit it).
// The runtime's before_tool_call ctx carries NO workspaceDir, so the declared
// map is the only deterministic source for that default.
const CFG_WS = normalizeConfig({
  ownerIds: ["111111"],
  agentWorkspaces: { "agent:bob": "workspace-bob" },
  trustedIds: [{ id: "555555", scopePathGlobs: ["workspace-bob/**"] }],
});
function tws(name, c, sender, expect, sessionKey = "agent:bob:telegram:group:-100:topic:1") {
  const v = decide(c, sender, CFG_WS, sessionKey);
  const ok = v.action === expect;
  if (ok) { pass++; console.log(`PASS  ${name}  -> ${v.action} (${v.reason})`); }
  else { fail++; console.log(`FAIL  ${name}  -> ${v.action} (${v.reason})`); }
}
tws("WS: no workdir -> declared agent workspace resolves the relative token",
  call("exec", { command: "python3 tools/mine.py" }), "555555", "allow");
tws("WS: no workdir -> venv prefix resolves too",
  call("exec", { command: "./venv/bin/python tools/mine.py" }), "555555", "allow");
tws("WS: declared workspace does NOT rescue a cross-workspace relative token",
  call("exec", { command: "python3 ../workspace-alice/x.py" }), "555555", "block");
tws("WS: explicit workdir still wins over the declared default",
  call("exec", { command: "python3 tools/mine.py", cwd: "workspace-bob" }), "555555", "allow");
tws("WS: wrong agent lane -> map does not apply, relative token blocked",
  call("exec", { command: "python3 tools/mine.py" }), "555555", "block", "agent:zed:telegram:group:-100:topic:1");
// BACK-COMPAT: an install that never declares agentWorkspaces must behave exactly
// as before this field existed.
tt("WS: empty agentWorkspaces -> relative token still blocked (pre-patch behaviour)",
  call("exec", { command: "python3 tools/mine.py" }), "555555", "block");

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

// ── EXEC RESULT RETRIEVAL (process read-vs-write split) ──────────────────────
// WHY these exist: an allowed exec that outruns the foreground yield window is
// handed back as a background session handle, and `process` is the only door to
// that output. Allowing the exec but not the read made every slow allowlisted
// script silently unreadable (measured 2026-10-27). These lock BOTH halves: the
// read half opens, the write half stays shut.
t("exec-result: non-owner process poll -> allow", call("process", { action: "poll" }), STRANGER, "allow");
t("exec-result: non-owner process log -> allow", call("process", { action: "log" }), STRANGER, "allow");
t("exec-result: non-owner process list -> allow", call("process", { action: "list" }), STRANGER, "allow");
t("exec-result: action is case-insensitive (POLL) -> allow", call("process", { action: "POLL" }), STRANGER, "allow");
// Mutating actions are NOT result retrieval -- they stay blocked.
t("exec-result: non-owner process kill -> block", call("process", { action: "kill" }), STRANGER, "block");
t("exec-result: non-owner process send-keys -> block", call("process", { action: "send-keys" }), STRANGER, "block");
t("exec-result: non-owner process write -> block", call("process", { action: "write" }), STRANGER, "block");
// FAIL-CLOSED: an unknown or missing action must land on the write side.
t("exec-result: unknown action -> block (fail-closed)", call("process", { action: "teleport" }), STRANGER, "block");
t("exec-result: absent action -> block (fail-closed)", call("process"), STRANGER, "block");
r("exec-result: deny names the read actions, not the allowlist", call("process", { action: "kill" }), STRANGER, /process list\|poll\|log/);
// Owner is untouched by the split.
t("exec-result: OWNER process kill -> allow", call("process", { action: "kill" }), OWNER, "allow");
// A lane that cannot reach exec at all has no background output to collect,
// so it gets nothing -- the grant is tied to the exec grant, not standalone.
const CFG_NOEXEC = normalizeConfig({ ownerIds: ["111111"], nonOwnerAllowedScripts: [] });
function tn(name, c, sender, expect) {
  const v = decide(c, sender, CFG_NOEXEC);
  const ok = v.action === expect;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  -> ${v.action} (${v.reason})`);
  ok ? pass++ : fail++;
}
tn("exec-result: no allowlisted scripts -> process poll blocked", call("process", { action: "poll" }), STRANGER, "block");

// back-compat: empty trustedIds -> byte-identical to pre-trusted-tier behavior
const v = decide(call("read"), "555555", CFG);
const backOk = v.action === "allow" && v.reason === "non-owner allowed tool";
console.log(`${backOk ? "PASS" : "FAIL"}  back-compat: empty trustedIds unaffected  -> ${v.action} (${v.reason})`);
backOk ? pass++ : fail++;

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
