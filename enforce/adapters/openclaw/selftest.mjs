// Standalone logic self-test for owner-warn / non-owner-strict-allowlist model.
const PROTECTED = ["**/.env", "**/.env.*", "**/*.pem", "**/id_rsa", "**/credentials", "**/secrets/**"];
const MUTATING = ["exec", "write", "edit", "apply_patch"];
const OWNERS = ["1083618205"];
const NONOWNER_TOOLS = ["read", "web_search", "web_fetch", "browser", "memory_search", "memory_get"];
const NONOWNER_SCRIPTS = ["exchange_data", "semantic_search", "defillama_search", "arkham_search", "consensus_search"];
const CRIT_EXEC = ["rm\\s+-rf", "git\\s+push.*--force", "git\\s+push.*-f\\b", "\\bDROP\\s+TABLE", "uninstall", "--hard\\b"];
const CRIT_PATHS = ["**/openclaw.json", "**/security_rules.md", "**/AGENTS.md", "**/.env"];
const DEFAULT_TRUSTED_TOOLS = ["read", "write", "edit", "apply_patch", "exec", "web_search", "web_fetch", "browser", "memory_search", "memory_get"];
let TRUSTED = []; // mutated per-test-block below (mirrors config.trustedIds)

function globToRe(glob) {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === "*") { if (glob[i + 1] === "*") { re += ".*"; i++; } else re += "[^/]*"; }
    else if (".+^${}()|[]\\".includes(ch)) re += "\\" + ch; else re += ch;
  }
  return new RegExp("^" + re + "$");
}
function matchesProtected(p, globs) {
  const norm = p.replace(/\\/g, "/"); const base = norm.split("/").pop() || norm;
  for (const g of globs) { const re = globToRe(g); const gb = globToRe(g.replace(/^\*\*\//, ""));
    if (re.test(norm) || re.test(base) || gb.test(norm) || gb.test(base)) return g; }
  return null;
}
function targetPaths(event) {
  const out = [], seen = new Set(); const push = v => { if (typeof v === "string" && v && !seen.has(v)) { seen.add(v); out.push(v); } };
  const p = event.params ?? {}; push(p.path); push(p.file); push(p.filename); push(p.filepath);
  if (Array.isArray(p.paths)) p.paths.forEach(push); if (Array.isArray(event.derivedPaths)) event.derivedPaths.forEach(push);
  return out;
}
function anyProtected(event, globs) {
  for (const tp of targetPaths(event)) { const h = matchesProtected(tp, globs); if (h) return tp; }
  if (event.toolName === "exec") { const cmd = String((event.params ?? {}).command ?? "");
    for (const t of cmd.split(/[\s;|&><'"()]+/).filter(Boolean)) { const h = matchesProtected(t, globs); if (h) return "exec:" + h; } }
  return null;
}
function execRunsAllowedScript(event, scripts) {
  if (event.toolName !== "exec") return false;
  const cmd = String((event.params ?? {}).command ?? ""); if (!cmd) return false;
  if (/[;|&><`$(){}]/.test(cmd)) return false;
  for (const s of scripts) { const esc = s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); const re = new RegExp("(^|[\\/\\s])" + esc + "[A-Za-z0-9_]*\\.py([\\s]|$)"); if (re.test(cmd)) return true; }
  return false;
}
function resolveSenderId(event, ctx) {
  for (const src of [ctx, event, event.metadata]) if (src && src.senderId != null && String(src.senderId).length) return String(src.senderId);
  const sk = String(ctx.sessionKey ?? ""); const parts = sk.split(":"); const di = parts.indexOf("direct");
  if (di >= 0 && parts[di + 1]) return parts[di + 1];
  return null;
}
function writeTargets(cmd) {
  const out = [];
  const redir = /(?:^|\s)(?:[0-9]*|&)?>>?\s*([^\s;|&><'"()]+)/g;
  let m;
  while ((m = redir.exec(cmd)) !== null) { if (m[1]) out.push(m[1]); }
  const tee = /(?:^|[|;&]\s*|\s)tee\b((?:\s+(?:-a|--append))*)((?:\s+[^\s;|&><'"()]+)+)/g;
  while ((m = tee.exec(cmd)) !== null) {
    for (const t of (m[2] || "").split(/\s+/).filter(Boolean)) { if (!t.startsWith("-")) out.push(t); }
  }
  return out;
}
function criticalHit(event) {
  const toolName = event.toolName;
  if (["write", "edit", "apply_patch"].includes(toolName)) {
    for (const tp of targetPaths(event)) { const h = matchesProtected(tp, CRIT_PATHS); if (h) return "path:" + tp; }
  }
  if (toolName === "exec") {
    const cmd = String((event.params ?? {}).command ?? "");
    for (const pat of CRIT_EXEC) { try { if (new RegExp(pat, "i").test(cmd)) return "exec:" + pat; } catch {} }
    for (const wt of writeTargets(cmd)) { const h = matchesProtected(wt, CRIT_PATHS); if (h) return "exec-write:" + wt; }
  }
  return null;
}
function findTrusted(senderId) {
  for (const t of TRUSTED) if (t.id === senderId) return t;
  return null;
}
function decideTrusted(event, entry) {
  const toolName = event.toolName;
  const protectedHit = anyProtected(event, PROTECTED);
  if (protectedHit) return { block: true, why: "trusted-protected" };
  if (entry.scopePathGlobs && entry.scopePathGlobs.length) {
    const tp = targetPaths(event);
    if (tp.length && tp.some((p) => !matchesProtected(p, entry.scopePathGlobs))) return { block: true, why: "trusted-scope" };
  }
  const crit = criticalHit(event);
  if (crit) return { block: true, why: "trusted-critical" };
  const allowedTools = entry.allowedTools ?? DEFAULT_TRUSTED_TOOLS;
  if (toolName === "exec") {
    if (!allowedTools.includes("exec")) return { block: true, why: "trusted-exec-not-allowlisted" };
    return execRunsAllowedScript(event, entry.allowedScripts ?? NONOWNER_SCRIPTS)
      ? { block: false, why: "trusted-script" } : { block: true, why: "trusted-exec-script-blocked" };
  }
  if (allowedTools.includes(toolName)) return { block: false, why: "trusted-tool" };
  return { block: true, why: "trusted-tool-blocked" };
}
function decide(event, ctx) {
  const toolName = event.toolName;
  const sender = resolveSenderId(event, ctx);
  const isOwner = sender == null || OWNERS.includes(sender);
  const protectedHit = anyProtected(event, PROTECTED);
  if (isOwner) {
    const crit = criticalHit(event);
    if (crit) return { block: false, approval: true, why: "owner-approval" };
    return { block: false, why: protectedHit ? "owner-warn" : "owner-pass" };
  }
  if (sender != null && TRUSTED.length) {
    const entry = findTrusted(sender);
    if (entry) return decideTrusted(event, entry);
  }
  if (protectedHit) return { block: true, why: "nonowner-secret" };
  if (NONOWNER_TOOLS.includes(toolName)) return { block: false, why: "nonowner-allowed-tool" };
  if (toolName === "exec") return execRunsAllowedScript(event, NONOWNER_SCRIPTS)
    ? { block: false, why: "nonowner-script" } : { block: true, why: "nonowner-exec" };
  if (MUTATING.includes(toolName)) return { block: true, why: "nonowner-mutate" };
  return { block: true, why: "nonowner-default" };
}

let pass = 0, fail = 0;
function t(name, event, ctx, expectBlock, expectWhy) {
  const r = decide(event, ctx);
  const ok = r.block === expectBlock && (expectWhy ? r.why === expectWhy : true);
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  -> ${JSON.stringify(r)}`);
  ok ? pass++ : fail++;
}
const OWNER = { sessionKey: "agent:analyst:telegram:direct:1083618205", senderId: "1083618205" };
const SELF = { sessionKey: "agent:analyst" }; // no senderId => agent-operated-by-owner
const STRANGER = { sessionKey: "agent:analyst:telegram:direct:999", senderId: "999" };

// OWNER — never hard-blocked; critical actions require approval (are-you-sure)
t("owner rm -rf -> approval", { toolName: "exec", params: { command: "rm -rf /tmp/x" } }, OWNER, false, "owner-approval");
t("owner git push --force -> approval", { toolName: "exec", params: { command: "git push origin main --force" } }, OWNER, false, "owner-approval");
t("owner write openclaw.json -> approval", { toolName: "write", params: { path: "/root/.openclaw/openclaw.json" } }, OWNER, false, "owner-approval");
t("owner edit AGENTS.md -> approval", { toolName: "edit", params: { path: "/x/AGENTS.md" } }, OWNER, false, "owner-approval");
t("owner normal exec -> pass", { toolName: "exec", params: { command: "ls -la" } }, OWNER, false, "owner-pass");
t("owner normal write -> pass", { toolName: "write", params: { path: "/tmp/note.txt" } }, OWNER, false, "owner-pass");
t("owner cat .env -> warn+pass (read)", { toolName: "exec", params: { command: "cat .env" } }, OWNER, false, "owner-warn");
t("owner grep security file -> pass (read arg)", { toolName: "exec", params: { command: "grep -n foo docs/security_rules.md" } }, OWNER, false, "owner-pass");
t("owner echo > openclaw.json -> approval (write target)", { toolName: "exec", params: { command: "echo x > /root/.openclaw/openclaw.json" } }, OWNER, false, "owner-approval");
t("owner tee -a .env -> approval (tee write)", { toolName: "exec", params: { command: "echo x | tee -a /x/.env" } }, OWNER, false, "owner-approval");
t("owner edit .env -> approval (write to critical path)", { toolName: "edit", params: { path: "/x/.env" } }, OWNER, false, "owner-approval");

// SELF (agent-operated-by-owner, no senderId) — treated as owner, never blocked
t("self exec", { toolName: "exec", params: { command: "python3 procedures/backup.py" } }, SELF, false, "owner-pass");
t("self write config -> approval", { toolName: "write", params: { path: "/root/.openclaw/openclaw.json" } }, SELF, false, "owner-approval");
t("self cat .env -> warn+pass (read)", { toolName: "exec", params: { command: "cat .env" } }, SELF, false, "owner-warn");

// NON-OWNER — strict
t("stranger exec allowed script", { toolName: "exec", params: { command: "python3 tools/exchange_data.py price BTC" } }, STRANGER, false, "nonowner-script");
t("stranger exec semantic_search_cli", { toolName: "exec", params: { command: "python3 tools/semantic_search_cli.py --query x" } }, STRANGER, false, "nonowner-script"); // _cli suffix now matched
t("stranger exec consensus_search", { toolName: "exec", params: { command: "python3 tools/consensus_search.py BTC" } }, STRANGER, false, "nonowner-script");
t("stranger exec arbitrary shell", { toolName: "exec", params: { command: "ls -la /root" } }, STRANGER, true, "nonowner-exec");
t("stranger exec allowed+chaining", { toolName: "exec", params: { command: "python3 tools/exchange_data.py price BTC; rm -rf /" } }, STRANGER, true, "nonowner-exec"); // chaining rejected
t("stranger write", { toolName: "write", params: { path: "/tmp/x.txt" } }, STRANGER, true, "nonowner-mutate");
t("stranger edit", { toolName: "edit", params: { path: "/tmp/x.txt" } }, STRANGER, true, "nonowner-mutate");
t("stranger read normal", { toolName: "read", params: { path: "/tmp/x.txt" } }, STRANGER, false, "nonowner-allowed-tool");
t("stranger read .env blocked", { toolName: "read", params: { path: "/x/.env" } }, STRANGER, true, "nonowner-secret");
t("stranger web_search", { toolName: "web_search", params: {} }, STRANGER, false, "nonowner-allowed-tool");
t("stranger memory_search", { toolName: "memory_search", params: {} }, STRANGER, false, "nonowner-allowed-tool");
t("stranger exec cat credentials", { toolName: "exec", params: { command: "cat ~/.config/credentials" } }, STRANGER, true, "nonowner-secret");
t("stranger unknown tool", { toolName: "some_write_tool", params: {} }, STRANGER, true, "nonowner-default");

// ── trusted/delegated tier (above non-owner, below owner) ──
TRUSTED = [
  { id: "555555", scopePathGlobs: ["workspace-bob/**"] },
  { id: "666666", allowedTools: ["read", "write"], allowedScripts: ["exchange_data"] },
  { id: "777777", allowedTools: ["read", "write", "exec"], allowedScripts: ["exchange_data"] },
];
const T1 = { sessionKey: "agent:analyst:telegram:direct:555555", senderId: "555555" };
const T2 = { sessionKey: "agent:analyst:telegram:direct:666666", senderId: "666666" };
const T3 = { sessionKey: "agent:analyst:telegram:direct:777777", senderId: "777777" };

t("trusted scope: in-scope write allowed", { toolName: "write", params: { path: "workspace-bob/notes.md" } }, T1, false, "trusted-tool");
t("trusted scope: out-of-scope write blocked", { toolName: "write", params: { path: "workspace-alice/notes.md" } }, T1, true, "trusted-scope");
t("trusted scope: protected glob wins even in scope", { toolName: "write", params: { path: "workspace-bob/.env" } }, T1, true, "trusted-protected");
t("trusted scope: critical action blocked not approved", { toolName: "exec", params: { command: "rm -rf workspace-bob/x" } }, T1, true, "trusted-critical");
t("trusted tool-allowlist: allowed tool passes", { toolName: "read", params: { path: "anywhere.txt" } }, T2, false, "trusted-tool");
t("trusted tool-allowlist: disallowed tool blocked", { toolName: "edit", params: { path: "anywhere.txt" } }, T2, true, "trusted-tool-blocked");
t("trusted exec: not granted -> blocked", { toolName: "exec", params: { command: "python3 tools/exchange_data.py price BTC" } }, T2, true, "trusted-exec-not-allowlisted");
t("trusted exec: granted + allowlisted script -> allowed", { toolName: "exec", params: { command: "python3 tools/exchange_data.py price BTC" } }, T3, false, "trusted-script");
t("trusted exec: granted but script not allowlisted -> blocked", { toolName: "exec", params: { command: "python3 tools/arkham_search.py x" } }, T3, true, "trusted-exec-script-blocked");
t("trusted with no scopePathGlobs: any path allowed if tool allowed", { toolName: "write", params: { path: "/etc/random/path.txt" } }, T3, false, "trusted-tool");
t("non-trusted stranger still hits normal non-owner path", { toolName: "write", params: { path: "anywhere.txt" } }, STRANGER, true, "nonowner-mutate");
t("owner unaffected by TRUSTED config", { toolName: "write", params: { path: "anything.txt" } }, OWNER, false, "owner-pass");

// back-compat: empty TRUSTED -> byte-identical to pre-trusted-tier behavior
TRUSTED = [];
t("back-compat: empty trustedIds unaffected", { toolName: "read", params: { path: "x" } }, T1, false, "nonowner-allowed-tool");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
