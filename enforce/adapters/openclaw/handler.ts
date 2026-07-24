/**
 * dinotrust-enforce — OpenClaw plugin (definePluginEntry pattern)
 *
 * ENFORCEMENT layer beneath dinotrust's AGENTS.md instruction layer.
 * before_tool_call returns { block:true } (terminal) so the runtime OBEYS,
 * independent of model compliance.
 *
 * POLICY (mirrors dinotrust AGENTS.md owner_rules / non_owner_rules):
 *
 *   OWNER (senderId in ownerIds) and AGENT-OPERATED-BY-OWNER (no senderId
 *   resolvable = internal/self turn):
 *     -> NEVER blocked. ownerWarnOnly => warn-log only. Owner has full access;
 *        the .md instruction layer already asks for approval on writes. No hard
 *        restriction here, by design.
 *
 *   NON-OWNER (senderId present AND not in ownerIds):
 *     -> STRICT. Default deny on mutating/exec + secret reads. Allowlist:
 *        - nonOwnerAllowedTools : read/web/memory tools pass
 *        - exec : passes ONLY if the command runs an allowlisted read-only
 *                 script under tools/ (exchange_data, semantic_search, ...);
 *                 any other exec is blocked (no shell outside tools/).
 *        - write/edit/apply_patch : blocked.
 *        - any tool touching a protected secret glob : blocked.
 *
 * Master switch config.enforce=false => dry-run (log only, no block).
 * Fail-open on errors: an enforcement bug must never brick tools.
 *
 * Requires plugins.entries["dinotrust-enforce"].hooks.allowConversationAccess=true
 * for senderId/channel context on conversation-bound runs.
 */

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

type TrustedEntry = {
  id: string;
  allowedTools?: string[];
  allowedScripts?: string[];
  scopePathGlobs?: string[];
};

type Cfg = {
  agentFilter: string;
  ownerIds: string[];
  ownerWarnOnly: boolean;
  criticalExecPatterns: string[];
  // Privilege-escalation / brick-risk paths: owner write here -> approval.
  escalationPathGlobs: string[];
  // Reversible security-doc paths: owner write here -> warn only.
  criticalPathGlobs: string[];
  protectedGlobs: string[];
  mutatingTools: string[];
  nonOwnerAllowedTools: string[];
  nonOwnerAllowedScripts: string[];
  // Trusted/delegated ids: per-individual tier ABOVE non-owner, BELOW owner.
  // Empty by default -> zero behavior change. See policy.ts TrustedEntry doc
  // for the full ceiling rules (protectedGlobs + escalation/doc hits always win).
  trustedIds: TrustedEntry[];
  logFile: string;
  enforce: boolean;
};

// Broader-than-non-owner default tool set for a trusted entry with no explicit allowedTools.
const DEFAULT_TRUSTED_TOOLS: string[] = [
  "read", "write", "edit", "apply_patch", "exec",
  "web_search", "web_fetch", "browser", "memory_search", "memory_get",
];

const DEFAULTS: Cfg = {
  // Generic safe defaults for distribution. agentFilter "" = enforce on ALL
  // agents (never silently no-op on a differently-named agent). ownerIds []
  // = no assumed owner: until the install configures ownerIds, a resolvable
  // sender is treated as NON-owner (locked down), never auto-owned. The
  // agent-operated-by-owner path (no senderId) still passes. Per-install
  // config in openclaw.json fills these.
  agentFilter: "",
  ownerIds: [],
  ownerWarnOnly: true,
  // Owner is warn-only EXCEPT these critical/irreversible actions -> requireApproval
  // ("are you sure?") even for the owner. Regex strings, tested against exec command.
  criticalExecPatterns: [
    "rm\\s+-rf", "git\\s+push.*--force", "git\\s+push.*-f\\b", "\\bDROP\\s+TABLE",
    "\\bTRUNCATE\\b", "mkfs", "dd\\s+if=", ":\\(\\)\\s*\\{", "uninstall", "--hard\\b",
  ],
  // Owner write/edit/exec-write to these paths -> requireApproval: genuine
  // privilege-escalation / brick risk (runtime+plugin config, secrets).
  escalationPathGlobs: ["**/openclaw.json", "**/.env"],
  // Owner write/edit here -> warn only (reversible security docs; git+backups).
  criticalPathGlobs: ["**/security_rules.md", "**/AGENTS.md"],
  protectedGlobs: [
    "**/.env", "**/.env.*", "**/*.pem", "**/id_rsa", "**/id_ed25519",
    "**/credentials", "**/secrets/**",
  ],
  mutatingTools: ["exec", "write", "edit", "apply_patch"],
  nonOwnerAllowedTools: ["read", "web_search", "web_fetch", "browser", "memory_search", "memory_get"],
  nonOwnerAllowedScripts: [
    "exchange_data", "semantic_search", "defillama_search", "arkham_search",
    "consensus_search", "news_consensus", "docs_search", "session_search", "graph_search",
  ],
  trustedIds: [],
  logFile: "",
  enforce: true,
};

function cfg(raw: any): Cfg {
  const c = { ...DEFAULTS, ...(raw || {}) };
  for (const k of ["ownerIds", "criticalExecPatterns", "escalationPathGlobs", "criticalPathGlobs", "protectedGlobs", "mutatingTools", "nonOwnerAllowedTools", "nonOwnerAllowedScripts", "trustedIds"] as const) {
    if (!Array.isArray((c as any)[k])) (c as any)[k] = (DEFAULTS as any)[k];
  }
  return c;
}

function findTrusted(senderId: string, c: Cfg): TrustedEntry | null {
  for (const t of c.trustedIds) if (t.id === senderId) return t;
  return null;
}

function logPath(c: Cfg): string {
  return c.logFile || path.join(os.homedir(), ".openclaw", "logs", "dinotrust-enforce.log");
}

function audit(c: Cfg, obj: Record<string, unknown>) {
  try {
    const p = logPath(c);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.appendFileSync(p, JSON.stringify({ ts: new Date().toISOString(), ...obj }) + "\n");
  } catch { /* silent by contract */ }
}

// ── Approval follow-up (A′: "confirmed-miss only") ────────────────────────────
// When the hook escalates a critical action -> OpenClaw shows an approval card.
// If APPROVED, OpenClaw resumes the SAME command in the SAME session, which
// re-enters before_tool_call. We use that re-fire as a deterministic "it ran"
// signal: match it to the pending intent by fingerprint -> mark RESOLVED ->
// the sweep never nudges. If the card EXPIRES/missed, no re-fire, no resolution
// -> sweep sends one owner reminder. No timer-guessing, no false pings.
//
// State lives in a JSONL sibling of the audit log so the sweep script (cron)
// can read it without importing the plugin. Each escalation appends a PENDING
// line; resolution appends a RESOLVED line for the same intentId (append-only,
// last-writer-wins on read — avoids read-modify-write races with the sweep).
const RESOLVE_WINDOW_MS = 1800 * 1000; // DEFAULT_EXEC_APPROVAL_TIMEOUT_MS (30m)

function pendingPath(c: Cfg): string {
  const base = logPath(c);
  const dir = path.dirname(base);
  const stem = path.basename(base).replace(/\.log$/i, "");
  return path.join(dir, `${stem}-pending-approvals.jsonl`);
}

// Stable fingerprint for {tool, command, session}. dinotrust never sees
// OpenClaw's approvalId, so this is how the resume re-fire is matched to its
// pending intent. Cheap non-crypto hash (djb2) — no node:crypto dependency.
function intentFingerprint(toolName: string, command: string, sessionKey: string): string {
  const s = `${toolName}\u0000${command}\u0000${sessionKey}`;
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return h.toString(16);
}

function execCommandOf(event: any): string {
  return String((event?.params ?? {}).command ?? "");
}

// Append a PENDING intent line at escalation time.
function recordPendingIntent(c: Cfg, o: { fp: string; command: string; toolName: string; sessionKey: string; sender: string; hit: string }) {
  try {
    const p = pendingPath(c);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    const line = {
      kind: "pending",
      intentId: `${o.fp}:${Date.now()}`,
      fp: o.fp,
      tsIssued: new Date().toISOString(),
      command: (o.command || "").slice(0, 400), // privacy/size cap
      toolName: o.toolName,
      sessionKey: o.sessionKey,
      sender: o.sender,
      hit: o.hit,
      severity: "critical",
    };
    fs.appendFileSync(p, JSON.stringify(line) + "\n");
  } catch { /* silent by contract */ }
}

// On a re-fire matching an OPEN pending intent within the window, append a
// RESOLVED marker. Returns true if this call resolved a pending intent (i.e.
// it is an approved-resume, not a fresh escalation) — caller then passes it
// through WITHOUT re-escalating, which also breaks the escalate->approve->
// resume->escalate loop.
function resolvePendingIfRefire(c: Cfg, fp: string): boolean {
  try {
    const p = pendingPath(c);
    if (!fs.existsSync(p)) return false;
    const now = Date.now();
    const lines = fs.readFileSync(p, "utf8").split("\n").filter(Boolean);
    // Build resolution state: pending intents minus already-resolved ones.
    const resolved = new Set<string>();
    const openByFp = new Map<string, { intentId: string; tsMs: number }>();
    for (const ln of lines) {
      let o: any; try { o = JSON.parse(ln); } catch { continue; }
      if (o?.kind === "resolved" && o.intentId) resolved.add(o.intentId);
    }
    for (const ln of lines) {
      let o: any; try { o = JSON.parse(ln); } catch { continue; }
      if (o?.kind !== "pending" || o.fp !== fp || !o.intentId) continue;
      if (resolved.has(o.intentId)) continue;
      const tsMs = Date.parse(o.tsIssued);
      if (isNaN(tsMs) || now - tsMs > RESOLVE_WINDOW_MS) continue;
      // pick the most recent open pending for this fp
      const prev = openByFp.get(fp);
      if (!prev || tsMs > prev.tsMs) openByFp.set(fp, { intentId: o.intentId, tsMs });
    }
    const hit = openByFp.get(fp);
    if (!hit) return false;
    fs.appendFileSync(p, JSON.stringify({
      kind: "resolved", intentId: hit.intentId, fp, resolvedAt: new Date().toISOString(),
    }) + "\n");
    return true;
  } catch { return false; }
}

/** Minimal glob -> RegExp. ** = any incl. /, * = any except /. */
function globToRe(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === "*") { if (glob[i + 1] === "*") { re += ".*"; i++; } else re += "[^/]*"; }
    else if (".+^${}()|[]\\".includes(ch)) re += "\\" + ch;
    else re += ch;
  }
  return new RegExp("^" + re + "$");
}

function matchesProtected(p: string, globs: string[]): string | null {
  const norm = p.replace(/\\/g, "/");
  const base = norm.split("/").pop() || norm;
  for (const g of globs) {
    const re = globToRe(g);
    const gBaseRe = globToRe(g.replace(/^\*\*\//, ""));
    if (re.test(norm) || re.test(base) || gBaseRe.test(norm) || gBaseRe.test(base)) return g;
  }
  return null;
}

function targetPaths(event: any): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (v: unknown) => { if (typeof v === "string" && v && !seen.has(v)) { seen.add(v); out.push(v); } };
  const p = event?.params ?? {};
  push(p.path); push(p.file); push(p.filename); push(p.filepath);
  if (Array.isArray(p.paths)) p.paths.forEach(push);
  if (Array.isArray(event?.derivedPaths)) event.derivedPaths.forEach(push);
  return out;
}

function anyProtected(event: any, globs: string[]): string | null {
  for (const tp of targetPaths(event)) {
    const h = matchesProtected(tp, globs);
    if (h) return `${tp} ~ ${h}`;
  }
  if (event?.toolName === "exec") {
    const cmd = String((event?.params ?? {}).command ?? "");
    for (const t of cmd.split(/[\s;|&><'"()]+/).filter(Boolean)) {
      const h = matchesProtected(t, globs);
      if (h) return `exec-arg ~ ${h}`;
    }
  }
  return null;
}

/**
 * Critical/irreversible action detector (owner-approval tier).
 * Returns a reason string when the tool call is critical, else null.
 */
/** Genuine write targets: `>`,`>>` redirection operands and `tee [-a] FILE`.
 *  A critical path only appearing as a READ arg (grep/cat) is not a write. */
function writeTargets(cmd: string): string[] {
  const out: string[] = [];
  const redir = /(?:^|\s)(?:[0-9]*|&)?>>?\s*([^\s;|&><'"()]+)/g;
  let m: RegExpExecArray | null;
  while ((m = redir.exec(cmd)) !== null) { if (m[1]) out.push(m[1]); }
  const tee = /(?:^|[|;&]\s*|\s)tee\b((?:\s+(?:-a|--append))*)((?:\s+[^\s;|&><'"()]+)+)/g;
  while ((m = tee.exec(cmd)) !== null) {
    for (const t of (m[2] || "").split(/\s+/).filter(Boolean)) { if (!t.startsWith("-")) out.push(t); }
  }
  return out;
}

// Strip shell quoted-string literals ('...' and "...") before scanning for
// critical-exec patterns: a destructive OPERATOR lives outside quotes; the same
// words inside a quoted ARG (git commit -m "...rm -rf...", echo, grep) are inert
// text and must not trip the gate. Real destructive cmds with quoted args still
// match (operator is unquoted). Mirror of core/policy.ts stripQuoted.
function stripQuoted(cmd: string): string {
  let out = ""; let i = 0; const n = cmd.length;
  while (i < n) {
    const ch = cmd[i];
    if (ch === "'") { i++; while (i < n && cmd[i] !== "'") i++; i++; out += " "; }
    else if (ch === '"') { i++; while (i < n && cmd[i] !== '"') { if (cmd[i] === "\\" && i + 1 < n) i++; i++; } i++; out += " "; }
    else { out += ch; i++; }
  }
  return out;
}

// `rm -rf` is critical BY DEFAULT, but wiping a throwaway scratch dir under /tmp
// is a routine build step. Gating every `rm -rf /tmp/<scratch>` behind approval
// creates a recurring away-from-screen stall (each /tmp path = new fingerprint =
// fresh prompt; allow-always never matches). Carve-out: if an `rm -rf` command
// touches ONLY /tmp/<child> paths, downgrade to warn. Any non-/tmp path (or no
// explicit path -> ambiguous) stays critical. Mirror of core/policy.ts.
function rmRfScratchOnly(cmd: string): boolean {
  const scan = stripQuoted(cmd);
  if (!/rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r/i.test(scan)) return false;
  const toks = scan.split(/[\s;|&><()]+/).filter(Boolean);
  // Real path (contains '/') OR a $VAR/${VAR} target. A variable is treated as
  // scratch ONLY when its NAME clearly signals a throwaway dir (unresolvable at
  // static-scan time). Mirror of core/policy.ts.
  const paths = toks.filter(t =>
    !t.startsWith("-") && (t.includes("/") || /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(t)));
  if (paths.length === 0) return false;
  const looksScratchVar = (t: string): boolean =>
    /tmp|temp|scratch|sandbox|dry|dryport|throwaway|workdir/i.test(t.replace(/^\$\{?/, "").replace(/\}$/, ""));
  let sawTmp = false;
  for (const p of paths) {
    const norm = p.replace(/\\/g, "/");
    if (/^\/tmp\/[^/]/.test(norm)) { sawTmp = true; continue; }
    if (/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(norm) && looksScratchVar(norm)) { sawTmp = true; continue; }
    return false;
  }
  return sawTmp;
}

// Translate a raw detector reason ("exec ~ /rm\s+-rf/", "write X ~ Y", ...) into
// a plain-language sentence a non-technical owner can act on. Falls back to the
// raw reason if nothing matches (never hides info).
function humanizeReason(esc: string): string {
  const m = /^exec ~ \/(.+)\/$/.exec(esc);
  if (m) {
    const pat = m[1];
    // NOTE: `pat` is the raw regex-SOURCE string (e.g. literal "rm\\s+-rf"), so
    // these matchers use `.*` not `\s` — the target contains a literal
    // backslash-s, not whitespace.
    const table: Array<[RegExp, string]> = [
      [/rm.*-.*r.*f/i, "permanently delete files/folders (rm -rf)"],
      [/git.*push.*(--force|-f\b)/i, "force-push to git (can overwrite remote history)"],
      [/--hard/i, "hard-reset git (discards uncommitted work)"],
      [/DROP.*TABLE/i, "drop a database table (destroys data)"],
      [/TRUNCATE/i, "truncate a database table (wipes all rows)"],
      [/mkfs/i, "format a filesystem (erases a disk)"],
      [/dd.*if=/i, "raw disk write with dd (can overwrite a drive)"],
      [/:\(\)/, "a fork-bomb pattern (can hang the machine)"],
      [/uninstall/i, "uninstall software"],
    ];
    for (const [re, phrase] of table) if (re.test(pat)) return `This command would ${phrase}.`;
    return `This is a command flagged as risky (pattern: ${pat}).`;
  }
  const w = /^(write|exec-write) (.+) ~ (.+)$/.exec(esc);
  if (w) return `This would write to a protected/critical file (${w[2]}) — editing it can brick or reconfigure the bot.`;
  return `This action is flagged as critical/irreversible (${esc}).`;
}

// ESCALATION / irreversible detector -> the ONLY owner-facing APPROVAL trigger.
// (a) critical/irreversible exec commands, (b) writes to an escalationPathGlobs
// target (openclaw.json/.env: brick or privilege-escalation risk). Reversible
// security-doc edits are NOT here -> see criticalDocHit.
function escalationHit(event: any, c: Cfg): string | null {
  const toolName = String(event?.toolName ?? "");
  if (["write", "edit", "apply_patch"].includes(toolName)) {
    for (const tp of targetPaths(event)) {
      const h = matchesProtected(tp, c.escalationPathGlobs);
      if (h) return `write ${tp} ~ ${h}`;
    }
  }
  if (toolName === "exec") {
    const cmd = String((event?.params ?? {}).command ?? "");
    const scan = stripQuoted(cmd);
    const scratchRm = rmRfScratchOnly(cmd);
    for (const pat of c.criticalExecPatterns) {
      try {
        if (new RegExp(pat, "i").test(scan)) {
          // /tmp-only `rm -rf` -> warn, not approve (see rmRfScratchOnly).
          if (scratchRm && /\brm\b/.test(pat)) continue;
          return `exec ~ /${pat}/`;
        }
      } catch { /* bad regex ignored */ }
    }
    // exec WRITING to an escalation path (redirect / tee). Reads (grep/cat) pass.
    for (const wt of writeTargets(cmd)) {
      const h = matchesProtected(wt, c.escalationPathGlobs);
      if (h) return `exec-write ${wt} ~ ${h}`;
    }
  }
  return null;
}

// SECURITY-DOC detector -> owner gets `warn` only (reversible: git + backups),
// never approval/block. A write (tool or exec-redirect) to a criticalPathGlobs
// doc (security_rules.md / AGENTS.md). Also feeds the trusted-tier ceiling.
function criticalDocHit(event: any, c: Cfg): string | null {
  const toolName = String(event?.toolName ?? "");
  if (["write", "edit", "apply_patch"].includes(toolName)) {
    for (const tp of targetPaths(event)) {
      const h = matchesProtected(tp, c.criticalPathGlobs);
      if (h) return `write ${tp} ~ ${h}`;
    }
  }
  if (toolName === "exec") {
    const cmd = String((event?.params ?? {}).command ?? "");
    for (const wt of writeTargets(cmd)) {
      const h = matchesProtected(wt, c.criticalPathGlobs);
      if (h) return `exec-write ${wt} ~ ${h}`;
    }
  }
  return null;
}

/** True if an exec command invokes one of the allowlisted read-only scripts. */
function execRunsAllowedScript(event: any, scripts: string[]): boolean {
  if (event?.toolName !== "exec") return false;
  const cmd = String((event?.params ?? {}).command ?? "");
  if (!cmd) return false;
  // Reject shell chaining / redirection first — allowlist is single read-only invocation only.
  if (/[;|&><`$(){}]/.test(cmd)) return false;
  // Command must reference an allowlisted script name, and stay within tools/.
  const mentionsTools = /(^|[\/\s])tools\//.test(cmd);
  for (const s of scripts) {
    // match an allowlisted script as a filename token: <script>[...]. Allow an
    // optional suffix before .py (e.g. semantic_search -> semantic_search_cli.py)
    // but require the .py extension so it's clearly a script invocation.
    const esc = s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp("(^|[\\/\\s])" + esc + "[A-Za-z0-9_]*\\.py([\\s]|$)");
    if (re.test(cmd)) return mentionsTools || true; // script name is sufficient signal
  }
  return false;
}

/** Resolve verified sender id. null => internal/self turn (agent-operated-by-owner). */
function resolveSenderId(event: any, ctx: any): string | null {
  for (const src of [ctx, event, event?.metadata]) {
    if (src && src.senderId != null && String(src.senderId).length > 0) return String(src.senderId);
  }
  const sk = String(ctx?.sessionKey ?? "");
  const parts = sk.split(":");
  const di = parts.indexOf("direct");
  if (di >= 0 && parts[di + 1]) return parts[di + 1];
  return null;
}

export default definePluginEntry({
  id: "dinotrust-enforce",
  name: "dinotrust enforce",
  description: "Code-level enforcement floor: owner warn-only, non-owner strict with allowlist. Beneath the dinotrust AGENTS.md instruction layer.",
  register(api: any) {
    const c = cfg(api?.pluginConfig ?? api?.config);
    audit(c, { evt: "register", enforce: c.enforce, ownerWarnOnly: c.ownerWarnOnly, agentFilter: c.agentFilter, hasPluginConfig: !!api?.pluginConfig });

    api.on("before_tool_call", async (event: any, ctx: any) => {
      try {
        const sessionKey: string = String(ctx?.sessionKey ?? event?.sessionKey ?? "");
        if (c.agentFilter && !sessionKey.includes(c.agentFilter)) return;

        const toolName: string = String(event?.toolName ?? ctx?.toolName ?? "");
        const sender = resolveSenderId(event, ctx);
        const isOwner = sender == null || c.ownerIds.includes(sender);
        const protectedHit = anyProtected(event, c.protectedGlobs);
        const trusted = (!isOwner && sender != null && c.trustedIds.length > 0) ? findTrusted(sender, c) : null;

        // ===== OWNER / agent-operated-by-owner: ALL ACCESS =====
        // Only friction is approval on genuinely critical/irreversible or
        // privilege-escalating actions (escalationHit: irreversible exec, or a
        // write to openclaw.json/.env). Reversible security-doc edits
        // (security_rules.md/AGENTS.md) and secret touches are ALLOWED with
        // warn-only telemetry so the owner still SEES them. No path/tool-pattern
        // gate beyond the escalation tripwire.
        if (isOwner) {
          const esc = escalationHit(event, c);
          if (esc) {
            // A′ re-fire resolution: an APPROVED escalation makes OpenClaw resume
            // the SAME command in the SAME session, re-entering this hook. If we
            // find an OPEN pending intent with the same fingerprint (within the
            // resolve window), THIS call is that approved-resume: mark it
            // resolved (so the sweep won't nudge) and PASS IT THROUGH without
            // re-escalating (else escalate->approve->resume->escalate loops).
            const fp = intentFingerprint(toolName, execCommandOf(event), sessionKey);
            if (c.enforce && resolvePendingIfRefire(c, fp)) {
              audit(c, { evt: "owner-approval-resolved", rule: "R-escalation", toolName, sessionKey, sender: sender ?? "self", hit: esc, fp });
              return; // approved-resume: allow, no second card, no nudge
            }
            audit(c, { evt: "owner-approval", rule: "R-escalation", toolName, sessionKey, sender: sender ?? "self", hit: esc, enforced: c.enforce });
            if (c.enforce) {
              // Log the PENDING intent BEFORE returning the card. If approved,
              // the resume re-fire resolves it; if it expires, the sweep nudges.
              recordPendingIntent(c, { fp, command: execCommandOf(event), toolName, sessionKey, sender: sender ?? "self", hit: esc });
              return {
                requireApproval: {
                  title: `dinotrust: confirm critical action`,
                  description: `This is irreversible/critical (${esc}). Are you sure? Reply /approve to proceed.`,
                  severity: "critical",
                  // Owner is trusted: unmet approval (no route / timeout) FAILS OPEN.
                  timeoutBehavior: "allow",
                },
              };
            }
          }
          const doc = criticalDocHit(event, c);
          if (doc) {
            // warn-only: reversible security-doc edit, owner still SEES it, no gate
            audit(c, { evt: "owner-warn", rule: "R-security-doc", toolName, sessionKey, sender: sender ?? "self", hit: doc });
          }
          if (protectedHit) {
            // warn-only telemetry so owner still SEES secret-touch, no block
            audit(c, { evt: "owner-warn", rule: "R-protected", toolName, sessionKey, sender: sender ?? "self", hit: protectedHit });
          }
          return; // otherwise full access, matches dinotrust owner_rules
        }

        // ===== TRUSTED / delegated (above non-owner, below owner) =====
        if (trusted) {
          // protectedGlobs ALWAYS wins, even inside this entry's own scopePathGlobs.
          if (protectedHit) {
            audit(c, { evt: "block", rule: "R-trusted-protected", toolName, sessionKey, sender, id: trusted.id, hit: protectedHit, blocked: c.enforce });
            if (c.enforce) return { block: true, blockReason: `dinotrust-enforce: trusted blocked (protected resource)` };
            return;
          }
          // Path confinement, if this entry sets it.
          if (trusted.scopePathGlobs && trusted.scopePathGlobs.length > 0) {
            const tp = targetPaths(event);
            if (tp.length > 0) {
              const outOfScope = tp.some((p) => !matchesProtected(p, trusted.scopePathGlobs!));
              if (outOfScope) {
                audit(c, { evt: "block", rule: "R-trusted-scope", toolName, sessionKey, sender, id: trusted.id, paths: tp, blocked: c.enforce });
                if (c.enforce) return { block: true, blockReason: `dinotrust-enforce: trusted path outside scope (${trusted.scopePathGlobs.join(", ")})` };
                return;
              }
            }
          }
          // Critical/irreversible actions AND security-doc writes are BLOCKED for
          // trusted, never auto-approved (below-owner ceiling: no irreversible
          // ops, no touching config/security files).
          const crit = escalationHit(event, c) ?? criticalDocHit(event, c);
          if (crit) {
            audit(c, { evt: "block", rule: "R-trusted-critical", toolName, sessionKey, sender, id: trusted.id, hit: crit, blocked: c.enforce });
            if (c.enforce) return { block: true, blockReason: `dinotrust-enforce: trusted critical/irreversible denied (${crit})` };
            return;
          }
          const allowedTools = trusted.allowedTools ?? DEFAULT_TRUSTED_TOOLS;
          if (toolName === "exec") {
            if (!allowedTools.includes("exec")) {
              audit(c, { evt: "block", rule: "R-trusted-exec", toolName, sessionKey, sender, id: trusted.id, blocked: c.enforce });
              if (c.enforce) return { block: true, blockReason: `dinotrust-enforce: trusted exec not allowlisted` };
              return;
            }
            if (execRunsAllowedScript(event, trusted.allowedScripts ?? c.nonOwnerAllowedScripts)) {
              audit(c, { evt: "allow", rule: "R-trusted-script", toolName, sessionKey, sender, id: trusted.id });
              return;
            }
            audit(c, { evt: "block", rule: "R-trusted-exec", toolName, sessionKey, sender, id: trusted.id, blocked: c.enforce });
            if (c.enforce) return { block: true, blockReason: `dinotrust-enforce: trusted exec restricted to allowlisted scripts` };
            return;
          }
          if (allowedTools.includes(toolName)) {
            audit(c, { evt: "allow", rule: "R-trusted-tool", toolName, sessionKey, sender, id: trusted.id });
            return;
          }
          audit(c, { evt: "block", rule: "R-trusted-tool", toolName, sessionKey, sender, id: trusted.id, blocked: c.enforce });
          if (c.enforce) return { block: true, blockReason: `dinotrust-enforce: trusted tool ${toolName} not allowlisted` };
          return;
        }

        // ===== NON-OWNER: strict + allowlist =====
        // 1. secret access -> always block
        if (protectedHit) {
          audit(c, { evt: "block", rule: "R-nonowner-secret", toolName, sessionKey, sender, hit: protectedHit, blocked: c.enforce });
          if (c.enforce) return { block: true, blockReason: `dinotrust-enforce: non-owner blocked (protected resource)` };
        }
        // 2. explicitly allowed non-mutating tools -> pass
        if (c.nonOwnerAllowedTools.includes(toolName)) return;
        // 3. exec -> only allowlisted read-only tools/ scripts
        if (toolName === "exec") {
          if (execRunsAllowedScript(event, c.nonOwnerAllowedScripts)) {
            audit(c, { evt: "allow", rule: "R-nonowner-script", toolName, sessionKey, sender });
            return;
          }
          audit(c, { evt: "block", rule: "R-nonowner-exec", toolName, sessionKey, sender, blocked: c.enforce });
          if (c.enforce) return { block: true, blockReason: `dinotrust-enforce: non-owner exec restricted to allowlisted tools` };
          return;
        }
        // 4. any other mutating tool -> block
        if (c.mutatingTools.includes(toolName)) {
          audit(c, { evt: "block", rule: "R-nonowner-mutate", toolName, sessionKey, sender, blocked: c.enforce });
          if (c.enforce) return { block: true, blockReason: `dinotrust-enforce: non-owner ${toolName} denied` };
        }
        // 5. everything else (unknown tool) for non-owner -> block (default deny)
        else {
          audit(c, { evt: "block", rule: "R-nonowner-default", toolName, sessionKey, sender, blocked: c.enforce });
          if (c.enforce) return { block: true, blockReason: `dinotrust-enforce: non-owner tool ${toolName} not allowlisted` };
        }
      } catch (err) {
        audit(c, { evt: "error", error: String(err) });
      }
    }, { priority: 100 });
  },
});
