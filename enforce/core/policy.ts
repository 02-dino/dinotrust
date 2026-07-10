/**
 * dinotrust enforce — shared policy engine (platform-agnostic).
 *
 * This is the SINGLE SOURCE OF TRUTH for the enforcement decision. Every
 * adapter (OpenClaw hook, Hermes/Claude/Codex pre_tool_call) feeds a normalized
 * ToolCall + resolved sender into `decide()` and obeys the returned Verdict.
 *
 * PARITY NOTE: like observability/core, daemon-class adapters IMPORT this file.
 * The OpenClaw managed-hook adapter loads as a single self-contained file and
 * cannot resolve sibling imports at hook-load time, so it INLINES this logic.
 * When you change policy here, mirror it in adapters/openclaw/handler.ts and
 * re-run both selftests. See ../PARITY.md.
 *
 * ZERO hardcoded policy: every rule comes from PolicyConfig, which each install
 * fills from its own config (dinotrust install.sh placeholders). Ships safe,
 * general defaults; per-install customization does the rest.
 */

export type PolicyConfig = {
  /** Verified owner identity ids (platform sender ids). */
  ownerIds: string[];
  /** When true (default) owner is never hard-blocked, only warn-logged — except critical* below. */
  ownerWarnOnly: boolean;
  /** Regex strings: critical/irreversible exec commands -> requireApproval even for owner. */
  criticalExecPatterns: string[];
  /** Path globs where an owner write/edit -> requireApproval (config/security files). */
  criticalPathGlobs: string[];
  /** Secret path globs: hard-blocked for NON-owner (owner gets warn/approval via criticalPathGlobs). */
  protectedGlobs: string[];
  /** Tool names treated as mutating/exec for the non-owner gate. */
  mutatingTools: string[];
  /** Non-mutating tools a non-owner MAY call directly (read/web/memory). */
  nonOwnerAllowedTools: string[];
  /** Non-owner exec allowlist: exec permitted only if it runs one of these read-only scripts. */
  nonOwnerAllowedScripts: string[];
  /** Master switch. false => dry-run (decide still returns verdicts, adapter logs but does not enforce). */
  enforce: boolean;
};

export const DEFAULT_POLICY: PolicyConfig = {
  ownerIds: [],
  ownerWarnOnly: true,
  criticalExecPatterns: [
    "rm\\s+-rf", "git\\s+push.*--force", "git\\s+push.*-f\\b", "\\bDROP\\s+TABLE",
    "\\bTRUNCATE\\b", "mkfs", "dd\\s+if=", "uninstall", "--hard\\b",
  ],
  criticalPathGlobs: ["**/openclaw.json", "**/security_rules.md", "**/AGENTS.md", "**/.env"],
  protectedGlobs: [
    "**/.env", "**/.env.*", "**/*.pem", "**/id_rsa", "**/id_ed25519",
    "**/credentials", "**/secrets/**",
  ],
  mutatingTools: ["exec", "write", "edit", "apply_patch"],
  nonOwnerAllowedTools: ["read", "web_search", "web_fetch", "browser", "memory_search", "memory_get"],
  nonOwnerAllowedScripts: [], // empty by default; each install fills its own (e.g. analyst tools/)
  enforce: true,
};

/** Normalized tool call, produced by each adapter from its native event shape. */
export type ToolCall = {
  toolName: string;
  /** Paths the tool targets (write/edit/read path, exec redirect targets, etc.). */
  paths: string[];
  /** For exec: the raw command string. Empty otherwise. */
  command: string;
};

export type Verdict =
  | { action: "allow"; reason: string }
  | { action: "warn"; reason: string }              // owner-only telemetry, proceeds
  | { action: "approve"; reason: string }            // requireApproval ("are you sure?")
  | { action: "block"; reason: string };

export function normalizeConfig(raw: Partial<PolicyConfig> | undefined | null): PolicyConfig {
  const c: PolicyConfig = { ...DEFAULT_POLICY, ...(raw || {}) };
  const arrKeys: (keyof PolicyConfig)[] = [
    "ownerIds", "criticalExecPatterns", "criticalPathGlobs", "protectedGlobs",
    "mutatingTools", "nonOwnerAllowedTools", "nonOwnerAllowedScripts",
  ];
  for (const k of arrKeys) if (!Array.isArray((c as any)[k])) (c as any)[k] = (DEFAULT_POLICY as any)[k];
  return c;
}

/** Minimal glob -> RegExp. ** = any incl '/', * = any except '/'. */
export function globToRe(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === "*") { if (glob[i + 1] === "*") { re += ".*"; i++; } else re += "[^/]*"; }
    else if (".+^${}()|[]\\".includes(ch)) re += "\\" + ch;
    else re += ch;
  }
  return new RegExp("^" + re + "$");
}

export function matchesGlob(p: string, globs: string[]): string | null {
  const norm = p.replace(/\\/g, "/");
  const base = norm.split("/").pop() || norm;
  for (const g of globs) {
    const re = globToRe(g);
    const gBaseRe = globToRe(g.replace(/^\*\*\//, ""));
    if (re.test(norm) || re.test(base) || gBaseRe.test(norm) || gBaseRe.test(base)) return g;
  }
  return null;
}

function anyProtected(call: ToolCall, globs: string[]): string | null {
  for (const p of call.paths) { const h = matchesGlob(p, globs); if (h) return `${p} ~ ${h}`; }
  if (call.toolName === "exec" && call.command) {
    for (const t of call.command.split(/[\s;|&><'"()]+/).filter(Boolean)) {
      const h = matchesGlob(t, globs); if (h) return `exec-arg ~ ${h}`;
    }
  }
  return null;
}

/**
 * Genuine WRITE targets in a shell command: operands of output redirection
 * (`>`, `>>`, fd-prefixed, `&>`) and `tee [-a] FILE...`. A critical path that
 * only appears as a READ argument (grep/cat/an input operand) is NOT a write
 * target and must not trigger owner critical-approval. (Non-owner secret READS
 * are still caught separately by anyProtected.)
 */
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

function criticalHit(call: ToolCall, c: PolicyConfig): string | null {
  if (["write", "edit", "apply_patch"].includes(call.toolName)) {
    for (const p of call.paths) { const h = matchesGlob(p, c.criticalPathGlobs); if (h) return `write ${p} ~ ${h}`; }
  }
  if (call.toolName === "exec" && call.command) {
    for (const pat of c.criticalExecPatterns) {
      try { if (new RegExp(pat, "i").test(call.command)) return `exec ~ /${pat}/`; } catch { /* skip bad regex */ }
    }
    // WRITES to a critical path -> approval. Reads (grep/cat) pass. See writeTargets.
    for (const wt of writeTargets(call.command)) {
      const h = matchesGlob(wt, c.criticalPathGlobs); if (h) return `exec-write ${wt} ~ ${h}`;
    }
  }
  return null;
}

/** True if an exec command invokes one of the allowlisted read-only scripts (no shell chaining). */
export function execRunsAllowedScript(call: ToolCall, scripts: string[]): boolean {
  if (call.toolName !== "exec" || !call.command) return false;
  if (/[;|&><`$(){}]/.test(call.command)) return false; // reject chaining/redirection
  for (const s of scripts) {
    const esc = s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp("(^|[\\/\\s])" + esc + "[A-Za-z0-9_]*\\.py([\\s]|$)");
    if (re.test(call.command)) return true;
  }
  return false;
}

/**
 * THE decision. Pure function: (call, senderId, config) -> Verdict.
 * senderId === null  => internal/self turn (agent-operated-by-owner) => treated as owner.
 */
export function decide(call: ToolCall, senderId: string | null, config: PolicyConfig): Verdict {
  const c = config;
  const isOwner = senderId == null || c.ownerIds.includes(senderId);
  const protectedHit = anyProtected(call, c.protectedGlobs);

  // ── OWNER / agent-operated-by-owner ──
  if (isOwner) {
    const crit = criticalHit(call, c);
    if (crit) return { action: "approve", reason: `critical/irreversible: ${crit}` };
    if (protectedHit) return { action: "warn", reason: `secret touch: ${protectedHit}` };
    return { action: "allow", reason: "owner" };
  }

  // ── NON-OWNER: strict + allowlist ──
  if (protectedHit) return { action: "block", reason: `non-owner protected resource: ${protectedHit}` };
  if (c.nonOwnerAllowedTools.includes(call.toolName)) return { action: "allow", reason: "non-owner allowed tool" };
  if (call.toolName === "exec") {
    return execRunsAllowedScript(call, c.nonOwnerAllowedScripts)
      ? { action: "allow", reason: "non-owner allowlisted script" }
      : { action: "block", reason: "non-owner exec restricted to allowlisted tools" };
  }
  if (c.mutatingTools.includes(call.toolName)) return { action: "block", reason: `non-owner ${call.toolName} denied` };
  return { action: "block", reason: `non-owner tool ${call.toolName} not allowlisted` };
}
