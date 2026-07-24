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
  /**
   * Path globs that are a genuine PRIVILEGE-ESCALATION / brick risk when written:
   * an owner (or agent-operated-by-owner) write/edit/exec-write to one of these
   * -> requireApproval. This is the ONE owner-facing approval tripwire on paths,
   * kept because a prompt-injected model acting as "owner" editing these files
   * (runtime/plugin/model-routing config, secrets) could silently escalate its
   * own privileges. Default: openclaw.json + .env only.
   */
  escalationPathGlobs: string[];
  /**
   * Path globs for config/SECURITY docs that are sensitive but REVERSIBLE
   * (git + backups): an owner write/edit here -> `warn` telemetry only, never
   * approval or block (owner has all access; a doc edit is not irreversible).
   * Non-owner is still blocked from these via protectedGlobs. Default:
   * security_rules.md + AGENTS.md.
   */
  criticalPathGlobs: string[];
  /** Secret path globs: hard-blocked for NON-owner (owner gets warn via criticalPathGlobs / approval via escalationPathGlobs). */
  protectedGlobs: string[];
  /** Tool names treated as mutating/exec for the non-owner gate. */
  mutatingTools: string[];
  /** Non-mutating tools a non-owner MAY call directly (read/web/memory). */
  nonOwnerAllowedTools: string[];
  /** Non-owner exec allowlist: exec permitted only if it runs one of these read-only scripts. */
  nonOwnerAllowedScripts: string[];
  /**
   * Trusted/delegated ids: a per-individual tier ABOVE non-owner, BELOW owner.
   * Empty by default -> zero behavior change for every existing install.
   * Each entry is independently configured (no shared named roles) so one
   * install can express both "extra tool access" and "admin of my own
   * workspace folder only" grants side by side.
   *
   * Ceiling that keeps this genuinely below owner, ALWAYS, no per-entry
   * override possible:
   *   - protectedGlobs still hard-blocks (.env, credentials, other
   *     workspace-*\/ dirs, etc.) even if a path also matches scopePathGlobs.
   *   - escalationHit() (irreversible/critical/escalating) AND criticalDocHit()
   *     (security-doc writes) are BLOCKED, never auto-approved the way owner's
   *     escalationHit escalates to "approve".
   */
  trustedIds: TrustedEntry[];
  /** Master switch. false => dry-run (decide still returns verdicts, adapter logs but does not enforce). */
  enforce: boolean;
};

export type TrustedEntry = {
  /** Platform sender id, same identity model as ownerIds entries (bare id only; no platform-scoping for trusted). */
  id: string;
  /**
   * Tool allowlist for this entry. Omitted -> DEFAULT_TRUSTED_TOOLS (broader
   * than the non-owner default, still excludes config/gateway/cron/message/
   * sessions_spawn -- those need explicit opt-in even for trusted).
   */
  allowedTools?: string[];
  /** exec allowlist for this entry. Omitted -> falls back to config.nonOwnerAllowedScripts. */
  allowedScripts?: string[];
  /**
   * Optional path confinement ("delegated admin of my own workspace only").
   * When set, ANY tool call carrying a path must match one of these globs or
   * it's blocked outright, regardless of the tool being otherwise allowlisted.
   * Tools with no path (e.g. web_search) are unaffected. exec is NOT
   * path-scoped by this (see execRunsAllowedScript note) -- exec's only gate
   * is allowedScripts, same mechanism as non-owner, to avoid unreliable
   * path-extraction from arbitrary shell commands.
   * Omitted -> no path restriction (pure tool-allowlist trusted grant).
   */
  scopePathGlobs?: string[];
};

/** Broader-than-non-owner default tool set for a trusted entry with no explicit allowedTools. */
export const DEFAULT_TRUSTED_TOOLS: string[] = [
  "read", "write", "edit", "apply_patch", "exec",
  "web_search", "web_fetch", "browser", "memory_search", "memory_get",
];

export const DEFAULT_POLICY: PolicyConfig = {
  ownerIds: [],
  ownerWarnOnly: true,
  criticalExecPatterns: [
    "rm\\s+-rf", "git\\s+push.*--force", "git\\s+push.*-f\\b", "\\bDROP\\s+TABLE",
    "\\bTRUNCATE\\b", "mkfs", "dd\\s+if=", "uninstall", "--hard\\b",
  ],
  escalationPathGlobs: ["**/openclaw.json", "**/.env"],
  criticalPathGlobs: ["**/security_rules.md", "**/AGENTS.md"],
  protectedGlobs: [
    "**/.env", "**/.env.*", "**/*.pem", "**/id_rsa", "**/id_ed25519",
    "**/credentials", "**/secrets/**",
  ],
  mutatingTools: ["exec", "write", "edit", "apply_patch"],
  nonOwnerAllowedTools: ["read", "web_search", "web_fetch", "browser", "memory_search", "memory_get"],
  nonOwnerAllowedScripts: [], // empty by default; each install fills its own (e.g. analyst tools/)
  trustedIds: [], // empty by default; zero behavior change unless an install explicitly grants trust
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
    "ownerIds", "criticalExecPatterns", "escalationPathGlobs", "criticalPathGlobs", "protectedGlobs",
    "mutatingTools", "nonOwnerAllowedTools", "nonOwnerAllowedScripts", "trustedIds",
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

/**
 * Strip shell quoted-string literals ('...' and "...") from a command before
 * scanning for critical-exec patterns. Rationale: a destructive OPERATOR
 * (rm -rf, dd, DROP TABLE, --force) lives OUTSIDE quotes; the same words buried
 * inside a quoted ARGUMENT (e.g. `git commit -m "... rm -rf ..."`, an echo, a
 * grep pattern) are inert text, not an execution -> must not trip the gate.
 * Real destructive commands with quoted args (`rm -rf "/some path"`) still match
 * because the operator itself is unquoted. Single-quote spans take no escapes
 * (sh semantics); double-quote spans honor \" . Unterminated quote -> strip to
 * end of string (conservative: a dangling quote can't hide a real operator that
 * would already have matched before the quote opened).
 */
function stripQuoted(cmd: string): string {
  let out = "";
  let i = 0;
  const n = cmd.length;
  while (i < n) {
    const ch = cmd[i];
    if (ch === "'") {
      i++; while (i < n && cmd[i] !== "'") i++;
      i++; // consume closing quote (or run off end)
      out += " "; // preserve token boundary
    } else if (ch === '"') {
      i++; while (i < n && cmd[i] !== '"') { if (cmd[i] === "\\" && i + 1 < n) i++; i++; }
      i++;
      out += " ";
    } else {
      out += ch; i++;
    }
  }
  return out;
}

/**
 * `rm -rf` is critical BY DEFAULT, but wiping a throwaway scratch dir under /tmp
 * is a routine, low-stakes build step (test fixtures, verify sandboxes). Gating
 * every `rm -rf /tmp/<scratch>` behind an approval card creates a recurring
 * away-from-screen stall (each distinct /tmp path = a new approval fingerprint,
 * so a prior allow-always never matches the next one). Carve-out: if an `rm -rf`
 * command touches ONLY paths under /tmp, downgrade to warn (skip approval). If
 * ANY path arg is outside /tmp -- or no explicit path is present (ambiguous) --
 * it stays critical. Conservative: requires >=1 explicit /tmp/<x> path AND zero
 * non-/tmp filesystem paths. Bare `/tmp` (no child) and `/` are NOT scratch.
 */
function rmRfScratchOnly(cmd: string): boolean {
  const scan = stripQuoted(cmd);
  if (!/rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r/i.test(scan)) return false;
  const toks = scan.split(/[\s;|&><()]+/).filter(Boolean);
  // Path-like tokens: real path (contains '/') OR a shell-variable target
  // ($VAR / ${VAR}). A variable is unresolvable at static-scan time, so it is
  // treated as scratch ONLY when its NAME clearly signals a throwaway dir.
  const paths = toks.filter(t =>
    !t.startsWith("-") && (t.includes("/") || /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(t)));
  if (paths.length === 0) return false; // no explicit path -> ambiguous -> stay critical
  const looksScratchVar = (t: string): boolean => {
    const name = t.replace(/^\$\{?/, "").replace(/\}$/, "");
    return /tmp|temp|scratch|sandbox|dry|dryport|throwaway|workdir/i.test(name);
  };
  let sawTmp = false;
  for (const p of paths) {
    const norm = p.replace(/\\/g, "/");
    if (/^\/tmp\/[^/]/.test(norm)) { sawTmp = true; continue; }
    // Shell-variable target whose NAME signals a throwaway scratch dir.
    if (/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(norm) && looksScratchVar(norm)) { sawTmp = true; continue; }
    return false; // any non-/tmp path (bare "/tmp", "/", real dirs, opaque $VAR) -> NOT scratch-only
  }
  return sawTmp;
}

/**
 * ESCALATION / irreversible hit -> the only owner-facing APPROVAL trigger.
 * Covers: (a) critical/irreversible exec commands (rm -rf, force-push, DROP,
 * mkfs, dd, --hard, ...), and (b) writes (tool or exec-redirect) to an
 * escalationPathGlobs target (openclaw.json / .env by default) -- files where a
 * write could brick the runtime or silently escalate privileges. Reversible doc
 * edits (security_rules.md / AGENTS.md) are deliberately NOT here; see
 * criticalDocHit.
 */
function escalationHit(call: ToolCall, c: PolicyConfig): string | null {
  if (["write", "edit", "apply_patch"].includes(call.toolName)) {
    for (const p of call.paths) { const h = matchesGlob(p, c.escalationPathGlobs); if (h) return `write ${p} ~ ${h}`; }
  }
  if (call.toolName === "exec" && call.command) {
    // Scan with quoted literals removed so quoted-arg text can't false-positive.
    const scan = stripQuoted(call.command);
    const scratchRm = rmRfScratchOnly(call.command);
    for (const pat of c.criticalExecPatterns) {
      try {
        if (new RegExp(pat, "i").test(scan)) {
          // /tmp-only `rm -rf` -> warn, not approve (see rmRfScratchOnly).
          if (scratchRm && /\brm\b/.test(pat)) continue;
          return `exec ~ /${pat}/`;
        }
      } catch { /* skip bad regex */ }
    }
    // WRITES to an escalation path -> approval. Reads (grep/cat) pass. See writeTargets.
    for (const wt of writeTargets(call.command)) {
      const h = matchesGlob(wt, c.escalationPathGlobs); if (h) return `exec-write ${wt} ~ ${h}`;
    }
  }
  return null;
}

/**
 * SECURITY-DOC hit -> owner gets `warn` telemetry only (reversible: git +
 * backups), never approval/block. A write (tool or exec-redirect) to a
 * criticalPathGlobs doc (security_rules.md / AGENTS.md). Used to (a) warn the
 * owner they touched a security doc, and (b) contribute to the trusted-tier
 * ceiling (trusted may never write these at all).
 */
function criticalDocHit(call: ToolCall, c: PolicyConfig): string | null {
  if (["write", "edit", "apply_patch"].includes(call.toolName)) {
    for (const p of call.paths) { const h = matchesGlob(p, c.criticalPathGlobs); if (h) return `write ${p} ~ ${h}`; }
  }
  if (call.toolName === "exec" && call.command) {
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

/** Finds a config.trustedIds entry matching senderId, or null. */
function findTrusted(senderId: string, c: PolicyConfig): TrustedEntry | null {
  for (const t of c.trustedIds) if (t.id === senderId) return t;
  return null;
}

/**
 * Decision for a matched trusted/delegated entry. Below owner, above
 * non-owner. See TrustedEntry doc comment for the ceiling rules.
 */
function decideTrusted(call: ToolCall, entry: TrustedEntry, c: PolicyConfig): Verdict {
  // protectedGlobs ALWAYS wins, even inside this entry's own scopePathGlobs.
  // No self-service escalation over secrets/system files/other workspaces.
  const protectedHit = anyProtected(call, c.protectedGlobs);
  if (protectedHit) return { action: "block", reason: `non-owner protected resource: ${protectedHit}` };

  // Path confinement, if this entry sets it: any call carrying a path must
  // match, or it's out of scope. Tools with no path are unaffected.
  if (entry.scopePathGlobs && entry.scopePathGlobs.length > 0 && call.paths.length > 0) {
    const inScope = call.paths.every((p) => matchesGlob(p, entry.scopePathGlobs!));
    if (!inScope) return { action: "block", reason: `trusted: ${entry.id} path outside scope (${entry.scopePathGlobs!.join(", ")})` };
  }

  // Critical/irreversible actions AND security-doc writes are BLOCKED for
  // trusted, never auto-approved the way owner's escalationHit -> "approve".
  // This is the other half of the below-owner ceiling: trusted can neither run
  // irreversible ops nor touch config/security files (escalation OR doc paths).
  const crit = escalationHit(call, c) ?? criticalDocHit(call, c);
  if (crit) return { action: "block", reason: `trusted: ${entry.id} critical/irreversible denied: ${crit}` };

  const allowedTools = entry.allowedTools ?? DEFAULT_TRUSTED_TOOLS;
  if (call.toolName === "exec") {
    if (!allowedTools.includes("exec")) return { action: "block", reason: `trusted: ${entry.id} exec not allowlisted` };
    const scripts = entry.allowedScripts ?? c.nonOwnerAllowedScripts;
    return execRunsAllowedScript(call, scripts)
      ? { action: "allow", reason: `trusted: ${entry.id} allowlisted script` }
      : { action: "block", reason: `trusted: ${entry.id} exec restricted to allowlisted scripts` };
  }
  if (allowedTools.includes(call.toolName)) return { action: "allow", reason: `trusted: ${entry.id} tool allowed` };
  return { action: "block", reason: `trusted: ${entry.id} tool ${call.toolName} not allowlisted` };
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
  // All access. The ONLY friction is approval on genuinely critical/irreversible
  // or privilege-escalating actions (escalationHit). Everything else -- including
  // reversible edits to security docs (security_rules.md / AGENTS.md) and secret
  // touches -- is allowed, with warn-only telemetry so the owner still SEES it.
  if (isOwner) {
    const esc = escalationHit(call, c);
    if (esc) return { action: "approve", reason: `critical/irreversible: ${esc}` };
    const doc = criticalDocHit(call, c);
    if (doc) return { action: "warn", reason: `security-doc edit (reversible): ${doc}` };
    if (protectedHit) return { action: "warn", reason: `secret touch: ${protectedHit}` };
    return { action: "allow", reason: "owner" };
  }

  // ── TRUSTED / delegated (above non-owner, below owner) ──
  if (senderId != null && c.trustedIds.length > 0) {
    const entry = findTrusted(senderId, c);
    if (entry) return decideTrusted(call, entry, c);
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
