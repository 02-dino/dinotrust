import { readFileSync, existsSync, unlinkSync, statSync, readdirSync } from "node:fs";
import { join, isAbsolute } from "node:path";
import { homedir } from "node:os";

// dinotrust-degraded-alert: on agent:bootstrap, if dinotrust-enforce previously
// FAILED OPEN (wrote a DEGRADED marker), inject a short plain-language warning
// into the owner's next turn — then AUTO-CLEAR the marker once enforcement has
// recovered. The point: a non-technical owner should never have to know the
// marker file exists, go read it, or `rm` it by hand. Enforcement breaks -> the
// bot just tells them, in words, on their next message; recovers -> silence.
// Fail-safe: any error is swallowed. This hook MUST NEVER break bootstrap.

type MaybeRecord = Record<string, unknown> | undefined | null;

interface BootstrapFileEntry {
  name: string;
  content: string;
  [k: string]: unknown;
}

function asString(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

// Owner-only: this warning is for the operator, not random senders. Match the
// inbound sender id against the enforce plugin's ownerIds (default single owner).
function ownerIds(): string[] {
  const raw = (process.env.DINOTRUST_OWNER_IDS ?? "").trim();
  if (raw) return raw.split(/[,\s]+/).filter(Boolean);
  return ["1083618205"]; // dinotrust-enforce default owner
}

function senderId(context: Record<string, unknown>): string | undefined {
  const direct = asString(context.senderId);
  if (direct) return direct;
  const sender = context.sender as MaybeRecord;
  if (sender && typeof sender === "object") {
    return asString((sender as Record<string, unknown>).id);
  }
  // Fall back to parsing the sessionKey tail (agent:...:<platform>:<kind>:<id>).
  const sk = asString(context.sessionKey);
  if (sk) {
    const m = sk.match(/:(\d+)$/);
    if (m) return m[1];
  }
  return undefined;
}

function isOwner(context: Record<string, unknown>): boolean {
  const sid = senderId(context);
  if (!sid) return false; // no resolvable id -> do not surface (deny by default)
  return ownerIds().includes(sid);
}

// The enforce plugin writes its marker next to its audit log. Default path
// mirrors dinotrust-enforce's logPath(): ~/.openclaw/logs/dinotrust-enforce.log
// -> ~/.openclaw/logs/dinotrust-enforce-DEGRADED.json. Override via env.
function markerPath(): string {
  const explicit = asString(process.env.DINOTRUST_DEGRADED_MARKER);
  if (explicit) return explicit;
  const logFile = asString(process.env.DINOTRUST_LOG_FILE);
  if (logFile) return logFile.replace(/\.log$/i, "") + "-DEGRADED.json";
  return join(homedir(), ".openclaw", "logs", "dinotrust-enforce-DEGRADED.json");
}

function auditLogPath(): string {
  const logFile = asString(process.env.DINOTRUST_LOG_FILE);
  if (logFile) return logFile;
  return join(homedir(), ".openclaw", "logs", "dinotrust-enforce.log");
}

interface DegradedMarker {
  status?: string;
  message?: string;
  error?: string;
  firstSeen?: string;
  lastSeen?: string;
  count?: number;
}

function readMarker(): DegradedMarker | null {
  try {
    const p = markerPath();
    if (!existsSync(p)) return null;
    const m = JSON.parse(readFileSync(p, "utf8"));
    return (m && typeof m === "object") ? (m as DegradedMarker) : null;
  } catch {
    return null;
  }
}

// RECOVERY DETECTION: the marker records lastSeen (when enforcement last failed).
// If the audit log has recorded any SUCCESSFUL verdict (evt:block/allow/register
// with no DEGRADED) strictly AFTER lastSeen, enforcement has recovered -> the
// marker is stale -> auto-clear it and stay silent. We approximate "recovered"
// cheaply: if the marker's lastSeen is older than RECOVERY_QUIET_MS AND the
// audit log's most recent line is newer than lastSeen and is NOT a DEGRADED
// event, treat as recovered. Conservative: when unsure, we DO warn (better a
// stale warning than a silent bypass).
const RECOVERY_QUIET_MS = 5 * 60 * 1000; // 5 min of no new fault = candidate recovery

function hasRecovered(marker: DegradedMarker): boolean {
  try {
    const lastSeen = marker.lastSeen ? Date.parse(marker.lastSeen) : NaN;
    if (!Number.isFinite(lastSeen)) return false;
    if (Date.now() - lastSeen < RECOVERY_QUIET_MS) return false; // fault too recent
    const logp = auditLogPath();
    if (!existsSync(logp)) return false;
    // Read only the tail to find the newest event cheaply.
    const txt = readFileSync(logp, "utf8");
    const lines = txt.split("\n").filter(Boolean);
    if (lines.length === 0) return false;
    // Walk backward: the newest non-empty JSON line decides.
    for (let i = lines.length - 1; i >= 0 && i >= lines.length - 50; i--) {
      let o: any;
      try { o = JSON.parse(lines[i]); } catch { continue; }
      const tsMs = o?.ts ? Date.parse(o.ts) : NaN;
      if (!Number.isFinite(tsMs)) continue;
      if (tsMs <= lastSeen) return false; // nothing newer than the fault -> not proven recovered
      // Newest event is AFTER the fault. If it is itself a DEGRADED event,
      // enforcement is still broken; otherwise it is a healthy verdict.
      const evt = String(o?.evt ?? "");
      return evt !== "DEGRADED" && evt !== "DEGRADED-carried";
    }
    return false;
  } catch {
    return false;
  }
}

function clearMarker(): void {
  try {
    const p = markerPath();
    if (existsSync(p)) unlinkSync(p);
  } catch {
    // swallow — never break bootstrap on a cleanup failure
  }
}

function renderWarning(marker: DegradedMarker): string {
  const count = typeof marker.count === "number" ? marker.count : 1;
  const times = count === 1 ? "once" : `${count} times`;
  const lines: string[] = [];
  lines.push("## ⚠️ Security notice (from dinotrust)");
  lines.push("");
  lines.push(
    "**Tell the owner, in your own words, at the top of your reply:** the security " +
    "layer (dinotrust) hit an internal error and had to let a tool run *without its " +
    "usual safety check*. This happened " + times + ". Nothing is necessarily wrong, but " +
    "for a short window the bot was not fully protected.",
  );
  lines.push("");
  lines.push(
    "Say it plainly (no file paths, no jargon, no error codes) — e.g. *“heads-up: my " +
    "safety layer briefly hiccupped and skipped a check; if you didn't ask me to do " +
    "anything risky just now, you're fine — flagging it so you're not in the dark.”* " +
    "Then answer their actual message normally.",
  );
  lines.push("");
  lines.push(
    "Do NOT paste the raw error, the marker filename, or ask them to delete any file — " +
    "it clears itself automatically once the layer recovers. Only mention it once; if " +
    "they ask for detail, you may summarize what broke in plain language.",
  );
  lines.push("");
  return lines.join("\n");
}

const handler = async (event: {
  type?: string;
  action?: string;
  context?: MaybeRecord;
}): Promise<void> => {
  try {
    if (event?.type !== "agent" || event?.action !== "bootstrap") return;
    const context = (event.context ?? {}) as Record<string, unknown>;

    const marker = readMarker();
    if (!marker) return; // clean -> zero-op, silent

    // Recovered? auto-clear and stay silent. The owner never learns a transient
    // blip happened if it already healed — which is the right UX for a noob.
    if (hasRecovered(marker)) {
      clearMarker();
      return;
    }

    // Still degraded. Only surface to the OWNER (this is an operator alert, not
    // something to leak to arbitrary senders).
    if (!isOwner(context)) return;

    const warning = renderWarning(marker);
    const existing = Array.isArray(context.bootstrapFiles)
      ? (context.bootstrapFiles as BootstrapFileEntry[])
      : [];
    // Inject under AGENTS.md so it survives the bootstrap allowlist on main
    // interactive sessions (same trick dinomem-open-notes uses).
    const entry: BootstrapFileEntry = { name: "AGENTS.md", content: warning };
    context.bootstrapFiles = [...existing, entry];

    console.log(
      `[dinotrust-degraded-alert] injected owner warning (count=${marker.count ?? 1})`,
    );
  } catch (err) {
    // Never break bootstrap.
    console.warn("[dinotrust-degraded-alert] handler error: " + String(err));
  }
};

export default handler;
