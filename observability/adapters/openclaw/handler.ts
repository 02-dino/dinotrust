// dinotrust observability — OpenClaw adapter (hook / producer)
//
// Taps every inbound + outbound message for one agent, runs the universal
// regex detector (patterns.json), and appends:
//   - all traffic            -> ACTIVITY_LOG  (ops telemetry)
//   - flagged injection only -> JAILBREAK_LOG (security audit, schema v2)
//
// This is the PLATFORM-BOUND adapter. The detection logic + taxonomy live in
// ../../patterns.json and are shared verbatim with every other platform.
// Only the 5 adapter concerns are OpenClaw-specific here:
//   1. tap        -> the `message:preprocessed` / `message:sent` event shapes
//   2. extract    -> ctx.senderId / senderName / channelId / messageId
//   3. scope      -> sessionKey.includes(AGENT_FILTER)
//   4. (deliver + renderMention + schedule live in report.py / cron)
//
// Installer placeholders (filled by install.sh):
//   __AGENT_FILTER__   e.g. "agent:analyst"
//   __ACTIVITY_LOG__   e.g. "<home>/.openclaw/logs/analyst-activity.log"
//   __JAILBREAK_LOG__  e.g. "<home>/.openclaw/logs/analyst-jailbreak.log"
//   __PATTERNS_FILE__  absolute path to the shared patterns.json
//   __PRIVACY__        "patterns-only" | "truncated" | "full"

import path from "node:path";
import fs from "node:fs/promises";
import os from "node:os";

// === FILLED BY install.sh ===
const AGENT_FILTER = "__AGENT_FILTER__";
const ACTIVITY_LOG = "__ACTIVITY_LOG__";
const JAILBREAK_LOG = "__JAILBREAK_LOG__";
const PATTERNS_FILE = "__PATTERNS_FILE__";
const PRIVACY = "__PRIVACY__"; // patterns-only | truncated | full
// ============================

const TRUNCATE_LEN = 200;

type Pattern = { id: string; regex: string; rule_id: string; severity: string; flags?: string; direction?: string };
type CompiledPattern = { id: string; re: RegExp; rule_id: string; severity: string; direction: "in" | "out" };
type Hit = { id: string; rule_id: string; severity: string };

let COMPILED: CompiledPattern[] | null = null;

async function loadPatterns(): Promise<CompiledPattern[]> {
  if (COMPILED) return COMPILED;
  try {
    const raw = await fs.readFile(PATTERNS_FILE, "utf-8");
    const data = JSON.parse(raw);
    const pats: Pattern[] = Array.isArray(data?.patterns) ? data.patterns : [];
    COMPILED = pats.map((p) => ({
      id: p.id,
      re: new RegExp(p.regex, p.flags ?? "i"),
      rule_id: p.rule_id,
      severity: p.severity,
      // No 'direction' field => inbound (historic default). 'out' => outbound only.
      direction: (p.direction === "out" ? "out" : "in") as "in" | "out",
    }));
  } catch {
    COMPILED = []; // fail open: never disrupt message flow if patterns missing
  }
  return COMPILED;
}

// Direction-scoped detection: inbound patterns run on user messages, outbound
// (secret-shape) patterns run on the agent's own sent messages. Never cross-applied.
async function detect(content: string, direction: "in" | "out"): Promise<Hit[]> {
  const compiled = await loadPatterns();
  const hits: Hit[] = [];
  for (const p of compiled) {
    if (p.direction !== direction) continue;
    if (p.re.test(content)) hits.push({ id: p.id, rule_id: p.rule_id, severity: p.severity });
  }
  return hits;
}

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
function topSeverity(hits: Hit[]): string {
  let best = "";
  let bestRank = 0;
  for (const h of hits) {
    const r = SEV_RANK[h.severity] ?? 0;
    if (r > bestRank) { bestRank = r; best = h.severity; }
  }
  return best || "low";
}

// Apply the install-time privacy level to the stored content field.
function privacyContent(content: string): string | null {
  if (PRIVACY === "patterns-only") return null;
  if (PRIVACY === "truncated") return content.slice(0, TRUNCATE_LEN);
  return content; // "full"
}

const handler = async (event: any) => {
  const sessionKey = String(event?.sessionKey ?? "");
  if (!sessionKey.includes(AGENT_FILTER)) return;

  const ctx = event?.context ?? {};
  const channelId = String(ctx.channelId ?? "");
  if (channelId === "heartbeat" || channelId === "system") return;

  let line: string | null = null;

  if (event?.type === "message" && event?.action === "preprocessed") {
    const content = String(ctx.bodyForAgent ?? ctx.body ?? "");
    if (!content) return;
    const ts =
      typeof ctx.timestamp === "number"
        ? new Date(ctx.timestamp).toISOString()
        : event?.timestamp instanceof Date
          ? event.timestamp.toISOString()
          : new Date().toISOString();

    line = JSON.stringify({
      direction: "in",
      timestamp: ts,
      senderId: ctx.senderId ?? null,
      senderName: ctx.senderName ?? null,
      channelId: ctx.channelId ?? "unknown",
      isGroup: ctx.isGroup ?? null,
      conversationId: ctx.conversationId ?? null,
      sessionKey,
      messageId: ctx.messageId ?? null,
      content,
    });

    // Injection heuristic check on inbound (no LLM).
    const hits = await detect(content, "in");
    if (hits.length > 0) {
      const jbLine = JSON.stringify({
        timestamp: ts,
        senderId: ctx.senderId ?? null,
        senderName: ctx.senderName ?? null,
        channelId: ctx.channelId ?? "unknown",
        isGroup: ctx.isGroup ?? null,
        conversationId: ctx.conversationId ?? null,
        messageId: ctx.messageId ?? null,
        patterns: hits.map((h) => h.id),
        rule_ids: [...new Set(hits.map((h) => h.rule_id))],
        severity: topSeverity(hits),
        hits,
        content: privacyContent(content),
        producer: "code-hook",
      });
      try {
        await fs.mkdir(path.dirname(JAILBREAK_LOG), { recursive: true });
        await fs.appendFile(JAILBREAK_LOG, jbLine + "\n");
      } catch {
        // Silent: never disrupt message flow
      }
    }
  } else if (event?.type === "message" && event?.action === "sent") {
    const content = String(ctx.content ?? "");
    if (!content) return;
    const ts = new Date().toISOString();
    line = JSON.stringify({
      direction: "out",
      timestamp: ts,
      channelId: ctx.channelId ?? "unknown",
      to: ctx.to ?? null,
      sessionKey,
      content,
      success: ctx.success ?? null,
    });

    // Outbound secret-shape check (verifier for S0_OUT self-gate). This hook is a
    // producer/observer: 'sent' fires post-delivery, so it ALERTS, it does not
    // redact. A critical hit here means a secret-shaped value left the channel
    // despite the composition-time self-gate — evidence-backed, agent-independent.
    const outHits = await detect(content, "out");
    if (outHits.length > 0) {
      const jbLine = JSON.stringify({
        timestamp: ts,
        senderId: null,
        senderName: null,
        channelId: ctx.channelId ?? "unknown",
        isGroup: null,
        conversationId: ctx.conversationId ?? null,
        messageId: ctx.messageId ?? null,
        patterns: outHits.map((h) => h.id),
        rule_ids: [...new Set(outHits.map((h) => h.rule_id))],
        severity: topSeverity(outHits),
        hits: outHits,
        content: privacyContent(content),
        producer: "code-hook",
        direction: "out",
      });
      try {
        await fs.mkdir(path.dirname(JAILBREAK_LOG), { recursive: true });
        await fs.appendFile(JAILBREAK_LOG, jbLine + "\n");
      } catch {
        // Silent: never disrupt message flow
      }
    }
  }

  if (!line) return;

  try {
    await fs.mkdir(path.dirname(ACTIVITY_LOG), { recursive: true });
    await fs.appendFile(ACTIVITY_LOG, line + "\n");
  } catch {
    // Silent: never disrupt message flow
  }
};

export default handler;
