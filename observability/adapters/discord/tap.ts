// dinotrust observability — Discord adapter (Tier-2, daemon-class). REFERENCE.
//
// A concrete, working daemon adapter built from the _template. Discord bots are
// long-lived processes (discord.js Client), so this is a genuine independent
// producer — Tier-2, same strength as OpenClaw's hook, in-proc timer instead of
// cron. Detection + audit schema are inherited from ../../core verbatim.
//
// Wire-up: attach attach(client) to your existing discord.js Client. It taps
// messageCreate for both inbound (humans) and outbound (this bot's own sends),
// using the bot's own user id to split direction. identityField = author.id
// (Discord's verified snowflake — never the display name).
//
// Env:
//   DT_ACTIVITY_LOG, DT_JAILBREAK_LOG, DT_PATTERNS_FILE, DT_PRIVACY
//   DT_AGENT_FILTER (optional; matched against the channel/guild scope key)

import { makeDetector, type Privacy } from "../../core/detector.js";
import { buildInbound, buildOutbound } from "../../core/event.js";
import { appendLine } from "../../core/sink.js";

const ACTIVITY_LOG = process.env.DT_ACTIVITY_LOG ?? "./discord-activity.log";
const JAILBREAK_LOG = process.env.DT_JAILBREAK_LOG ?? "./discord-jailbreak.log";
const PATTERNS_FILE = process.env.DT_PATTERNS_FILE ?? "../../patterns.json";
const PRIVACY = (process.env.DT_PRIVACY ?? "patterns-only") as Privacy;
const AGENT_FILTER = process.env.DT_AGENT_FILTER ?? "";

const detector = makeDetector(PATTERNS_FILE, PRIVACY);

// `msg` is a discord.js Message. We avoid importing discord.js as a hard dep
// (the adapter is glue, not a bundle); the shape used is the stable public API.
type DiscordMessage = {
  id: string;
  content: string;
  createdTimestamp?: number;
  channelId: string;
  guildId?: string | null;
  author: { id: string; username?: string; bot?: boolean };
};

type DiscordClient = {
  user: { id: string } | null;
  on: (event: string, cb: (msg: DiscordMessage) => void) => void;
};

function scopeKey(msg: DiscordMessage): string {
  // A stable per-conversation key; mirrors OpenClaw's sessionKey filter idea.
  return `discord:${msg.guildId ?? "dm"}:${msg.channelId}`;
}

export function attach(client: DiscordClient): void {
  client.on("messageCreate", (msg: DiscordMessage) => {
    void handle(client, msg);
  });
}

async function handle(client: DiscordClient, msg: DiscordMessage): Promise<void> {
  const botId = client.user?.id;
  const sessionKey = scopeKey(msg);
  if (AGENT_FILTER && !sessionKey.includes(AGENT_FILTER)) return;
  if (!msg.content) return;

  const ts = msg.createdTimestamp ? new Date(msg.createdTimestamp).toISOString() : new Date().toISOString();
  const isOutbound = !!botId && msg.author.id === botId;

  if (isOutbound) {
    const line = buildOutbound({
      timestamp: ts,
      channelId: msg.channelId,
      to: msg.guildId ?? null,
      sessionKey,
      content: msg.content,
      success: true, // messageCreate for our own id means it sent
    });
    await appendLine(ACTIVITY_LOG, line);
    return;
  }

  // Inbound (a human / other bot). Skip nothing here; detection is content-based.
  const built = await buildInbound(
    {
      timestamp: ts,
      senderId: msg.author.id,          // verified snowflake — identityField
      senderName: msg.author.username ?? null,
      channelId: msg.channelId,
      isGroup: msg.guildId != null,
      conversationId: msg.channelId,
      sessionKey,
      messageId: msg.id,
      content: msg.content,
    },
    detector,
    "code-daemon",
  );
  if (built.jailbreakLine) await appendLine(JAILBREAK_LOG, built.jailbreakLine);
  await appendLine(ACTIVITY_LOG, built.activityLine);
}

// Schedule the digest with an in-process timer (Tier-2 — no cron needed).
export function scheduleDigest(everyMs: number, fireDigest: () => void): NodeJS.Timeout {
  return setInterval(fireDigest, everyMs);
}
