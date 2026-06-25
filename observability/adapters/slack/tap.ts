// dinotrust observability — Slack adapter (Tier-2, daemon-class). REFERENCE.
//
// A concrete, working daemon adapter built from the _template. Slack bots are
// long-lived processes (Bolt SDK), so this is a genuine independent producer
// — Tier-2, same strength as OpenClaw's hook, in-proc timer instead of cron.
// Detection + audit schema are inherited from ../../core verbatim.
//
// Wire-up: import { attach } and call attach(app, botUserId). It taps
// app.message for both inbound (humans) and outbound (this bot's own sends).
// IMPORTANT: Bolt's ignoreSelf defaults to true, which skips bot messages.
// Observability needs to see both directions. Set ignoreSelf: false when
// creating your Bolt app, or wire handle() directly in your own middleware.
// identityField = user (U-prefixed Slack user id — never the display name).
//
// Env:
//   DT_ACTIVITY_LOG, DT_JAILBREAK_LOG, DT_PATTERNS_FILE, DT_PRIVACY
//   DT_AGENT_FILTER (optional; matched against the team:channel scope key)

import { makeDetector, type Privacy } from "../../core/detector.js";
import { buildInbound, buildOutbound } from "../../core/event.js";
import { appendLine } from "../../core/sink.js";

const ACTIVITY_LOG = process.env.DT_ACTIVITY_LOG ?? "./slack-activity.log";
const JAILBREAK_LOG = process.env.DT_JAILBREAK_LOG ?? "./slack-jailbreak.log";
const PATTERNS_FILE = process.env.DT_PATTERNS_FILE ?? "../../patterns.json";
const PRIVACY = (process.env.DT_PRIVACY ?? "patterns-only") as Privacy;
const AGENT_FILTER = process.env.DT_AGENT_FILTER ?? "";

const detector = makeDetector(PATTERNS_FILE, PRIVACY);

// Slack message event shape (from Events API / Bolt message payload).
// We use the stable public API; no Bolt SDK types are imported.
// user = verified U-prefixed user id; bot_id = B-prefixed bot id (fallback).
// text = message content; ts = Unix epoch string with microseconds.
// channel = C/G/D-prefixed channel id; channel_type = channel|group|im|mpim.
// thread_ts = parent timestamp for thread replies; team = workspace id.
type SlackMessage = {
  type: "message";
  user?: string;
  bot_id?: string;
  text?: string;
  ts: string;
  channel: string;
  channel_type?: string;
  team?: string;
  team_id?: string;
  thread_ts?: string;
  subtype?: string;
  edited?: { ts: string; user: string };
};

// Bolt app.message() duck type — we only need the callback registration.
// In Bolt v3+ the callback receives the message payload directly.
// If your version passes a context object ({ message, say }), use handle()
// directly instead of attach().
type SlackApp = {
  message: (callback: (msg: SlackMessage) => void | Promise<void>) => void;
};

function scopeKey(msg: SlackMessage): string {
  const team = msg.team || msg.team_id || "unknown";
  return `slack:${team}:${msg.channel}`;
}

// Subtypes that carry no user content (system events). Skip them.
const SKIP_SUBTYPES = new Set([
  "channel_join", "channel_leave", "channel_topic", "channel_purpose",
  "channel_archive", "channel_unarchive",
  "group_join", "group_leave", "group_topic", "group_purpose",
  "group_archive", "group_unarchive",
  "pinned_item", "unpinned_item", "reminder_add",
]);

// Attach this adapter to a Slack Bolt app.
// IMPORTANT: Bolt's ignoreSelf defaults to true, which blocks outbound
// observation. Set ignoreSelf: false when creating your Bolt app, or wire
// handle() directly in your own app.message() middleware.
// botUserId = the U-prefixed user id from auth.test (or your app config).
export function attach(app: SlackApp, botUserId: string): void {
  app.message((msg: SlackMessage) => {
    void handle(botUserId, msg);
  });
}

export async function handle(botUserId: string, msg: SlackMessage): Promise<void> {
  const sessionKey = scopeKey(msg);
  if (AGENT_FILTER && !sessionKey.includes(AGENT_FILTER)) return;

  // Skip system subtypes (joins, leaves, topic changes, etc.)
  if (msg.subtype && SKIP_SUBTYPES.has(msg.subtype)) return;

  // Slack messages may have blocks or attachments without text; skip those.
  const text = msg.text || "";
  if (!text) return;

  const ts = msg.ts
    ? new Date(parseFloat(msg.ts) * 1000).toISOString()
    : new Date().toISOString();

  // Determine direction: is this from our bot?
  // Bot messages usually carry user=<bot-user-id>; fallback to bot_id.
  const isOutbound = !!botUserId && msg.user === botUserId;

  if (isOutbound) {
    const line = buildOutbound({
      timestamp: ts,
      channelId: msg.channel,
      to: msg.thread_ts ?? null,
      sessionKey,
      content: text,
      success: true, // message received in app.message means it sent
    });
    await appendLine(ACTIVITY_LOG, line);
    return;
  }

  // Inbound (human or other bot). user is the verified Slack user id.
  const isGroup = msg.channel_type
    ? msg.channel_type !== "im"
    : null;

  const built = await buildInbound(
    {
      timestamp: ts,
      senderId: msg.user ?? msg.bot_id ?? null,
      senderName: null, // Slack message events don't carry display name
      channelId: msg.channel,
      isGroup,
      conversationId: msg.channel,
      sessionKey,
      messageId: msg.ts,
      content: text,
    },
    detector,
    "code-daemon",
  );
  if (built.jailbreakLine) await appendLine(JAILBREAK_LOG, built.jailbreakLine);
  await appendLine(ACTIVITY_LOG, built.activityLine);
}

// Schedule the digest with an in-process timer (Tier-2 — no cron needed).
export function scheduleDigest(everyMs: number, fireDigest: () => void): ReturnType<typeof setInterval> {
  return setInterval(fireDigest, everyMs);
}
