// dinotrust observability — DAEMON-CLASS adapter TEMPLATE (Tier-2).
//
// Copy this to adapters/<runtime>/ and fill the 4 TODO taps. Daemon-class
// runtimes (Hermes, Discord/Slack bots, any long-lived process) reuse the
// shared core verbatim — you only write the platform glue. The audit schema,
// detection, severity, and privacy handling are all inherited from ../../core,
// so a daemon adapter stays in lockstep with OpenClaw by construction.
//
// Tier-2 vs Tier-1 (OpenClaw): same independence (a real producer observes
// traffic the agent can't suppress), different schedule mechanism — in-process
// timer here instead of host cron, because the daemon is already long-lived.
//
// The 5-function contract (see ../../ADAPTER.md):
//   onInbound / onOutbound  -> normalize a platform event (TODO 1, 2)
//   deliver                 -> send the digest (TODO 4 / report side)
//   renderMention           -> platform mention syntax (see report.py)
//   schedule                -> in-proc timer (TODO 3)
//   identityField           -> which field is the verified sender id (doc)

import { makeDetector, type Privacy } from "../../core/detector.js";
import { buildInbound, buildOutbound } from "../../core/event.js";
import { appendLine } from "../../core/sink.js";

// === FILLED BY install (or env) ===
const AGENT_FILTER = process.env.DT_AGENT_FILTER ?? "";          // optional scope
const ACTIVITY_LOG = process.env.DT_ACTIVITY_LOG ?? "./activity.log";
const JAILBREAK_LOG = process.env.DT_JAILBREAK_LOG ?? "./jailbreak.log";
const PATTERNS_FILE = process.env.DT_PATTERNS_FILE ?? "../../patterns.json";
const PRIVACY = (process.env.DT_PRIVACY ?? "patterns-only") as Privacy;
// ==================================

const detector = makeDetector(PATTERNS_FILE, PRIVACY);

// TODO 1 — INBOUND TAP. Wire this to your platform's "message received" event.
// Map the platform event to a NormalizedInbound and let core do the rest.
export async function onInbound(evt: any): Promise<void> {
  // const sessionKey = String(evt.???);                 // your scope key
  // if (AGENT_FILTER && !sessionKey.includes(AGENT_FILTER)) return;
  const built = await buildInbound(
    {
      timestamp: new Date().toISOString(),               // TODO: use platform ts if present
      senderId: null,                                    // TODO: evt.author.id (verified id)
      senderName: null,                                  // TODO: evt.author.username
      channelId: "unknown",                              // TODO: evt.channelId
      isGroup: null,                                     // TODO: evt.guildId != null
      conversationId: null,                              // TODO: evt.channelId
      sessionKey: "",                                    // TODO: your scope key
      messageId: null,                                   // TODO: evt.id
      content: "",                                       // TODO: evt.content
    },
    detector,
    "code-daemon",                                       // honest provenance: Tier-2 producer
  );
  if (built.jailbreakLine) await appendLine(JAILBREAK_LOG, built.jailbreakLine);
  await appendLine(ACTIVITY_LOG, built.activityLine);
}

// TODO 2 — OUTBOUND TAP. Wire to your platform's "message sent (by the bot)".
export async function onOutbound(evt: any): Promise<void> {
  const line = buildOutbound({
    timestamp: new Date().toISOString(),
    channelId: "unknown",                                // TODO: evt.channelId
    to: null,                                            // TODO: evt.to
    sessionKey: "",                                      // TODO: your scope key
    content: "",                                         // TODO: evt.content
    success: null,                                       // TODO: send result
  });
  await appendLine(ACTIVITY_LOG, line);
}

// TODO 3 — SCHEDULE. Daemon-class uses an in-process timer (no cron). Call your
// runtime's report entrypoint on the cadence. Replace fireDigest with the
// daemon's own digest call (or shell out to report.py with the right env).
export function schedule(everyMs: number, fireDigest: () => void): NodeJS.Timeout {
  return setInterval(fireDigest, everyMs);
}

// TODO 4 — DELIVER lives on the report/consumer side. Reuse report.py's logic,
// or implement deliver(text, target) against your platform's send API. The
// digest grouping is universal (see ../../DIGEST.md); only deliver +
// renderMention are platform-specific.
