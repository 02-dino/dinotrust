// dinotrust observability — universal event builders (runtime-neutral).
//
// SHARED VERBATIM by every code-producer adapter. An adapter's only job on the
// producer side is to normalize its platform event into a `NormalizedInbound`
// or `NormalizedOutbound`, then call these builders to get the canonical JSONL
// line shape (audit-schema.json). The schema is therefore identical across
// every runtime — OpenClaw, Hermes, Discord, … — by construction.
//
// Nothing here touches platform APIs or log I/O. Pure shape + detection glue.

import type { Detector, Hit } from "./detector.js";

export interface NormalizedInbound {
  timestamp: string;          // ISO-8601
  senderId: string | null;
  senderName: string | null;
  channelId: string;
  isGroup: boolean | null;
  conversationId: string | null;
  sessionKey: string;
  messageId: string | null;
  content: string;            // raw; privacy applied only to the stored audit copy
}

export interface NormalizedOutbound {
  timestamp: string;          // ISO-8601
  channelId: string;
  to: string | null;
  sessionKey: string;
  content: string;
  success: boolean | null;
}

export interface BuiltInbound {
  activityLine: string;          // always written to ACTIVITY_LOG
  jailbreakLine: string | null;  // written to JAILBREAK_LOG only when hits > 0
  hits: Hit[];
}

// Build the inbound activity line + (if flagged) the jailbreak audit line.
// `producer` identifies the adapter class for honest provenance in the audit
// (e.g. "code-hook" for an independent hook, "self-audit" for Tier-3 CLIs).
export async function buildInbound(
  n: NormalizedInbound,
  detector: Detector,
  producer: string,
): Promise<BuiltInbound> {
  const activityLine = JSON.stringify({
    direction: "in",
    timestamp: n.timestamp,
    senderId: n.senderId,
    senderName: n.senderName,
    channelId: n.channelId || "unknown",
    isGroup: n.isGroup,
    conversationId: n.conversationId,
    sessionKey: n.sessionKey,
    messageId: n.messageId,
    content: n.content,
  });

  const hits = await detector.detect(n.content);
  let jailbreakLine: string | null = null;
  if (hits.length > 0) {
    jailbreakLine = JSON.stringify({
      timestamp: n.timestamp,
      senderId: n.senderId,
      senderName: n.senderName,
      channelId: n.channelId || "unknown",
      isGroup: n.isGroup,
      conversationId: n.conversationId,
      messageId: n.messageId,
      patterns: hits.map((h) => h.id),
      rule_ids: [...new Set(hits.map((h) => h.rule_id))],
      severity: detector.topSeverity(hits),
      hits,
      content: detector.privacyContent(n.content),
      producer,
    });
  }
  return { activityLine, jailbreakLine, hits };
}

export function buildOutbound(n: NormalizedOutbound): string {
  return JSON.stringify({
    direction: "out",
    timestamp: n.timestamp,
    channelId: n.channelId || "unknown",
    to: n.to,
    sessionKey: n.sessionKey,
    content: n.content,
    success: n.success,
  });
}
