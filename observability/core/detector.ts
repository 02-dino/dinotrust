// dinotrust observability — universal detection core (runtime-neutral).
//
// SHARED by DAEMON-CLASS adapters that run as real Node processes with module
// resolution (Hermes, Discord/Slack bots). It contains NO runtime-specific
// code: no event shapes, no log I/O, no platform APIs. Just: load patterns.json,
// run the regex taxonomy, rank severity, apply the privacy level.
//
// NOTE on OpenClaw: OpenClaw managed hooks load as a SINGLE self-contained file
// (no sibling-source imports resolve at hook-load time). So the OpenClaw adapter
// (../adapters/openclaw/handler.ts) intentionally INLINES this same logic
// instead of importing it. The two must stay behavior-identical; patterns.json
// is the shared source of truth that keeps detection in lockstep, and the
// behavior parity is covered by core/PARITY.md.
//
// The taxonomy itself lives in ../patterns.json and is shared with the Python
// consumer + every other-language adapter. This module is the TS embodiment of
// that same data — identical detection, wherever it runs.
//
// Adapters import { makeDetector } and call detector.detect(text) /
// detector.privacyContent(text). They never re-implement detection.

import fs from "node:fs/promises";

export type Pattern = { id: string; regex: string; rule_id: string; severity: string; flags?: string; direction?: string };
export type CompiledPattern = { id: string; re: RegExp; rule_id: string; severity: string; direction: "in" | "out" };
export type Hit = { id: string; rule_id: string; severity: string };
export type Direction = "in" | "out";
export type Privacy = "patterns-only" | "truncated" | "full";

export const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
export const DEFAULT_TRUNCATE_LEN = 200;

export function topSeverity(hits: Hit[]): string {
  let best = "";
  let bestRank = 0;
  for (const h of hits) {
    const r = SEV_RANK[h.severity] ?? 0;
    if (r > bestRank) { bestRank = r; best = h.severity; }
  }
  return best || "low";
}

export interface Detector {
  // direction defaults to "in" (inbound) for backward compatibility. Outbound
  // (secret-shape) detection: pass "out". Patterns are scoped by direction and
  // never cross-applied.
  detect(content: string, direction?: Direction): Promise<Hit[]>;
  privacyContent(content: string): string | null;
  topSeverity(hits: Hit[]): string;
}

// makeDetector binds a detector to one patterns.json path + privacy level.
// Patterns are loaded once and cached. Fails OPEN (empty pattern set) if the
// file is missing/corrupt — observability must never disrupt message flow.
export function makeDetector(patternsFile: string, privacy: Privacy, truncateLen = DEFAULT_TRUNCATE_LEN): Detector {
  let compiled: CompiledPattern[] | null = null;

  async function loadPatterns(): Promise<CompiledPattern[]> {
    if (compiled) return compiled;
    try {
      const raw = await fs.readFile(patternsFile, "utf-8");
      const data = JSON.parse(raw);
      const pats: Pattern[] = Array.isArray(data?.patterns) ? data.patterns : [];
      compiled = pats.map((p) => ({
        id: p.id,
        re: new RegExp(p.regex, p.flags ?? "i"),
        rule_id: p.rule_id,
        severity: p.severity,
        // No 'direction' field => inbound (historic default). 'out' => outbound only.
        direction: (p.direction === "out" ? "out" : "in") as Direction,
      }));
    } catch {
      compiled = []; // fail open
    }
    return compiled;
  }

  return {
    async detect(content: string, direction: Direction = "in"): Promise<Hit[]> {
      const pats = await loadPatterns();
      const hits: Hit[] = [];
      for (const p of pats) {
        if (p.direction !== direction) continue;
        if (p.re.test(content)) hits.push({ id: p.id, rule_id: p.rule_id, severity: p.severity });
      }
      return hits;
    },
    privacyContent(content: string): string | null {
      if (privacy === "patterns-only") return null;
      if (privacy === "truncated") return content.slice(0, truncateLen);
      return content; // "full"
    },
    topSeverity,
  };
}
