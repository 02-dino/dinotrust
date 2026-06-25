// dinotrust observability — shared log sink (runtime-neutral, Node fs).
//
// Appends a JSONL line, creating the parent dir as needed. ALWAYS silent on
// failure: observability must never throw into the host message path. Used by
// every Node-based adapter (OpenClaw, Hermes). Non-Node runtimes implement
// their own sink with the same contract: append-one-line, never throw.

import path from "node:path";
import fs from "node:fs/promises";

export async function appendLine(file: string, line: string): Promise<void> {
  try {
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.appendFile(file, line + "\n");
  } catch {
    // Silent by contract: never disrupt message flow.
  }
}
