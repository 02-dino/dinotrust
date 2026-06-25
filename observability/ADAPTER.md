# Observability Adapter Contract

The observability core is **language-neutral data + spec**: `patterns.json`
(taxonomy) and `audit-schema.json` (event shape). Detection logic and severity
calibration live there and are shared **verbatim** across every platform.

An *adapter* is the thin, platform-specific glue that connects that core to one
host. The reference adapter is OpenClaw (`adapters/openclaw/`). Porting to a new
platform means implementing the same five concerns — nothing more.

---

## The 5-function contract

| Function | Signature | Job |
|----------|-----------|-----|
| `onInbound` | `(raw) -> normalized \| null` | Tap a host message event, normalize to `{senderId, senderName, channelId, messageId, text, direction}`. Return `null` to skip (wrong agent/scope). |
| `deliver` | `(text, target) -> void` | Send the rendered digest to a destination on the host's channel. |
| `renderMention` | `({id, name}) -> string` | Produce a platform-native mention/link for a flagged sender (e.g. a Telegram `tg://user?id=` link). |
| `schedule` | `(expr, fn) -> void` | Run the digest on a cadence. Daemon platforms use an in-process timer; no-daemon CLIs use the host scheduler (cron). |
| `identityField` | *(doc-only)* | Declare which host metadata field is the authoritative sender identity (e.g. OpenClaw `senderId`, Telegram `from.id`). Used for correct attribution, never inferred from content. |

The first three are pure transforms + I/O. `schedule` is the only one whose
mechanism differs by tier (below). `identityField` is documentation — it tells
a porter which field to trust so audit attribution matches the same identity
signal dinotrust's `security_rules.md` uses.

---

## Core vs adapter (what you may NOT change)

- **`patterns.json` is the spine.** Each regex maps to a `rule_id` (exact IDs
  from `security_rules.md`: R1, R3, R4, R6, R7, S0) + a severity tier. Adapters
  load it as-is; they never redefine patterns or severities.
- **`audit-schema.json` is the event contract.** Every adapter emits the same
  JSONL line shape so digests and downstream tooling are platform-agnostic.
- **`R2_external_instructions` and `T1_config_conflict` are agent-judged, not
  regex-detectable** by design — declared under `_meta.agent_judged_only` in
  `patterns.json`. Adapters do not attempt to regex these.
- **Digest logic is universal** (windowing, grouping by `rule_id` + severity,
  counts, worst-severity headline). Only `deliver` + `renderMention` are
  platform-specific. See `DIGEST.md`.

---

## Tiers

The contract is identical across tiers; only `schedule` (and honesty about
guarantees) changes.

- **T1 — OpenClaw** *(reference, implemented)*
  Code hook produces events (`adapters/openclaw/handler.ts`); a consumer script
  (`adapters/openclaw/report.py`) builds + delivers the digest. `schedule` =
  host cron (wired by `install.sh`).

- **T2 — Daemon bots (Discord, Slack, …)** *(later)*
  Long-lived process taps the gateway events directly. `schedule` = in-process
  timer (no external cron). Same `patterns.json`, same schema.

- **T3 — No-daemon CLIs (Claude Code, Cursor, Aider, …)**
  No place to run a code adapter. Instead, a **self-audit clause** in
  `security_rules.md` asks the agent to append one audit line (naming the
  `rule_id`) on each reject-pattern match, plus an **on-demand** digest. Same
  schema, but honestly marked **best-effort / weaker** — there is no independent
  producer, so it depends on the agent's own compliance.

---

## Adding a platform

1. Implement the 5 functions against the host's event + delivery APIs.
2. Load the **unchanged** `patterns.json`; do not fork the taxonomy.
3. Emit lines matching `audit-schema.json` (respect the privacy mode — see
   `DIGEST.md`).
4. Reuse the universal digest grouping; only swap `deliver` + `renderMention`.
5. Pick the right `schedule` mechanism for the tier (timer vs cron vs on-demand).
6. Declare your `identityField` so attribution uses the platform's verified id.
7. Run `validate.py` — if `patterns.json` rule_ids drift from
   `security_rules.md`, the install must fail closed.
