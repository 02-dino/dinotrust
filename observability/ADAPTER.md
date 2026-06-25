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

- **T1 — Real hook API (OpenClaw, Hermes)** *(both implemented)*
  The runtime exposes a hook that fires per message — an independent producer.
  - **OpenClaw** (`adapters/openclaw/handler.ts`, TS, self-contained per
    OpenClaw's single-file hook constraint — see `core/PARITY.md`); consumer
    `adapters/openclaw/report.py`; `schedule` = host cron (wired by `install.sh`).
  - **Hermes** (`adapters/hermes/HOOK.yaml`+`handler.py`, Python; Gateway hook
    in `~/.hermes/hooks/`). Taps `agent:start`/`agent:end`. Loads the same
    `patterns.json`, emits the same schema; `schedule` = Hermes/any cron. Manual
    install for now (see `adapters/hermes/README.md`).

- **T2 — Daemon bots, no hook API (Discord, Slack, …)** *(implemented: shared
  core + template + Discord reference)*
  Long-lived process taps its own message pipeline. Reuses `core/` **verbatim**
  (`makeDetector` + `buildInbound`/`buildOutbound` + `appendLine`); the adapter
  is just the platform glue. `schedule` = in-process timer (no cron). Start from
  `adapters/_template/daemon-adapter.ts`; `adapters/discord/tap.ts` is a working
  reference. Same independence as T1.

- **T3 — No-daemon CLIs (Claude Code, Codex CLI, Cursor, Windsurf, Continue,
  Aider, Goose)** *(implemented: self-audit path)*
  No persistent process and no message hook → **no independent producer is
  physically possible**. The only observer is the agent itself. A **self-audit
  clause** in `security_rules.md` (`audit.A1_reject_pattern_audit`) has the agent
  append one audit line (naming the `rule_id`) per reject-pattern match, in the
  **same schema**; `report.py` reads it on demand (`DT_SELFAUDIT_LOG`). Honestly
  marked **best-effort / weaker** (`producer: "self-audit"`, `independent:
  false`) — it depends on the agent's own compliance. See
  `adapters/cli-selfaudit/README.md`.

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
