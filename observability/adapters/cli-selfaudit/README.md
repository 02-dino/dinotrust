# Tier-3 — No-daemon CLI self-audit

**Runtimes:** Claude Code, OpenAI Codex CLI, Cursor, Windsurf, Continue.dev,
Aider, Goose — any request/response CLI with **no persistent process and no
message-event hook**.

## Why this tier is different (physics, not effort)

Tier-1 (OpenClaw hook) and Tier-2 (Hermes/Discord daemon) both run an
**independent producer** — code that observes traffic the agent cannot suppress.
No-daemon CLIs have nowhere to run that producer: the process starts on a
request and exits. The **only** observer available is the agent itself.

So Tier-3 cannot offer an independent audit. It is honestly weaker, and we mark
it as such everywhere (`producer: "self-audit"`, `independent: false`). What it
*can* do: have the agent log its own reject-pattern hits, in the **same audit
schema**, so the digest tooling is identical.

## How it works

1. **`security_rules.md` carries the audit clause** (`audit.A1_reject_pattern_audit`,
   shipped in dinotrust core): on detecting any reject-pattern (R1–R7 / S0)
   match, the agent appends one audit line naming the `rule_id` to its audit log.
2. The agent writes that line in `audit-schema.json` shape with
   `producer: "self-audit"`.
3. **`report.py` (Tier-1 consumer) reads it unchanged** — same schema, same
   grouping, same digest. Run it on demand (no cron; there's no daemon to
   schedule one).

## Honest guarantees

- ✅ Same taxonomy, same schema, same digest format as Tier-1/2.
- ✅ Zero infra, no new process.
- ⚠️ **Depends on the agent's own compliance.** A successfully-jailbroken or
  non-compliant agent may not log. This is a self-report, not an independent
  control. Treat the absence of audit lines as *no evidence*, not *evidence of
  none*.
- ⚠️ **Outbound + full traffic telemetry is not available** (no tap). Tier-3
  digests cover flagged reject-pattern self-reports only.

## Setup

There is no installer hook for Tier-3 (nothing to install — the producer *is*
the agent). Steps:

1. Ensure `security_rules.md` (with the `audit.A1` clause) is injected via
   dinotrust core's `scripts/install.sh` for your CLI.
2. Point the agent at an audit log path (tell it where to append).
3. Run the digest on demand:

   ```bash
   DT_SELFAUDIT_LOG=~/.dinotrust/<agent>-selfaudit.jsonl \
     python3 ../openclaw/report.py --period weekly --dry-run
   ```

   (`report.py` reads `JAILBREAK_LOG`; for Tier-3 set it to your self-audit log.
   Delivery still works via any channel if `openclaw` CLI is present, else use
   `--dry-run` and read the report inline.)

## Schema line the agent appends (example)

```json
{"timestamp":"2026-06-25T04:30:00Z","senderId":null,"senderName":null,
 "channelId":"cli","rule_ids":["R1_override_claims"],"severity":"high",
 "patterns":["ignore_instructions"],"content":null,"producer":"self-audit"}
```

`senderId` is typically null on a single-user CLI; `content` honors privacy
(null under patterns-only). Everything else matches `../../audit-schema.json`.
