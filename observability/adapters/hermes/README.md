# Hermes adapter — Tier-1 (gateway hook, independent producer)

Hermes Gateway hooks (`HOOK.yaml` + `handler.py` in `~/.hermes/hooks/<name>/`)
are a genuine independent producer — the same class as OpenClaw's hook, just
Python instead of TS. So **Hermes is Tier-1, not the daemon template path.**

Source: Hermes docs → *Event Hooks* (`hermes-agent.nousresearch.com/docs/
user-guide/features/hooks`). Handler signature `handle(event_type, context)`,
non-blocking (errors caught, never crash the agent).

## Event mapping

| Hermes event | dinotrust use | context keys used |
|--------------|---------------|-------------------|
| `agent:start` | inbound; run detection | `platform`, `user_id`, `session_id`, `message` |
| `agent:end` | outbound activity | `platform`, `user_id`, `session_id`, `response` |

`identityField = user_id` (Hermes' verified sender id — never inferred from
message text).

## Detection parity

`handler.py` loads the **same `patterns.json`** as every other runtime, so the
taxonomy is identical. Because a Hermes hook loads as a single Python file
(like OpenClaw's single-file hook), the detection mechanics are inlined and kept
behavior-identical to `core/` (TS) and `report.py` (Python). See
`../../core/PARITY.md`.

## Install (manual — no automated installer yet)

1. Copy this dir + the shared taxonomy into the hook path:
   ```bash
   mkdir -p ~/.hermes/hooks/dinotrust-observability
   cp adapters/hermes/HOOK.yaml adapters/hermes/handler.py \
      patterns.json ~/.hermes/hooks/dinotrust-observability/
   ```
2. Configure via env (the handler reads `DT_*`, falling back to installer
   placeholders):
   ```bash
   export DT_ACTIVITY_LOG=~/.hermes/logs/dinotrust-activity.log
   export DT_JAILBREAK_LOG=~/.hermes/logs/dinotrust-jailbreak.log
   export DT_PATTERNS_FILE=~/.hermes/hooks/dinotrust-observability/patterns.json
   export DT_PRIVACY=patterns-only          # patterns-only | truncated | full
   export DT_AGENT_FILTER=                   # optional scope (platform:session_id)
   ```
3. Restart the Hermes gateway so the hook loads.

## Digest

Reuse the universal consumer — `report.py` reads the Hermes-produced JSONL
unchanged (same `audit-schema.json`). Schedule it with Hermes cron (`hermes cron`)
or any cron:

```bash
DT_SELFAUDIT_LOG=~/.hermes/logs/dinotrust-jailbreak.log \
  python3 ../openclaw/report.py --period daily --dry-run
```

(Set `DT_CHANNEL`/`DT_TARGET` for real delivery; otherwise `--dry-run`.)
