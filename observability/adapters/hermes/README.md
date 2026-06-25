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

## Install (automated)

The installer auto-detects Hermes (`~/.hermes` exists) or you can force it:

```bash
bash observability/install.sh --platform hermes --report-target <chat-id>
```

Same conventions as the OpenClaw path: auto-detects log paths, substitutes
placeholders, wires idempotent cron, runs `validate.py` preflight. Key flags:

- `--report-target ID` — **required**, where the digest is delivered.
- `--agent ID` — defaults to `hermes`; override if you run multiple agents.
- `--report-channel NAME` — delivery channel (default `telegram`).
- `--schedule CRON` — digest cadence (default `30 10 * * *`).
- `--privacy patterns-only|truncated|full` — default `patterns-only`.
- `--dry-run` — print the plan, change nothing.
- `--force` — overwrite an existing install.
- `--non-interactive` — fail fast with the missing flag.

## Manual install (env overrides)

If you prefer to place files by hand, the handler reads `DT_*` env vars
(falling back to installer placeholders):

```bash
mkdir -p ~/.hermes/hooks/dinotrust-observability
cp adapters/hermes/HOOK.yaml adapters/hermes/handler.py \
   patterns.json ~/.hermes/hooks/dinotrust-observability/

export DT_ACTIVITY_LOG=~/.hermes/logs/dinotrust-activity.log
export DT_JAILBREAK_LOG=~/.hermes/logs/dinotrust-jailbreak.log
export DT_PATTERNS_FILE=~/.hermes/hooks/dinotrust-observability/patterns.json
export DT_PRIVACY=patterns-only          # patterns-only | truncated | full
export DT_AGENT_FILTER=                   # optional scope (platform:session_id)
```

Restart the Hermes gateway so the hook loads.

## Digest

Reuse the universal consumer — `report.py` reads the Hermes-produced JSONL
unchanged (same `audit-schema.json`). After install it runs via cron; test it:

```bash
python3 ~/.hermes/scripts/dinotrust-report.py --period daily --dry-run
```

(Set `DT_CHANNEL`/`DT_TARGET` for real delivery if running outside the installed
cron context; otherwise the installer already wired them.)
