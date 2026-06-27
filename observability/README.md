# 🦖 dinotrust observability

The **audit layer**. dinotrust *enforces* access control and injection defense;
this module *observes* and *reports* on it — an independent record of what the
agent saw and which reject-patterns fired.

Same ethos as dinotrust core: **zero infrastructure**. Regex, no LLM. The core
is language-neutral **data + spec** (`patterns.json`, `audit-schema.json`); each
platform plugs in via a thin 5-function adapter.

---

## What it does

- **Taps traffic** — every inbound + outbound message for one agent.
- **Detects injection** — runs the universal regex taxonomy (`patterns.json`)
  mapping each match to a dinotrust `rule_id`
  (R1/R3/R4/R6/R7/S0/S0_outbound_self_gate) + severity.
- **Verifies outbound secret protection** — runs `"direction":"out"`
  secret-shape patterns on the agent's *sent* messages and raises a **critical**
  audit line if a secret-shaped value (API key, token, PEM key, `.env` line)
  left the channel. This is the independent **verifier** for the
  `S0_outbound_self_gate` self-redaction clause in `security_rules.md`. It
  **alerts**, it does not block (`sent` fires post-delivery) — the redaction
  itself is the every-turn `.md` self-gate's job (prevention).
- **Logs two streams** — all traffic → activity log (ops); flagged attempts +
  outbound secret-egress → jailbreak log (security audit, schema v2).
- **Reports a digest** — deterministic daily/weekly summary grouped by rule and
  severity, delivered to a trusted owner target.

It does **not** block anything — that's dinotrust core's job. This is the
read-only mirror.

---

## Taxonomy (the spine)

`patterns.json` maps each regex → `rule_id` (exact IDs from
`security_rules.md`) + severity (critical / high / medium / low, calibrated so
bare keywords stay low, not screaming).

Two rules are **agent-judged, not regex-detectable** by design and are declared
under `_meta.agent_judged_only`:

- `R2_external_instructions`
- `T1_config_conflict`

`validate.py` fails closed if `patterns.json` rule_ids ever drift out of
`security_rules.md`.

---

## Tiers

| Tier | Runtimes | Producer | Schedule | Strength |
|------|----------|----------|----------|----------|
| **T1** | OpenClaw (`adapters/openclaw`), Hermes (`adapters/hermes`) | real hook API | host/Hermes cron | independent, full |
| **T2** | Discord, Slack | daemon, reuses `core/` (`adapters/_template`, `adapters/discord`) | in-process timer | independent, full |
| **T3** | Claude Code, Codex CLI, Cursor, Windsurf, Continue, Aider, Goose | none — self-audit clause (`adapters/cli-selfaudit`) | on-demand | best-effort, honestly weaker |

The tier is decided by **physics, not effort**: does the runtime expose a
programmatic message hook / long-lived process?

- **T1** runtimes expose a real **hook API** (OpenClaw: TS hook; Hermes:
  `HOOK.yaml`+`handler.py`, Python). Independent producer, host/Hermes cron.
- **T1/T2** run an **independent producer** — code that observes traffic the
  agent can't suppress. T2 reuses the shared `core/` library verbatim; only the
  platform tap differs (OpenClaw inlines the same logic due to its single-file
  hook constraint — see `core/PARITY.md`).
- **T3** no-daemon CLIs have nowhere to run a producer, so the only observer is
  the agent itself. `security_rules.md` carries a self-audit clause; the agent
  appends one audit line per reject-pattern match, same schema, read on demand.
  Depends on agent compliance — marked `producer: "self-audit"`,
  `independent: false`.

---

## Install

### OpenClaw (auto-detected)

```bash
bash observability/install.sh --report-target <chat-id>
```

### Hermes (auto-detected when `~/.hermes` exists)

```bash
bash observability/install.sh --platform hermes --report-target <chat-id>
```

### T3 — No-daemon CLIs (Claude Code, Codex CLI, Cursor, Windsurf, Continue, Aider, Goose)

Observability is set up automatically by `scripts/install.sh` when you pass
`--with-observability`. It creates `~/.dinotrust/env` and a self-audit log:

```bash
bash scripts/install.sh --platform claude-code --owner-id <id> --profile <preset> \
  --with-observability --report-target <chat-id> --report-channel telegram
```

Then source the env and run the digest:

```bash
source ~/.dinotrust/env
python3 observability/adapters/openclaw/report.py --period daily
```

Auto-detects platform, workspace (OpenClaw), agent-id, log paths, and the
openclaw binary (with Homebrew PATH fallback). You must supply
`--report-target` — it is a leak vector, so it is never silently defaulted.

Key flags:

- `--report-target ID` — **required**, where the digest is delivered.
- `--report-thread ID` — optional forum topic/thread.
- `--report-channel NAME` — delivery channel (default `telegram`).
- `--schedule CRON` — digest cadence (default `30 10 * * *`).
- `--report-tz TZ` — schedule tz (default host).
- `--privacy patterns-only|truncated|full` — default `patterns-only` (safest;
  no raw user content in reports).
- `--dry-run` — print the plan, change nothing.
- `--force` — overwrite an existing install.
- `--non-interactive` / `--yes` / `-y` — fail fast with the missing flag.

The installer runs `validate.py` as a preflight and refuses to install on
taxonomy drift. Cron is merged into the existing crontab (idempotent, tagged,
never clobbered) with a PATH that includes Homebrew bin.

---

## Files

| File | Role |
|------|------|
| `patterns.json` | Universal taxonomy: regex → rule_id + severity. |
| `audit-schema.json` | JSONL event contract. |
| `validate.py` | Drift guard (patterns ⊆ `security_rules.md`). |
| `install.sh` | OpenClaw (Tier-1) installer; routes other runtimes to their tier. |
| `core/` | Shared TS detection + event library (Tier-2 daemons import it). |
| `core/PARITY.md` | Why OpenClaw inlines core; what must stay identical. |
| `adapters/openclaw/handler.ts` | Tier-1 OpenClaw producer hook (self-contained TS). |
| `adapters/hermes/` | Tier-1 Hermes producer hook (`HOOK.yaml`+`handler.py`, Python). |
| `adapters/openclaw/report.py` | Consumer (digest + delivery; env-overridable, serves all tiers). |
| `adapters/_template/daemon-adapter.ts` | Tier-2 daemon adapter template. |
| `adapters/discord/tap.ts` | Tier-2 working Discord reference adapter. |
| `adapters/slack/tap.ts` | Tier-2 working Slack reference adapter (Bolt SDK). |
| `adapters/cli-selfaudit/README.md` | Tier-3 no-daemon CLI self-audit path. |
| `ADAPTER.md` | The 5-function contract + how to add a platform. |
| `DIGEST.md` | Digest output spec. |

---

Made with 🦖 by [@02-dino](https://github.com/02-dino)
