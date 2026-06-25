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
  mapping each match to a dinotrust `rule_id` (R1/R3/R4/R6/R7/S0) + severity.
- **Logs two streams** — all traffic → activity log (ops); flagged attempts →
  jailbreak log (security audit, schema v2).
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

| Tier | Platforms | Producer | Schedule | Strength |
|------|-----------|----------|----------|----------|
| **T1** | OpenClaw *(implemented)* | code hook | host cron | full |
| **T2** | Discord, Slack *(later)* | daemon, in-proc | in-process timer | full |
| **T3** | Claude Code, Cursor, Aider | none (self-audit clause) | on-demand | best-effort, honestly weaker |

T3 has no place to run a code adapter, so `security_rules.md` carries a
self-audit clause asking the agent to append one audit line per reject-pattern
match. Same schema, but it depends on the agent's own compliance.

---

## Install (OpenClaw)

```bash
bash observability/install.sh --report-target <chat-id>
```

Auto-detects platform, workspace, agent-id, log paths, and the openclaw binary
(with Homebrew PATH fallback). You must supply `--report-target` — it is a leak
vector, so it is never silently defaulted.

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
| `install.sh` | OpenClaw installer (substitute + install + cron). |
| `adapters/openclaw/handler.ts` | Producer hook (taps traffic, detects, logs). |
| `adapters/openclaw/report.py` | Consumer (builds + delivers the digest). |
| `ADAPTER.md` | The 5-function contract + how to add a platform. |
| `DIGEST.md` | Digest output spec. |

---

Made with 🦖 by [@02-dino](https://github.com/02-dino)
