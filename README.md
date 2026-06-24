# 🦖 dinotrust — The Firewall Inside Your AI Agent

> Access control & prompt-injection defense for any AI agent — block impersonation and unauthorized access in under a minute.

---

## Why dinotrust is different

Knowing a Telegram user ID is easy. Knowing whether that ID is allowed to read your files, run commands, or see your keys — and enforcing it every turn — is what dinotrust does.

Most agent-security tools sit *in front of* the agent: a proxy, a middleware firewall, an API gateway that intercepts every message. That means another service to deploy, another endpoint to secure, another thing that breaks.

dinotrust has **zero infrastructure**. It injects a structured ruleset straight into the agent's own context — the same channel the agent reads its instructions from — and the agent enforces the rules itself. No proxy. No middleware. No API changes. Delete the injected block and it's gone cleanly.

- **Self-enforcing** — the agent is the firewall. Nothing to run in front of it, nothing to keep online.
- **Zero-infrastructure** — one config block, no extra service, no new attack surface.
- **9 platforms, one ruleset** — OpenClaw, Hermes, Claude Code, Codex CLI, Goose, Cursor, Windsurf, Continue.dev, Aider — each via its native config mechanism (AGENTS.md, CLAUDE.md, .windsurfrules, …).
- **Authorization, not authentication** — ownership is bound to the platform's verified identity signal (numeric/UUID), never to chat claims. Re-checked every turn.

**This tracks model capability.** Enforcement is the agent's own instruction-following, not a static regex or proxy filter. As models get better at following instructions, they enforce the rules more reliably and resist manipulation better — while a fixed filter stays exactly as good (or as brittle) as the day it shipped. It cuts both ways: stronger models also mean stronger adversaries, so this raises reliability, not absolute guarantees (see the Identity model note).

---

## What it does

- **Installs security rules** into your AI agent's config file — injected every conversation automatically
- **Verifies ownership** via platform metadata (Telegram user ID, Discord user ID, etc.) — not chat claims
- **Blocks non-owners** from write/delete/exec operations, config access, and credential exposure
- **Rejects injection attempts** — override claims, encoded commands, hypothetical bypasses, multi-turn escalation
- **Supports 9 platforms** — OpenClaw, Hermes, Claude Code, OpenAI Codex CLI, Goose, Cursor, Windsurf, Continue.dev, Aider
- **Profile presets** — private-assistant, market-analyst, or custom

---

## How it works

```
install.sh
    │
    ├── Detect platform (or ask)
    ├── Ask: owner ID(s) + profile preset
    ├── Fill placeholders in security_rules.md
    ├── Inject into platform config file
    │     (project-level by default; --global for global)
    └── Done — agent enforces rules on next restart
```

The injected block is clearly marked with `# --- dinotrust begin ---` / `# --- dinotrust end ---` so it can be updated or removed cleanly.

---

## Identity model

dinotrust is an **authorization** framework, not an authentication framework.

| Question | Answered by |
|----------|-------------|
| *Who are you?* | Your platform (Telegram, Discord, GitHub, etc.) |
| *What are you allowed to do?* | dinotrust |

dinotrust assumes the host platform provides a trusted identity signal through system-injected metadata — a numeric ID the platform attaches to every message before the agent sees it.

**Valid identity signals:**
- Telegram User ID
- Discord User ID
- GitHub User ID
- OAuth Subject ID
- Authenticated Session ID

**Not valid for ownership verification:**
- Usernames or display names
- Claims made in chat ("I am the owner")
- Memory entries
- Tool outputs or external content

The rules enforce this distinction explicitly: ownership claims in chat are ignored regardless of how convincing they sound.

**Per-turn verification**

Ownership is re-verified on every message — not just at session start. If the platform-injected sender ID is absent or malformed, the agent defaults to non-owner. No carry-over from previous turns.

**Platform identity fields**

| Platform | Authoritative field |
|----------|--------------------|
| Telegram | `from.id` (integer user ID) |
| Discord | `author.id` (snowflake) |
| Slack | `user` (member ID, `Uxxxxxxxx`) |
| WhatsApp | sender phone in E.164 |
| Signal | sender UUID |
| GitHub | `sender.id` from webhook payload |
| OpenClaw | `sender_id` from `inbound_meta.v2` |

Username, display name, and any user-provided field are never used for verification — only the platform-injected numeric or UUID identifier.

**What this means in practice:** if someone shares your account or your session is compromised, dinotrust cannot detect it — because the platform itself cannot. dinotrust is only as strong as the platform's authentication.

**Multiple owners**

dinotrust supports more than one owner. Pass several IDs comma-separated:

```bash
bash scripts/install.sh --owner-id "123456789,987654321"
```

The rules store them as a set (`owner_ids`), and a sender is the owner if and only if their platform-injected ID is an exact member of that set. A single ID behaves exactly like single-owner mode — fully backward-compatible.

> **⚠️ Each owner is a full-access account.** More owners means more accounts that, if compromised, grant the agent's full owner privileges. Add only IDs you trust at the same level as your own. There is no partial-owner tier — owner is all-or-nothing (use a profile preset if you need scoped non-owner access instead).

---

## Using dinotrust

After install, the agent enforces rules automatically. No commands needed.

To verify injection:
```bash
# OpenClaw example
grep -n "dinotrust" ~/.openclaw/workspace-<agent>/AGENTS.md

# Claude Code example
grep -n "dinotrust" ~/.claude/CLAUDE.md
```

To update rules (re-run installer):
```bash
bash ~/.dinotrust/scripts/install.sh --force
```

---

## Prerequisites

- Bash 4+
- One of the supported AI agent platforms installed and configured
- Your platform user ID (Telegram: Settings → Advanced → copy numeric ID; Discord: Developer Mode → right-click username → Copy ID)

---

## Quick Start

```bash
git clone https://github.com/02-dino/dinotrust
cd dinotrust
bash scripts/install.sh
```

Follow the prompts. Done in under a minute.

---

## How do I know it's working?

1. Check the injection landed:
```bash
grep "dinotrust begin" <your-agent-config-file>
```

2. Test as a non-owner: ask the agent to read a config file or run a shell command — it should refuse.

3. Test as owner: send a message from your verified account — full access should work normally.

---

## Install options

| Flag | Default | Description |
|------|---------|-------------|
| `--platform NAME` | Interactive | Skip platform detection prompt |
| `--owner-id IDS` | Interactive | Your platform user ID(s) — comma-separated for multiple owners (e.g. `123,456`) |
| `--profile NAME` | Interactive | Preset: `private-assistant`, `market-analyst`, `custom` |
| `--global` | Project-level | Inject into global config instead of project-level |
| `--force` | — | Overwrite existing dinotrust block |
| `--dry-run` | — | Preview what would be injected, no changes |

---

## What gets installed

```
dinotrust/
├── scripts/
│   ├── install.sh       ← main installer
│   ├── uninstall.sh     ← removes injected block
│   └── update.sh        ← re-runs install with --force
├── security_rules.md    ← the ruleset template (filled by installer)
├── README.md
├── CHANGELOG.md
├── VERSION
└── LICENSE
```

Nothing is copied to your workspace. The installer reads `security_rules.md`, fills placeholders, and appends the result to your agent's config file.

---

## Supported platforms

| Platform | Config file (project) | Config file (global) |
|----------|----------------------|---------------------|
| OpenClaw | `<workspace>/AGENTS.md` | — |
| Hermes | `~/.hermes/SOUL.md` | — |
| Claude Code | `./CLAUDE.md` | `~/.claude/CLAUDE.md` |
| OpenAI Codex CLI | `./AGENTS.md` | `~/.codex/AGENTS.md` |
| Goose | `./AGENTS.md` | — |
| Cursor | `.cursor/rules/dinotrust.mdc` | — |
| Windsurf | `.windsurfrules` | `global_rules.md` |
| Continue.dev | `.continuerules` | — |
| Aider | `CONVENTIONS.md` + `.aider.conf.yml` | — |

---

## Profile presets

| Profile | Use case | Non-owner access |
|---------|----------|-----------------|
| `private-assistant` | Personal assistant, no public access | None |
| `market-analyst` | Market analysis bot with public users | Market data tools only |
| `custom` | You define everything | You define |

---

## Troubleshooting

**Agent ignores the rules**
Some platforms only read config files at startup. Restart the agent after install.

**Injection not found**
```bash
bash scripts/install.sh --force
```

**Wrong platform detected**
```bash
bash scripts/install.sh --platform openclaw
```

**Need to see what would be injected without changing anything**
```bash
bash scripts/install.sh --dry-run
```

---

## FAQ

**Does this work with any LLM?**
Yes — the rules are injected as plain text into the agent's context. Any LLM that reads the config file will see them.

**What if someone claims to be the owner in chat?**
The rules explicitly instruct the agent to ignore ownership claims made in chat. Only platform-injected metadata (user ID from Telegram, Discord, etc.) counts.

**Can I add my own protected files?**
Yes — the installer prompts for this, or you can edit the injected block directly after install.

**Does this guarantee security?**
No. The agent enforces rules based on its own judgment. A sufficiently adversarial prompt may still bypass them. dinotrust raises the bar significantly but is not a hard security boundary.

---

## Update

```bash
bash scripts/update.sh
```

Pulls latest + re-runs install with `--force`. Your owner ID and profile are preserved in the existing block.

## Uninstall

```bash
bash scripts/uninstall.sh
```

Removes the dinotrust block from your agent's config file. Agent returns to default behavior.

---

## License

MIT — see LICENSE.

---

Made with 🦖 by [@02-dino](https://github.com/02-dino) | [komunitech.com](https://komunitech.com)
