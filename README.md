# 🦖 dinotrust — AI Agent Security Rules Installer

> One command to harden any AI agent against prompt injection, impersonation, and unauthorized access.

---

## Why dinotrust is different

Most AI agents ship with no access control. Anyone in the chat can ask them to read files, run commands, or reveal secrets.

dinotrust injects a structured security ruleset directly into the agent's context — the same way the agent reads its own instructions. No middleware, no proxy, no API changes. The agent enforces the rules itself.

- **Platform-native** — works with how each agent already reads its config (AGENTS.md, CLAUDE.md, .windsurfrules, etc.)
- **Owner-verified** — ownership is verified via platform-injected metadata, not chat claims
- **Injection-resistant** — explicit reject patterns for override attempts, encoded commands, and hypothetical bypasses

---

## What it does

- **Installs security rules** into your AI agent's config file — injected every conversation automatically
- **Verifies ownership** via platform metadata (Telegram user ID, Discord user ID, etc.) — not chat claims
- **Blocks non-owners** from write/delete/exec operations, config access, and credential exposure
- **Rejects injection attempts** — override claims, encoded commands, hypothetical bypasses, multi-turn escalation
- **Supports 9 platforms** — OpenClaw, Hermes, Claude Code, OpenAI Codex CLI, Goose, Cursor, Windsurf, Continue.dev, Aider
- **Profile presets** — public-bot, private-assistant, market-analyst, or custom

---

## How it works

```
install.sh
    │
    ├── Detect platform (or ask)
    ├── Ask: owner ID + profile preset
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
| `--owner-id ID` | Interactive | Your platform user ID |
| `--profile NAME` | Interactive | Preset: `public-bot`, `private-assistant`, `market-analyst`, `custom` |
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
| `public-bot` | Public Telegram/Discord bot | Read-only market data tools |
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
