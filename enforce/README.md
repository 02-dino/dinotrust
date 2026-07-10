# dinotrust enforce — the enforcement layer

`security_rules.md` (dinotrust core) is the **instruction** layer: it tells the
agent the policy. A compliant agent obeys it. `enforce/` is the **code** layer
beneath it: a `pre_tool_call` / `before_tool_call` hook that returns a terminal
verdict, so the policy holds **even if the model doesn't comply**.

```
instruction layer  (security_rules.md)   — the agent SHOULD (all runtimes)
enforce layer       (this)               — the runtime WILL (4 supported runtimes)
```

## What it does

Same authorization model as dinotrust core (`owner_rules` / `non_owner_rules`),
as an actual gate:

| Sender | Action | Verdict |
|---|---|---|
| **Owner** / agent-operated-by-owner | normal | **allow** (warn-log on secret touch) |
| **Owner** | critical/irreversible (`rm -rf`, `git push --force`, write to `openclaw.json`/`security_rules.md`/`AGENTS.md`/`.env`, …) | **ask** — "are you sure?" confirmation, even for the owner |
| **Non-owner** | read / web / memory tools | **allow** |
| **Non-owner** | exec of an allowlisted read-only script (e.g. `tools/exchange_data.py`) | **allow** |
| **Non-owner** | any other exec / shell | **block** |
| **Non-owner** | write / edit / apply_patch | **block** |
| **Non-owner** | touch a secret path (`.env`, keys, `credentials`, `secrets/**`) | **block** |

**Zero hardcoded policy.** Every rule is config (`ownerIds`,
`criticalExecPatterns`, `criticalPathGlobs`, `protectedGlobs`, `mutatingTools`,
`nonOwnerAllowedTools`, `nonOwnerAllowedScripts`, `enforce`). Ships with safe
general defaults and an **empty** `nonOwnerAllowedScripts` — each install fills
its own allowlist. `enforce:false` = dry-run (log, no block).

## Supported runtimes (real enforcement only)

Enforcement requires a runtime that lets a hook **veto a tool call before it
runs**. Four runtimes provide that contract:

| Runtime | Mechanism | Adapter |
|---|---|---|
| **OpenClaw** | `before_tool_call` managed hook (returns `{block}` / `{requireApproval}`) | `adapters/openclaw/` |
| **Hermes** | `pre_tool_call` shell hook (stdin event → stdout `{decision}`) | `adapters/pre_tool_call/` |
| **Claude Code** | `PreToolUse` hook (stdin → stdout `{decision}`) | `adapters/pre_tool_call/` |
| **OpenAI Codex CLI** | `pre_tool_call` hook (stdin → stdout `{decision}`) | `adapters/pre_tool_call/` |

Runtimes **without** a pre-tool veto (Cursor, Windsurf, Continue.dev, Aider,
Goose) cannot enforce — they only get dinotrust core's instruction layer, which
is compliance-dependent. They are **not supported by the enforce layer**; see
the top-level README support scope.

## Parity

`core/policy.ts` is the single source of truth for the decision. The OpenClaw
adapter inlines it (managed hooks load as one self-contained file — no sibling
imports); the `pre_tool_call` adapter re-implements it in Python (no JS dep).
All three are covered by selftests that assert identical verdicts:

```bash
node --experimental-strip-types enforce/core/policy.selftest.mjs      # 24/24
node enforce/adapters/openclaw/selftest.mjs                           # 27/27
python3 enforce/adapters/pre_tool_call/selftest.py                    # 29/29
```

Change policy in one place → mirror in the others → re-run all three. See
`../observability/core/PARITY.md` for the same discipline applied to the audit
layer.

## Install

```bash
bash enforce/install.sh --platform openclaw --owner-id <id> \
  [--allow-scripts exchange_data,semantic_search,...] [--dry-run]
```

- **OpenClaw:** installs the managed hook plugin + writes the plugin config into
  `openclaw.json` (`plugins.entries.dinotrust-enforce.config`).
- **Hermes / Claude Code / Codex:** installs the `pre_tool_call` handler, writes
  `~/.dinotrust/enforce.json`, and registers the hook in the runtime's config
  (`cli-config.yaml` hooks block for Hermes; `settings.json` hooks for Claude
  Code; equivalent for Codex).

`enforce:false` first to shadow-test (log only), then flip to `true`.

## Owners, and this installer's scope

`ownerIds` here is an **array**, not a single id — comma-separated, e.g.
`--owner-id "111111,222222,333333"`. Every id gets identical owner tier; no
primary/secondary.

**This is the enforce-layer's own config, separate from `security_rules.md`'s
`owner_ids`.** Running `enforce/install.sh` directly at INSTALL time (standalone,
bypassing the top-level `scripts/install.sh`) sets ONLY the enforce hook's
owner list — it does not touch the instruction-layer copy in your agent config.
That's fine if you're intentionally running enforce standalone (e.g.
`--no-observability` installs, or testing the hook in isolation).

**To add/remove an owner LATER (post-install), don't re-run this installer** —
use `../scripts/manage-owner.sh` instead:

```bash
bash scripts/manage-owner.sh add 987654321
```

It's a surgical single-line edit (via the same `merge_config.py` key-scoped
merge this installer uses) that keeps the instruction layer AND this enforce
config in sync automatically, in one command — it looks in the same hardcoded
path this installer itself always writes to (`~/.openclaw/openclaw.json` or
`~/.dinotrust/enforce.json`), WITHOUT resetting any other customization,
unlike re-running an installer with `--force`, which regenerates from scratch.

See the main [README's Identity model](../README.md#identity-model) section
("Multiple owners" / "Adding or removing an owner after install") for the full
add/remove flow, why `AGENTS.md` edits alone don't grant enforce-layer
ownership, and platform-scoped owner syntax (`id@platform`).

## Trusted / delegated ids (third tier, below owner)

`trustedIds` is a separate, optional config on this same enforce hook: a
per-individual grant above non-owner but below owner (e.g. "admin of their
own workspace folder, nothing else"). Empty by default — zero behavior
change unless you explicitly add someone. Unlike `ownerIds`, it lives
**only** here (no instruction-layer counterpart to sync), managed with:

```bash
bash ../scripts/manage-trusted.sh add 555555 --scope "workspace-bob/**"
bash ../scripts/manage-trusted.sh add 666666 --tools read,write --scripts exchange_data
bash ../scripts/manage-trusted.sh list
bash ../scripts/manage-trusted.sh remove 555555
```

Protected resources and critical/irreversible actions are hard-blocked for
every trusted id regardless of scope — that ceiling has no per-entry
override. See the main [README's Trusted / delegated access](../README.md#trusted--delegated-access-a-third-tier)
section for the full picture, and `enforce/core/policy.ts`'s `TrustedEntry`
doc comment for the exact enforcement semantics.
