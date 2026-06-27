# Changelog

All notable changes to dinotrust are documented here.

---

## [1.18.0] — 2026-06-27

### Added
- **Outbound secret protection (S0_outbound_self_gate).** Extends S0 from
  refuse-to-reveal (inbound requests) to actually catching secret-shaped
  *values* leaving the channel. Two complementary layers, one rule:
  - **Prevention — every-turn `.md` (all tiers, incl. no-daemon CLIs).** New
    `S0_outbound_self_gate` clause in `security_rules.md` has the agent scan its
    own drafted output *at composition time* and replace secret-shaped values
    (`sk-`, `ghp_`/`github_pat_`, AWS `AKIA`/`ASIA`, Slack `xox*`, PEM private
    keys, `.env` `KEY=value` lines) with `[REDACTED:secret]` **before** the
    message is sent. Pre-send by construction, so it is the only layer that can
    truly redact and the only one that reaches T3 CLIs. Best-effort
    (agent-compliance-dependent) like every dinotrust rule. Owner may still
    request a secret explicitly for a legitimate reason.
  - **Verification — observability producer hook (T1/T2).** `patterns.json`
    gains six `"direction":"out"` critical secret-shape patterns; the OpenClaw
    adapter runs them on the `sent` event and emits a **critical**,
    evidence-backed audit line if a secret-shaped value still left — an
    independent, agent-compliance-*independent* check that the self-gate held.
    The hook is a producer/observer (`sent` fires post-delivery): it **alerts**,
    it does not mutate or block. Digest now surfaces an **Outbound
    secret-egress** callout distinct from user attacks.
- **Direction-scoped detection.** Patterns without a `direction` field are
  inbound (historic default); `"out"` is outbound. Inbound and outbound patterns
  are never cross-applied. Applied in lockstep to `core/detector.ts` (T2) and
  the inlined OpenClaw hook (parity preserved; `core/PARITY.md` updated).

### Notes
- **Roadmap, not claimed:** hook-layer *hard pre-send block/redact* requires the
  host to expose a mutating/blocking pre-send hook. OpenClaw currently exposes
  only a post-delivery `sent` event, so hook-level redaction is an upstream
  dependency. README/ADAPTER docs scope the claim honestly: `.md` self-gate
  redacts (prevention), the hook alerts (verification).
- No installer/seamlessness change: detection stays fail-open and observe-only;
  the `.md` self-gate is injected text, no message-flow mutation.

---

## [1.17.0] — 2026-06-26

### Added
- **Self-bootstrap identity disclosure.** The agent already receives the
  requester's authoritative platform id in inbound metadata (the same field
  dinotrust verifies). New `identity_self_disclosure` block in
  `security_rules.md` lets a user ask the agent `what is my user ID?` and get
  *their own* sender id back plus the matching install command — a self-hosted
  alternative to a third-party id bot.
  - Safe by design: a requester's own id is present in every message they send,
    so disclosing it back leaks nothing and grants no privilege
    (`grants_privilege: false`, `changes_ownership: false`).
  - Constrained: only the requester's **own** id; never another sender's id,
    never enumerate the configured owner_ids list (stays under
    `protected_resources`), source is platform metadata only — never chat claims.
- README: "ask your agent" is now the **primary** ID-discovery method in
  Prerequisites (third-party bots demoted to fallback), plus a self-bootstrap
  note in the Identity model section. CLI agents documented as having no inbound
  sender metadata (owner id is a local identifier).

---

## [1.16.1] — 2026-06-26

### Fixed
- **Wrong Telegram ID-discovery instructions.** Both the installer hint
  (`id_discovery_hint`) and the README Prerequisites told users to find their
  numeric ID via "Settings → Advanced → copy numeric ID" — a path that does not
  exist in stock Telegram. Corrected to the reliable method: message
  `@userinfobot` (or `@RawDataBot`), which replies with the numeric ID.
- **README Prerequisites only covered 2 platforms** and drifted from the
  installer's own per-platform hints. Now lists correct Telegram/Discord/Slack
  methods and points to the installer's interactive, platform-specific prompt as
  the source of truth (so the README no longer maintains a drift-prone copy).

---

## [1.16.0] — 2026-06-26

### Added
- **Post-install feature discovery.** The installer's success output was purely
  operational (platform / config / owner / profile / restart) and never told the
  user about the advanced surface they just gained — a real UX gap given how fast
  and seamless install is. `scripts/install.sh` now prints, after a successful
  install:
  - A short "you can tune this anytime" block naming the three customizable knobs
    (`non_owner_rules.allowed`, `deflection_message`, `protected_resources`),
    where they live (between the `# --- dinotrust begin/end ---` markers), and
    that `--profile custom` sets them interactively.
  - A profile-aware nudge: if the chosen profile is `private-assistant`, it notes
    non-owners get no access and suggests `market-analyst`/`custom` for
    public/group channels.

### Changed
- **Observability skip message is now self-explaining.** Declining the optional
  observability step previously printed a terse one-liner. It now briefly says
  what observability is (daily/weekly digest of injection attempts + which
  reject-patterns fired), confirms core enforcement is fully active without it,
  and shows the exact re-run command.

---

## [1.15.0] — 2026-06-26

### Added
- **Platform-scoped owners.** `owner_ids` entries may now be bound to specific
  platform(s). Pass `--owner-id id@platform` (or `id@platform1+platform2`) and
  that ID grants owner ONLY when the inbound platform matches; on any other
  platform it is non-owner. A bare id keeps the previous behavior (owner on any
  platform) — fully backward-compatible.
  - Installer parses `id@platform` into an inline YAML object
    `{id: X, platforms: [...]}`; bare ids still render as bare ids.
  - Ruleset (`security_rules.md`) gains a `platform_scoping` block under
    `who_is_owner.detection` defining the match rule: sender is owner IFF a bare
    owner_id equals the sender_id, OR a scoped owner_id's id equals the sender_id
    AND the inbound platform is in that entry's `platforms`.
  - Use case: build the agent on one channel (e.g. Telegram) and connect it to a
    customer-facing channel (e.g. a WhatsApp VIP group) without granting owner
    powers there — previously this relied on cross-platform ID formats never
    colliding rather than explicit policy.
- README: worked Telegram+WhatsApp scoping examples and updated `--owner-id` flag
  documentation.

---

## [1.14.0] — 2026-06-25

### Added
- **Per-platform ID discovery hints (headless-friendly).** `scripts/install.sh`
  now surfaces platform-specific instructions when `--owner-id` or
  `--report-target` is missing in non-interactive mode:
  - **Telegram**: "send /start to @userinfobot, or check Settings → Advanced →
    copy numeric ID"
  - **Discord**: "enable Developer Mode (Settings → Advanced), then right-click
    your username anywhere → Copy ID"
  - **Slack**: "open your profile → click 'More' → Copy member ID (starts with U)"
  - **CLI agents**: "your owner ID is typically your platform user ID (check the
    agent's config or the platform's account settings)"
- New function `id_discovery_hint(platform, what)` returns actionable
  instructions the AI agent can surface to the human owner.
- Updated `need_input()` to include discovery hints in error messages.
- Interactive prompts for owner ID and report target now show per-platform
  discovery instructions.

---

## [1.13.0] — 2026-06-25

### Added
- **Cross-platform delivery in `report.py`.** The consumer now supports
  multiple delivery modes (first match wins):
  1. `--dry-run` — print to stdout, no send
  2. `--output path` — write digest to file
  3. `--webhook-url URL` — POST to Discord/Slack webhook
  4. `openclaw message send` — T1/T2 default (unchanged)
  5. **none configured** — print to stdout with a note (was: fail with error 2)
- **T3 default behavior:** when `CHANNEL`/`TARGET` are unconfigured placeholders,
  `report.py` now prints the digest to stdout instead of failing. This is the
  honest default for T3 self-audit: the user sees the digest immediately and
  can decide how to route it.

### Changed
- `report.py` header updated: now described as "universal report consumer"
  (was "OpenClaw adapter"), since it serves every tier.

---

## [1.12.0] — 2026-06-25

### Added
- **Unified observability chain for ALL platforms.** `scripts/install.sh` now
  chains the audit layer for every supported platform, not just OpenClaw:
  - **T1 (OpenClaw, Hermes)** — chains to `observability/install.sh` with
    auto-routing (`--platform hermes` for Hermes).
  - **T3 (claude-code, codex-cli, cursor, windsurf, continue, aider, goose)** —
    sets up self-audit: creates `~/.dinotrust/logs/<platform>-selfaudit.jsonl`,
    writes `~/.dinotrust/env` with `DT_SELFAUDIT_LOG`, `DT_CHANNEL`, `DT_TARGET`,
    prints usage instructions. Interactive mode prompts for delivery channel
    (Telegram/Discord/Slack/File) and target ID.
- **New install.sh flags:** `--report-channel` (telegram|discord|slack|file) and
  `--report-thread` (forum topic ID).

### Changed
- `scripts/install.sh` help text updated: observability is now "all platforms"
  (was "OpenClaw only").

---

## [1.11.0] — 2026-06-25

### Added
- **GitHub Actions CI workflow** (`.github/workflows/ci.yml`). Runs on every
  push to `main` and on every pull request:
  1. `python3 validate.py` — taxonomy drift guard (exits non-zero if any
     `rule_id` in `patterns.json` is missing from `security_rules.md`).
  2. Node smoke test — loads `core/detector.ts`, compiles `patterns.json`,
     detects a test injection string, asserts `R1` rule matches. Confirms
     TypeScript core compiles and detection mechanics still work.
  3. `bash -n install.sh` — shell syntax check.
  4. `python3 -m py_compile` on `report.py`, `handler.py`, `validate.py` —
     Python syntax check.

### Changed
- None.

---

## [1.10.0] — 2026-06-25

### Added
- **Slack adapter — Tier-2 daemon-class reference.** `adapters/slack/tap.ts` mirrors
  the Discord adapter line-for-line: `attach(app, botUserId)` wires `app.message()`,
  `handle()` processes inbound/outbound, `scheduleDigest()` runs in-proc timer.
  Duck-types the Bolt SDK message event shape (no Bolt import), `identityField = user`
  (U-prefixed Slack user id), `scopeKey = slack:${team}:${channel}`. Filters
  system subtypes (joins, leaves, topic changes) and messages without text. Documents
  the Bolt `ignoreSelf: false` requirement for outbound observation (honest degrade
  if not set: inbound-only still works). Same `core/` imports, same `patterns.json`,
  same `audit-schema.json` output as every other adapter.

### Changed
- **ADAPTER.md + README**: T2 tier now lists both Discord and Slack as working
  references (was "Discord reference + template"). `adapters/slack/tap.ts` added
  to the files table.

---

## [1.9.0] — 2026-06-25

### Added
- **Automated Hermes installer.** `observability/install.sh` now supports
  `--platform hermes` (auto-detected when `~/.hermes` exists). Mirrors every
  OpenClaw convention:
  - sentinel detection (`~/.hermes`), `--platform hermes` override
  - placeholder substitution in `handler.py` (`__ACTIVITY_LOG__`,
    `__JAILBREAK_LOG__`, `__PATTERNS_FILE__`, `__PRIVACY__`)
  - `HOOK.yaml` placed alongside `handler.py` in
    `~/.hermes/hooks/dinotrust-observability/`
  - `report.py` placed in `~/.hermes/scripts/`
  - same `need_input` leak-guard, idempotency/overwrite guard, residual-
    placeholder guard, `validate.py` preflight, cron wiring (tagged, PATH-prefixed,
    `CRON_TZ=`), `--dry-run` plan, touch-logs
  - defaults agent to `hermes` (override with `--agent`)

### Changed
- **`install.sh` — platform as first-class dimension.** Replaced the flat
  OpenClaw-only install with a platform-aware structure: `OPT_PLATFORM`
  (`openclaw` | `hermes`, auto-detected), shared owner-input validation,
  platform-specific auto-detect blocks (workspace for OpenClaw, agent-id default
  for Hermes), unified file install + cron + summary. Non-T1 runtimes still get
  per-tier routing guidance. OpenClaw path regression-tested.
- **Hermes README** (`adapters/hermes/README.md`): manual copy steps replaced
  with one-command install; env overrides still documented for hand-installers.
- **ADAPTER.md** + **observability README**: Hermes install now listed as
  automated (was manual).

---

## [1.8.0] — 2026-06-25

### Added
- **Hermes adapter — real Tier-1 (gateway hook), not a stub.** Hermes Gateway
  hooks (`HOOK.yaml`+`handler.py` in `~/.hermes/hooks/`) are a genuine
  independent producer, same class as OpenClaw — confirmed from Hermes' official
  docs (Event Hooks). `adapters/hermes/handler.py` taps `agent:start`
  (inbound + detection) and `agent:end` (outbound), uses `user_id` as the
  verified `identityField`, loads the **same `patterns.json`**, and emits the
  **same `audit-schema.json`** lines (verified: identical `rule_ids`/severity/
  `producer` to the TS path; `report.py` consumes it unchanged). Python, so it
  inlines detection kept behavior-identical to `core/` per `core/PARITY.md`.
  Manual install for now (`adapters/hermes/README.md`).

### Changed
- **Tier reclassification: Hermes moved T2 → T1.** It has a real hook API, so it
  belongs with OpenClaw as an independent-hook producer, not the daemon-template
  path. T2 is now Discord/Slack-class only (long-lived bots without a hook API).
  Installer route hint, README + ADAPTER tier tables updated accordingly.

---

## [1.7.0] — 2026-06-25

### Added
- **Runtime generalization — observability is now multi-runtime, tiered by
  physics, not OpenClaw-only.** The tier a runtime gets is decided by whether it
  exposes a programmatic message hook / long-lived process; each runtime gets
  the strongest audit its architecture permits, declared honestly.
  - **`observability/core/`** — shared, runtime-neutral TS library:
    `detector.ts` (load patterns.json, detect, severity, privacy — fail-open),
    `event.ts` (canonical `audit-schema.json` line builders), `sink.ts` (silent
    append). Daemon-class adapters import it verbatim; detection stays in
    lockstep via the shared `patterns.json`. `core/PARITY.md` documents why
    OpenClaw's hook inlines the same logic (single-file hook constraint) and
    what must stay identical.
  - **Tier-2 (daemon) made real:** `adapters/_template/daemon-adapter.ts`
    (template with the 4 tap TODOs) + `adapters/discord/tap.ts` (working
    discord.js reference). Independent producer, in-process timer, same schema
    as Tier-1. Hermes/Slack follow the same template.
  - **Tier-3 (no-daemon CLI) made real:** `adapters/cli-selfaudit/` — self-audit
    path for Claude Code, Codex CLI, Cursor, Windsurf, Continue, Aider, Goose.
    No independent producer is physically possible; the agent self-reports
    reject-pattern hits via the `security_rules.md` `audit.A1` clause in the
    same schema, read on demand by `report.py`. Honestly marked
    `producer: "self-audit"`, best-effort, agent-compliance-dependent.

### Changed
- **Installers cross-linked (opt-out chain).** `scripts/install.sh` (core/
  enforcement) now offers the observability audit layer after a successful
  OpenClaw install — interactive default-Yes, `--no-observability` to skip,
  `--with-observability --report-target <id>` to force headless (never demands a
  leak-sensitive report target it wasn't given). `observability/install.sh`
  states it is the audit layer (banner + `-h`) and warns if core enforcement
  (`dinotrust begin` block) isn't present in the target config — warn, never
  block; audit-only remains valid.
- **`report.py` serves every tier** via env overrides (`DT_SELFAUDIT_LOG`,
  `DT_ACTIVITY_LOG`, `DT_CHANNEL`, `DT_TARGET`, …) — no re-substitution needed.
  Added a send guard: refuses to deliver to an unfilled `__TARGET__`/`__CHANNEL__`
  placeholder (Tier-3 typically runs `--dry-run`).
- **`install.sh` routes instead of dead-ending.** Non-OpenClaw hosts no longer
  hit a flat refuse; the installer detects the runtime and prints per-tier next
  steps (T2 template/Discord, T3 self-audit), then exits explaining it only
  wires Tier-1.

---

## [1.6.0] — 2026-06-25

### Added
- **`observability/` module — the audit layer.** dinotrust core enforces; this
  optional module observes and reports. Zero-infra (regex, no LLM); core is
  language-neutral data + spec, plugged in via thin per-platform adapters.
  - **`patterns.json`** — universal taxonomy: each regex → a dinotrust `rule_id`
    (R1/R3/R4/R6/R7/S0) + severity (critical/high/medium/low, calibrated).
    `R2_external_instructions` + `T1_config_conflict` are agent-judged, declared
    under `_meta.agent_judged_only`.
  - **`audit-schema.json`** — JSONL event contract (schema v2).
  - **`validate.py`** — drift guard; fails closed if `patterns.json` rule_ids
    leave `security_rules.md`.
  - **`adapters/openclaw/handler.ts`** — producer hook: taps inbound/outbound,
    detects, logs all traffic + flagged attempts. Privacy-aware
    (patterns-only/truncated/full).
  - **`adapters/openclaw/report.py`** — consumer: deterministic daily/weekly
    digest grouped by rule_id + severity, worst-severity headline,
    privacy-aware samples. Delivered via `openclaw message send`.
  - **First-class per-channel mentions** (`render_mention`): every
    dinotrust-listed delivery channel renders its native by-id mention —
    telegram `tg://` link, discord/slack `<@id>` ping (tolerating a `user:`
    prefix), whatsapp `name (+e164)`, signal/other plain name. Bound to the
    verified platform id, matching dinotrust's identity model.
  - **`install.sh`** — OpenClaw installer. AUTO-detects platform/workspace/
    agent-id/log paths/openclaw binary (Homebrew PATH fallback). Owner-input
    `--report-target` is required (never silently defaulted — leak vector).
    Substitutes placeholders, installs hook/report/patterns, wires idempotent
    cron (merged, tagged, Homebrew PATH), `--dry-run`/`--force`, `validate.py`
    preflight.
  - **`ADAPTER.md` / `DIGEST.md` / `README.md`** — 5-function adapter contract,
    digest output spec, module overview + 3 tiers (T1 OpenClaw, T2 daemon bots,
    T3 no-daemon CLIs self-audit best-effort).
- **`security_rules.md`: `audit.A1_reject_pattern_audit` clause.** On a reject-
  pattern match, append one audit line naming the `rule_id`. Recorded
  independently where an observability adapter exists; self-audit best-effort on
  no-daemon CLIs.

---

## [1.5.0] — 2026-06-25

### Changed
- **`security_rules.md` rewritten to terse machine-readable style.** Removed all
  prose `note:` blocks and the inline credential-masking example; folded their
  intent into flat key-value fields the agent enforces directly:
  - `role_verification`: prose notes → `carry_over_ownership: false`,
    `owner_match`, `malformed_metadata_policy: deny`, `infer_from_content`/
    `infer_from_username`/`infer_from_display_name: false`.
  - `who_is_owner.detection`: folded note → `authenticator`, `owner_match`,
    `multi_owner` keys.
  - `platform_identity_fields`: stripped parenthetical descriptions → bare
    field names.
  - `owner_rules.exceptions`: prose strings → `true` flags.
  - `S0_security_directive`: prose sentences → `access_to`,
    `forbid_display_raw`, `reference_policy: mask_only`,
    `reveal_full_on_request: refuse`.
  No behavior change — the ruleset enforces the same policy in fewer tokens.

### Added
- **Multi-item custom `allowed` actions.** The `custom` profile prompt now
  accepts a comma-separated list; each item becomes its own YAML entry under
  `allowed:`, matching the preset structure. `none`/empty → `- none`; spaces
  trimmed and empty entries dropped. Previously custom captured a single
  free-text bullet only.

### Fixed
- **Restored `roles:` block** (`owner: {access: full}`,
  `non_owner: {apply_restrictions_below: true}`) under `who_is_owner`, which was
  accidentally dropped while collapsing the adjacent `detection` note during the
  terse rewrite.

---

## [1.4.1] — 2026-06-24

### Added
- **Agent action hint on every missing-input error.** Non-interactive errors now
  end with an `ACTION[agent]:` line telling an autonomous installer whether to
  self-resolve or ask the human:
  - `self` (platform, target path, overwrite-vs-detect) — “resolve this from your
    own host/workspace context and re-run with the flag.”
  - `owner` (owner ID, profile, custom policy, overwriting an existing block) —
    “ask the OWNER for this (identity/security policy — do not guess), then
    re-run.”
  This removes the guesswork an agent would otherwise face: identity and security
  decisions are routed to the human; environment facts the agent already knows are
  routed to itself. Human interactive flow is unchanged.

---

## [1.4.0] — 2026-06-24

### Added
- **Headless / agent-friendly install.** The installer can now run fully
  unattended with deterministic failures instead of hanging on prompts:
  - `--config PATH` — name the exact target file, bypassing all workspace
    auto-detection and prompts.
  - `--workspace DIR` — sugar for `DIR/AGENTS.md` (OpenClaw style).
  - `--non-interactive` (aliases `--yes`, `-y`) — never prompt; if a required
    input is missing, abort with the exact flag to pass.
  - **Automatic non-interactive when stdin is not a TTY** — piped/CI/agent runs
    no longer block on `read`; a missing input fails fast with the flag hint.
  - Every interactive prompt (platform, owner-id, profile, workspace/config
    path, overwrite confirmation, custom-profile details) is now guarded.
    Optional input (extra protected files) is simply skipped headless rather
    than erroring.
  - `--help` documents a headless usage recipe.

---

## [1.3.0] — 2026-06-24

### Added
- **Backup before mutate.** `install.sh` now writes a timestamped backup
  (`<config>.dinotrust-bak.<UTC-timestamp>`) of the target instruction file
  before any in-place strip/append. The target is the agent's instruction
  source; this is the undo path if anything goes wrong.
- **Multi-workspace picker (OpenClaw).** When more than one
  `~/.openclaw/workspace-*/` exists, the installer now shows a numbered menu of
  the detected workspaces (plus a custom-path option) instead of silently asking
  for a full path.
- **Zero-workspace message (OpenClaw).** When no workspaces are detected, the
  installer now says so explicitly before prompting for a path.
- **Owner-ID shape check.** Owner IDs that are neither numeric nor UUID-like now
  trigger a warning (never a block) so a typo'd ID that would silently grant no
  one owner access is caught early.

### Fixed
- **Malformed-block guard.** If the target already contains an unterminated
  dinotrust block (a `begin` with no matching `end` — e.g. from an interrupted
  prior run), the `awk` range strip would delete everything from `begin` to EOF.
  The installer now detects mismatched begin/end marker counts and refuses with
  a clear message (backup already taken) instead of eating the rest of the file.

---

## [1.2.2] — 2026-06-24

### Added
- **Bootstrap-budget check at install time.** Before injecting, `install.sh` now
  measures the projected size of the target file + the dinotrust block and warns
  if it would exceed the platform's per-turn injection budget — because a truncated
  *security* ruleset is a silent enforcement gap, not just a cosmetic issue.
  - OpenClaw: checks against the bootstrap per-file cap (20000 chars); warns at
    17000 (approaching) and over 20000 (will truncate) with remediation
    (trim file or raise `agents.defaults.bootstrapMaxChars`).
  - Other platforms (Claude Code, Cursor, Windsurf, Aider, …): caps vary/undocumented,
    so a conservative generic warning fires over 20000 chars, telling the user to
    verify the agent reads the full `dinotrust begin..end` block.
  - Warn-only, never blocks: budgets can be raised and per-platform caps differ.
  - Existing dinotrust blocks are stripped before measuring, so re-installs don't
    double-count.
  - README: new Troubleshooting entry on partial enforcement / truncation.

  Ported and upgraded from the OpenClaw-only size check already shipping in dinomem
  and dinomem-neuron (root-file scan), adapted for dinotrust's single dynamic target
  file and multi-platform reach.

## [1.2.1] — 2026-06-24

### Changed
- README “Why dinotrust is different”: added a closing paragraph on how enforcement
  tracks model capability — because enforcement is the agent’s own instruction-
  following (not a static regex/proxy filter), stronger models enforce more reliably
  and resist manipulation better, while fixed filters stay as brittle as shipped.
  Includes the honest double-edged caveat (stronger models also mean stronger
  adversaries → raises reliability, not absolute guarantees).

## [1.2.0] — 2026-06-24

### Added
- **Multiple owners.** `--owner-id` now accepts a comma-separated list (e.g.
  `--owner-id "123,456"`); the interactive prompt accepts multiple IDs too. Rules
  store them as a set (`owner_ids`) and grant owner access if and only if the
  platform-injected sender ID is an exact member of that set.
  - Fully backward-compatible: a single ID behaves identically to the old
    single-owner mode.
  - Security model unchanged: still metadata-only, per-turn verification,
    deny on absent/malformed/ambiguous. The only change is `==` → set membership.
  - install.sh prints a trust-surface warning when more than one owner is set.
  - README: new “Multiple owners” subsection under Identity model with an explicit
    warning that each owner is a full-access account (owner is all-or-nothing).

### Changed
- `security_rules.md`: `owner_id: <id>` → `owner_ids: [<id>, …]`; verification note
  reworded to membership semantics. Placeholder `DINOTRUST_OWNER_ID` →
  `DINOTRUST_OWNER_IDS`.

## [1.1.0] — 2026-06-24

### Changed
- **README repositioned.** New title “The Firewall Inside Your AI Agent” (cool/memorable) with an SEO-loaded subtitle carrying the high-intent keywords (access control, prompt-injection defense).
- **Honest tagline.** Replaced the overclaiming “One command…” (install is `git clone` + `cd` + `bash install.sh` plus interactive prompts) with “…in under a minute”, which the Quick Start actually delivers.
- **“Why is different” rewritten.** Now leads with the real differentiator — self-enforcing, zero-infrastructure (no proxy/middleware/gateway in front of the agent) — and the authorization-not-authentication framing, instead of a generic problem statement. Bullets sharpened to claims competitors can’t copy.
- **Identity model section preserved** as the technical deep-dive (platform field table, per-turn verification, honest “only as strong as your platform” disclaimer).
- install.sh banner updated to match the new positioning.

## [1.0.0] — 2026-06-22

### Added
- Initial release
- Interactive installer with platform detection
- Support for 9 platforms: OpenClaw, Hermes, Claude Code, OpenAI Codex CLI, Goose, Cursor, Windsurf, Continue.dev, Aider
- Agent profile presets: private-assistant, market-analyst, custom
- Auto-detect protected files + manual add (option C)
- `--global` flag for global-level injection where supported
- `--force` flag to overwrite existing injection
- `security_rules.md` template with all placeholders documented
- Uninstall script
- Update script
