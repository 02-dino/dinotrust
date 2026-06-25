# Changelog

All notable changes to dinotrust are documented here.

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
