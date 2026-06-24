# Changelog

All notable changes to dinotrust are documented here.

---

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
