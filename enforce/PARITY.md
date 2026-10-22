# PARITY: policy.ts (core) <-> adapters/openclaw/handler.ts (inline)

The OpenClaw managed-hook adapter loads as ONE self-contained file and cannot
resolve sibling imports at hook-load time, so it INLINES the policy engine.
Any change to the enforcement decision MUST land in BOTH files, and BOTH
selftests must pass (enforce/core/policy.selftest.mjs + adapters/openclaw/selftest.mjs).

## FOUR surfaces, not two (a pattern lives in all of them)

Two-file parity is NOT enough for `criticalExecPatterns`. The same pattern list
is duplicated across FOUR places, and a change that lands in fewer than four
leaves the gate misfiring while the repo looks fixed:

1. `enforce/core/policy.ts`                        -> DEFAULT_POLICY
2. `enforce/adapters/openclaw/handler.ts`           -> inlined DEFAULT_POLICY
3. `enforce/adapters/openclaw/openclaw.plugin.json` -> configSchema default
4. `enforce/adapters/openclaw/selftest.mjs`         -> CRIT_EXEC fixture

Measured failure (2026-10-09): the invocation-anchored teardown-verb pattern was
landed in (1) ONLY. Surfaces (2)(3)(4) kept the loose one-word string, so
`git status` in any repo containing a teardown script stayed fail-closed for
weeks while `policy.ts` read as already fixed. A plain-substring truncate
pattern likewise blocked an unrelated `docker run --auto-trunc*` CLI flag. Both
expired as unconfirmed approval cards -> the commands never ran at all.

Rule: when touching `criticalExecPatterns`, grep ALL FOUR for the old string and
confirm zero remain. A pattern must be anchored to the ACTION (SQL statement
shape; verb in invocation position after `^`/`;`/`&&`, or a package-manager
subcommand), never a bare substring -- a read-only command that merely MENTIONS
a destructive word must pass, or the gate fails closed on safe work and trains
the operator to ignore it.

## Shared contract (keep byte-parallel)
- TrustedEntry fields: id, allowedTools, allowedScripts, scopePathGlobs, scopeAgents
- findTrusted(senderId, cfg, sessionKey): matches id AND (if set) scopeAgents
  substring-matched against sessionKey (same match as pickAgentOwners keys).
- scopePathGlobs path-confinement fires ONLY for MUTATING tools
  (mutatingTools minus exec: write/edit/apply_patch). read/memory/web carry
  paths but are NOT path-scoped -> cross-agent read collaboration stays open.
  exec is gated by allowedScripts, not path.
- KNOWN GAP (deliberate, 2026-10-22): null-sender handling is NOT byte-parallel.
  policy.ts + handler.ts split a null sender by LANE via isChannelLane() -- null
  on a chat lane means platform metadata was LOST and is never owner; null on a
  cron/explicit/main/subagent lane is the agent operating itself. The
  pre_tool_call adapter CANNOT express this: its stdin contract carries
  session_id but no lane-shaped session key, and the harnesses it serves
  (Claude Code / Codex / Hermes shell hooks) have no multi-party chat lane, so
  null there really is the local operator. If a CHAT-surface harness ever adopts
  pre_tool_call, it MUST pass a lane-shaped key and handler.py's `is_owner` line
  must split too. Measured cost of the lane split being missing on a chat
  surface: every group participant resolves to owner-tier and the trusted /
  non-owner tiers are never consulted at all.
- protectedGlobs / escalation / criticalDoc ALWAYS win over a trusted grant.
- criticalExecPatterns: action-anchored, mirrored across all FOUR surfaces above.
- auditAllowedNonOwnerTools: observability flag, mirrored across all FOUR surfaces
  (policy.ts DEFAULT_POLICY + Cfg, handler.ts inlined DEFAULT_POLICY + Cfg,
  openclaw.plugin.json configSchema, pre_tool_call/handler.py DEFAULTS).
  It changes NO decision -- an allowed non-owner tool stays allowed either way.
  WHY it exists: an allowed non-owner tool returns BEFORE any audit() call, so a
  tool that is itself a security boundary (a scoped peer-memory read handing a
  stranger their own record) leaves zero trace, and "did a non-owner read their
  rep, and when" is unanswerable from logs. Measured on a live box: every allow
  event in the whole log came from the exec-script rule; allowed TOOLS were
  invisible by construction. Default false because this is the hot path.

When you change any of the above here, mirror it in the other file and re-run
both selftests before commit.
