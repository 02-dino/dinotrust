# PARITY: policy.ts (core) <-> adapters/openclaw/handler.ts (inline)

The OpenClaw managed-hook adapter loads as ONE self-contained file and cannot
resolve sibling imports at hook-load time, so it INLINES the policy engine.
Any change to the enforcement decision MUST land in BOTH files, and BOTH
selftests must pass (enforce/core/policy.selftest.mjs + adapters/openclaw/selftest.mjs).

## Shared contract (keep byte-parallel)
- TrustedEntry fields: id, allowedTools, allowedScripts, scopePathGlobs, scopeAgents
- findTrusted(senderId, cfg, sessionKey): matches id AND (if set) scopeAgents
  substring-matched against sessionKey (same match as pickAgentOwners keys).
- scopePathGlobs path-confinement fires ONLY for MUTATING tools
  (mutatingTools minus exec: write/edit/apply_patch). read/memory/web carry
  paths but are NOT path-scoped -> cross-agent read collaboration stays open.
  exec is gated by allowedScripts, not path.
- protectedGlobs / escalation / criticalDoc ALWAYS win over a trusted grant.

When you change any of the above here, mirror it in the other file and re-run
both selftests before commit.
