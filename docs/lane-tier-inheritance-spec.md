# dinotrust — Non-Channel Lane Tier Inheritance (spec v0)

Status: **DESIGN ONLY (no code yet).** Grounded against the live box + repo as of 2026-10-28.
Every number below was measured, not inferred; the measurement command is named so it can be re-run.

## The gap (confirmed in code AND by execution)

`index.ts:1578` / `policy.ts` equivalent:

```ts
const agentSelf = sender == null && !isChannelLane(sessionKey);
const isOwner   = agentSelf || (sender != null && owners.includes(sender));
```

`CHANNEL_LANES` (index.ts:1433) holds only the 18 channel names (telegram, whatsapp, signal, ...).
Every other lane shape is "non-channel" → `sender == null` → `agentSelf` → **owner**.

Executed the real predicate (node, 2026-10-28):

```
agent:editor:telegram:group:-100123:topic:5   channelLane=true   -> agentSelf=false
agent:editor:subagent:helper                  channelLane=false  -> agentSelf=true -> isOwner=TRUE
agent:main:subagent:search-helper             channelLane=false  -> agentSelf=true -> isOwner=TRUE
agent:cs:main                                 channelLane=false  -> agentSelf=true -> isOwner=TRUE
```

The comment at index.ts:1427 states the intent plainly: *"A null id on a non-channel lane
(cron/explicit/main/subagent) is the agent operating itself unattended"*. That intent is correct for an
**owner-operated** agent. It is wrong the moment a **trusted** id can cause one of those lanes to exist.

**Consequence:** granting a trusted id the `cron` tool (or `sessions_spawn`) hands them a lane in which
they are owner — past `scopePathGlobs`, past `allowedTools`, past `protectedGlobs` (.env / openclaw.json /
AGENTS.md), past the critical gate.

## Measured ground truth (do NOT re-guess these)

### 1. Real lane shapes

From the live session store (`/root/.openclaw-analyst/agents/analyst/sessions/sessions.json`, 307 keys):

| count | shape | note |
|---|---|---|
| 264 | `agent:analyst:explicit:model-run-<uuid>` | **largest lane by far** |
| 25 | `agent:analyst:telegram:direct:<senderId>` | channel lane, id present |
| 12 | `agent:analyst:cron:<jobId>` | **job id is embedded in the key** |
| 6 | `agent:analyst:subagent:<uuid>` | opaque uuid, no parent reference |

Two findings that shape everything below:

- **The cron lane carries the job id.** At enforcement time the firing job is resolvable by
  `sessionKey.split(':cron:')[1]` — no new lane→job plumbing is required.
- **The subagent lane carries nothing.** Opaque uuid. `grep parentSessionKey|parentSession|spawnedBy|
  originSession` in index.ts = **0 hits**. There is no path from child back to spawner.

### 2. The job record

Schema observed in real snapshots:
`agentId, createdAtMs, delivery, enabled, id, lastDelivered, lastRunAtMs, name, nextRunAtMs, payload,
schedule, sessionTarget, state, status, updatedAtMs, wakeMode`

An **optional `owner` field exists** (it is the "Owner" column in `openclaw cron list`). Measured:
9/9 jobs in the latest snapshot have `owner=None`; across analyst's 22 jobs exactly **one** is populated,
and its value is a **session key** (`agent:analyst:telegra...`), not a sender id.

Partial sufficiency — state it precisely:

- direct lane key → yields an id (`agent:analyst:telegram:direct:1083618205` → `1083618205`), the same
  parse `resolveSenderId` already performs
- group lane key → yields **nothing** (`agent:x:telegram:group:-100...:topic:N`)

Trusted karyawan talk to these agents **from groups**. So `owner` as it stands cannot identify them.

### 3. Payload kinds

Across all job snapshots on this box:

| payload.kind | count | meaning |
|---|---|---|
| `command` | 210 | argv executed as shell |
| `agentTurn` | 143 | LLM turn with a prompt |

`command` is the sharp one: it is arbitrary shell, scheduled, running later in an owner-tier lane.

### 4. Exposure on this box

- tool `cron` already granted to trusted ids: editor 8, modul 4, marketing 2, MAIN/webdev 2 = **16 ids**
- tool `sessions_spawn`: **0** across all 14 gateways
- dinotrust gates `cron` nowhere: `grep '"cron"'` in gate logic = 0 hits
- job census (14 gateways, `openclaw cron list`): **72 jobs total** —
  analyst 22 · sosmed 14 · ads 7 · kttal 7 · cs 4 · event 3 · konsultan 3 · modul 3 · sales 3 ·
  editor 2 · kaka689 2 · marketing 2 · MAIN 0 · extractor 0
- gateways holding BOTH jobs AND cron-granted trusted ids: editor (2), modul (3), marketing (2)
  → only **7 jobs** ever need provenance review
- `/root/.dinotrust/logs/enforce.log`: 8 lines, from July, 0 `subagent` hits
  → **no production evidence of exploitation; this is a code reading plus an executed predicate**

## The reshaping insight: gate CREATION, don't inherit at FIRE

The obvious design is "stamp the job with its creator, resolve that tier when it fires". Measurement 2
shows that road is blocked for exactly the population we care about (group-lane creators).

But a creation-time gate **does not need the stamp at all**:

> At creation the trusted user is on a **channel lane**, so their identity is fully readable and their
> tier fully resolvable. The payload is **static, inspectable data**. Reject at `add`/`update` any job
> whose payload exceeds what that user could have executed directly. A job that survives the gate is,
> by construction, a job its creator was already entitled to run.

The job may then fire in an owner-tier lane without harm, because the capability was bounded when it was
written. **No persistence, no schema change, no migration, no new plumbing.**

Provenance stamping remains desirable for **audit** ("who created job X") — but it is NOT load-bearing
for enforcement, and must not be allowed to block shipping the gate.

### Scope of the creation gate

- MUST cover `add` **and** `update` (otherwise: create a benign job, then mutate its payload)
- MUST cover `payload.kind=command` (argv → the existing exec policy: `execRunsAllowedScript` /
  workspace-scoped token check / critical patterns / protectedGlobs)
- SHOULD cover `payload.kind=agentTurn` — weaker by nature: a prompt is not statically decidable.
  Treat as "the child turn runs at the creator's tier is UNPROVABLE here" → the honest options are
  (a) allow, accepting that an agentTurn job is only as dangerous as the agent's own tool policy, or
  (b) require the creator hold the tools the prompt would plausibly need. **(a) is recommended**;
  (b) is prompt-guessing dressed up as security.
- `delivery` targets are an exfil surface (announce → arbitrary chat/webhook). Gate `delivery.to`
  against the same rules as a message send for that tier.

## Subagent: the hard half — do NOT pretend it is solved

The creation gate does not transfer. The child is an autonomous LLM: the brief can read harmless and the
execution not be. And measurement 1 shows there is no parent→child linkage to inherit through.

Candidate mechanisms, with honest costs:

| option | mechanism | cost / failure mode |
|---|---|---|
| A | in-memory map at spawn: hook sees `sessions_spawn` from a trusted sender, records `childKey → tier` | hook may not observe the generated child key; map dies on gateway restart → silent fail-OPEN |
| B | keep `sessions_spawn` denied for trusted (**status quo**) | zero new risk, zero new capability; the ask stays unmet |
| C | treat any `subagent` lane as non-owner unless a positive owner stamp exists | fail-CLOSED and sound, but breaks owner-initiated subagents unless the stamp lands first |

**Recommendation: ship cron first, keep B for subagent**, and only revisit once an owner-stamp mechanism
exists that C can stand on. Shipping A without solving the restart case would create a security control
that silently stops existing — worse than the honest denial of B.

## The `explicit` lane: newly discovered, unresolved

`explicit:model-run-<uuid>` is **264 of 307 keys** on analyst — the largest non-channel lane, and it
inherits owner by the same predicate. It was not part of the original problem statement.

**UNKNOWN (must be measured before any code):** what creates these, and whether a trusted id can cause
one. If they are only ever owner/CLI-initiated, risk is low and they stay out of scope with that reason
recorded. If a trusted id can trigger one, the cron fix is cosmetic while the bigger door stands open.

Do not design for this lane until that is measured.

## Back-compat contract (the ship blocker)

Two **independent** layers, both verified in source:

1. `policy.ts:226` → `trustedIds: []` by default, commented *"empty by default; zero behavior change
   unless an install explicitly grants trust"*. And `index.ts:1581`:
   `const trusted = (!isOwner && sender != null && c.trustedIds.length > 0) ? findTrusted(...) : null;`
   An install with no trusted ids never enters this branch — **the new code cannot run there at all.**
2. The creation gate only fires on `cron` `add`/`update` **by a trusted sender**. Existing jobs are never
   re-evaluated, never rewritten, never migrated. 72 jobs on this box: 0 touched.

To be affected at all, an install must (a) deliberately populate `trustedIds`, (b) grant them tool
`cron`, and (c) have one of them create or edit a job **after** the update.

`normalizeConfig()` already handles older configs (`{...DEFAULT_POLICY, ...raw}` + per-key array
fallback), so a config lacking any new field takes the default rather than throwing.

Follow existing dinotrust precedent — **config flag, default = current behaviour**
(cf. `auditAllowedNonOwnerTools: false`, `ownerSelfApproval: "warn"`, `allowScopedCritical` default OFF).

**Stated openly, not back-compat:** a trusted user who could previously register any job becomes
tier-bounded at creation. Existing jobs keep running; only creation changes. That is the fix, not a
side effect.

## Mandatory selftest cases

| # | case | expected |
|---|---|---|
| 1 | config with **no** trustedIds | verdict byte-identical to pre-patch (the back-compat ship blocker) |
| 2 | owner creates `command` job with critical argv | unchanged from today |
| 3 | trusted creates `command` job with argv **inside** their scope | allow |
| 4 | trusted creates `command` job with argv **outside** their scope | block, reason names the resolved target |
| 5 | trusted creates benign job, then `update`s payload to out-of-scope argv | block (the update bypass) |
| 6 | trusted creates `agentTurn` job | allow per recommendation (a); asserted explicitly so a later change is deliberate |
| 7 | unattended cron fires an existing job (no stamp) | still owner; **still runs** |
| 8 | trusted sets `delivery.to` to an unauthorized target | block |
| 9 | non-owner (not trusted) calls cron | block, as today |

Case 1 and case 7 are the two that make the "other installs are unaffected" claim **evidence** instead of
assertion. Neither may be skipped.

## Two-file sync hazard

`enforce/core/policy.ts` and `enforce/adapters/openclaw/handler.ts` carry mirrored logic, and
`/root/.openclaw/extensions/dinotrust-enforce/index.ts` is the copy that actually runs on this box.
v1.27.0's own notes record this drift trap. Any change here lands in **all three**, and both selftests
(`policy.selftest.mjs`, `adapters/openclaw/selftest.mjs`) must be green before tagging.

## Open questions (blocking implementation)

1. What creates `explicit:model-run-*`, and can a trusted id cause one? (largest lane, unresolved)
2. Can the enforce hook **modify** tool-call params, or only allow/block? Decides whether an audit-only
   provenance stamp is even writable from here. The gate itself does not depend on the answer.
3. Of the 7 jobs on editor/modul/marketing, were any created by a trusted id? (~10 min audit; affects
   nothing in the design, only what we tell the owner about existing state)
