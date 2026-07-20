# dinotrust — Expiry-Aware Approval Follow-Up (spec v0)

Status: DESIGN ONLY (no code yet). Grounded against the real repo/dist as of 2026-07-21.

## The gap (confirmed in code)
- Enforce hook returns `requireApproval` on owner critical/irreversible actions
  (handler.ts ~L326). OpenClaw shows the card.
- If the card expires and the owner replies `/approve` late, OpenClaw's
  `waitDecision` throws `"approval expired or not found"` → handler returns
  `null` (dist `bash-tools-CXGuwe7d.js` L154). The late `/approve` is a **silent
  no-op**. User can't distinguish expired-and-ignored vs. ran.
- OpenClaw core owns the null. dinotrust CANNOT revive a dead approval ID.
- Achievable scope: **kill the silent ambiguity + offer fast re-trigger.**
  NOT "revive dead approvals."

## What we can rely on (verified, do NOT re-guess)
1. Hook audit writer: `audit(c, obj)` in handler.ts L124 — appends one JSON line
   `{ts, ...obj}` to `logPath(c)`, wrapped in try/catch (silent by contract).
   Escalation ALREADY emits: `audit(c,{evt:"owner-approval", rule:"R-escalation",
   toolName, sessionKey, sender, hit:esc, enforced:c.enforce})` (handler.ts ~L324),
   emitted BEFORE the `requireApproval` return.
2. `requireApproval` interface fields the hook may set: `title, description,
   severity, timeoutBehavior` ONLY. No timeout, no approvalId passthrough,
   no callback. (Confirmed: openclaw.plugin.json + handler usage.)
   → The hook does NOT currently know the approvalId OpenClaw mints. That id is
     created downstream by OpenClaw AFTER the hook returns. **Design must not
     assume the hook can capture OpenClaw's approvalId.**
3. Observability layer (installed by default, all platforms):
   - Logs: `$HOME/.openclaw/logs/<agent>-activity.log` + `<agent>-jailbreak.log`
     (observability/install.sh L254-256).
   - Report script copied to `$HOME/.openclaw/scripts/<agent>-dinotrust-report.py`
     (L264), delivered via a CRON entry, default schedule `30 10 * * *`
     (install.sh L88 `--schedule`), to `--report-target` over `--report-channel`
     (default telegram).
   - Report delivery already solves "how do we message the owner from cron"
     (report.py uses the openclaw binary; PATH/Homebrew wired at install L300-310).
4. Audit schema (observability/audit-schema.json) is the digest's contract:
   `{timestamp, senderId?, ..., rule_ids[], severity, hits[], producer}`.
   The follow-up state is a SEPARATE file — do NOT overload the audit log shape.

## Hard constraint that reshapes the design
Because the hook cannot see OpenClaw's approvalId, we CANNOT key follow-up state
on the approvalId and we CANNOT deterministically detect "resolved vs expired"
from inside dinotrust. So the honest mechanism is:

- **What the hook CAN record at escalation time:** a "pending intent" =
  `{intentId (our own uuid), tsIssued, command, toolName, sessionKey, sender,
    hit (which pattern), expectExpiresAt = tsIssued + PROMPT_TTL_GUESS}`.
- **What we CANNOT know:** whether the owner approved/denied/expired (that's
  OpenClaw's private approval state, no dinotrust-readable signal).

Therefore resolution has to be inferred from OBSERVABLE downstream facts:
  (a) Did the command run? For exec, the enforce hook fires again on the SAME
      command only if re-triggered — no "it ran" signal exists either.
  → Conclusion: dinotrust has NO reliable "was it resolved" oracle. A naive
    expiry-sweep would send "expired, nothing ran" follow-ups that are FALSE
    whenever the owner actually tapped Allow in time.

## LOCKED DESIGN: A′ — "confirmed-miss only" (noise-free)

The blind-timer Design A below is SUPERSEDED. Key discovery in OpenClaw dist:
when an exec approval is APPROVED, OpenClaw registers an `exec-approval-followup`
runtime handoff and RESUMES the same command in the same session
(`bash-tools.exec-approval-followup-state.ts`; resume prompt
`buildExecApprovalFollowupPrompt` = "An async command the user already approved
has completed"). The resumed exec RE-ENTERS the tool pipeline → dinotrust's
`before_tool_call` hook FIRES AGAIN on the identical `{command, sessionKey}`.
That re-fire is the deterministic "it ran" oracle. Timer-guessing is unnecessary.

### A′ mechanism
1. **Escalation** (handler.ts, right after the existing `owner-approval` audit
   emit, before the `requireApproval` return): append a PENDING intent line to
   the pending file: `{intentId(uuid), tsIssued, command(privacy-capped),
   toolName, sessionKey, sender, hit, severity:"critical"}`.
   A stable fingerprint `fp = sha1(toolName + "\u0000" + command + "\u0000" +
   sessionKey)` is stored so the re-fire can match without OpenClaw's approvalId.
2. **Re-fire = resolution** (same hook, on EVERY before_tool_call, BEFORE the
   escalation check): compute `fp` for the current call; if a PENDING intent with
   the same `fp` exists AND was issued within RESOLVE_WINDOW (default 1800s = the
   real DEFAULT_EXEC_APPROVAL_TIMEOUT_MS), mark it RESOLVED (`resolvedAt`) and DO
   NOT re-escalate that resumed run (return allow) — otherwise we'd loop: escalate
   → approve → resume → escalate again forever. This is the critical correctness
   point: **the resume must be recognized and passed through**, both to record
   resolution AND to avoid an approval loop.
3. **Sweep** (cron): any PENDING intent with no `resolvedAt` and
   `now > tsIssued + NUDGE_AFTER` (default 200s, just past the ~120s card window)
   → send ONE owner reminder, set `nudgedAt`. GC lines older than RESOLVE_WINDOW.

### A′ correctness / edge cases
- **Approved in time** → resume re-fires → RESOLVED marker → sweep skips. No ping.
- **Expired/missed** → no resume → no marker → sweep nudges once. Correct.
- **Same command twice legitimately** in one session inside the window → the
  second (non-approval) run could get matched as the "resume" and mark the intent
  resolved off the wrong fire. FAILS SAFE (suppresses a nudge, never a false
  alarm). Acceptable.
- **Loop guard is mandatory**: without step-2 pass-through, the resumed approved
  command would trip escalationHit again → infinite approval prompts. The fp match
  within window is exactly what breaks the loop.
- **Non-exec (write/edit) escalations**: openclaw.json/.env writes. If those
  resume through the hook, same fp logic applies. If a given tool doesn't resume
  through before_tool_call, it simply never gets a marker → nudge fires → correct
  ("did that write go through?"). Safe either way.

---

## (SUPERSEDED) Design A — "Reminder, not verdict" (safe, low-fidelity)
Don't claim expired-vs-ran. Instead, at escalation the hook records the pending
intent + a short human echo. A sweep (cron, every N min) finds intents older than
PROMPT_TTL that have NOT been manually cleared, and sends ONE gentle nudge:
  "⏱ A critical action was requested ~<age> ago: `<cmd>`. If your approval card
   already expired and nothing happened, reply/re-run to trigger it again."
- Phrasing is TRUE in both cases (ran OR expired) — it's a reminder, not a false
  "nothing ran" claim.
- Owner self-clears by reacting/replying (or it auto-expires from the state file
  after M minutes so it fires at most once).
- Zero core changes, zero false "it failed" alarms. Honest about uncertainty.
- Cost: can nudge even when the owner DID approve (mild noise). Mitigate: only
  nudge for `severity:critical` + rate-limit 1/intent + suppress if any newer
  activity-log line for the same sessionKey appeared after tsIssued (weak
  "probably resolved" heuristic).

### Design B — "Wait for the upstream signal" (defer)
Do nothing dinotrust-side until the OpenClaw core issue lands (waitDecision on
expired id emits a visible "expired, not run"). Then dinotrust needs nothing —
core does the right thing. Lowest effort, correct, but delivers nothing now.

## Recommendation
Design A, `severity:critical` only, with the "newer activity line = probably
resolved, suppress" heuristic, rate-limited to one nudge per intent, auto-expiring
state. Framed as a REMINDER (true regardless of outcome), never a false verdict.
Ship the OpenClaw core issue in parallel as the real fix; retire Design A's sweep
once core emits the visible expired message.

## State file (Design A)
Path: `$HOME/.openclaw/logs/<agent>-pending-approvals.jsonl` (sibling of activity
log, same dir the report cron already has access to).
Line schema (NEW, distinct from audit-schema.json):
```
{ "intentId": "<uuid>", "tsIssued": "<iso>", "command": "<cmd string, privacy-capped>",
  "toolName": "exec|write|edit", "sessionKey": "<key>", "sender": "<id|self>",
  "hit": "<pattern>", "severity": "critical",
  "promptTtlSec": <int>, "nudgedAt": null, "clearedAt": null }
```
Privacy: honor observability `--privacy` (patterns-only omits `command`, truncated
caps it). Reuse the existing privacy knob; don't invent a new one.

## Sweep (Design A)
- New script `observability/adapters/openclaw/approval-followup.py`, installed to
  `$HOME/.openclaw/scripts/<agent>-dinotrust-approval-followup.py`.
- Separate cron (e.g. every 5 min) — NOT the daily digest cron; different cadence.
- Logic: read pending file; for each line where `nudgedAt==null && clearedAt==null
  && now > tsIssued+promptTtlSec`: apply "newer activity line for sessionKey"
  suppression; else send reminder via same delivery path report.py uses; set
  `nudgedAt`. Drop lines older than M minutes (GC).

## Open questions to resolve BEFORE code
1. PROMPT_TTL guess: what's the real card TTL to time the nudge against? The card
   said 120s but that's the plugin-approval prompt window; confirm the actual
   value dinotrust should assume (or make it an install flag defaulting ~180s).
2. Is the mild "nudge even when approved" noise acceptable to Dino? If not,
   Design B (defer to core) is the honest choice — because dinotrust genuinely
   cannot know resolution state.
3. Install surface: new `--approval-followup` opt-in flag on observability
   install (default off? on?), plus its own cron cadence flag.

## What this is NOT
- Not reviving expired approvals (core-owned dead id).
- Not overloading the audit-schema.json digest shape.
- Not assuming the hook can read OpenClaw's approvalId (it can't).
