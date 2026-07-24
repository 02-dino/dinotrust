---
name: dinotrust-degraded-alert
description: "On every agent bootstrap, if dinotrust-enforce previously FAILED OPEN (wrote a DEGRADED marker), inject a short plain-language warning into the OWNER's next turn — then auto-clear the marker once enforcement recovers. Turns the silent-fail-open + read-a-file-and-rm-it pattern into a self-surfacing, self-clearing owner alert. A non-technical owner never has to know the marker file exists."
metadata:
  { "openclaw": { "emoji": "⚠️", "events": ["agent:bootstrap"], "requires": { "bins": [] } } }
---
# dinotrust-degraded-alert

Auto-surfacing companion to the `dinotrust-enforce` plugin's DEGRADED state.

## Why

`dinotrust-enforce` fails OPEN on any internal error (an enforcement bug must
never brick the tool loop). It records that as a durable `*-DEGRADED.json` marker
+ a loud `evt:DEGRADED` audit line. But a marker on disk that the owner has to
*know exists*, go *read*, and manually `rm` to clear is exactly the not-noob-
friendly pattern dinotrust is trying to remove. A non-technical owner should
never touch a file.

## What it does

On **every** `agent:bootstrap`:

1. Read the DEGRADED marker (default `~/.openclaw/logs/dinotrust-enforce-DEGRADED.json`;
   override via `DINOTRUST_DEGRADED_MARKER` / `DINOTRUST_LOG_FILE`).
2. **Recovered?** If the audit log shows a healthy verdict strictly *after* the
   marker's `lastSeen` (and the fault is older than a 5-min quiet window),
   enforcement has recovered → **auto-clear the marker, stay silent.** A
   transient blip that already healed never bothers the owner.
3. **Still degraded + requester is the OWNER?** Inject a short **plain-language**
   instruction into the bootstrap context telling the model to warn the owner in
   their own words (no file paths, no error codes, no "delete this file"), then
   answer normally. Only surfaces to the owner (owner-id match), never to other
   senders.
4. **Still degraded + non-owner?** Stay silent (this is an operator alert).

Conservative: when recovery can't be *proven* (no newer verdict than the fault),
it **warns** — better a stale warning than a silently-hidden bypass window.

## Fail-safe

Every path is wrapped; any error is swallowed. This hook MUST NEVER break
bootstrap. Zero-op when there's no marker.

## Env

- `DINOTRUST_OWNER_IDS` — comma/space list; default `1083618205` (matches the
  enforce plugin's default owner).
- `DINOTRUST_DEGRADED_MARKER` — explicit marker path override.
- `DINOTRUST_LOG_FILE` — audit log path (marker derived as `<log>-DEGRADED.json`).
