# Digest Output Spec

The digest is the human-facing summary the consumer builds from the JSONL logs.
The **grouping logic is universal** (identical across platforms); only delivery
and mention rendering are adapter-specific. This documents the reference
OpenClaw/Telegram render (`adapters/openclaw/report.py`).

---

## Inputs

- `ACTIVITY_LOG` — all traffic (in + out), ops telemetry.
- `JAILBREAK_LOG` — flagged injection events only (`audit-schema.json`, v2).

Both are JSONL. Malformed lines are skipped, not fatal.

## Windowing

`--period daily` → last 24h. `--period weekly` → last 7 days. Events are kept if
their `timestamp` parses and is `>= since`. The window header is rendered in
UTC: `YYYY-MM-DD HH:MM → YYYY-MM-DD HH:MM UTC`.

---

## Sections

### 1. Activity

- **Queries (real):** inbound messages, excluding slash/system noise (anything
  whose content starts with `/`, e.g. `/new`, `/status`).
- **Replies:** outbound count.
- **Unique users:** distinct `senderId`.
- **Top:** up to 5 most active senders as `mention:count` (mentions via
  `renderMention` — first-class per channel, see below).
- **Avg reply length:** mean outbound content length in chars.
- **Failed sends:** count of outbound rows with `success == false` (only shown
  if > 0).

### 2. Security (jailbreak / injection)

If no flagged events in window: `✅ No flagged attempts.`

Otherwise:

- **Flagged attempts:** total count, plus the **worst severity** seen.
- **Severity:** per-tier counts, ordered critical → low, each with its emoji
  (🔴 critical, 🟠 high, 🟡 medium, ⚪ low).
- **Rules:** counts grouped by `rule_id` (R1/R3/R4/R6/R7/S0), most-common first.
  Falls back to legacy `patterns` field if `rule_ids` absent.
- **By sender:** up to 5 flagged senders as `mention:count`.
- **Samples:** up to 3 example snippets — **only if `content` is present**.

---

## Grouping keys (universal)

| Key | Source field | Use |
|-----|--------------|-----|
| `rule_id` | `rule_ids[]` (v2) / `patterns[]` (legacy) | Rule breakdown |
| `severity` | `severity` | Severity tally + worst-severity headline |
| `senderId` | `senderId` | Unique users, by-sender, mention links |
| `direction` | `direction` (`in`/`out`) | Activity split |

Severity rank: `critical=4, high=3, medium=2, low=1`. Worst-severity =
max rank present.

---

## Mentions (per-channel, first-class)

`renderMention` uses each platform's native by-id mention form — bound to the
verified platform id (never a chat-claimed handle), matching dinotrust's
identity model. The id arrives bare or with a `user:` prefix; both are handled.

| Channel | Render | Notes |
|---------|--------|-------|
| `telegram` | `[name](tg://user?id=<id>)` | Markdown inline link; numeric id. |
| `discord` | `<@<id>>` | Native ping; numeric id (strips `user:`). |
| `slack` | `<@<UID>>` | Native ping; ids start `U`/`W` (strips `user:`). |
| `whatsapp` | `name (+<e164>)` | No inline id-mention in text; shows e164 for traceability. |
| `signal` | `name` | Sender is a UUID; no text-body mention form. |
| *(other)* | `name` | Safe generic fallback. |

OpenClaw's channel adapter applies the correct parse mode per channel, so the
Telegram/Discord/Slack forms render as real mentions (no `--parse-mode` flag
needed). Names are sanitized (`[`, `]`, `<`, `>` stripped). Unknown/empty id →
plain name.

---

## Privacy interaction

Samples honor the **producer's** privacy mode (set at install via `--privacy`):

- `patterns-only` *(default, safest)* — `content` is `null`; **no samples
  render**. The digest still shows full counts/rules/severity/senders.
- `truncated` — `content` is capped (~200 chars at the producer); samples show a
  ≤120-char snippet.
- `full` — raw `content`; samples show a ≤120-char snippet.

The consumer renders only what the producer wrote — it never reconstructs
content the producer withheld. Skipping null-content rows is automatic.

---

## Delivery

Reference adapter shells out:

```
openclaw message send --channel <CHANNEL> --target <TARGET> \
  [--account <ACCOUNT>] [--thread-id <THREAD_ID>] --message <report>
```

`--dry-run` prints the report to stdout and sends nothing. Other adapters
replace this `deliver` step with their own channel API; the report text and
grouping are unchanged.
