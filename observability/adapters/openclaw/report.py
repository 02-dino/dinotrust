#!/usr/bin/env python3
"""
dinotrust observability — OpenClaw adapter (report / consumer).

NO LLM. Pure parse + format + send. Reads the activity + jailbreak JSONL logs
written by handler.ts, builds a deterministic digest, and delivers it via
`openclaw message send`.

The DIGEST LOGIC (windowing, grouping by rule_id + severity, counts) is the
universal part — identical across every platform. Only delivery + mention
rendering are channel-specific (the adapter's job). Mentions are first-class
for every dinotrust-listed channel: telegram (tg:// link), discord/slack
(native <@id> ping), whatsapp (name +e164), signal (name). See render_mention.

Installer placeholders (filled by install.sh):
  __ACTIVITY_LOG__   absolute path to the activity log
  __JAILBREAK_LOG__  absolute path to the jailbreak log
  __CHANNEL__        e.g. "telegram"
  __TARGET__         chat/channel destination id (owner-supplied, REQUIRED)
  __THREAD_ID__      forum topic/thread id, or empty
  __ACCOUNT__        sending account id, or empty (uses platform default)

Usage:
  report.py --period daily
  report.py --period weekly
  report.py --period daily --dry-run
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.request
import urllib.error
from collections import Counter
from datetime import datetime, timedelta, timezone

# === FILLED BY install.sh ===
ACTIVITY_LOG = "__ACTIVITY_LOG__"
JAILBREAK_LOG = "__JAILBREAK_LOG__"
CHANNEL = "__CHANNEL__"
TARGET = "__TARGET__"
THREAD_ID = "__THREAD_ID__"   # may be empty
ACCOUNT = "__ACCOUNT__"       # may be empty
# ============================

# Env overrides — lets one consumer serve every tier without re-substitution.
# Tier-3 (no-daemon CLI self-audit) has no installer; it points the consumer at
# the agent's self-audit log via DT_SELFAUDIT_LOG (mapped onto JAILBREAK_LOG).
# Tier-2 daemons may set these from their own env. Unset -> installed defaults.
ACTIVITY_LOG = os.environ.get("DT_ACTIVITY_LOG", ACTIVITY_LOG)
JAILBREAK_LOG = os.environ.get("DT_SELFAUDIT_LOG", os.environ.get("DT_JAILBREAK_LOG", JAILBREAK_LOG))
CHANNEL = os.environ.get("DT_CHANNEL", CHANNEL)
TARGET = os.environ.get("DT_TARGET", TARGET)
THREAD_ID = os.environ.get("DT_THREAD_ID", THREAD_ID)
ACCOUNT = os.environ.get("DT_ACCOUNT", ACCOUNT)


def resolve_openclaw():
    """Find the openclaw binary. cron PATH often lacks Homebrew bin."""
    found = shutil.which("openclaw")
    if found:
        return found
    for cand in (
        "/home/linuxbrew/.linuxbrew/bin/openclaw",
        "/opt/homebrew/bin/openclaw",
        "/usr/local/bin/openclaw",
    ):
        if os.path.exists(cand):
            return cand
    return "openclaw"  # last resort; raises if truly missing


def render_mention(name, sender_id):
    """Per-channel sender mention. First-class for every dinotrust-listed
    delivery channel; each uses that platform's native by-id mention syntax
    where one exists in a plain text send, else a clean plain-name fallback.

    The log carries the platform's verified id (no @username), so id-based
    forms are the reliable path — matching dinotrust's identity model
    (attribution bound to the platform id, never to a chat-claimed handle).

      telegram : [name](tg://user?id=<numeric>)   Markdown inline link
      discord  : <@<numeric>>                       native ping
      slack    : <@<UID>>                            native ping (U/W ids)
      whatsapp : name (+<e164>)                      no inline-id mention in text
      signal   : name                               no inline-id mention in text
      <other>  : name                               safe generic fallback
    """
    safe = str(name).replace("[", "").replace("]", "").replace("<", "").replace(">", "").strip() or "user"
    sid = str(sender_id).strip()
    ch = (CHANNEL or "").lower()

    if not sid or sid == "unknown":
        return safe

    if ch == "telegram":
        return f"[{safe}](tg://user?id={sid})" if sid.isdigit() else safe
    if ch == "discord":
        # senderId may arrive bare (123) or prefixed (user:123) per --target shape.
        did = sid.split(":", 1)[1] if sid.startswith("user:") else sid
        return f"<@{did}>" if did.isdigit() else safe
    if ch == "slack":
        # Slack user ids start with U or W; tolerate a user: prefix.
        uid = sid.split(":", 1)[1] if sid.startswith("user:") else sid
        return f"<@{uid}>" if (uid[:1] in ("U", "W") and uid[1:].isalnum()) else safe
    if ch == "whatsapp":
        # No inline id-mention in a plain text body; show e164 for traceability.
        e164 = sid if sid.startswith("+") else ("+" + sid if sid.isdigit() else "")
        return f"{safe} ({e164})" if e164 else safe
    if ch == "signal":
        # Signal sender is a UUID; no text-body mention form. Plain name.
        return safe
    return safe


def load_jsonl(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rows.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
    return rows


def parse_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--period", choices=["daily", "weekly"], default="daily")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--output", dest="output_path", help="Write digest to file path (instead of sending)")
    ap.add_argument("--webhook-url", dest="webhook_url", help="POST digest to a Discord/Slack webhook URL")
    args = ap.parse_args()

    now = datetime.now(timezone.utc)
    if args.period == "daily":
        since = now - timedelta(days=1)
        label = "Daily"
    else:
        since = now - timedelta(days=7)
        label = "Weekly"

    activity = load_jsonl(ACTIVITY_LOG)
    jailbreaks = load_jsonl(JAILBREAK_LOG)

    def in_window(r):
        ts = parse_ts(r.get("timestamp"))
        return ts is not None and ts >= since

    act = [r for r in activity if in_window(r)]
    jb = [r for r in jailbreaks if in_window(r)]

    inbound = [r for r in act if r.get("direction") == "in"]
    outbound = [r for r in act if r.get("direction") == "out"]

    # Skip slash/system noise in user-facing counts (e.g. /new, /status)
    real_in = [
        r for r in inbound
        if not str(r.get("content", "")).strip().startswith("/")
    ]

    # Unique users — keyed by senderId so we can build mention links
    users = Counter(str(r.get("senderId") or "unknown") for r in real_in)
    id_to_name = {}
    for r in real_in:
        sid = str(r.get("senderId") or "unknown")
        id_to_name[sid] = r.get("senderName") or sid

    out_lens = [len(str(r.get("content", ""))) for r in outbound]
    avg_out = round(sum(out_lens) / len(out_lens)) if out_lens else 0
    fails = [r for r in outbound if r.get("success") is False]

    # --- Security breakdown: group by rule_id + severity (schema v2) ---
    SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    SEV_EMOJI = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1", "low": "\u26aa"}
    jb_rules = Counter()
    jb_sev = Counter()
    for r in jb:
        rids = r.get("rule_ids")
        if rids:
            for rid in rids:
                jb_rules[rid] += 1
        else:
            for p in r.get("patterns", []):  # legacy fallback
                jb_rules[p] += 1
        sev = r.get("severity")
        if sev:
            jb_sev[sev] += 1
    jb_users = Counter(str(r.get("senderId") or "unknown") for r in jb)
    jb_id_to_name = {}
    for r in jb:
        sid = str(r.get("senderId") or "unknown")
        jb_id_to_name[sid] = r.get("senderName") or sid
    worst_sev = max(jb_sev, key=lambda s: SEV_RANK.get(s, 0)) if jb_sev else None

    win = since.strftime("%Y-%m-%d %H:%M") + " \u2192 " + now.strftime("%Y-%m-%d %H:%M") + " UTC"

    lines = []
    lines.append(f"\U0001f4ca Security {label} Report")
    lines.append(win)
    lines.append("")
    lines.append("\u2014 Activity \u2014")
    lines.append(f"Queries (real): {len(real_in)}  |  Replies: {len(outbound)}")
    lines.append(f"Unique users: {len(users)}")
    if users:
        top = ", ".join(
            f"{render_mention(id_to_name.get(uid, uid), uid)}:{c}"
            for uid, c in users.most_common(5)
        )
        lines.append(f"Top: {top}")
    lines.append(f"Avg reply length: {avg_out} chars")
    if fails:
        lines.append(f"\u26a0\ufe0f Failed sends: {len(fails)}")
    lines.append("")
    lines.append("\u2014 Security (jailbreak / injection) \u2014")
    if not jb:
        lines.append("\u2705 No flagged attempts.")
    else:
        head = f"\U0001f6a8 Flagged attempts: {len(jb)}"
        if worst_sev:
            head += f"  (worst: {SEV_EMOJI.get(worst_sev,'')}{worst_sev})"
        lines.append(head)
        if jb_sev:
            sevline = "  ".join(
                f"{SEV_EMOJI.get(s,'')}{s}:{jb_sev[s]}"
                for s in sorted(jb_sev, key=lambda s: -SEV_RANK.get(s, 0))
            )
            lines.append(f"Severity: {sevline}")
        rl = ", ".join(f"{rid}:{c}" for rid, c in jb_rules.most_common())
        lines.append(f"Rules: {rl}")
        # Outbound secret-egress is the agent's own message leaking a secret-shaped
        # value (verifier for the S0_outbound_self_gate self-redaction clause), not
        # a user attack. Call it out separately so it is not mislabeled by-sender.
        egress = [r for r in jb if r.get("direction") == "out"]
        if egress:
            lines.append(
                f"\U0001f534 Outbound secret-egress: {len(egress)} — "
                "secret-shaped value left the channel despite the S0 self-gate (investigate)"
            )
        usr = ", ".join(
            f"{render_mention(jb_id_to_name.get(uid, uid), uid)}:{c}"
            for uid, c in jb_users.most_common(5)
        )
        lines.append(f"By sender: {usr}")
        # Samples honor the producer's privacy level: 'content' may be null
        # (patterns-only) or truncated. We further gate by severity: only
        # high/critical hits are worth quoting back into a digest that may land
        # in a shared channel. Low/medium are usually keyword false-positives
        # (e.g. someone discussing the ruleset), so echoing their raw content is
        # noise and a needless privacy leak — we show the count, not the text.
        SAMPLE_SEV = {"critical", "high"}
        sample_rows = [
            r for r in jb
            if r.get("content") and r.get("severity") in SAMPLE_SEV
        ]
        if sample_rows:
            lines.append("Samples (high/critical only):")
            for r in sample_rows[:3]:
                who = r.get("senderName") or r.get("senderId") or "?"
                raw = str(r.get("content", "")).replace("\n", " ").strip()
                snip = raw[:120] + ("\u2026" if len(raw) > 120 else "")
                lines.append(f"  \u2022 [{who}] {snip}")

    report = "\n".join(lines)

    if args.dry_run:
        print(report)
        return 0

    # --output path: write to file, no send
    if args.output_path:
        with open(args.output_path, "w", encoding="utf-8") as f:
            f.write(report + "\n")
        print(f"written to {args.output_path}")
        return 0

    # --webhook-url: POST to Discord/Slack webhook
    if args.webhook_url:
        return deliver_webhook(args.webhook_url, report)

    # If no delivery configured (unfilled placeholders), default to stdout
    # instead of failing. This is the T3 self-audit path when the user hasn't
    # set up a target yet — they still see the digest.
    if not TARGET or TARGET.startswith("__") or CHANNEL.startswith("__"):
        print(report)
        sys.stderr.write(
            "\nNote: CHANNEL/TARGET not configured — printed to stdout. "
            "Set DT_CHANNEL/DT_TARGET env vars, or use --output, --webhook-url, "
            "or --dry-run.\n"
        )
        return 0

    cmd = [resolve_openclaw(), "message", "send", "--channel", CHANNEL, "--target", TARGET]
    if ACCOUNT:
        cmd += ["--account", ACCOUNT]
    if THREAD_ID:
        cmd += ["--thread-id", THREAD_ID]
    cmd += ["--message", report]

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "send failed\n")
        return res.returncode
    print("sent")
    return 0


def deliver_webhook(url, text):
    """POST a plain-text digest to a Discord or Slack webhook."""
    # Discord accepts {content: text}; Slack accepts {text: text}
    # Try Discord shape first; if it fails, Slack shape is the fallback
    # on the next run. In practice users know which platform their webhook is.
    payload = json.dumps({"content": text}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status in (200, 204):
                print("webhook sent")
                return 0
            sys.stderr.write(f"webhook returned {resp.status}\n")
            return 1
    except urllib.error.HTTPError as e:
        # Discord webhooks return 204 No Content on success
        if e.code == 204:
            print("webhook sent")
            return 0
        sys.stderr.write(f"webhook failed: {e.code} {e.reason}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"webhook error: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
