#!/usr/bin/env python3
"""
dinotrust observability — approval follow-up sweep (OpenClaw adapter).

Part of Design A′ ("confirmed-miss only"). Companion to report.py.

NO LLM. Pure parse + format + send. Reads the pending-approvals JSONL written
by the enforce hook (handler.ts). For each escalation the hook records a
PENDING line; when the owner APPROVES, OpenClaw resumes the same command, the
hook re-fires and appends a RESOLVED line. This sweep sends ONE owner reminder
ONLY for pending intents that were never resolved and whose card window has
elapsed — i.e. genuine misses. Approved-in-time escalations are resolved by the
re-fire marker and produce NO nudge (no false pings).

State file (append-only JSONL, last-writer-wins on read):
  { "kind": "pending",  "intentId", "fp", "tsIssued", "command",
    "toolName", "sessionKey", "sender", "hit", "severity" }
  { "kind": "resolved", "intentId", "fp", "resolvedAt" }
  { "kind": "nudged",   "intentId", "nudgedAt" }   <- written by THIS sweep

Idempotency: a "nudged" line is appended after a reminder is sent, so the same
intent is never nudged twice. GC drops lines older than GC_AFTER_SEC.

Installer placeholders (filled by install.sh):
  __PENDING_LOG__   absolute path to the pending-approvals JSONL
  __CHANNEL__       e.g. "telegram"
  __TARGET__        owner chat/channel destination id (REQUIRED)
  __THREAD_ID__     forum topic/thread id, or empty
  __ACCOUNT__       sending account id, or empty (uses platform default)

Timing:
  __NUDGE_AFTER_SEC__  seconds after tsIssued before a miss is nudged (default 200)
  __GC_AFTER_SEC__     seconds after tsIssued before a line is GC'd (default 1800)

Usage:
  approval-followup.py            # sweep + send
  approval-followup.py --dry-run  # print what would be sent, no send, no state write
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

# === FILLED BY install.sh ===
PENDING_LOG = "__PENDING_LOG__"
CHANNEL = "__CHANNEL__"
TARGET = "__TARGET__"
THREAD_ID = "__THREAD_ID__"   # may be empty
ACCOUNT = "__ACCOUNT__"       # may be empty
NUDGE_AFTER_SEC = int("__NUDGE_AFTER_SEC__") if "__NUDGE_AFTER_SEC__".isdigit() else 200
GC_AFTER_SEC = int("__GC_AFTER_SEC__") if "__GC_AFTER_SEC__".isdigit() else 1800
# ============================

# Env overrides — same pattern as report.py, so one consumer serves any tier
# without re-substitution and tests can point at a throwaway file.
PENDING_LOG = os.environ.get("DT_PENDING_LOG", PENDING_LOG)
CHANNEL = os.environ.get("DT_CHANNEL", CHANNEL)
TARGET = os.environ.get("DT_TARGET", TARGET)
THREAD_ID = os.environ.get("DT_THREAD_ID", THREAD_ID)
ACCOUNT = os.environ.get("DT_ACCOUNT", ACCOUNT)
NUDGE_AFTER_SEC = int(os.environ.get("DT_NUDGE_AFTER_SEC", NUDGE_AFTER_SEC))
GC_AFTER_SEC = int(os.environ.get("DT_GC_AFTER_SEC", GC_AFTER_SEC))


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


def parse_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def load_lines(path):
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


def compute_state(rows):
    """Fold the append-only log into per-intent state.

    Returns (pending_by_id, resolved_ids, nudged_ids). A pending intent is an
    unresolved, un-nudged miss iff its id is in pending_by_id but NOT in
    resolved_ids or nudged_ids.
    """
    pending_by_id = {}
    resolved_ids = set()
    nudged_ids = set()
    for o in rows:
        kind = o.get("kind")
        iid = o.get("intentId")
        if not iid:
            continue
        if kind == "pending":
            pending_by_id[iid] = o
        elif kind == "resolved":
            resolved_ids.add(iid)
        elif kind == "nudged":
            nudged_ids.add(iid)
    return pending_by_id, resolved_ids, nudged_ids


def render_reminder(intent):
    """One owner reminder for a genuinely-missed critical approval.

    Phrasing is a REMINDER, honest about the achievable scope: dinotrust cannot
    revive the dead approval id (OpenClaw core owns that), so the actionable
    ask is 're-trigger'. No false 'nothing ran' verdict — the resolved-marker
    path already filtered out the approved-in-time case, so reaching here means
    the command provably did NOT resume.
    """
    cmd = str(intent.get("command", "")).strip() or "(command not recorded)"
    if len(cmd) > 200:
        cmd = cmd[:200] + "\u2026"
    hit = str(intent.get("hit", "")).strip()
    ts = intent.get("tsIssued", "")
    lines = [
        "\u23f1\ufe0f dinotrust — approval expired, nothing ran",
        "",
        f"A critical action was flagged and its approval card was never confirmed:",
        f"  \u2022 {cmd}",
    ]
    if hit:
        lines.append(f"  \u2022 reason: {hit}")
    if ts:
        lines.append(f"  \u2022 requested: {ts}")
    lines += [
        "",
        "The approval window elapsed with no confirmation, so the command did NOT run. "
        "Approving now won't revive it (the request id is gone) — re-trigger the action "
        "to get a fresh approval card.",
    ]
    return "\n".join(lines)


def send(report):
    if not TARGET or TARGET.startswith("__") or CHANNEL.startswith("__"):
        print(report)
        sys.stderr.write(
            "\nNote: CHANNEL/TARGET not configured — printed to stdout. "
            "Set DT_CHANNEL/DT_TARGET env vars or use --dry-run.\n"
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
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would be sent; no send, no state write")
    args = ap.parse_args()

    now = datetime.now(timezone.utc)
    rows = load_lines(PENDING_LOG)
    pending_by_id, resolved_ids, nudged_ids = compute_state(rows)

    to_nudge = []
    for iid, intent in pending_by_id.items():
        if iid in resolved_ids or iid in nudged_ids:
            continue  # approved-in-time (resolved) or already reminded
        ts = parse_ts(intent.get("tsIssued"))
        if ts is None:
            continue
        age = (now - ts).total_seconds()
        if age < NUDGE_AFTER_SEC:
            continue  # card may still be live; too early to call it a miss
        if age > GC_AFTER_SEC:
            continue  # too old to be actionable; will be GC'd below
        to_nudge.append((iid, intent))

    sent_ids = []
    for iid, intent in to_nudge:
        report = render_reminder(intent)
        if args.dry_run:
            print("--- would nudge ---")
            print(report)
            print()
            continue
        rc = send(report)
        if rc == 0:
            sent_ids.append(iid)
        else:
            sys.stderr.write(f"nudge send failed for {iid} (rc={rc})\n")

    # Append 'nudged' markers for successfully sent reminders (idempotency), and
    # GC lines older than GC_AFTER_SEC by rewriting the file without them. Both
    # skipped in dry-run so a dry-run never mutates state.
    if not args.dry_run:
        try:
            # append nudged markers
            if sent_ids:
                with open(PENDING_LOG, "a", encoding="utf-8") as f:
                    for iid in sent_ids:
                        f.write(json.dumps({
                            "kind": "nudged", "intentId": iid,
                            "nudgedAt": now.isoformat(),
                        }) + "\n")
            # GC: keep only lines whose linked intent is younger than GC_AFTER_SEC.
            # A resolved/nudged line is kept iff its intent is still kept, so
            # state stays consistent. Reload after the append so markers persist.
            rows2 = load_lines(PENDING_LOG)
            pby, _, _ = compute_state(rows2)
            keep_ids = set()
            for iid, intent in pby.items():
                ts = parse_ts(intent.get("tsIssued"))
                if ts is None:
                    keep_ids.add(iid)  # can't age it -> don't drop
                    continue
                if (now - ts).total_seconds() <= GC_AFTER_SEC:
                    keep_ids.add(iid)
            kept = [o for o in rows2 if o.get("intentId") in keep_ids]
            if len(kept) != len(rows2):
                tmp = PENDING_LOG + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    for o in kept:
                        f.write(json.dumps(o) + "\n")
                os.replace(tmp, PENDING_LOG)
        except OSError as e:
            sys.stderr.write(f"state update failed: {e}\n")

    if args.dry_run:
        print(f"[dry-run] {len(to_nudge)} intent(s) would be nudged")
    else:
        print(f"nudged {len(sent_ids)}/{len(to_nudge)} intent(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
