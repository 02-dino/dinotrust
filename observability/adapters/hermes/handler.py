"""
dinotrust observability — Hermes adapter (gateway hook / producer). REAL Tier-1.

Hermes Gateway hooks (HOOK.yaml + handler.py in ~/.hermes/hooks/<name>/) are a
genuine independent producer — exactly like OpenClaw's hook, just Python instead
of TS. So Hermes is Tier-1 (independent), NOT the daemon template path.

This handler is the PLATFORM-BOUND adapter. The detection logic + taxonomy live
in ../../patterns.json and are shared verbatim with every other runtime. Because
Hermes hooks load as a single Python file (like OpenClaw's single-file hook),
the detection mechanics are inlined here — kept behavior-identical to core/
(TS) and report.py (Python) via the shared patterns.json. See ../../core/PARITY.md.

Only the adapter concerns are Hermes-specific:
  1. tap     -> the `agent:start` / `agent:end` gateway events
  2. extract -> context: platform, user_id, session_id, message, response
  3. scope   -> optional DT_AGENT_FILTER against session_id/platform
  identityField = user_id  (Hermes' verified sender id; never inferred from text)

Installer placeholders (filled by install.sh), with env fallbacks so the hook
also works when dropped in by hand:
  __ACTIVITY_LOG__   -> DT_ACTIVITY_LOG
  __JAILBREAK_LOG__  -> DT_JAILBREAK_LOG (a.k.a. self-audit/jailbreak log)
  __PATTERNS_FILE__  -> DT_PATTERNS_FILE
  __PRIVACY__        -> DT_PRIVACY  (patterns-only | truncated | full)
  __AGENT_FILTER__   -> DT_AGENT_FILTER (optional; "" = all)
"""
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

# === FILLED BY install.sh (env overrides win for hand installs) ===
ACTIVITY_LOG = os.environ.get("DT_ACTIVITY_LOG", "__ACTIVITY_LOG__")
JAILBREAK_LOG = os.environ.get("DT_JAILBREAK_LOG", "__JAILBREAK_LOG__")
PATTERNS_FILE = os.environ.get("DT_PATTERNS_FILE", "__PATTERNS_FILE__")
PRIVACY = os.environ.get("DT_PRIVACY", "__PRIVACY__")          # patterns-only|truncated|full
AGENT_FILTER = os.environ.get("DT_AGENT_FILTER", "__AGENT_FILTER__")
# ==================================================================

TRUNCATE_LEN = 200
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Resolve patterns.json next to this handler if the placeholder wasn't filled.
if PATTERNS_FILE.startswith("__"):
    PATTERNS_FILE = str(Path(__file__).resolve().parent / "patterns.json")

_COMPILED = None  # lazy, cached; fail-open (empty) on any error


def _load_patterns():
    global _COMPILED
    if _COMPILED is not None:
        return _COMPILED
    try:
        data = json.loads(Path(PATTERNS_FILE).read_text(encoding="utf-8"))
        pats = data.get("patterns", []) if isinstance(data, dict) else []
        out = []
        for p in pats:
            flags = re.IGNORECASE if "i" in (p.get("flags") or "i") else 0
            out.append((re.compile(p["regex"], flags), p["id"], p["rule_id"], p["severity"]))
        _COMPILED = out
    except Exception:
        _COMPILED = []  # fail open: never disrupt the agent
    return _COMPILED


def _detect(content):
    hits = []
    for rx, pid, rule_id, severity in _load_patterns():
        if rx.search(content):
            hits.append({"id": pid, "rule_id": rule_id, "severity": severity})
    return hits


def _top_severity(hits):
    best, best_rank = "", 0
    for h in hits:
        r = SEV_RANK.get(h["severity"], 0)
        if r > best_rank:
            best_rank, best = r, h["severity"]
    return best or "low"


def _privacy_content(content):
    if PRIVACY == "patterns-only":
        return None
    if PRIVACY == "truncated":
        return content[:TRUNCATE_LEN]
    return content  # full


def _append(path, line):
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass  # silent by contract


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _scope_key(context):
    # Mirror OpenClaw's sessionKey idea: a stable per-agent scope string.
    return f"{context.get('platform', '?')}:{context.get('session_id', '?')}"


def handle(event_type, context):
    """Hermes gateway hook entrypoint (must be named 'handle')."""
    try:
        scope = _scope_key(context)
        if AGENT_FILTER and not AGENT_FILTER.startswith("__") and AGENT_FILTER not in scope:
            return

        if event_type == "agent:start":
            content = str(context.get("message") or "")
            if not content:
                return
            ts = _now_iso()
            user_id = context.get("user_id")
            activity = {
                "direction": "in",
                "timestamp": ts,
                "senderId": user_id,
                "senderName": None,                      # Hermes ctx has no display name here
                "channelId": context.get("platform", "unknown"),
                "isGroup": None,
                "conversationId": context.get("session_id"),
                "sessionKey": scope,
                "messageId": None,
                "content": content,
            }
            hits = _detect(content)
            if hits:
                jb = {
                    "timestamp": ts,
                    "senderId": user_id,
                    "senderName": None,
                    "channelId": context.get("platform", "unknown"),
                    "isGroup": None,
                    "conversationId": context.get("session_id"),
                    "messageId": None,
                    "patterns": [h["id"] for h in hits],
                    "rule_ids": sorted({h["rule_id"] for h in hits}),
                    "severity": _top_severity(hits),
                    "hits": hits,
                    "content": _privacy_content(content),
                    "producer": "code-hook",
                }
                _append(JAILBREAK_LOG, json.dumps(jb))
            _append(ACTIVITY_LOG, json.dumps(activity))

        elif event_type == "agent:end":
            response = str(context.get("response") or "")
            if not response:
                return
            out = {
                "direction": "out",
                "timestamp": _now_iso(),
                "channelId": context.get("platform", "unknown"),
                "to": context.get("user_id"),
                "sessionKey": scope,
                "content": response,
                "success": True,
            }
            _append(ACTIVITY_LOG, json.dumps(out))
    except Exception:
        # Absolute backstop: a hook must never crash the agent.
        pass
