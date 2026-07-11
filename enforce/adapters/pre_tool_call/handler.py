#!/usr/bin/env python3
"""
dinotrust enforce — pre_tool_call handler (Hermes / Claude Code / Codex CLI).

These runtimes share the same enforcement contract: before a tool runs the
runtime invokes a hook process with a JSON event on stdin and reads a JSON
verdict on stdout. This one handler serves all three.

CONTRACT (verified from Hermes source agent/shell_hooks.py + Claude Code /
Codex pre_tool_call docs):

  stdin  : {"hook_event_name": "pre_tool_call"|"PreToolUse",
            "tool_name": "...", "tool_input": {...},
            "session_id": "...", "cwd": "...",
            "sender_id": "..."|null}          # sender_id: platform-injected id
  stdout : {} | {"decision": "block", "reason": "..."}
                | {"decision": "ask",   "reason": "..."}   # are-you-sure (owner critical)
  exit   : 0 always (verdict is in stdout; non-zero is treated as error/fail-open)

POLICY == enforce/core/policy.ts (parity). This file inlines the same logic so
it has no JS dependency. Config comes from $DT_ENFORCE_CONFIG (JSON path) or
~/.dinotrust/enforce.json; missing keys fall back to safe defaults.

Fail-open by contract: any error -> emit {} (allow) so an enforcement bug never
bricks the agent. The instruction layer (security_rules.md) still applies.
"""
import json
import os
import re
import sys

DEFAULTS = {
    "ownerIds": [],
    "ownerWarnOnly": True,
    "criticalExecPatterns": [
        r"rm\s+-rf", r"git\s+push.*--force", r"git\s+push.*-f\b", r"\bDROP\s+TABLE",
        r"\bTRUNCATE\b", r"mkfs", r"dd\s+if=", r"uninstall", r"--hard\b",
    ],
    # Owner write/edit/exec-write here -> approval (privilege-escalation / brick risk).
    "escalationPathGlobs": ["**/openclaw.json", "**/.env"],
    # Owner write/edit here -> warn only (reversible security docs; git+backups).
    "criticalPathGlobs": ["**/security_rules.md", "**/AGENTS.md"],
    "protectedGlobs": [
        "**/.env", "**/.env.*", "**/*.pem", "**/id_rsa", "**/id_ed25519",
        "**/credentials", "**/secrets/**",
    ],
    "mutatingTools": ["exec", "write", "edit", "apply_patch",
                      "Bash", "Write", "Edit", "MultiEdit", "NotebookEdit"],
    "nonOwnerAllowedTools": ["read", "web_search", "web_fetch", "browser",
                             "memory_search", "memory_get",
                             "Read", "WebSearch", "WebFetch", "Grep", "Glob"],
    "nonOwnerAllowedScripts": [],
    # Trusted/delegated ids: per-individual tier ABOVE non-owner, BELOW owner.
    # Empty by default -> zero behavior change for every existing install.
    # Each entry: {"id": "...", "allowedTools": [...]?, "allowedScripts": [...]?,
    # "scopePathGlobs": [...]?}. See policy.ts TrustedEntry doc for the full
    # ceiling rules (protectedGlobs + escalation/doc hits always win, no per-entry override).
    "trustedIds": [],
    "enforce": True,
}

# Broader-than-non-owner default tool set for a trusted entry with no explicit allowedTools.
DEFAULT_TRUSTED_TOOLS = [
    "read", "write", "edit", "apply_patch", "exec",
    "web_search", "web_fetch", "browser", "memory_search", "memory_get",
    "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Bash",
    "WebSearch", "WebFetch", "Grep", "Glob",
]

# tool-name normalization: map runtime-native tool names to canonical roles.
EXEC_TOOLS = {"exec", "Bash", "shell", "run_command"}
WRITE_TOOLS = {"write", "edit", "apply_patch", "Write", "Edit", "MultiEdit", "NotebookEdit"}


def load_config():
    path = os.environ.get("DT_ENFORCE_CONFIG") or os.path.expanduser("~/.dinotrust/enforce.json")
    cfg = dict(DEFAULTS)
    try:
        if os.path.isfile(path):
            with open(path) as f:
                user = json.load(f)
            if isinstance(user, dict):
                cfg.update(user)
    except Exception:
        pass
    for k, v in DEFAULTS.items():
        if isinstance(v, list) and not isinstance(cfg.get(k), list):
            cfg[k] = v
    return cfg


def glob_to_re(glob):
    out = ""
    i = 0
    while i < len(glob):
        ch = glob[i]
        if ch == "*":
            if i + 1 < len(glob) and glob[i + 1] == "*":
                out += ".*"; i += 1
            else:
                out += "[^/]*"
        elif ch in ".+^${}()|[]\\":
            out += "\\" + ch
        else:
            out += ch
        i += 1
    return re.compile("^" + out + "$")


def matches_glob(p, globs):
    norm = p.replace("\\", "/")
    base = norm.split("/")[-1] if "/" in norm else norm
    for g in globs:
        r = glob_to_re(g)
        rb = glob_to_re(re.sub(r"^\*\*/", "", g))
        if r.match(norm) or r.match(base) or rb.match(norm) or rb.match(base):
            return g
    return None


def target_paths(tool_input):
    out, seen = [], set()

    def push(v):
        if isinstance(v, str) and v and v not in seen:
            seen.add(v); out.append(v)
    for key in ("path", "file", "filename", "filepath", "file_path", "notebook_path"):
        push(tool_input.get(key))
    for key in ("paths", "files"):
        val = tool_input.get(key)
        if isinstance(val, list):
            for v in val:
                push(v)
    return out


def get_command(tool_input):
    for key in ("command", "cmd", "script"):
        v = tool_input.get(key)
        if isinstance(v, str):
            return v
    return ""


def any_protected(tool, paths, command, globs):
    for p in paths:
        h = matches_glob(p, globs)
        if h:
            return "%s ~ %s" % (p, h)
    if tool in EXEC_TOOLS and command:
        for t in re.split(r"[\s;|&><'\"()]+", command):
            if not t:
                continue
            h = matches_glob(t, globs)
            if h:
                return "exec-arg ~ %s" % h
    return None


def write_targets(cmd):
    """Genuine write targets: `>`/`>>` redirection operands and `tee [-a] FILE`.
    A critical path only appearing as a READ arg (grep/cat) is not a write."""
    out = []
    for m in re.finditer(r"(?:^|\s)(?:[0-9]*|&)?>>?\s*([^\s;|&><'\"()]+)", cmd):
        if m.group(1):
            out.append(m.group(1))
    for m in re.finditer(r"(?:^|[|;&]\s*|\s)tee\b((?:\s+(?:-a|--append))*)((?:\s+[^\s;|&><'\"()]+)+)", cmd):
        for t in (m.group(2) or "").split():
            if not t.startswith("-"):
                out.append(t)
    return out


def strip_quoted(cmd):
    """Strip shell quoted-string literals ('...' and "...") before scanning for
    critical-exec patterns: a destructive OPERATOR lives outside quotes; the same
    words inside a quoted ARG (git commit -m "...rm -rf...", echo, grep) are inert
    text and must not trip the gate. Real destructive cmds with quoted args still
    match (operator is unquoted). Mirror of core/policy.ts stripQuoted."""
    out = []
    i = 0
    n = len(cmd)
    while i < n:
        ch = cmd[i]
        if ch == "'":
            i += 1
            while i < n and cmd[i] != "'":
                i += 1
            i += 1
            out.append(" ")
        elif ch == '"':
            i += 1
            while i < n and cmd[i] != '"':
                if cmd[i] == "\\" and i + 1 < n:
                    i += 1
                i += 1
            i += 1
            out.append(" ")
        else:
            out.append(ch)
            i += 1
    return "".join(out)

def escalation_hit(tool, paths, command, cfg):
    """ESCALATION / irreversible -> the only owner-facing APPROVAL trigger.
    (a) critical/irreversible exec commands, (b) writes to an escalationPathGlobs
    target (openclaw.json/.env: brick or privilege-escalation risk). Reversible
    security-doc edits are NOT here -> see critical_doc_hit."""
    if tool in WRITE_TOOLS:
        for p in paths:
            h = matches_glob(p, cfg["escalationPathGlobs"])
            if h:
                return "write %s ~ %s" % (p, h)
    if tool in EXEC_TOOLS and command:
        scan = strip_quoted(command)
        for pat in cfg["criticalExecPatterns"]:
            try:
                if re.search(pat, scan, re.I):
                    return "exec ~ /%s/" % pat
            except re.error:
                pass
        # exec WRITING to an escalation path. Reads (grep/cat) pass.
        for wt in write_targets(command):
            h = matches_glob(wt, cfg["escalationPathGlobs"])
            if h:
                return "exec-write %s ~ %s" % (wt, h)
    return None

def critical_doc_hit(tool, paths, command, cfg):
    """SECURITY-DOC write -> owner gets `warn` only (reversible: git+backups),
    never approval/block. Write (tool or exec-redirect) to a criticalPathGlobs
    doc (security_rules.md / AGENTS.md). Also feeds the trusted-tier ceiling."""
    if tool in WRITE_TOOLS:
        for p in paths:
            h = matches_glob(p, cfg["criticalPathGlobs"])
            if h:
                return "write %s ~ %s" % (p, h)
    if tool in EXEC_TOOLS and command:
        for wt in write_targets(command):
            h = matches_glob(wt, cfg["criticalPathGlobs"])
            if h:
                return "exec-write %s ~ %s" % (wt, h)
    return None


def exec_runs_allowed_script(command, scripts):
    if not command:
        return False
    if re.search(r"[;|&><`$(){}]", command):
        return False
    for s in scripts:
        esc = re.escape(s)
        if re.search(r"(^|[\\/\s])" + esc + r"[A-Za-z0-9_]*\.py([\s]|$)", command):
            return True
    return False


def find_trusted(sender_id, cfg):
    for t in cfg["trustedIds"]:
        if isinstance(t, dict) and t.get("id") == sender_id:
            return t
    return None

def decide_trusted(tool, paths, command, entry, cfg):
    """Decision for a matched trusted/delegated entry. Below owner, above
    non-owner. protectedGlobs + escalation/doc hits always win -- see TrustedEntry
    doc in policy.ts for the ceiling rules this mirrors."""
    entry_id = entry.get("id", "?")
    protected = any_protected(tool, paths, command, cfg["protectedGlobs"])
    if protected:
        return ("block", "non-owner protected resource: " + protected)

    scope = entry.get("scopePathGlobs")
    if scope and paths:
        out_of_scope = [p for p in paths if not matches_glob(p, scope)]
        if out_of_scope:
            return ("block", "trusted: %s path outside scope (%s)" % (entry_id, ", ".join(scope)))

    # Critical/irreversible AND security-doc writes blocked for trusted (ceiling).
    crit = escalation_hit(tool, paths, command, cfg) or critical_doc_hit(tool, paths, command, cfg)
    if crit:
        return ("block", "trusted: %s critical/irreversible denied: %s" % (entry_id, crit))

    allowed_tools = entry.get("allowedTools") or DEFAULT_TRUSTED_TOOLS
    if tool in EXEC_TOOLS:
        if "exec" not in allowed_tools and tool not in allowed_tools:
            return ("block", "trusted: %s exec not allowlisted" % entry_id)
        scripts = entry.get("allowedScripts") or cfg["nonOwnerAllowedScripts"]
        if exec_runs_allowed_script(command, scripts):
            return ("allow", "trusted: %s allowlisted script" % entry_id)
        return ("block", "trusted: %s exec restricted to allowlisted scripts" % entry_id)
    if tool in allowed_tools:
        return ("allow", "trusted: %s tool allowed" % entry_id)
    return ("block", "trusted: %s tool %s not allowlisted" % (entry_id, tool))

def decide(tool, paths, command, sender_id, cfg):
    is_owner = sender_id is None or sender_id in cfg["ownerIds"]
    protected = any_protected(tool, paths, command, cfg["protectedGlobs"])

    if is_owner:
        # All access. Only approval trigger is genuine escalation/irreversible.
        esc = escalation_hit(tool, paths, command, cfg)
        if esc:
            return ("approve", "critical/irreversible: " + esc)
        # Reversible security-doc edit -> warn only (owner still sees it).
        doc = critical_doc_hit(tool, paths, command, cfg)
        if doc:
            return ("warn", "security-doc edit (reversible): " + doc)
        if protected:
            return ("warn", "secret touch: " + protected)
        return ("allow", "owner")

    if sender_id is not None and cfg["trustedIds"]:
        entry = find_trusted(sender_id, cfg)
        if entry:
            return decide_trusted(tool, paths, command, entry, cfg)

    if protected:
        return ("block", "non-owner protected resource: " + protected)
    if tool in cfg["nonOwnerAllowedTools"]:
        return ("allow", "non-owner allowed tool")
    if tool in EXEC_TOOLS:
        if exec_runs_allowed_script(command, cfg["nonOwnerAllowedScripts"]):
            return ("allow", "non-owner allowlisted script")
        return ("block", "non-owner exec restricted to allowlisted tools")
    if tool in cfg["mutatingTools"]:
        return ("block", "non-owner %s denied" % tool)
    return ("block", "non-owner tool %s not allowlisted" % tool)


def emit(obj):
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def audit(cfg, obj):
    try:
        log = os.environ.get("DT_ENFORCE_LOG") or os.path.expanduser("~/.dinotrust/logs/enforce.log")
        os.makedirs(os.path.dirname(log), exist_ok=True)
        with open(log, "a") as f:
            import datetime
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            f.write(json.dumps(dict(ts=ts, **obj)) + "\n")
    except Exception:
        pass


def main():
    try:
        raw = sys.stdin.read()
        event = json.loads(raw) if raw.strip() else {}
    except Exception:
        emit({})  # fail-open
        return

    cfg = load_config()
    tool = str(event.get("tool_name") or event.get("toolName") or "")
    tool_input = event.get("tool_input") or event.get("toolInput") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    sender = event.get("sender_id", event.get("senderId", None))
    sender = None if sender in (None, "", "null") else str(sender)

    paths = target_paths(tool_input)
    command = get_command(tool_input)

    try:
        action, reason = decide(tool, paths, command, sender, cfg)
    except Exception as e:
        audit(cfg, dict(evt="error", error=str(e)))
        emit({})  # fail-open
        return

    audit(cfg, dict(evt=action, tool=tool, sender=sender or "self", reason=reason,
                    enforce=cfg["enforce"]))

    if not cfg["enforce"]:
        emit({})  # dry-run: log only
        return

    if action == "block":
        emit({"decision": "block", "reason": "dinotrust-enforce: " + reason})
    elif action == "approve":
        emit({"decision": "ask", "reason": "dinotrust: confirm critical action (%s). Are you sure?" % reason})
    else:  # allow / warn
        emit({})


if __name__ == "__main__":
    main()
