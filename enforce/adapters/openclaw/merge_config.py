#!/usr/bin/env python3
"""Idempotently merge the dinotrust-enforce plugin entry into openclaw.json.

Env in: OC_JSON, MODULE, OWNERS (json array str), SCRIPTS (json array str),
        ENFORCE ("true"/"false"), AGENTF (agentFilter substring, may be empty).

Semantics:
  - Preserve the entire rest of the file. Only touch
    plugins.entries["dinotrust-enforce"].
  - Create it if absent; if present (re-run/upgrade), update the keys we own
    (module, enabled, hooks.allowConversationAccess, config.ownerIds,
     config.nonOwnerAllowedScripts, config.enforce, config.agentFilter) and
    leave any other user-set config keys intact.
  - Never lower enforce a user explicitly set: if the existing entry already has
    config.enforce == true and we were asked for false (shadow), keep true unless
    SHADOW_OK=1. (Upgrades should not silently disable enforcement.)
Exit 0 on success, non-zero on any parse/write failure (caller falls back to
manual paste instructions).
"""
import json
import os
import sys


def _arr(s):
    try:
        v = json.loads(s or "[]")
        return v if isinstance(v, list) else []
    except Exception:
        return []


def main():
    path = os.environ.get("OC_JSON", "")
    if not path or not os.path.isfile(path):
        return 1
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except Exception as e:
        sys.stderr.write("parse error: %s\n" % e)
        return 1

    if not isinstance(data, dict):
        return 1

    module = os.environ.get("MODULE", "")
    owners = _arr(os.environ.get("OWNERS"))
    scripts = _arr(os.environ.get("SCRIPTS"))
    enforce = os.environ.get("ENFORCE", "true").lower() == "true"
    agentf = os.environ.get("AGENTF", "") or ""
    shadow_ok = os.environ.get("SHADOW_OK", "") == "1"

    plugins = data.setdefault("plugins", {})
    if not isinstance(plugins, dict):
        return 1
    entries = plugins.setdefault("entries", {})
    if not isinstance(entries, dict):
        return 1

    entry = entries.get("dinotrust-enforce")
    if not isinstance(entry, dict):
        entry = {}

    # keys we own
    entry["module"] = module
    entry["enabled"] = True
    hooks = entry.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
    hooks["allowConversationAccess"] = True
    entry["hooks"] = hooks

    cfg = entry.get("config")
    if not isinstance(cfg, dict):
        cfg = {}
    if owners:
        cfg["ownerIds"] = owners
    elif "ownerIds" not in cfg:
        cfg["ownerIds"] = []
    cfg["nonOwnerAllowedScripts"] = scripts
    if agentf:
        cfg["agentFilter"] = agentf
    # don't silently disable an already-enabled enforcement on upgrade
    prev = cfg.get("enforce")
    if prev is True and not enforce and not shadow_ok:
        cfg["enforce"] = True
    else:
        cfg["enforce"] = enforce
    entry["config"] = cfg

    entries["dinotrust-enforce"] = entry

    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
    except Exception as e:
        sys.stderr.write("write error: %s\n" % e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
