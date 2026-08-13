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

    # keys we own.
    # NOTE: OpenClaw (>=2026.7) auto-discovers extension-dir plugins from
    # ~/.openclaw/extensions/<name>/ and its plugin-entry SCHEMA REJECTS a
    # `module` key (validation error: 'plugins.entries.dinotrust-enforce:
    # Invalid input' -> gateway won't load / config invalid). So we must NOT
    # write `module` for the auto-discovered install. We only preserve an
    # existing `module` if the user's current entry already had one (older
    # runtimes that DID key on module); we never introduce it fresh.
    if module and entry.get("module"):
        entry["module"] = module  # keep pre-existing module (legacy schema)
    else:
        entry.pop("module", None)  # extension-dir install: no module key
    entry["enabled"] = True
    hooks = entry.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
    hooks["allowConversationAccess"] = True
    entry["hooks"] = hooks

    cfg = entry.get("config")
    if not isinstance(cfg, dict):
        cfg = {}

    # ---- Multi-agent owner scoping (agentOwners map) ----
    # dinotrust owner config lives in a SINGLE plugin entry (one entry per
    # plugin id). The OLD behavior overwrote flat cfg.ownerIds + cfg.agentFilter,
    # so installing for a 2nd agent CLOBBERED the 1st (analyst loses dinotrust,
    # the new agent gets it). Fix: MERGE the installing agent's owners into
    # cfg.agentOwners["<agentFilter>"] keyed by the agent-scope substring (AGENTF,
    # e.g. "agent:analyst"), so N agents coexist in one entry.
    #
    # AGENTF present (the normal agent-scoped install):
    #   - migrate any pre-existing flat (ownerIds + agentFilter) into the map on
    #     first multi-agent touch so the earlier agent is NOT dropped;
    #   - upsert this agent's owners at cfg.agentOwners[AGENTF];
    #   - clear cfg.agentFilter ("") — the map does the scoping now — and drop the
    #     flat cfg.ownerIds so there is ONE source of truth.
    # AGENTF empty (legacy / all-agents install): keep the old flat behavior
    #   verbatim (full back-compat; single-agent installs are unchanged).
    if agentf:
        agent_owners = cfg.get("agentOwners")
        if not isinstance(agent_owners, dict):
            agent_owners = {}
        # Migrate a pre-existing flat single-agent entry into the map so the
        # earlier install is preserved, not clobbered.
        prev_flat_owners = cfg.get("ownerIds")
        prev_flat_filter = cfg.get("agentFilter")
        if (
            isinstance(prev_flat_owners, list) and prev_flat_owners
            and isinstance(prev_flat_filter, str) and prev_flat_filter
            and prev_flat_filter not in agent_owners
        ):
            agent_owners[prev_flat_filter] = prev_flat_owners
        # Upsert THIS agent's owners (only when we were actually given some;
        # an owner-less re-run must not wipe an existing mapping).
        if owners:
            agent_owners[agentf] = owners
        elif agentf not in agent_owners:
            agent_owners[agentf] = []
        cfg["agentOwners"] = agent_owners
        # Map is now the single source of truth: neutralize the flat keys.
        cfg["agentFilter"] = ""
        cfg.pop("ownerIds", None)
    else:
        # Legacy flat path (no agent scope): unchanged behavior.
        if owners:
            cfg["ownerIds"] = owners
        elif "ownerIds" not in cfg:
            cfg["ownerIds"] = []
    cfg["nonOwnerAllowedScripts"] = scripts
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
