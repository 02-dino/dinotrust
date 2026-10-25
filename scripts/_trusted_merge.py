#!/usr/bin/env python3
"""Single merge engine for trusted entries, shared by both store kinds.

WHY ONE FILE: this logic lived as two near-identical heredocs inside
_manage-trusted-impl.sh (one for the openclaw.json plugin entry, one for
~/.dinotrust/enforce.json). They differed only in where trustedIds lives. Two
hand-kept copies of a PRIVILEGE-GRANTING merge is a drift waiting to happen,
and the incident this code already carries a comment about -- silently erased
scopeAgents -- is exactly that class of bug. One engine, two locators.

LIST SEMANTICS (the UX fix): every list field carries a MODE.
  set  replace the whole list   (the old, only behaviour)
  add  union with what is there (idempotent)
  del  subtract from what is there
Measured 2026-10-25: `trusted add <id> --scripts yt_dlp_tool` on an entry
holding ["sheet_fill_links"] silently produced ["yt_dlp_tool"]. Nothing warned,
and the lost grant is invisible until someone's workflow breaks. Replace is a
legitimate operation, but it must be CHOSEN, never the accidental default of
someone who meant "also allow this".

Prints a unified before/after summary on stdout so the caller can show a diff
and (with --dry-run) decline to write.

ARGV: path kind action id
      tools_j scripts_j scope_j agents_j crit_j
      tools_mode scripts_mode dry_run
"""
from __future__ import annotations

import json
import sys


def locate(data: dict, kind: str) -> dict:
    """Return the config dict that owns trustedIds, creating the path if needed."""
    if kind == "oc":
        return (data.setdefault("plugins", {}).setdefault("entries", {})
                    .setdefault("dinotrust-enforce", {}).setdefault("config", {}))
    return data


def apply_list(prior, incoming, mode: str):
    """Combine a prior list with an incoming one under the given mode.

    Order is preserved and duplicates are dropped: an allowlist is a set in
    meaning, and a duplicated grant reads as two grants in a diff.
    """
    prior = [x for x in (prior or []) if isinstance(x, str)]
    if mode == "set":
        return list(dict.fromkeys(incoming))
    if mode == "add":
        return list(dict.fromkeys([*prior, *incoming]))
    if mode == "del":
        drop = set(incoming)
        return [x for x in prior if x not in drop]
    raise ValueError(f"unknown list mode: {mode}")


def main() -> int:
    (path, kind, action, arg_id,
     tools_j, scripts_j, scope_j, agents_j, crit_j,
     tools_mode, scripts_mode, dry_run) = sys.argv[1:13]

    with open(path) as f:
        data = json.load(f)
    cfg = locate(data, kind)
    trusted = cfg.get("trustedIds")
    if not isinstance(trusted, list):
        trusted = []

    if action == "remove":
        before = len(trusted)
        trusted = [e for e in trusted if str(e.get("id")) != arg_id]
        if len(trusted) == before:
            sys.stderr.write(f"NOOP: '{arg_id}' is not a trusted id. No change.\n")
            return 3
        print(f"REMOVED {arg_id}")
    else:
        # MERGE, never rebuild. WHY (incident 2026-10-21): this used to drop the
        # old entry and construct {"id": ...} from scratch, so every field the
        # CLI has no flag for -- scopeAgents above all -- was SILENTLY ERASED by
        # an unrelated update. Measured: six per-agent grants became cross-agent
        # in one command. Silent privilege WIDENING is the one failure mode this
        # must not have, so unknown keys carry over untouched.
        prior = next((e for e in trusted if str(e.get("id")) == arg_id), {})
        trusted = [e for e in trusted if str(e.get("id")) != arg_id]
        entry = dict(prior)
        entry["id"] = arg_id
        changes = []

        for key, raw, mode in (("allowedTools", tools_j, tools_mode),
                               ("allowedScripts", scripts_j, scripts_mode)):
            if raw == "null":
                continue
            was = prior.get(key)
            now = apply_list(was, json.loads(raw), mode)
            entry[key] = now
            if was != now:
                changes.append((key, was, now))

        for key, raw in (("scopePathGlobs", scope_j), ("scopeAgents", agents_j)):
            if raw == "null":
                continue
            was, now = prior.get(key), json.loads(raw)
            entry[key] = now
            if was != now:
                changes.append((key, was, now))

        if crit_j != "null":
            was, now = prior.get("allowScopedCritical"), json.loads(crit_j)
            entry["allowScopedCritical"] = now
            if was != now:
                changes.append(("allowScopedCritical", was, now))

        trusted.append(entry)
        verb = "UPDATED" if prior else "CREATED"
        print(f"{verb} {arg_id}")
        if not changes:
            print("  (no field changed)")
        for key, was, now in changes:
            print(f"  {key}:")
            print(f"    - {json.dumps(was)}")
            print(f"    + {json.dumps(now)}")
        # Fields the caller did not touch are listed so a human can SEE that the
        # scope survived, instead of trusting that it did.
        untouched = [k for k in prior if k != "id" and k not in [c[0] for c in changes]]
        if untouched:
            print(f"  preserved: {', '.join(sorted(untouched))}")

    if dry_run == "true":
        print("  (dry run — not written)")
        return 0

    cfg["trustedIds"] = trusted
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
