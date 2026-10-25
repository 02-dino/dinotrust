#!/usr/bin/env python3
"""Render trusted entries for `list` / `show`, for either store kind.

WHY NOT THE OLD ONE-LINER: it printed every field on a single long line, with
python repr for the lists, and -- worst -- showed MISSING as "(default)" or
"(shared default)" without saying what that default actually resolves to. The
single most expensive misunderstanding in this whole system is exactly that
distinction: `allowedScripts` ABSENT means "inherits the global list and keeps
inheriting future additions", while `allowedScripts: [...]` means "cut off from
global forever" (the engine does `entry.allowedScripts ?? global`, which is
override, not merge). Measured 2026-10-25: two sosmed ids were silently excluded
from a fleet-wide grant for precisely this reason, and nothing in `list` output
would have revealed it.

So this renderer's job is not prettiness. It is to make INHERITED vs PINNED
visible at a glance, and to show the global list the inheritors actually get.

ARGV: path kind action filter_id
"""
from __future__ import annotations

import json
import sys

PLAIN = {"true": False, "false": True}.get(
    __import__("os").environ.get("DINOTRUST_COLOR", "true").lower(), False)
DIM = "" if PLAIN else "\033[2m"
BOLD = "" if PLAIN else "\033[1m"
YEL = "" if PLAIN else "\033[0;33m"
NC = "" if PLAIN else "\033[0m"


def fmt_list(vals) -> str:
    return ", ".join(str(v) for v in vals) if vals else "(empty)"


def main() -> int:
    path, kind, action, filter_id = sys.argv[1:5]
    with open(path) as f:
        data = json.load(f)
    cfg = (data.get("plugins", {}).get("entries", {})
               .get("dinotrust-enforce", {}).get("config", {})
           if kind == "oc" else data)

    g_scripts = cfg.get("nonOwnerAllowedScripts") or []
    entries = cfg.get("trustedIds") or []

    if action == "show":
        entries = [e for e in entries if str(e.get("id")) == filter_id]
        if not entries:
            print(f"    (no trusted entry for id {filter_id})")
            return 0
    if not entries:
        print("    (none)")
        return 0

    for e in entries:
        print(f"    {BOLD}id={e.get('id')}{NC}")

        tools = e.get("allowedTools")
        if tools is None:
            print(f"      tools   : {DIM}(default trusted set){NC}")
        else:
            print(f"      tools   : {fmt_list(tools)}")

        # The one line that matters most -- see module docstring.
        scripts = e.get("allowedScripts")
        if scripts is None:
            print(f"      scripts : {DIM}inherits global ->{NC} {fmt_list(g_scripts)}")
            print(f"                {DIM}(future global additions apply automatically){NC}")
        else:
            print(f"      scripts : {fmt_list(scripts)}")
            missing = [s for s in g_scripts if s not in scripts]
            print(f"                {YEL}PINNED{NC} — cut off from the global list.")
            if missing:
                print(f"                {YEL}not inherited:{NC} {fmt_list(missing)}")
                print(f"                {DIM}add with: trusted add {e.get('id')} "
                      f"--add-scripts {','.join(missing)}{NC}")

        scope = e.get("scopePathGlobs")
        print(f"      paths   : {fmt_list(scope) if scope else DIM + '(unrestricted)' + NC}")
        agents = e.get("scopeAgents")
        print(f"      agents  : {fmt_list(agents) if agents else YEL + 'ALL agents' + NC}")
        if e.get("allowScopedCritical"):
            print(f"      critical: {YEL}allowed INSIDE its scope{NC} "
                  f"{DIM}(secrets/config writes still blocked){NC}")
        extra = [k for k in e if k not in {
            "id", "allowedTools", "allowedScripts", "scopePathGlobs",
            "scopeAgents", "allowScopedCritical"}]
        if extra:
            print(f"      other   : {', '.join(sorted(extra))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
