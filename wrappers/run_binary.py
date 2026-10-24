#!/usr/bin/env python3
# DINOTRUST-DOC-BEGIN
# run_binary.py - generic locked-flag runner for SIMPLE binaries (policy as data).
#   python3 <wrappers>/run_binary.py --list          # which binaries are configured
#   python3 <wrappers>/run_binary.py jq -r .name data.json
#   python3 <wrappers>/run_binary.py pdftotext report.pdf -
# Only binaries named in binaries.json run, and only with the flags that file
# allows; everything else is refused. Adding one is a config edit, not new code.
# NOT for binaries that can execute or read their own config file (yt-dlp,
# ffmpeg, sqlite3, pandoc, curl) - those need a real wrapper. The runner refuses
# them by name if a spec tries, so an over-eager config cannot open a hole.
# DINOTRUST-DOC-END
"""Generic locked-flag runner: ONE allowlisted script, many simple binaries.

WHY THIS EXISTS
  A per-binary wrapper is ~150 lines of which only ~5 are policy; the rest is
  argparse/JSON/error boilerplate retyped every time. Measured on yt_dlp_tool.py:
  159 lines, 5 of them policy. For an org that just wants `jq` to work, that
  boilerplate is an entry barrier -- and the realistic response to an entry
  barrier in a security tool is to disable the security tool. So the boilerplate
  is paid ONCE here and each new simple binary becomes a few lines of JSON.

WHAT IT DOES NOT REPLACE
  A runner controls HOW a command is invoked. It cannot reshape OUTPUT. yt-dlp
  emits a .vtt archive that has to become text; that is code, so yt_dlp_tool.py
  stays. See wrappers/README.md for the easy/hard split.

CONTRACT
  - The caller picks a binary by NAME from the spec. Never a path: a path would
    let the caller choose the executable, which is the whole decision we are
    making for them.
  - Flags are allowlisted per binary. forcedFlags are prepended by US, which is
    the one thing a gate cannot do -- a gate judges a finished command, it
    cannot rewrite one (this is why --ignore-config can only be guaranteed here).
  - No shell anywhere: fixed argv, bounded time, loud JSON error + exit 1.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC_PATH = Path(os.environ.get("DINOTRUST_BINARY_SPEC") or (HERE / "binaries.json"))
DEFAULT_TIMEOUT = 120
MAX_OUTPUT = 200_000

# Flags that hand a binary the ability to execute something, fetch an
# executable, or load flags from a file we are not reading. Refused even when a
# spec allows them: the spec is the surface most likely to be edited casually,
# and "the config said it was fine" is exactly how an allowlist turns into an
# RCE. A binary that genuinely needs one of these is hard-class by definition --
# the right answer is a wrapper, which is what the error says.
HARD_DENY = {
    "--exec", "--exec-before-download", "--downloader", "--external-downloader",
    "--config", "--config-locations", "--config-location", "-K",
    "--lua-filter", "--filter", "--preload", "--load-extension",
    "--use-askpass", "--upload-file", "-T",
}


def die(msg: str, **extra) -> None:
    print(json.dumps({"error": msg, **extra}))
    sys.exit(1)


def load_spec() -> dict:
    """Read the policy file, refusing it if anyone else could have written it.

    The spec decides which binaries and flags are permitted, so it is a security
    file in the same class as .env. A group/world-writable spec means the policy
    is attacker-controlled and every check below is theatre -- fail loudly
    instead of enforcing a policy we cannot vouch for.
    """
    if not SPEC_PATH.is_file():
        die(f"no binary spec at {SPEC_PATH}", hint="copy binaries.default.json to binaries.json")
    mode = SPEC_PATH.stat().st_mode
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        die(f"refusing spec {SPEC_PATH}: writable by group/other",
            hint="chmod 600 (or 644) it; a writable policy file is not a policy")
    try:
        spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        die(f"unreadable binary spec: {e}")
    if not isinstance(spec, dict):
        die("binary spec must be a JSON object of {binary: {...}}")
    return spec


def flag_name(arg: str) -> str:
    """`--sub-langs=en` and `--sub-langs en` are the SAME flag. Comparing the raw
    token would let the `=` form slip past an allowlist built from bare names."""
    return arg.split("=", 1)[0]


def check_entry(name: str, entry: dict) -> None:
    """Validate the SPEC itself, before any user input is considered."""
    if not isinstance(entry, dict):
        die(f"spec for '{name}' must be an object")
    for key in ("allowedFlags", "forcedFlags"):
        val = entry.get(key, [])
        if not isinstance(val, list) or any(not isinstance(v, str) for v in val):
            die(f"spec '{name}.{key}' must be a list of strings")
        for v in val:
            if flag_name(v) in HARD_DENY:
                die(f"spec '{name}' allows '{v}', which can execute or load external config",
                    hint="this binary is hard-class: write a real wrapper instead of a spec entry")


def main() -> None:
    argv = sys.argv[1:]
    spec = load_spec()

    if not argv or argv[0] in ("--list", "-h", "--help"):
        out = {}
        for name, entry in spec.items():
            if isinstance(entry, dict):
                out[name] = {
                    "available": shutil.which(name) is not None,
                    "allowedFlags": entry.get("allowedFlags", []),
                    "forcedFlags": entry.get("forcedFlags", []),
                }
        print(json.dumps({"spec": str(SPEC_PATH), "binaries": out}, indent=2))
        sys.exit(0)

    name, user_args = argv[0], argv[1:]
    if name.startswith("-") or "/" in name:
        die("first argument must be a binary NAME from the spec, not a path or flag",
            hint="run with --list to see configured names")
    entry = spec.get(name)
    if entry is None:
        die(f"'{name}' is not in the binary spec",
            hint=f"add it to {SPEC_PATH}, or use --list to see what is configured")
    check_entry(name, entry)

    allowed = set(entry.get("allowedFlags", []))
    forced = list(entry.get("forcedFlags", []))
    timeout = int(entry.get("timeout", DEFAULT_TIMEOUT))

    # Validate user args. Positionals pass through: no shell is involved, so
    # metacharacters are inert here, and protected-path reads are already caught
    # upstream by the gate's exec-arg scan against protectedGlobs.
    for arg in user_args:
        if not arg.startswith("-") or arg == "-":
            continue
        fn = flag_name(arg)
        if fn in HARD_DENY:
            die(f"flag '{fn}' is never allowed through the generic runner",
                hint="it can execute or load external config; that needs a real wrapper")
        if fn not in allowed:
            die(f"flag '{fn}' is not allowed for '{name}'",
                allowed=sorted(allowed),
                hint=f"add it to {SPEC_PATH} under {name}.allowedFlags if it is safe")

    binary = shutil.which(name)
    if not binary:
        die(f"binary '{name}' is configured but not installed on this host")

    try:
        p = subprocess.run([binary, *forced, *user_args],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        die(f"'{name}' timed out after {timeout}s")

    sys.stdout.write(p.stdout[:MAX_OUTPUT])
    if len(p.stdout) > MAX_OUTPUT:
        sys.stdout.write(f"\n[truncated at {MAX_OUTPUT} chars]\n")
    if p.returncode != 0:
        sys.stderr.write(p.stderr[-2000:])
    sys.exit(p.returncode)


if __name__ == "__main__":
    main()
