# wrappers/ — ready-made exec wrappers shipped with dinotrust

A wrapper is a small `.py` that OWNS how one external binary is invoked: it
forces the safety flags, refuses caller-supplied flags, and pins the write
directory. The gate decides *whether* a command runs; only the caller of the
binary can decide *how* it runs. That gap is why these exist.

## Why dinotrust ships these at all

Without them, every org that installs dinotrust and wants `yt-dlp` has to write
this file themselves before anything works. Most won't — they'll turn `enforce`
off instead, and you will never hear about it. A security tool that loses to
`enforce: false` has failed completely, not partially. So the boilerplate is
paid ONCE here, by the maintainer, instead of N times by N installs.

## The two classes (be honest about this)

| Class | Example | What it needs |
|---|---|---|
| **Easy** — raw output is already usable, no config file, no exec flag | `jq`, `pdftotext`, `xmllint` | flag allowlist only |
| **Hard** — reads external config, can execute, or emits an archival format that must be reshaped | `yt-dlp`, likely `ffmpeg` | a wrapper, i.e. code |

Two independent reasons a binary lands in **Hard**, and either one is enough:

1. **It can be steered from outside argv.** Measured 2026-10-23: `yt-dlp` loads
   config files by default (`--ignore-config` exists precisely to stop it), so
   flags — including `--exec` — can enter without ever appearing in the command.
   No amount of argument filtering closes that, because it is looking in the
   wrong place. Only the process that *builds* the argv can force
   `--ignore-config` in front.
2. **Its raw output isn't an answer.** `yt-dlp` subtitle output is a `.vtt`
   archive on disk: per-line timestamps, duplicated rolling-caption lines. It
   has to be reshaped into text before it is useful. A gate cannot reshape
   output; it only says yes or no.

A config-driven runner can cover the Easy class completely. It cannot cover
reason (2), which is why the Hard class stays code.

## The generic runner (Easy class — no new code per binary)

`run_binary.py` is allowlisted ONCE; adding a binary after that is a few lines
in `binaries.json`. Why this exists: `yt_dlp_tool.py` is 159 lines of which **5**
are policy. Retyping 154 lines of argparse/JSON/error boilerplate for every
binary is an entry barrier, and the realistic response to an entry barrier in a
security tool is to switch the security tool off.

    python3 <wrappers>/run_binary.py --list
    python3 <wrappers>/run_binary.py jq -r .name data.json

```json
"jq": { "allowedFlags": ["-r", "-c", "-n"], "forcedFlags": [], "timeout": 60 }
```

`forcedFlags` is the part a gate can never provide: the runner BUILDS the argv,
so it can prepend a flag. A gate only judges a finished command.

Four refusals, in this order, each covering a different failure:

1. **Binary must be a NAME from the spec** — never a path. A path would let the
   caller choose the executable, which is the whole decision being made for them.
2. **Flags are allowlisted per binary**, matched on the flag name so
   `--opt=value` cannot slip past a list written as bare names.
3. **`HARD_DENY` overrides the spec.** Flags that execute, fetch an executable,
   or load an unseen config file are refused *even if a spec allows them*. The
   spec is the surface most likely to be edited casually, and "the config said it
   was fine" is how an allowlist becomes an RCE.
4. **A group/world-writable spec is refused outright.** A policy file anyone can
   rewrite is not a policy, and enforcing it would be theatre.

`binaries.json` is per-install policy: the installer seeds it only when absent
(so updates never revert your tuning) and chmods it 600. Run
`bash wrappers/selftest.sh` after editing — it is weighted toward the refusal
paths, because a happy path fails loudly on first use while a refusal that
quietly stopped refusing looks exactly like a working tool.

## Installing

`scripts/install.sh` copies this directory next to your config and adds each
wrapper's allowlist key to `nonOwnerAllowedScripts`. Nothing to write by hand.

Verify after install:

    python3 <config-dir>/wrappers/yt_dlp_tool.py info https://youtu.be/<ID>

## Calling convention (matters more than it looks)

Run the **wrapper**, never the bare binary:

    python3 .../wrappers/yt_dlp_tool.py subs https://youtu.be/<ID>

- The allowlist matches a `.py` **basename**, not a location — one shared copy
  serves every agent. Do not fork it per workspace.
- The bare binary can never match (`"yt-dlp".endsWith(".py")` is false), and the
  deny message will read like a missing permission. It is not.
- Strip the URL to its bare form. `&list=`/`&t=` trips the shell-metacharacter
  check and the denial will blame the allowlist instead of the `&`.

## Adding a wrapper

1. Copy an existing one; keep the shape: fixed flag set per subcommand, no
   passthrough, writes confined to one directory, loud JSON error + exit 1.
2. Force the binary's "ignore external config" flag if it has one. Check
   `--help` for it — its presence means the binary reads config by default.
3. Derive the write dir from env or a fixed home path, never from `__file__`
   or the cwd. Deriving it from cwd hands the caller the one thing the fixed
   output template was supposed to take away.
4. Document WHY the binary is Hard class at the top of the file, with what you
   measured. The next maintainer will otherwise "simplify" it back open.
