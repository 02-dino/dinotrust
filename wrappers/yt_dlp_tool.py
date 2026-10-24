#!/usr/bin/env python3
# DINOTRUST-DOC-BEGIN
# yt_dlp_tool.py - YouTube/media reader (metadata | captions | audio).
#   python3 <wrappers>/yt_dlp_tool.py info  <url>            # title, duration, caption langs
#   python3 <wrappers>/yt_dlp_tool.py subs  <url> [--lang en] # published captions as text
#   python3 <wrappers>/yt_dlp_tool.py audio <url>            # bestaudio -> m4a
# CALL THIS, never the bare `yt-dlp` binary: the allowlist matches *.py only, so
# the raw binary is denied with a message that reads like a MISSING PERMISSION
# when the permission already exists. Measured cost of that confusion: 2 hours.
# STRIP THE URL to https://youtu.be/<ID> - a `&list=`/`&t=` trips the shell-
# metacharacter check and the denial blames the allowlist, not the `&`.
# status=no_subtitles means NO captions were published, so transcription was
# never attempted; it is not an empty transcript and not "no speech".
# DINOTRUST-DOC-END
"""YouTube/media reader — locked-flag wrapper around the yt-dlp binary.

WHY THIS EXISTS (instead of just allowlisting `yt-dlp`):
  1. dinotrust's non-owner exec allowlist only matches *.py files
     (namesAllowlistedScript: `script.endsWith(".py")` -> index.ts:1062), so a
     bare binary name in nonOwnerAllowedScripts is DEAD CONFIG — it can never
     match, and the caller just gets a generic deny.
  2. Raw yt-dlp is an RCE primitive for a restricted caller: --exec runs an
     arbitrary shell command per file; --downloader/--paths/-o reach the
     filesystem outside the gate. The allowlist contract assumes ONE read-only
     invocation; raw yt-dlp breaks that assumption.

CONTRACT: caller passes a subcommand + URL. NO yt-dlp flags are forwarded from
user input — the flag set per subcommand is fixed here. Writes land only under
MEDIA_DIR. Fails loud with JSON {"error": ...} and exit 1.

GOTCHA: `subs` returns published captions only (zero cost, no ASR). A video
with none returns status=no_subtitles — that means transcription was never
ATTEMPTED, not that the video has no speech. Never report it as empty content.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# WRITE DIR: deliberately NOT derived from __file__ or cwd. Deriving it from the
# file location made the dir move when the wrapper moved (workspace -> repo),
# and deriving it from cwd would let the caller pick the write target by
# choosing where they run from -- the output template is supposed to be the one
# thing the caller cannot steer. A fixed home-anchored dir keeps it constant for
# every install; override only via env, which is operator-side, not caller-side.
MEDIA_DIR = Path(os.environ.get("DINOTRUST_MEDIA_DIR")
                 or (Path.home() / ".dinotrust" / "media_cache")).resolve()
TIMEOUT = 300
# Plain http(s) only. A leading '-' or shell char would let the URL slot
# smuggle a flag into argv despite the fixed flag set above.
URL_RE = re.compile(r"^https?://[^\s'\"\\;|&><`$(){}]+$")


def die(msg: str, **extra) -> None:
    print(json.dumps({"error": msg, **extra}))
    sys.exit(1)


def run(args: list[str], timeout: int = TIMEOUT) -> subprocess.CompletedProcess:
    """One yt-dlp invocation: no shell, fixed argv, bounded time."""
    binary = shutil.which("yt-dlp")
    if not binary:
        die("yt-dlp binary not found on PATH")
    # --ignore-config is NOT optional (measured 2026-10-23): yt-dlp loads config
    # files by default (~/.config/yt-dlp/config, ./yt-dlp.conf, $XDG_CONFIG_HOME),
    # so flags can enter WITHOUT passing through argv. The fixed flag set below
    # would otherwise be silently extended by anyone who can write such a file --
    # including --exec. Filtering arguments alone cannot close that path; this can.
    try:
        return subprocess.run([binary, "--ignore-config", *args],
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        die(f"yt-dlp timed out after {timeout}s")


def cmd_info(url: str) -> dict:
    """Metadata only — no media bytes written anywhere."""
    p = run(["--no-playlist", "--skip-download", "--dump-single-json", url])
    if p.returncode != 0:
        die("yt-dlp metadata fetch failed", detail=p.stderr.strip()[-500:])
    d = json.loads(p.stdout)
    subs = sorted(set(d.get("subtitles") or {}))
    autos = sorted(set(d.get("automatic_captions") or {}))
    return {
        "id": d.get("id"),
        "title": d.get("title"),
        "uploader": d.get("uploader"),
        "upload_date": d.get("upload_date"),
        "duration_seconds": d.get("duration"),
        "view_count": d.get("view_count"),
        "like_count": d.get("like_count"),
        "webpage_url": d.get("webpage_url"),
        "description": (d.get("description") or "")[:2000],
        "subtitle_langs": subs,
        "auto_caption_langs": autos[:20],
        "has_any_captions": bool(subs or autos),
    }


def _vtt_to_text(raw: str) -> str:
    """VTT -> plain text. Dedups the rolling-window repeats auto-captions emit."""
    out: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or "-->" in line or line in ("WEBVTT", "NOTE"):
            continue
        if line.startswith(("Kind:", "Language:")) or line.isdigit():
            continue
        line = re.sub(r"<[^>]+>", "", line).strip()
        if line and (not out or out[-1] != line):
            out.append(line)
    return " ".join(out)


def cmd_subs(url: str, lang: str) -> dict:
    """Captions as text. Manual subs preferred, auto-captions as fallback."""
    with tempfile.TemporaryDirectory() as tmp:
        p = run([
            "--no-playlist", "--skip-download",
            "--write-subs", "--write-auto-subs",
            "--sub-langs", lang, "--sub-format", "vtt/best",
            "--convert-subs", "vtt",
            "-o", str(Path(tmp) / "s.%(ext)s"), url,
        ])
        files = sorted(Path(tmp).glob("*.vtt"))
        if not files:
            return {"status": "no_subtitles", "lang_requested": lang,
                    "note": "no captions published for this lang — transcription was NOT attempted",
                    "detail": p.stderr.strip()[-300:]}
        text = _vtt_to_text(files[0].read_text(encoding="utf-8", errors="replace"))
        return {"status": "ok", "lang_file": files[0].name,
                "chars": len(text), "transcript": text}


def cmd_audio(url: str) -> dict:
    """Audio into MEDIA_DIR only — output template is fixed, never caller-supplied."""
    MEDIA_DIR.mkdir(parents=True, exist_ok=True)
    before = set(MEDIA_DIR.iterdir())
    p = run(["--no-playlist", "-f", "bestaudio/best", "-x", "--audio-format", "m4a",
             "-o", str(MEDIA_DIR / "%(id)s.%(ext)s"), url])
    new = sorted(set(MEDIA_DIR.iterdir()) - before)
    if p.returncode != 0 and not new:
        die("yt-dlp audio download failed", detail=p.stderr.strip()[-500:])
    return {"status": "ok", "dir": str(MEDIA_DIR),
            "files": [{"path": str(f), "bytes": f.stat().st_size} for f in new]}


def main() -> None:
    ap = argparse.ArgumentParser(description="Locked-flag yt-dlp reader (no flag passthrough).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("info", "subs", "audio"):
        s = sub.add_parser(name)
        s.add_argument("url")
        if name == "subs":
            s.add_argument("--lang", default="en", help="caption language code (default en)")
    a = ap.parse_args()

    if not URL_RE.match(a.url):
        die("invalid url: expected a plain http(s) URL with no shell characters")
    if a.cmd == "info":
        res = cmd_info(a.url)
    elif a.cmd == "subs":
        if not re.fullmatch(r"[A-Za-z0-9_.-]{2,12}", a.lang):
            die("invalid --lang")
        res = cmd_subs(a.url, a.lang)
    else:
        res = cmd_audio(a.url)
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
