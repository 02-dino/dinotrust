#!/usr/bin/env bash
# dinotrust observability — bounded log rotation (optional, deployment-side).
#
# Why: report.py reads the WHOLE activity/jailbreak log each run, then filters to
# the report window. Unbounded logs => slower reports + disk growth at scale.
# This caps each log at MAX_BYTES; when exceeded it gzip-archives the current
# file with a timestamp, truncates the live file in place (producer keeps writing
# — same inode, no reopen needed), and keeps only the newest KEEP archives.
#
# Safe by design: archive-then-truncate (never drops un-archived data), only
# touches files above the cap, idempotent. Run BEFORE the report cron so the
# report always reads an already-bounded file.
#
# This is a DEPLOYMENT concern, not core detection — it ships here as a
# convenience for hooked installs. T3 (no-daemon CLI) self-audit logs are tiny
# and typically don't need it.
#
# Config (env or matching install.sh placeholders):
#   DT_ACTIVITY_LOG   absolute path to the activity log   (required)
#   DT_JAILBREAK_LOG  absolute path to the jailbreak log  (required)
#   DT_LOG_MAX_BYTES  per-log size cap in bytes           (default 10485760 = 10 MB)
#   DT_LOG_KEEP       newest gz archives to keep per log  (default 3)
#   DT_ARCHIVE_DIR    archive destination                 (default <logdir>/archive)
set -euo pipefail

ACTIVITY_LOG="${DT_ACTIVITY_LOG:-}"
JAILBREAK_LOG="${DT_JAILBREAK_LOG:-}"
MAX_BYTES="${DT_LOG_MAX_BYTES:-10485760}"
KEEP="${DT_LOG_KEEP:-3}"

[ -z "$ACTIVITY_LOG" ] && [ -z "$JAILBREAK_LOG" ] && {
  echo "Set DT_ACTIVITY_LOG and/or DT_JAILBREAK_LOG." >&2
  exit 1
}

ts="$(date -u +%Y%m%d-%H%M%S)"

rotate_one() {
  local f="$1"
  [ -n "$f" ] || return 0
  [ -f "$f" ] || return 0
  local size
  size=$(stat -c%s "$f" 2>/dev/null || echo 0)
  [ "$size" -le "$MAX_BYTES" ] && return 0

  local logdir archive_dir name
  logdir="$(dirname "$f")"
  archive_dir="${DT_ARCHIVE_DIR:-$logdir/archive}"
  name="$(basename "$f")"
  mkdir -p "$archive_dir"

  gzip -c "$f" > "$archive_dir/${name}.${ts}.gz"
  : > "$f"
  echo "rotated $name (was ${size} bytes) -> $archive_dir/${name}.${ts}.gz"

  # Prune: keep newest KEEP archives for this log.
  ls -1t "$archive_dir/${name}."*.gz 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
    rm -f "$old" && echo "pruned $old"
  done
}

rotate_one "$ACTIVITY_LOG"
rotate_one "$JAILBREAK_LOG"
