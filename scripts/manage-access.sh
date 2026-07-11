#!/usr/bin/env bash
# dinotrust manage-access — one front door for managing WHO can do WHAT.
#
# dinotrust has three identity tiers:
#   owner    — full access (all-or-nothing). Instruction layer + enforce hook.
#   trusted  — a delegated middle tier: per-id extra tool/script allowlist and
#              optional path-scope confinement, still under the hard ceiling
#              (secrets + critical actions always blocked). Enforce hook only.
#   non-owner — the default public tier (tuned at install via --profile).
#
# This single command manages the two tiers you add/remove ids from — owner and
# trusted — so you don't have to remember two separate scripts. Pick the tier
# with the first argument (the "subject"), then the action:
#
#   bash scripts/manage-access.sh owner   <list|add|remove> ...
#   bash scripts/manage-access.sh trusted <list|show|add|remove> ...
#
# It's a thin dispatcher: `owner ...` is forwarded verbatim to the owner
# implementation, `trusted ...` to the trusted implementation. Every flag,
# behavior, backup, and enforce-sync of the originals is preserved exactly —
# this only unifies the entry point and help text.
#
# ─── OWNER subject ───────────────────────────────────────────────────────────
#   Surgically edits the owner_ids: line in the injected instruction block AND
#   (by default) syncs the enforce hook's ownerIds config — both layers in one
#   command. Never regenerates the rest of the ruleset (unlike install.sh
#   --force), so your customizations survive.
#
#   bash scripts/manage-access.sh owner list   [--config PATH]
#   bash scripts/manage-access.sh owner add    <id[@platform[+platform2]]> [--config PATH] [--oc-json PATH] [--dt-conf PATH] [--no-sync-enforce]
#   bash scripts/manage-access.sh owner remove <id> [--config PATH] [--oc-json PATH] [--dt-conf PATH] [--no-sync-enforce]
#
# ─── TRUSTED subject ─────────────────────────────────────────────────────────
#   Edits ONLY the enforce hook's own config (openclaw.json plugin entry, or
#   ~/.dinotrust/enforce.json on CLI runtimes). No instruction-layer copy —
#   trusted is a code-enforced allowlist, not an ownership claim.
#
#   bash scripts/manage-access.sh trusted list
#   bash scripts/manage-access.sh trusted show   <id>
#   bash scripts/manage-access.sh trusted add    <id> [--tools t1,t2,...] [--scripts s1,s2,...] [--scope glob1,glob2,...] [--oc-json PATH] [--dt-conf PATH]
#   bash scripts/manage-access.sh trusted remove <id> [--oc-json PATH] [--dt-conf PATH]
#
#   Examples:
#     bash scripts/manage-access.sh trusted add 555555 --scope "workspace-bob/**"
#       # delegated admin of their own workspace folder only, default trusted tool set inside it
#     bash scripts/manage-access.sh trusted add 666666 --tools read,write --scripts exchange_data
#       # extra tool access, no path restriction
#
# Back-compat: the previous scripts/manage-owner.sh and scripts/manage-trusted.sh
# still exist as thin shims that forward here, so old commands/muscle memory keep
# working. New docs use manage-access.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
err() { echo -e "${RED}✗${NC}  $*" >&2; }

usage() {
  echo -e "${BOLD}dinotrust manage-access${NC} — manage who can do what"
  cat <<EOF

Usage:
  bash scripts/manage-access.sh owner   <list|add|remove> [id[@platform]] [flags]
  bash scripts/manage-access.sh trusted <list|show|add|remove> [id] [flags]

Subjects:
  owner     Full-access ids. Syncs instruction layer + enforce hook in one command.
            add/remove/list. Flags: --config, --oc-json, --dt-conf, --no-sync-enforce
  trusted   Delegated middle tier (per-id tool/script allowlist + optional path scope).
            Enforce hook only. add/remove/list/show.
            Flags: --tools, --scripts, --scope, --oc-json, --dt-conf

Examples:
  bash scripts/manage-access.sh owner add 987654321
  bash scripts/manage-access.sh owner remove 987654321
  bash scripts/manage-access.sh owner list
  bash scripts/manage-access.sh trusted add 555555 --scope "workspace-bob/**"
  bash scripts/manage-access.sh trusted add 666666 --tools read,write --scripts exchange_data
  bash scripts/manage-access.sh trusted list
  bash scripts/manage-access.sh trusted show 555555

Run a subject with no action to see that subject's full flag help.
EOF
}

SUBJECT="${1:-}"
case "$SUBJECT" in
  owner)
    shift
    exec bash "$SCRIPT_DIR/_manage-owner-impl.sh" "$@"
    ;;
  trusted)
    shift
    exec bash "$SCRIPT_DIR/_manage-trusted-impl.sh" "$@"
    ;;
  -h|--help|help|"")
    usage
    exit 0
    ;;
  *)
    err "Unknown subject '$SUBJECT'. Expected 'owner' or 'trusted'."
    echo "" >&2
    usage >&2
    exit 2
    ;;
esac
