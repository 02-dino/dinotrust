#!/usr/bin/env python3
"""
dinotrust observability — taxonomy drift guard.

The spine of the design: every rule_id referenced in patterns.json MUST exist
in security_rules.md. If they drift, a flagged audit event names a rule that
doesn't exist, and the enforce<->audit coupling silently rots.

Run by hand, in install.sh, or pre-commit. Exits non-zero on mismatch.
No CI infra required (zero-infrastructure ethos).

Usage:
    python3 validate.py [--patterns PATH] [--rules PATH]
"""
import json
import re
import sys
import argparse
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_PATTERNS = HERE / "patterns.json"
DEFAULT_RULES = HERE.parent / "security_rules.md"


def load_pattern_rule_ids(patterns_path: Path) -> tuple[set[str], set[str]]:
    """Return (checked_ids, agent_judged_ids).

    checked_ids       — rule_ids attached to actual regex patterns; these MUST
                        exist verbatim in security_rules.md (the enforce<->audit
                        coupling the drift guard protects).
    agent_judged_ids  — declared in _meta.agent_judged_only: rules that are
                        enforcement-only / agent-judged and have NO text pattern
                        (e.g. T1_config_conflict = runtime config contradiction,
                        not a message pattern). These are exempt from the
                        verbatim-presence check because security_rules.md may
                        declare them in a non-canonical form (bare `T1:` under
                        tamper_detection rather than `T1_config_conflict`).
                        They are still validated softly below (warn, not fail).
    """
    data = json.loads(patterns_path.read_text(encoding="utf-8"))
    checked = {p["rule_id"] for p in data.get("patterns", [])}
    agent_judged = set(data.get("_meta", {}).get("agent_judged_only", []))
    # A rule can appear in both; the pattern-attached form always wins (stays checked).
    agent_judged -= checked
    return checked, agent_judged


def load_rule_ids_from_rules(rules_path: Path) -> set[str]:
    text = rules_path.read_text(encoding="utf-8")
    # rule ids look like:  - id: R1_override_claims  /  id: S0_security_directive
    # also bare references in the taxonomy. Match the canonical id tokens.
    found = set(re.findall(r"\b((?:R\d+|S\d+|T\d+)_[a-z_]+)\b", text))
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description="dinotrust taxonomy drift guard")
    ap.add_argument("--patterns", type=Path, default=DEFAULT_PATTERNS)
    ap.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    args = ap.parse_args()

    if not args.patterns.exists():
        print(f"\u2717 patterns file not found: {args.patterns}", file=sys.stderr)
        return 2
    if not args.rules.exists():
        print(f"\u2717 rules file not found: {args.rules}", file=sys.stderr)
        return 2

    pattern_ids, agent_judged_ids = load_pattern_rule_ids(args.patterns)
    rule_ids = load_rule_ids_from_rules(args.rules)
    # Bare taxonomy tokens (e.g. `T1`, `S0`) declared without the _suffix form,
    # so agent-judged rules declared as `T1:` in security_rules.md still resolve.
    bare_ids = set(re.findall(r"\b(R\d+|S\d+|T\d+)\b", args.rules.read_text(encoding="utf-8")))

    # HARD check: every pattern-attached rule_id must exist verbatim. This is the
    # coupling that actually matters — a flagged audit event naming a nonexistent
    # rule is real drift.
    missing = sorted(pattern_ids - rule_ids)
    if missing:
        print("\u2717 DRIFT: rule_ids referenced by patterns.json but absent from security_rules.md:", file=sys.stderr)
        for m in missing:
            print(f"    - {m}", file=sys.stderr)
        print("\nFix: add the rule to security_rules.md, or correct the rule_id in patterns.json.", file=sys.stderr)
        return 1

    # SOFT check: agent-judged rules (no text pattern) are exempt from failing the
    # install. If neither the full id nor its bare taxonomy token is present, warn
    # only — they carry no regex to couple, so a missing declaration can't rot an
    # audit event the way a pattern-attached one can.
    aj_missing = sorted(
        r for r in agent_judged_ids
        if r not in rule_ids and r.split("_", 1)[0] not in bare_ids
    )
    for r in aj_missing:
        print(f"\u26a0 note: agent-judged rule '{r}' not found in security_rules.md "
              f"(exempt from drift failure \u2014 enforcement-only, no text pattern).", file=sys.stderr)

    total = len(pattern_ids) + len(agent_judged_ids)
    print(f"\u2713 taxonomy OK \u2014 {len(pattern_ids)} pattern rule_id(s) verified present; "
          f"{len(agent_judged_ids)} agent-judged rule(s) checked (soft). {total} total.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
