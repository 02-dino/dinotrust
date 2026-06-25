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


def load_pattern_rule_ids(patterns_path: Path) -> set[str]:
    data = json.loads(patterns_path.read_text(encoding="utf-8"))
    ids = {p["rule_id"] for p in data.get("patterns", [])}
    # rule_ids that are intentionally agent-judged (not in patterns) are declared
    # in _meta.agent_judged_only — they still must exist in the rules file.
    ids |= set(data.get("_meta", {}).get("agent_judged_only", []))
    return ids


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

    pattern_ids = load_pattern_rule_ids(args.patterns)
    rule_ids = load_rule_ids_from_rules(args.rules)

    missing = sorted(pattern_ids - rule_ids)
    if missing:
        print("\u2717 DRIFT: rule_ids referenced by patterns.json but absent from security_rules.md:", file=sys.stderr)
        for m in missing:
            print(f"    - {m}", file=sys.stderr)
        print("\nFix: add the rule to security_rules.md, or correct the rule_id in patterns.json.", file=sys.stderr)
        return 1

    print(f"\u2713 taxonomy OK \u2014 {len(pattern_ids)} rule_id(s) in patterns.json all present in security_rules.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
