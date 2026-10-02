"""Inline suppression comments, in the spirit of Bandit's `# nosec` and Semgrep's `nosemgrep`.

    risky_call()  # codeguard-ignore
    risky_call()  # codeguard-ignore: CG-EVAL, BANDIT-B307
    // codeguard-ignore-next-line: CG-SQLI-CONCAT -- reason
    {/* codeguard-ignore-next-line */}

A marker with no rule list silences every finding on that line; with a list, only those
rule ids. Suppressed findings are counted in the report so they are never invisible.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from .models import Finding, SourceFile

# Rule ids are upper-case tokens like CG-EVAL, BANDIT-B307, SEMGREP-flask-ssti, OSV-GHSA-...
MARKER = re.compile(r"codeguard-ignore(?P<next>-next-line)?(?:\s*:\s*(?P<rules>[A-Za-z0-9_.\-]+(?:\s*,\s*[A-Za-z0-9_.\-]+)*))?")
ALL = "*"


def _rules(match: re.Match) -> Set[str]:
    raw = match.group("rules")
    return {r.strip() for r in raw.split(",")} if raw else {ALL}


def directives(content: str) -> Dict[int, Set[str]]:
    """Map of 1-based line number -> rule ids suppressed on that line."""
    out: Dict[int, Set[str]] = {}
    for lineno, line in enumerate(content.split("\n"), 1):
        for m in MARKER.finditer(line):
            target = lineno + 1 if m.group("next") else lineno
            out.setdefault(target, set()).update(_rules(m))
    return out


def apply(findings: List[Finding], files: List[SourceFile]) -> Tuple[List[Finding], int]:
    """Drop suppressed findings. Returns (kept, suppressed_count)."""
    cache: Dict[str, Optional[Dict[int, Set[str]]]] = {}
    by_path = {f.path: f for f in files}
    kept, suppressed = [], 0
    for f in findings:
        if f.line_number is None:
            kept.append(f)
            continue
        if f.file_path not in cache:
            src = by_path.get(f.file_path)
            cache[f.file_path] = directives(src.content) if src and "codeguard-ignore" in src.content else None
        rules = (cache[f.file_path] or {}).get(f.line_number)
        if rules and (ALL in rules or f.rule_id in rules):
            suppressed += 1
        else:
            kept.append(f)
    return kept, suppressed
