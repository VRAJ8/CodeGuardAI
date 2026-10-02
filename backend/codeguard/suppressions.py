"""Inline suppression comments, in the spirit of Bandit's `# nosec` and Semgrep's `nosemgrep`.

    risky_call()  # codeguard-ignore
    risky_call()  # codeguard-ignore: CG-EVAL, BANDIT-B307
    // codeguard-ignore-next-line: CG-SQLI-CONCAT -- reviewed, demo string only
    {/* codeguard-ignore-next-line */}

Design rules (a suppression mechanism in a security tool must fail closed):
- A marker counts only directly after a comment leader (#, //, /*, <!--, --), outside string
  literals, and as a whole word: `codeguard-ignored`, `nocodeguard-ignore`, or a marker inside
  "a string" are not markers.
- Anything malformed after the marker is rejected and reported as a warning, never widened into a
  suppress-all. A bare marker suppresses the whole line; a rule list scopes it (case-insensitive).
- Suppressed findings are kept, not deleted: they carry a `suppression` record, stay out of the
  score / severity counts / --fail-on, and are exported as SARIF results with `suppressions`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .models import Finding, SourceFile, Suppression

TOKEN = re.compile(r"codeguard-ignore(?P<next>-next-line)?(?![\w-])")
LEADERS = ("#", "//", "/*", "<!--", "--")
RULE = r"[A-Za-z][A-Za-z0-9_.\-]*[A-Za-z0-9]"
# What may follow the marker: optional ": RULE, RULE", optional "-- justification", optional comment closer.
TAIL = re.compile(
    rf"^(?:\s*:\s*(?P<rules>{RULE}(?:\s*,\s*{RULE})*))?"
    r"(?:\s+--\s*(?P<why>.*?))?"
    r"\s*(?:\*/\s*\}?|-->)?\s*$"
)
ALL = "*"


@dataclass
class Directive:
    rules: Set[str]
    marker_line: int
    justification: str = ""


@dataclass
class ParseResult:
    by_line: Dict[int, List[Directive]] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


def _in_string(prefix: str) -> bool:
    """Heuristic: an odd number of unescaped quotes before the comment leader means we're in a literal."""
    unescaped = re.sub(r"\\.", "", prefix)
    return any(unescaped.count(q) % 2 for q in ('"', "'", "`"))


def parse(content: str, path: str = "") -> ParseResult:
    out = ParseResult()
    if "codeguard-ignore" not in content:
        return out
    for lineno, line in enumerate(content.split("\n"), 1):
        line = line.rstrip("\r")
        for m in TOKEN.finditer(line):
            before = line[: m.start()].rstrip()
            leader = next((ld for ld in LEADERS if before.endswith(ld)), None)
            if leader is None or _in_string(before[: -len(leader)]):
                continue  # not a comment marker (string content, prose, URL, lookalike word)
            tail = TAIL.match(line[m.end():])
            if not tail:
                out.warnings.append(f"{path}:{lineno}: malformed codeguard-ignore marker ignored "
                                    f"(expected 'codeguard-ignore[-next-line][: RULE, ...] [-- reason]')")
                continue
            rules = {r.strip().upper() for r in tail.group("rules").split(",")} if tail.group("rules") else {ALL}
            target = lineno + 1 if m.group("next") else lineno
            out.by_line.setdefault(target, []).append(
                Directive(rules=rules, marker_line=lineno, justification=(tail.group("why") or "").strip()))
    return out


def apply(findings: List[Finding], files: List[SourceFile]) -> Tuple[List[Finding], List[Finding], List[str]]:
    """Split findings into (active, suppressed). Suppressed ones get a `suppression` record."""
    by_path = {f.path: f for f in files}
    parsed: Dict[str, ParseResult] = {}
    warnings: List[str] = []
    for f in files:
        if "codeguard-ignore" in f.content:
            parsed[f.path] = parse(f.content, f.path)
            warnings += parsed[f.path].warnings
    active, suppressed = [], []
    for f in findings:
        directives = parsed.get(f.file_path)
        hit: Optional[Directive] = None
        if directives and f.line_number is not None and f.file_path in by_path:
            hit = next((d for d in directives.by_line.get(f.line_number, [])
                        if ALL in d.rules or f.rule_id.upper() in d.rules), None)
        if hit:
            suppressed.append(f.model_copy(update={"suppression": Suppression(
                justification=hit.justification, marker_line=hit.marker_line)}))
        else:
            active.append(f)
    return active, suppressed, warnings
