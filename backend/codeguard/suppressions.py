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

MARKER = "codeguard-ignore"
TOKEN = re.compile(r"codeguard-ignore(?P<next>-next-line)?(?![\w-])")
LEADERS = ("<!--", "//", "/*", "#", "--")
# A comment leader must start the line or follow whitespace/punctuation (so "...abc#codeguard-ignore" in a URL is not one).
LEADER_PREFIX = set(" \t;{}(),")
CLOSERS = ("*/}", "*/", "-->")
RULE = r"[A-Za-z][A-Za-z0-9_.\-]*[A-Za-z0-9]"
# Applied after the comment closer is stripped. No nested quantifiers over the same characters, so matching is linear.
TAIL = re.compile(rf"^(?:\s*:\s*(?P<rules>{RULE}(?:\s*,\s*{RULE})*))?(?:\s+--(?P<why>.*))?$")
MAX_MARKER_LINE = 2000  # longer lines (minified bundles) are never searched for markers
ALL = "*"
ESCAPED = re.compile(r"\\.")  # a backslash escape, dropped before counting quotes
QUOTES = ('"', "'", "`")
MULTILINE_DELIMS = {"python": ('"""', "'''"), "javascript": ("`",), "typescript": ("`",)}
MALFORMED = "malformed codeguard-ignore marker ignored (expected 'codeguard-ignore[-next-line][: RULE, ...] [-- reason]')"


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
    unescaped = ESCAPED.sub("", prefix)
    return any(unescaped.count(q) % 2 for q in QUOTES)


def _multiline_string_lines(lines: List[str], language: str) -> Set[int]:
    """1-based numbers of lines that *start* inside a multi-line string (Python triple quotes, JS template
    literals). Markers on those lines are string content, so they are ignored (fail closed)."""
    inside: Set[int] = set()
    delims = MULTILINE_DELIMS.get(language)
    if not delims:
        return inside
    open_delim = None
    for n, line in enumerate(lines, 1):
        if open_delim:
            inside.add(n)
        text = ESCAPED.sub("", line)
        for d in delims:
            if open_delim and d != open_delim:
                continue
            if text.count(d) % 2:
                open_delim = None if open_delim else d
    return inside


def _strip_closer(tail: str) -> str:
    tail = tail.rstrip()
    for closer in CLOSERS:
        if tail.endswith(closer):
            return tail[: -len(closer)].rstrip()
    return tail


def parse(content: str, path: str = "", language: str = "") -> ParseResult:
    out = ParseResult()
    if MARKER not in content:
        return out
    lines = content.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    in_multiline = _multiline_string_lines(lines, language)
    for lineno, line in enumerate(lines, 1):
        if lineno in in_multiline or len(line) > MAX_MARKER_LINE or MARKER not in line:
            continue
        for m in TOKEN.finditer(line):
            before = line[: m.start()].rstrip()
            leader = next((ld for ld in LEADERS if before.endswith(ld)), None)
            if leader is None:
                continue
            ahead = before[: -len(leader)]
            if (ahead and ahead[-1] not in LEADER_PREFIX) or _in_string(ahead):
                continue  # URL fragment, lookalike word, or a marker inside a string literal
            tail = TAIL.match(_strip_closer(line[m.end():]))
            if not tail:
                out.warnings.append(f"{path}:{lineno}: {MALFORMED}")
                break
            rules = {r.strip().upper() for r in tail.group("rules").split(",")} if tail.group("rules") else {ALL}
            target = lineno + 1 if m.group("next") else lineno
            out.by_line.setdefault(target, []).append(
                Directive(rules=rules, marker_line=lineno, justification=(tail.group("why") or "").strip()))
            break  # one directive per line
    return out


def apply(findings: List[Finding], files: List[SourceFile]) -> Tuple[List[Finding], List[Finding], List[str]]:
    """Split findings into (active, suppressed). Suppressed ones get a `suppression` record."""
    by_path = {f.path: f for f in files}
    parsed: Dict[str, ParseResult] = {}
    warnings: List[str] = []
    for f in files:
        if MARKER in f.content:
            parsed[f.path] = parse(f.content, f.path, f.language)
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
