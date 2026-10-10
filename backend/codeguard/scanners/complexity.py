"""Code-health analysis.

Python files get real metrics from Radon (McCabe cyclomatic complexity and the
Maintainability Index) plus AST nesting depth. Other languages use a
decision-point heuristic and brace-depth nesting.
"""
from __future__ import annotations

import ast
import re
from typing import List, Tuple

from ..models import BugRisk, FunctionMetric

try:
    from radon.complexity import cc_rank, cc_visit
    from radon.metrics import mi_visit
    RADON = True
except ImportError:  # pragma: no cover
    RADON = False

NESTING_NODES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try, ast.FunctionDef,
                 ast.AsyncFunctionDef, ast.ClassDef, ast.Match) if hasattr(ast, "Match") else \
                (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try, ast.FunctionDef,
                 ast.AsyncFunctionDef, ast.ClassDef)

DECISION = re.compile(r"\b(if|for|while|case|catch|elif|except)\b|&&|\|\||\?\?|(?<![?.])\?(?![.?:])")
FUNC = re.compile(r"\bfunction\b|=>|\bfunc\s+\w|\bdef\s+\w|\bfn\s+\w|^\s*(public|private|protected|static)\s+[\w<>\[\]]+\s+\w+\s*\(",
                  re.MULTILINE)
EMPTY_CATCH = re.compile(r"catch\s*(\([^)]*\))?\s*\{\s*\}")
COMMENTS = re.compile(r"//.*|/\*[\s\S]*?\*/")
STRING_LITERAL = re.compile(r"(['\"`])(?:\\.|(?!\1).)*\1")
TODO = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b")
RANK_CUTOFFS = ((5, "A"), (10, "B"), (20, "C"), (30, "D"), (40, "E"))  # radon's cc_rank; anything higher is "F"

# Risk signals as (threshold, risk points). The browser engine reads these through browser_export.
LARGE_FILE, MODERATE_FILE = (500, 20), (300, 10)  # more than N lines
VERY_HIGH_CC, HIGH_CC = (20, 30), (10, 15)  # most complex block above N
HIGH_AVG_CC = (10, 10)  # average complexity per block above N
LOW_MI, MODERATE_MI = (20, 20), (50, 10)  # Maintainability Index below N (Radon only)
DEEP_NESTING, NESTED = (5, 15), (4, 8)  # nesting depth above N
LONG_LINE, LONG_LINES = 120, (10, 5)  # more than N lines longer than LONG_LINE characters
TODOS = (5, 10)  # more than N TODO/FIXME markers
EMPTY_HANDLER = (15, 30)  # points per empty exception handler, and their cap
RISK_LEVELS = ((50, "high"), (25, "medium"))  # risk score above N; otherwise "low"


def _rank(cc: int) -> str:
    if RADON:
        return cc_rank(cc)
    return next((rank for limit, rank in RANK_CUTOFFS if cc <= limit), "F")


def _py_nesting(tree: ast.AST) -> int:
    def depth(node: ast.AST, d: int) -> int:
        best = d
        for child in ast.iter_child_nodes(node):
            best = max(best, depth(child, d + 1 if isinstance(child, NESTING_NODES) else d))
        return best
    return depth(tree, 0)


def _py_empty_handlers(tree: ast.AST) -> int:
    n = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            body_is_pass = all(isinstance(s, ast.Pass) for s in node.body)
            if body_is_pass:
                n += 1
    return n


def _brace_depth(content: str) -> int:
    depth = best = 0
    for ch in STRING_LITERAL.sub("", content):
        if ch == "{":
            depth += 1
            best = max(best, depth)
        elif ch == "}":
            depth = max(0, depth - 1)
    return best


def _python_metrics(content: str) -> Tuple[float, int, float, int, int, List[FunctionMetric]]:
    tree = ast.parse(content)
    blocks = cc_visit(content) if RADON else []
    ccs = [b.complexity for b in blocks] or [1]
    mi = mi_visit(content, multi=True) if RADON else None
    hotspots = sorted(
        (FunctionMetric(name=getattr(b, "fullname", b.name), line=b.lineno, complexity=b.complexity, rank=_rank(b.complexity))
         for b in blocks if b.complexity > 5),
        key=lambda h: -h.complexity,
    )[:5]
    # Nesting counts the def/class wrappers too, so subtract one level of baseline structure.
    return sum(ccs) / len(ccs), max(ccs), mi, max(_py_nesting(tree) - 1, 0), _py_empty_handlers(tree), hotspots


def _generic_metrics(content: str) -> Tuple[float, int, None, int, int, List[FunctionMetric]]:
    stripped = COMMENTS.sub("", content)
    decisions = len(DECISION.findall(stripped))
    funcs = max(len(FUNC.findall(stripped)), 1)
    avg = 1 + decisions / funcs
    return avg, int(avg * 2), None, max(_brace_depth(stripped) - 1, 0), len(EMPTY_CATCH.findall(stripped)), []


def analyze_file(content: str, file_path: str, language: str, heuristic: bool = False) -> BugRisk:
    """`heuristic=True` measures Python with the generic heuristic too (what the in-browser engine does,
    where Radon and the ast module are unavailable)."""
    lines = content.split("\n")
    issues: List[str] = []
    score = 0.0

    try:
        avg_cc, max_cc, mi, nesting, empty, hotspots = (
            _python_metrics(content) if language == "python" and not heuristic else _generic_metrics(content)
        )
    except (SyntaxError, ValueError, RecursionError):
        avg_cc, max_cc, mi, nesting, empty, hotspots = 1.0, 1, None, 0, 0, []
        issues.append("File could not be parsed")

    n = len(lines)
    if n > LARGE_FILE[0]:
        score += LARGE_FILE[1]; issues.append(f"Large file ({n} lines) — consider splitting by responsibility")
    elif n > MODERATE_FILE[0]:
        score += MODERATE_FILE[1]; issues.append(f"Moderately large file ({n} lines)")

    if max_cc > VERY_HIGH_CC[0]:
        score += VERY_HIGH_CC[1]; issues.append(f"Very high cyclomatic complexity (max {max_cc}, rank {_rank(max_cc)})")
    elif max_cc > HIGH_CC[0]:
        score += HIGH_CC[1]; issues.append(f"High cyclomatic complexity (max {max_cc}, rank {_rank(max_cc)})")
    if avg_cc > HIGH_AVG_CC[0]:
        score += HIGH_AVG_CC[1]; issues.append(f"Average complexity per block is {avg_cc:.1f}")

    if mi is not None:
        if mi < LOW_MI[0]:
            score += LOW_MI[1]; issues.append(f"Low Maintainability Index ({mi:.0f}/100)")
        elif mi < MODERATE_MI[0]:
            score += MODERATE_MI[1]; issues.append(f"Moderate Maintainability Index ({mi:.0f}/100)")

    if nesting > DEEP_NESTING[0]:
        score += DEEP_NESTING[1]; issues.append(f"Deeply nested logic (depth {nesting})")
    elif nesting > NESTED[0]:
        score += NESTED[1]; issues.append(f"Nested logic (depth {nesting})")

    long_lines = sum(1 for line in lines if len(line) > LONG_LINE)
    if long_lines > LONG_LINES[0]:
        score += LONG_LINES[1]; issues.append(f"{long_lines} lines exceed {LONG_LINE} characters")

    todos = sum(1 for line in lines if TODO.search(line))
    if todos > TODOS[0]:
        score += TODOS[1]; issues.append(f"{todos} TODO/FIXME markers")

    if empty:
        score += min(EMPTY_HANDLER[0] * empty, EMPTY_HANDLER[1]); issues.append(f"{empty} empty exception handler(s) swallow errors")

    score = min(score, 100.0)
    maintainability = mi if mi is not None else max(0.0, 100 - score)
    return BugRisk(
        file_path=file_path,
        risk_score=round(score, 1),
        complexity=next((level for limit, level in RISK_LEVELS if score > limit), "low"),
        issues=issues,
        language=language,
        lines=n,
        cyclomatic=round(avg_cc, 2),
        max_cyclomatic=int(max_cc),
        maintainability=round(maintainability, 1),
        hotspots=hotspots,
    )
