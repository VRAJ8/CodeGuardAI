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


def _rank(cc: int) -> str:
    if RADON:
        return cc_rank(cc)
    return "A" if cc <= 5 else "B" if cc <= 10 else "C" if cc <= 20 else "D" if cc <= 30 else "E" if cc <= 40 else "F"


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
    for ch in re.sub(r"(['\"`])(?:\\.|(?!\1).)*\1", "", content):
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
    stripped = re.sub(r"//.*|/\*[\s\S]*?\*/", "", content)
    decisions = len(DECISION.findall(stripped))
    funcs = max(len(FUNC.findall(stripped)), 1)
    avg = 1 + decisions / funcs
    return avg, int(avg * 2), None, max(_brace_depth(stripped) - 1, 0), len(EMPTY_CATCH.findall(stripped)), []


def analyze_file(content: str, file_path: str, language: str) -> BugRisk:
    lines = content.split("\n")
    issues: List[str] = []
    score = 0.0

    try:
        avg_cc, max_cc, mi, nesting, empty, hotspots = (
            _python_metrics(content) if language == "python" else _generic_metrics(content)
        )
    except (SyntaxError, ValueError, RecursionError):
        avg_cc, max_cc, mi, nesting, empty, hotspots = 1.0, 1, None, 0, 0, []
        issues.append("File could not be parsed")

    n = len(lines)
    if n > 500:
        score += 20; issues.append(f"Large file ({n} lines) — consider splitting by responsibility")
    elif n > 300:
        score += 10; issues.append(f"Moderately large file ({n} lines)")

    if max_cc > 20:
        score += 30; issues.append(f"Very high cyclomatic complexity (max {max_cc}, rank {_rank(max_cc)})")
    elif max_cc > 10:
        score += 15; issues.append(f"High cyclomatic complexity (max {max_cc}, rank {_rank(max_cc)})")
    if avg_cc > 10:
        score += 10; issues.append(f"Average complexity per block is {avg_cc:.1f}")

    if mi is not None:
        if mi < 20:
            score += 20; issues.append(f"Low Maintainability Index ({mi:.0f}/100)")
        elif mi < 50:
            score += 10; issues.append(f"Moderate Maintainability Index ({mi:.0f}/100)")

    if nesting > 5:
        score += 15; issues.append(f"Deeply nested logic (depth {nesting})")
    elif nesting > 4:
        score += 8; issues.append(f"Nested logic (depth {nesting})")

    long_lines = sum(1 for line in lines if len(line) > 120)
    if long_lines > 10:
        score += 5; issues.append(f"{long_lines} lines exceed 120 characters")

    todos = sum(1 for line in lines if re.search(r"\b(TODO|FIXME|HACK|XXX)\b", line))
    if todos > 5:
        score += 10; issues.append(f"{todos} TODO/FIXME markers")

    if empty:
        score += min(15 * empty, 30); issues.append(f"{empty} empty exception handler(s) swallow errors")

    score = min(score, 100.0)
    maintainability = mi if mi is not None else max(0.0, 100 - score)
    return BugRisk(
        file_path=file_path,
        risk_score=round(score, 1),
        complexity="high" if score > 50 else "medium" if score > 25 else "low",
        issues=issues,
        language=language,
        lines=n,
        cyclomatic=round(avg_cc, 2),
        max_cyclomatic=int(max_cc),
        maintainability=round(maintainability, 1),
        hotspots=hotspots,
    )
