"""Security posture scoring.

Penalties decay exponentially so one critical hurts a lot, but a repo with 200 low
findings doesn't drop below a repo with 5 criticals.
"""
import math
from typing import Dict, List, Tuple

from .models import BugRisk, Finding

WEIGHTS = {"critical": 15, "high": 8, "medium": 3, "low": 1}


def security_score(findings: List[Finding]) -> float:
    penalty = sum(WEIGHTS.get(f.severity, 1) for f in findings)
    return 100 * math.exp(-penalty / 60)


def health_score(risks: List[BugRisk], total_files: int) -> float:
    if total_files == 0:
        return 100.0
    # Files with no risk count as perfectly healthy.
    total = sum(r.risk_score for r in risks)
    return max(0.0, 100 - total / total_files * 1.5)


def grade_for(score: float) -> str:
    for threshold, grade in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= threshold:
            return grade
    return "F"


def overall(findings: List[Finding], risks: List[BugRisk], total_files: int) -> Tuple[float, str, Dict[str, float]]:
    sec = security_score(findings)
    health = health_score(risks, total_files)
    score = round(0.7 * sec + 0.3 * health, 1)
    return score, grade_for(score), {"security": round(sec, 1), "health": round(health, 1)}
