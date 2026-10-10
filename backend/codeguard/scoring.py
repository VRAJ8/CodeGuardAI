"""Security posture scoring.

Penalties decay exponentially so one critical hurts a lot, but a repo with 200 low
findings doesn't drop below a repo with 5 criticals.
"""
import math
from typing import Dict, List, Tuple

from .models import BugRisk, Finding

WEIGHTS = {"critical": 15, "high": 8, "medium": 3, "low": 1}
DECAY = 60  # penalty points that cut the security score to 100/e
HEALTH_PER_RISK = 1.5  # health points lost per point of average per-file risk
BLEND = (0.7, 0.3)  # overall = security * 0.7 + code health * 0.3
GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"))  # below the last cutoff: "F"


def security_score(findings: List[Finding]) -> float:
    penalty = sum(WEIGHTS.get(f.severity, 1) for f in findings)
    return 100 * math.exp(-penalty / DECAY)


def health_score(risks: List[BugRisk], total_files: int) -> float:
    if total_files == 0:
        return 100.0
    # Files with no risk count as perfectly healthy.
    total = sum(r.risk_score for r in risks)
    return max(0.0, 100 - total / total_files * HEALTH_PER_RISK)


def grade_for(score: float) -> str:
    for threshold, grade in GRADES:
        if score >= threshold:
            return grade
    return "F"


def overall(findings: List[Finding], risks: List[BugRisk], total_files: int) -> Tuple[float, str, Dict[str, float]]:
    sec = security_score(findings)
    health = health_score(risks, total_files)
    score = round(BLEND[0] * sec + BLEND[1] * health, 1)
    return score, grade_for(score), {"security": round(sec, 1), "health": round(health, 1)}
