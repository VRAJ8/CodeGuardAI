// Security posture scoring, ported from backend/codeguard/scoring.py. Penalties decay exponentially, so one
// critical hurts a lot but a repo with 200 low findings doesn't drop below a repo with 5 criticals.
import { RULES, pyRound, pySum } from "./lang";

const S = RULES.scoring;
const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

export function securityScore(findings) {
  const penalty = findings.reduce((sum, f) => sum + (own(S.weights, f.severity) ? S.weights[f.severity] : 1), 0);
  return 100 * Math.exp(-penalty / S.decay);
}

/** Files with no risk count as perfectly healthy. */
export function healthScore(risks, totalFiles) {
  if (totalFiles === 0) return 100.0;
  const health = 100 - (pySum(risks.map((r) => r.risk_score)) / totalFiles) * S.health_per_risk;
  return health > 0 ? health : 0.0;
}

export const gradeFor = (score) => (S.grades.find(([threshold]) => score >= threshold) || [null, "F"])[1];

/** [score, grade, {security, health}] */
export function overall(findings, risks, totalFiles) {
  const sec = securityScore(findings);
  const health = healthScore(risks, totalFiles);
  const score = pyRound(S.blend[0] * sec + S.blend[1] * health, 1);
  return [score, gradeFor(score), { security: pyRound(sec, 1), health: pyRound(health, 1) }];
}
