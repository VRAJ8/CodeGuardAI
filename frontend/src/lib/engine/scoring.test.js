/** @jest-environment node */
import GOLDEN from "./parity.golden.json";
import { pyRound } from "./lang";
import { gradeFor, healthScore, overall, securityScore } from "./scoring";

const S = GOLDEN.vectors.scoring;
const findings = (severities) => severities.map((severity) => ({ severity }));
const risks = (scores) => scores.map((risk_score) => ({ risk_score }));
const close = (got, want) => Math.abs(pyRound(got, 10) - want) < 1e-9;

describe("scoring", () => {
  test("security_score", () => {
    expect(S.security_score_rounded10.filter(([sevs, x]) => !close(securityScore(findings(sevs)), x))).toEqual([]);
  });

  test("health_score", () => {
    expect(S.health_score_rounded10.filter(([scores, n, x]) => !close(healthScore(risks(scores), n), x))).toEqual([]);
  });

  test("overall (score, grade, parts) rounds like Python", () => {
    expect(S.overall.map((v) => overall(findings(v.severities), risks(v.risk_scores), v.total_files))).toEqual(S.overall.map((v) => v.result));
  });

  test("grade_for", () => {
    expect(S.grade_for.map(([s]) => [s, gradeFor(s)])).toEqual(S.grade_for);
  });
});
