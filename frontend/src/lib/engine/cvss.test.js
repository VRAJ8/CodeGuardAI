/** @jest-environment node */
import GOLDEN from "./parity.golden.json";
import { cvss3BaseScore, roundHalfEven, roundup, severityFromScore } from "./cvss";

const D = GOLDEN.vectors.dependencies;

/** Every combination of the metric values, last metric varying fastest (itertools.product order). */
function* product(metrics, prefix = []) {
  if (prefix.length === metrics.length) {
    yield prefix;
    return;
  }
  for (const value of metrics[prefix.length][1]) yield* product(metrics, [...prefix, value]);
}

describe("cvss", () => {
  test("cvss3_base_score vectors, including malformed ones", () => {
    expect(D.cvss3_base_score.map(([v]) => [v, cvss3BaseScore(v)])).toEqual(D.cvss3_base_score);
    expect([cvss3BaseScore(null), cvss3BaseScore(undefined), cvss3BaseScore(3.1)]).toEqual([null, null, null]);
  });

  test("all 2592 CVSS:3.1 base vectors", () => {
    const { metrics, scores } = D.cvss3_exhaustive;
    const got = [...product(metrics)].map((combo) =>
      cvss3BaseScore(`CVSS:3.1/${combo.map((value, i) => `${metrics[i][0]}:${value}`).join("/")}`));
    expect(got).toHaveLength(2592);
    expect(got).toEqual(scores);
  });

  test("severity_from_score", () => {
    expect(D.severity_from_score.map(([s]) => [s, severityFromScore(s)])).toEqual(D.severity_from_score);
  });

  test("round() to an integer is half to even", () => {
    expect([0.5, 1.5, 2.5, -0.5, -1.5, -2.5, 2.4, 2.6].map(roundHalfEven)).toEqual([0, 2, 2, -0, -2, -2, 2, 3]);
    expect([roundup(4.0), roundup(4.02), roundup(4.000001)]).toEqual([4.0, 4.1, 4.0]);
  });
});
