/** @jest-environment node */
import GOLDEN from "./parity.golden.json";
import { analyzeFile, rank } from "./complexity";

const V = GOLDEN.vectors.complexity;

describe("complexity", () => {
  test("rank matches radon's cc_rank", () => {
    expect(V.rank.map(([cc]) => [cc, rank(cc)])).toEqual(V.rank);
  });

  test("analyze_file(..., heuristic=True) vectors", () => {
    V.analyze_file.forEach((v) => {
      expect([v.path, analyzeFile(v.content, v.path, v.language)]).toEqual([v.path, v.risk]);
    });
  });

  test("an exact tie rounds half to even, as round(1.125, 2) == 1.12 in Python", () => {
    // 8 functions, 1 decision: avg 1.125. Expected values from analyze_file(src, "a.js", "javascript", heuristic=True).
    const src = [...Array.from({ length: 8 }, (_, i) => `function f${i}() {}`), "if (x) {}"].join("\n");
    expect(analyzeFile(src, "a.js", "javascript")).toMatchObject({ cyclomatic: 1.12, max_cyclomatic: 2, lines: 9 });
  });
});
