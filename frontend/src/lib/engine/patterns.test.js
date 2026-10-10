/** @jest-environment node */
import GOLDEN from "./parity.golden.json";
import { RULES } from "./lang";
import { isComment, overLimit, owaspForCwe, scanPatterns } from "./patterns";

const V = GOLDEN.vectors.patterns;
const pub = (findings) => findings.map(({ fp_basis: _, ...f }) => f);

describe("patterns", () => {
  test("_is_comment", () => {
    expect(V.is_comment.map(([line]) => [line, isComment(line)])).toEqual(V.is_comment);
  });

  test("scan_patterns vectors (scanner output, before the engine re-fingerprints)", () => {
    V.scan_patterns.forEach((v) => {
      expect(pub(scanPatterns(v.content, v.path, v.language, v.skip_bandit_overlap))).toEqual(v.findings);
    });
  });

  test("skip_bandit_overlap drops the Python rules Bandit covers, only for Python", () => {
    const line = "eval(x)\n";
    expect(scanPatterns(line, "a.py", "python", true)).toEqual([]);
    expect(scanPatterns(line, "a.py", "python", false).map((f) => f.rule_id)).toEqual(["CG-EVAL"]);
    expect(scanPatterns(line, "a.js", "javascript", true).map((f) => f.rule_id)).toEqual(["CG-EVAL"]);
    expect(scanPatterns(line, "a.json", "json")).toEqual([]);
  });

  test("lines longer than max_line code points are skipped", () => {
    const astral = String.fromCodePoint(0x1f600); // two UTF-16 units, one code point
    const fits = `eval(x)${astral.repeat(RULES.patterns.max_line - 7)}`;
    expect(overLimit(fits, RULES.patterns.max_line)).toBe(false);
    expect(scanPatterns(fits, "a.js", "javascript")).toHaveLength(1);
    expect(scanPatterns(`${fits}x`, "a.js", "javascript")).toEqual([]);
  });

  test("the cached regexes are not global, so one line's match never leaks into the next", () => {
    const content = "eval(a)\neval(b)\neval(c)\n";
    expect(scanPatterns(content, "a.js", "javascript").map((f) => f.line_number)).toEqual([1, 2, 3]);
  });

  test("owaspForCwe uses the taxonomy", () => {
    expect([owaspForCwe("CWE-798"), owaspForCwe("cwe-89"), owaspForCwe("918"), owaspForCwe("CWE-9999"), owaspForCwe("x"), owaspForCwe(null)])
      .toEqual(["A07:2021", "A03:2021", "A10:2021", null, null, null]);
  });
});
