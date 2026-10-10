/** @jest-environment node */
import GOLDEN from "./parity.golden.json";
import { pyCompare } from "./engine";
import { applySuppressions, parseSuppressions } from "./suppressions";

/** ParseResult as browser_export dumps it: lines in order, rules sorted. */
const dump = ({ byLine, warnings }) => ({
  by_line: Object.fromEntries([...byLine].sort(([a], [b]) => a - b).map(([n, ds]) =>
    [String(n), ds.map((d) => ({ rules: [...d.rules].sort(pyCompare), marker_line: d.marker_line, justification: d.justification }))])),
  warnings,
});

describe("suppressions", () => {
  test("parse vectors", () => {
    GOLDEN.vectors.suppressions.forEach((v) => {
      expect([v.content, dump(parseSuppressions(v.content, v.path, v.language))])
        .toEqual([v.content, { by_line: v.by_line, warnings: v.warnings }]);
    });
  });

  test("apply: rule-scoped markers suppress only their rules; suppressed copies keep everything else", () => {
    const content = "eval(a) // codeguard-ignore: CG-EVAL -- reviewed\neval(b) // codeguard-ignore: OTHER\n";
    const files = [{ path: "a.js", content, language: "javascript", lines: 3 }];
    const f = (line, rule = "CG-EVAL") => ({ rule_id: rule, file_path: "a.js", line_number: line, fp_basis: "kept", suppression: null });
    const [active, suppressed, warnings] = applySuppressions([f(1), f(2), f(1, "cg-other"), { ...f(1), file_path: "b.js" }], files);
    expect(active.map((x) => [x.line_number, x.file_path])).toEqual([[2, "a.js"], [1, "a.js"], [1, "b.js"]]);
    expect(suppressed).toEqual([{ ...f(1), suppression: { kind: "inSource", justification: "reviewed", marker_line: 1 } }]);
    expect(warnings).toEqual([]);
  });

  test("apply: findings without a line are never suppressed", () => {
    const files = [{ path: "a.js", content: "// codeguard-ignore\n", language: "javascript", lines: 2 }];
    const [active, suppressed] = applySuppressions([{ rule_id: "X", file_path: "a.js", line_number: null }], files);
    expect([active.length, suppressed.length]).toEqual([1, 0]);
  });
});
