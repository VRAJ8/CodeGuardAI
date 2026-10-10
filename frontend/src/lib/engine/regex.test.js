/** @jest-environment node */
import { countMatches, escapeRegex, globalRegex, literalRegex } from "./regex";

describe("regex helpers", () => {
  test("escapeRegex makes every character literal under the u flag", () => {
    const text = "a.b*c+d?e^f$g\\h(i)j[k]l{m}n|o/p-q#r s~t&u";
    const re = new RegExp(`^${escapeRegex(text)}$`, "u");
    expect(re.test(text)).toBe(true);
    expect(re.test(text.replace(".", "X"))).toBe(false);
  });

  test("countMatches is len(findall) and does not depend on earlier calls", () => {
    const re = globalRegex({ pattern: "ab", flags: "u" });
    expect([countMatches(re, "ab ab ab"), countMatches(re, "ab"), countMatches(re, "")]).toEqual([3, 1, 0]);
    expect(re.lastIndex).toBe(0);
  });

  test("literalRegex splices a literal between two specs", () => {
    const re = literalRegex({ pattern: "^\\[", flags: "u" }, "a+b", { pattern: "\\]$", flags: "u" });
    expect([re.test("[a+b]"), re.test("[aab]"), re.flags]).toEqual([true, false, "u"]);
  });
});
