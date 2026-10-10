/** @jest-environment node */
import GOLDEN from "./parity.golden.json";
import {
  cleanVersion, collectDependencies, compareVersionKeys, dependencyFindings, parseJsonLikePython, parsePackageJson, parseVuln,
  purl, versionKey,
} from "./dependencies";

const D = GOLDEN.vectors.dependencies;
const pub = (findings) => findings.map(({ fp_basis: _, ...f }) => f);
/** Maps back to plain objects, for comparing with JSON.parse. */
const plain = (x) => (x instanceof Map ? Object.fromEntries([...x].map(([k, v]) => [k, plain(v)])) : Array.isArray(x) ? x.map(plain) : x);

describe("manifests", () => {
  test("_clean_version", () => {
    expect(D.clean_version.map(([spec]) => [spec, cleanVersion(spec)])).toEqual(D.clean_version);
  });

  test("collect_dependencies over package.json, requirements*.txt and go.mod", () => {
    D.parse.forEach((v) => {
      const file = { path: v.path, content: v.content, language: "config", lines: v.content.split("\n").length };
      expect([v.path, v.content, collectDependencies([file])]).toEqual([v.path, v.content, v.deps]);
    });
  });

  test("manifest names are matched case-sensitively, like the backend", () => {
    const f = (path) => ({ path, content: '{"dependencies": {"a": "1.0.0"}}', language: "json", lines: 1 });
    expect(collectDependencies([f("x/Package.json"), f("x/package.json")]).map((d) => d.manifest)).toEqual(["x/package.json"]);
  });

  test("package.json keeps Python's key order and duplicate-key rule", () => {
    const deps = parsePackageJson('{"dependencies": {"b": "1.0.0", "10": "2.0.0", "a": "3.0.0", "b": "4.0.0", "2": "5"}}', "package.json");
    expect(deps.map((d) => [d.name, d.version])).toEqual([["b", "4.0.0"], ["10", "2.0.0"], ["a", "3.0.0"], ["2", "5"]]);
  });

  test("package.json shapes Python rejects or crashes on yield no dependencies here", () => {
    ["[1]", "null", '"x"', '{"dependencies": ["a"]}', '{"dependencies": "a"}', '{"dependencies": {"a": "1",}}', ""]
      .forEach((text) => expect([text, parsePackageJson(text, "package.json")]).toEqual([text, []]));
    expect(parsePackageJson('{"dependencies": {"a": NaN, "b": "1.0.0"}, "x": -Infinity}', "p").map((d) => d.name)).toEqual(["b"]);
  });
});

describe("json.loads grammar", () => {
  test("agrees with JSON.parse on valid JSON", () => {
    const docs = ['{"a": [1, -2.5e+3, true, false, null, "x\\u00e9\\ud83d\\ude00\\n\\"\\\\\\/"]}', " [ ] ", '{"":{}}', "0", '"\\ud800"',
      '{"k": {"nested": [[[]], {"z": 1e-7}]}}', '\t\n\r {"__proto__": 1}'];
    docs.forEach((text) => expect(plain(parseJsonLikePython(text))).toEqual(JSON.parse(text)));
  });

  test("rejects what Python rejects", () => {
    ["﻿{}", "{,}", "[1,]", "01", "1.", ".5", "+1", "'a'", '"a\tb"', '"\\x41"', '"\\u12G4"', "nul", "[1] 2", "{\"a\" 1}", "-",
      "[".repeat(5000)].forEach((text) => expect(() => parseJsonLikePython(text)).toThrow(SyntaxError));
  });

  test("accepts Python's NaN and Infinity literals", () => {
    expect(parseJsonLikePython("[NaN, Infinity, -Infinity]")).toEqual([NaN, Infinity, -Infinity]);
  });
});

describe("versions", () => {
  test("_version_key", () => {
    expect(D.version_key.map(([v]) => [v, versionKey(v).map(Number)])).toEqual(D.version_key);
  });

  test("keys compare like Python tuples, exactly for long numbers, Unicode digits included", () => {
    const cmp = (a, b) => compareVersionKeys(versionKey(a), versionKey(b));
    expect([cmp("1.0", "1.0.0"), cmp("1.10", "1.9"), cmp("2", "10"), cmp("1.0.0", "1.0.0"), cmp("", "0")]).toEqual([-1, 1, -1, 0, 0]);
    expect(cmp("1.90071992547409931", "1.90071992547409930")).toBe(1); // beyond 2^53
    expect(versionKey("١.٢٠")).toEqual(["1", "20"]); // int("١") == 1
    expect(versionKey(`${String.fromCodePoint(0x1d7d7)}.007`)).toEqual(["9", "7"]); // MATHEMATICAL BOLD DIGIT NINE
  });
});

describe("advisories", () => {
  test("parse_vuln vectors", () => {
    D.parse_vuln.forEach((v) => expect([v.detail.id, parseVuln(v.detail, v.dep)]).toEqual([v.detail.id, v.vuln]));
  });

  test("a 0.0 CVSS score never replaces an earlier one, and alone counts as no score (Python's `or`)", () => {
    // Expected values from the Python engine's parse_vuln on the same input.
    const dep = { name: "x", version: "1.0", ecosystem: "npm", manifest: "m", dev: false, vulnerabilities: [] };
    const zero = { score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N" };
    expect(parseVuln({ id: "X", severity: [{ score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" }, zero] }, dep))
      .toMatchObject({ cvss: 5.3, severity: "medium" });
    expect(parseVuln({ id: "Y", severity: [zero] }, dep)).toMatchObject({ cvss: null, severity: "medium" });
  });

  test("dependency_findings vectors", () => {
    const { deps, files, findings } = D.dependency_findings;
    expect(pub(dependencyFindings(deps, files))).toEqual(findings);
  });

  test("purl", () => {
    expect(D.purl.map(([name, version, ecosystem]) => [name, version, ecosystem, purl({ name, version, ecosystem })])).toEqual(D.purl);
  });

  test("a dependency name with regex syntax is matched literally on its manifest line", () => {
    const vuln = { id: "X", aliases: [], summary: "", severity: "low", cvss: null, fixed_in: null, url: null };
    const dep = { name: "a.b+c(d)", version: "1", ecosystem: "PyPI", manifest: "requirements.txt", dev: false, vulnerabilities: [vuln] };
    const files = [{ path: "requirements.txt", content: "aXb+c(d)==1\na.b+c(d)==1\n" }];
    expect(dependencyFindings([dep], files)[0].line_number).toBe(2);
  });
});
