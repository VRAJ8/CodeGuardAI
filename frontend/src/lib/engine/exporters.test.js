/** @jest-environment node */
import GOLDEN from "./parity.golden.json";
import { RULES, detectLanguage, makeSourceFile, shouldSkip } from "./lang";
import { scan } from "./engine";
import { owaspLabel, toCycloneDx, toSarif } from "./exporters";

const substitute = (text) =>
  Object.entries(GOLDEN.placeholders).reduce((t, [name, parts]) => t.split(name).join(parts.join("")), text);
const corpusFiles = () => Object.entries(GOLDEN.corpus)
  .filter(([path]) => !shouldSkip(path) && detectLanguage(path))
  .map(([path, content]) => makeSourceFile(path, substitute(content)))
  .filter(Boolean);
/** The volatile fields (parity.golden.json "volatile"), checked for shape and then dropped. */
function stable(bom) {
  const { serialNumber, metadata: { timestamp, ...metadata }, ...rest } = bom;
  expect(serialNumber).toMatch(/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  expect(timestamp).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?\+00:00$/);
  expect(Math.abs(Date.parse(timestamp) - Date.now())).toBeLessThan(60000);
  return { ...rest, metadata };
}

describe("exporters on the golden corpus", () => {
  let report;
  beforeAll(async () => {
    report = await scan(corpusFiles(), { osv: false });
  });

  test("SARIF 2.1.0 equals to_sarif(security_issues, suppressed_issues), key order included", () => {
    const sarif = toSarif(report.security_issues, report.suppressed_issues);
    expect(sarif).toEqual(GOLDEN.expected.sarif);
    expect(JSON.stringify(sarif)).toBe(JSON.stringify(GOLDEN.expected.sarif));
  });

  test("suppressed results carry SARIF suppressions", () => {
    const sarif = toSarif(report.security_issues, report.suppressed_issues);
    const suppressed = sarif.runs[0].results.filter((r) => r.suppressions);
    expect(suppressed).toHaveLength(report.suppressed_issues.length);
    expect(suppressed[0].suppressions[0]).toMatchObject({ kind: "inSource", status: "accepted" });
  });

  test("CycloneDX 1.5 equals to_cyclonedx(dependencies, 'parity') minus the volatile fields", () => {
    const bom = stable(toCycloneDx(report.dependencies, "parity"));
    expect(bom).toEqual(GOLDEN.expected.cyclonedx);
    // Key order too, with the volatile fields dropped where Python has them.
    const { serialNumber: _, ...rest } = toCycloneDx(report.dependencies, "parity");
    const { timestamp: __, ...metadata } = rest.metadata;
    expect(JSON.stringify({ ...rest, metadata })).toBe(JSON.stringify(GOLDEN.expected.cyclonedx));
  });
});

describe("exporters on vectors", () => {
  test("CycloneDX with vulnerabilities (ratings with and without a CVSS score)", () => {
    expect(stable(toCycloneDx(GOLDEN.vectors.dependencies.dependency_findings.deps, "parity"))).toEqual(GOLDEN.vectors.dependencies.cyclonedx);
  });

  test("each export gets a fresh serial number", () => {
    expect(toCycloneDx([], "p").serialNumber).not.toBe(toCycloneDx([], "p").serialNumber);
  });

  test("SARIF rule descriptions are cut at 1000 code points and findings without a line have no region", () => {
    const astral = String.fromCodePoint(0x1f600);
    const f = { rule_id: "R", scanner: "patterns", severity: "low", type: "t", description: astral.repeat(1001), file_path: "a",
      line_number: null, recommendation: "r", cwe: null, owasp: null, snippet: null, fingerprint: "f", suppression: null };
    const sarif = toSarif([f]);
    expect(Array.from(sarif.runs[0].tool.driver.rules[0].fullDescription.text)).toHaveLength(1000);
    expect(sarif.runs[0].results[0].locations[0].physicalLocation).toEqual({ artifactLocation: { uri: "a" } });
    expect(sarif.runs[0].tool.driver.rules[0].properties.tags).toEqual(["security", "patterns"]);
    expect(sarif.runs[0].tool.driver.semanticVersion).toBe(RULES.version);
  });

  test("owaspLabel", () => {
    expect([owaspLabel("A03:2021"), owaspLabel("A99:2021")]).toEqual(["A03 Injection", "A99"]);
  });
});
