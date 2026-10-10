/** @jest-environment node */
// Holds the whole engine to the Python one: parity.golden.json records what backend/codeguard reports on the corpus
// under browser semantics (python -m codeguard.browser_export), and scan() must reproduce it exactly.
import GOLDEN from "./parity.golden.json";
import { RULES, detectLanguage, makeSourceFile, shouldSkip } from "./lang";
import { dedupe, disambiguateFingerprints, pyCompare, scan } from "./engine";
import { ENGINE_VERSION, scan as indexScan, toCycloneDx, toSarif, makeSourceFile as indexMakeSourceFile } from "./index";

const OSV = GOLDEN.expected_osv;
const substitute = (text) =>
  Object.entries(GOLDEN.placeholders).reduce((t, [name, parts]) => t.split(name).join(parts.join("")), text);

/** The golden procedure: placeholders filled in, skip-listed and unknown paths dropped, then makeSourceFile. */
const corpusFiles = () => Object.entries(GOLDEN.corpus)
  .filter(([path]) => !shouldSkip(path) && detectLanguage(path))
  .map(([path, content]) => makeSourceFile(path, substitute(content)))
  .filter(Boolean);
const manifests = () => corpusFiles().filter((f) => OSV.manifests.includes(f.path));
const withoutVolatile = ({ duration_ms: _, ...report }) => report;

/** fetch over the golden's OSV mock, recording each request the way browser_export records httpx's. */
function mockFetch({ batchStatus = 200 } = {}) {
  const requests = [];
  const respond = (status, body) => ({ status, ok: status >= 200 && status < 300, json: async () => body });
  const fetchImpl = async (url, init = {}) => {
    if (url === RULES.dependencies.osv_batch) {
      const { queries } = JSON.parse(init.body);
      requests.push({ method: init.method, url, json: { queries } });
      if (batchStatus !== 200) return respond(batchStatus, { code: 14, message: "unavailable" });
      const ids = queries.map((q) => OSV.mock.batch[`${q.package.ecosystem}/${q.package.name}@${q.version}`]);
      return respond(200, { results: ids.map((v) => (v && v.length ? { vulns: v.map((id) => ({ id })) } : {})) });
    }
    requests.push({ method: init.method || "GET", url });
    const id = url.slice(url.lastIndexOf("/") + 1);
    return Object.prototype.hasOwnProperty.call(OSV.mock.vulns, id)
      ? respond(200, OSV.mock.vulns[id]) : respond(404, { code: 5, message: "Bug not found." });
  };
  return { fetchImpl, requests };
}

const normaliseReason = (errors) => errors.map((e) => e.replace(/\(.*\)$/s, "(<reason>)"));

describe("golden corpus", () => {
  test("loading yields exactly the files Python scans", () => {
    expect(corpusFiles().map(({ path, language, lines }) => ({ path, language, lines }))).toEqual(GOLDEN.expected.files);
  });

  test("scan() reproduces the Python report exactly (OSV off)", async () => {
    const fetchImpl = jest.fn();
    const report = await scan(corpusFiles(), { osv: false, fetchImpl });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(Object.keys(report).sort()).toEqual([...Object.keys(GOLDEN.expected.report), "duration_ms"].sort());
    expect(Number.isInteger(report.duration_ms) && report.duration_ms >= 0).toBe(true);
    // Field by field first, so a failure names the part that drifted.
    const got = withoutVolatile(report);
    Object.keys(GOLDEN.expected.report).forEach((key) => expect([key, got[key]]).toEqual([key, GOLDEN.expected.report[key]]));
    expect(got).toEqual(GOLDEN.expected.report);
    // toEqual ignores key order; Python's dict order is part of the output (most_common for the counts).
    expect(JSON.stringify(got)).toBe(JSON.stringify(GOLDEN.expected.report));
  });

  test("findings carry no internal fields", async () => {
    const report = await scan(corpusFiles(), { osv: false });
    const keys = Object.keys(GOLDEN.expected.report.security_issues[0]).sort();
    [...report.security_issues, ...report.suppressed_issues].forEach((f) => expect(Object.keys(f).sort()).toEqual(keys));
  });

  test("scan does not modify its input files", async () => {
    const files = corpusFiles();
    const before = JSON.stringify(files);
    await scan(files, { osv: false });
    expect(JSON.stringify(files)).toBe(before);
  });

  test("progress is reported as (stage, pct) with pct rising", async () => {
    const calls = [];
    await scan(corpusFiles(), { osv: false, onProgress: (stage, pct) => calls.push([stage, pct]) });
    expect(calls.length).toBeGreaterThanOrEqual(3);
    calls.forEach(([stage, pct]) => expect(typeof stage === "string" && Number.isInteger(pct)).toBe(true));
    expect(calls.map(([, pct]) => pct)).toEqual([...calls.map(([, pct]) => pct)].sort((a, b) => a - b));
    expect(calls.some(([stage]) => /Bandit|Semgrep/.test(stage))).toBe(false); // they never run in the browser
  });

  test("an empty scan", async () => {
    const report = await scan([], { osv: true, fetchImpl: jest.fn() });
    expect(withoutVolatile(report)).toEqual({
      metrics: { total_files: 0, total_lines: 0, languages: {}, avg_complexity: 0, maintainability_index: 100 },
      security_issues: [], bug_risks: [], dependencies: [], overall_score: 100, grade: "A",
      severity_counts: { critical: 0, high: 0, medium: 0, low: 0 }, owasp_counts: {}, scanner_counts: {},
      scanners_run: RULES.engine.scanners_run, suppressed: 0, suppressed_issues: [], errors: [], warnings: [],
    });
  });
});

describe("OSV (mocked fetch)", () => {
  test("success: the same requests, vulnerabilities and dependency findings as Python", async () => {
    const { fetchImpl, requests } = mockFetch();
    const report = await scan(manifests(), { osv: true, fetchImpl });
    expect(manifests().map((f) => f.path)).toEqual(OSV.manifests);
    expect(withoutVolatile(report)).toEqual(OSV.report);
    expect(JSON.stringify(withoutVolatile(report))).toBe(JSON.stringify(OSV.report));
    expect(report.scanners_run).toEqual([...RULES.engine.scanners_run, "osv"]);
    expect(report.security_issues.some((f) => f.scanner === "osv")).toBe(true);
    expect(report.dependencies.some((d) => d.vulnerabilities.length)).toBe(true);
    // One POST first (body compared as JSON), then the advisory-detail GETs, which run concurrently.
    const [post, ...gets] = requests;
    const [wantPost, ...wantGets] = OSV.requests;
    expect(post).toEqual(wantPost);
    expect(gets.map((r) => r.method)).toEqual(wantGets.map(() => "GET"));
    expect(gets.map((r) => r.url).sort()).toEqual(wantGets.map((r) => r.url).sort());
  });

  test("the exports of the OSV report match too", async () => {
    const { fetchImpl } = mockFetch();
    const report = await scan(manifests(), { osv: true, fetchImpl });
    expect(toSarif(report.security_issues, report.suppressed_issues)).toEqual(OSV.sarif);
    const { serialNumber, metadata: { timestamp, ...metadata }, ...bom } = toCycloneDx(report.dependencies, "parity");
    expect({ ...bom, metadata }).toEqual(OSV.cyclonedx);
    expect(serialNumber).toMatch(/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(timestamp).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?\+00:00$/);
  });

  test("outage (batch answers 503): fail closed exactly like the backend", async () => {
    const { fetchImpl } = mockFetch({ batchStatus: 503 });
    const report = await scan(manifests(), { osv: true, fetchImpl });
    expect({ ...withoutVolatile(report), errors: normaliseReason(report.errors) }).toEqual(OSV.outage);
    expect(report.errors[0]).toMatch(/^osv: dependency audit did not run \(.*503.*\)$/);
  });

  const failing = {
    "network error": async () => { throw new TypeError("NetworkError when attempting to fetch resource."); },
    "CORS block (fetch's TypeError)": async () => { throw new TypeError("Failed to fetch"); },
    "non-2xx batch answer": async () => ({ status: 429, ok: false, json: async () => ({}) }),
    "invalid JSON": async () => ({ status: 200, ok: true, json: async () => JSON.parse("<html>") }),
    "unexpected body": async () => ({ status: 200, ok: true, json: async () => ["not", "an", "object"] }),
    "results that are not a list": async () => ({ status: 200, ok: true, json: async () => ({ results: null }) }),
    "a vuln without an id": async () => ({ status: 200, ok: true, json: async () => ({ results: [{ vulns: [{}] }] }) }),
  };
  Object.entries(failing).forEach(([name, fetchImpl]) => {
    test(`${name}: an errors entry, no "osv" in scanners_run, nothing reported as clean or vulnerable`, async () => {
      const report = await scan(manifests(), { osv: true, fetchImpl });
      expect(report.errors).toHaveLength(1);
      expect(report.errors[0]).toMatch(/^osv: dependency audit did not run \(.+\)$/);
      expect(normaliseReason(report.errors)).toEqual(OSV.outage.errors);
      expect(report.scanners_run).toEqual(RULES.engine.scanners_run);
      expect(report.dependencies.every((d) => d.vulnerabilities.length === 0)).toBe(true);
      expect(report.security_issues.filter((f) => f.scanner === "osv")).toEqual([]);
      expect(withoutVolatile(report)).toEqual({ ...OSV.outage, errors: report.errors });
    });
  });

  test("a failing advisory-detail lookup fails the whole audit, leaving no partial results", async () => {
    const { fetchImpl: base } = mockFetch();
    const fetchImpl = async (url, init) => {
      if (url.endsWith("/PYSEC-2018-66")) throw new TypeError("Failed to fetch");
      return base(url, init);
    };
    const report = await scan(manifests(), { osv: true, fetchImpl });
    expect(normaliseReason(report.errors)).toEqual(OSV.outage.errors);
    expect(report.dependencies.every((d) => d.vulnerabilities.length === 0)).toBe(true);
  });

  test("a non-200 advisory detail keeps the bare id, as in Python", async () => {
    const { fetchImpl, requests } = mockFetch();
    await scan(manifests(), { osv: true, fetchImpl });
    expect(requests.some((r) => r.url.endsWith("/GHSA-0000-missing-detail"))).toBe(true);
  });

  test("no fetch available: an errors entry, not a crash", async () => {
    const report = await scan(manifests(), { osv: true, fetchImpl: null });
    expect(report.errors).toEqual(["osv: dependency audit did not run (fetch is not available)"]);
  });

  test("a lookup that never answers is aborted after the timeout and fails closed", async () => {
    let called;
    const fetchCalled = new Promise((resolve) => { called = resolve; });
    const fetchImpl = (url, init) => {
      called();
      return new Promise((_, reject) => init.signal.addEventListener("abort", () =>
        reject(Object.assign(new Error("The operation was aborted."), { name: "AbortError" }))));
    };
    jest.useFakeTimers();
    try {
      const pending = scan(manifests(), { osv: true, fetchImpl });
      await fetchCalled;
      jest.advanceTimersByTime(20000);
      const report = await pending;
      expect(normaliseReason(report.errors)).toEqual(OSV.outage.errors);
      expect(report.errors[0]).toContain("within 20 s");
    } finally {
      jest.useRealTimers();
    }
  });

  test("osv: false makes no request and records no error", async () => {
    const fetchImpl = jest.fn();
    const report = await scan(manifests(), { osv: false, fetchImpl });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(report.errors).toEqual([]);
    expect(report.scanners_run).toEqual(RULES.engine.scanners_run);
  });

  test("dependencies without a version: no request, but the audit counts as run", async () => {
    const fetchImpl = jest.fn();
    const files = [makeSourceFile("requirements.txt", "flask\nrequests>2\n")];
    const report = await scan(files, { osv: true, fetchImpl });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(report.scanners_run).toEqual([...RULES.engine.scanners_run, "osv"]);
    expect(report.errors).toEqual([]);
  });

  test("advisory details are capped at max_detail_lookups and run at most osv_concurrency at a time", async () => {
    const n = RULES.dependencies.max_detail_lookups + 5;
    const lines = Array.from({ length: n }, (_, i) => `pkg${i}==1.0.${i}`).join("\n");
    let inFlight = 0;
    let peak = 0;
    const gets = [];
    const fetchImpl = async (url, init = {}) => {
      if (init.method === "POST") {
        const { queries } = JSON.parse(init.body);
        return { status: 200, ok: true, json: async () => ({ results: queries.map((_, i) => ({ vulns: [{ id: `V-${i}` }] })) }) };
      }
      gets.push(url);
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 1));
      inFlight -= 1;
      const id = url.slice(url.lastIndexOf("/") + 1);
      return { status: 200, ok: true, json: async () => ({ id, summary: `about ${id}` }) };
    };
    const report = await scan([makeSourceFile("requirements.txt", lines)], { osv: true, fetchImpl });
    expect(gets).toHaveLength(RULES.dependencies.max_detail_lookups);
    expect(peak).toBeLessThanOrEqual(RULES.dependencies.osv_concurrency);
    expect(peak).toBeGreaterThan(1);
    const last = report.dependencies[n - 1];
    expect(last.vulnerabilities).toEqual([{ id: `V-${n - 1}`, aliases: [], summary: "", severity: "medium", cvss: null, fixed_in: null, url: null }]);
    expect(report.dependencies[0].vulnerabilities[0].summary).toBe("about V-0");
  });
});

describe("engine helpers", () => {
  test("pyCompare orders by code point, like Python's sorted()", () => {
    const astral = String.fromCodePoint(0x1f600);
    expect(["\uffff", astral, "a", "", "ab", "\ue000"].sort(pyCompare)).toEqual(["", "a", "ab", "\ue000", "\uffff", astral]);
    expect(pyCompare("x", "x")).toBe(0);
  });

  test("disambiguateFingerprints matches engine.disambiguate_fingerprints", () => {
    const family = GOLDEN.vectors.fingerprints.disambiguate.map((v) => ({ ...v, fingerprint: v.before }));
    disambiguateFingerprints(family);
    expect(family.map((f) => f.fingerprint)).toEqual(GOLDEN.vectors.fingerprints.disambiguate.map((v) => v.after));
  });

  test("dedupe keeps the more precise scanner, then the higher severity, in first-seen position", () => {
    const f = (scanner, severity, extra = {}) => ({ file_path: "a.py", line_number: 3, cwe: "CWE-78", rule_id: scanner, scanner, severity, ...extra });
    const kept = dedupe([f("patterns", "critical"), f("bandit", "low"), f("semgrep", "medium"), f("x", "critical", { line_number: 4 })]);
    expect(kept.map((k) => k.scanner)).toEqual(["x", "semgrep"]);
    expect(dedupe([f("patterns", "low"), f("patterns", "high")]).map((k) => k.severity)).toEqual(["high"]);
    expect(dedupe([f("patterns", "low", { cwe: null }), f("secrets", "low", { cwe: null })])).toHaveLength(2); // keyed by rule_id
  });

  test("index re-exports the contract and the browser engine version", () => {
    expect(ENGINE_VERSION).toBe(`browser-${RULES.version}`);
    expect(ENGINE_VERSION).toBe(RULES.engine.engine_version);
    expect(indexScan).toBe(scan);
    expect(indexMakeSourceFile).toBe(makeSourceFile);
  });
});
