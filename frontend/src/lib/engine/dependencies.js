// Software composition analysis, ported from backend/codeguard/scanners/dependencies.py: parses npm, PyPI and Go
// manifests, queries the OSV.dev batch API, then enriches each advisory with severity (GHSA rating or a computed
// CVSS v3 base score) and the earliest fixed version. Only package names and versions are sent, never code.
/* global globalThis */
import { RULES, compileRegex, pySlice, pySplitLines, pyStrip } from "./lang";
import { cvss3BaseScore, severityFromScore } from "./cvss";
import { literalRegex } from "./regex";
import { withFingerprint } from "./sha1";

const D = RULES.dependencies;
const VERSION = compileRegex(D.version);
const REQUIREMENT = compileRegex(D.requirement);
const GO_REQUIRE = compileRegex(D.go_require);
const REQUIREMENTS_FILE = compileRegex(D.requirements_file);
const VERSION_SPLIT = compileRegex(D.version_split);
const DIGITS = /^\p{Nd}+$/u;
const OSV_TIMEOUT_MS = 20000; // the backend's httpx timeout; a stalled lookup must not hang the scan

const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
const isDict = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
/** dict.get(key, default) on a parsed JSON object (anything that is not one has no keys). */
const get = (obj, key, dflt) => (isDict(obj) && own(obj, key) ? obj[key] : dflt);
/** Python truthiness of a parsed JSON value: [], {}, "", 0, false and null are falsy. */
const truthy = (x) => (Array.isArray(x) ? x.length > 0 : isDict(x) ? Object.keys(x).length > 0 : Boolean(x) || Number.isNaN(x));
const list = (x) => (Array.isArray(x) ? x : []);

const dependency = (name, version, ecosystem, manifest, dev = false) =>
  ({ name, version, ecosystem, manifest, dev, vulnerabilities: [] });

// ------------------------------------------------------------------------------------------------ manifests

export function cleanVersion(spec) {
  const m = VERSION.exec(spec || "");
  if (!m || D.non_registry.some((x) => spec.includes(x))) return null;
  return m[0];
}

const ESCAPES = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?/y;
const LITERALS = [["null", null], ["true", true], ["false", false], ["NaN", NaN], ["Infinity", Infinity], ["-Infinity", -Infinity]];
const MAX_DEPTH = 900; // Python's recursion limit stops the scanner near here

/** json.loads with Python's grammar (NaN and Infinity allowed, a leading BOM rejected) and dict semantics: objects
 *  become Maps, so key order and duplicate keys behave as in Python (last value wins, first position kept), where a
 *  plain object would hoist integer-like keys. Throws SyntaxError like json.JSONDecodeError. */
export function parseJsonLikePython(text) {
  let i = 0;
  const fail = (why) => { throw new SyntaxError(`${why} at char ${i}`); };
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const string = () => {
    let out = "";
    let start = ++i;
    for (;;) {
      if (i >= text.length) fail("Unterminated string");
      const c = text.charCodeAt(i);
      if (c === 0x22) { out += text.slice(start, i++); return out; }
      if (c < 0x20) fail("Invalid control character");
      if (c !== 0x5c) { i++; continue; }
      out += text.slice(start, i);
      const e = text[i + 1];
      if (e === "u") {
        const hex = text.slice(i + 2, i + 6);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("Invalid \\uXXXX escape");
        out += String.fromCharCode(parseInt(hex, 16)); // surrogate pairs join as they do in Python
        i += 6;
      } else if (e !== undefined && own(ESCAPES, e)) {
        out += ESCAPES[e];
        i += 2;
      } else fail("Invalid \\escape");
      start = i;
    }
  };
  const value = (depth) => {
    if (depth > MAX_DEPTH) fail("Too deeply nested");
    const c = text[i];
    if (c === '"') return string();
    if (c === "{" || c === "[") {
      const isObject = c === "{";
      const out = isObject ? new Map() : [];
      i++; ws();
      if (text[i] === (isObject ? "}" : "]")) { i++; return out; }
      for (;;) {
        if (isObject) {
          if (text[i] !== '"') fail("Expecting property name enclosed in double quotes");
          const key = string();
          ws();
          if (text[i] !== ":") fail("Expecting ':' delimiter");
          i++; ws();
          out.set(key, value(depth + 1));
        } else {
          out.push(value(depth + 1));
        }
        ws();
        if (text[i] === (isObject ? "}" : "]")) { i++; return out; }
        if (text[i] !== ",") fail("Expecting ',' delimiter");
        i++; ws();
      }
    }
    const literal = LITERALS.find(([word]) => text.startsWith(word, i));
    if (literal) { i += literal[0].length; return literal[1]; }
    NUMBER.lastIndex = i;
    const m = NUMBER.exec(text);
    if (!m) fail("Expecting value");
    i += m[0].length;
    return Number(m[0]);
  };
  if (text.startsWith("﻿")) fail("Unexpected UTF-8 BOM");
  ws();
  const result = value(0);
  ws();
  if (i !== text.length) fail("Extra data");
  return result;
}

const mapTruthy = (x) => (x instanceof Map ? x.size > 0 : Array.isArray(x) ? x.length > 0 : Boolean(x) || Number.isNaN(x));

export function parsePackageJson(content, path) {
  let data;
  try {
    data = parseJsonLikePython(content);
  } catch (e) {
    if (e instanceof SyntaxError) return [];
    throw e;
  }
  const deps = [];
  // Python raises AttributeError (and the scan fails) on a non-object document or section; here they hold nothing.
  if (!(data instanceof Map)) return deps;
  [["dependencies", false], ["devDependencies", true]].forEach(([section, dev]) => {
    const specs = data.get(section);
    if (!mapTruthy(specs) || !(specs instanceof Map)) return;
    specs.forEach((spec, name) => {
      if (typeof spec === "string") deps.push(dependency(name, cleanVersion(spec) || "", "npm", path, dev));
    });
  });
  return deps;
}

export function parseRequirements(content, path) {
  const deps = [];
  pySplitLines(content).forEach((raw) => {
    const line = pyStrip(raw.split("#")[0]);
    if (!line || D.requirement_skip.some((p) => line.startsWith(p)) || line.includes("://")) return; // options, VCS, URLs
    const m = REQUIREMENT.exec(line);
    if (!m) return;
    const version = D.pinning_ops.includes(m[3]) ? cleanVersion(m[4]) : null;
    deps.push(dependency(m[1], version || "", "PyPI", path));
  });
  return deps;
}

export function parseGoMod(content, path) {
  const deps = [];
  let inBlock = false;
  pySplitLines(content).forEach((raw) => {
    const line = pyStrip(raw.split("//")[0]);
    if (line.startsWith("require (")) {
      inBlock = true;
      return;
    }
    if (inBlock && line === ")") {
      inBlock = false;
      return;
    }
    const m = inBlock || line.startsWith("require ") ? GO_REQUIRE.exec(line) : null;
    if (m) deps.push(dependency(m[1], m[2], "Go", path));
  });
  return deps;
}

export function collectDependencies(files) {
  const deps = [];
  files.forEach((f) => {
    const name = f.path.slice(f.path.lastIndexOf("/") + 1); // case-sensitive, unlike detectLanguage
    if (name === "package.json") deps.push(...parsePackageJson(f.content, f.path));
    else if (REQUIREMENTS_FILE.test(name)) deps.push(...parseRequirements(f.content, f.path));
    else if (name === "go.mod") deps.push(...parseGoMod(f.content, f.path));
  });
  return deps;
}

const PURL_TYPES = { npm: "npm", PyPI: "pypi", Go: "golang" };

/** Dependency.purl */
export function purl(dep) {
  const eco = own(PURL_TYPES, dep.ecosystem) ? PURL_TYPES[dep.ecosystem] : dep.ecosystem.toLowerCase();
  return dep.version ? `pkg:${eco}/${dep.name}@${dep.version}` : `pkg:${eco}/${dep.name}`;
}

// ------------------------------------------------------------------------------------------- version order

/** The value of a run of Unicode decimal digits as a canonical ASCII digit string (int() accepts any Nd digit;
 *  each Nd block of ten is contiguous and starts at 0, so a digit's value is its offset in its run mod 10). */
function digitValue(part) {
  let out = "";
  for (const ch of part) {
    let cp = ch.codePointAt(0);
    if (cp > 0x7f) {
      let start = cp;
      while (DIGITS.test(String.fromCodePoint(start - 1))) start -= 1;
      cp = 0x30 + ((cp - start) % 10);
    }
    out += String.fromCharCode(cp);
  }
  return out.replace(/^0+(?=.)/, "");
}

/** _version_key: up to four numeric parts (non-numeric ones count as 0), as canonical digit strings so very long
 *  numbers compare exactly. Compare keys with compareVersionKeys. */
export const versionKey = (v) => v.split(VERSION_SPLIT).slice(0, 4).map((p) => (DIGITS.test(p) ? digitValue(p) : "0"));

const compareDigits = (a, b) => (a.length !== b.length ? a.length - b.length : a < b ? -1 : a > b ? 1 : 0);

/** Python tuple ordering: element by element, and a prefix is smaller. */
export function compareVersionKeys(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const c = compareDigits(a[i], b[i]);
    if (c) return Math.sign(c);
  }
  return Math.sign(a.length - b.length);
}

/** sorted(versions, key=_version_key): stable, so equal keys keep their order. */
const sortVersions = (versions) => versions.map((v) => [versionKey(v), v])
  .sort((x, y) => compareVersionKeys(x[0], y[0])).map(([, v]) => v);

// ---------------------------------------------------------------------------------------------- advisories

export function parseVuln(detail, dep) {
  let score = null;
  list(get(detail, "severity", [])).forEach((s) => {
    score = cvss3BaseScore(get(s, "score", "")) || score;
  });
  const dbSeverity = get(truthy(get(detail, "database_specific", null)) ? detail.database_specific : {}, "severity", "");
  const ghsaKey = typeof dbSeverity === "string" ? dbSeverity.toUpperCase() : "";
  const ghsa = own(D.ghsa_severity, ghsaKey) ? D.ghsa_severity[ghsaKey] : null;
  const severity = ghsa || (score !== null ? severityFromScore(score) : "medium");

  const fixed = [];
  const depName = dep.name.toLowerCase();
  list(get(detail, "affected", [])).forEach((aff) => {
    const name = get(truthy(get(aff, "package", null)) ? aff.package : {}, "name", "");
    if (typeof name !== "string" || name.toLowerCase() !== depName) return;
    list(get(aff, "ranges", [])).forEach((rng) => {
      list(get(rng, "events", [])).forEach((e) => {
        if (isDict(e) && own(e, "fixed") && typeof e.fixed === "string") fixed.push(e.fixed);
      });
    });
  });
  const current = dep.version ? versionKey(dep.version) : [];
  const newer = sortVersions(fixed.filter((f) => compareVersionKeys(versionKey(f), current) > 0));
  const refs = list(truthy(get(detail, "references", null)) ? detail.references : []);
  const advisory = refs.find((r) => get(r, "type", null) === "ADVISORY");
  const summary = get(detail, "summary", null);
  const details = get(detail, "details", "");
  return {
    id: get(detail, "id", ""),
    aliases: list(get(detail, "aliases", [])),
    summary: pyStrip(typeof summary === "string" && summary ? summary : pySlice(typeof details === "string" ? details : "", 0, 200)),
    severity,
    cvss: score,
    fixed_in: newer.length ? newer[0] : fixed.length ? sortVersions(fixed)[fixed.length - 1] : null,
    url: advisory ? get(advisory, "url", null) : refs.length ? get(refs[0], "url", null) : null,
  };
}

// ---------------------------------------------------------------------------------------------- OSV lookup

/** The dependency audit could not run. Callers must not treat this as "no vulnerabilities". */
export class OSVUnavailable extends Error {
  constructor(reason) {
    super(reason);
    this.name = "OSVUnavailable";
  }
}

/** fetch(url, init) -> {status, ok, body}, reading the JSON body only when wantBody(response). Every failure
 *  becomes OSVUnavailable, as httpx.HTTPError and ValueError do in the backend. */
async function request(fetchImpl, url, init, wantBody) {
  const controller = typeof AbortController === "function" ? new AbortController() : null;
  const timer = controller && setTimeout(() => controller.abort(), OSV_TIMEOUT_MS);
  try {
    const resp = await fetchImpl(url, controller ? { ...init, signal: controller.signal } : init);
    return { status: resp.status, ok: resp.ok, body: wantBody(resp) ? await resp.json() : null };
  } catch (e) {
    if (e && e.name === "AbortError") throw new OSVUnavailable(`no answer from ${url} within ${OSV_TIMEOUT_MS / 1000} s`);
    if (e instanceof SyntaxError) throw new OSVUnavailable(`invalid JSON from ${url}: ${e.message}`);
    // fetch rejects with a TypeError for DNS, TLS and connection failures, and when CORS hides the response
    throw new OSVUnavailable(`network error or CORS block on ${url}: ${(e && (e.message || e.name)) || e}`);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

const unexpected = (url) => new OSVUnavailable(`unexpected response shape from ${url}`);

/** Runs jobs with at most `limit` in flight; rejects with the first failure and starts nothing after it. */
async function pool(items, limit, job) {
  const results = new Array(items.length);
  let next = 0;
  let failed = false;
  const worker = async () => {
    while (!failed && next < items.length) {
      const i = next++;
      try {
        results[i] = await job(items[i]);
      } catch (e) {
        failed = true;
        throw e;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

/** enrich_with_osv: fills dep.vulnerabilities in place and returns deps, or throws OSVUnavailable. Any failure
 *  (network, CORS, timeout, non-2xx batch answer, bad JSON) leaves every dependency untouched. */
export async function enrichWithOsv(deps, fetchImpl = globalThis.fetch) {
  const queryable = deps.filter((d) => d.version);
  if (!queryable.length) return deps;
  if (typeof fetchImpl !== "function") throw new OSVUnavailable("fetch is not available");
  const idsPerDep = new Map();
  for (let start = 0; start < queryable.length; start += D.osv_batch_size) {
    const chunk = queryable.slice(start, start + D.osv_batch_size);
    const queries = chunk.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version }));
    const init = { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ queries }) };
    const resp = await request(fetchImpl, D.osv_batch, init, (r) => r.ok);
    if (!resp.ok) throw new OSVUnavailable(`HTTP ${resp.status} from ${D.osv_batch}`); // raise_for_status
    const results = get(resp.body, "results", []);
    if (!isDict(resp.body) || !Array.isArray(results)) throw unexpected(D.osv_batch);
    results.slice(0, chunk.length).forEach((result, i) => {
      if (!isDict(result)) throw unexpected(D.osv_batch);
      const ids = list(truthy(get(result, "vulns", [])) ? result.vulns : []).map((v) => get(v, "id", null));
      if (ids.some((id) => typeof id !== "string")) throw unexpected(D.osv_batch);
      if (ids.length) idsPerDep.set(start + i, ids);
    });
  }

  const uniqueIds = [...new Set([...idsPerDep.values()].flat())].slice(0, D.max_detail_lookups);
  const fetched = await pool(uniqueIds, D.osv_concurrency, async (vid) => {
    const url = D.osv_vuln.replace("{id}", () => vid);
    const resp = await request(fetchImpl, url, {}, (r) => r.status === 200);
    if (resp.status !== 200) return [vid, { id: vid }]; // e.g. 404: no detail record, keep the bare id
    if (!isDict(resp.body)) throw unexpected(url);
    return [vid, resp.body];
  });
  const details = new Map(fetched);
  const assigned = [...idsPerDep].map(([idx, ids]) => {
    const dep = queryable[idx];
    return [dep, ids.map((v) => parseVuln(details.has(v) ? details.get(v) : { id: v }, dep))];
  });
  assigned.forEach(([dep, vulns]) => { dep.vulnerabilities = vulns; });
  return deps;
}

// ------------------------------------------------------------------------------------------------ findings

const SEV_ORDER = D.sev_order;

export function dependencyFindings(deps, files) {
  const contents = new Map(files.map((f) => [f.path, f.content.split("\n")]));
  const findings = [];
  deps.forEach((d) => {
    if (!d.vulnerabilities.length) return;
    let worst = d.vulnerabilities[0]; // max(): the first of equal maxima
    const rankOf = (v) => [SEV_ORDER.indexOf(v.severity), v.cvss || 0];
    d.vulnerabilities.forEach((v) => {
      const [a, b] = rankOf(v);
      const [x, y] = rankOf(worst);
      if (a > x || (a === x && b > y)) worst = v;
    });
    const fixes = d.vulnerabilities.filter((v) => v.fixed_in).map((v) => v.fixed_in);
    const target = fixes.length ? sortVersions(fixes)[fixes.length - 1] : null;
    const pattern = literalRegex(D.dep_line.prefix, d.name, D.dep_line.suffix);
    const index = (contents.get(d.manifest) || []).findIndex((text) => pattern.test(text));
    const ids = d.vulnerabilities.slice(0, 5).map((v) => (v.aliases.length ? v.aliases[0] : v.id)).join(", ");
    findings.push(withFingerprint({
      rule_id: `OSV-${worst.id}`,
      scanner: "osv",
      severity: worst.severity,
      type: `Vulnerable dependency: ${d.name}@${d.version}`,
      description: pyStrip(`${d.vulnerabilities.length} known advisory(ies): ${ids}. ${worst.summary}`),
      file_path: d.manifest,
      line_number: index >= 0 ? index + 1 : null,
      recommendation: target ? `Upgrade ${d.name} to ${target} or later.` : `No fixed release yet — consider replacing ${d.name}.`,
      cwe: D.cwe,
      owasp: D.owasp,
      snippet: `${d.name}@${d.version}`,
      fingerprint: "",
      suppression: null,
      fp_basis: null,
    }));
  });
  return findings;
}
