// Scan orchestration for the in-browser engine, ported from backend/codeguard/engine.py with the browser's scanner
// set: regex patterns, secrets, dependency manifests (+ OSV.dev when enabled) and the generic complexity heuristic.
// Bandit and Semgrep are Python tools and only run on the server. The report has exactly ScanReport's shape.
/* global globalThis */
import { RULES, isCode, pyRound, pySum } from "./lang";
import { analyzeFile } from "./complexity";
import { collectDependencies, dependencyFindings, enrichWithOsv } from "./dependencies";
import { scanPatterns } from "./patterns";
import { overall } from "./scoring";
import { scanSecrets } from "./secrets";
import { withFingerprint } from "./sha1";
import { applySuppressions } from "./suppressions";

const E = RULES.engine;
const SEV_RANK = E.severity_rank;
const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
const extend = (target, items) => { items.forEach((x) => target.push(x)); }; // no spread: arrays can be huge
const now = () => (typeof performance !== "undefined" && performance.now ? performance.now() : Date.now());
const tick = () => new Promise((resolve) => setTimeout(resolve, 0)); // let a progress bar paint between files

/** Python's str ordering (by code point). `<` compares UTF-16 units, which disagrees once a character above U+FFFF
 *  meets one in U+E000-U+FFFF; remapping the units at the first difference fixes that. */
export function pyCompare(a, b) {
  if (a === b) return 0;
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    let x = a.charCodeAt(i);
    let y = b.charCodeAt(i);
    if (x === y) continue;
    if (x >= 0xd800 && y >= 0xd800) {
      x = x >= 0xe000 ? x - 0x800 : x + 0x2000;
      y = y >= 0xe000 ? y - 0x800 : y + 0x2000;
    }
    return x < y ? -1 : 1;
  }
  return a.length < b.length ? -1 : 1;
}

/** When two scanners flag the same line+CWE, keep the more precise tool's result (then the higher severity). */
export function dedupe(findings) {
  const priority = (f) => (own(E.scanner_priority, f.scanner) ? E.scanner_priority[f.scanner] : 0);
  const best = new Map(); // dict: a replaced entry keeps its first position
  findings.forEach((f) => {
    const key = JSON.stringify([f.file_path, f.line_number ?? null, f.cwe || f.rule_id]);
    const cur = best.get(key);
    if (!cur || priority(f) > priority(cur) || (priority(f) === priority(cur) && SEV_RANK[f.severity] > SEV_RANK[cur.severity])) {
      best.set(key, f);
    }
  });
  return [...best.values()].sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]
    || pyCompare(a.file_path, b.file_path) || (a.line_number || 0) - (b.line_number || 0));
}

/** One line-ending convention for every scanner, so a finding, its marker and its fingerprint agree on lines. */
function normalizeNewlines(f) {
  if (!f.content.includes("\r")) return f;
  const content = f.content.split("\r\n").join("\n").split("\r").join("\n");
  return { ...f, content, lines: content.split("\n").length };
}

/** Identical code lines in one file share a content fingerprint; suffix repeats in line order. */
export function disambiguateFingerprints(findings) {
  const seen = new Map();
  const order = [...findings].sort((a, b) => pyCompare(a.file_path, b.file_path)
    || (a.line_number || 0) - (b.line_number || 0) || pyCompare(a.rule_id, b.rule_id));
  order.forEach((f) => {
    const n = (seen.get(f.fingerprint) || 0) + 1;
    seen.set(f.fingerprint, n);
    if (n > 1) f.fingerprint = `${f.fingerprint}-${n}`;
  });
}

/** Fingerprint every finding from the flagged source line itself, then disambiguate repeats. */
function fingerprintFromSource(findings, files) {
  const linesByPath = new Map(files.map((f) => [f.path, f.content.split("\n")]));
  findings.forEach((f) => {
    const lines = linesByPath.get(f.file_path);
    const n = f.line_number;
    withFingerprint(f, lines && n && n > 0 && n <= lines.length ? lines[n - 1] : null);
  });
  disambiguateFingerprints(findings);
}

/** dict(Counter(keys).most_common()): by count, ties in first-seen order. */
function mostCommon(pairs) {
  const counts = new Map();
  pairs.forEach(([key, n]) => counts.set(key, (counts.get(key) || 0) + n));
  return Object.fromEntries([...counts].sort((a, b) => b[1] - a[1]));
}

/** A Finding as ScanReport.model_dump() emits it (fp_basis is internal, like the excluded pydantic field). */
const publicFinding = ({ fp_basis: _, ...f }) => f;

/** Scan SourceFiles (lang.makeSourceFile) -> a report with exactly the keys of the backend's ScanReport.
 *  `osv` queries OSV.dev with package names and versions through `fetchImpl`; when that lookup fails, the report
 *  says so in `errors` (fail closed) instead of claiming the dependencies are clean. */
export async function scan(files, { osv = true, fetchImpl = globalThis.fetch, onProgress = () => {} } = {}) {
  const started = now();
  const sources = files.map(normalizeNewlines);
  const scannersRun = [...E.scanners_run];
  const errors = [];

  onProgress("Running secret & pattern rules", 20);
  const findings = [];
  for (let i = 0; i < sources.length; i++) {
    const f = sources[i];
    extend(findings, scanSecrets(f.content, f.path));
    extend(findings, scanPatterns(f.content, f.path, f.language, false)); // no Bandit here, so its overlaps stay on
    if (i % 25 === 24) {
      onProgress("Running secret & pattern rules", 20 + Math.floor((30 * (i + 1)) / sources.length));
      await tick();
    }
  }

  const deps = collectDependencies(sources);
  if (deps.length && osv) {
    onProgress("Resolving dependencies against OSV.dev", 55);
    try {
      await enrichWithOsv(deps, fetchImpl);
      scannersRun.push("osv");
    } catch (e) {
      const reason = (e && (e.message || e.name)) || String(e);
      errors.push(E.osv_error.replace("{}", () => reason));
    }
  } else {
    onProgress("Reading dependency manifests", 55);
  }
  extend(findings, dependencyFindings(deps, sources));

  onProgress("Measuring complexity & maintainability", 70);
  const codeFiles = sources.filter(isCode);
  const allHealth = codeFiles.map((f) => analyzeFile(f.content, f.path, f.language));
  const risks = allHealth.filter((r) => r.risk_score > 0).sort((a, b) => b.risk_score - a.risk_score);

  // Suppress before dedupe, so a rule-scoped marker means the same thing whichever engines ran.
  const [active, suppressedRaw, warnings] = applySuppressions(findings, sources);
  const security = dedupe(active);
  const suppressed = dedupe(suppressedRaw);
  fingerprintFromSource([...security, ...suppressed], sources);
  const avgCc = pySum(allHealth.map((h) => h.cyclomatic)) / Math.max(allHealth.length, 1);
  const avgMi = allHealth.length ? pySum(allHealth.map((h) => h.maintainability || 0)) / allHealth.length : 100.0;

  const [score, grade] = overall(security, risks, codeFiles.length);
  return {
    metrics: {
      total_files: sources.length,
      total_lines: sources.reduce((sum, f) => sum + f.lines, 0),
      languages: mostCommon(codeFiles.map((f) => [f.language, f.lines])),
      avg_complexity: pyRound(avgCc, 2),
      maintainability_index: pyRound(avgMi, 1),
    },
    security_issues: security.map(publicFinding),
    bug_risks: risks,
    dependencies: deps,
    overall_score: score,
    grade,
    severity_counts: Object.fromEntries(E.severities.map((s) => [s, security.filter((f) => f.severity === s).length])),
    owasp_counts: mostCommon(security.filter((f) => f.owasp).map((f) => [f.owasp, 1])),
    scanner_counts: mostCommon(security.map((f) => [f.scanner, 1])),
    scanners_run: scannersRun,
    suppressed: suppressed.length,
    suppressed_issues: suppressed.map(publicFinding),
    errors,
    warnings,
    duration_ms: Math.trunc(now() - started),
  };
}
