// Standard-format exports, ported from backend/codeguard/exporters.py: SARIF 2.1.0 (GitHub Code Scanning) and a
// CycloneDX 1.5 SBOM. The output matches the backend's except the volatile serialNumber and timestamp.
/* global globalThis */
import { RULES, pySlice, pyStrip } from "./lang";
import { purl } from "./dependencies";

const E = RULES.exporters;
const TOOL = "CodeGuard AI";

/** Active findings become results; suppressed ones are emitted too, carrying SARIF `suppressions`. */
export function toSarif(findings, suppressed = []) {
  const rules = new Map();
  const results = [];
  [...findings, ...(suppressed || [])].forEach((f) => {
    if (!rules.has(f.rule_id)) {
      const tags = ["security", f.scanner];
      if (f.cwe) tags.push(`external/cwe/${f.cwe.toLowerCase()}`);
      if (f.owasp) tags.push(`owasp/${f.owasp}`);
      rules.set(f.rule_id, {
        id: f.rule_id,
        name: f.type,
        shortDescription: { text: f.type },
        fullDescription: { text: pySlice(f.description, 0, 1000) },
        help: { text: f.recommendation, markdown: `**Fix:** ${f.recommendation}` },
        defaultConfiguration: { level: E.sarif_level[f.severity] },
        properties: { tags, "security-severity": E.security_severity[f.severity], precision: "medium" },
      });
    }
    const location = { physicalLocation: { artifactLocation: { uri: f.file_path } } };
    if (f.line_number) location.physicalLocation.region = { startLine: f.line_number };
    const result = {
      ruleId: f.rule_id,
      level: E.sarif_level[f.severity],
      message: { text: `${f.description}\n\nFix: ${f.recommendation}` },
      locations: [location],
      partialFingerprints: { "codeguard/v2": f.fingerprint },
      properties: { severity: f.severity, cwe: f.cwe ?? null, owasp: f.owasp ?? null },
    };
    if (f.suppression) {
      result.suppressions = [{
        kind: "inSource", status: "accepted", justification: f.suppression.justification || "codeguard-ignore marker",
      }];
    }
    results.push(result);
  });
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: TOOL, informationUri: "https://github.com/VRAJ8/CodeGuardAI", semanticVersion: RULES.version, rules: [...rules.values()] } },
      results,
    }],
  };
}

function uuid4() {
  const c = globalThis.crypto;
  if (c && typeof c.randomUUID === "function") return c.randomUUID();
  const b = new Uint8Array(16);
  if (c && typeof c.getRandomValues === "function") c.getRandomValues(b);
  else for (let i = 0; i < 16; i++) b[i] = Math.floor(Math.random() * 256);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** datetime.now(timezone.utc).isoformat(): microseconds and a +00:00 offset. */
function utcIsoformat(date = new Date()) {
  const ms = date.getUTCMilliseconds();
  return `${date.toISOString().slice(0, 19)}${ms ? `.${String(ms * 1000).padStart(6, "0")}` : ""}+00:00`;
}

export function toCycloneDx(dependencies, projectName) {
  const components = [];
  const vulns = [];
  dependencies.forEach((d) => {
    const ref = purl(d);
    components.push({
      type: "library",
      "bom-ref": ref,
      name: d.name,
      version: d.version || "unknown",
      purl: ref,
      scope: d.dev ? "optional" : "required",
      properties: [{ name: "codeguard:manifest", value: d.manifest }],
    });
    d.vulnerabilities.forEach((v) => {
      const entry = {
        "bom-ref": `${v.id}:${ref}`,
        id: v.id,
        source: { name: "OSV", url: `https://osv.dev/vulnerability/${v.id}` },
        ratings: [{ severity: v.severity, ...(v.cvss ? { score: v.cvss, method: "CVSSv31" } : {}) }],
        description: v.summary,
        affects: [{ ref }],
      };
      if (v.fixed_in) entry.recommendation = `Upgrade to ${v.fixed_in}`;
      vulns.push(entry);
    });
  });
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${uuid4()}`,
    version: 1,
    metadata: {
      timestamp: utcIsoformat(),
      tools: { components: [{ type: "application", name: TOOL, version: RULES.version }] },
      component: { type: "application", name: projectName, "bom-ref": "root" },
    },
    components,
    vulnerabilities: vulns,
  };
}

const OWASP = RULES.taxonomy.owasp_top10;

/** exporters.owasp_label: "A03:2021" -> "A03 Injection" */
export const owaspLabel = (code) =>
  pyStrip(`${code.split(":")[0]} ${Object.prototype.hasOwnProperty.call(OWASP, code) ? OWASP[code] : ""}`);
