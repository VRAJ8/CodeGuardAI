// Regex SAST rules with CWE / OWASP classification: a port of backend/codeguard/scanners/patterns.py. The rules
// themselves come from rules.generated.json. The browser has no Bandit, so rules flagged bandit_overlap stay on.
import { RULES, compileRegex, pyLen, pyLstrip, pySlice, pyStrip } from "./lang";
import { withFingerprint } from "./sha1";

const P = RULES.patterns;
const CWE_TO_OWASP = RULES.taxonomy.cwe_to_owasp;
const PATTERN_RULES = P.rules.map((r) => ({ ...r, regex: compileRegex(r), languages: new Set(r.languages) }));

/** taxonomy.owasp_for_cwe: "CWE-798" (any case, or a bare number) -> "A07:2021", or null. */
export function owaspForCwe(cwe) {
  if (!cwe) return null;
  const num = pyStrip(String(cwe).toUpperCase().split("CWE-").join(""));
  if (!/^[+-]?\d+$/.test(num)) return null; // int() also takes "1_0" and non-ASCII digits; no CWE is written so
  const key = `CWE-${Number(num)}`;
  return Object.prototype.hasOwnProperty.call(CWE_TO_OWASP, key) ? CWE_TO_OWASP[key] : null;
}

/** Longer lines than `limit` code points (minified bundles) are not searched. */
export const overLimit = (line, limit) => line.length > limit && pyLen(line) > limit;

export function isComment(line) {
  const text = pyLstrip(line);
  return P.comment_prefixes.some((prefix) => text.startsWith(prefix));
}

function finding(rule, filePath, lineno, line) {
  const text = pyStrip(line);
  return withFingerprint({
    rule_id: rule.id,
    scanner: "patterns",
    severity: rule.severity,
    type: rule.title,
    description: `Found: ${pySlice(text, 0, P.description_chars)}`,
    file_path: filePath,
    line_number: lineno,
    recommendation: rule.recommendation,
    cwe: rule.cwe,
    owasp: rule.owasp,
    snippet: pySlice(text, 0, P.snippet_chars),
    fingerprint: "",
    suppression: null,
    fp_basis: null,
  });
}

export function scanPatterns(content, filePath, language, skipBanditOverlap = false) {
  const findings = [];
  const skip = skipBanditOverlap && language === "python";
  const rules = PATTERN_RULES.filter((r) => r.languages.has(language) && !(skip && r.bandit_overlap));
  if (!rules.length) return findings;
  content.split("\n").forEach((line, i) => {
    if (overLimit(line, P.max_line) || isComment(line)) return;
    rules.forEach((rule) => {
      if (rule.regex.test(line)) findings.push(finding(rule, filePath, i + 1, line));
    });
  });
  return findings;
}
