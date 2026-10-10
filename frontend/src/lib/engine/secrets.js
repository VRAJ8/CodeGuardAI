// Hardcoded-secret detection: provider signatures plus a Shannon-entropy check for generic `password = "..."`
// assignments, ported from backend/codeguard/scanners/secrets.py. Matches are always redacted.
import { RULES, compileRegex, pyFixed, pyLen, pySlice, pySum } from "./lang";
import { owaspForCwe, overLimit } from "./patterns";
import { withFingerprint } from "./sha1";

const S = RULES.secrets;
const SIGNATURES = S.signatures.map((s) => ({ ...s, regex: compileRegex(s) }));
const GENERIC = compileRegex(S.generic);
const CWE = "CWE-798"; // hardcoded in secrets._make; the golden pins it
const OWASP = owaspForCwe(CWE);

export function shannonEntropy(value) {
  if (!value) return 0.0;
  const counts = new Map(); // Counter: first-seen order, by code point
  for (const ch of value) counts.set(ch, (counts.get(ch) || 0) + 1);
  const n = pyLen(value);
  return -pySum([...counts.values()].map((c) => (c / n) * Math.log2(c / n)));
}

export function redact(value) {
  const { min_length: min, head, tail, mask } = S.redact;
  return pyLen(value) > min ? `${pySlice(value, 0, head)}${mask}${pySlice(value, -tail)}` : mask;
}

export function looksPlaceholder(value) {
  const low = value.toLowerCase();
  return S.placeholder_hints.some((hint) => low.includes(hint)) || new Set(value).size < S.min_distinct;
}

function make(ruleId, title, severity, filePath, lineno, raw, entropy, line) {
  const extra = entropy ? ` (entropy ${pyFixed(entropy, 2)} bits/char)` : "";
  return withFingerprint({
    rule_id: ruleId,
    scanner: "secrets",
    severity,
    type: `Hardcoded secret: ${title}`,
    description: `Potential ${title} committed to source${extra}. Value: ${redact(raw)}`,
    file_path: filePath,
    line_number: lineno,
    recommendation: S.recommendation,
    cwe: CWE,
    owasp: OWASP,
    snippet: redact(raw),
    fingerprint: "",
    suppression: null,
    fp_basis: line.split(raw).join("<secret>") || null, // str.replace: every occurrence
  });
}

export function scanSecrets(content, filePath) {
  const findings = [];
  content.split("\n").forEach((line, i) => {
    const lineno = i + 1;
    if (overLimit(line, S.max_line)) return;
    let seen = false;
    SIGNATURES.forEach((sig) => {
      const m = sig.regex.exec(line);
      if (!m) return;
      if (sig.id === S.db_url.rule && looksPlaceholder(m[S.db_url.password_group] || "")) return;
      findings.push(make(sig.id, sig.title, sig.severity, filePath, lineno, m[0], null, line));
      seen = true;
    });
    if (seen) return;
    const m = GENERIC.exec(line);
    if (!m) return;
    const value = m[S.generic.value_group];
    const entropy = shannonEntropy(value);
    if (looksPlaceholder(value) || entropy < S.min_entropy) return;
    const name = pySlice(m[S.generic.name_group], 0, 40);
    findings.push(make("SEC-GENERIC", `Hardcoded credential in \`${name}\``, "high", filePath, lineno, value, entropy, line));
  });
  return findings;
}
