// CVSS v3.x base scores (FIRST.org specification), ported from backend/codeguard/scanners/dependencies.py. The
// metric weights come from rules.generated.json; the equation's coefficients are the specification's own.
// parity.golden.json holds all 2592 CVSS:3.1 base vectors.
import { RULES } from "./lang";

const D = RULES.dependencies;
const W = D.cvss_weights;
const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

/** round(x) to an integer: Python rounds half to even, Math.round rounds half up. */
export function roundHalfEven(x) {
  const r = Math.round(x);
  return Math.abs(x % 1) === 0.5 && r % 2 !== 0 ? r - 1 : r;
}

/** The specification's Roundup: the smallest one-decimal number >= x, robust to float noise. */
export function roundup(x) {
  const i = roundHalfEven(x * 100000);
  return i % 10000 === 0 ? i / 100000.0 : (Math.floor(i / 10000) + 1) / 10.0;
}

const weight = (metric, value) => {
  if (!own(W[metric], value)) throw new RangeError(`${metric}:${value}`);
  return W[metric][value];
};

/** Base score from a "CVSS:3.x/AV:N/..." vector, or null when it is not a valid v3 base vector. */
export function cvss3BaseScore(vector) {
  if (typeof vector !== "string" || !vector || !vector.startsWith("CVSS:3")) return null;
  const m = {};
  for (const part of vector.split("/").slice(1)) {
    const kv = part.split(":");
    if (kv.length !== 2) return null; // dict() of a non-pair is a ValueError
    m[kv[0]] = kv[1];
  }
  try {
    for (const key of ["S", "PR", "C", "I", "A", "AV", "AC", "UI"]) if (!own(m, key)) throw new RangeError(key);
    const scopeChanged = m.S === "C";
    const prWeights = D.privileges_required[scopeChanged ? "changed" : "unchanged"];
    if (!own(prWeights, m.PR)) throw new RangeError(`PR:${m.PR}`);
    const pr = prWeights[m.PR];
    const iss = 1 - (1 - weight("C", m.C)) * (1 - weight("I", m.I)) * (1 - weight("A", m.A));
    const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
    const exploit = 8.22 * weight("AV", m.AV) * weight("AC", m.AC) * pr * weight("UI", m.UI);
    if (impact <= 0) return 0.0;
    const raw = scopeChanged ? 1.08 * (impact + exploit) : impact + exploit;
    return roundup(Math.min(raw, 10));
  } catch (e) {
    if (e instanceof RangeError) return null; // KeyError: a missing or unknown metric
    throw e;
  }
}

/** CVSS score -> critical / high / medium / low */
export const severityFromScore = (score) => (D.severity_cutoffs.find(([limit]) => score >= limit) || [null, "low"])[1];
