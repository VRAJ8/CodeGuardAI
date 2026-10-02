// Design tokens shared by every page and chart.
// Categorical slots are validated (CVD-safe, >=3:1) against the #111113 card surface.
export const CATEGORICAL = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"];
export const OTHER = "#5f5e5a";

// Color follows the entity, never its rank: each language owns a fixed slot.
const LANGUAGE_SLOTS = ["python", "javascript", "typescript", "go", "java", "rust", "php", "ruby"];
export const languageColor = (lang) => {
  const i = LANGUAGE_SLOTS.indexOf(lang);
  return i >= 0 ? CATEGORICAL[i] : OTHER;
};

// Status palette — reserved for severity, always shown with a label.
export const SEVERITY = {
  critical: { color: "#d03b3b", label: "Critical" },
  high: { color: "#ec835a", label: "High" },
  medium: { color: "#fab219", label: "Medium" },
  low: { color: "#898781", label: "Low" },
};
export const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

export const GRADE = {
  A: { color: "#00E599", bg: "rgba(0,229,153,0.12)", vibe: "Locked in" },
  B: { color: "#7dd3a8", bg: "rgba(125,211,168,0.12)", vibe: "Solid" },
  C: { color: "#fab219", bg: "rgba(250,178,25,0.12)", vibe: "Mid — needs work" },
  D: { color: "#ec835a", bg: "rgba(236,131,90,0.12)", vibe: "Risky" },
  F: { color: "#d03b3b", bg: "rgba(208,59,59,0.14)", vibe: "Cooked" },
};
export const gradeFor = (score) =>
  score == null ? null : score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";

export const SCANNERS = {
  semgrep: { label: "Semgrep", blurb: "Dataflow / taint rules" },
  bandit: { label: "Bandit", blurb: "Python AST security linter" },
  osv: { label: "OSV.dev", blurb: "Dependency CVE database" },
  secrets: { label: "Secrets", blurb: "Signatures + entropy" },
  patterns: { label: "Rule pack", blurb: "Cross-language patterns" },
  radon: { label: "Radon", blurb: "Complexity & maintainability" },
};

// Sequential ramp (one hue, dark -> bright) for the activity heatmap.
export const ACTIVITY_RAMP = ["#1c1c20", "#0f4d3b", "#0a7a5a", "#05b37f", "#00E599"];

export const CHART = {
  grid: "#232327",
  axis: "#3a3a40",
  muted: "#898781",
  brand: "#00E599",
};
