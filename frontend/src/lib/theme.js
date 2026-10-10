// Design tokens shared by every page and chart (neo-brutalist theme).
// Categorical slots are validated (CVD-safe adjacent pairs) against the #FFFDF8 card surface;
// three slots sit below 3:1 contrast, so every multi-series chart carries visible labels.
export const CATEGORICAL = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"];
export const OTHER = "#a8a297";

// Color follows the entity, never its rank: each language owns a fixed slot.
const LANGUAGE_SLOTS = ["python", "javascript", "typescript", "go", "java", "rust", "php", "ruby"];
export const languageColor = (lang) => {
  const i = LANGUAGE_SLOTS.indexOf(lang);
  return i >= 0 ? CATEGORICAL[i] : OTHER;
};

// Status palette — reserved for severity. Rendered as filled blocks with ink text + icon + label.
export const SEVERITY = {
  critical: { color: "#FF5A5F", label: "Critical" },
  high: { color: "#FF9F43", label: "High" },
  medium: { color: "#FFE14D", label: "Medium" },
  low: { color: "#DCD5C8", label: "Low" },
};
export const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

// Grade stickers: flat fill + ink text, tilted a little.
export const GRADE = {
  A: { color: "#7CF0B4", vibe: "Locked in", emoji: "🔒" },
  B: { color: "#B8F35E", vibe: "Solid", emoji: "👍" },
  C: { color: "#FFE14D", vibe: "Mid. Needs work", emoji: "😬" },
  D: { color: "#FF9F43", vibe: "Risky", emoji: "⚠️" },
  F: { color: "#FF5A5F", vibe: "Cooked", emoji: "🔥" },
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
  complexity: { label: "Complexity", blurb: "Decision-point heuristic (browser scans)" },
};

// Sequential ramp (one hue, light -> dark) for the activity heatmap.
export const ACTIVITY_RAMP = ["#ECE6DA", "#C4CEFF", "#8EA1FF", "#5F78FF", "#3B5BFF"];

export const CHART = {
  grid: "#E4DDD0",
  axis: "#111111",
  muted: "#4A463F",
  brand: "#3B5BFF",
  fill: "#FFE14D",
};

// Rotating sticker colors for decorative blocks (never for data).
export const POP = ["#FFE14D", "#FF8AD8", "#B8F35E", "#C9B6FF", "#FF9F43", "#7CF0B4"];
