import axios from "axios";
import { toast } from "sonner";

export const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
export const API = `${BACKEND_URL}/api`;
export const DEV_LOGIN = process.env.REACT_APP_DEV_LOGIN === "true";

axios.defaults.withCredentials = true;

export const timeAgo = (iso) => {
  if (!iso) return "";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 604800) return `${Math.floor(s / 86400)}d ago`;
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
};

export const compact = (n) =>
  n == null ? "0" : n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}k` : `${n}`;

export const severityCounts = (analysis) => {
  if (analysis?.severity_counts) return analysis.severity_counts;
  const c = { critical: 0, high: 0, medium: 0, low: 0 };
  (analysis?.security_issues || []).forEach((i) => { c[i.severity] = (c[i.severity] || 0) + 1; });
  return c;
};

export async function downloadFromApi(path, filename) {
  let res;
  try {
    res = await axios.get(`${API}${path}`, { responseType: "blob" });
  } catch (err) {
    const status = err.response?.status;
    let detail = "";
    try {
      detail = JSON.parse(await err.response.data.text()).detail || ""; // blob responses carry the JSON error body
    } catch {
      /* not JSON */
    }
    toast.error(status === 404 ? "This export isn't available on this server yet" : detail || "Download failed");
    return;
  }
  const url = URL.createObjectURL(res.data);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------------------------
// Payload normalization. The UI can be deployed ahead of the API (Netlify ships the frontend on
// merge; the backend deploys separately), so tolerate the v2 API shapes: derive every field the
// v3 widgets read from what the older endpoints return, instead of crashing on undefined.

const OWASP_CODES = [
  ["A01:2021", "Broken Access Control"], ["A02:2021", "Cryptographic Failures"], ["A03:2021", "Injection"],
  ["A04:2021", "Insecure Design"], ["A05:2021", "Security Misconfiguration"], ["A06:2021", "Vulnerable & Outdated Components"],
  ["A07:2021", "Identification & Auth Failures"], ["A08:2021", "Software & Data Integrity Failures"],
  ["A09:2021", "Logging & Monitoring Failures"], ["A10:2021", "Server-Side Request Forgery"],
];

const scoreGrade = (s) => (s == null ? null : s >= 90 ? "A" : s >= 80 ? "B" : s >= 70 ? "C" : s >= 60 ? "D" : "F");

// v2 findings have no `scanner`; infer it from the v2 scanners' fixed `type` strings.
const inferScanner = (i) =>
  i.scanner || (/secret/i.test(i.type || "") ? "secrets" : /^vulnerable dependency/i.test(i.type || "") ? "osv" : "patterns");

/** Ensure an analysis (list item or detail) has grade, severity_counts, issue_count and per-issue scanner. */
export function normalizeAnalysis(a) {
  if (!a) return a;
  const issues = a.security_issues ? a.security_issues.map((i) => (i.scanner ? i : { ...i, scanner: inferScanner(i) })) : a.security_issues;
  const withIssues = issues ? { ...a, security_issues: issues } : a;
  return {
    ...withIssues,
    legacy: !a.engine_version,
    grade: a.grade || scoreGrade(a.overall_score),
    severity_counts: severityCounts(withIssues),
    issue_count: a.issue_count ?? (issues || []).length,
    error: a.error || (a.status === "failed" ? a.ai_summary : undefined),
  };
}

const newestFirst = (xs) => xs.slice().sort((x, y) => String(y.created_at || "").localeCompare(String(x.created_at || "")));
const daysAgo = (n) => { const d = new Date(); d.setUTCDate(d.getUTCDate() - n); return d.toISOString().slice(0, 10); };

/**
 * Mirror of the v3 server's build_dashboard, used only when the API predates it. `history` is the full
 * GET /analysis/list payload (v2 returns complete docs, which is all we need to aggregate client-side).
 */
function aggregateLegacy(docs) {
  const all = newestFirst(docs.map(normalizeAnalysis));
  const completed = all.filter((a) => (a.status || "completed") === "completed" && a.overall_score != null);
  const latest = new Map();
  completed.forEach((a) => { const k = a.source_url || a.name; if (!latest.has(k)) latest.set(k, a); });
  const projects = [...latest.values()];

  const severity = { critical: 0, high: 0, medium: 0, low: 0 };
  const scanners = {};
  let secrets = 0;
  let vulnDeps = 0;
  projects.forEach((a) => (a.security_issues || []).forEach((i) => {
    severity[i.severity] = (severity[i.severity] || 0) + 1;
    scanners[i.scanner] = (scanners[i.scanner] || 0) + 1;
    if (i.scanner === "secrets") secrets += 1;
    if (i.scanner === "osv") vulnDeps += 1;
  }));

  const perDay = {};
  all.forEach((a) => { const d = String(a.created_at || "").slice(0, 10); if (d) perDay[d] = (perDay[d] || 0) + 1; });
  const activity = Array.from({ length: 28 }, (_, i) => ({ date: daysAgo(27 - i), count: perDay[daysAgo(27 - i)] || 0 }));
  let streak = 0;
  for (let i = activity.length - 1; i >= 0; i--) {
    if (activity[i].count === 0) { if (streak === 0 && i === activity.length - 1) continue; break; }
    streak += 1;
  }
  const avg = (xs) => (xs.length ? Math.round((xs.reduce((a, b) => a + b, 0) / xs.length) * 10) / 10 : 0);
  const languages = {};
  projects.forEach((a) => Object.entries(a.metrics?.languages || {}).forEach(([k, n]) => { languages[k] = (languages[k] || 0) + n; }));

  return {
    total_analyses: completed.length,
    projects: projects.length,
    running: all.filter((a) => a.status === "processing").length,
    avg_score: avg(completed.map((a) => a.overall_score)),
    posture_score: avg(projects.map((a) => a.overall_score)),
    total_issues: Object.values(severity).reduce((a, b) => a + b, 0),
    severity,
    secrets,
    vulnerable_dependencies: vulnDeps,
    lines_scanned: completed.reduce((n, a) => n + (a.metrics?.total_lines || 0), 0),
    scanners,
    languages,
    trend: completed.slice(0, 30).reverse().map((a) => ({ date: a.created_at, score: a.overall_score, name: a.name, grade: a.grade })),
    activity,
    streak,
    riskiest: projects.slice().sort((x, y) => x.overall_score - y.overall_score).slice(0, 5)
      .map((a) => ({ analysis_id: a.analysis_id, name: a.name, score: a.overall_score, grade: a.grade, severity: a.severity_counts })),
    recent_analyses: all.slice(0, 6),
  };
}

/** Accept a v3 dashboard payload as-is, or rebuild it from the v2 payload plus the full scan list. */
export function normalizeDashboard(raw, history) {
  const s = raw || {};
  const legacy = !Array.isArray(s.owasp);
  const base = legacy ? aggregateLegacy(history || s.recent_analyses || []) : s;
  const posture = base.posture_score ?? 0;
  return {
    ...base,
    legacy,
    total_analyses: base.total_analyses || 0,
    projects: base.projects || 0,
    running: base.running || 0,
    avg_score: base.avg_score || 0,
    posture_score: posture,
    posture_grade: base.posture_grade || (base.total_analyses ? scoreGrade(posture) : null),
    score_delta_7d: base.score_delta_7d ?? null,
    total_issues: base.total_issues || 0,
    severity: base.severity || { critical: 0, high: 0, medium: 0, low: 0 },
    secrets: base.secrets || 0,
    vulnerable_dependencies: base.vulnerable_dependencies || 0,
    total_dependencies: base.total_dependencies || 0,
    lines_scanned: base.lines_scanned || 0,
    fixed_total: base.fixed_total || 0,
    owasp: legacy ? OWASP_CODES.map(([code, name]) => ({ code, name, count: 0 })) : base.owasp,
    scanners: base.scanners || {},
    languages: base.languages || {},
    trend: base.trend || [],
    activity: base.activity || [],
    streak: base.streak || 0,
    riskiest: base.riskiest || [],
    recent_analyses: (base.recent_analyses || []).map(normalizeAnalysis),
  };
}
