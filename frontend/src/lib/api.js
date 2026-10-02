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
    toast.error(err.response?.status === 404 ? "This export isn't available on this server yet" : "Download failed");
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

/** Ensure an analysis (list item or detail) has grade, severity_counts and issue_count. */
export function normalizeAnalysis(a) {
  if (!a) return a;
  return {
    ...a,
    grade: a.grade || scoreGrade(a.overall_score),
    severity_counts: severityCounts(a),
    issue_count: a.issue_count ?? (a.security_issues || []).length,
  };
}

export function normalizeDashboard(raw) {
  const s = raw || {};
  const recent = (s.recent_analyses || []).map(normalizeAnalysis);
  const completed = recent.filter((a) => (a.status || "completed") === "completed" && a.overall_score != null);
  const legacy = !Array.isArray(s.owasp);

  const severity = s.severity || completed.reduce((acc, a) => {
    Object.entries(a.severity_counts).forEach(([k, n]) => { acc[k] = (acc[k] || 0) + n; });
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });

  const byDay = {};
  recent.forEach((a) => { const d = (a.created_at || "").slice(0, 10); if (d) byDay[d] = (byDay[d] || 0) + 1; });
  const today = new Date();
  const activity = s.activity || Array.from({ length: 28 }, (_, i) => {
    const d = new Date(today);
    d.setUTCDate(d.getUTCDate() - (27 - i));
    const key = d.toISOString().slice(0, 10);
    return { date: key, count: byDay[key] || 0 };
  });

  const posture = s.posture_score ?? s.avg_score ?? 0;
  return {
    ...s,
    legacy,
    total_analyses: s.total_analyses || 0,
    projects: s.projects ?? new Set(completed.map((a) => a.source_url || a.name)).size,
    running: s.running || 0,
    avg_score: s.avg_score || 0,
    posture_score: posture,
    posture_grade: s.posture_grade || (s.total_analyses ? scoreGrade(posture) : null),
    score_delta_7d: s.score_delta_7d ?? null,
    total_issues: s.total_issues || 0,
    severity,
    secrets: s.secrets ?? completed.reduce((n, a) => n + (a.security_issues || []).filter((i) =>
      i.scanner === "secrets" || /secret/i.test(i.type || "")).length, 0),
    vulnerable_dependencies: s.vulnerable_dependencies ?? 0,
    total_dependencies: s.total_dependencies ?? 0,
    lines_scanned: s.lines_scanned ?? completed.reduce((n, a) => n + (a.metrics?.total_lines || 0), 0),
    fixed_total: s.fixed_total ?? 0,
    owasp: legacy ? OWASP_CODES.map(([code, name]) => ({ code, name, count: 0 })) : s.owasp,
    scanners: s.scanners || {},
    languages: s.languages || {},
    trend: s.trend || completed.slice().reverse().map((a) => ({ date: a.created_at, score: a.overall_score, name: a.name, grade: a.grade })),
    activity,
    streak: s.streak ?? 0,
    riskiest: s.riskiest || completed.slice().sort((x, y) => x.overall_score - y.overall_score).slice(0, 5)
      .map((a) => ({ analysis_id: a.analysis_id, name: a.name, score: a.overall_score, grade: a.grade, severity: a.severity_counts })),
    recent_analyses: recent,
  };
}
