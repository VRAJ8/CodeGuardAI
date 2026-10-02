import axios from "axios";

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
  const res = await axios.get(`${API}${path}`, { responseType: "blob" });
  const url = URL.createObjectURL(res.data);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
