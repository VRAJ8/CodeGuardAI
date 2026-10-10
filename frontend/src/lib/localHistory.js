// Recent browser scans, remembered in this browser only. Every storage access is guarded: private windows,
// blocked storage and full quotas just mean less is remembered, never a crash. The current tab also keeps its
// scans in memory, so a result still opens when storage refused it.
const KEY = "codeguard:browser-scans";
const MAX_SCANS = 8;
const MAX_CHARS = 1_500_000; // per scan; localStorage quotas are counted in UTF-16 characters (~5M per origin)

const memory = new Map();

const read = () => {
  try {
    const scans = JSON.parse(localStorage.getItem(KEY) || "[]");
    return Array.isArray(scans) ? scans : [];
  } catch {
    return [];
  }
};

const write = (scans) => {
  try {
    localStorage.setItem(KEY, JSON.stringify(scans));
    return true;
  } catch {
    return false;
  }
};

/** A very large report keeps its summary and the top findings, marked as trimmed. */
function fit(analysis) {
  if (JSON.stringify(analysis).length <= MAX_CHARS) return analysis;
  return {
    ...analysis,
    trimmed: true,
    security_issues: analysis.security_issues.slice(0, 300),
    suppressed_issues: [],
    bug_risks: analysis.bug_risks.slice(0, 100),
    dependencies: analysis.dependencies.filter((d) => d.vulnerabilities?.length),
  };
}

export const listLocalScans = () => read();

export const getLocalScan = (id) => memory.get(id) || read().find((a) => a.analysis_id === id) || null;

/** Returns true when the scan was stored (oldest scans are dropped until it fits). */
export function saveLocalScan(analysis) {
  memory.set(analysis.analysis_id, analysis);
  let scans = [fit(analysis), ...read().filter((a) => a.analysis_id !== analysis.analysis_id)].slice(0, MAX_SCANS);
  while (scans.length && !write(scans)) scans = scans.slice(0, -1);
  return scans.length > 0;
}

export function removeLocalScan(id) {
  memory.delete(id);
  write(read().filter((a) => a.analysis_id !== id));
}
